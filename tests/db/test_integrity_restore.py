"""A real ``pg_dump`` / ``pg_restore`` into a new cluster, then a fork.

The managed-service path: no ``pg_resetwal``, so transaction ids start low
again in the new cluster and run through the ranges the old blocks sealed.
Containers of the test server's major version: the source, where the chain
is built, sealed and checkpointed once per module, and for each test a
fresh destination cluster that the dump is restored into. Skipped without
Docker, except in CI (``AUDIT_TEST_EXPECT_PG`` set).
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

import pytest
from sqlalchemy import Engine, create_engine, make_url, select, text
from sqlalchemy.orm import Session, sessionmaker

from audit_trail import AuditEvent, AuditTrail, Severity, event, migrations
from audit_trail.integrity import _seal
from audit_trail.integrity._anchor import declare_fork, export_checkpoint
from audit_trail.integrity._block import parse_body
from audit_trail.integrity._ed25519 import Ed25519Signer, Ed25519Verifier
from audit_trail.integrity._options import Integrity
from audit_trail.integrity._seal import SealRefusedError
from audit_trail.integrity._verify import Anchor, FailureKind, NoteKind
from audit_trail.integrity._verify_db import verify
from audit_trail.maintenance import ensure_partitions
from audit_trail.migrations import create_audit_tables

pytestmark = pytest.mark.filterwarnings("ignore:Did not recognize type 'xid8'")

SCHEMA = "audit_restore"
SIGNER = Ed25519Signer.from_seed("audit.example/sealer", bytes(range(32)))
VERIFIER = Ed25519Verifier([SIGNER.vkey])


class RestoreEvent(AuditEvent):
    NOTED = event("restore_test.noted", Severity.INFO)
    KEPT = event("restore_test.kept", Severity.CRITICAL)


_FACTORIES: dict[int, sessionmaker[Session]] = {}


def trail_for(engine: Engine) -> AuditTrail:
    trail = AuditTrail(
        engine,
        schema=SCHEMA,
        events=[RestoreEvent],
        severities=Severity,
        integrity=Integrity(),
    )
    factory = sessionmaker(engine)
    trail.install(factory)
    _FACTORIES[id(trail)] = factory
    return trail


def write(engine: Engine, trail: AuditTrail, count: int) -> None:
    factory = _FACTORIES[id(trail)]
    for n in range(count):
        with factory() as session:
            trail.log(session, RestoreEvent.NOTED, payload={"n": n})
            trail.log(session, RestoreEvent.KEPT, payload={"n": n})
            session.commit()


def current_xid(engine: Engine) -> int:
    with engine.connect() as conn:
        return int(conn.execute(text("SELECT pg_current_xact_id()::text")).scalar_one())


def burn_to(engine: Engine, target: int) -> None:
    """Use up transaction ids, one per transaction, until ``target``."""
    count = target - current_xid(engine)
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        for _ in range(max(count, 0)):
            conn.execute(text("SELECT pg_current_xact_id()"))


def seal_all(trail: AuditTrail) -> None:
    while trail.maintenance.seal(signer=SIGNER).capped:
        pass


def bodies(engine: Engine, trail: AuditTrail) -> list[dict[str, Any]]:
    block = _seal.block_table(trail.tables)
    with engine.connect() as conn:
        return [
            parse_body(bytes(body))
            for body in conn.execute(
                select(block.c.body).order_by(block.c.seq)
            ).scalars()
        ]


def cannot_run(reason: str) -> NoReturn:
    if os.environ.get("AUDIT_TEST_EXPECT_PG"):
        pytest.fail(reason)
    pytest.skip(reason)


@dataclass
class Dump:
    """The source cluster's dump, and what was true when it was taken."""

    image: str
    path: Path
    checkpoint: str
    seals: list[dict[str, Any]]
    old_max_xid: int


def run(container: Any, *command: str) -> str:
    result = container.exec(list(command))
    output = str(result.output.decode(errors="replace"))
    assert result.exit_code == 0, output
    return output


@pytest.fixture(scope="module")
def dump(engine: Engine, tmp_path_factory: pytest.TempPathFactory) -> Dump:
    try:
        from testcontainers.community.postgres import PostgresContainer
    except ImportError:  # pragma: no cover
        cannot_run("testcontainers is not installed")
    with engine.connect() as conn:
        version = int(conn.execute(text("SHOW server_version_num")).scalar_one())
    image = f"postgres:{version // 10000}"
    try:
        source = PostgresContainer(image, driver="psycopg")
        source.start()
    except Exception as exc:  # no Docker
        cannot_run(f"cannot start a source container: {exc}")
    path = tmp_path_factory.mktemp("restore") / "full.dump"
    try:
        built = _build_source(source.get_connection_url())
        run(
            source,
            "pg_dump",
            "-U",
            source.username,
            "-Fc",
            "-f",
            "/tmp/full.dump",
            source.dbname,
        )
        source.copy_from_container("/tmp/full.dump", path)
    finally:
        source.stop()
    return Dump(image, path, *built)


@pytest.fixture
def destination(dump: Dump) -> Iterator[Any]:
    """A new cluster, its transaction ids still low, with the dump file."""
    from testcontainers.community.postgres import PostgresContainer

    container = PostgresContainer(dump.image, driver="psycopg")
    try:
        container.start()
    except Exception as exc:
        cannot_run(f"cannot start a destination container: {exc}")
    try:
        container.copy_into_container(dump.path, "/tmp/full.dump")
        yield container
    finally:
        container.stop()


def _build_source(url: str) -> tuple[str, list[dict[str, Any]], int]:
    """Tables, a signed chain, two seals far apart, a checkpoint, a tail."""
    engine = create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(text(f'CREATE SCHEMA "{SCHEMA}"'))
        trail = trail_for(engine)
        with engine.begin() as conn:
            create_audit_tables(conn, trail.tables, Severity)
            ensure_partitions(conn, trail.tables, list(Severity), months_ahead=0)
            migrations.write_genesis(conn, trail.tables, signer=SIGNER)
        write(engine, trail, 5)
        seal_all(trail)
        burn_to(engine, current_xid(engine) + 1500)
        write(engine, trail, 5)
        seal_all(trail)
        with engine.connect() as conn:
            note = export_checkpoint(conn, trail.tables, signer=SIGNER).to_note()
        burn_to(engine, current_xid(engine) + 1500)
        write(engine, trail, 3)  # committed before the dump, never sealed there
        seals = [b for b in bodies(engine, trail) if b["kind"] == "seal"]
        with engine.connect() as conn:
            highest = int(
                conn.execute(
                    text(
                        f'SELECT t.xid::text AS x FROM "{SCHEMA}".audit_activity t '
                        "ORDER BY t.xid DESC LIMIT 1"
                    )
                ).scalar_one()
            )
        trail.dispose()
        return note, seals, highest
    finally:
        engine.dispose()


@pytest.fixture
def restored(destination: Any) -> Iterator[tuple[Engine, AuditTrail]]:
    """The dump restored with ``pg_restore`` into a new database."""
    name = f"r_{uuid.uuid4().hex[:10]}"
    container = destination
    run(
        container,
        "psql",
        "-U",
        container.username,
        "-d",
        container.dbname,
        "-c",
        f"CREATE DATABASE {name}",
    )
    run(container, "pg_restore", "-U", container.username, "-d", name, "/tmp/full.dump")
    url = make_url(container.get_connection_url()).set(database=name)
    engine = create_engine(url)
    trail = trail_for(engine)
    yield engine, trail
    trail.dispose()
    engine.dispose()


def test_a_restore_rewinds_xids_and_is_refused_until_a_fork(
    dump: Dump, restored: tuple[Engine, AuditTrail]
) -> None:
    engine, trail = restored
    assert current_xid(engine) < dump.seals[-1]["xid_to"]
    with pytest.raises(SealRefusedError) as info:
        trail.maintenance.seal()
    assert info.value.reason == "XID_REWIND"
    report = verify(engine, trail.tables, checkpoints=[dump.checkpoint])
    assert FailureKind.XID_REWIND in {f.kind for f in report.failures}


def test_a_declared_fork_after_a_restore_verifies(
    dump: Dump, restored: tuple[Engine, AuditTrail]
) -> None:
    engine, trail = restored
    with engine.connect() as conn:
        fork = declare_fork(
            conn,
            trail.tables,
            dump.checkpoint,
            reason="pg_restore into a managed service",
            signer=SIGNER,
        )
    assert fork.id_floor is not None
    assert fork.id_floor["transaction"] == 13
    assert fork.id_count == dict.fromkeys(fork.id_floor, 13)
    # The closing seal holds the tail committed after the last seal.
    closing = bodies(engine, trail)[fork.closing_seq - 1] if fork.closing_seq else {}
    assert closing["xid_to"] == dump.old_max_xid + 1
    assert {s["stream"]: s["rows"] for s in closing["segments"]} == dict.fromkeys(
        fork.id_floor, 3
    )
    # New rows: right after the fork, then with xids inside the old sealed
    # ranges, then past every old xid.
    write(engine, trail, 4)
    seal_all(trail)
    middle = (dump.seals[-1]["xid_from"] + dump.seals[-1]["xid_to"]) // 2
    assert current_xid(engine) < middle
    burn_to(engine, middle)
    write(engine, trail, 4)
    seal_all(trail)
    burn_to(engine, dump.old_max_xid + 200)
    write(engine, trail, 4)
    seal_all(trail)
    new_seals = [b for b in bodies(engine, trail) if b["kind"] == "seal"]
    new_seals = new_seals[len(dump.seals) + 1 :]
    assert sum(s["rows"] for b in new_seals for s in b["segments"]) == 12 * 3
    report = verify(
        engine,
        trail.tables,
        checkpoints=[dump.checkpoint],
        verifier=VERIFIER,
        require_signatures=True,
    )
    assert report.failures == []
    assert NoteKind.FORKED in {n.kind for n in report.notes}
    assert report.anchor is Anchor.ANCHORED
    health = trail.maintenance.health()
    assert health.seal is not None
    assert health.seal.unsealed_rows == 0


def test_a_data_only_restore_without_sequences_is_refused(
    dump: Dump, destination: Any
) -> None:
    container = destination
    name = f"d_{uuid.uuid4().hex[:10]}"
    run(
        container,
        "psql",
        "-U",
        container.username,
        "-d",
        container.dbname,
        "-c",
        f"CREATE DATABASE {name}",
    )
    url = make_url(container.get_connection_url()).set(database=name)
    engine = create_engine(url)
    trail = trail_for(engine)
    try:
        with engine.begin() as conn:
            conn.execute(text(f'CREATE SCHEMA "{SCHEMA}"'))
            create_audit_tables(conn, trail.tables, Severity)
            ensure_partitions(conn, trail.tables, list(Severity), months_ahead=0)
        run(
            container,
            "sh",
            "-c",
            "pg_restore -l /tmp/full.dump | grep -v 'SEQUENCE SET' > /tmp/noseq.list",
        )
        run(
            container,
            "pg_restore",
            "-U",
            container.username,
            "-d",
            name,
            "--data-only",
            "-L",
            "/tmp/noseq.list",
            "/tmp/full.dump",
        )
        with engine.connect() as conn, pytest.raises(SealRefusedError) as info:
            declare_fork(conn, trail.tables, dump.checkpoint, reason="data only")
        assert info.value.reason == "ID_FLOOR_VIOLATION"
    finally:
        trail.dispose()
        engine.dispose()
