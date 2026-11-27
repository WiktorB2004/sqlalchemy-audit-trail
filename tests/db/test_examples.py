"""The scripts under ``examples/``, which the documentation includes.

Each quickstart runs in a database of its own, created for the test, so it
can keep its default ``audit`` schema and public tables. ``roles.sql`` is run
with unique role names, and every operation is tried as each role, without
integrity and with it (after an upgrade from the grants of 0.3).
"""

from __future__ import annotations

import asyncio
import importlib.util
import re
import sys
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from audit_trail import Audited, AuditEvent, AuditTrail, Severity, event
from audit_trail.integrity import (
    Anchor,
    FailureKind,
    Integrity,
    NoteKind,
    ReplicationError,
    Status,
    declare_fork,
    export_checkpoint,
)
from audit_trail.integrity.ed25519 import Ed25519Signer, Ed25519Verifier
from audit_trail.maintenance import ensure_partitions
from audit_trail.migrations import (
    add_integrity,
    add_integrity_indexes,
    create_audit_tables,
    write_genesis,
)
from audit_trail.privacy import ScrubResult
from audit_trail.testing import assert_audited

EXAMPLES = Path(__file__).parents[2] / "examples"


@pytest.fixture
def database(engine: Engine) -> Iterator[str]:
    """Name of a new, empty database, dropped after the test."""
    name = f"example_{uuid.uuid4().hex[:12]}"
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    yield name
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))


@pytest.fixture
def database_engine(engine: Engine, database: str) -> Iterator[Engine]:
    """Superuser engine on ``database``."""
    eng = create_engine(engine.url.set(database=database))
    yield eng
    eng.dispose()


def url_of(
    engine: Engine,
    database: str,
    driver: str,
    *,
    username: str | None = None,
    password: str | None = None,
) -> str:
    url = engine.url.set(drivername=f"postgresql+{driver}", database=database)
    if username is not None:
        url = url.set(username=username, password=password)
    return url.render_as_string(hide_password=False)


def load(name: str, database_url: str, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import ``examples/<name>.py`` afresh, with ``DATABASE_URL`` set."""
    monkeypatch.setenv("DATABASE_URL", database_url)
    module_name = f"example_{name}_{uuid.uuid4().hex[:8]}"
    spec = importlib.util.spec_from_file_location(module_name, EXAMPLES / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # SQLAlchemy resolves the models' string annotations through sys.modules.
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module


def test_quickstart_sync(
    engine: Engine,
    database: str,
    database_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    example = load("quickstart_sync", url_of(engine, database, "psycopg"), monkeypatch)
    example.main()

    trail: AuditTrail = example.audit
    invoice = ("Invoice", "1")
    assert_audited(
        trail,
        database_engine,
        verb="entity.created",
        obj=invoice,
        actor_id="42",
        changes={"customer": [None, "Acme"], "total": [None, "120.00"]},
    )
    assert_audited(
        trail,
        database_engine,
        verb="entity.updated",
        obj=invoice,
        actor_id="42",
        changes={"status": ["draft", "sent"], "payment_token": [None, "***"]},
    )
    assert_audited(
        trail,
        database_engine,
        verb="billing.invoice_sent",
        obj=invoice,
        payload={"channel": "email"},
    )
    output = capsys.readouterr().out
    assert output.count("by ada@example.com") == 2
    assert "billing.invoice_sent {'channel': 'email'}" in output


def test_quickstart_async(
    engine: Engine,
    database: str,
    database_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    example = load("quickstart_async", url_of(engine, database, "asyncpg"), monkeypatch)
    # A sync test: the example's asyncio.run() needs no running loop.
    asyncio.run(example.main())

    trail: AuditTrail = example.audit
    assert_audited(
        trail,
        database_engine,
        verb="entity.updated",
        obj=("Project", "1"),
        actor_id="7",
        changes={"tasks": {"added": ["2"], "removed": []}},
    )
    assert_audited(
        trail,
        database_engine,
        verb="entity.created",
        obj=("Task", "2"),
        target=("Project", "1"),
        actor_id="7",
    )
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 4
    assert lines[0].startswith("entity.created Task Review")


async def test_quickstart_fastapi(
    engine: Engine,
    database: str,
    database_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    example = load(
        "quickstart_fastapi", url_of(engine, database, "asyncpg"), monkeypatch
    )
    app = example.app
    transport = httpx.ASGITransport(app=app, client=("203.0.113.9", 50000))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://test") as client,
    ):
        created = await client.post(
            "/notes", json={"title": "Hello"}, headers={"X-User": "ada"}
        )
        assert created.status_code == 201
        renamed = await client.patch(
            "/notes/1", json={"title": "Hi"}, headers={"X-User": "bob"}
        )
        assert renamed.status_code == 200
        history = (await client.get("/notes/1/history")).json()

    assert history == [
        {
            "actor_id": "bob",
            "verb": "entity.updated",
            "changes": {"title": ["Hello", "Hi"]},
            "path": "/notes/1",
        },
        {
            "actor_id": "ada",
            "verb": "entity.created",
            "changes": {"id": [None, 1], "title": [None, "Hello"]},
            "path": "/notes",
        },
    ]
    [row] = assert_audited(
        example.audit, database_engine, verb="entity.updated", actor_id="bob"
    )
    context = row["data"]["context"]
    assert context["remote_addr"] == "203.0.113.9"
    assert context["auth_method"] == "header"
    assert context["channel"] == "api"


# --- roles.sql ---------------------------------------------------------------

ROLES = ("audit_maintenance", "app_user", "audit_scrubber")
DENIED = "permission denied|must be owner"


def sql_section(name: str, names: dict[str, str]) -> list[str]:
    """Statements of one snippet section of ``roles.sql``, with names replaced."""
    source = (EXAMPLES / "roles.sql").read_text()
    match = re.search(
        rf"\[start:{name}\]\n(.*?)\n[^\n]*\[end:{name}\]", source, flags=re.DOTALL
    )
    assert match is not None, name
    body = "\n".join(
        line for line in match.group(1).splitlines() if not line.startswith("--")
    )
    for old, new in names.items():
        body = re.sub(rf"\b{old}\b", new, body)
    return [statement.strip() for statement in body.split(";") if statement.strip()]


class RolesEvent(AuditEvent):
    CHECKED = event("docs_roles.checked", Severity.NOTICE)


class Thing(DeclarativeBase):
    pass


class Gadget(Thing, Audited):
    __tablename__ = "gadget"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]


def test_roles_sql_grants_what_each_operation_needs(
    engine: Engine,
    database: str,
    database_engine: Engine,
    request: pytest.FixtureRequest,
) -> None:
    suffix = uuid.uuid4().hex[:8]
    names = {role: f"{role}_{suffix}" for role in ROLES} | {"app": database}
    password = uuid.uuid4().hex

    def drop_roles() -> None:
        # The database goes first: the roles own objects in it and hold a
        # privilege on it, and DROP ROLE refuses while they do.
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)'))
            for role in ROLES:
                conn.execute(text(f'DROP ROLE IF EXISTS "{names[role]}"'))

    request.addfinalizer(drop_roles)
    engines: list[Engine] = []

    def engine_as(role: str) -> Engine:
        eng = create_engine(
            url_of(engine, database, "psycopg", username=names[role], password=password)
        )
        engines.append(eng)
        return eng

    def dispose_engines() -> None:
        for eng in engines:
            eng.dispose()

    request.addfinalizer(dispose_engines)

    with database_engine.begin() as conn:
        for statement in sql_section("roles", names):
            conn.execute(text(statement))
        for role in ROLES[:2]:
            conn.execute(text(f"ALTER ROLE \"{names[role]}\" PASSWORD '{password}'"))
        # The application's own table, created by its own migrations.
        Thing.metadata.create_all(conn)
        conn.execute(
            text(f'GRANT SELECT, INSERT, UPDATE ON gadget TO "{names["app_user"]}"')
        )

    # Maintenance: migration, grants and partitions, including an old month.
    maintenance_engine = engine_as("audit_maintenance")
    maintenance = AuditTrail(maintenance_engine, events=[], allow_scrub=True)
    with maintenance_engine.begin() as conn:
        create_audit_tables(conn, maintenance.tables, maintenance.severities)
        for statement in sql_section("grants", names):
            conn.execute(text(statement))
    assert maintenance.maintenance.ensure_partitions()
    old = datetime(2020, 1, 15, tzinfo=UTC)
    with maintenance_engine.begin() as conn:
        ensure_partitions(conn, maintenance.tables, Severity, months_ahead=0, now=old)

    # The application role writes, durably too, and reads.
    app_engine = engine_as("app_user")
    app = AuditTrail(app_engine, events=[RolesEvent], on_error="raise")
    factory = sessionmaker(app_engine)
    app.install(factory)
    with (
        app.context(actor_type="user", actor_id="u1", remote_addr="192.0.2.1"),
        factory() as session,
    ):
        gadget = Gadget(id=1, name="a")
        session.add(gadget)
        session.commit()
        gadget.name = "b"
        session.commit()
        app.log(session, RolesEvent.CHECKED, obj=gadget, durable=True)
        assert len(app.query.list_groups(session).groups) == 3
        history = app.query.object_history(session, "Gadget", "1")
        assert len(history.groups) == 3
    app.dispose()
    assert app.maintenance.health().ok

    # ... and nothing else.
    with pytest.raises(ProgrammingError, match=DENIED):
        app.maintenance.ensure_partitions(months_ahead=6)
    with pytest.raises(ProgrammingError, match=DENIED):
        app.maintenance.drop_expired(dict.fromkeys(Severity, timedelta(days=1)))
    with pytest.raises(ProgrammingError, match=DENIED), app_engine.begin() as conn:
        conn.execute(text("UPDATE audit.audit_activity SET object_label = NULL"))
    app_scrub = AuditTrail(app_engine, events=[], allow_scrub=True)
    with pytest.raises(ProgrammingError, match=DENIED):
        app_scrub.scrub("Gadget", "1")

    # Maintenance: retention, scrub and health.
    dropped = maintenance.maintenance.drop_expired(
        dict.fromkeys(Severity, timedelta(days=365))
    )
    assert "audit.audit_transaction_p2020_01" in dropped
    assert maintenance.scrub("Gadget", "1") == ScrubResult(2, 0)
    assert maintenance.scrub_actor("u1") == ScrubResult(3, 3)
    assert maintenance.maintenance.health().ok
    maintenance.dispose()

    # The optional scrub-only role scrubs, and manages no partitions.
    with database_engine.begin() as conn:
        for statement in sql_section("scrubber", names):
            conn.execute(text(statement))
        scrubber_role = names["audit_scrubber"]
        conn.execute(text(f"ALTER ROLE \"{scrubber_role}\" PASSWORD '{password}'"))
    scrubber_engine = engine_as("audit_scrubber")
    scrubber = AuditTrail(scrubber_engine, events=[], allow_scrub=True)
    assert scrubber.scrub("Gadget", "1") == ScrubResult(0, 0)
    assert scrubber.scrub_actor("u1") == ScrubResult(0, 0)
    with pytest.raises(ProgrammingError, match=DENIED):
        scrubber.maintenance.ensure_partitions(months_ahead=6)
    scrubber.dispose()


# --- roles.sql with integrity ------------------------------------------------

INTEGRITY_ROLES = (*ROLES, "audit_sealer", "audit_verifier")
SIGNER = Ed25519Signer.from_seed("audit.example/sealer", bytes(range(32)))
INSERT_BLOCK = (
    "INSERT INTO audit.audit_seal_block (seq, kind, body, prev_hash, block_hash) "
    "VALUES (99, 'seal', '', '', '')"
)
BACKDATE = (
    "INSERT INTO audit.audit_transaction (actor_type, xid) VALUES ('x', '3'::xid8)"
)


class IntegrityRolesEvent(AuditEvent):
    CHECKED = event("docs_integrity_roles.checked", Severity.NOTICE)
    ALERTED = event("docs_integrity_roles.alerted", Severity.CRITICAL)


def denied(eng: Engine, *statements: str) -> None:
    """Each statement is refused for lack of a privilege."""
    for statement in statements:
        try:
            with eng.begin() as conn:
                conn.execute(text(statement))
        except ProgrammingError as exc:
            if not re.search(DENIED, str(exc)):
                pytest.fail(f"failed otherwise: {statement}: {exc}")
        else:
            pytest.fail(f"allowed: {statement}")


def write_gadget(trail: AuditTrail, factory: sessionmaker[Any], name: str) -> None:
    """One change of the gadget and one durable event: two transactions."""
    with trail.context(actor_id="u1", remote_addr="192.0.2.1"), factory() as session:
        gadget = session.get(Gadget, 1)
        if gadget is None:
            gadget = Gadget(id=1, name=name)
            session.add(gadget)
        else:
            gadget.name = name
        session.commit()
        trail.log(session, IntegrityRolesEvent.CHECKED, obj=gadget, durable=True)


def current_xid(eng: Engine) -> int:
    with eng.begin() as conn:
        return int(conn.execute(text("SELECT pg_current_xact_id()::text")).scalar_one())


@pytest.mark.filterwarnings("ignore:Did not recognize type 'xid8'")
def test_roles_sql_with_integrity_grants_what_each_role_needs(
    engine: Engine,
    database: str,
    database_engine: Engine,
    request: pytest.FixtureRequest,
) -> None:
    suffix = uuid.uuid4().hex[:8]
    names = {role: f"{role}_{suffix}" for role in INTEGRITY_ROLES} | {"app": database}
    password = uuid.uuid4().hex
    retention = dict.fromkeys(Severity, timedelta(days=365))

    def drop_roles() -> None:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)'))
            for role in INTEGRITY_ROLES:
                conn.execute(text(f'DROP ROLE IF EXISTS "{names[role]}"'))

    request.addfinalizer(drop_roles)
    trails: list[AuditTrail] = []

    def trail_as(role: str, **options: Any) -> AuditTrail:
        eng = create_engine(
            url_of(engine, database, "psycopg", username=names[role], password=password)
        )
        trail = AuditTrail(eng, events=[IntegrityRolesEvent], **options)
        trails.append(trail)
        return trail

    def dispose() -> None:
        for trail in trails:
            trail.dispose()
            assert isinstance(trail.engine, Engine)
            trail.engine.dispose()

    request.addfinalizer(dispose)

    def run_sections(eng: Engine, *sections: str) -> None:
        with eng.begin() as conn:
            for section in sections:
                for statement in sql_section(section, names):
                    # The scrubber role exists already, from 0.3.
                    if statement != f"CREATE ROLE {names['audit_scrubber']} LOGIN":
                        conn.execute(text(statement))
            for role in INTEGRITY_ROLES:
                exists = conn.execute(
                    text("SELECT 1 FROM pg_roles WHERE rolname = :role"),
                    {"role": names[role]},
                ).first()
                if exists:
                    conn.execute(
                        text(f"ALTER ROLE \"{names[role]}\" PASSWORD '{password}'")
                    )

    # 0.3: tables without integrity, the scrubber with UPDATE on the whole
    # tables, and entries written before the upgrade.
    scrubber_role = names["audit_scrubber"]
    with database_engine.begin() as conn:
        conn.execute(text(f'CREATE ROLE "{scrubber_role}" LOGIN'))
        Thing.metadata.create_all(conn)
    run_sections(database_engine, "roles")
    with database_engine.begin() as conn:
        conn.execute(
            text(f'GRANT SELECT, INSERT, UPDATE ON gadget TO "{names["app_user"]}"')
        )
    plain = trail_as("audit_maintenance")
    maintenance_engine = plain.engine
    assert isinstance(maintenance_engine, Engine)
    with maintenance_engine.begin() as conn:
        create_audit_tables(conn, plain.tables, plain.severities)
        for statement in sql_section("grants", names):
            conn.execute(text(statement))
        conn.execute(text(f'GRANT USAGE ON SCHEMA audit TO "{scrubber_role}"'))
        conn.execute(
            text(
                "GRANT SELECT, INSERT, UPDATE ON audit.audit_transaction, "
                f'audit.audit_activity TO "{scrubber_role}"'
            )
        )
    plain.maintenance.ensure_partitions()
    with maintenance_engine.begin() as conn:
        old = datetime(2020, 1, 15, tzinfo=UTC)
        ensure_partitions(conn, plain.tables, Severity, months_ahead=0, now=old)
    old_app = trail_as("app_user", on_error="raise")
    app_engine = old_app.engine
    assert isinstance(app_engine, Engine)
    old_factory = sessionmaker(app_engine)
    old_app.install(old_factory)
    write_gadget(old_app, old_factory, "before")

    # The upgrade, as the maintenance role: columns, indexes, grants.
    maintenance = trail_as("audit_maintenance", allow_scrub=True, integrity=Integrity())
    with maintenance_engine.begin() as conn:
        add_integrity(conn, maintenance.tables)
    with maintenance_engine.connect().execution_options(
        isolation_level="AUTOCOMMIT"
    ) as conn:
        add_integrity_indexes(conn, maintenance.tables)
    # The table-wide INSERT of 0.3 reaches the new xid column ...
    with app_engine.connect() as conn:
        conn.execute(text(BACKDATE))
        conn.rollback()
    with maintenance_engine.begin() as conn:
        for statement in sql_section("integrity", names):
            conn.execute(text(statement))
    # ... until the integrity grants replace it.
    denied(app_engine, BACKDATE)
    run_sections(database_engine, "scrubber")
    with maintenance_engine.begin() as conn:
        for statement in sql_section("integrity-scrubber", names):
            conn.execute(text(statement))
    run_sections(database_engine, "sealer", "verifier")

    # The application, upgraded, writes and reads; then the chain starts.
    app = trail_as("app_user", on_error="raise", integrity=Integrity())
    factory = sessionmaker(app_engine)
    app.install(factory)
    write_gadget(app, factory, "after")
    with maintenance_engine.begin() as conn:
        assert write_genesis(conn, maintenance.tables, signer=SIGNER).created
    write_gadget(app, factory, "sealed")
    with factory() as session:
        app.log(session, IntegrityRolesEvent.ALERTED, durable=True)
        assert len(app.query.object_history(session, "Gadget", "1").groups) == 6
    assert app.maintenance.health().seal is not None
    # ... and nothing else.
    denied(
        app_engine,
        BACKDATE,
        "INSERT INTO audit.audit_transaction (id, actor_type) "
        "OVERRIDING SYSTEM VALUE VALUES (999999, 'x')",
        "UPDATE audit.audit_activity SET object_label = NULL",
        "UPDATE audit.audit_activity SET seal_salts = NULL",
        "DELETE FROM audit.audit_activity",
        INSERT_BLOCK,
    )
    with pytest.raises(ProgrammingError, match=DENIED):
        app.maintenance.seal()

    # The sealer seals, exports checkpoints and declares forks.
    sealer = trail_as("audit_sealer", integrity=Integrity())
    sealer_engine = sealer.engine
    assert isinstance(sealer_engine, Engine)
    assert sealer.maintenance.seal(signer=SIGNER).blocks == 1
    assert sealer.maintenance.health().seal is not None
    with sealer_engine.connect() as conn:
        first = export_checkpoint(conn, sealer.tables, signer=SIGNER)
    # pg_monitor shows it the standbys' positions that pg_stat_replication
    # hides from other roles, as pg_stat_activity shows it others' queries.
    with database_engine.connect() as watched:
        pid = watched.execute(text("SELECT pg_backend_pid()")).scalar_one()
        with sealer_engine.connect() as conn:
            query = conn.execute(
                text("SELECT query FROM pg_stat_activity WHERE pid = :pid"),
                {"pid": pid},
            ).scalar_one()
    assert query == "SELECT pg_backend_pid()"
    with (
        sealer_engine.connect() as conn,
        pytest.raises(ReplicationError, match="NO_SYNC_STANDBY"),
    ):
        export_checkpoint(conn, sealer.tables, signer=SIGNER, require_replicated=True)
    # An id window, as after a restore on a managed service: the fork and
    # every later seal read the identity sequences.
    with sealer_engine.connect() as conn:
        fork = declare_fork(
            conn,
            sealer.tables,
            first,
            reason="role test",
            signer=SIGNER,
            id_window=True,
        )
    assert fork.id_floor is not None
    write_gadget(app, factory, "forked")
    assert sealer.maintenance.seal(signer=SIGNER).blocks == 1
    denied(
        sealer_engine,
        "UPDATE audit.audit_seal_block SET kind = kind",
        "DELETE FROM audit.audit_seal_block",
        "UPDATE audit.audit_activity SET object_label = NULL",
        "INSERT INTO audit.audit_transaction (actor_type) VALUES ('x')",
        "DELETE FROM audit.audit_transaction",
    )

    # The scrubber, narrowed from the table-wide UPDATE of 0.3, scrubs ...
    scrubber = trail_as("audit_scrubber", allow_scrub=True, integrity=Integrity())
    scrubbed = scrubber.scrub("Gadget", "1")
    assert scrubbed.activity_rows == 4
    assert scrubber.scrub_actor("u1") == ScrubResult(8, 8)
    # ... and can change nothing that the chain hashes in clear.
    scrubber_engine = scrubber.engine
    assert isinstance(scrubber_engine, Engine)
    denied(
        scrubber_engine,
        "UPDATE audit.audit_activity SET verb = 'x'",
        "UPDATE audit.audit_activity SET xid = xid",
        "UPDATE audit.audit_activity SET seal_commitments = seal_commitments",
        "UPDATE audit.audit_transaction SET actor_id = 'x'",
        "UPDATE audit.audit_transaction SET xid = xid",
        "DELETE FROM audit.audit_activity",
        BACKDATE,
        INSERT_BLOCK,
        "UPDATE audit.audit_seal_block SET kind = kind",
    )
    with pytest.raises(ProgrammingError, match=DENIED):
        scrubber.maintenance.ensure_partitions(months_ahead=6)

    # A writer still without Integrity: its rows lack commitments, and the
    # maintenance role waives them with an ack block.
    xid_from = current_xid(maintenance_engine)
    write_gadget(old_app, old_factory, "lagging")
    xid_to = current_xid(maintenance_engine)
    assert sealer.maintenance.seal(signer=SIGNER).blocks == 1
    ack = maintenance.maintenance.acknowledge(
        FailureKind.COMMITMENT_MISSING,
        {"xid_from": xid_from, "xid_to": xid_to},
        "a writer ran without Integrity during the deploy",
        signer=SIGNER,
    )
    assert ack > fork.seq
    with sealer_engine.connect() as conn:
        latest = export_checkpoint(conn, sealer.tables, signer=SIGNER).to_note()

    # Retention retires the old, empty partitions before it drops them, and
    # partitions created later are readable by the verifier too.
    dropped = maintenance.maintenance.drop_expired(retention, signer=SIGNER)
    assert "audit.audit_transaction_p2020_01" in dropped
    assert not dropped.skipped
    assert maintenance.maintenance.ensure_partitions(months_ahead=5)

    # The verifier verifies everything, and writes nothing.
    verifier = trail_as("audit_verifier", integrity=Integrity())
    report = verifier.maintenance.verify(
        retention=retention,
        checkpoints=[latest],
        verifier=Ed25519Verifier([SIGNER.vkey]),
        require_signatures=True,
    )
    assert report.failures == [], report.failures
    assert report.status is Status.VALID_WITH_NOTES
    assert report.anchor is Anchor.ANCHORED
    assert {NoteKind.ERASED, NoteKind.ACKNOWLEDGED, NoteKind.FORKED} <= report.kinds()
    assert verifier.maintenance.health().seal is not None
    verifier_engine = verifier.engine
    assert isinstance(verifier_engine, Engine)
    denied(
        verifier_engine,
        "INSERT INTO audit.audit_transaction (actor_type) VALUES ('x')",
        "UPDATE audit.audit_activity SET object_label = NULL",
        "DELETE FROM audit.audit_activity",
        INSERT_BLOCK,
        "UPDATE audit.audit_seal_block SET kind = kind",
    )
    with pytest.raises(ProgrammingError, match=DENIED):
        verifier.maintenance.seal()
    with (
        verifier_engine.connect() as conn,
        pytest.raises(ProgrammingError, match=DENIED),
    ):
        export_checkpoint(conn, verifier.tables)
