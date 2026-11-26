"""Integrity columns, commitments and scrub stamps against a real PostgreSQL.

Every test that checks a commitment recomputes it from the row as read back
through the driver, which is what the verifier will do.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import pytest
from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st
from sqlalchemy import (
    Column,
    Connection,
    Engine,
    Integer,
    MetaData,
    RowMapping,
    Table,
    Text,
    bindparam,
    cast,
    insert,
    inspect,
    select,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import DBAPIError, StatementError
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from audit_trail import (
    AuditContext,
    Audited,
    AuditEvent,
    AuditOptions,
    AuditTrail,
    Severity,
    event,
    migrations,
)
from audit_trail.integrity import _commit
from audit_trail.integrity._canonical import CanonicalEncodingError, canonical
from audit_trail.integrity._commit import (
    activity_groups,
    commitment,
    inet_text,
    transaction_groups,
)
from audit_trail.integrity._options import Integrity
from audit_trail.integrity._types import Xid8
from audit_trail.maintenance import ensure_partitions
from audit_trail.migrations import create_audit_tables
from audit_trail.tables import build_tables
from tests.db.listener_support import (
    SESSION_KINDS,
    Env,
    SessionKind,
    each_session_kind,
    make_env,
    record_statements,
    session_kind,
)

# Reflection does not know xid8; the tests only read the column's name,
# nullability and default.
pytestmark = pytest.mark.filterwarnings("ignore:Did not recognize type 'xid8'")

ANN = AuditContext(
    actor_type="user",
    actor_id="ann",
    actor_label="Ann",
    remote_addr="2001:DB8::0:1",
    user_agent="Firefox",
    extra={"tenant": 7, "ratio": -0.0},
)
ADMIN = AuditContext(actor_type="user", actor_id="admin", actor_label="Admin")


class IntegrityEvent(AuditEvent):
    NOTED = event("integrity_test.noted", Severity.INFO)
    KEPT = event("integrity_test.kept", Severity.INFO, durable=True)


@dataclass
class Models:
    Doc: Any


@pytest.fixture
def models(engine: Engine, schema: str) -> Models:
    class Base(DeclarativeBase):
        metadata = MetaData(schema=schema)

    class Doc(Base, Audited):
        __tablename__ = "doc"
        id: Mapped[int] = mapped_column(primary_key=True)
        title: Mapped[str] = mapped_column(default="")
        size: Mapped[float] = mapped_column(default=0.0)

        __audit__ = AuditOptions(label=lambda doc: doc.title)

    Base.metadata.create_all(engine)
    return Models(Doc)


OPTIONS: dict[str, Any] = {
    "events": [IntegrityEvent],
    "severities": Severity,
    "integrity": Integrity(),
    "allow_scrub": True,
}


@pytest.fixture
def env(engine: Engine, schema: str, models: Models) -> Iterator[Env]:
    built = make_env(engine, schema, **OPTIONS)
    yield built
    built.trail.dispose()


@pytest.fixture
async def kind(request: pytest.FixtureRequest, engine: Engine) -> Any:
    async with session_kind(request.param, engine) as k:
        yield k


def b64(value: str) -> bytes:
    return base64.b64decode(value)


def check_commitments(row: RowMapping, groups: Mapping[str, object]) -> None:
    """Every present group has a salt, and its commitment matches the value."""
    present = {group for group, value in groups.items() if value is not None}
    assert set(row["seal_salts"]) == present
    assert present <= set(row["seal_commitments"])
    for group in present:
        salt = b64(row["seal_salts"][group])
        expected = b64(row["seal_commitments"][group])
        assert commitment(group, salt, groups[group]) == expected


def check_activity(row: RowMapping) -> None:
    check_commitments(row, activity_groups(row["object_label"], row["data"]))


def check_transaction(row: RowMapping) -> None:
    check_commitments(row, transaction_groups(dict(row)))


def write_doc(env: Env, models: Models) -> int:
    """Create, update and log about a Doc in one transaction; return its xid."""
    with env.trail.context(ANN), env.factory() as session:
        doc = models.Doc(id=1, title="Doc One", size=1e16)
        session.add(doc)
        session.flush()
        doc.title = "Renamed"
        doc.size = -0.0
        session.flush()
        env.trail.log(
            session,
            IntegrityEvent.NOTED,
            obj=doc,
            payload={"email": "ann@example.com", "\U0001f600": 1.50, "\ue000": None},
        )
        current = session.execute(text("SELECT pg_current_xact_id()::text"))
        xid = int(current.scalar_one())
        session.commit()
    return xid


@pytest.mark.parametrize("kind", SESSION_KINDS, indirect=True)
async def test_flush_and_log_rows_carry_xid_and_commitments(
    engine: Engine, schema: str, models: Models, kind: SessionKind
) -> None:
    env = make_env(engine, schema, kind, **OPTIONS)

    @each_session_kind
    def body(kind: SessionKind) -> None:
        xid = write_doc(env, models)
        (transaction,) = env.transactions()
        activities = env.activities()
        assert [row["verb"] for row in activities] == [
            "entity.created",
            "entity.updated",
            IntegrityEvent.NOTED.value,
        ]
        assert transaction["xid"] == xid
        assert all(row["xid"] == xid for row in activities)
        check_transaction(transaction)
        assert set(transaction["seal_salts"]) == {"actor"}
        for row in activities:
            check_activity(row)
            assert row["seal_erased"] is None
            assert set(row["seal_commitments"]) == set(row["seal_salts"])
        assert set(activities[0]["seal_salts"]) == {"label", "changes", "actor"}
        assert set(activities[2]["seal_salts"]) == {"label", "payload", "actor"}

    await body(kind=kind)


def test_salts_are_never_shared(env: Env, models: Models) -> None:
    write_doc(env, models)
    salts = [
        salt
        for row in [*env.transactions(), *env.activities()]
        for salt in row["seal_salts"].values()
    ]
    assert len(salts) == 10
    assert len(set(salts)) == len(salts)
    assert all(len(b64(salt)) == 16 for salt in salts)


def test_null_columns_are_sql_null(env: Env, models: Models) -> None:
    with env.trail.context(AuditContext(actor_type="system")), env.factory() as s:
        s.add(models.Doc(id=1))
        s.commit()
    table = env.trail.tables.activity
    with env.engine.connect() as conn:
        row = conn.execute(
            select(
                table.c.seal_erased.is_(None),
                table.c.seal_commitments,
                table.c.seal_salts,
            )
        ).one()
    # Python None in seal_erased is SQL NULL, not JSON null; no actor group.
    assert row[0] is True
    assert set(row[1]) == set(row[2]) == {"label", "changes"}


def test_durable_entries_get_commitments(env: Env) -> None:
    with env.trail.context(ANN), env.factory() as session:
        env.trail.log(session, IntegrityEvent.KEPT, payload={"n": 2**70})
    (transaction,) = env.transactions()
    (activity,) = env.activities()
    check_transaction(transaction)
    check_activity(activity)
    assert set(activity["seal_salts"]) == {"payload", "actor"}
    assert activity["xid"] == transaction["xid"]


def test_a_durable_retry_never_reuses_a_salt(
    engine: Engine, schema: str, models: Models, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No partitions: the first attempt fails with 23514 on the transaction
    # row, the partitions are created and the write is retried.
    env = make_env(
        engine, schema, partitions=[], auto_create_partitions=True, **OPTIONS
    )
    drawn: list[bytes] = []
    real = _commit.new_salt

    def recording() -> bytes:
        salt = real()
        drawn.append(salt)
        return salt

    monkeypatch.setattr(_commit, "new_salt", recording)
    try:
        with env.trail.context(ANN), env.factory() as session:
            env.trail.log(session, IntegrityEvent.KEPT, payload={"a": 1})
    finally:
        env.trail.dispose()

    (transaction,) = env.transactions()
    (activity,) = env.activities()
    stored = b64(transaction["seal_salts"]["actor"])
    # Attempt one drew the transaction row's salt, attempt two drew it again
    # plus the activity row's two.
    assert len(drawn) == 4
    assert stored == drawn[1] != drawn[0]
    assert len(set(drawn)) == 4
    check_transaction(transaction)
    check_activity(activity)


def scrubbed_record(env: Env) -> RowMapping:
    (record,) = [r for r in env.activities() if r["verb"] == "audit.scrubbed"]
    return record


def erased_is_null(env: Env, row_id: int) -> bool:
    table = env.trail.tables.activity
    with env.engine.connect() as conn:
        result: bool = conn.execute(
            select(table.c.seal_erased.is_(None)).where(table.c.id == row_id)
        ).scalar_one()
    return result


def test_scrub_removes_salts_and_points_to_its_record(env: Env, models: Models) -> None:
    write_doc(env, models)
    before = {row["id"]: row for row in env.activities()}
    # The pointer is set on a SQL NULL seal_erased, which a bare || would lose.
    assert all(erased_is_null(env, row_id) for row_id in before)

    with env.trail.context(ADMIN):
        result = env.trail.scrub("Doc", "1")

    assert result.activity_rows == 3
    record = scrubbed_record(env)
    check_activity(record)
    pointer = str(record["xid"])
    for row in env.activities():
        if row["verb"] == "audit.scrubbed":
            continue
        old = before[row["id"]]
        assert row["seal_commitments"] == old["seal_commitments"]
        assert set(row["seal_salts"]) == {"actor"}
        assert row["seal_salts"]["actor"] == old["seal_salts"]["actor"]
        assert row["seal_erased"] == {
            "label": pointer,
            "changes": pointer,
            "payload": pointer,
        }
        # What is left is still verifiable.
        groups = activity_groups(row["object_label"], row["data"])
        check_commitments(row, {"actor": groups["actor"]})


def test_scrub_stamping_is_idempotent(env: Env, models: Models) -> None:
    write_doc(env, models)
    with env.trail.context(ADMIN):
        env.trail.scrub("Doc", "1")
    first = {row["id"]: row for row in env.activities()}

    with env.trail.context(ADMIN):
        again = env.trail.scrub("Doc", "1")

    assert again.activity_rows == 0
    for row in env.activities():
        if row["id"] in first:
            assert row["seal_erased"] == first[row["id"]]["seal_erased"]
            assert row["seal_salts"] == first[row["id"]]["seal_salts"]


def test_scrub_actor_stamps_both_tables_and_keeps_earlier_stamps(
    env: Env, models: Models
) -> None:
    write_doc(env, models)
    with env.trail.context(ADMIN):
        env.trail.scrub("Doc", "1")
        result = env.trail.scrub_actor("ann")

    assert result.transaction_rows == 1
    assert result.activity_rows == 3
    records = [r for r in env.activities() if r["verb"] == "audit.scrubbed"]
    scrub_xid, actor_xid = (str(r["xid"]) for r in records)
    assert scrub_xid != actor_xid
    (transaction, *_) = env.transactions()
    assert transaction["actor_id"] == "ann"
    assert transaction["seal_salts"] == {}
    assert transaction["seal_erased"] == {"actor": actor_xid}
    for row in env.activities():
        if row["verb"] == "audit.scrubbed":
            continue
        assert row["seal_salts"] == {}
        assert row["seal_erased"] == {
            "label": scrub_xid,
            "changes": scrub_xid,
            "payload": scrub_xid,
            "actor": actor_xid,
        }


def test_reads_never_select_integrity_columns(env: Env, models: Models) -> None:
    write_doc(env, models)
    with record_statements(env.engine) as log, env.factory() as session:
        log.recording = True
        page = env.trail.query.list_groups(session)
        (group,) = page.groups
        activity = group.activities[0]
        detail = env.trail.query.get(session, activity["id"], activity["created_at"])
        log.recording = False
    assert detail is not None
    selects = [s for s in log.statements if s.lstrip().upper().startswith("SELECT")]
    assert selects
    for statement in selects:
        assert "seal_" not in statement
        assert ".xid" not in statement


def test_tables_without_integrity_have_no_new_columns(
    engine: Engine, schema: str
) -> None:
    env = make_env(engine, schema, events=[], severities=Severity)
    columns = inspect(engine).get_columns("audit_activity", schema=schema)
    names = {column["name"] for column in columns}
    assert "data" in names
    assert not names & {"xid", "seal_commitments", "seal_salts", "seal_erased"}
    assert env.trail.integrity is None


# -- migrations.add_integrity ------------------------------------------------


def columns_of(engine: Engine, schema: str, table: str) -> dict[str, Any]:
    return {c["name"]: c for c in inspect(engine).get_columns(table, schema=schema)}


def test_fresh_install_has_a_not_null_xid(env: Env, schema: str) -> None:
    for table in ("audit_transaction", "audit_activity"):
        xid = columns_of(env.engine, schema, table)["xid"]
        assert xid["nullable"] is False
        assert "pg_current_xact_id()" in str(xid["default"])


@pytest.fixture
def old_install(engine: Engine, schema: str, models: Models) -> Iterator[Env]:
    """An install without integrity holding one entry."""
    old = make_env(engine, schema, events=[IntegrityEvent], severities=Severity)
    with old.trail.context(ANN), old.factory() as session:
        session.add(models.Doc(id=1, title="Old"))
        session.commit()
    yield old
    old.trail.dispose()


def test_add_integrity_upgrades_an_existing_install(
    engine: Engine, schema: str, models: Models, old_install: Env
) -> None:
    with engine.begin() as conn:
        migrations.add_integrity(conn, old_install.trail.tables)
    with engine.begin() as conn:  # idempotent
        migrations.add_integrity(conn, old_install.trail.tables)

    for table in ("audit_transaction", "audit_activity"):
        xid = columns_of(engine, schema, table)["xid"]
        assert xid["nullable"] is True
        assert "pg_current_xact_id()" in str(xid["default"])
    indexes = {
        index["name"]
        for table in ("audit_transaction", "audit_activity")
        for index in inspect(engine).get_indexes(table, schema=schema)
    }
    assert {"audit_transaction_xid_idx", "audit_activity_xid_idx"} <= indexes

    new = AuditTrail(engine, schema=schema, **OPTIONS)
    factory = sessionmaker(engine)
    new.install(factory)
    with new.context(ANN), factory() as session:
        new.log(session, IntegrityEvent.NOTED, payload={"a": 1})
        session.commit()
    old_row, new_row = Env(engine, new, factory).activities()
    # The old row was not stamped with the migration's xid.
    assert old_row["xid"] is None
    assert old_row["seal_commitments"] is None
    assert new_row["xid"] is not None
    check_activity(new_row)


def lock_parent(engine: Engine, schema: str) -> Connection:
    """A connection holding a lock that blocks ALTER TABLE on the activity parent."""
    blocker = engine.connect()
    blocker.execute(text(f'LOCK TABLE "{schema}".audit_activity IN ACCESS SHARE MODE'))
    return blocker


def test_add_integrity_gives_up_after_its_attempts(
    engine: Engine,
    schema: str,
    old_install: Env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(migrations, "_sleep", lambda seconds: None)
    blocker = lock_parent(engine, schema)
    try:
        with engine.begin() as conn, pytest.raises(DBAPIError) as info:
            migrations.add_integrity(
                conn, old_install.trail.tables, lock_timeout="50ms", attempts=2
            )
    finally:
        blocker.close()
    assert getattr(info.value.orig, "sqlstate", None) == "55P03"
    # Nothing was changed, on the blocked table or the one before it.
    for table in ("audit_transaction", "audit_activity"):
        assert "xid" not in columns_of(engine, schema, table)


def test_add_integrity_retries_a_lock_timeout(
    engine: Engine,
    schema: str,
    old_install: Env,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    blocker = lock_parent(engine, schema)
    pauses: list[float] = []

    def release(seconds: float) -> None:
        pauses.append(seconds)
        blocker.rollback()

    monkeypatch.setattr(migrations, "_sleep", release)
    try:
        with engine.begin() as conn:
            migrations.add_integrity(
                conn, old_install.trail.tables, lock_timeout="50ms", attempts=3
            )
            timeout = conn.execute(text("SHOW lock_timeout")).scalar()
    finally:
        blocker.close()
    assert len(pauses) == 1
    assert 0 <= pauses[0] <= 0.5
    assert "attempt 1 of 3" in caplog.text
    assert timeout == "0"  # the session's setting is back
    assert "xid" in columns_of(engine, schema, "audit_activity")


# -- driver behaviour ----------------------------------------------------------


@pytest.fixture
def scratch(engine: Engine, schema: str) -> Table:
    metadata = MetaData(schema=schema)
    table = Table(
        "scratch",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("a", Integer),
        Column("b", Integer),
    )
    metadata.create_all(engine)
    return table


def test_executemany_needs_the_first_rows_keys_in_every_row(
    engine: Engine, scratch: Table
) -> None:
    # Why every writer row carries the same keys, in both directions.
    missing = "A value is required for bind parameter 'b', in parameter group 1"
    with engine.begin() as conn, pytest.raises(StatementError, match=missing):
        conn.execute(insert(scratch), [{"id": 1, "a": 1, "b": 1}, {"id": 2, "a": 2}])
    with engine.begin() as conn:
        conn.execute(insert(scratch), [{"id": 1, "a": 1}, {"id": 2, "a": 2, "b": 2}])
        rows = conn.execute(select(scratch).order_by(scratch.c.id)).all()
    assert [tuple(row) for row in rows] == [(1, 1, None), (2, 2, None)]


async def test_xid8_round_trip(async_engine: AsyncEngine) -> None:
    async with async_engine.connect() as conn:
        current: str = (
            await conn.execute(text("SELECT pg_current_xact_id()::text"))
        ).scalar_one()
        value = bindparam("x", int(current), type_=Xid8())
        row = (
            await conn.execute(
                select(
                    value,
                    cast(text("pg_current_xact_id()"), Xid8()) == value,
                    cast(text("pg_snapshot_xmin(pg_current_snapshot())"), Xid8())
                    <= bindparam("y", int(current), type_=Xid8()),
                    bindparam("small", 5, type_=Xid8()),
                )
            )
        ).one()
    assert row == (int(current), True, True, 5)


# -- canonical encoding survives JSONB -------------------------------------------

_keys = st.text(st.characters(exclude_categories=["Cs"], exclude_characters="\x00"))
_scalars = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-(10**40), max_value=10**40)
    | st.floats(allow_nan=False, allow_infinity=False)
    | _keys
)
JSON_VALUES = st.recursive(
    _scalars,
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(_keys, children, max_size=4)
    ),
    max_leaves=12,
)


@settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(value=JSON_VALUES)
@example(value={"a": -0.0, "b": 1e16, "c": 1.5e300, "d": 5e-324, "e": 2**60})
@example(value={"\ue000": 1, "\U0001f600": 2, "a": [12345678901234567890.0]})
async def test_canonical_survives_a_jsonb_round_trip(
    async_engine: AsyncEngine, value: object
) -> None:
    jsonb = cast(bindparam("v", value, type_=JSONB), JSONB)
    async with async_engine.connect() as conn:
        back, as_text = (await conn.execute(select(jsonb, jsonb.cast(Text)))).one()
    assert canonical(back) == canonical(value)
    # A reader that parses floats as Decimal gets the same bytes too.
    assert canonical(json.loads(as_text, parse_float=Decimal)) == canonical(value)


_prefixed = st.one_of(
    st.tuples(st.ip_addresses(v=4), st.integers(0, 32)),
    st.tuples(st.ip_addresses(v=6), st.integers(0, 128)),
)


@settings(max_examples=300, deadline=None)
@given(address=_prefixed)
@example(address=("::ffff:1.2.3.4", 128))
@example(address=("::102:304", 128))
@example(address=("::ffff:0:0", 128))
@example(address=("::1", 128))
@example(address=("::2", 128))
@example(address=("1:0:0:2:0:0:0:3", 128))
@example(address=("0:0:1::", 128))
@example(address=("1:0:2:3:4:5:6:7", 64))
def test_inet_text_matches_postgres(engine: Engine, address: tuple[Any, int]) -> None:
    ip, prefix = address
    given_text = f"{str(ip).upper()}/{prefix}"
    # format() uses inet's output function; ::text would always add the prefix.
    with engine.connect() as conn:
        shown: str = conn.execute(
            text("SELECT format('%s', CAST(:v AS inet))"), {"v": given_text}
        ).scalar_one()
    assert inet_text(given_text) == shown
    assert inet_text(shown) == shown


def inet_shown(engine: Engine, value: str) -> str | None:
    """What PostgreSQL shows for ``value`` cast to inet, ``None`` if it rejects it."""
    with engine.connect() as conn:
        try:
            shown: str = conn.execute(
                text("SELECT format('%s', CAST(:v AS inet))"), {"v": value}
            ).scalar_one()
        except DBAPIError:
            return None
    return shown


_octet = st.integers(0, 300).map(str) | st.integers(0, 255).map(lambda n: f"0{n}")
_space = st.sampled_from(["", " ", "\t", "\n", "\u00a0"])
_loose_v4 = st.builds(
    lambda octets, dot: ".".join(octets) + dot,
    st.lists(_octet, min_size=1, max_size=5),
    st.sampled_from(["", "."]),
)
_loose_v6 = st.builds(
    lambda ip, upper, tail: (str(ip).upper() if upper else str(ip)) + tail,
    st.ip_addresses(v=6),
    st.booleans(),
    st.sampled_from(["", "%eth0", "%1", ".", ":", "::"]),
)
_loose_prefix = st.sampled_from(["", "/", "/0", "/00", "/8", "/024", "/32"]) | (
    st.integers(-1, 130).map(lambda n: f"/{n}")
)
LOOSE_ADDRESSES = st.builds(
    lambda lead, address, prefix, trail: lead + address + prefix + trail,
    _space,
    _loose_v4 | _loose_v6,
    _loose_prefix | st.just("/255.255.255.0"),
    _space,
)


@settings(max_examples=300, deadline=None)
@given(value=LOOSE_ADDRESSES)
@example(value="01.02.03.04")
@example(value="1.2.3/24")
@example(value="10/8")
@example(value="1.2.3.4.")
@example(value="::1.2.3")
@example(value=" 1.2.3.4")
@example(value="1.2.3.4/024")
@example(value="::1/0128")
def test_inet_text_never_commits_to_another_text(engine: Engine, value: str) -> None:
    # Either the value is refused, or PostgreSQL stores exactly that text.
    try:
        committed = inet_text(value)
    except CanonicalEncodingError:
        return
    assert inet_shown(engine, value) == committed


def test_create_tables_with_integrity_gives_partitions_the_columns(
    engine: Engine, schema: str
) -> None:
    tables = build_tables(schema=schema, integrity=True)
    with engine.begin() as conn:
        create_audit_tables(conn, tables, Severity)
        ensure_partitions(conn, tables, list(Severity), months_ahead=0)
    names = set(columns_of(engine, schema, "audit_activity_20"))
    assert {"xid", "seal_commitments", "seal_salts", "seal_erased"} <= names
