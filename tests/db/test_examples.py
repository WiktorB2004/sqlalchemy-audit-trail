"""The scripts under ``examples/``, which the documentation includes.

Each quickstart runs in a database of its own, created for the test, so it
can keep its default ``audit`` schema and public tables. ``roles.sql`` is run
with unique role names, and every operation is tried as each role.
"""

from __future__ import annotations

import asyncio
import importlib.util
import re
import sys
import uuid
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType

import httpx
import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from audit_trail import Audited, AuditEvent, AuditTrail, Severity, event
from audit_trail.maintenance import ensure_partitions
from audit_trail.migrations import create_audit_tables
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
    old = datetime(2020, 1, 15, tzinfo=timezone.utc)
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
