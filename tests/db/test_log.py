"""``AuditTrail.log`` and the bulk statement warning."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import pytest
from pydantic import BaseModel
from sqlalchemy import Engine, ForeignKey, MetaData, delete, select, update
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from audit_trail import (
    Actor,
    AuditContext,
    Audited,
    AuditEvent,
    AuditOptions,
    AuditTrail,
    Pseudonymized,
    Severity,
    event,
)
from audit_trail.events import Crud, PayloadError, UnknownEventError
from audit_trail.serialization import KeyRing, pseudonymize
from tests.db.listener_support import Env, make_env

KEY = b"k" * 32


class Payment(BaseModel):
    amount: Decimal
    login: Pseudonymized[str | None] = None


class LogEvent(AuditEvent):
    VIEWED = event("log_test.viewed", Severity.NOTICE)
    PAID = event("log_test.paid", Severity.WARNING, Payment)
    DENIED = event("log_test.denied", Severity.CRITICAL, durable=True)
    LOCKED = event("log_test.locked", Severity.CRITICAL, fail_closed=True)


class UnregisteredEvent(AuditEvent):
    OTHER = event("log_test.other", Severity.NOTICE)


@dataclass
class Models:
    Folder: Any
    File: Any
    Plain: Any


@pytest.fixture
def models(engine: Engine, schema: str) -> Models:
    class Base(DeclarativeBase):
        metadata = MetaData(schema=schema)

    class Folder(Base, Audited):
        __tablename__ = "folder"
        id: Mapped[int] = mapped_column(primary_key=True)

    class File(Base, Audited):
        __tablename__ = "file"
        id: Mapped[int] = mapped_column(primary_key=True)
        folder_id: Mapped[int | None] = mapped_column(ForeignKey("folder.id"))
        name: Mapped[str] = mapped_column(default="")
        tenant: Mapped[str | None]

        __audit__ = AuditOptions(
            label=lambda file: file.name,
            scope=lambda file: file.tenant,
            target=lambda file: ("Folder", file.folder_id),
        )

    class Plain(Base):
        __tablename__ = "plain"
        id: Mapped[int] = mapped_column(primary_key=True)
        name: Mapped[str] = mapped_column(default="")

    Base.metadata.create_all(engine)
    return Models(Folder, File, Plain)


def log_env(engine: Engine, schema: str, **options: Any) -> Env:
    options.setdefault("pseudonymize_key", KEY)
    return make_env(engine, schema, severities=Severity, events=[LogEvent], **options)


@pytest.fixture
def env(engine: Engine, schema: str, models: Models) -> Env:
    return log_env(engine, schema)


def logged(env: Env) -> list[Any]:
    return [row for row in env.activities() if row["verb"].startswith("log_test.")]


def test_log_writes_an_entry_in_the_session_transaction(
    env: Env, models: Models
) -> None:
    ctx = AuditContext(actor_type="user", actor_id="1", channel="api")
    with env.factory() as session:
        env.trail.bind(session, ctx)
        file = models.File(id=5, folder_id=None, name="report.pdf", tenant="t1")
        session.add_all([models.Folder(id=9), file])
        session.flush()
        file.folder_id = 9
        env.trail.log(
            session,
            LogEvent.VIEWED,
            obj=file,
            payload={"reason": "support", "cost": Decimal("1.0")},
        )
        session.commit()

    rows = env.activities()
    row = rows[2]  # created Folder, created File, then the explicit entry
    assert row["verb"] == "log_test.viewed"
    assert row["severity"] == Severity.NOTICE
    assert (row["object_type"], row["object_id"]) == ("File", "5")
    assert row["object_label"] == "report.pdf"
    assert row["scope_id"] == "t1"
    assert (row["target_type"], row["target_id"]) == ("Folder", "9")
    assert row["actor_id"] == "1"
    assert row["data"] == {
        "v": 1,
        "payload": {"reason": "support", "cost": "1.0"},
        "context": {"actor_type": "user", "channel": "api"},
    }
    (transaction,) = env.transactions()
    assert {r["transaction_id"] for r in rows} == {transaction["id"]}
    assert row["created_at"] == transaction["issued_at"]


def test_log_is_rolled_back_with_the_session(env: Env) -> None:
    with env.factory() as session:
        env.trail.log(session, LogEvent.VIEWED)
        session.rollback()
    assert env.activities() == []
    assert env.transactions() == []


def test_actor_sets_the_entry_not_the_transaction_row(env: Env) -> None:
    ctx = AuditContext(
        actor_type="user", actor_id="Y", actor_label="y@x", channel="api"
    )
    with env.factory() as session:
        env.trail.bind(session, ctx)
        env.trail.log(
            session, LogEvent.VIEWED, actor=Actor(type="user", id="X", label="x@x")
        )
        env.trail.log(session, LogEvent.VIEWED)
        session.commit()

    (transaction,) = env.transactions()
    assert (transaction["actor_id"], transaction["actor_label"]) == ("Y", "y@x")
    first, second = env.activities()
    assert first["actor_id"] == "X"
    assert first["data"]["context"] == {
        "actor_type": "user",
        "actor_label": "x@x",
        "channel": "api",
    }
    assert second["actor_id"] == "Y"
    assert second["data"]["context"]["actor_label"] == "y@x"
    assert ctx.actor_id == "Y"  # the bound context is not modified


def test_targets_and_context_scope(env: Env, models: Models) -> None:
    with env.factory() as session:
        env.trail.bind(session, AuditContext(scope_id="ctx"))
        folder = models.Folder(id=3)
        session.add(folder)
        session.flush()
        env.trail.log(session, LogEvent.VIEWED, target=folder)
        env.trail.log(session, LogEvent.VIEWED, target=("Order", ("a", 1)))
        env.trail.log(session, LogEvent.VIEWED, target=("Order", 7))
        env.trail.log(session, LogEvent.VIEWED, target=("Order", None))
        session.commit()

    rows = logged(env)
    assert [(r["target_type"], r["target_id"]) for r in rows] == [
        ("Folder", "3"),
        ("Order", '["a","1"]'),
        ("Order", "7"),
        (None, None),
    ]
    assert {r["object_type"] for r in rows} == {None}
    assert {r["scope_id"] for r in rows} == {"ctx"}


def test_obj_and_target_need_a_primary_key(env: Env, models: Models) -> None:
    with env.factory() as session:
        file = models.File(name="new")
        folder = models.Folder()
        session.add_all([file, folder])
        with pytest.raises(ValueError, match="obj has no primary key yet; flush"):
            env.trail.log(session, LogEvent.VIEWED, obj=file)
        with pytest.raises(ValueError, match="target has no primary key yet"):
            env.trail.log(session, LogEvent.VIEWED, target=folder)


@pytest.mark.parametrize(
    ("kwargs", "error", "match"),
    [
        ({"event": UnregisteredEvent.OTHER}, UnknownEventError, "Unknown audit event"),
        ({"event": Crud.CREATED}, ValueError, "reserved"),
        ({"event": LogEvent.DENIED}, NotImplementedError, "durable writes"),
        (
            {"event": LogEvent.VIEWED, "durable": True},
            NotImplementedError,
            "durable writes",
        ),
        ({"event": LogEvent.LOCKED}, NotImplementedError, "durable writes"),
    ],
)
def test_refused_events(
    env: Env, kwargs: dict[str, Any], error: type[Exception], match: str
) -> None:
    with env.factory() as session:
        with pytest.raises(error, match=match):
            env.trail.log(session, **kwargs)
        session.commit()
    assert env.activities() == []


def test_log_needs_an_installed_session(
    engine: Engine, env: Env, models: Models
) -> None:
    with Session(engine) as session, pytest.raises(TypeError, match="installed"):
        env.trail.log(session, LogEvent.VIEWED)
    other = AuditTrail(engine, schema=env.trail.schema, events=[LogEvent])
    factory = sessionmaker(engine)
    other.install(factory)
    with factory() as session, pytest.raises(TypeError, match="installed"):
        env.trail.log(session, LogEvent.VIEWED)


def test_log_writes_when_capture_is_disabled(env: Env, models: Models) -> None:
    with env.factory() as session:
        session.info["audit_enabled"] = False
        session.add(models.Folder(id=1))
        env.trail.log(session, LogEvent.VIEWED)
        session.commit()
    assert [row["verb"] for row in env.activities()] == ["log_test.viewed"]


def test_schema_payload_is_pseudonymized(env: Env) -> None:
    with env.factory() as session:
        env.trail.log(
            session,
            LogEvent.PAID,
            payload=Payment(amount=Decimal("2.50"), login="alice"),
        )
        env.trail.log(session, LogEvent.PAID, payload={"amount": "3"})
        session.commit()

    first, second = logged(env)
    token = pseudonymize("alice", purpose="login", keys=KeyRing(KEY))
    assert first["data"]["payload"] == {"amount": "2.50", "login": token}
    assert second["data"]["payload"] == {"amount": "3", "login": None}


def test_payload_errors(env: Env) -> None:
    token = env.trail.pseudonymize("alice", purpose="login")
    with env.factory() as session:
        with pytest.raises(PayloadError, match="already holds a pseudonym"):
            env.trail.log(
                session, LogEvent.PAID, payload=Payment(amount=Decimal(1), login=token)
            )
        with pytest.raises(PayloadError, match="Invalid payload"):
            env.trail.log(session, LogEvent.PAID, payload={"amount": "x"})
        session.commit()
    assert env.activities() == []


def test_pseudonymized_field_needs_a_key(
    engine: Engine, schema: str, models: Models
) -> None:
    env = log_env(engine, schema, pseudonymize_key=None)
    with env.factory() as session:
        with pytest.raises(ValueError, match="configure pseudonymize_key"):
            env.trail.log(
                session,
                LogEvent.PAID,
                payload=Payment(amount=Decimal(1), login="alice"),
            )
        env.trail.log(session, LogEvent.PAID, payload=Payment(amount=Decimal(1)))
        session.commit()
    assert len(env.activities()) == 1


def test_failed_log_write_is_logged(
    engine: Engine, schema: str, models: Models, caplog: pytest.LogCaptureFixture
) -> None:
    env = log_env(engine, schema, partitions=[])
    with (
        caplog.at_level(logging.ERROR, logger="audit_trail"),
        env.factory() as session,
    ):
        env.trail.log(session, LogEvent.VIEWED)
        session.add(models.Plain(id=1))
        session.commit()
    assert env.activities() == []
    assert "no partition for the row" in caplog.text


BULK_WARNING = "bypasses the audit trail"


def bulk_statements(models: Models) -> list[tuple[Any, str]]:
    table = models.File.__table__
    return [
        (update(models.File).values(name="x"), "UPDATE"),
        (delete(models.File), "DELETE"),
        (update(table).values(name="y"), "UPDATE"),
        (delete(table), "DELETE"),
    ]


def test_bulk_statements_warn(
    env: Env, models: Models, caplog: pytest.LogCaptureFixture
) -> None:
    with env.factory() as session:
        session.add(models.File(id=1, name="a"))
        session.commit()
    for statement, kind in bulk_statements(models):
        caplog.clear()
        with (
            caplog.at_level(logging.WARNING, logger="audit_trail"),
            env.factory() as session,
        ):
            session.execute(statement)
            session.commit()
        assert f"Bulk {kind} of " in caplog.text, statement
        assert f".File {BULK_WARNING}" in caplog.text
    assert [row["verb"] for row in env.activities()] == ["entity.created"]


def test_bulk_warning_can_be_silenced(
    env: Env, models: Models, caplog: pytest.LogCaptureFixture
) -> None:
    statement = update(models.File).values(name="x")
    with (
        caplog.at_level(logging.WARNING, logger="audit_trail"),
        env.factory() as session,
    ):
        session.execute(statement.execution_options(audit_bulk_ok=True))
        session.execute(statement, execution_options={"audit_bulk_ok": True})
        session.execute(update(models.Plain).values(name="x"))  # not audited
        session.execute(select(models.File))  # not a bulk write
        session.info["audit_enabled"] = False
        session.execute(statement)
        session.commit()
    assert BULK_WARNING not in caplog.text


def test_warn_on_bulk_false(
    engine: Engine, models: Models, caplog: pytest.LogCaptureFixture, schema: str
) -> None:
    env = log_env(engine, schema, warn_on_bulk=False)
    with (
        caplog.at_level(logging.WARNING, logger="audit_trail"),
        env.factory() as session,
    ):
        session.execute(update(models.File).values(name="x"))
        session.commit()
    assert BULK_WARNING not in caplog.text
