"""Durable and ``fail_closed`` entries written by ``AuditTrail.log``."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pytest
from sqlalchemy import Engine, MetaData, create_engine, inspect, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from audit_trail import AuditContext, Audited, AuditEvent, Severity, event
from audit_trail.maintenance import PartitionLockTimeoutError, ensure_partitions
from audit_trail.writer import AuditWriteError
from tests.db.listener_support import Env, logged_error, make_env

CAP = 15
"""Seconds after which a test that should not block fails instead of hanging."""


class DurableEvent(AuditEvent):
    NOTED = event("durable_test.noted", Severity.INFO)
    DENIED = event("durable_test.denied", Severity.CRITICAL, durable=True)
    LOCKED = event("durable_test.locked", Severity.CRITICAL, fail_closed=True)


@dataclass
class Models:
    Account: Any


@pytest.fixture
def models(engine: Engine, schema: str) -> Models:
    class Base(DeclarativeBase):
        metadata = MetaData(schema=schema)

    class Account(Base, Audited):
        __tablename__ = "account"
        id: Mapped[int] = mapped_column(primary_key=True)
        name: Mapped[str] = mapped_column(default="")

    Base.metadata.create_all(engine)
    return Models(Account)


EnvMaker = Callable[..., Env]


@pytest.fixture
def make(engine: Engine, schema: str, models: Models) -> Iterator[EnvMaker]:
    """Builds envs for the test's schema and disposes their durable engines."""
    made: list[Env] = []

    def build(**options: Any) -> Env:
        options.setdefault("events", [DurableEvent])
        options.setdefault("severities", Severity)
        env = make_env(engine, schema, **options)
        made.append(env)
        return env

    yield build
    for env in made:
        env.trail.dispose()


def verbs(env: Env) -> list[str]:
    return [row["verb"] for row in env.activities()]


def partitions(engine: Engine, schema: str) -> set[str]:
    return set(inspect(engine).get_table_names(schema=schema))


def test_durable_entry_is_committed_before_log_returns_and_survives_rollback(
    make: EnvMaker, models: Models
) -> None:
    env = make()
    ctx = AuditContext(
        actor_type="user",
        actor_id="7",
        remote_addr="10.0.0.1",
        request_id=uuid.uuid4(),
    )
    with env.trail.context(ctx), env.factory() as session:
        account = models.Account(name="a")
        session.add(account)
        session.flush()
        env.trail.log(session, DurableEvent.DENIED, obj=account)
        # Visible to another connection while the session is still open.
        assert verbs(env) == ["durable_test.denied"]
        session.rollback()

    row = env.activities()[0]
    assert verbs(env) == ["durable_test.denied"]  # entity.created rolled back
    (transaction,) = env.transactions()
    assert row["transaction_id"] == transaction["id"]
    assert row["created_at"] == transaction["issued_at"]
    assert transaction["actor_id"] == "7"
    assert str(transaction["remote_addr"]) == "10.0.0.1"
    assert transaction["correlation_id"] == ctx.correlation_id
    assert row["correlation_id"] == ctx.correlation_id
    assert (row["object_type"], row["object_label"]) == ("Account", None)
    assert row["actor_id"] == "7"
    assert str(row["data"]["context"]["remote_addr"]) == "10.0.0.1"


def test_durable_entry_has_its_own_transaction_row(
    make: EnvMaker, models: Models
) -> None:
    env = make()
    with env.factory() as session:
        session.add(models.Account(name="a"))
        session.flush()  # the session's transaction row
        env.trail.log(session, DurableEvent.NOTED, durable=True)
        env.trail.log(session, DurableEvent.DENIED, durable=False)
        session.commit()

    rows = {row["verb"]: row for row in env.activities()}
    assert set(rows) == {"entity.created", "durable_test.noted", "durable_test.denied"}
    assert (
        rows["durable_test.denied"]["transaction_id"]
        == (rows["entity.created"]["transaction_id"])
    )
    assert (
        rows["durable_test.noted"]["transaction_id"]
        != (rows["entity.created"]["transaction_id"])
    )
    assert len(env.transactions()) == 2


def test_durable_false_does_not_weaken_fail_closed(make: EnvMaker) -> None:
    env = make()
    with env.factory() as session, pytest.raises(ValueError, match="cannot weaken"):
        env.trail.log(session, DurableEvent.LOCKED, durable=False)
    assert env.activities() == []


def test_fail_closed_raises_even_with_on_error_log(make: EnvMaker) -> None:
    env = make(partitions=[], on_error="log")  # every write fails with 23514
    with env.factory() as session:
        with pytest.raises(AuditWriteError, match="fail_closed") as raised:
            env.trail.log(session, DurableEvent.LOCKED)
        session.commit()
    cause = raised.value.__cause__
    assert isinstance(cause, DBAPIError)
    assert "no partition of relation" in str(cause.orig)
    assert env.transactions() == []


def test_durable_failure_is_logged_with_on_error_log(
    make: EnvMaker, models: Models, caplog: pytest.LogCaptureFixture
) -> None:
    env = make(partitions=[Severity.INFO])  # the CRITICAL entry fits no partition
    with (
        caplog.at_level(logging.ERROR, logger="audit_trail"),
        env.factory() as session,
    ):
        env.trail.log(session, DurableEvent.DENIED)
        session.add(models.Account(name="business"))
        session.commit()

    assert verbs(env) == ["entity.created"]
    assert "durable audit entry was not written: no partition" in caplog.text


def test_durable_failure_raises_with_on_error_raise(
    make: EnvMaker, models: Models
) -> None:
    env = make(partitions=[Severity.INFO], on_error="raise")
    with env.factory() as session:
        session.add(models.Account(name="business"))
        session.flush()
        with pytest.raises(AuditWriteError, match="durable") as raised:
            env.trail.log(session, DurableEvent.DENIED)
        session.commit()  # the session's own transaction is unaffected

    assert isinstance(raised.value.__cause__, DBAPIError)
    assert verbs(env) == ["entity.created"]


@pytest.mark.parametrize("verb", [DurableEvent.DENIED, DurableEvent.LOCKED])
def test_missing_severity_partition_is_created_and_retried(
    engine: Engine,
    schema: str,
    make: EnvMaker,
    verb: DurableEvent,
    caplog: pytest.LogCaptureFixture,
) -> None:
    env = make(auto_create_partitions=True)
    with engine.begin() as conn:  # the CRITICAL severity with all its months
        conn.execute(text(f'DROP TABLE "{schema}".audit_activity_40'))
    with (
        caplog.at_level(logging.WARNING, logger="audit_trail"),
        env.factory() as session,
    ):
        env.trail.log(session, verb)

    assert verbs(env) == [verb.value]
    assert "audit_activity_40" in partitions(engine, schema)
    assert "created" in caplog.text and "retried once" in caplog.text


@pytest.mark.parametrize("verb", [DurableEvent.DENIED, DurableEvent.LOCKED])
def test_missing_month_partition_is_created_and_retried(
    engine: Engine, schema: str, make: EnvMaker, verb: DurableEvent
) -> None:
    env = make(partitions=[], auto_create_partitions=True)
    past = datetime(2020, 1, 15, tzinfo=timezone.utc)
    with engine.begin() as conn:  # every severity, but only January 2020
        ensure_partitions(conn, env.trail.tables, Severity, months_ahead=0, now=past)
    this_month = datetime.now(timezone.utc).strftime("p%Y_%m")
    assert f"audit_transaction_{this_month}" not in partitions(engine, schema)

    with env.factory() as session:
        env.trail.log(session, verb)

    assert verbs(env) == [verb.value]
    assert f"audit_transaction_{this_month}" in partitions(engine, schema)


def test_failed_partition_creation_goes_to_the_policy(
    engine: Engine, schema: str, make: EnvMaker
) -> None:
    env = make(partitions=[Severity.INFO], auto_create_partitions=True)
    table = f'"{schema}".audit_activity'
    with engine.connect() as blocker, ThreadPoolExecutor(max_workers=1) as pool:
        blocker.execute(text(f"LOCK TABLE {table} IN ACCESS SHARE MODE"))
        try:

            def log_locked() -> None:
                with env.factory() as session:
                    env.trail.log(session, DurableEvent.LOCKED)

            attempt = pool.submit(log_locked)
            # ensure_partitions gives up after its 5 s lock timeout; a
            # regression fails here instead of hanging.
            with pytest.raises(AuditWriteError) as raised:
                attempt.result(timeout=CAP)
        finally:
            blocker.rollback()

    assert isinstance(raised.value.__cause__, PartitionLockTimeoutError)
    assert env.activities() == []


@pytest.mark.parametrize(
    ("on_error", "verb", "raises"),
    [
        ("log", DurableEvent.DENIED, False),
        ("raise", DurableEvent.DENIED, True),
        ("log", DurableEvent.LOCKED, True),
    ],
)
def test_exhausted_durable_pool_times_out(
    database_url: str,
    make: EnvMaker,
    on_error: str,
    verb: DurableEvent,
    raises: bool,
    caplog: pytest.LogCaptureFixture,
) -> None:
    durable = create_engine(database_url, pool_size=1, max_overflow=0, pool_timeout=0.3)
    env = make(durable_engine=durable, on_error=on_error)
    held = durable.connect()  # the only connection of the pool

    def log_once() -> None:
        with env.factory() as session:
            env.trail.log(session, verb)

    try:
        with (
            caplog.at_level(logging.ERROR, logger="audit_trail"),
            ThreadPoolExecutor(max_workers=1) as pool,
        ):
            attempt = pool.submit(log_once)
            try:
                # A deadlock fails here after CAP seconds instead of hanging.
                if raises:
                    with pytest.raises(AuditWriteError) as raised:
                        attempt.result(timeout=CAP)
                    assert isinstance(raised.value.__cause__, PoolTimeoutError)
                else:
                    attempt.result(timeout=CAP)
                    assert isinstance(logged_error(caplog), PoolTimeoutError)
            finally:
                held.close()  # also releases a hung attempt
    finally:
        durable.dispose()
    assert env.activities() == []


def test_log_refuses_an_async_durable_engine(database_url: str, make: EnvMaker) -> None:
    durable = create_async_engine(
        database_url.replace("+psycopg", "+asyncpg", 1)
    )  # never connects
    env = make(durable_engine=durable)
    with env.factory() as session, pytest.raises(TypeError, match="use alog"):
        env.trail.log(session, DurableEvent.DENIED)
    assert env.activities() == []
