"""A logical-replication subscriber of the block table, for the integrity tests.

One container with ``wal_level=logical`` holds two databases: the publisher,
with the audit tables and a genesis block, publishes ``audit_seal_block``;
the subscriber, with the same tables, subscribes to it and has the genesis
block copied in.
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import NoReturn

import pytest
from sqlalchemy import Engine, create_engine, make_url, text
from sqlalchemy.orm import sessionmaker

from audit_trail import (
    AuditContext,
    AuditEvent,
    AuditTrail,
    Severity,
    event,
    migrations,
)
from audit_trail.integrity._options import Integrity
from audit_trail.tables import AuditTables
from tests.db.listener_support import create_trail

SUBSCRIPTION = "audit_blocks"


class ReplicaEvent(AuditEvent):
    NOTED = event("replica_test.noted", Severity.INFO)


@dataclass(frozen=True)
class Subscriber:
    """The two databases, each with its own trail on the ``audit`` schema."""

    publisher: Engine
    subscriber: Engine
    publisher_trail: AuditTrail
    subscriber_trail: AuditTrail

    @property
    def tables(self) -> AuditTables:
        return self.publisher_trail.tables


def write(trail: AuditTrail, engine: Engine) -> int:
    """Commit one audit entry through ``trail``; its xid."""
    factory = sessionmaker(engine)
    trail.install(factory)
    ann = AuditContext(actor_type="user", actor_id="ann")
    with trail.context(ann), factory() as session:
        trail.log(session, ReplicaEvent.NOTED, payload={"n": 1})
        xid = session.execute(text("SELECT pg_current_xact_id()::text"))
        value = int(xid.scalar_one())
        session.commit()
    return value


@contextmanager
def subscribed(engine: Engine) -> Iterator[Subscriber]:
    """Start the container, on ``engine``'s PostgreSQL major version.

    Skips the test without Docker, except in CI (``AUDIT_TEST_EXPECT_PG``
    set), where it fails.
    """
    try:
        from testcontainers.community.postgres import PostgresContainer
    except ImportError:  # pragma: no cover
        _cannot_run("testcontainers is not installed")
    with engine.connect() as conn:
        version = int(conn.execute(text("SHOW server_version_num")).scalar_one())
    try:
        container = PostgresContainer(
            f"postgres:{version // 10000}", driver="psycopg"
        ).with_command("postgres -c wal_level=logical")
        container.start()
    except Exception as exc:  # no Docker
        _cannot_run(f"cannot start a container: {exc}")
    try:
        url = make_url(container.get_connection_url())
        name = f"sub_{uuid.uuid4().hex[:8]}"
        publisher = create_engine(url)
        publisher_trail = _trail(publisher)
        tables = publisher_trail.tables
        with publisher.begin() as conn:
            migrations.write_genesis(conn, tables)
            conn.execute(
                text(f"CREATE PUBLICATION {SUBSCRIPTION} FOR TABLE {_block(tables)}")
            )
        with publisher.connect().execution_options(isolation_level="AUTOCOMMIT") as c:
            c.execute(text(f'CREATE DATABASE "{name}"'))
            # In the same cluster, the slot cannot be made by CREATE SUBSCRIPTION.
            c.execute(
                text("SELECT pg_create_logical_replication_slot(:slot, 'pgoutput')"),
                {"slot": name},
            )
        subscriber = create_engine(url.set(database=name))
        subscriber_trail = _trail(subscriber)
        conninfo = (
            f"host=localhost port=5432 dbname={url.database} "
            f"user={url.username} password={url.password}"
        )
        with subscriber.connect().execution_options(isolation_level="AUTOCOMMIT") as c:
            c.execute(
                text(
                    f"CREATE SUBSCRIPTION {SUBSCRIPTION} CONNECTION '{conninfo}' "
                    f"PUBLICATION {SUBSCRIPTION} "
                    f"WITH (create_slot = false, slot_name = '{name}')"
                )
            )
        _wait_for_copy(subscriber, tables)
        yield Subscriber(publisher, subscriber, publisher_trail, subscriber_trail)
        subscriber.dispose()
        publisher.dispose()
    finally:
        container.stop()


def _wait_for_copy(subscriber: Engine, tables: AuditTables) -> None:
    deadline = time.monotonic() + 30
    query = text(f"SELECT count(*) FROM {_block(tables)}")
    while time.monotonic() < deadline:
        with subscriber.connect() as conn:
            if conn.execute(query).scalar_one():
                return
        time.sleep(0.1)
    pytest.fail("the subscription did not copy the genesis block within 30 s")


def wait_for_rows(subscriber: Engine, tables: AuditTables, rows: int) -> None:
    """Wait until the subscriber's block table has ``rows`` rows."""
    deadline = time.monotonic() + 30
    query = text(f"SELECT count(*) FROM {_block(tables)}")
    while time.monotonic() < deadline:
        with subscriber.connect() as conn:
            if conn.execute(query).scalar_one() >= rows:
                return
        time.sleep(0.1)
    pytest.fail(f"the subscriber did not get {rows} blocks within 30 s")


def _trail(engine: Engine) -> AuditTrail:
    return create_trail(
        engine,
        "audit",
        severities=Severity,
        events=[ReplicaEvent],
        integrity=Integrity(),
    )


def _block(tables: AuditTables) -> str:
    block = tables.seal_block
    assert block is not None
    return f'"{block.schema}"."{block.name}"'


def _cannot_run(reason: str) -> NoReturn:
    if os.environ.get("AUDIT_TEST_EXPECT_PG"):
        pytest.fail(reason)
    pytest.skip(reason)
