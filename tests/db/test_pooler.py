"""Partition maintenance behind PgBouncer, in a Docker container.

PgBouncer runs with ``server_round_robin = 1`` and a few server connections
already open, so in ``transaction`` mode consecutive statements of one client
land on different backends. Skipped when Docker is not available.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from enum import IntEnum

import pytest
from sqlalchemy import Engine, create_engine, make_url, text
from sqlalchemy.exc import OperationalError

from audit_trail.maintenance import (
    PartitionError,
    drop_expired,
    ensure_partitions,
)
from audit_trail.migrations import create_audit_tables
from audit_trail.tables import AuditTables, build_tables

PGBOUNCER_IMAGE = "edoburu/pgbouncer:v1.26.1-p0"
SERVER_CONNECTIONS = 3


class Sev(IntEnum):
    INFO = 10
    NOTICE = 20


NOW = datetime(2026, 9, 10, 12, tzinfo=UTC)
RETENTION = dict.fromkeys(Sev, timedelta(days=30))


def _docker_available() -> bool:
    try:
        from testcontainers.core.docker_client import DockerClient

        DockerClient().client.ping()
    except Exception:
        return False
    return True


pytestmark = pytest.mark.skipif(not _docker_available(), reason="needs Docker")


def _pgbouncer(database_url: str, pool_mode: str) -> Iterator[Engine]:
    from testcontainers.core.container import DockerContainer

    url = make_url(database_url)
    # The container reaches a server published on the Docker host through
    # host.docker.internal.
    host = url.host or "localhost"
    if host in {"localhost", "127.0.0.1", "::1"}:
        host = "host.docker.internal"
    server = url.set(drivername="postgres", host=host, port=url.port or 5432)
    container = (
        DockerContainer(PGBOUNCER_IMAGE)
        .with_name(f"fixlock-pgbouncer-{uuid.uuid4().hex[:8]}")
        .with_env("DATABASE_URL", server.render_as_string(hide_password=False))
        .with_env("AUTH_TYPE", "scram-sha-256")
        .with_env("POOL_MODE", pool_mode)
        .with_env("SERVER_ROUND_ROBIN", "1")
        .with_env("DEFAULT_POOL_SIZE", str(SERVER_CONNECTIONS))
        .with_exposed_ports(5432)
        .with_kwargs(extra_hosts={"host.docker.internal": "host-gateway"})
    )
    with container:
        pooled = url.set(
            host=container.get_container_host_ip(),
            port=int(container.get_exposed_port(5432)),
        ).render_as_string(hide_password=False)
        # Prepared statements would need max_prepared_statements; keep it plain.
        engine = create_engine(
            pooled, connect_args={"prepare_threshold": None}, pool_pre_ping=True
        )
        _wait_until_ready(engine)
        _open_server_connections(engine)
        yield engine
        engine.dispose()


def _wait_until_ready(engine: Engine) -> None:
    deadline = time.monotonic() + 30
    while True:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except OperationalError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.2)


def _open_server_connections(engine: Engine) -> None:
    """Make PgBouncer open ``SERVER_CONNECTIONS`` backends, all left idle."""

    def hold(_: int) -> None:
        with engine.begin() as conn:
            conn.execute(text("SELECT pg_sleep(0.3)"))

    with ThreadPoolExecutor(SERVER_CONNECTIONS) as pool:
        list(pool.map(hold, range(SERVER_CONNECTIONS)))


@pytest.fixture
def transaction_pooled(database_url: str) -> Iterator[Engine]:
    yield from _pgbouncer(database_url, "transaction")


@pytest.fixture
def session_pooled(database_url: str) -> Iterator[Engine]:
    yield from _pgbouncer(database_url, "session")


@pytest.fixture
def tables(engine: Engine, schema: str) -> AuditTables:
    """Audit tables with monthly partitions from June to September 2026."""
    t = build_tables(schema=schema)
    with engine.begin() as conn:
        create_audit_tables(conn, t, Sev)
        ensure_partitions(
            conn, t, Sev, months_ahead=3, now=datetime(2026, 6, 5, tzinfo=UTC)
        )
    return t


def advisory_locks(engine: Engine) -> int:
    """Advisory locks held by any backend, seen from a direct connection."""
    with engine.connect() as conn:
        count: int = conn.execute(
            text("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory'")
        ).scalar_one()
        return count


def lock_timeouts(pooled: Engine) -> set[str]:
    """``lock_timeout`` of every pooled backend, one statement per backend."""
    with pooled.connect() as conn:
        auto = conn.execution_options(isolation_level="AUTOCOMMIT")
        return {
            auto.execute(text("SHOW lock_timeout")).scalar_one()
            for _ in range(2 * SERVER_CONNECTIONS)
        }


def backends(pooled: Engine) -> set[int]:
    with pooled.connect() as conn:
        auto = conn.execution_options(isolation_level="AUTOCOMMIT")
        return {
            auto.execute(text("SELECT pg_backend_pid()")).scalar_one()
            for _ in range(2 * SERVER_CONNECTIONS)
        }


def test_transaction_pooling_switches_backends(transaction_pooled: Engine) -> None:
    # The premise of the tests below.
    assert len(backends(transaction_pooled)) > 1


def test_drop_expired_refuses_transaction_pooling_and_leaks_nothing(
    engine: Engine, transaction_pooled: Engine, tables: AuditTables
) -> None:
    before = lock_timeouts(transaction_pooled)
    for _ in range(2):
        with transaction_pooled.connect() as conn:
            auto = conn.execution_options(isolation_level="AUTOCOMMIT")
            with pytest.raises(PartitionError, match="session-pooled connection"):
                drop_expired(auto, tables, RETENTION, now=NOW, lock_timeout="1s")

    assert advisory_locks(engine) == 0
    assert lock_timeouts(transaction_pooled) == before
    # Nothing was detached, and a direct connection still works afterwards.
    with engine.connect() as conn:
        auto = conn.execution_options(isolation_level="AUTOCOMMIT")
        dropped = drop_expired(auto, tables, RETENTION, now=NOW, lock_timeout="1s")
    assert len(dropped) == 3 * 2  # June and July of the three parents


def test_ensure_partitions_works_with_transaction_pooling(
    engine: Engine, transaction_pooled: Engine, tables: AuditTables
) -> None:
    before = lock_timeouts(transaction_pooled)
    with transaction_pooled.begin() as conn:
        created = ensure_partitions(
            conn, tables, Sev, months_ahead=3, now=NOW, lock_timeout="1s"
        )

    assert len(created) == 3 * 3  # October to December of the three parents
    assert advisory_locks(engine) == 0
    assert lock_timeouts(transaction_pooled) == before


def test_drop_expired_works_with_session_pooling(
    engine: Engine, session_pooled: Engine, tables: AuditTables
) -> None:
    for expected in (3 * 2, 0):
        with session_pooled.connect() as conn:
            auto = conn.execution_options(isolation_level="AUTOCOMMIT")
            before = auto.execute(text("SHOW lock_timeout")).scalar_one()
            dropped = drop_expired(auto, tables, RETENTION, now=NOW, lock_timeout="1s")
            assert auto.execute(text("SHOW lock_timeout")).scalar_one() == before
        assert len(dropped) == expected
    assert advisory_locks(engine) == 0
