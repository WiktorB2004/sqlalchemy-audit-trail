"""Small PostgreSQL helpers shared by the modules that talk to the database."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import text

if TYPE_CHECKING:
    from sqlalchemy import Connection, Table
    from sqlalchemy.exc import DBAPIError

UNIQUE_VIOLATION = "23505"
"""SQLSTATE of an insert that repeats a primary or unique key."""

CHECK_VIOLATION = "23514"
"""SQLSTATE of a row that fits no partition (and of other CHECK violations)."""

UNDEFINED_COLUMN = "42703"
"""SQLSTATE of a statement naming a column the table lacks."""

UNDEFINED_TABLE = "42P01"
"""SQLSTATE of a statement naming a relation that does not exist."""

LOCK_NOT_AVAILABLE = "55P03"
"""SQLSTATE raised when ``lock_timeout`` expires."""


XACT_LOCK = "pg_advisory_xact_lock(hashtext(:key))"
"""SQL that waits for the transaction-level advisory lock named by ``:key``."""

TRY_XACT_LOCK = "pg_try_advisory_xact_lock(hashtext(:key))"
"""SQL that tries the transaction-level advisory lock named by ``:key``."""

SUBSCRIBED = (
    "EXISTS (SELECT FROM pg_catalog.pg_subscription_rel "
    "WHERE srrelid = to_regclass(:table))"
)
"""SQL that is true when a logical-replication subscription of this database
writes into the table named by ``:table``, in any state, enabled or not.
Every role can read ``pg_subscription_rel``."""


def sqlstate(exc: DBAPIError) -> str | None:
    """The SQLSTATE of a database error, or ``None`` when the driver gives none.

    psycopg 3 names it ``sqlstate``, psycopg2 ``pgcode``.
    """
    orig = exc.orig
    code: str | None = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
    return code


def is_sqlstate(exc: DBAPIError, code: str) -> bool:
    """Tell whether a database error has the SQLSTATE ``code``."""
    return sqlstate(exc) == code


def set_config(connection: Connection, name: str, value: str, *, local: bool) -> str:
    """Set a setting for the transaction or the session; return the old value.

    Args:
        connection: Connection to set it on.
        name: The setting, e.g. ``lock_timeout``.
        value: Its new value.
        local: Set it for the rest of the transaction only, as ``SET LOCAL``.
    """
    previous: str = connection.execute(
        text("SELECT current_setting(:name)"), {"name": name}
    ).scalar_one()
    connection.execute(
        text("SELECT set_config(:name, :value, :local)"),
        {"name": name, "value": value, "local": local},
    )
    return previous


def execute_ddl(connection: Connection, statement: str) -> None:
    """Execute one DDL statement built by this library as-is.

    The statement goes to the driver without parameters, so ``%`` and ``:``
    inside quoted names are not taken for placeholders.

    Args:
        connection: Connection to run on.
        statement: A statement built by this library.
    """
    connection.exec_driver_sql(statement, execution_options={"no_parameters": True})


def lock_key(block: Table) -> str:
    """Key of the advisory lock that lets one writer of a seal chain run at a time."""
    return f"audit_trail.seal:{block.schema}.{block.name}"


def regclass(connection: Connection, table: Table) -> str:
    """The quoted, schema-qualified name of a table, as ``to_regclass`` takes it."""
    return connection.dialect.identifier_preparer.format_table(table)


def xact_lock(connection: Connection, key: str) -> None:
    """Wait for an advisory lock held until the transaction ends."""
    connection.execute(text(f"SELECT {XACT_LOCK}"), {"key": key})


def session_lock(connection: Connection, key: str) -> int:
    """Wait for an advisory lock held until ``session_unlock`` or disconnect.

    Returns the ``pg_backend_pid()`` of the backend that took it, which the
    caller compares with its own to tell whether a pooler moved it.
    """
    pid: int = connection.execute(
        text("SELECT pg_backend_pid() FROM pg_advisory_lock(hashtext(:key))"),
        {"key": key},
    ).scalar_one()
    return pid


def session_unlock(connection: Connection, key: str) -> tuple[bool, int]:
    """Release a lock taken by ``session_lock``.

    Returns whether this backend held the lock, and its ``pg_backend_pid()``.
    """
    unlocked, pid = connection.execute(
        text("SELECT pg_advisory_unlock(hashtext(:key)), pg_backend_pid()"),
        {"key": key},
    ).one()
    return bool(unlocked), int(pid)
