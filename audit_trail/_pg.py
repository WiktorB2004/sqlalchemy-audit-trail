"""Small PostgreSQL helpers shared by the modules that talk to the database."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import text

if TYPE_CHECKING:
    from sqlalchemy import Connection
    from sqlalchemy.exc import DBAPIError

CHECK_VIOLATION = "23514"
"""SQLSTATE of a row that fits no partition (and of other CHECK violations)."""

UNDEFINED_COLUMN = "42703"
"""SQLSTATE of a statement naming a column the table lacks."""

LOCK_NOT_AVAILABLE = "55P03"
"""SQLSTATE raised when ``lock_timeout`` expires."""


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
