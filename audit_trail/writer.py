"""Inserts into the audit tables, in-session and durable.

Everything here works on a Core ``Connection`` and never touches the ORM, so
it is safe to call from ``after_flush``.

A write in the caller's transaction is one ``audit_transaction`` row per
database transaction (inserted by the first entry, then reused) and one
``INSERT ... executemany`` of ``audit_activity`` rows per call. Rows are
never updated afterwards.

A durable write runs on the library's own connection, in its own transaction
holding one ``audit_transaction`` row and its activity rows, committed at
once and never through the caller's session.
"""

from __future__ import annotations

import functools
import logging
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import TYPE_CHECKING, NamedTuple, TypedDict, TypeVar, assert_never
from uuid import UUID

from sqlalchemy import Connection, Table, insert
from sqlalchemy.exc import DBAPIError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from audit_trail import _pg
from audit_trail._compaction import ActivityData
from audit_trail.context import AuditContext, ContextSnapshot, context_snapshot
from audit_trail.events import PayloadError
from audit_trail.integrity._canonical import CanonicalEncodingError
from audit_trail.integrity._commit import (
    activity_groups,
    seal_columns,
    transaction_groups,
)
from audit_trail.integrity._schema import has_integrity
from audit_trail.maintenance import PartitionError, ensure_partitions
from audit_trail.serialization import (
    JSONValue,
    KeyRing,
    encode_value,
    pseudonymize,
    pseudonymized_fields,
)

if TYPE_CHECKING:
    import json

    from pydantic import BaseModel

    from audit_trail.config import OnError
    from audit_trail.tables import AuditTables

logger = logging.getLogger(__name__)

CHECK_VIOLATION = _pg.CHECK_VIOLATION
UNDEFINED_COLUMN = _pg.UNDEFINED_COLUMN

MISSING_INTEGRITY_COLUMNS = (
    "Integrity is on, but the audit tables lack a column it writes; "
    "run migrations.add_integrity() on them"
)
"""What a write with integrity on reports when a column is missing."""
"""SQLSTATE of a row that fits no partition (and of other CHECK violations)."""

ENVELOPE_VERSION = 1
"""Value of ``data["v"]``."""

_NO_PARTITION = "no partition of relation"

# The prefix of a pseudonym token, for any purpose and key version.
_PSEUDONYM_PREFIX = re.compile(r"audit\.[a-z][a-z0-9_]*\.v[0-9]+:")

_T = TypeVar("_T")


class AuditWriteError(Exception):
    """A durable audit write failed and the write policy says to raise.

    Raised for ``fail_closed`` events, and for other durable writes with
    ``on_error="raise"``. The original error (a ``DBAPIError``, the pool's
    ``sqlalchemy.exc.TimeoutError``, a ``PartitionError``, a
    ``CanonicalEncodingError`` of an integrity commitment or, from ``alog``,
    a connection error the async driver raised unwrapped) is the
    ``__cause__``. Nothing of the entry was committed.
    """


class TransactionRow(NamedTuple):
    """The ``audit_transaction`` row the entries of one transaction share.

    Attributes:
        id: The row's ``id``.
        issued_at: The row's ``issued_at``, copied to ``created_at`` of every
            activity row.
        correlation_id: The row's ``correlation_id``, copied to every
            activity row.
    """

    id: int
    issued_at: datetime
    correlation_id: UUID | None


class _TransactionColumns(TypedDict):
    actor_type: str
    actor_id: str | None
    actor_label: str | None
    remote_addr: str | None
    user_agent: str | None
    method: str | None
    path: str | None
    channel: str | None
    auth_method: str | None
    request_id: UUID | None
    correlation_id: UUID | None


class TransactionValues(_TransactionColumns, total=False):
    """Column values of an ``audit_transaction`` row.

    ``meta`` is left out when the context has no ``extra``, so the column
    stays SQL ``NULL`` rather than JSON ``null``.
    """

    meta: dict[str, object]


class Entry(TypedDict):
    """One activity row before it is attached to a transaction row."""

    verb: str
    severity: int
    object_type: str | None
    object_id: str | None
    object_label: str | None
    target_type: str | None
    target_id: str | None
    actor_id: str | None
    scope_id: str | None
    data: ActivityData


class ActivityValues(Entry):
    """Column values of an ``audit_activity`` row, without the generated ``id``."""

    transaction_id: int
    correlation_id: UUID | None
    created_at: datetime


def encode_meta(
    extra: Mapping[str, object], json_encoder: type[json.JSONEncoder] | None
) -> dict[str, object]:
    """Encode ``AuditContext.extra`` for a JSON column.

    Args:
        extra: The host's extra context.
        json_encoder: Host encoder for types ``encode_value`` does not handle.

    Returns:
        JSON-native data.

    Raises:
        UnserializableValueError: A value cannot be encoded.
    """
    encoded = encode_value(dict(extra), json_encoder=json_encoder)
    assert isinstance(encoded, dict)  # a dict with str keys encodes to a dict
    result: dict[str, object] = {}
    result.update(encoded)
    return result


def context_data(
    ctx: AuditContext, json_encoder: type[json.JSONEncoder] | None
) -> ContextSnapshot:
    """Return the ``data.context`` snapshot of ``ctx`` with ``meta`` encoded.

    Args:
        ctx: The context of the entry.
        json_encoder: Host encoder for ``extra`` values.

    Returns:
        The snapshot, ready for a JSON column.

    Raises:
        UnserializableValueError: An ``extra`` value cannot be encoded.
    """
    snapshot = context_snapshot(ctx)
    if "meta" in snapshot:
        snapshot["meta"] = encode_meta(snapshot["meta"], json_encoder)
    return snapshot


def encode_payload(
    payload: dict[str, object] | BaseModel | None,
    *,
    keys: KeyRing | None,
    json_encoder: type[json.JSONEncoder] | None,
) -> dict[str, JSONValue]:
    """Encode a validated event payload for ``data["payload"]``.

    A pydantic model is dumped (Python mode) and its ``Pseudonymized`` fields
    are replaced with ``pseudonymize(value, purpose=<field name>)``; ``None``
    stays ``None``.

    Args:
        payload: The result of ``validate_payload``.
        keys: Key ring for ``Pseudonymized`` fields.
        json_encoder: Host encoder for types ``encode_value`` does not handle.

    Returns:
        JSON-native data; ``{}`` for no payload.

    Raises:
        PayloadError: A ``Pseudonymized`` field already holds a pseudonym
            token, which would be pseudonymized twice.
        ValueError: A ``Pseudonymized`` field has a value and no
            ``pseudonymize_key`` is configured, or its name is not a valid
            purpose (snake_case).
        UnserializableValueError: A value cannot be encoded.
    """
    if payload is None:
        return {}
    if isinstance(payload, dict):
        values = payload
    else:
        values = payload.model_dump(mode="python")
        for name in sorted(pseudonymized_fields(type(payload))):
            value = values.get(name)
            if value is None:
                continue
            if isinstance(value, str) and _PSEUDONYM_PREFIX.match(value):
                raise PayloadError(
                    f"{type(payload).__name__}.{name} is Pseudonymized but already "
                    "holds a pseudonym token; pass the raw value"
                )
            if keys is None:
                raise ValueError(
                    f"{type(payload).__name__}.{name} is Pseudonymized; "
                    "configure pseudonymize_key"
                )
            values[name] = pseudonymize(
                value, purpose=name, keys=keys, json_encoder=json_encoder
            )
    encoded = encode_value(values, json_encoder=json_encoder)
    assert isinstance(encoded, dict)  # a dict with str keys encodes to a dict
    return encoded


def transaction_values(
    ctx: AuditContext, json_encoder: type[json.JSONEncoder] | None
) -> TransactionValues:
    """Build the ``audit_transaction`` row for a context.

    Args:
        ctx: The context when the row is created.
        json_encoder: Host encoder for ``extra`` values.

    Returns:
        The column values.

    Raises:
        UnserializableValueError: An ``extra`` value cannot be encoded.
    """
    values: TransactionValues = {
        "actor_type": ctx.actor_type,
        "actor_id": ctx.actor_id,
        "actor_label": ctx.actor_label,
        "remote_addr": ctx.remote_addr,
        "user_agent": ctx.user_agent,
        "method": ctx.method,
        "path": ctx.path,
        "channel": ctx.channel,
        "auth_method": ctx.auth_method,
        "request_id": ctx.request_id,
        "correlation_id": ctx.correlation_id,
    }
    if ctx.extra:
        values["meta"] = encode_meta(ctx.extra, json_encoder)
    return values


def insert_transaction(
    connection: Connection, table: Table, values: TransactionValues
) -> TransactionRow:
    """Insert an ``audit_transaction`` row.

    On a table with the integrity columns, the row gets fresh commitments and
    salts on every call, so a retried write never reuses a salt.

    Args:
        connection: Connection in the transaction being audited.
        table: The ``audit_transaction`` table.
        values: The row, from ``transaction_values``.

    Returns:
        The inserted row's ``id``, ``issued_at`` and ``correlation_id``.
    """
    statement = insert(table).returning(
        table.c.id, table.c.issued_at, table.c.correlation_id
    )
    row: Mapping[str, object] = values
    if has_integrity(table):
        row = {**values, **seal_columns(transaction_groups(values))}
    row_id, issued_at, correlation_id = connection.execute(statement, row).one()
    return TransactionRow(row_id, issued_at, correlation_id)


def insert_activities(
    connection: Connection,
    table: Table,
    transaction: TransactionRow,
    entries: Sequence[Entry],
) -> None:
    """Insert activity rows with one ``executemany``.

    Every row gets the transaction row's ``id``, ``issued_at`` (as
    ``created_at``) and ``correlation_id``.

    Args:
        connection: Connection in the transaction being audited.
        table: The ``audit_activity`` table.
        transaction: The transaction row the entries belong to.
        entries: The entries; nothing is executed when empty.
    """
    if not entries:
        return
    connection.execute(insert(table), activity_rows(table, transaction, entries))


def activity_rows(
    table: Table, transaction: TransactionRow, entries: Sequence[Entry]
) -> list[dict[str, object]]:
    """Build the ``audit_activity`` rows of ``insert_activities``.

    Every row has the same keys: ``executemany`` takes its column list from
    the first row, raises for a later row that lacks a key and silently drops
    a key the first row does not have. On a table with the integrity columns
    each row also gets ``SealColumns``, with fresh salts.

    Args:
        table: The ``audit_activity`` table.
        transaction: The transaction row the entries belong to.
        entries: The entries.

    Returns:
        The rows, in the order of ``entries``.

    Raises:
        CanonicalEncodingError: An erasable value has no canonical encoding.
    """
    sealed = has_integrity(table)
    rows: list[dict[str, object]] = []
    for entry in entries:
        values: ActivityValues = {
            **entry,
            "transaction_id": transaction.id,
            "correlation_id": transaction.correlation_id,
            "created_at": transaction.issued_at,
        }
        row: dict[str, object] = dict(values)
        if sealed:
            groups = activity_groups(entry["object_label"], entry["data"])
            row.update(seal_columns(groups))
        rows.append(row)
    return rows


def run_isolated(
    connection: Connection,
    on_error: OnError,
    work: Callable[[], _T],
    *,
    integrity: bool = False,
) -> _T | None:
    """Run an audit write according to the ``on_error`` policy.

    ``"raise"`` runs ``work`` directly; any error propagates and fails the
    caller's transaction. ``"log"`` runs it inside a savepoint on the
    connection (never a ``Session`` savepoint, which would snapshot and later
    restore the unit of work in the middle of a flush). A ``DBAPIError``, or
    a ``CanonicalEncodingError`` refusing a value an integrity commitment
    cannot encode, rolls the savepoint back, is logged and swallowed, so the
    caller's transaction continues without the audit rows. A missing
    partition (SQLSTATE ``23514``) is logged as such; it is not retried.
    Other exceptions always propagate.

    With ``integrity``, a missing column (SQLSTATE ``42703``) is reported as
    ``MISSING_INTEGRITY_COLUMNS``: in the log message, or as a note on the
    raised error.

    Args:
        connection: Connection in the transaction being audited.
        on_error: The write policy.
        work: The inserts to run.
        integrity: The audit tables were built with the integrity columns.

    Returns:
        What ``work`` returned, or ``None`` when a failure was logged.
    """
    match on_error:
        case "raise":
            try:
                return work()
            except DBAPIError as exc:
                if is_missing_integrity_column(exc, integrity):
                    exc.add_note(MISSING_INTEGRITY_COLUMNS)
                raise
        case "log":
            try:
                with connection.begin_nested():
                    return work()
            except (DBAPIError, CanonicalEncodingError) as exc:
                _log_failure(exc, integrity)
                return None
        case _:
            assert_never(on_error)


def is_missing_partition(exc: DBAPIError) -> bool:
    """Tell whether a database error is a row that fits no partition.

    Args:
        exc: The error.

    Returns:
        ``True`` for SQLSTATE ``23514`` with PostgreSQL's "no partition of
        relation" message.
    """
    return _pg.is_sqlstate(exc, CHECK_VIOLATION) and _NO_PARTITION in str(exc.orig)


def is_missing_integrity_column(exc: BaseException, integrity: bool) -> bool:
    """Tell whether a write with integrity on failed on a missing column.

    It looks only at the error; the write path runs no extra query.

    Args:
        exc: The error.
        integrity: The audit tables were built with the integrity columns.

    Returns:
        ``True`` for SQLSTATE ``42703`` when ``integrity`` is set.
    """
    return (
        integrity
        and isinstance(exc, DBAPIError)
        and _pg.is_sqlstate(exc, UNDEFINED_COLUMN)
    )


def _log_failure(exc: DBAPIError | CanonicalEncodingError, integrity: bool) -> None:
    if isinstance(exc, DBAPIError) and is_missing_partition(exc):
        logger.error(
            "Audit entries were not written: no partition for the row (%s). "
            "Run ensure_partitions; the business transaction continues.",
            str(exc.orig).strip(),
        )
        return
    if is_missing_integrity_column(exc, integrity):
        logger.error(
            "Audit entries were not written: %s. The business transaction continues.",
            MISSING_INTEGRITY_COLUMNS,
            exc_info=exc,
        )
        return
    logger.error(
        "Audit entries were not written; the business transaction continues.",
        exc_info=exc,
    )


def write_durable(
    connection: Connection,
    tables: AuditTables,
    severities: Sequence[int],
    values: TransactionValues,
    entries: Sequence[Entry],
    *,
    auto_create_partitions: bool,
) -> TransactionRow:
    """Write one ``audit_transaction`` row and its entries, and commit.

    Runs its own transactions on ``connection``, which must be idle and not
    in ``AUTOCOMMIT`` mode. With ``auto_create_partitions``, a row that fits
    no partition (SQLSTATE ``23514``) makes it create the missing partitions
    with ``ensure_partitions`` in a separate transaction on the same
    connection and retry once.

    Args:
        connection: A connection of the durable engine.
        tables: The audit tables.
        severities: Severity values to create partitions for on a retry.
        values: The ``audit_transaction`` row.
        entries: The entries.
        auto_create_partitions: Create missing partitions and retry once.

    Returns:
        The committed transaction row.

    Raises:
        DBAPIError: An insert failed (on the retry, when there was one).
        PartitionError: Creating the partitions failed, for example
            ``PartitionLockTimeoutError``.
        CanonicalEncodingError: An integrity commitment cannot encode a
            value of the entry; nothing was inserted.
    """

    def insert_all() -> TransactionRow:
        with connection.begin():
            row = insert_transaction(connection, tables.transaction, values)
            insert_activities(connection, tables.activity, row, entries)
        return row

    try:
        return insert_all()
    except DBAPIError as exc:
        if not (auto_create_partitions and is_missing_partition(exc)):
            raise
    # The partitions are created here, on the connection that already holds
    # the failed write, rather than through PartitionManager on the main
    # engine: that needs no second checkout from a pool that may be the
    # exhausted one, it works whether log() or alog() is writing, and it is
    # still a transaction of its own, separate from the caller's session
    # (ensure_partitions refuses AUTOCOMMIT).
    with connection.begin():
        created = ensure_partitions(connection, tables, severities)
    logger.warning(
        "A durable audit write found no partition for its row; created %s "
        "and retried once. Run ensure_partitions ahead of time.",
        ", ".join(created) or "nothing (another process created them)",
    )
    return insert_all()


DURABLE_WRITE_ERRORS = (
    DBAPIError,
    PoolTimeoutError,
    PartitionError,
    CanonicalEncodingError,
)
"""Failures of a durable write that the write policy handles."""


@functools.cache
def async_durable_write_errors() -> tuple[type[Exception], ...]:
    """Failures of an async durable write that the write policy handles.

    ``DURABLE_WRITE_ERRORS`` plus what asyncpg raises unwrapped when it
    cannot connect; psycopg (sync and async) wraps all of these in a
    ``DBAPIError``. Each extra type is needed:

    - ``OSError``: asyncpg, SQLAlchemy 2.0 and 2.1: an unreachable server
      (``ConnectionRefusedError``), an unresolvable host
      (``socket.gaierror``), no route to host, TLS failures, and the connect
      timeout (``TimeoutError``; ``asyncio.TimeoutError`` is the same class).
    - ``asyncpg.PostgresError``: asyncpg, SQLAlchemy 2.0 only: the server
      refusing the connection (missing database, bad password, too many
      connections, closed during the handshake); 2.1 wraps it.

    Returns:
        The exception types; ``asyncpg.PostgresError`` only when asyncpg is
        installed.
    """
    errors = (*DURABLE_WRITE_ERRORS, OSError)
    try:
        from asyncpg import PostgresError  # type: ignore[import-untyped]
    except ImportError:  # asyncpg is an optional driver
        return errors
    return (*errors, PostgresError)


def handle_durable_failure(
    exc: Exception,
    on_error: OnError,
    fail_closed: bool,
    *,
    integrity: bool = False,
) -> None:
    """Apply the write policy to a failed durable write.

    A ``fail_closed`` write, or any durable write with ``on_error="raise"``,
    raises ``AuditWriteError``; otherwise the failure is logged. With
    ``integrity``, a missing column (SQLSTATE ``42703``) is reported as
    ``MISSING_INTEGRITY_COLUMNS`` in the error or the log message.

    Args:
        exc: The failure, one of ``DURABLE_WRITE_ERRORS`` or, from ``alog``,
            ``async_durable_write_errors()``.
        on_error: The write policy.
        fail_closed: The entry must not be lost; always raise.
        integrity: The audit tables were built with the integrity columns.

    Raises:
        AuditWriteError: The policy says to raise; ``exc`` is the cause.
    """
    hint = ""
    if is_missing_integrity_column(exc, integrity):
        hint = f": {MISSING_INTEGRITY_COLUMNS}"
    if fail_closed:
        raise AuditWriteError(
            f"a fail_closed audit entry was not written{hint}"
        ) from exc
    match on_error:
        case "raise":
            raise AuditWriteError(
                f"a durable audit entry was not written{hint}"
            ) from exc
        case "log":
            if isinstance(exc, DBAPIError) and is_missing_partition(exc):
                logger.error(
                    "A durable audit entry was not written: no partition for "
                    "the row (%s). Run ensure_partitions.",
                    str(exc.orig).strip(),
                )
            else:
                logger.error(
                    "A durable audit entry was not written%s.", hint, exc_info=exc
                )
        case _:
            assert_never(on_error)
