"""``verify`` and ``acknowledge`` against the database.

Private for now. ``verify`` reads the chain and then each partition in short
``READ ONLY`` transactions, one per chunk of rows in ``(xid, id)`` order, and
feeds them to the pure ``Verifier``. It never holds one snapshot over the
whole log: a long snapshot would hold back vacuum and block ``DETACH ...
CONCURRENTLY``, and sealed rows need none. ``acknowledge`` appends an ``ack``
block to the chain, under the sealer's lock.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import (
    Column,
    Connection,
    Engine,
    MetaData,
    Table,
    bindparam,
    func,
    select,
    text,
    tuple_,
)

from audit_trail import _pg
from audit_trail.integrity import _schema
from audit_trail.integrity._block import ack_body, parse_body
from audit_trail.integrity._seal import (
    _insert,
    _last,
    _missing,
    _regclass,
    block_table,
)
from audit_trail.integrity._types import Xid8
from audit_trail.integrity._verify import (
    ACTIVITY,
    TRANSACTION,
    FailureKind,
    Partition,
    StoredBlock,
    VerificationReport,
    Verifier,
    check_scope,
    failure_kind,
    stream_retention,
)
from audit_trail.maintenance import _children, _oid, _orphans, _qualified
from audit_trail.tables import AuditTables

DEFAULT_CHUNK_ROWS = 2_000
"""Rows read per ``READ ONLY`` transaction."""

_BLOCK_CHUNK = 1_000


class VerifyBusyError(RuntimeError):
    """Another ``verify`` of the same chain is running."""


@dataclass(frozen=True)
class _Leaf:
    partition: Partition
    schema: str


def verify_lock_key(block: Table) -> str:
    """Key of the advisory lock that lets one ``verify`` of a chain run."""
    return f"audit_trail.verify:{block.schema}.{block.name}"


def verify(
    engine: Engine,
    tables: AuditTables,
    *,
    retention: Mapping[int, timedelta | None] | None = None,
    transaction_retention: timedelta | None = None,
    system_severity: int | None = None,
    chunk_rows: int = DEFAULT_CHUNK_ROWS,
) -> VerificationReport:
    """Check the hash chain and every row it seals; report all failures.

    Private for now. Runs on connections of its own from ``engine``. One
    run per chain at a time: a session-level advisory try-lock is held on
    one connection, which stays idle outside a transaction while the others
    read. The chain and the catalog are read first, then each partition in
    chunks of ``chunk_rows`` rows, each in its own short ``READ ONLY``
    transaction, keyset-paged by ``(xid, id)``.

    Args:
        engine: An engine whose role can read the audit tables, the block
            table and the catalog.
        tables: Audit tables built with integrity.
        retention: Retention by severity, as ``drop_expired`` takes it.
            Given, a retire block whose partition was still inside its
            retention is ``RETIRED_EARLY``.
        transaction_retention: Retention of the transaction table, as
            ``drop_expired`` takes it.
        system_severity: Severity of the ``audit.scrubbed`` records, the
            trail's ``system_severity``. Given, an erasure whose record was
            sealed into a retired partition of that severity is
            ``ERASED_RECEIPT_RETIRED``; otherwise it is
            ``SCRUB_COUNT_MISMATCH``.
        chunk_rows: Rows read per transaction, at least 1.

    Returns:
        The report.

    Raises:
        ValueError: The tables were built without integrity, the chain has
            no genesis block, or ``chunk_rows`` is below 1.
        VerifyBusyError: Another ``verify`` of this chain is running.
    """
    if chunk_rows < 1:
        raise ValueError("chunk_rows must be at least 1")
    block = block_table(tables)
    streams = None
    if retention is not None:
        streams = stream_retention(retention, transaction_retention)
    with engine.connect() as lock:
        key = verify_lock_key(block)
        locked = lock.execute(
            text("SELECT pg_try_advisory_lock(hashtext(:key))"), {"key": key}
        ).scalar_one()
        lock.commit()
        if not locked:
            raise VerifyBusyError("another verify of this chain is running")
        try:
            return _verify(engine, tables, block, streams, system_severity, chunk_rows)
        finally:
            lock.execute(
                text("SELECT pg_advisory_unlock(hashtext(:key))"), {"key": key}
            )
            lock.commit()


def _verify(
    engine: Engine,
    tables: AuditTables,
    block: Table,
    streams: dict[str, timedelta | None] | None,
    system_severity: int | None,
    chunk_rows: int,
) -> VerificationReport:
    with engine.connect() as conn:
        with _read_only(conn):
            horizon, xmax = (
                int(value)
                for value in conn.execute(
                    text(
                        "SELECT pg_snapshot_xmin(s)::text, pg_snapshot_xmax(s)::text "
                        "FROM pg_current_snapshot() AS s"
                    )
                ).one()
            )
        stored = list(_blocks(conn, block))
        if not stored:
            raise ValueError(
                f"{block.fullname} has no genesis block; run "
                "migrations.write_genesis() first"
            )
        verifier = Verifier(
            stored,
            horizon=horizon,
            xmax=xmax,
            retention=streams,
            system_severity=system_severity,
        )
        with _read_only(conn):
            leaves, detached = _catalog(conn, tables)
        for leaf in leaves:
            parent = (
                tables.transaction
                if leaf.partition.table == TRANSACTION
                else (tables.activity)
            )
            table = _partition_table(parent, leaf)
            with _read_only(conn):
                nulls = conn.execute(
                    select(func.count())
                    .select_from(table)
                    .where(table.c[_schema.XID].is_(None))
                ).scalar_one()
            verifier.null_xid_rows(leaf.partition, int(nulls))
            verifier.check_partition(leaf.partition, _rows(conn, table, chunk_rows))
        verifier.schema(detached)
    return verifier.report()


@contextmanager
def _read_only(conn: Connection) -> Iterator[Connection]:
    """A short ``READ ONLY`` transaction on a connection."""
    transaction = conn.begin()
    try:
        conn.execute(text("SET TRANSACTION READ ONLY"))
        yield conn
    finally:
        # Nothing was written; ending it either way releases the snapshot.
        transaction.rollback()


def _blocks(conn: Connection, block: Table) -> Iterator[StoredBlock]:
    """Every block in ``seq`` order, in chunks of short transactions."""
    after = 0
    while True:
        with _read_only(conn):
            rows = conn.execute(
                select(
                    block.c.seq,
                    block.c.kind,
                    block.c.body,
                    block.c.prev_hash,
                    block.c.block_hash,
                    block.c.sealed_at,
                )
                .where(block.c.seq > after)
                .order_by(block.c.seq)
                .limit(_BLOCK_CHUNK)
            ).all()
        for row in rows:
            yield StoredBlock(
                int(row.seq),
                str(row.kind),
                bytes(row.body),
                bytes(row.prev_hash),
                bytes(row.block_hash),
                row.sealed_at,
            )
        if len(rows) < _BLOCK_CHUNK:
            return
        after = int(rows[-1].seq)


def _catalog(conn: Connection, tables: AuditTables) -> tuple[list[_Leaf], list[str]]:
    """The partitions holding rows, and the names of detached ones.

    Detached are the tables ``health`` lists as orphaned, and partitions
    whose detach is pending; a pending one is not read.
    """
    leaves: list[_Leaf] = []
    detached: list[str] = []
    severity_parents = []
    for table_name, parent in (
        (TRANSACTION, tables.transaction),
        (ACTIVITY, tables.activity),
    ):
        stack = [_oid(conn, _qualified(parent))]
        while stack:
            for child in _children(conn, stack.pop()):
                if parent is tables.activity and child.relkind == "p":
                    severity_parents.append(child)
                if child.pending:
                    detached.append(child.name)
                elif child.relkind == "p":
                    stack.append(child.oid)
                else:
                    partition = Partition(table_name, child.name)
                    leaves.append(_Leaf(partition, child.schema))
    for name in _orphans(conn, tables, severity_parents):
        detached.append(name.rpartition(".")[2])
    leaves.sort(key=lambda leaf: (leaf.partition.table, leaf.partition.name))
    return leaves, detached


def _partition_table(parent: Table, leaf: _Leaf) -> Table:
    columns = [Column(column.name, column.type) for column in parent.columns]
    return Table(leaf.partition.name, MetaData(), *columns, schema=leaf.schema)


def _rows(conn: Connection, table: Table, chunk_rows: int) -> Iterator[dict[str, Any]]:
    """The rows of a partition with an ``xid``, in ``(xid, id)`` order."""
    xid, row_id = table.c[_schema.XID], table.c.id
    last: tuple[int, int] | None = None
    while True:
        statement = select(table).where(xid.is_not(None))
        if last is not None:
            statement = statement.where(
                tuple_(xid, row_id)
                > tuple_(
                    bindparam("last_xid", last[0], type_=Xid8()),
                    bindparam("last_id", last[1]),
                )
            )
        statement = statement.order_by(xid, row_id).limit(chunk_rows)
        with _read_only(conn):
            rows = [dict(row) for row in conn.execute(statement).mappings()]
        yield from rows
        if len(rows) < chunk_rows:
            return
        last = (int(rows[-1][_schema.XID]), int(rows[-1]["id"]))


def acknowledge(
    connection: Connection,
    tables: AuditTables,
    kind: FailureKind | str,
    scope: Mapping[str, object],
    reason: str,
) -> int:
    """Waive a known incident with an ``ack`` block in the chain.

    Private for now. Later verifications report the failures of ``kind``
    that ``scope`` matches as ``ACKNOWLEDGED`` notes naming this block,
    instead of failing; the ack stays in the chain for every later reader.
    Takes the sealer's advisory lock and appends the block after the last
    one, hashed like every block, in a ``READ COMMITTED`` transaction of its
    own that it commits.

    Args:
        connection: A connection that may insert into the block table, not
            in a transaction and not in ``AUTOCOMMIT`` mode.
        tables: Audit tables built with integrity.
        kind: The failure kind to waive; only those about rows and
            partitions (``ACKNOWLEDGEABLE``).
        scope: What it covers; keys from ``SCOPE_KEYS``, at least one, such
            as ``{"xid_from": a, "xid_to": b}`` for a writer that ran
            without ``Integrity``.
        reason: Why, for whoever reads the chain; it is stored in clear.

    Returns:
        The ``seq`` of the ack block.

    Raises:
        ValueError: The kind cannot be waived, the scope is invalid, the
            tables were built without integrity, the chain has no genesis
            block, or the connection is in a transaction or ``AUTOCOMMIT``
            mode.
    """
    failure = failure_kind(str(kind))
    checked = check_scope(scope)
    block = block_table(tables)
    if getattr(connection.connection.dbapi_connection, "autocommit", False):
        raise ValueError("acknowledge needs a transaction, not AUTOCOMMIT")
    if connection.in_transaction():
        raise ValueError(
            "acknowledge runs its own transaction; pass a connection that is "
            "not in a transaction"
        )
    with connection.begin():
        connection.execute(text("SET TRANSACTION ISOLATION LEVEL READ COMMITTED"))
        # Blocks until no sealer runs; later statements see its block.
        connection.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
            {"key": _pg.lock_key(block)},
        )
        created = connection.execute(
            text("SELECT to_regclass(:block) IS NOT NULL"),
            {"block": _regclass(connection, block)},
        ).scalar_one()
        if not created:
            raise ValueError(_missing(block))
        genesis = connection.execute(
            select(block.c.kind, block.c.body).where(block.c.seq == 1)
        ).one_or_none()
        last = _last(connection, block)
        if genesis is None or genesis.kind != "genesis" or last is None:
            raise ValueError(
                f"{block.fullname} has no genesis block; run "
                "migrations.write_genesis() first"
            )
        chain = str(parse_body(bytes(genesis.body))["chain"])
        seq = int(last.seq) + 1
        body = ack_body(chain, seq, failure=failure.value, scope=checked, reason=reason)
        _insert(connection, block, seq, "ack", bytes(last.block_hash), body)
    return seq
