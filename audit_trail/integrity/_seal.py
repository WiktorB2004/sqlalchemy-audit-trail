"""The sealer: chained blocks over the audit rows of finished transactions.

Which rows are safe to seal is decided by the *horizon*
``H = pg_snapshot_xmin(pg_current_snapshot())``: every transaction id below
it has committed or rolled back, and a transaction that gets its id later
gets one at or above every earlier snapshot's ``xmax``, so no row can appear
below a horizon once it has been read. Only transactions that hold an id
keep ``H`` back: writers, sessions idle in a transaction after a write, and
prepared transactions. Read-only sessions do not.

Block ``k`` covers the rows with ``xid`` in ``[H(k-1), H(k))`` of every
stream; the genesis block's ``enforce_from`` is the first lower bound. The
sealer never updates an audit row.

``xid8`` has no ``min``, ``max`` or ``+``, so the queries use
``ORDER BY xid LIMIT``; values are bound through ``Xid8``.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from sqlalchemy import (
    BigInteger,
    Connection,
    Select,
    Table,
    func,
    insert,
    literal_column,
    select,
    text,
    union_all,
)
from sqlalchemy.exc import DBAPIError, IntegrityError

from audit_trail.integrity import _schema
from audit_trail.integrity._block import (
    ACTIVITY_LEAF_COLUMNS,
    TRANSACTION_LEAF_COLUMNS,
    TRANSACTION_STREAM,
    ZERO_HASH,
    SegmentBuilder,
    activity_leaf_row,
    activity_stream,
    block_hash,
    genesis_body,
    parse_body,
    seal_body,
    transaction_leaf_row,
)
from audit_trail.tables import AuditTables

DEFAULT_MAX_ROWS = 50_000
"""Default soft cap on the rows of one seal block."""

DEFAULT_MAX_SEAL_LAG = timedelta(minutes=5)
"""Default age past which ``health`` flags unsealed rows and prepared
transactions."""

_UNIQUE_VIOLATION = "23505"

# Rows fetched per round trip while streaming a block's rows.
_CHUNK = 2_000

SealRefusal = Literal["XID_REWIND", "NO_GENESIS"]


class SealRefusedError(Exception):
    """The sealer refused to seal, and changed nothing.

    Attributes:
        reason: ``XID_REWIND``: the horizon is below the last sealed one, so
            the database was restored from a dump or is a logical replica,
            and its transaction ids repeat sealed ranges. ``NO_GENESIS``: the
            chain has not been started with ``write_genesis``.
    """

    def __init__(self, reason: SealRefusal, message: str) -> None:
        super().__init__(f"{reason}: {message}")
        self.reason: SealRefusal = reason


@dataclass(frozen=True)
class SealResult:
    """What one ``seal`` call did.

    Attributes:
        blocks: Blocks written, ``0`` or ``1``.
        rows: Rows sealed into the block.
        horizon: The ``xid`` the chain is sealed up to (exclusive) after the
            call; ``None`` when the call was skipped.
        capped: ``max_rows`` cut the block short and finished rows remain
            unsealed; call again.
        skipped: Why nothing was attempted: ``"standby"`` (the server is in
            recovery) or ``"busy"`` (another sealer holds the lock).
    """

    blocks: int
    rows: int
    horizon: int | None
    capped: bool = False
    skipped: Literal["standby", "busy"] | None = None


@dataclass(frozen=True)
class Genesis:
    """The genesis block of a chain.

    Attributes:
        chain: The chain id, a UUID as text.
        enforce_from: Rows with a lower ``xid`` are out of scope.
        created: Whether this call wrote it.
    """

    chain: str
    enforce_from: int
    created: bool


@dataclass(frozen=True)
class SealHealth:
    """How far the sealer is behind.

    Attributes:
        started: Whether the chain has a genesis block.
        sealed_to: The ``xid`` the chain is sealed up to (exclusive).
        last_sealed_at: When the block holding ``sealed_to`` was written.
        unsealed_rows: Committed rows at or above ``sealed_to``.
        seal_lag: Age of the oldest of them, ``None`` when there is none.
        max_seal_lag: The threshold the report was made with.
        prepared: Global ids of prepared transactions in this database older
            than ``max_seal_lag``. Each holds the horizon back until it is
            committed or rolled back, so sealing stalls behind it.
    """

    started: bool
    sealed_to: int | None
    last_sealed_at: datetime | None
    unsealed_rows: int
    seal_lag: timedelta | None
    max_seal_lag: timedelta
    prepared: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Whether the chain is started, not lagging and not held back."""
        lagging = self.seal_lag is not None and self.seal_lag > self.max_seal_lag
        return self.started and not lagging and not self.prepared


def lock_key(block: Table) -> str:
    """Key of the advisory lock that lets one sealer of a chain run at a time."""
    return f"audit_trail.seal:{block.schema}.{block.name}"


def block_table(tables: AuditTables) -> Table:
    """The table of sealed blocks of tables built with integrity.

    Raises:
        ValueError: The tables were built without integrity.
    """
    block = tables.seal_block
    if block is None or not _schema.has_integrity(tables.transaction):
        raise ValueError(
            "the audit tables were built without integrity; build them with "
            "build_tables(integrity=True) or AuditTrail(integrity=Integrity())"
        )
    return block


def write_genesis(connection: Connection, tables: AuditTables) -> Genesis:
    """Start the chain, once; see ``migrations.write_genesis``."""
    block = block_table(tables)
    _check_transactional(connection, "write_genesis")
    connection.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
        {"key": lock_key(block)},
    )
    first = connection.execute(
        select(block.c.kind, block.c.body).where(block.c.seq == 1)
    ).one_or_none()
    if first is not None:
        if first.kind != "genesis":
            raise ValueError(f"block 1 of {block.fullname} is not a genesis block")
        body = parse_body(first.body)
        return Genesis(str(body["chain"]), int(body["enforce_from"]), created=False)
    if connection.execute(select(func.count()).select_from(block)).scalar_one():
        raise ValueError(f"{block.fullname} has blocks but no genesis block")
    horizon = _horizon(connection)
    chain = str(uuid.uuid4())
    _insert(connection, block, 1, "genesis", ZERO_HASH, genesis_body(chain, horizon))
    return Genesis(chain, horizon, created=True)


def seal(
    connection: Connection, tables: AuditTables, *, max_rows: int = DEFAULT_MAX_ROWS
) -> SealResult:
    """Seal the finished transactions since the last block into a new block.

    Runs one ``REPEATABLE READ`` transaction on ``connection`` and commits
    it. Its first statement takes ``pg_try_advisory_xact_lock`` and reads the
    horizon ``H``, which is the transaction snapshot's own, so every row of a
    transaction below ``H`` is visible and every later one is not. The lock
    is transaction-level, which is safe behind PgBouncer in transaction mode.

    The block covers ``[H(last), H)``, cut lower when that holds more than
    ``max_rows`` rows (both tables counted): the cut is the ``xid`` of the
    first row past ``max_rows``, so one transaction is never split, and a
    transaction that alone has more rows is sealed whole. Rows are streamed
    in ``(xid, id)`` order into one Merkle root per (stream, partition). No
    block is written when the range has no rows: the next one starts where
    the last one ended either way.

    The snapshot is taken just before the lock is tried, so a sealer that
    started while another one was committing can get the lock without seeing
    that block. Its ``INSERT`` then fails on the ``seq`` primary key; the
    transaction is rolled back, nothing is written, and the call returns
    ``skipped="busy"`` as if it had not got the lock. The next run goes on.

    Args:
        connection: A connection that is not in a transaction and not in
            ``AUTOCOMMIT`` mode; never the DDL connection of ``drop_expired``.
        tables: Audit tables built with integrity.
        max_rows: Soft cap on the rows of the block, at least 1.

    Returns:
        What was sealed. On a standby, while another sealer holds the lock,
        and when another one committed a block this snapshot does not see,
        nothing is written.

    Raises:
        ValueError: ``max_rows`` is below 1, the tables were built without
            integrity, or the connection is in a transaction or
            ``AUTOCOMMIT`` mode.
        SealRefusedError: ``XID_REWIND`` or ``NO_GENESIS``; nothing was
            written.
    """
    if max_rows < 1:
        raise ValueError("max_rows must be at least 1")
    block = block_table(tables)
    _check_transactional(connection, "seal")
    if connection.in_transaction():
        raise ValueError(
            "seal runs its own REPEATABLE READ transaction; pass a connection "
            "that is not in a transaction"
        )
    try:
        return _seal(connection, tables, block, max_rows)
    except _StaleSnapshotError:
        # The transaction was rolled back on the way out.
        return SealResult(0, 0, None, skipped="busy")


class _StaleSnapshotError(Exception):
    """Another sealer committed the block number this one tried to insert."""


def _seal(
    connection: Connection, tables: AuditTables, block: Table, max_rows: int
) -> SealResult:
    with connection.begin():
        # Before any query, so the snapshot is taken at REPEATABLE READ.
        connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))
        start = connection.execute(
            text(
                "SELECT pg_is_in_recovery() AS standby, "
                "pg_try_advisory_xact_lock(hashtext(:key)) AS locked, "
                "pg_snapshot_xmin(pg_current_snapshot())::text AS horizon"
            ),
            {"key": lock_key(block)},
        ).one()
        if start.standby:
            return SealResult(0, 0, None, skipped="standby")
        if not start.locked:
            return SealResult(0, 0, None, skipped="busy")
        horizon = int(start.horizon)
        last = _last(connection, block)
        sealed = _sealed_to(connection, block)
        if last is None or sealed is None:
            raise SealRefusedError(
                "NO_GENESIS",
                f"{block.fullname} has no genesis block; run "
                "migrations.write_genesis once every writer runs with integrity",
            )
        chain, xid_from = sealed
        if horizon < xid_from:
            raise SealRefusedError(
                "XID_REWIND",
                f"the horizon {horizon} is below the sealed horizon {xid_from}: "
                "transaction ids were rewound (a pg_dump restore or a logical "
                "replica), so new rows would repeat sealed ranges. Never seal "
                "on a logical replica; after a restore, declare a fork",
            )
        xid_to, capped = _cut(connection, tables, xid_from, horizon, max_rows)
        if xid_to is None:
            return SealResult(0, 0, xid_from)
        builder = SegmentBuilder()
        for stream, partition, row in _rows(connection, tables, xid_from, xid_to):
            builder.add(stream, partition, row)
        seq = last.seq + 1
        body = seal_body(chain, seq, xid_from, xid_to, builder.segments())
        try:
            _insert(connection, block, seq, "seal", last.block_hash, body)
        except IntegrityError as exc:
            if _sqlstate(exc) == _UNIQUE_VIOLATION:
                raise _StaleSnapshotError from exc
            raise
        return SealResult(1, builder.rows, xid_to, capped=capped)


def seal_health(
    connection: Connection,
    tables: AuditTables,
    *,
    now: datetime,
    max_seal_lag: timedelta = DEFAULT_MAX_SEAL_LAG,
) -> SealHealth:
    """Report the sealing lag and prepared transactions holding it back.

    Args:
        connection: Connection that can read the audit tables, the block
            table and ``pg_prepared_xacts``.
        tables: Audit tables built with integrity.
        now: Reference time.
        max_seal_lag: Unsealed rows, and prepared transactions, older than
            this are flagged.

    Raises:
        ValueError: The tables were built without integrity.
    """
    block = block_table(tables)
    prepared = list(
        connection.execute(
            text(
                "SELECT gid FROM pg_prepared_xacts "
                "WHERE database = current_database() AND prepared < :cutoff "
                "ORDER BY prepared, gid"
            ),
            {"cutoff": now - max_seal_lag},
        ).scalars()
    )
    horizon = connection.execute(
        select(block.c.body, block.c.sealed_at)
        .where(block.c.kind.in_(("genesis", "seal")))
        .order_by(block.c.seq.desc())
        .limit(1)
    ).one_or_none()
    if horizon is None:
        return SealHealth(False, None, None, 0, None, max_seal_lag, prepared)
    sealed_to = _xid_to(parse_body(horizon.body))
    rows = 0
    oldest: datetime | None = None
    for table, stamp in (
        (tables.transaction, tables.transaction.c.issued_at),
        (tables.activity, tables.activity.c.created_at),
    ):
        unsealed = table.c[_schema.XID] >= sealed_to
        count, first = connection.execute(
            select(func.count(), func.min(stamp)).where(unsealed)
        ).one()
        rows += count
        if first is not None and (oldest is None or first < oldest):
            oldest = first
    lag = None if oldest is None else max(now - oldest, timedelta(0))
    return SealHealth(
        True, sealed_to, horizon.sealed_at, rows, lag, max_seal_lag, prepared
    )


def _sqlstate(exc: DBAPIError) -> str | None:
    orig = exc.orig
    sqlstate: str | None = getattr(orig, "sqlstate", None) or getattr(
        orig, "pgcode", None
    )
    return sqlstate


def _check_transactional(connection: Connection, name: str) -> None:
    dbapi = connection.connection.dbapi_connection
    if getattr(dbapi, "autocommit", False):
        raise ValueError(f"{name} needs a transaction, not AUTOCOMMIT")


def _horizon(connection: Connection) -> int:
    return int(
        connection.execute(
            text("SELECT pg_snapshot_xmin(pg_current_snapshot())::text")
        ).scalar_one()
    )


def _last(connection: Connection, block: Table) -> Any:
    return connection.execute(
        select(block.c.seq, block.c.block_hash).order_by(block.c.seq.desc()).limit(1)
    ).one_or_none()


def _sealed_to(connection: Connection, block: Table) -> tuple[str, int] | None:
    """The chain id and the horizon of the newest genesis or seal block."""
    body = connection.execute(
        select(block.c.body)
        .where(block.c.kind.in_(("genesis", "seal")))
        .order_by(block.c.seq.desc())
        .limit(1)
    ).scalar_one_or_none()
    if body is None:
        return None
    parsed = parse_body(body)
    return str(parsed["chain"]), _xid_to(parsed)


def _xid_to(body: Mapping[str, Any]) -> int:
    if body["kind"] == "genesis":
        return int(body["enforce_from"])
    return int(body["xid_to"])


def _xids(
    tables: AuditTables, lower: int, upper: int, *, above: int | None = None
) -> Select[Any]:
    """Every row's ``xid`` in ``[lower, upper)`` of both tables, in order.

    With ``above``, only those greater than it.
    """
    parts = []
    for table in (tables.transaction, tables.activity):
        xid = table.c[_schema.XID]
        conditions = [xid >= lower, xid < upper]
        if above is not None:
            conditions.append(xid > above)
        parts.append(select(xid.label("xid")).where(*conditions))
    xids = union_all(*parts).subquery("xids")
    return select(xids.c.xid).order_by(xids.c.xid)


def _cut(
    connection: Connection,
    tables: AuditTables,
    lower: int,
    horizon: int,
    max_rows: int,
) -> tuple[int | None, bool]:
    """The upper bound of the block and whether ``max_rows`` lowered it.

    ``None`` when ``[lower, horizon)`` has no rows.
    """
    xids = _xids(tables, lower, horizon)
    first: int | None = connection.execute(xids.limit(1)).scalar_one_or_none()
    if first is None:
        return None, False
    past: int | None = connection.execute(
        xids.offset(max_rows).limit(1)
    ).scalar_one_or_none()
    if past is None:
        return horizon, False
    if past > first:
        return past, True
    # The first transaction alone has more than max_rows rows: seal it
    # whole, up to the next transaction's xid.
    following: int | None = connection.execute(
        _xids(tables, lower, horizon, above=past).limit(1)
    ).scalar_one_or_none()
    if following is None:
        return horizon, False
    return following, True


def _rows(
    connection: Connection, tables: AuditTables, lower: int, upper: int
) -> Iterator[tuple[str, str, dict[str, object]]]:
    """``(stream, partition, leaf row)`` of every row in ``[lower, upper)``."""
    for table, columns in (
        (tables.transaction, TRANSACTION_LEAF_COLUMNS),
        (tables.activity, ACTIVITY_LEAF_COLUMNS),
    ):
        names = _leaf_partitions(connection, table)
        xid = table.c[_schema.XID]
        statement = (
            select(
                literal_column("tableoid", BigInteger).label("tableoid"),
                *(table.c[name] for name in columns),
            )
            .where(xid >= lower, xid < upper)
            .order_by(xid, table.c.id)
        )
        result = connection.execute(statement, execution_options={"yield_per": _CHUNK})
        for row in result.mappings():
            partition = names[int(row["tableoid"])]
            if table is tables.transaction:
                yield TRANSACTION_STREAM, partition, transaction_leaf_row(row)
            else:
                stream = activity_stream(row["severity"])
                yield stream, partition, activity_leaf_row(row)


_LEAF_PARTITIONS = text(
    """
    WITH RECURSIVE tree(oid) AS (
        SELECT to_regclass(:parent)::oid
        UNION ALL
        SELECT i.inhrelid
        FROM pg_catalog.pg_inherits i
        JOIN tree ON i.inhparent = tree.oid
    )
    SELECT c.oid::bigint, c.relname
    FROM tree JOIN pg_catalog.pg_class c ON c.oid = tree.oid
    WHERE c.relkind = 'r'
    """
)


def _leaf_partitions(connection: Connection, table: Table) -> dict[int, str]:
    """Names of the partitions that hold the rows of a partitioned table."""
    parent = connection.dialect.identifier_preparer.format_table(table)
    rows = connection.execute(_LEAF_PARTITIONS, {"parent": parent}).all()
    return {int(oid): str(name) for oid, name in rows}


def _insert(
    connection: Connection,
    block: Table,
    seq: int,
    kind: str,
    prev_hash: bytes,
    body: bytes,
) -> None:
    connection.execute(
        insert(block).values(
            seq=seq,
            kind=kind,
            body=body,
            prev_hash=prev_hash,
            block_hash=block_hash(prev_hash, body),
        )
    )
