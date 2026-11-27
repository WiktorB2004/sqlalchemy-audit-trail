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
    ColumnElement,
    Connection,
    Integer,
    Table,
    and_,
    false,
    func,
    insert,
    literal_column,
    or_,
    select,
    text,
    union_all,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.selectable import Select, Subquery

from audit_trail import _pg
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
    horizon_of,
    parse_body,
    seal_body,
    transaction_leaf_row,
)
from audit_trail.integrity._sign import Signer, sign_block
from audit_trail.tables import AuditTables

DEFAULT_MAX_ROWS = 50_000
"""Default soft cap on the rows of one seal block."""

DEFAULT_MAX_SEAL_LAG = timedelta(minutes=5)
"""Default age past which ``health`` flags unsealed rows and prepared
transactions."""

UNSEALED_ROWS_CAP = 10_000
"""``health`` counts unsealed rows up to this many."""

SealRefusal = Literal["XID_REWIND", "NO_GENESIS", "ID_FLOOR_VIOLATION"]


class SealRefusedError(Exception):
    """The sealer refused to seal, and changed nothing.

    Attributes:
        reason: ``XID_REWIND``: the horizon is below the last sealed one, so
            the database was restored from a dump or is a logical replica,
            and its transaction ids repeat sealed ranges. ``NO_GENESIS``: the
            chain has not been started with ``write_genesis``.
            ``ID_FLOOR_VIOLATION``: after a fork with an id window, an
            identity sequence is behind the floor, or a stream has more rows
            at or below the floor than the fork counted: new rows got ids of
            the restored ones (``ALTER ... RESTART``, or a data-only restore
            without the sequence values) and would never be sealed.
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
            recovery), ``"subscriber"`` (a logical-replication subscription
            writes into the block table, so the publisher seals) or
            ``"busy"`` (another sealer holds the lock).
    """

    blocks: int
    rows: int
    horizon: int | None
    capped: bool = False
    skipped: Literal["standby", "subscriber", "busy"] | None = None


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
        unsealed_rows: Committed rows at or above ``sealed_to``, counted up
            to ``UNSEALED_ROWS_CAP``.
        seal_lag: Age of the unsealed entry with the lowest ``xid`` in each
            table, the older of the two, ``None`` when there is none. Age is
            measured from the entry's own time (``issued_at``,
            ``created_at``), not from its commit, so a transaction that ran
            longer than ``max_seal_lag`` is flagged briefly once it commits,
            until the next seal.
        max_seal_lag: The threshold the report was made with.
        prepared: Global ids of prepared transactions in this database older
            than ``max_seal_lag``. Each holds the horizon back until it is
            committed or rolled back, so sealing stalls behind it.
        problem: Why the chain is not started, naming the step to run:
            ``migrations.add_integrity()`` when the block table does not
            exist, ``migrations.write_genesis()`` when it has no genesis
            block; else ``None``.
    """

    started: bool
    sealed_to: int | None
    last_sealed_at: datetime | None
    unsealed_rows: int
    seal_lag: timedelta | None
    max_seal_lag: timedelta
    prepared: list[str] = field(default_factory=list)
    problem: str | None = None

    @property
    def ok(self) -> bool:
        """Whether the chain is started, not lagging and not held back."""
        lagging = self.seal_lag is not None and self.seal_lag > self.max_seal_lag
        return self.started and not lagging and not self.prepared


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


def write_genesis(
    connection: Connection, tables: AuditTables, *, signer: Signer | None = None
) -> Genesis:
    """Start the chain, once; see ``migrations.write_genesis``."""
    block = block_table(tables)
    _check_transactional(connection, "write_genesis")
    start = connection.execute(
        text(
            f"SELECT {_pg.XACT_LOCK} AS locked, "
            "to_regclass(:block) IS NOT NULL AS created"
        ),
        {"key": _pg.lock_key(block), "block": _pg.regclass(connection, block)},
    ).one()
    if not start.created:
        raise ValueError(missing_block_table(block))
    existing = _genesis(connection, block)
    if existing is not None:
        return existing
    if connection.execute(select(func.count()).select_from(block)).scalar_one():
        raise ValueError(f"{block.fullname} has blocks but no genesis block")
    horizon = snapshot_horizon(connection)
    chain = str(uuid.uuid4())
    try:
        # A savepoint, so a conflict leaves the caller's transaction usable.
        with connection.begin_nested():
            body = genesis_body(chain, horizon)
            insert_block(connection, block, 1, "genesis", ZERO_HASH, body, signer)
    except IntegrityError as exc:
        if not _pg.is_sqlstate(exc, _pg.UNIQUE_VIOLATION):
            raise
        # Another call committed block 1 after this transaction's snapshot
        # was taken (at REPEATABLE READ), so only a new snapshot sees it.
        with connection.engine.connect() as fresh:
            existing = _genesis(fresh, block)
        if existing is None:
            raise
        return existing
    return Genesis(chain, horizon, created=True)


def _genesis(connection: Connection, block: Table) -> Genesis | None:
    """Block 1, as a genesis block that this call did not write."""
    first = connection.execute(
        select(block.c.kind, block.c.body).where(block.c.seq == 1)
    ).one_or_none()
    if first is None:
        return None
    if first.kind != "genesis":
        raise ValueError(f"block 1 of {block.fullname} is not a genesis block")
    body = parse_body(first.body)
    return Genesis(str(body["chain"]), int(body["enforce_from"]), created=False)


def seal(
    connection: Connection,
    tables: AuditTables,
    *,
    max_rows: int = DEFAULT_MAX_ROWS,
    up_to: int | None = None,
    signer: Signer | None = None,
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
        up_to: Seal no transaction at or above this ``xid``: ``H`` is
            lowered to it. A catch-up loop that passes the horizon it read
            first ends even while writers outpace the sealer.
        signer: Signs the block (``_sign``); ``None`` leaves it unsigned.

    Returns:
        What was sealed. On a standby, on a logical-replication subscriber of
        the block table, while another sealer holds the lock, and when another
        one committed a block this snapshot does not see, nothing is written.

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
        return _seal(connection, tables, block, max_rows, up_to, signer)
    except _StaleSnapshotError:
        # The transaction was rolled back on the way out.
        return SealResult(0, 0, None, skipped="busy")


class _StaleSnapshotError(Exception):
    """Another sealer committed the block number this one tried to insert."""


def _seal(
    connection: Connection,
    tables: AuditTables,
    block: Table,
    max_rows: int,
    up_to: int | None,
    signer: Signer | None,
) -> SealResult:
    with connection.begin():
        # Before any query, so the snapshot is taken at REPEATABLE READ.
        connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))
        start = connection.execute(
            text(
                "SELECT pg_is_in_recovery() AS standby, "
                f"{_pg.SUBSCRIBED} AS subscriber, "
                f"{_pg.TRY_XACT_LOCK} AS locked, "
                "pg_snapshot_xmin(pg_current_snapshot())::text AS horizon"
            ),
            {"key": _pg.lock_key(block), "table": _pg.regclass(connection, block)},
        ).one()
        if start.standby:
            return SealResult(0, 0, None, skipped="standby")
        if start.subscriber:
            # Its blocks come from the publisher; one of its own would take
            # the next seq and stop the subscription on a duplicate key.
            return SealResult(0, 0, None, skipped="subscriber")
        if not start.locked:
            return SealResult(0, 0, None, skipped="busy")
        horizon = int(start.horizon)
        last = last_block(connection, block)
        sealed = sealed_horizon(connection, block)
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
        window = _window(connection, block)
        check_floor(connection, tables, window)
        windows = _windows(tables, window.id_floor)
        if up_to is not None:
            horizon = max(min(horizon, up_to), xid_from)
        xid_to, capped = _cut(connection, tables, xid_from, horizon, max_rows, windows)
        if xid_to is None:
            return SealResult(0, 0, xid_from)
        builder = SegmentBuilder()
        for stream, partition, row in _rows(
            connection, tables, xid_from, xid_to, windows
        ):
            builder.add(stream, partition, row)
        seq = last.seq + 1
        body = seal_body(chain, seq, xid_from, xid_to, builder.segments())
        try:
            insert_block(connection, block, seq, "seal", last.block_hash, body, signer)
        except IntegrityError as exc:
            if _pg.is_sqlstate(exc, _pg.UNIQUE_VIOLATION):
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

    Reads at most ``UNSEALED_ROWS_CAP`` index entries per table. The lag is
    measured from the event time of the entries (see ``SealHealth``), so a
    long-running transaction can raise a brief lag alarm after it commits.

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
    start = connection.execute(
        text(
            "SELECT to_regclass(:block) IS NOT NULL AS created, ARRAY("
            "SELECT gid FROM pg_prepared_xacts "
            "WHERE database = current_database() AND prepared < :cutoff "
            "ORDER BY prepared, gid) AS prepared"
        ),
        {"block": _pg.regclass(connection, block), "cutoff": now - max_seal_lag},
    ).one()
    prepared = list(start.prepared)
    if not start.created:
        return SealHealth(
            False,
            None,
            None,
            0,
            None,
            max_seal_lag,
            prepared,
            missing_block_table(block),
        )
    horizon = connection.execute(
        select(block.c.body, block.c.sealed_at)
        .where(block.c.kind.in_(HORIZON_KINDS))
        .order_by(block.c.seq.desc())
        .limit(1)
    ).one_or_none()
    if horizon is None:
        problem = (
            f"{block.fullname} has no genesis block; run "
            "migrations.write_genesis() once every writer runs with integrity"
        )
        return SealHealth(False, None, None, 0, None, max_seal_lag, prepared, problem)
    sealed_to = horizon_of(parse_body(horizon.body))
    # Rows of an earlier incarnation are sealed, whatever their xid.
    windows = _windows(tables, _window(connection, block).id_floor)
    # Bounded, so each walks the (xid, id) indexes from sealed_to only.
    columns = []
    for table, stamp in (
        (tables.transaction, tables.transaction.c.issued_at),
        (tables.activity, tables.activity.c.created_at),
    ):
        xid = table.c[_schema.XID]
        where = [xid >= sealed_to, *windows[table.name]]
        unsealed = select(literal_column("1", Integer)).where(*where)
        capped = unsealed.order_by(xid).limit(UNSEALED_ROWS_CAP).subquery()
        columns.append(select(func.count()).select_from(capped).scalar_subquery())
        lowest = select(stamp).where(*where).order_by(xid).limit(1)
        columns.append(lowest.scalar_subquery())
    counted, first, counted_activity, first_activity = connection.execute(
        select(*columns)
    ).one()
    rows = min(counted + counted_activity, UNSEALED_ROWS_CAP)
    stamps = [stamp for stamp in (first, first_activity) if stamp is not None]
    lag = max(now - min(stamps), timedelta(0)) if stamps else None
    return SealHealth(
        True, sealed_to, horizon.sealed_at, rows, lag, max_seal_lag, prepared
    )


def missing_block_table(block: Table) -> str:
    """The error message for a block table that does not exist."""
    return (
        f"the block table {block.fullname} does not exist; run "
        "migrations.add_integrity() first"
    )


def _check_transactional(connection: Connection, name: str) -> None:
    dbapi = connection.connection.dbapi_connection
    if getattr(dbapi, "autocommit", False):
        raise ValueError(f"{name} needs a transaction, not AUTOCOMMIT")


def snapshot_horizon(connection: Connection) -> int:
    """The ``xmin`` of the current snapshot: every lower xid has ended."""
    return int(
        connection.execute(
            text("SELECT pg_snapshot_xmin(pg_current_snapshot())::text")
        ).scalar_one()
    )


def last_block(connection: Connection, block: Table) -> Any:
    """The ``seq`` and ``block_hash`` of the newest block, or ``None``."""
    return connection.execute(
        select(block.c.seq, block.c.block_hash).order_by(block.c.seq.desc()).limit(1)
    ).one_or_none()


HORIZON_KINDS = ("genesis", "seal", "fork")
"""Blocks that move the sealed horizon: a fork restarts it at ``xid_at_fork``."""


def sealed_horizon(connection: Connection, block: Table) -> tuple[str, int] | None:
    """The chain id and the horizon of the newest genesis, seal or fork block."""
    body = connection.execute(
        select(block.c.body)
        .where(block.c.kind.in_(HORIZON_KINDS))
        .order_by(block.c.seq.desc())
        .limit(1)
    ).scalar_one_or_none()
    if body is None:
        return None
    parsed = parse_body(body)
    return str(parsed["chain"]), horizon_of(parsed)


@dataclass(frozen=True)
class Window:
    """The ``id`` window of the current incarnation, from its forks.

    Attributes:
        incarnation: Its number, 1 before any fork.
        id_floor: Rows of a stream with ``id`` at or below this are of an
            earlier incarnation; ``None`` before a fork with an id window.
        id_count: Rows of each stream at or below the floor at the fork.
    """

    incarnation: int = 1
    id_floor: dict[str, int] | None = None
    id_count: dict[str, int] | None = None


def _window(connection: Connection, block: Table) -> Window:
    """The id window of the current incarnation: of the newest fork with one.

    A fork without an id window keeps the one before it.
    """
    incarnation: int | None = None
    for body in connection.execute(
        select(block.c.body).where(block.c.kind == "fork").order_by(block.c.seq.desc())
    ).scalars():
        parsed = parse_body(body)
        if incarnation is None:
            incarnation = int(parsed["incarnation"])
        if parsed.get("id_floor") is not None:
            floors = {str(k): int(v) for k, v in parsed["id_floor"].items()}
            counts = {str(k): int(v) for k, v in parsed["id_count"].items()}
            return Window(incarnation, floors, counts)
    return Window(incarnation or 1)


def window_clause(
    table: Table, floors: Mapping[str, int] | None, *, above: bool
) -> ColumnElement[bool] | None:
    """The rows of ``table`` above (or at or below) the id floor of each stream.

    ``table`` is the transaction table, or the activity table (one with a
    ``severity`` column), or a partition of either.

    ``None`` when there is no floor. A stream the floor does not name had no
    row at the fork, as if its floor were -1: above the floor it is not
    bounded, and at or below it there is no row of it (a stream that
    appears after the fork belongs to the new incarnation alone).
    """
    if floors is None:
        return None
    row_id = table.c.id

    def bound(limit: int) -> ColumnElement[bool]:
        return row_id > limit if above else row_id <= limit

    if "severity" not in table.c:
        limit = floors.get(TRANSACTION_STREAM)
        if limit is None:
            return None if above else false()
        return bound(limit)
    severities = {
        int(stream.removeprefix("activity.")): limit
        for stream, limit in floors.items()
        if stream.startswith("activity.")
    }
    severity = table.c.severity
    named = [
        and_(severity == value, bound(limit)) for value, limit in severities.items()
    ]
    if not above:
        return or_(*named) if named else false()
    if not named:
        return None
    return or_(*named, severity.not_in(list(severities)))


def _windows(
    tables: AuditTables,
    lower: Mapping[str, int] | None,
    upper: Mapping[str, int] | None = None,
) -> dict[str, list[ColumnElement[bool]]]:
    """The window conditions of each table, by table name."""
    found: dict[str, list[ColumnElement[bool]]] = {}
    for table in (tables.transaction, tables.activity):
        conditions = [
            clause
            for clause in (
                window_clause(table, lower, above=True),
                window_clause(table, upper, above=False),
            )
            if clause is not None
        ]
        found[table.name] = conditions
    return found


def check_floor(connection: Connection, tables: AuditTables, window: Window) -> None:
    """Refuse to seal when new rows may have ids at or below the floor.

    Rows a fork left at or below the id floor belong to the incarnations
    before it, so a new row that gets such an id (after an identity reset)
    would never be sealed. Two checks catch that:

    - the sequence: a table's identity sequence below the highest floor of
      its streams (cheap, one read per table);
    - the count: a stream with more rows at or below its floor than the
      fork counted (``id_count``), for a sequence that was reset and has
      climbed past the floor again. It reads at most ``id_count + 1``
      entries of the primary key, so it runs only while the sequence is
      within ``id_count`` of the floor. Past that the sequence check alone
      remains: a reset is missed only if more than ``id_count`` ids were
      drawn between two seals, or the sequence was set far above the floor
      (``setval``) while rows with ids at or below it were left behind.

    Retention weakens the count (not fixed): ``drop_expired`` drops rows at
    or below the floor that the fork counted, so later more new rows can
    hide under ``id_count`` before it refuses. The sequence check does not
    depend on it.

    Raises:
        SealRefusedError: ``ID_FLOOR_VIOLATION``: a table's identity
            sequence is below the highest floor of its streams, or a stream
            has more rows at or below its floor than the fork counted.
    """
    floors, counts = window.id_floor, window.id_count
    if floors is None or counts is None:
        return
    values: dict[str, int | None] = {}
    for table in (tables.transaction, tables.activity):
        streams = [
            limit
            for stream, limit in floors.items()
            if (stream == TRANSACTION_STREAM) == (table is tables.transaction)
        ]
        if not streams:
            continue
        value = values[table.name] = sequence_value(connection, table)
        if value is not None and value < max(streams):
            raise SealRefusedError(
                "ID_FLOOR_VIOLATION",
                f"the id sequence of {table.fullname} is at {value}, below the "
                f"fork's id floor {max(streams)}: new rows would get ids of "
                "restored rows. Set it above the floor with setval()",
            )
    for stream, limit in floors.items():
        table = tables.transaction if stream == TRANSACTION_STREAM else tables.activity
        allowed = counts.get(stream, 0)
        value = values.get(table.name)
        if value is not None and value > limit + allowed:
            continue
        found = connection.execute(
            floor_count(table, stream, limit, allowed)
        ).scalar_one()
        if found > allowed:
            raise SealRefusedError(
                "ID_FLOOR_VIOLATION",
                f"stream {stream} has more rows with id <= {limit} than the "
                f"{allowed} the fork counted: new rows got ids of restored "
                "rows (an identity reset?) and would never be sealed",
            )


def floor_count(table: Table, stream: str, limit: int, allowed: int) -> Select[Any]:
    """Rows of ``stream`` with ``id <= limit``, counted up to ``allowed + 1``.

    Ordered by ``id`` so that the planner reads the primary key (``id``
    first) from the floor down and stops after ``allowed + 1`` entries,
    instead of scanning the table.
    """
    condition = [table.c.id <= limit]
    if stream != TRANSACTION_STREAM:
        condition.append(table.c.severity == int(stream.removeprefix("activity.")))
    capped = (
        select(table.c.id)
        .where(*condition)
        .order_by(table.c.id.desc())
        .limit(allowed + 1)
        .subquery()
    )
    return select(func.count()).select_from(capped)


def sequence_value(connection: Connection, table: Table) -> int | None:
    """The last id the identity sequence of ``table`` gave, or ``None``.

    ``last_value``, or ``last_value - 1`` when the sequence was never called
    (a fresh one, or one set with ``setval(..., false)``). ``None`` when the
    table's ``id`` has no sequence.
    """
    name = connection.execute(
        text("SELECT pg_get_serial_sequence(:table, 'id')"),
        {"table": _pg.regclass(connection, table)},
    ).scalar_one_or_none()
    if name is None:
        return None
    row = connection.execute(text(f"SELECT last_value, is_called FROM {name}")).one()
    return int(row.last_value) if row.is_called else int(row.last_value) - 1


def _xids(
    tables: AuditTables,
    upper: int,
    limit: int,
    *,
    lower: int | None = None,
    above: int | None = None,
    windows: Mapping[str, list[ColumnElement[bool]]] | None = None,
) -> Subquery:
    """The lowest ``limit`` row ``xid`` values below ``upper`` of each table.

    Bounded below by ``lower`` (inclusive) or ``above`` (exclusive). Each
    branch is an ordered ``LIMIT`` on its own table, so it reads at most
    ``limit`` entries of the ``(xid, id)`` indexes (a Merge Append over the
    partitions) instead of sorting the whole range; the smallest ``limit``
    of both tables together are among them.
    """
    parts = []
    for table in (tables.transaction, tables.activity):
        xid = table.c[_schema.XID]
        conditions = [xid < upper]
        if lower is not None:
            conditions.append(xid >= lower)
        if above is not None:
            conditions.append(xid > above)
        if windows is not None:
            conditions.extend(windows[table.name])
        branch = select(xid.label("xid")).where(*conditions)
        ordered = branch.order_by(xid).limit(limit).subquery()
        parts.append(select(ordered.c.xid))
    return union_all(*parts).subquery("xids")


def _cut(
    connection: Connection,
    tables: AuditTables,
    lower: int,
    horizon: int,
    max_rows: int,
    windows: Mapping[str, list[ColumnElement[bool]]] | None = None,
) -> tuple[int | None, bool]:
    """The upper bound of the block and whether ``max_rows`` lowered it.

    ``None`` when ``[lower, horizon)`` has no rows. Reads at most
    ``max_rows + 1`` index entries per table.
    """
    xids = _xids(tables, horizon, max_rows + 1, lower=lower, windows=windows)
    # One pass over the merged branches: the first row and the one past
    # max_rows.
    number = func.row_number().over(order_by=xids.c.xid).label("number")
    numbered = select(xids.c.xid, number).subquery("numbered")
    found: list[int] = list(
        connection.execute(
            select(numbered.c.xid)
            .where(numbered.c.number.in_((1, max_rows + 1)))
            .order_by(numbered.c.number)
        ).scalars()
    )
    if not found:
        return None, False
    if len(found) == 1:
        return horizon, False
    first, past = found
    if past > first:
        return past, True
    # The first transaction alone has more than max_rows rows: seal it
    # whole, up to the next transaction's xid.
    after = _xids(tables, horizon, 1, above=past, windows=windows)
    following: int | None = connection.execute(
        select(after.c.xid).order_by(after.c.xid).limit(1)
    ).scalar_one_or_none()
    if following is None:
        return horizon, False
    return following, True


def _rows(
    connection: Connection,
    tables: AuditTables,
    lower: int,
    upper: int,
    windows: Mapping[str, list[ColumnElement[bool]]] | None = None,
) -> Iterator[tuple[str, str, dict[str, object]]]:
    """``(stream, partition, leaf row)`` of every row in ``[lower, upper)``.

    Only rows in the id window, given as conditions by table name.
    """
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
            .where(xid >= lower, xid < upper, *(windows or {}).get(table.name, []))
            .order_by(xid, table.c.id)
        )
        result = connection.execute(
            statement, execution_options={"yield_per": _schema.DEFAULT_CHUNK_ROWS}
        )
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
    rows = connection.execute(
        _LEAF_PARTITIONS, {"parent": _pg.regclass(connection, table)}
    ).all()
    return {int(oid): str(name) for oid, name in rows}


def insert_block(
    connection: Connection,
    block: Table,
    seq: int,
    kind: str,
    prev_hash: bytes,
    body: bytes,
    signer: Signer | None = None,
    **columns: Any,
) -> bytes:
    """Insert a block, signed by ``signer`` if given; its ``block_hash``."""
    digest = block_hash(prev_hash, body)
    connection.execute(
        insert(block).values(
            seq=seq,
            kind=kind,
            body=body,
            prev_hash=prev_hash,
            block_hash=digest,
            **signature_columns(signer, digest),
            **columns,
        )
    )
    return digest


def signature_columns(signer: Signer | None, digest: bytes) -> dict[str, Any]:
    """The ``signature``, ``key_id`` and ``alg`` of a block; none unsigned."""
    if signer is None:
        return {}
    signature, key_id, alg = sign_block(signer, digest)
    return {"signature": signature, "key_id": key_id, "alg": alg}
