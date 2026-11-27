"""Retire blocks: what ``drop_expired`` writes before it drops a partition.

Private for now. With integrity on, ``drop_expired`` hands each expired
partition to a ``Retirer``, which works on a second connection of its own
(the drop runs on an ``AUTOCOMMIT`` connection, and the chain needs
transactions):

1. ``prepare``: seal, then (``verify_before_drop``) verify the expired
   partitions in short ``READ ONLY`` transactions, all ended before the
   first detach. A partition that a failure names, or every partition after
   a failure of the chain itself, is skipped.
2. ``retire``: under the sealer's lock, refuse a partition that still holds
   an unsealed row, then append a ``retire`` block covering every segment
   sealed into it so far (``_block.retire_body``), with ``ON CONFLICT
   (retired_partition) ... DO NOTHING``: a retried or finalized detach adds
   no second block. Committed before the detach.
3. ``ddl``: the detach and the drop; ``55P03`` (a lock not granted in
   ``lock_timeout``) and ``55000`` (a detach of a sibling pending) skip the
   partition instead of failing the call.
4. ``check_detached``: after the detach and before the drop, the retire
   block must still cover the whole table: no seal block after it names
   the partition, and no row of it is unsealed.

A crash between 2 and 3 leaves a partition present with a retire block,
which verifies clean; one between the detach and the drop leaves a
detached or pending table, which ``verify`` reports as
``DETACHED_PARTITION`` until it is dropped.

A table left detached that way, or by a drop refused with ``55P03`` or
another error, is dropped by the next call once it has expired: when
``check_orphan`` finds a valid retire block for it and ``check_detached``
passes. Without one, it is kept and reported as ``not_retired``.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from types import TracebackType

from sqlalchemy import (
    AssertionPool,
    Column,
    Connection,
    Engine,
    Integer,
    MetaData,
    QueuePool,
    SingletonThreadPool,
    StaticPool,
    Table,
    bindparam,
    literal_column,
    select,
    text,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DBAPIError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from audit_trail import _pg
from audit_trail.integrity import _schema
from audit_trail.integrity._block import (
    TRANSACTION_STREAM,
    SealedSegment,
    Segment,
    activity_stream,
    block_hash,
    parse_body,
    parse_segments,
    retire_body,
    retire_coverage,
)
from audit_trail.integrity._codec import rfc3339
from audit_trail.integrity._seal import (
    block_table,
    last_block,
    seal,
    sealed_horizon,
    snapshot_horizon,
)
from audit_trail.integrity._types import Xid8
from audit_trail.integrity._verify import ACTIVITY, TRANSACTION, FailureKind
from audit_trail.integrity._verify_db import (
    DEFAULT_CHUNK_ROWS,
    VerifyOptions,
    run_verification,
)
from audit_trail.maintenance import (
    PartitionError,
    SkippedPartition,
    SkipReason,
    _Child,
    _RetentionTarget,
)
from audit_trail.tables import AuditTables

logger = logging.getLogger("audit_trail.maintenance")

_DDL_SKIPS: dict[str, SkipReason] = {
    _pg.LOCK_NOT_AVAILABLE: "lock_not_available",
    _pg.OBJECT_NOT_IN_PREREQUISITE_STATE: "detach_pending",
}


def _no_second_connection(engine: Engine) -> str:
    return (
        "drop_expired with integrity needs a second connection from the pool "
        f"of {engine!r}, besides the one it was given, and the pool "
        f"({engine.pool.status()}) has no free one; give the pool room for "
        "one more connection"
    )


def _check_free_slot(engine: Engine) -> None:
    """Raise ``PartitionError`` when the pool cannot give another connection.

    Checked before ``connect`` so that a full pool fails at once, not after
    its ``pool_timeout``. A pool that hands out one shared connection can
    never give a second one.
    """
    pool = engine.pool
    if isinstance(pool, StaticPool | SingletonThreadPool | AssertionPool):
        raise PartitionError(_no_second_connection(engine))
    if isinstance(pool, QueuePool):
        limit = pool.size() + pool._max_overflow
        if pool._max_overflow >= 0 and pool.checkedout() >= limit:
            raise PartitionError(_no_second_connection(engine))


def chain_started(connection: Connection, tables: AuditTables) -> bool:
    """Whether the block table of ``tables`` holds any block.

    With none, the chain has not been started (``write_genesis``), nothing
    was sealed, and ``drop_expired`` drops as without integrity. A block
    table that holds blocks but no genesis is refused by ``seal``.
    """
    block = block_table(tables)
    found = connection.execute(select(block.c.seq).limit(1)).first()
    return found is not None


class Retirer:
    """Seals, verifies and retires expired partitions for ``drop_expired``.

    Private for now. A context manager: it holds a second connection from
    the engine of ``connection`` while it is open. A pool that cannot give
    one at once raises ``PartitionError`` instead of waiting for its
    ``pool_timeout``.

    Args:
        connection: The ``AUTOCOMMIT`` connection of ``drop_expired``.
        tables: Audit tables built with integrity.
        verify_before_drop: Verify the expired partitions before the first
            detach, and skip those it fails. Retention is not judged there
            (``RETIRED_EARLY`` is for a verifier given the retention from
            elsewhere): a retire block already written stays either way.
    """

    def __init__(
        self,
        connection: Connection,
        tables: AuditTables,
        *,
        verify_before_drop: bool,
    ) -> None:
        self._engine = connection.engine
        self._tables = tables
        self._block = block_table(tables)
        self._verify_before_drop = verify_before_drop
        self._conn: Connection | None = None
        self._blocked: dict[str, SkippedPartition] = {}
        self.skipped: list[SkippedPartition] = []
        # What the blocks read so far say about the expired partitions: their
        # sealed segments, and their retire blocks. Each block is read once
        # per call (``_scan``).
        self._wanted: set[str] = set()
        self._sealed: dict[str, dict[tuple[int, str], SealedSegment]] = {}
        self._retired: dict[str, _RetireBlock] = {}
        self._scanned = 0

    def __enter__(self) -> Retirer:
        _check_free_slot(self._engine)
        try:
            conn = self._engine.connect()
        except PoolTimeoutError as exc:
            raise PartitionError(_no_second_connection(self._engine)) from exc
        # Not AUTOCOMMIT, whatever the engine's default: the chain needs
        # transactions.
        self._conn = conn.execution_options(isolation_level="READ COMMITTED")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    @property
    def conn(self) -> Connection:
        if self._conn is None:
            raise RuntimeError("the Retirer is not open")
        return self._conn

    # -- before the first detach --

    def prepare(
        self, expired: Iterable[_Child], *, detached: Iterable[_Child] = ()
    ) -> None:
        """Seal, read the chain and verify the expired partitions.

        Every step runs in transactions of its own, ended before it returns,
        so none of them holds a snapshot while a partition is detached.
        ``detached`` are expired partitions already detached, which
        ``verify`` reports as such; only its other failures keep them.

        Raises:
            SealRefusedError: The chain has no genesis block, or the
                transaction ids were rewound; nothing was dropped.
        """
        orphans = list(detached)
        children = [*expired, *orphans]
        self._wanted = {child.name for child in children}
        # Only up to the horizon of now: writers that outpace the sealer
        # would keep a loop to the moving horizon capped forever.
        with self.conn.begin():
            up_to = snapshot_horizon(self.conn)
        while seal(self.conn, self._tables, up_to=up_to).capped:
            pass
        self._scan()
        if not self._verify_before_drop or not children:
            return
        options = VerifyOptions(None, None, DEFAULT_CHUNK_ROWS, frozenset(self._wanted))
        report = run_verification(self.conn, self._tables, self._block, options)
        # A pending detach is what this call finishes; an orphan, what it
        # drops.
        pending = {child.name for child in children if child.pending}
        pending |= {child.name for child in orphans}
        for finding in report.failures:
            if finding.partition is None:
                # The chain itself is broken: a retire block would extend it.
                targets = self._wanted
            elif finding.partition in self._wanted:
                if (
                    finding.kind is FailureKind.DETACHED_PARTITION
                    and finding.partition in pending
                ):
                    continue
                targets = {finding.partition}
            else:
                continue
            for child in children:
                if child.name in targets and child.name not in self._blocked:
                    self._blocked[child.name] = SkippedPartition(
                        child.display,
                        "verify_failed",
                        f"verify found {finding.kind}: {finding.detail}",
                    )

    # -- each partition --

    def retire(self, target: _RetentionTarget, child: _Child) -> bool:
        """Append the retire block of ``child``; whether it may be detached.

        Under the sealer's lock, so it is ordered with the seal blocks, and
        committed before it returns. A partition already retired keeps its
        block; the insert does nothing.
        """
        blocked = self._blocked.get(child.name)
        if blocked is not None:
            return self._skip(blocked)
        conn = self.conn
        block = self._block
        with conn.begin():
            conn.execute(text("SET TRANSACTION ISOLATION LEVEL READ COMMITTED"))
            # Waits for a running sealer; later statements see its block.
            _pg.xact_lock(conn, _pg.lock_key(block))
            last = last_block(conn, block)
            sealed = sealed_horizon(conn, block)
            if last is None or sealed is None:
                raise ValueError(
                    f"{block.fullname} has no genesis block; run "
                    "migrations.write_genesis() first"
                )
            chain, sealed_to = sealed
            if self._unsealed(conn, child, sealed_to):
                return self._skip(
                    SkippedPartition(
                        child.display,
                        "unsealed",
                        "it holds rows the chain has not sealed yet, held back "
                        "by a transaction still open; retry later",
                    )
                )
            self._scan(conn)
            seq = int(last.seq) + 1
            table, streams = _table_streams(target)
            assert child.upper is not None  # only expired partitions retire
            body = retire_body(
                chain,
                seq,
                table=table,
                partition=child.name,
                streams=streams,
                upper_bound=child.upper,
                retention=(
                    None if target.limit is None else int(target.limit.total_seconds())
                ),
                segments=self._sealed.get(child.name, {}).values(),
            )
            prev = bytes(last.block_hash)
            inserted = conn.execute(
                pg_insert(block)
                .values(
                    seq=seq,
                    kind="retire",
                    body=body,
                    prev_hash=prev,
                    block_hash=block_hash(prev, body),
                    retired_partition=child.name,
                )
                .on_conflict_do_nothing(
                    index_elements=[block.c.retired_partition],
                    index_where=block.c.retired_partition.is_not(None),
                )
            ).rowcount
        if inserted:
            logger.info("retired partition %s in block %s", child.display, seq)
        return True

    def ddl(self, connection: Connection, sql: str, child: _Child) -> bool:
        """Run a detach or drop; whether it ran.

        ``55P03`` and ``55000`` skip the partition and are reported; any
        other error is raised.
        """
        try:
            _pg.execute_ddl(connection, sql)
        except DBAPIError as exc:
            reason = _DDL_SKIPS.get(_pg.sqlstate(exc) or "")
            if reason is None:
                raise
            return self._skip(
                SkippedPartition(
                    child.display, reason, str(exc.orig).strip().splitlines()[0]
                )
            )
        return True

    def check_orphan(self, target: _RetentionTarget, child: _Child) -> bool:
        """Whether the detached ``child`` has a valid retire block.

        Valid is what ``verify`` accepts: the block names the partition, the
        table and streams of ``target`` and the bound of ``child``, and
        covers exactly the segments of the partition sealed before it.
        """
        retired = self._retired.get(child.name)
        if retired is None or not _covers(retired, target, child, self._sealed):
            return self._skip(
                SkippedPartition(
                    child.display,
                    "not_retired",
                    "it is detached without a valid retire block; it is left "
                    "in place, for verify to report",
                )
            )
        return True

    def check_detached(self, child: _Child) -> bool:
        """Whether the detached ``child`` is wholly covered by its retire block."""
        conn = self.conn
        with _pg.read_only(conn):
            self._scan(conn)
            sealed = sealed_horizon(conn, self._block)
            unsealed = sealed is not None and self._unsealed(conn, child, sealed[1])
        retired = self._retired.get(child.name)
        later = retired is not None and any(
            seq > retired.seq for seq, _stream in self._sealed.get(child.name, {})
        )
        if retired is None or later or unsealed:
            return self._skip(
                SkippedPartition(
                    child.display,
                    "changed_after_retire",
                    "rows reached it after its retire block was written; it is "
                    "left detached, for verify to report",
                )
            )
        return True

    # -- helpers --

    def _skip(self, skipped: SkippedPartition) -> bool:
        logger.warning(
            "kept expired partition %s (%s): %s",
            skipped.partition,
            skipped.reason,
            skipped.detail,
        )
        self.skipped.append(skipped)
        return False

    def _unsealed(self, conn: Connection, child: _Child, sealed_to: int) -> bool:
        table = Table(
            child.name,
            MetaData(),
            Column(_schema.XID, Xid8()),
            schema=child.schema,
        )
        xid = table.c[_schema.XID]
        found = conn.execute(
            select(literal_column("1", Integer))
            .select_from(table)
            .where(xid >= bindparam("sealed_to", sealed_to, type_=Xid8()))
            .limit(1)
        ).first()
        return found is not None

    def _scan(self, conn: Connection | None = None) -> None:
        """Read the blocks written since the last scan.

        Keeps the segments and the retire blocks of the expired partitions.
        Without ``conn``, in short transactions of its own; with one, in its
        transaction.
        """
        for seq, retired, segments in self._seal_blocks(conn, self._scanned):
            self._scanned = seq
            if retired is not None and retired.partition in self._wanted:
                self._retired.setdefault(retired.partition, retired)
            for segment in segments:
                if segment.partition in self._wanted:
                    self._sealed.setdefault(segment.partition, {})[
                        (seq, segment.stream)
                    ] = SealedSegment(seq, segment)

    def _seal_blocks(
        self, conn: Connection | None, after: int
    ) -> Iterable[tuple[int, _RetireBlock | None, list[Segment]]]:
        """``(seq, retire block, segments)`` of every block after ``after``.

        In order. A block that is not a retire block has ``None``; one that
        is not a seal block has no segments. Malformed seal bodies have no
        segments either; ``verify`` reports them.
        """
        block = self._block
        while True:
            statement = (
                select(
                    block.c.seq, block.c.kind, block.c.body, block.c.retired_partition
                )
                .where(block.c.seq > after)
                .order_by(block.c.seq)
                .limit(_schema.BLOCK_CHUNK_ROWS)
            )
            if conn is None:
                with _pg.read_only(self.conn):
                    rows = self.conn.execute(statement).all()
            else:
                rows = conn.execute(statement).all()
            for row in rows:
                seq = int(row.seq)
                after = seq
                if row.kind == "retire" and row.retired_partition is not None:
                    yield (
                        seq,
                        _RetireBlock(seq, str(row.retired_partition), bytes(row.body)),
                        [],
                    )
                    continue
                if row.kind != "seal":
                    yield seq, None, []
                    continue
                try:
                    body = parse_body(bytes(row.body))
                except (UnicodeDecodeError, ValueError):
                    yield seq, None, []
                    continue
                parsed = parse_segments(seq, body.get("segments")) or []
                yield (
                    seq,
                    None,
                    [Segment(s.stream, s.partition, s.rows, s.root) for s in parsed],
                )
            if len(rows) < _schema.BLOCK_CHUNK_ROWS:
                return


def _table_streams(target: _RetentionTarget) -> tuple[str, list[str]]:
    """The table and the streams of the partitions of ``target``."""
    if target.values is None:
        return TRANSACTION, [TRANSACTION_STREAM]
    return ACTIVITY, [activity_stream(value) for value in sorted(target.values)]


def _covers(
    retired: _RetireBlock,
    target: _RetentionTarget,
    child: _Child,
    sealed: dict[str, dict[tuple[int, str], SealedSegment]],
) -> bool:
    """Whether ``retired`` is a valid retire block of ``child``."""
    try:
        body = parse_body(retired.body)
    except (UnicodeDecodeError, ValueError):
        return False
    table, streams = _table_streams(target)
    if child.upper is None or (
        body.get("kind"),
        body.get("partition"),
        body.get("table"),
        body.get("streams"),
        body.get("upper_bound"),
    ) != ("retire", child.name, table, sorted(streams), rfc3339(child.upper)):
        return False
    before = [
        segment
        for (seq, _stream), segment in sealed.get(child.name, {}).items()
        if seq < retired.seq
    ]
    coverage = retire_coverage(before)
    return {name: body.get(name) for name in coverage} == coverage


@dataclass(frozen=True)
class _RetireBlock:
    """A retire block as stored: its number, partition and body."""

    seq: int
    partition: str
    body: bytes
