"""``verify`` and ``acknowledge`` against the database.

Private for now. ``verify`` reads the catalog, the chain and then each
partition in short ``READ ONLY`` transactions, one per chunk of rows in
``(xid, id)`` order, and feeds them to the pure ``Verifier``. It never holds
one snapshot over the whole log: a long snapshot would hold back vacuum and
block ``DETACH ... CONCURRENTLY``, and sealed rows need none.
``acknowledge`` appends an ``ack`` block to the chain, under the sealer's
lock.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable, Iterator, Mapping
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
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from audit_trail import _pg
from audit_trail.integrity import _schema
from audit_trail.integrity._block import ack_body, parse_body
from audit_trail.integrity._checkpoint import Checkpoint
from audit_trail.integrity._seal import (
    block_table,
    insert_block,
    last_block,
    missing_block_table,
)
from audit_trail.integrity._sign import SignatureVerifier, Signer
from audit_trail.integrity._types import Xid8
from audit_trail.integrity._verify import (
    ACTIVITY,
    TRANSACTION,
    Ack,
    FailureKind,
    Partition,
    StoredBlock,
    VerificationReport,
    Verifier,
    check_scope,
    failure_kind,
    pin,
    pin_key,
    stream_retention,
)
from audit_trail.maintenance import _children, _oid, _orphans, _qualified
from audit_trail.tables import AuditTables

DEFAULT_CHUNK_ROWS = 2_000
"""Rows read per ``READ ONLY`` transaction."""

_XMAX = text("SELECT pg_snapshot_xmax(pg_current_snapshot())::text")


@dataclass(frozen=True)
class _Leaf:
    partition: Partition
    schema: str


@dataclass(frozen=True)
class VerifyOptions:
    """What a run takes besides the connection and the tables."""

    streams: dict[str, timedelta | None] | None
    system_severity: int | None
    chunk_rows: int
    partitions: frozenset[str] | None = None
    """Read only these partitions, by name; ``None`` reads every one."""
    checkpoints: tuple[Checkpoint, ...] = ()
    signatures: SignatureVerifier | None = None
    require_signatures: bool = False


def _options(
    retention: Mapping[int, timedelta | None] | None,
    transaction_retention: timedelta | None,
    system_severity: int | None,
    chunk_rows: int,
    checkpoints: Iterable[Checkpoint | str] = (),
    verifier: SignatureVerifier | None = None,
    require_signatures: bool = False,
) -> VerifyOptions:
    if chunk_rows < 1:
        raise ValueError("chunk_rows must be at least 1")
    if require_signatures and verifier is None:
        raise ValueError("require_signatures needs a verifier")
    streams = None
    if retention is not None:
        streams = stream_retention(retention, transaction_retention)
    read = tuple(
        Checkpoint.from_note(c) if isinstance(c, str) else c for c in checkpoints
    )
    return VerifyOptions(
        streams,
        system_severity,
        chunk_rows,
        checkpoints=read,
        signatures=verifier,
        require_signatures=require_signatures,
    )


def verify(
    engine: Engine,
    tables: AuditTables,
    *,
    retention: Mapping[int, timedelta | None] | None = None,
    transaction_retention: timedelta | None = None,
    system_severity: int | None = None,
    chunk_rows: int = DEFAULT_CHUNK_ROWS,
    checkpoints: Iterable[Checkpoint | str] = (),
    verifier: SignatureVerifier | None = None,
    require_signatures: bool = False,
) -> VerificationReport:
    """Check the hash chain and every row it seals; report all failures.

    Private for now. Runs on one connection of its own from ``engine``,
    which it holds only between short ``READ ONLY`` transactions; it takes
    no lock, so runs side by side are fine and a pool of one does. It reads
    the catalog, then the chain, then the horizon, then each partition in
    chunks of ``chunk_rows`` rows, each in its own transaction, keyset-paged
    by ``(xid, id)``. A partition dropped during the run is read again once
    from the catalog; dropped again, it is reported as absent.

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
        checkpoints: Trusted checkpoints, kept off the database host, as
            ``Checkpoint`` objects or the note texts ``to_note`` gave. Each
            must name a block of the chain with its hash: a chain shorter
            than one is ``TRUNCATED``, another hash at its ``seq`` is
            ``CHAIN_MISMATCH``, and either one explained by a fork block
            after the fork's own prior checkpoint, signed by a key
            ``verifier`` knows, is a ``FORKED`` note; only a checkpoint
            taken before the fork (in an earlier incarnation) is explained.
            With ``verifier``, a signed checkpoint must verify by
            c2sp.org/signed-note rules, or it is ``BAD_SIGNATURE`` /
            ``UNKNOWN_KEY`` and is not used. The
            report is ``ANCHORED`` when one matched, and the blocks after
            the newest match are an ``UNANCHORED_TAIL`` note.
        verifier: Checks the signatures of signed blocks and checkpoints.
        require_signatures: Every block and every checkpoint must be
            signed by a key ``verifier`` knows.

    Returns:
        The report.

    Raises:
        TypeError: The engine is an ``AsyncEngine``; use ``averify``.
        ValueError: The tables were built without integrity, the chain has
            no genesis block, ``chunk_rows`` is below 1, a checkpoint text
            is not a checkpoint (a ``NoteError``), ``require_signatures``
            has no ``verifier``, or the database is a logical-replication
            subscriber of the block table: its rows carry the publisher's
            transaction ids, so verify on the publisher.
    """
    if not isinstance(engine, Engine):
        raise TypeError("the engine is async; use averify")
    options = _options(
        retention,
        transaction_retention,
        system_severity,
        chunk_rows,
        checkpoints,
        verifier,
        require_signatures,
    )
    block = block_table(tables)
    with engine.connect() as conn:
        return run_verification(conn, tables, block, options)


async def averify(
    engine: AsyncEngine,
    tables: AuditTables,
    *,
    retention: Mapping[int, timedelta | None] | None = None,
    transaction_retention: timedelta | None = None,
    system_severity: int | None = None,
    chunk_rows: int = DEFAULT_CHUNK_ROWS,
    checkpoints: Iterable[Checkpoint | str] = (),
    verifier: SignatureVerifier | None = None,
    require_signatures: bool = False,
) -> VerificationReport:
    """Async ``verify``, for an ``AsyncEngine``; the same arguments.

    Private for now. Runs ``verify``'s reads on one connection through
    ``run_sync``.

    Raises:
        TypeError: The engine is a sync ``Engine``; use ``verify``.
        ValueError: As ``verify``.
    """
    if not isinstance(engine, AsyncEngine):
        raise TypeError("the engine is sync; use verify")
    options = _options(
        retention,
        transaction_retention,
        system_severity,
        chunk_rows,
        checkpoints,
        verifier,
        require_signatures,
    )
    block = block_table(tables)
    async with engine.connect() as conn:
        return await conn.run_sync(
            lambda sync_conn: run_verification(sync_conn, tables, block, options)
        )


class _Vanished(Exception):
    """A partition in the catalog read was gone when its rows were read."""


def run_verification(
    conn: Connection, tables: AuditTables, block: Table, options: VerifyOptions
) -> VerificationReport:
    """One run, read again from the catalog once if a partition vanishes.

    ``drop_expired`` writes a retire block and then drops the partition; a
    run that read the catalog before the drop finds the partition gone. A
    second run reads the catalog without it and the chain with its retire
    block. A partition that vanishes during the second run is not retried:
    it is reported as absent, like one dropped before the run.
    """
    with _pg.read_only(conn):
        subscribed = conn.execute(
            text(f"SELECT {_pg.SUBSCRIBED}"), {"table": _pg.regclass(conn, block)}
        ).scalar_one()
    if subscribed:
        # Every replicated row would read as XID_REWIND against this
        # server's own horizon, and its seal blocks are the publisher's.
        raise ValueError(
            f"{block.fullname} is written by a logical-replication "
            "subscription: verify on the publisher. After a cutover, drop the "
            "subscription and declare a fork first"
        )
    try:
        return _run(conn, tables, block, options, retry=True)
    except _Vanished:
        return _run(conn, tables, block, options, retry=False)


def _run(
    conn: Connection,
    tables: AuditTables,
    block: Table,
    options: VerifyOptions,
    *,
    retry: bool,
) -> VerificationReport:
    # The order matters. The catalog before the chain: a partition dropped
    # after its retire block was read is still listed, and its read is
    # retried. The chain before the horizon: every seal block read ends at
    # or below an xmin taken after it.
    with _pg.read_only(conn):
        leaves, detached = _catalog(conn, tables)
    blocks = _blocks(conn, block)
    first = next(blocks, None)
    if first is None:
        raise ValueError(
            f"{block.fullname} has no genesis block; run "
            "migrations.write_genesis() first"
        )
    verifier = Verifier(
        itertools.chain([first], blocks),
        retention=options.streams,
        system_severity=options.system_severity,
        count_scrubs=options.partitions is None,
        signatures=options.signatures,
        require_signatures=options.require_signatures,
        checkpoints=options.checkpoints,
    )
    with _pg.read_only(conn):
        horizon, xmax = (
            int(value)
            for value in conn.execute(
                text(
                    "SELECT pg_snapshot_xmin(s)::text, pg_snapshot_xmax(s)::text "
                    "FROM pg_current_snapshot() AS s"
                )
            ).one()
        )
    verifier.set_horizon(horizon, xmax)
    for leaf in leaves:
        parent = (
            tables.transaction
            if leaf.partition.table == TRANSACTION
            else (tables.activity)
        )
        if options.partitions is not None and (
            leaf.partition.name not in options.partitions
        ):
            verifier.skip_partition(leaf.partition)
            continue
        table = _partition_table(parent, leaf)
        try:
            verifier.check_partition(
                leaf.partition, _rows(conn, table, options.chunk_rows, verifier)
            )
            with _pg.read_only(conn):
                nulls = conn.execute(
                    select(func.count())
                    .select_from(table)
                    .where(table.c[_schema.XID].is_(None))
                ).scalar_one()
        except DBAPIError as exc:
            if not _pg.is_sqlstate(exc, _pg.UNDEFINED_TABLE):
                raise
            if retry:
                raise _Vanished(leaf.partition.name) from exc
            continue
        verifier.null_xid_rows(leaf.partition, int(nulls))
    verifier.schema(detached)
    return verifier.report()


def _blocks(conn: Connection, block: Table) -> Iterator[StoredBlock]:
    """Every block in ``seq`` order, in chunks of short transactions."""
    after = 0
    while True:
        with _pg.read_only(conn):
            rows = conn.execute(
                select(
                    block.c.seq,
                    block.c.kind,
                    block.c.body,
                    block.c.prev_hash,
                    block.c.block_hash,
                    block.c.sealed_at,
                    block.c.signature,
                    block.c.key_id,
                    block.c.alg,
                )
                .where(block.c.seq > after)
                .order_by(block.c.seq)
                .limit(_schema.BLOCK_CHUNK_ROWS)
            ).all()
        for row in rows:
            yield StoredBlock(
                int(row.seq),
                str(row.kind),
                bytes(row.body),
                bytes(row.prev_hash),
                bytes(row.block_hash),
                row.sealed_at,
                None if row.signature is None else bytes(row.signature),
                row.key_id,
                row.alg,
            )
        if len(rows) < _schema.BLOCK_CHUNK_ROWS:
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


def _rows(
    conn: Connection, table: Table, chunk_rows: int, verifier: Verifier
) -> Iterator[dict[str, Any]]:
    """The rows of a partition with an ``xid``, in ``(xid, id)`` order.

    After each chunk, in the same transaction, the snapshot's ``xmax`` is
    read and given to the verifier. Read after the rows, it is at least the
    ``xmax`` of the snapshot that read them, so every real row is below it.
    """
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
        with _pg.read_only(conn):
            rows = [dict(row) for row in conn.execute(statement).mappings()]
            xmax = conn.execute(_XMAX).scalar_one()
        verifier.observe_xmax(int(xmax))
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
    *,
    retention: Mapping[int, timedelta | None] | None = None,
    transaction_retention: timedelta | None = None,
    system_severity: int | None = None,
    chunk_rows: int = DEFAULT_CHUNK_ROWS,
    signer: Signer | None = None,
) -> int:
    """Waive a known incident with an ``ack`` block in the chain.

    Private for now. Runs ``verify`` on the connection first, and pins the
    failures of ``kind`` that ``scope`` matches as it observed them: the
    rows for a failure about a row, the root and row count for a segment,
    every field for the rest. Later verifications report those failures as
    ``ACKNOWLEDGED`` notes naming this block, instead of failing; a failure
    that is new or changed since, in the same scope, is reported again. The
    ack stays in the chain for every later reader. Takes the sealer's
    advisory lock and appends the block after the last one, hashed like
    every block, in a ``READ COMMITTED`` transaction of its own that it
    commits.

    Args:
        connection: A connection that may insert into the block table, not
            in a transaction and not in ``AUTOCOMMIT`` mode.
        tables: Audit tables built with integrity.
        kind: The failure kind to waive; only those about rows and
            partitions (``ACKNOWLEDGEABLE``).
        scope: What it covers; keys from ``SCOPE_KEYS``, at least one other
            than ``table``, such as ``{"xid_from": a, "xid_to": b}`` for a
            writer that ran without ``Integrity``.
        reason: Why, for whoever reads the chain; it is stored in clear.
        retention: As ``verify`` takes it, to observe ``RETIRED_EARLY``.
        transaction_retention: As ``verify`` takes it.
        system_severity: As ``verify`` takes it.
        chunk_rows: As ``verify`` takes it.
        signer: Signs the ack block; ``None`` leaves it unsigned.

    Returns:
        The ``seq`` of the ack block.

    Raises:
        ValueError: The kind cannot be waived, the scope is invalid, no
            failure of the kind is in the scope, the tables were built
            without integrity, the chain has no genesis block, or the
            connection is in a transaction or ``AUTOCOMMIT`` mode.
    """
    failure = failure_kind(str(kind))
    checked = check_scope(scope)
    options = _options(retention, transaction_retention, system_severity, chunk_rows)
    block = block_table(tables)
    if getattr(connection.connection.dbapi_connection, "autocommit", False):
        raise ValueError("acknowledge needs a transaction, not AUTOCOMMIT")
    if connection.in_transaction():
        raise ValueError(
            "acknowledge runs its own transaction; pass a connection that is "
            "not in a transaction"
        )
    report = run_verification(connection, tables, block, options)
    wanted = Ack(0, failure, checked)
    pins = {pin_key(f): pin(f) for f in report.failures if wanted.in_scope(f)}
    if not pins:
        raise ValueError(
            f"no {failure} failure in this scope; an ack would waive nothing"
        )
    waives = [pins[key] for key in sorted(pins, key=repr)]
    with connection.begin():
        connection.execute(text("SET TRANSACTION ISOLATION LEVEL READ COMMITTED"))
        # Blocks until no sealer runs; later statements see its block.
        _pg.xact_lock(connection, _pg.lock_key(block))
        created = connection.execute(
            text("SELECT to_regclass(:block) IS NOT NULL"),
            {"block": _pg.regclass(connection, block)},
        ).scalar_one()
        if not created:
            raise ValueError(missing_block_table(block))
        genesis = connection.execute(
            select(block.c.kind, block.c.body).where(block.c.seq == 1)
        ).one_or_none()
        last = last_block(connection, block)
        if genesis is None or genesis.kind != "genesis" or last is None:
            raise ValueError(
                f"{block.fullname} has no genesis block; run "
                "migrations.write_genesis() first"
            )
        chain = str(parse_body(bytes(genesis.body))["chain"])
        seq = int(last.seq) + 1
        body = ack_body(
            chain,
            seq,
            failure=failure.value,
            scope=checked,
            waives=waives,
            reason=reason,
        )
        insert_block(
            connection, block, seq, "ack", bytes(last.block_hash), body, signer
        )
    return seq


async def aacknowledge(
    connection: AsyncConnection,
    tables: AuditTables,
    kind: FailureKind | str,
    scope: Mapping[str, object],
    reason: str,
    *,
    retention: Mapping[int, timedelta | None] | None = None,
    transaction_retention: timedelta | None = None,
    system_severity: int | None = None,
    chunk_rows: int = DEFAULT_CHUNK_ROWS,
    signer: Signer | None = None,
) -> int:
    """Async ``acknowledge``, on an ``AsyncConnection``; the same arguments.

    Private for now. Runs ``acknowledge`` through ``run_sync``.

    Returns:
        The ``seq`` of the ack block.

    Raises:
        ValueError: As ``acknowledge``.
    """
    return await connection.run_sync(
        lambda sync_conn: acknowledge(
            sync_conn,
            tables,
            kind,
            scope,
            reason,
            retention=retention,
            transaction_retention=transaction_retention,
            system_severity=system_severity,
            chunk_rows=chunk_rows,
            signer=signer,
        )
    )
