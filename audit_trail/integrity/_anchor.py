"""Checkpoints and forks against the database.

Private for now.

``export_checkpoint`` appends a ``checkpoint`` block, so the chain records
that an anchor was taken, and returns the checkpoint naming it. Storing it
off the database host is the caller's job: S3 Object Lock in compliance
mode, an RFC 3161 timestamp, or a printed sheet. With
``require_replicated`` it first waits until the synchronous standbys have
flushed the block, so that a failover that loses the newest blocks is not
mistaken for an attack.

``declare_fork`` starts a new incarnation of the chain after a restore,
before any writer runs. How it is used depends on how the database came
back:

- PITR, or a base backup started as a primary: transaction ids carry on
  (repeating some, harmlessly, since the blocks after the restore point are
  gone too). The fork has no id window.
- ``pg_dump`` / ``pg_restore`` with ``pg_resetwal --epoch`` (self-hosted):
  the epoch moves the ids above every stored one, so again no id window.
- ``pg_dump`` / ``pg_restore`` on a managed service: ids start low again
  (``XID_REWIND``), and the fork records an id window. Every incarnation's
  blocks select by ``xid`` range and ``id_floor[i] < id <= id_floor[i+1]``.

A fork first seals what the old incarnation left unsealed (the closing
seal), and needs the last good checkpoint, which must still be in the
chain. ``verify`` reports a fork as a ``FORKED`` note, and given a
checkpoint taken after the fork's own but before the fork (in an earlier
incarnation), explains the divergence only when the fork block is signed by
a key it knows. A checkpoint taken after the fork is never explained by it.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Literal

from sqlalchemy import Connection, Table, desc, func, select, text

from audit_trail import _pg
from audit_trail.integrity import _schema
from audit_trail.integrity._block import (
    TRANSACTION_STREAM,
    SegmentBuilder,
    activity_stream,
    checkpoint_body,
    fork_body,
    seal_body,
)
from audit_trail.integrity._checkpoint import Checkpoint
from audit_trail.integrity._seal import (
    SealRefusedError,
    block_table,
    current_window,
    insert_block,
    last_block,
    leaf_rows,
    sealed_horizon,
    sequence_value,
    window_clauses,
)
from audit_trail.integrity._sign import Signer
from audit_trail.tables import AuditTables

DEFAULT_REPLICATION_TIMEOUT = timedelta(seconds=30)
"""Default wait for the synchronous standbys in ``export_checkpoint``."""

ANCHOR_KINDS = ("genesis", "checkpoint", "fork")
"""Blocks a fork can name as its last good checkpoint."""

NO_STANDBY_GRACE = timedelta(seconds=2)
"""How long ``require_replicated`` waits for a configured synchronous standby
that is not connected (one reconnecting) before ``NO_SYNC_STANDBY``."""

ReplicationProblem = Literal["NO_SYNC_STANDBY", "NOT_REPLICATED", "CHECK_FAILED"]

SyncRule = tuple[Literal["FIRST", "ANY"], int]
"""``(method, num_sync)`` of ``synchronous_standby_names``."""


class ReplicationError(Exception):
    """The checkpoint block was not confirmed by the synchronous standbys.

    The block is in the chain already; no checkpoint was returned. A later
    export, once the standbys are back, writes a new one.

    Attributes:
        reason: ``NO_SYNC_STANDBY``: ``synchronous_standby_names`` is empty,
            or ``pg_stat_replication`` lists fewer standbys with
            ``sync_state`` ``sync`` (``FIRST n``) or ``quorum`` (``ANY n``)
            than it asks for, for longer than ``NO_STANDBY_GRACE`` (or the
            role cannot see them: reading the view needs ``pg_monitor``).
            ``NOT_REPLICATED``: they are listed, but not as many as it asks
            for flushed the block's WAL within the timeout.
            ``CHECK_FAILED``: reading the WAL position or the standbys
            failed; the cause is chained.
        seq: The checkpoint block.
        lsn: The WAL position the standbys had to reach; empty when reading
            it failed.
    """

    def __init__(
        self, reason: ReplicationProblem, message: str, *, seq: int, lsn: str
    ) -> None:
        super().__init__(f"{reason}: {message}")
        self.reason: ReplicationProblem = reason
        self.seq = seq
        self.lsn = lsn


def export_checkpoint(
    connection: Connection,
    tables: AuditTables,
    *,
    signer: Signer | None = None,
    require_replicated: bool = False,
    replication_timeout: timedelta = DEFAULT_REPLICATION_TIMEOUT,
) -> Checkpoint:
    """Append a checkpoint block and return the checkpoint that names it.

    Private for now. Takes the sealer's advisory lock (waiting for a running
    sealer) in a ``READ COMMITTED`` transaction of its own, appends a
    ``checkpoint`` block after the last block, and commits. The statement is
    ``{v, chain, seq, block_hash, xid_to, sealed_at, incarnation}`` of that
    block, framed as a C2SP signed note by ``Checkpoint.to_note``.

    With ``require_replicated``, after the commit it reads
    ``pg_current_wal_insert_lsn()``, at or past the block's commit record,
    and polls ``pg_stat_replication`` until as many synchronous standbys as
    ``synchronous_standby_names`` asks for have flushed that far: the ``n``
    with ``sync_state = 'sync'`` for ``FIRST n`` (or a plain list, ``FIRST
    1``), ``n`` of those with ``quorum`` for ``ANY n``. ``flush_lsn``, not
    ``replay_lsn``: the block is safe once it is on the standby's disk. With
    ``synchronous_commit = on`` and a synchronous standby the commit already
    waited for it; the check matters with ``local`` or ``off``, and with
    quorum setups.

    Args:
        connection: A connection that may insert into the block table, not
            in a transaction and not in ``AUTOCOMMIT`` mode.
        tables: Audit tables built with integrity.
        signer: Signs the block and the note; ``None`` exports the
            statement unsigned (keep it where it cannot be changed).
        require_replicated: Return the checkpoint only once the synchronous
            standbys have flushed the block.
        replication_timeout: How long to wait for that.

    Returns:
        The checkpoint, signed by ``signer`` if given.

    Raises:
        ValueError: The tables were built without integrity, the connection
            is in a transaction or in ``AUTOCOMMIT`` mode, or the server is
            in recovery.
        SealRefusedError: ``NO_GENESIS``.
        ReplicationError: ``require_replicated``, and the synchronous
            standbys did not confirm the block, or checking them failed;
            any error after the commit is one, with ``seq`` and ``lsn``.
    """
    block = block_table(tables)
    _pg.check_transactional(connection, "export_checkpoint")
    _check_idle(connection, "export_checkpoint")
    with connection.begin():
        _lock(connection, block)
        head = sealed_horizon(connection, block)
        last = last_block(connection, block)
        if head is None or last is None:
            raise _no_genesis(block)
        chain, xid_to = head
        incarnation = current_window(connection, block).incarnation
        seq = int(last.seq) + 1
        body = checkpoint_body(chain, seq, xid_to)
        digest = insert_block(
            connection, block, seq, "checkpoint", bytes(last.block_hash), body, signer
        )
        sealed_at = connection.execute(
            select(block.c.sealed_at).where(block.c.seq == seq)
        ).scalar_one()
    if require_replicated:
        wait_replicated(connection, seq, replication_timeout)
    checkpoint = Checkpoint(chain, seq, digest, xid_to, sealed_at, incarnation)
    return checkpoint if signer is None else checkpoint.signed([signer])


_SYNC_RULE = re.compile(
    r"(?:(FIRST|ANY)\s+)?(\d+)\s*\((.*)\)", re.IGNORECASE | re.DOTALL
)


def sync_rule(names: str | None) -> SyncRule | None:
    """How many synchronous standbys ``synchronous_standby_names`` asks for.

    ``FIRST n (...)`` and ``n (...)``: the first ``n`` connected standbys by
    priority; ``ANY n (...)``: any ``n`` of them (quorum); a plain list of
    names: ``FIRST 1``.

    Returns:
        ``(method, n)``, or ``None`` when the setting is empty (no standby
        is synchronous) or asks for fewer than one.
    """
    text = (names or "").strip()
    if not text:
        return None
    match = _SYNC_RULE.fullmatch(text)
    if match is None:
        return "FIRST", 1
    count = int(match.group(2))
    if count < 1:
        return None
    method: Literal["FIRST", "ANY"] = (
        "ANY" if (match.group(1) or "").upper() == "ANY" else "FIRST"
    )
    return method, count


def replication_state(
    standbys: Iterable[tuple[str | None, bool | None]],
    rule: SyncRule | None,
) -> Literal["none", "waiting", "confirmed"]:
    """Whether the synchronous standbys confirmed a WAL position.

    Args:
        standbys: ``(sync_state, flush_lsn >= position)`` of each row of
            ``pg_stat_replication``.
        rule: What ``synchronous_standby_names`` asks for (``sync_rule``).

    Returns:
        ``none`` without a rule, or with fewer standbys of its kind (``sync``
        for ``FIRST``, ``quorum`` for ``ANY``) than it asks for;
        ``confirmed`` when as many as it asks for flushed the position;
        else ``waiting``.
    """
    if rule is None:
        return "none"
    method, count = rule
    kind = "sync" if method == "FIRST" else "quorum"
    flushed = [bool(done) for state, done in standbys if state == kind]
    if len(flushed) < count:
        return "none"
    return "confirmed" if sum(flushed) >= count else "waiting"


_INSERT_LSN = text("SELECT pg_current_wal_insert_lsn()::text")

_SYNC_NAMES = text("SELECT current_setting('synchronous_standby_names')")

_STANDBYS = text(
    "SELECT sync_state, flush_lsn >= CAST(:lsn AS pg_lsn) AS flushed "
    "FROM pg_stat_replication"
)


def _poll(
    connection: Connection, lsn: str
) -> tuple[str | None, list[tuple[str | None, bool | None]]]:
    """``synchronous_standby_names`` and the standbys, in one transaction."""
    with connection.begin():
        names = connection.execute(_SYNC_NAMES).scalar()
        rows = connection.execute(_STANDBYS, {"lsn": lsn}).all()
    return names, [(row.sync_state, row.flushed) for row in rows]


def wait_replicated(connection: Connection, seq: int, timeout: timedelta) -> str:
    """Wait until the synchronous standbys flushed the WAL written so far.

    As many as ``synchronous_standby_names`` asks for (``sync_rule``). A
    configured standby that is not connected is waited for up to
    ``NO_STANDBY_GRACE`` (capped by ``timeout``), since one that reconnects
    is listed again within moments. Each poll runs in a transaction of its
    own, ended before the next: the statistics views keep their snapshot
    for the length of a transaction.

    Returns:
        The WAL position confirmed.

    Raises:
        ReplicationError: ``NO_SYNC_STANDBY``, ``NOT_REPLICATED``, or
            ``CHECK_FAILED`` for any error reading the position or the
            standbys; always with ``seq`` and, once read, ``lsn``.
    """
    lsn = ""
    try:
        with connection.begin():
            lsn = str(connection.execute(_INSERT_LSN).scalar())
        start = time.monotonic()
        deadline = start + timeout.total_seconds()
        grace = start + min(NO_STANDBY_GRACE, timeout).total_seconds()
        delay = 0.05
        while True:
            names, standbys = _poll(connection, lsn)
            rule = sync_rule(names)
            state = replication_state(standbys, rule)
            if state == "confirmed":
                return lsn
            now = time.monotonic()
            if state == "none" and (rule is None or now >= grace):
                raise ReplicationError(
                    "NO_SYNC_STANDBY",
                    _no_standby(rule, standbys)
                    + f"; the checkpoint block {seq} is written but not confirmed",
                    seq=seq,
                    lsn=lsn,
                )
            if now >= deadline:
                raise ReplicationError(
                    "NOT_REPLICATED",
                    f"the synchronous standbys did not flush {lsn} within {timeout}",
                    seq=seq,
                    lsn=lsn,
                )
            time.sleep(delay)
            delay = min(delay * 2, 1.0)
    except ReplicationError:
        raise
    except Exception as exc:
        raise ReplicationError(
            "CHECK_FAILED",
            f"checking the standbys failed ({exc.__class__.__name__}); the "
            f"checkpoint block {seq} is written but not confirmed",
            seq=seq,
            lsn=lsn,
        ) from exc


def _no_standby(
    rule: SyncRule | None, standbys: list[tuple[str | None, bool | None]]
) -> str:
    if rule is None:
        return "synchronous_standby_names is empty: no standby is synchronous"
    method, count = rule
    kind = "sync" if method == "FIRST" else "quorum"
    listed = sum(state == kind for state, _ in standbys)
    return (
        f"synchronous_standby_names asks for {method} {count}, "
        f"pg_stat_replication lists {listed} with sync_state {kind} "
        "(reading it needs pg_monitor)"
    )


@dataclass(frozen=True)
class Fork:
    """What ``declare_fork`` wrote.

    Attributes:
        seq: The fork block.
        incarnation: The incarnation it starts.
        closing_seq: The closing seal block of the old incarnation; ``None``
            when nothing was left to seal.
        xid_at_fork: Where the new incarnation's seal blocks start.
        id_floor: Highest ``id`` of each stream at the fork, ``None`` without
            an id window.
        id_count: Rows of each stream at or below it.
    """

    seq: int
    incarnation: int
    closing_seq: int | None
    xid_at_fork: int
    id_floor: dict[str, int] | None
    id_count: dict[str, int] | None


def declare_fork(
    connection: Connection,
    tables: AuditTables,
    last_good_checkpoint: Checkpoint | str,
    *,
    reason: str,
    signer: Signer | None = None,
    id_window: bool | None = None,
) -> Fork:
    """Start a new incarnation of the chain after a restore.

    Private for now. Run it after the restore and before any writer starts.
    In one ``READ COMMITTED`` transaction, once it holds the sealer's
    advisory lock (so no seal, retire or ack block is written meanwhile),
    it:

    1. checks that ``last_good_checkpoint`` names a genesis, checkpoint or
       fork block of this chain, with its hash;
    2. with an id window, reads the highest ``id`` (``id_floor``) and the
       row count (``id_count``) of each stream, and refuses when a table's
       identity sequence is below the highest floor of its streams;
    3. writes the closing seal of the old incarnation: with an id window,
       over ``[sealed horizon, highest stored xid + 1)`` and the rows at or
       below the floor; without one, a normal seal up to the horizon. It is
       left out when there is nothing to seal;
    4. writes the fork block, whose ``xid_at_fork`` is the horizon now.

    From then on the sealer and ``verify`` apply the id window: the old
    incarnations' blocks hold the rows at or below the floor, the new one's
    the rows above it, and every seal refuses with ``ID_FLOOR_VIOLATION``
    when new rows got ids at or below the floor. The closing seal is one
    block, whatever its size.

    Args:
        connection: A connection that may insert into the block table, not
            in a transaction and not in ``AUTOCOMMIT`` mode.
        tables: Audit tables built with integrity.
        last_good_checkpoint: The newest checkpoint the restored chain still
            has, kept off the database; a ``Checkpoint`` or its note text.
            Signatures are not checked here.
        reason: Why, for whoever reads the chain; stored in clear.
        signer: Signs the closing seal and the fork block. ``verify`` takes
            a fork as the explanation of a diverging checkpoint only when it
            is signed by a key it knows.
        id_window: Record an id window. ``None`` decides by the horizon: an
            id window when transaction ids were rewound (``pg_restore`` into
            a new cluster), none otherwise (PITR, ``pg_resetwal``).

    Returns:
        What was written.

    Raises:
        ValueError: The checkpoint does not match the chain, the connection
            is in a transaction or in ``AUTOCOMMIT`` mode, the server is in
            recovery, or the tables were built without integrity.
        SealRefusedError: ``NO_GENESIS``; ``XID_REWIND`` when the ids were
            rewound and ``id_window`` is ``False``; ``ID_FLOOR_VIOLATION``
            when an identity sequence is behind the floor. Nothing was
            written.
    """
    block = block_table(tables)
    checkpoint = (
        Checkpoint.from_note(last_good_checkpoint)
        if isinstance(last_good_checkpoint, str)
        else last_good_checkpoint
    )
    _pg.check_transactional(connection, "declare_fork")
    _check_idle(connection, "declare_fork")
    with connection.begin():
        horizon = _lock(connection, block)
        head = sealed_horizon(connection, block)
        last = last_block(connection, block)
        if head is None or last is None:
            raise _no_genesis(block)
        chain, sealed_to = head
        _check_checkpoint(connection, block, chain, checkpoint)
        window = current_window(connection, block)
        rewound = horizon < sealed_to
        with_window = rewound if id_window is None else id_window
        if rewound and not with_window:
            raise SealRefusedError(
                "XID_REWIND",
                f"the horizon {horizon} is below the sealed horizon {sealed_to}: "
                "a fork without an id window needs transaction ids above every "
                "stored one (pg_resetwal --epoch)",
            )
        floors = counts = None
        if with_window:
            floors, counts = _floors(connection, tables)
            _check_sequences(connection, tables, floors)
            lower, upper = window.id_floor, floors
            closing_to = _highest_xid(connection, tables, lower, upper)
            closing_to = None if closing_to is None else closing_to + 1
        else:
            lower, upper = window.id_floor, None
            closing_to = horizon
        prev, seq = bytes(last.block_hash), int(last.seq) + 1
        closing_seq: int | None = None
        if closing_to is not None and closing_to > sealed_to:
            builder = SegmentBuilder()
            windows = window_clauses(tables, lower, upper)
            for stream, partition, row in leaf_rows(
                connection, tables, sealed_to, closing_to, windows
            ):
                builder.add(stream, partition, row)
            if builder.rows:
                body = seal_body(chain, seq, sealed_to, closing_to, builder.segments())
                prev = insert_block(connection, block, seq, "seal", prev, body, signer)
                closing_seq, seq = seq, seq + 1
        incarnation = window.incarnation + 1
        body = fork_body(
            chain,
            seq,
            incarnation=incarnation,
            reason=reason,
            prior_seq=checkpoint.seq,
            prior_hash=checkpoint.block_hash,
            xid_at_fork=horizon,
            id_floor=floors,
            id_count=counts,
        )
        insert_block(connection, block, seq, "fork", prev, body, signer)
    return Fork(seq, incarnation, closing_seq, horizon, floors, counts)


def _check_idle(connection: Connection, name: str) -> None:
    if connection.in_transaction():
        raise ValueError(
            f"{name} runs its own transaction; pass a connection that is not "
            "in a transaction"
        )


def _lock(connection: Connection, block: Table) -> int:
    """Wait for the sealer's lock, then read the horizon.

    The transaction is ``READ COMMITTED``, so every later statement sees the
    blocks committed before the lock was granted; a snapshot taken before
    the wait would miss them, and the next ``seq`` would collide.
    """
    connection.execute(text("SET TRANSACTION ISOLATION LEVEL READ COMMITTED"))
    start = connection.execute(
        text(
            "SELECT pg_is_in_recovery() AS standby, "
            "to_regclass(:block) IS NOT NULL AS created"
        ),
        {"block": _pg.regclass(connection, block)},
    ).one()
    if start.standby:
        raise ValueError("the server is in recovery; run this on the primary")
    if not start.created:
        raise ValueError(
            f"the block table {block.fullname} does not exist; run "
            "migrations.add_integrity() first"
        )
    _pg.xact_lock(connection, _pg.lock_key(block))
    return int(
        connection.execute(
            text("SELECT pg_snapshot_xmin(pg_current_snapshot())::text")
        ).scalar_one()
    )


def _no_genesis(block: Table) -> SealRefusedError:
    return SealRefusedError(
        "NO_GENESIS",
        f"{block.fullname} has no genesis block; run migrations.write_genesis()",
    )


def _check_checkpoint(
    connection: Connection, block: Table, chain: str, checkpoint: Checkpoint
) -> None:
    found = connection.execute(
        select(block.c.kind, block.c.block_hash).where(block.c.seq == checkpoint.seq)
    ).one_or_none()
    if (
        checkpoint.chain != chain
        or found is None
        or bytes(found.block_hash) != checkpoint.block_hash
    ):
        raise ValueError(
            f"the checkpoint at block {checkpoint.seq} does not match this chain; "
            "give the newest checkpoint the restored database still has"
        )
    if found.kind not in ANCHOR_KINDS:
        raise ValueError(
            f"block {checkpoint.seq} is a {found.kind} block, not a checkpoint"
        )


def _floors(
    connection: Connection, tables: AuditTables
) -> tuple[dict[str, int], dict[str, int]]:
    """Highest ``id`` and row count of each stream that has rows."""
    transaction, activity = tables.transaction, tables.activity
    floors: dict[str, int] = {}
    counts: dict[str, int] = {}
    highest, count = connection.execute(
        select(func.max(transaction.c.id), func.count()).select_from(transaction)
    ).one()
    if count:
        floors[TRANSACTION_STREAM], counts[TRANSACTION_STREAM] = int(highest), count
    for severity, highest, count in connection.execute(
        select(activity.c.severity, func.max(activity.c.id), func.count()).group_by(
            activity.c.severity
        )
    ):
        stream = activity_stream(severity)
        floors[stream], counts[stream] = int(highest), int(count)
    return floors, counts


def _check_sequences(
    connection: Connection, tables: AuditTables, floors: Mapping[str, int]
) -> None:
    for table in (tables.transaction, tables.activity):
        limits = [
            limit
            for stream, limit in floors.items()
            if (stream == TRANSACTION_STREAM) == (table is tables.transaction)
        ]
        value = sequence_value(connection, table)
        if limits and value is not None and value < max(limits):
            raise SealRefusedError(
                "ID_FLOOR_VIOLATION",
                f"the id sequence of {table.fullname} is at {value}, below the "
                f"highest stored id {max(limits)}: restore the sequence values "
                "(a data-only restore without SEQUENCE SET leaves them behind) "
                "and declare the fork again",
            )


def _highest_xid(
    connection: Connection,
    tables: AuditTables,
    lower: Mapping[str, int] | None,
    upper: Mapping[str, int] | None,
) -> int | None:
    """The highest ``xid`` of a row in the window, over both tables."""
    windows = window_clauses(tables, lower, upper)
    found: list[int] = []
    for table in (tables.transaction, tables.activity):
        xid = table.c[_schema.XID]
        # Aliased: ORDER BY on the bare output name would sort the text.
        value: Any = connection.execute(
            select(xid.label("highest"))
            .where(xid.is_not(None), *windows[table.name])
            .order_by(desc(xid))
            .limit(1)
        ).scalar_one_or_none()
        if value is not None:
            found.append(int(value))
    return max(found, default=None)
