# Tamper evidence

The audit tables are append-only for the application role (see [roles](permissions.md)), but whoever owns the database, or holds a role that may update the tables, can still change them. With integrity on, such a change is **detected**: a sealer job hashes the audit rows of finished transactions into blocks chained by hash, and `verify()` rebuilds every block from the rows and reports every difference.

This makes the log **tamper-evident, not tamper-proof**. Nothing here stops a change; it makes changes visible to whoever verifies. What it can detect depends on where you keep checkpoints and keys, which the [three tiers](#three-tiers) below describe, and [Limitations](../limitations.md#tamper-evidence) lists what it does not detect.

## How it works

- **At write time**, every audit row gets its PostgreSQL transaction id in a new `xid` column, and a salted SHA-256 commitment for each part that scrubbing may erase (the label, the changes, the payload and the actor's context). Writes take no extra lock and no extra round trip.
- **The sealer** (`audit.maintenance.seal()`, run every minute or so) appends a `seal` block covering the rows of every transaction that has finished since the last block. Each block holds one Merkle root per partition (the tree hash of [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962#section-2.1)), and the hash of the block before it. It never updates an audit row.
- **Retention** appends a `retire` block before it drops a partition, so a dropped partition is accounted for.
- **Scrubbing** still works: `scrub()` and `scrub_actor()` delete the salt of each part they erase and stamp the part with the scrub's own transaction id, which points to the scrub's `audit.scrubbed` entry. An erasure is therefore **attributable**: every erased value points to a recorded scrub.
- **`verify()`** walks the chain, recomputes every block it can still read, checks the commitments of values that were not erased and the receipts of those that were, and reports every failure it finds instead of stopping at the first.
- **Checkpoints** (`export_checkpoint()`) are signed statements of the head of the chain, for you to store where the database cannot reach them.

## Three tiers

| Tier | What you run | What it catches |
|---|---|---|
| 1. Verify only | the sealer and `verify()` | Edits and deletes of sealed rows, by anyone who cannot also rewrite the block table: a scrubber or maintenance role, a stray `UPDATE`, a deleted partition |
| 2. Plus checkpoints | tier 1, and `export_checkpoint()` on a schedule, stored off the database host (S3 Object Lock in compliance mode, an RFC 3161 timestamp, another machine that keeps the last head) | Also a rewrite of the whole chain by a superuser, a cut-off chain and a restore to an earlier state, up to the newest checkpoint |
| 3. Plus signed blocks | tier 2, and a `Signer` whose key the database host cannot read (a KMS or HSM, or a sealer on another machine) | Also a rewrite between two checkpoints: a superuser cannot sign new blocks. Truncation still needs tier 2 |

Without a checkpoint a report is `UNANCHORED`: it says the chain is internally consistent, not that nobody rewrote it. A signing key kept on the database host adds attribution only, since whoever controls the host can use it.

## Turning it on

Pass `Integrity()` to every `AuditTrail` that writes audit entries, and to the ones that run maintenance and verification:

```python
from audit_trail import AuditTrail, Integrity

audit = AuditTrail(engine, events=[BillingEvent], integrity=Integrity())
```

Install the extra if you use the reference Ed25519 signer: `pip install "sqlalchemy-audit-trail[integrity]"`. Nothing else needs it.

### A new install

`build_tables(integrity=True)` declares the integrity columns, the `(xid, id)` indexes and the block table (`audit_seal_block`), and `create_audit_tables()` creates them:

```python
tables = build_tables(schema="audit", integrity=True)


def upgrade() -> None:
    migrations.create_audit_tables(op.get_bind(), tables, Level)
```

Then start the chain once the application runs with `Integrity()`, as in step 3 below.

### An existing install

The upgrade takes three steps, in this order:

1. **Columns.** `migrations.add_integrity()` adds `xid` and the `seal_*` columns to both tables, and creates the block table. Existing rows keep `xid` `NULL`: they are out of scope.
2. **Indexes.** `migrations.add_integrity_indexes()` builds the `(xid, id)` indexes online, one partition at a time with `CREATE INDEX CONCURRENTLY`, so it needs an `AUTOCOMMIT` connection.
3. **Genesis.** `migrations.write_genesis()` starts the chain. Run it only after **every** writer runs with `Integrity()`: rows written after it must carry commitments, and rows of an old writer fail as `COMMITMENT_MISSING`. Rows written between steps 1 and 3 are out of scope too (`PRE_GENESIS`), which gives a rolling deploy a defined order.

```python
from alembic import op

from audit_trail import migrations
from audit_trail.tables import build_tables

tables = build_tables(schema="audit", integrity=True)


def upgrade() -> None:
    migrations.add_integrity(op.get_bind(), tables)
    with op.get_context().autocommit_block():
        migrations.add_integrity_indexes(op.get_bind(), tables)
```

Deploy the application with `Integrity()`, then start the chain from a script or a later migration:

```python
with maintenance_engine.begin() as conn:
    migrations.write_genesis(conn, tables)
```

Calling it again returns the existing genesis block. Change the grants as shown in [roles](permissions.md#with-integrity): the application must lose its table-wide `INSERT`.

!!! note "A short stall during `add_integrity`"
    Each `ALTER TABLE` takes an `ACCESS EXCLUSIVE` lock on the parent and its partitions. It rewrites and scans nothing, so the lock itself is held for milliseconds. But while the `ALTER` waits for open transactions that have used the table, new audit writes queue behind it. `add_integrity` caps the wait with `lock_timeout` (2 seconds by default) and retries with a random pause, up to `attempts` times, so writers stall for at most about that long per attempt. Run it outside peak hours, and keep long transactions off the audit tables while it runs.

## Running the sealer

Run `seal()` every minute, under the [sealer role](permissions.md#with-integrity). Each call seals up to `max_rows` rows (50,000 by default; one transaction is never split) and returns a `SealResult`; call it again while `capped` is true:

```python
from audit_trail.integrity import SealRefusedError

sealer = AuditTrail(
    create_engine(SEALER_DATABASE_URL), events=[], integrity=Integrity()
)


def seal() -> None:
    try:
        while sealer.maintenance.seal(signer=SIGNER).capped:
            pass
    except SealRefusedError as exc:  # XID_REWIND, NO_GENESIS, ID_FLOOR_VIOLATION
        logging.error("the sealer refused: %s", exc)
        raise
```

A missed run only leaves rows unsealed for longer. Two sealers at once are safe: the second returns with `skipped="busy"`. On a hot standby it returns with `skipped="standby"`. Never run it on a logical replication subscriber.

Only finished transactions are sealed. A transaction that has written and is still open holds the seal back, and so does a **prepared transaction**, until it is committed or rolled back. `health()` reports this in `report.seal`:

- `seal_lag`: how old the oldest unsealed entry is. Its age counts from the entry's own time (`issued_at`, `created_at`), not from its commit, so a transaction that ran longer than `max_seal_lag` (5 minutes by default) is flagged once it commits, until the next seal;
- `unsealed_rows`, `sealed_to` and `last_sealed_at`;
- `prepared`: prepared transactions older than `max_seal_lag`, which stall sealing until someone resolves them;
- `problem`: the step to run when the chain is not started yet.

`report.ok` is false while sealing lags, so the [health probe](operations.md#health) covers the sealer too.

## Verifying

Run `verify()` on a schedule, under the read-only [verifier role](permissions.md#with-integrity), ideally from another machine:

```python
from audit_trail.integrity import Status
from audit_trail.integrity.ed25519 import Ed25519Verifier

verifier = AuditTrail(
    create_engine(VERIFIER_DATABASE_URL), events=[], integrity=Integrity()
)
report = verifier.maintenance.verify(
    retention=RETENTION,
    checkpoints=load_checkpoints_from_off_the_box(),
    verifier=Ed25519Verifier(PUBLIC_KEYS),
)
if report.status is Status.FAILED:
    for failure in report.failures:
        logging.error("%s: %s", failure.kind, failure.detail)
```

Use an `AuditTrail` with the same `schema`, severities and `system_severity` as the application: the severity of the `audit.scrubbed` entries is needed to account for erasures whose receipt was retired. `averify()` is the async variant. `verify()` holds no lock and no long snapshot: it reads each partition in short `READ ONLY` transactions.

The report has a `status` (`VALID`, `VALID_WITH_NOTES` or `FAILED`), an `anchor` (`ANCHORED` when a checkpoint matched), `failures` and `notes`, each a `Finding` with a `kind`, a `detail` sentence and the block, partition or row it concerns. A finding never contains a stored value or a salt.

- **Failures** (`FailureKind`) include `ROOT_MISMATCH` and `ROW_COUNT_MISMATCH` (sealed rows changed, added or deleted), `COMMITMENT_MISMATCH` (an erasable value changed), `COMMITMENT_MISSING` (a row written without `Integrity`), `ERASURE_UNEXPLAINED` and `SCRUB_COUNT_MISMATCH` (an erasure without a matching scrub), `SEGMENT_MISSING` (a partition gone without a retire block), `RETIRED_EARLY` (with `retention`: a partition retired inside its retention), `DETACHED_PARTITION`, `PREV_MISMATCH` and `HASH_MISMATCH` (the chain itself), `TRUNCATED` and `CHAIN_MISMATCH` (against a checkpoint), `BAD_SIGNATURE`, `UNKNOWN_KEY`, `MALFORMED_BLOCK` and `XID_REWIND`.
- **Notes** (`NoteKind`) do not fail the report: `ERASED`, `ERASED_RECEIPT_RETIRED`, `RETIRED`, `PRE_GENESIS`, `UNSEALED_TAIL`, `UNANCHORED_TAIL`, `FORKED`, `FORKED_UNSIGNED` and `ACKNOWLEDGED`. With a `verifier`, a fork block that no key it knows signed gets a `FORKED_UNSIGNED` note next to its `FORKED` one: anyone who can write the block table can add such a block, so it explains no checkpoint (see [restores and forks](#restores-and-forks)).

### Acknowledging a known incident

Some failures are expected once, for example rows of a writer that still ran without `Integrity` during a deploy. `acknowledge()` waives them with an `ack` block in the chain, so later reports show them as `ACKNOWLEDGED` notes:

```python
maintenance.maintenance.acknowledge(
    FailureKind.COMMITMENT_MISSING,
    {"xid_from": 81234, "xid_to": 81290},
    "a writer ran without Integrity during the 2026-11-30 deploy",
    signer=SIGNER,
)
```

It runs `verify()` first and pins exactly what it waives: the rows for a failure about rows, the root and row count for a partition. A failure that is new or changed later in the same scope is reported again. Only failures about rows and partitions can be waived (`ACKNOWLEDGEABLE`), never a broken chain. An ack that would waive nothing is refused. The reason is stored in clear, and the ack stays visible in the chain and in every later checkpoint: it is accountable, not silent.

## Retention

With integrity on, `drop_expired()` first seals, then, with `verify_before_drop=True` (the default), verifies the expired partitions, and appends a `retire` block for each one before it detaches and drops it. A partition that still holds unsealed rows, failed verification or could not be locked is kept and listed in `skipped` with a reason; the next run tries again:

```python
dropped = maintenance.maintenance.drop_expired(RETENTION, signer=SIGNER)
for kept in dropped.skipped:
    logging.warning("kept %s: %s", kept.partition, kept.detail)
```

- The seal, verification and retire blocks run on a **second connection** from the same engine's pool, while the first stays in `AUTOCOMMIT` for the detach. Size the pool for it: with no free connection the call raises `PartitionError` at once, instead of waiting for the pool timeout.
- The verify runs once, before the drops. A sealed row changed in place after it, and before its partition is dropped, is not seen, and is dropped with the partition.
- Until `write_genesis()` has run, `drop_expired()` drops as it does without integrity.
- Pass the same retention to `verify(retention=...)` to catch a partition retired early.

## Checkpoints

A checkpoint states which block was the head of the chain at a moment. Kept where whoever can rewrite the database cannot reach it, it lets `verify()` catch a chain rewritten, cut short or restored to an earlier state since. Export one on a schedule (hourly, daily) and store the text:

```python
from audit_trail.integrity import export_checkpoint
from audit_trail.integrity.ed25519 import Ed25519Signer

SIGNER = Ed25519Signer.from_skey(os.environ["AUDIT_SIGNER_KEY"])

with sealer_engine.connect() as conn:
    checkpoint = export_checkpoint(conn, sealer.tables, signer=SIGNER)
store_off_the_box(checkpoint.to_note())
```

The text is a [C2SP signed note](https://c2sp.org/signed-note): a two-line statement of the chain id, block number, block hash, sealed horizon, time and incarnation (1 until the first fork, then the number of the newest fork's), followed by one signature line per key, so existing note tooling can check the signatures. It is not a C2SP [tlog-checkpoint](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md): the head of the chain is a hash chain, not a Merkle tree over the blocks, so there is no tree size and no consistency proof. `Checkpoint.from_note(text)` reads one back, and `verify(checkpoints=[...])` takes the texts as they are. A note with two signatures of one key, or a key name with a control character, is refused as malformed, and `checkpoint.signed([...])` refuses a key that signed it already.

Storing it is up to you; the database must not be able to change it afterwards:

- S3 Object Lock in **compliance** mode, which nobody can lift before the retention date (in governance mode, users with a special permission can delete the object). Object Lock needs a bucket with versioning;
- an [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) timestamp from a time-stamping authority, which signs a hash of the text;
- a verifier on another machine that keeps the newest head it has seen;
- a printed sheet, for a small log.

Exporting appends a `checkpoint` block, so the chain itself records that an anchor was taken.

**Replication.** After an asynchronous failover that lost the newest blocks, a checkpoint naming one of them would look exactly like an attack (`TRUNCATED`). `export_checkpoint(require_replicated=True)` returns the checkpoint only once as many synchronous standbys as `synchronous_standby_names` asks for have flushed its block: `n` with `sync_state` `sync` for `FIRST n` (or a plain list of names, which means `FIRST 1`), `n` with `quorum` for `ANY n`. It waits up to `replication_timeout` (30 seconds by default). It reads `pg_stat_replication`, whose WAL positions only roles with the privileges of `pg_read_all_stats` (included in `pg_monitor`) can see.

The check runs after the commit, so the `checkpoint` block is in the chain whatever happens; only the checkpoint is withheld. Any error from then on is a `ReplicationError` with the block's `seq` and the WAL position it waited for (`lsn`, empty if reading it failed), and a `reason`:

- `NO_SYNC_STANDBY`: `synchronous_standby_names` is empty, which fails at once, or fewer standbys of the kind it asks for are listed. A standby that is reconnecting is listed again within moments, so this waits about two seconds (capped by `replication_timeout`) before it gives up. A role without `pg_monitor` sees no standby and fails this way too;
- `NOT_REPLICATED`: enough standbys are listed, but not enough flushed the block within `replication_timeout`;
- `CHECK_FAILED`: reading the WAL position or `pg_stat_replication` failed; the error is chained as the cause.

In every case, export again once the standbys are back: the next call appends a new `checkpoint` block.

**Keys.** `Ed25519Signer.generate("audit.example.com/sealer-2027")` makes a key; keep its `skey` secret and give its `vkey` to the verifiers. Use a new name for each new key, and keep old verifier keys in `Ed25519Verifier` for as long as blocks and checkpoints signed by them are checked. For tier 3, implement the `Signer` protocol (`key_id`, `algorithm`, `sign(message)`) against your KMS or HSM.

## Restores and forks

A restore can make the database disagree with a checkpoint, or reuse transaction ids that the chain has already sealed. What happens depends on how the database came back:

| Event | Transaction ids | What to do |
|---|---|---|
| `pg_upgrade` to a new major version | kept | nothing |
| a physical standby promoted | kept | nothing; with `require_replicated`, no checkpoint names a lost block |
| `pg_dump` / `pg_restore` into a new cluster | rewound: the sealer refuses with `XID_REWIND` | a fork, below, before any writer starts |
| point-in-time recovery, or a base backup started as a primary | reused silently | a fork; only a checkpoint shows the divergence |
| a logical replication subscriber | its own | never run the sealer there; `verify()` works |

`declare_fork()` starts a new incarnation of the chain. Run it after the restore and **before any writer starts**, as the sealer role, with the newest checkpoint the restored chain still has:

```python
from audit_trail.integrity import declare_fork

with sealer_engine.connect() as conn:
    declare_fork(
        conn,
        sealer.tables,
        last_good_checkpoint,
        reason="restored from the 2026-11-30 backup after a disk failure",
        signer=SIGNER,
    )
```

It first seals what the old incarnation left unsealed, then appends a `fork` block. `verify()` reports it as a `FORKED` note.

A checkpoint stored before the restore may name a block that the restored chain lost or holds with another hash. Such a checkpoint is a `FORKED` note instead of a failure only when all of these hold:

- the fork block is signed by a key the verifier knows; an unsigned fork gets a `FORKED_UNSIGNED` note and explains nothing;
- the checkpoint is of an earlier incarnation than the one the fork starts (each checkpoint records its incarnation);
- the checkpoint names a block after the last good checkpoint the fork was declared from.

Otherwise it fails as `TRUNCATED` or `CHAIN_MISMATCH`. A checkpoint taken after the fork is never explained by it: the chain it saw already held the fork block, so a divergence since is a rewrite.

**Point-in-time recovery**, or a base backup started as a primary: transaction ids carry on from the restore point and repeat some ids of the lost blocks, which is harmless because those blocks are gone too. Declare the fork.

**`pg_dump` / `pg_restore`, self-hosted**: move the transaction ids above every stored one before any writer starts. Stop the server, then, as the operating-system user that owns the data directory:

```sh
pg_resetwal --epoch=<(highest stored xid >> 32) + 1> "$PGDATA"
```

Find the highest stored xid with `SELECT max(xid::text::numeric) FROM audit.audit_activity` (and the same for `audit_transaction`). Start the server and declare the fork. `pg_resetwal` discards the write-ahead log, so rebuild the replicas afterwards, and read [its documentation](https://www.postgresql.org/docs/current/app-pgresetwal.html) first.

**`pg_dump` / `pg_restore` on a managed service**, where `pg_resetwal` is not available: `declare_fork()` sees the rewound ids and records an **id window**, the highest `id` of each stream at the fork. From then on the old blocks hold the rows at or below it and the new incarnation the rows above it. This needs the identity sequences restored with the data (a full `pg_restore`, or a data-only restore that keeps the `SEQUENCE SET` entries): `declare_fork()` refuses when a sequence is behind the window, and every later seal refuses with `ID_FLOOR_VIOLATION` if new rows get ids at or below it (`ALTER ... RESTART`, for example): when a table's identity sequence is below the window, and, while the sequence is still within the fork's row count of the window, when a stream has more rows at or below the window than the fork counted. The second check weakens as retention drops those rows (see [Limitations](../limitations.md#tamper-evidence)). `id_window=` forces the choice either way.

A block table from another incarnation is never reused without `declare_fork()`. Point-in-time recovery is detected only against a checkpoint: without tier 2, a restore to an earlier state looks like a consistent, shorter chain.
