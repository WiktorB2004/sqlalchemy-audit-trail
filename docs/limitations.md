# Limitations

The library records what passes through SQLAlchemy's unit of work, in Python. That is what makes diffs, labels and context cheap to capture, and it is also where the gaps are. Each one below says what is missed and what to do about it.

## Bulk statements are warned about, not audited

`session.execute(update(Invoice)...)`, `delete(...)` and the Core equivalents bypass the flush, so no entry is written for the rows they change: the library never sees those rows. When such a statement targets the table of an `Audited` model through an installed session, a warning is logged on `audit_trail.listener`.

- Silence it for a statement you know about with `.execution_options(audit_bulk_ok=True)`; the rows are still not audited.
- Switch the warning off globally with `AuditTrail(warn_on_bulk=False)`.
- To audit such a change, load the objects and change them through the session, or log a [domain event](guides/events.md) describing the bulk operation.

Statements run on a plain `Connection` or another engine are not seen at all.

## Sessions with binds

A session without a default bind needs the audit tables in its `binds` for `log()` without `obj` and for queries; see [Sessions with binds](guides/models.md#sessions-with-binds).

## Database-side cascades

Rows deleted by the database, through `ForeignKey(..., ondelete="CASCADE")` with `passive_deletes=True`, never pass through the session, so they get no `entity.deleted` entry. The same goes for triggers and anything else the database changes on its own. Let SQLAlchemy cascade the delete (`cascade="all, delete-orphan"` without `passive_deletes`) for models whose deletion must be audited.

## JSON changed in place

- A plain `JSON`/`JSONB` column changed in place (`obj.settings["a"] = 1`) is not detected by SQLAlchemy, so nothing is saved or audited.
- With `MutableDict`/`MutableList` the change is saved, but the old value is unknown: the entry stores `["<unknown>", new]`.
- Adding the column to `AuditOptions(snapshot_on_load=...)` keeps a copy from load time, so the entry has the old value, at the cost of a deep copy on every load.
- Assigning a new object always records both values.

`check_models()` warns about JSON columns in neither case. See [JSON columns](guides/models.md#json-columns).

## `"<unknown>"` values

`"<unknown>"` is a marker, not a value: it stands where the value was not in memory when the session flushed, and the library does not run extra SQL to fetch it. Besides JSON changed in place, it appears for:

- a column filled by the database on INSERT (`server_default`, `Computed`, `Identity`) in an `entity.created` entry, **only** when the mapper sets `eager_defaults=False`. SQLAlchemy's default, `eager_defaults="auto"`, fetches these values with `RETURNING` on PostgreSQL, so the entry holds the real value;
- a column that is not loaded when the object is deleted, such as a `deferred()` column, in an `entity.deleted` entry;
- the new value of a column assigned a SQL expression (`obj.placed_at = func.now()`), on INSERT and UPDATE, and of a client-side SQL default (`default=func.now()`) on INSERT with `eager_defaults=False`;
- the new value of `onupdate=func.now()` unless the mapper sets `eager_defaults=True`.

As a new value, `"<unknown>"` means the column was written, possibly with the value it already had.

## Columns set by SQL

`onupdate`, `server_onupdate`, `Computed` and the mapper's `version_id_col` are added to an `entity.updated` entry only when another column of the object changed too (see [timestamps](guides/models.md#timestamps-and-other-columns-set-by-sql)). Some cases are not recorded:

- `eager_defaults="auto"`, SQLAlchemy's default, fetches values back on INSERT only, never on UPDATE. Use `eager_defaults=True` to get the new value of `onupdate=func.now()`; without it the entry holds `"<unknown>"`.
- `server_onupdate`, triggers and `Computed` are recorded only with `eager_defaults=True`. Otherwise the value is not in memory after the UPDATE, and the library cannot tell whether it changed.
- On a second flush of the same object in one transaction, the first flush expired such a column, so its old value is `"<unknown>"` unless `eager_defaults=True`. With `onupdate=func.now()` and no `eager_defaults=True` both values are `"<unknown>"`: the entry only says the column was written.
- An entry whose only changes are [relationship changes](#relationships) gets none of these columns.
- A SQL expression assigned in your own `before_update` mapper listener is recorded only if that listener runs before the library's. Listeners run in registration order, so one added with `event.listen(Model, "before_update", fn)` after the model is defined runs after the library's and its expression is missed. Register it with `insert=True`, or assign the expression in a `before_flush` session listener, which is always recorded.

## Unloaded attributes under AsyncSession

`AsyncSession` cannot load an attribute implicitly: outside an awaited call, a load needs database I/O that SQLAlchemy cannot run, and it raises `MissingGreenlet`. Two such loads come from using the audit trail, and for them the library raises `AsyncLoadError` instead, naming the model, the attribute and the fix. The original error is its `__cause__`.

- **A tracked collection that is not loaded.** Appending to or replacing a collection makes SQLAlchemy load it first. Load collections named in `track_relationships` eagerly before changing them: `selectinload(Post.tags)` in the query, or `lazy="selectin"` on the relationship. See the [async quickstart](quickstart.md#async).
- **An expired column of an `Audited` model.** To record the old value, `Audited` loads an expired column when it is assigned, not only when it is read. With the default `expire_on_commit=True`, every column is expired after `await session.commit()`, so `post.title = "new"` right after a commit needs a load. Refresh the object first (`await session.refresh(post)`), or create the session with `async_sessionmaker(..., expire_on_commit=False)`.

`AsyncLoadError` subclasses SQLAlchemy's `MissingGreenlet`, so an `except MissingGreenlet` still catches it. With psycopg, SQLAlchemy wraps `MissingGreenlet` in a `StatementError`; for these two loads you get `AsyncLoadError` instead of that `StatementError`, on psycopg and asyncpg alike. Every other load (a relationship not in `track_relationships`, a model that is not `Audited`) keeps SQLAlchemy's own error.

Inside the flush, the audit trail never loads anything: changes, labels, scopes and targets are built from what is already in memory.

## Relationships

Only changes made through the ORM collection API of a tracked relationship are recorded:

- Writing the foreign-key column directly (`child.parent_id = 2`) records the column change on the child, but no relationship change on either parent.
- Changing a parent through the other side of a relationship (`child.parent = new_parent`, with the parent's collection tracked through `back_populates` or `backref`) records `added` on the new parent. It records `removed` on the old parent only if the old parent is loaded in the session; otherwise SQLAlchemy never touches its collection.
- Inserting into or deleting from an association table directly is not seen.
- Deleting the parent itself records `entity.deleted`, not a relationship change.

## A child moved to another parent

The target of an entry is computed when the entry is written. A child moved to another parent records the foreign-key change with its **new** target, so from the move on its entries appear in the new parent's history only, not in the old parent's. Log a domain event on the old parent if its history must show the move.

## `actor_id` is opaque

`actor_id` should be an internal id, not an e-mail address or login: `scrub_actor` does not clear it. See [actor ids](guides/privacy.md#actor-ids).

## Time of an entry and tailing

`created_at` is the time the database transaction **started**, not when it committed, and all entries of a transaction share it. A loop that exports "everything since the last run" must stay behind the current time by at least the longest time a transaction can stay open, or it misses transactions that committed late. The library does not do this for you: pass an `until` that lags, as in [exporting and tailing](guides/querying.md#exporting-and-tailing).

## Only PostgreSQL

The tables rely on PostgreSQL's declarative partitioning, `jsonb` and `inet`; PostgreSQL 14 or newer is supported. There is no support for other databases.

## No state at a point in time

The log stores diffs, not copies of rows. It cannot answer "which records had status X on date D" in one query, and the library has no function to rebuild or revert a record's state. Excluded, redacted, hashed, scrubbed and `"<unknown>"` values could not be restored from the log in any case.

## Tamper evidence

[Integrity](guides/integrity.md) makes the log tamper-evident, not tamper-proof: it detects changes, it does not prevent them, and it proves what the application wrote, not that it was true. What it detects, with the [roles](guides/permissions.md#with-integrity) of `examples/roles.sql`:

| Attack | Detected? |
|---|---|
| The application role edits or deletes entries | Blocked already by the grants (no `UPDATE` or `DELETE`). The chain adds nothing here |
| The application role inserts a row backdated into a sealed range | Blocked by the column `INSERT` grants, which exclude `xid`. Without them: a root mismatch |
| A role with `UPDATE` (scrubber, maintenance) rewrites a **sealed** entry | Yes |
| The scrubber erases a sealed value and inserts a matching forged `audit.scrubbed` entry | No: it looks exactly like a real scrub. Erasure is attributable, not prevented. Keep the scrubber role for admin tasks |
| Rows or a whole partition deleted without retention | Yes (`ROOT_MISMATCH`, `ROW_COUNT_MISMATCH`, `SEGMENT_MISSING`), unless whoever deletes can also write blocks (see below) |
| A partition detached but not dropped | Yes (`DETACHED_PARTITION`) |
| A value erased outside `scrub()` / `scrub_actor()` | Yes: the erasure has no pointer to a scrub, or the scrub's counts disagree |
| An `audit.scrubbed` entry forged by the application | Yes: its counts match no erased rows, and erasing needs `UPDATE`, which the application lacks |
| The newest blocks cut off, the database replaced, or a restore to an earlier state | Only against an exported checkpoint (`TRUNCATED`, `CHAIN_MISMATCH`) |
| A role that may insert blocks (sealer, owner) retires a young partition, or seals rows it changed while they were unsealed | Partly. An early retire is caught when `verify()` gets the retention (`RETIRED_EARLY`). Rows changed before their seal are not. Run the sealer under its own role |
| A superuser rewrites the rows **and** recomputes the chain | Only for history covered by a checkpoint stored off the database host, or, between checkpoints, by blocks signed with a key the host cannot read. Everything after the newest checkpoint can otherwise be rewritten undetected |
| An entry changed between its commit and its seal | No. Only roles with `UPDATE` on the audit tables have that chance, and the application role is not one. The window is the seal interval plus the longest open write transaction: a library outside the database engine cannot hash at commit |
| The application writes a false entry | No |

A `verify()` report without checkpoints is `UNANCHORED`: the chain is internally consistent, which does not mean nobody rewrote it.

Accepted risks, by design:

- **The scrubber can forge scrubs.** It holds `INSERT` and `UPDATE` of the erased columns, so it can erase a value and write a matching `audit.scrubbed` entry. It also needs `UPDATE` of the whole `data` column, because the scrub rewrites it with `jsonb_set`; a change to a part of `data` that is never erased is detected once the row is sealed, since that part is hashed in clear.
- **Failure logs carry salts.** When an audit write fails under `on_error="log"`, the logged parameters include the salts and commitments next to the values, which were logged before too. Logs are outside the reach of `scrub()`: keep them on a short retention, or treat them as personal data.
- **Rows changed after the pre-drop verify are dropped.** `drop_expired()` verifies the expired partitions once, before the drops. A sealed row changed in place between that verify and its partition's drop is not seen, and is dropped with the partition.
- **Retention weakens the count check after a fork.** After a fork with an id window, each seal also compares the number of rows at or below the window with the count the fork recorded. Dropping partitions lowers that number, so the comparison catches less over time; the check of the identity sequences still covers an `ALTER ... RESTART`.
- **Seal lag is measured from event time.** `health()` measures an unsealed entry's age from its `issued_at` / `created_at`, not from its commit, so a transaction that ran longer than `max_seal_lag` is flagged once it commits, until the next seal.
- **An unsigned fork can only add notes.** A fork block that no key known to the verifier signed never explains a checkpoint that diverges from the chain: such a checkpoint still fails as `TRUNCATED` or `CHAIN_MISMATCH`. Sign forks with the same key as the blocks.
- **The table owner can drop or truncate.** `TRUNCATE` or `DROP` by the owner is detected (missing segments), not prevented.
