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
- a column that is not loaded when the object is deleted, such as a `deferred()` column, in an `entity.deleted` entry.

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
