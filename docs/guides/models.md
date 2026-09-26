# Audited models

## Marking a model as audited

Mix `Audited` into a mapped class. Every column is audited unless its policy says otherwise; relationships are audited only when you name them.

```python
from sqlalchemy.orm import Mapped, mapped_column

from audit_trail import Audited, AuditOptions


class Customer(Base, Audited):
    __tablename__ = "customer"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    email: Mapped[str] = mapped_column(info={"audit": "hash"})
    api_secret: Mapped[str] = mapped_column(info={"audit": "redact"})
    avatar: Mapped[bytes | None] = mapped_column(info={"audit": "exclude"})

    __audit__ = AuditOptions(label=lambda customer: customer.name)
```

Nothing is recorded until `AuditTrail.install()` has been called on the session factory you use (see the [quickstart](../quickstart.md)). Setting `session.info["audit_enabled"] = False` switches recording of `entity.*` entries off for one session of that factory, for example a data migration run with the application's sessions.

`Audited` also turns on SQLAlchemy's `active_history` for the audited columns, so assigning to an expired attribute loads its old value first and the diff has both sides.

## What an entry holds

| Verb | `data["changes"]` |
|---|---|
| `entity.created` | every audited column as `[null, value]`, empty ones too |
| `entity.updated` | only the columns whose value really changed, as `[old, new]` |
| `entity.deleted` | every audited column as `[value, null]` |

An update that changes nothing (for example `Decimal("1.5")` to `Decimal("1.50")`, compared with the column type) writes no entry. One entry is written per object and flush; when you read the log, the rows of one object within one transaction are merged into its net change (see [querying](querying.md#compaction)).

Values are stored as JSON: `Decimal` as a string, `datetime` as ISO 8601, `UUID` in canonical form, an `Enum` as its value and `bytes` as `{"sha256": ..., "len": ...}`. Other types raise `UnserializableValueError` and abort the flush, rather than writing half an entry; pass `AuditTrail(json_encoder=...)`, a `json.JSONEncoder` subclass, to encode your own types.

## Column policies

Set the policy where the column is defined, with `mapped_column(info={"audit": ...})`:

| Policy | Stored |
|---|---|
| none | the value |
| `"redact"` | `"***"` for any non-null value; `null` stays `null`, so you still see that a value was set or cleared |
| `"hash"` | `hv<version>:<hex>`, an HMAC-SHA256 of the value under your `pseudonymize_key`; equal values give equal hashes, so you can correlate without storing the value |
| `"exclude"` | nothing; the column is left out |

`"hash"` needs `AuditTrail(pseudonymize_key=...)`; see [privacy](privacy.md#keys-and-rotation).

`AuditTrail(global_redact={"password", "token"})` redacts columns with those attribute keys or column names when they have no explicit policy. It is a safety net, not a replacement for policies: [`check_models()`](#checking-models-in-ci) still reports such columns.

## Options

`__audit__ = AuditOptions(...)` takes:

| Option | Meaning |
|---|---|
| `severity` | severity of the model's `entity.*` entries; `None` uses `AuditTrail(default_severity=...)`, which defaults to the lowest level |
| `verb_severity` | per-verb override, e.g. `{"entity.deleted": Severity.WARNING}` |
| `track_relationships` | names of collection relationships whose membership changes are recorded |
| `snapshot_on_load` | JSON columns copied on load, so in-place changes keep an old value |
| `object_type` | name stored in `object_type`; defaults to the class name |
| `label` | callable returning the object's label, stored in `object_label` |
| `scope` | callable returning the scope id (e.g. a tenant), stored in `scope_id` |
| `target` | callable returning the parent object as `Target(type, id)` or a `(type, id)` tuple |

### Labels, scope and target

These callables run while the session flushes. They receive a read-only view of the instance and may only read attributes that are already loaded: reading an expired or unloaded attribute emits no SQL. Instead the library logs a warning on the `audit_trail.diff` logger (once per model, attribute and option) and falls back: `label` and `target` to `None`, `scope` to the context's `scope_id`. Any other exception from your callable aborts the flush.

```python
from audit_trail import AuditOptions, Target


class OrderItem(Base, Audited):
    __tablename__ = "order_item"

    id: Mapped[int] = mapped_column(primary_key=True)
    order_id: Mapped[int] = mapped_column(ForeignKey("order.id"))
    sku: Mapped[str]
    company_id: Mapped[int]

    __audit__ = AuditOptions(
        label=lambda item: item.sku,
        scope=lambda item: item.company_id,
        target=lambda item: Target("Order", item.order_id),
    )
```

Read foreign-key columns (`item.order_id`) rather than relationships (`item.order`), which are often not loaded.

`scope` returning `None` means "no scope"; the context's scope is used only when the option is not set. The `target` is the object's parent, for example the root of an aggregate: `object_history("Order", "5")` then lists the order's own entries and those of its items. The target is computed when each entry is written, also for `entity.deleted`.

### Relationships

Collection relationships named in `track_relationships` are recorded as `{"added": [ids], "removed": [ids]}`, with ids formatted like `object_id`:

```python
class Post(Base, Audited):
    __tablename__ = "post"

    id: Mapped[int] = mapped_column(primary_key=True)
    tags: Mapped[list[Tag]] = relationship(secondary=post_tags)

    __audit__ = AuditOptions(track_relationships={"tags"})
```

Changes are captured from the collection's append and remove events and merged to the net change, so appending and removing the same tag records nothing. Only collection relationships can be tracked, and only one side of a bidirectional relationship: tracking both sides would record every change twice, and `check_models()` reports it. See [limitations](../limitations.md#relationships) for what is not captured.

### JSON columns

A JSON column changed in place (`obj.settings["theme"] = "dark"`) is a special case:

- a plain `JSON`/`JSONB` column: SQLAlchemy does not see the change at all, so neither does the audit trail;
- `MutableDict.as_mutable(JSONB)` (or `MutableList`): the change is saved, but the old value is gone, and the entry stores `["<unknown>", new]`;
- `MutableDict` plus `snapshot_on_load={"settings"}`: the library deep-copies the column whenever the instance is loaded or refreshed, and the entry has the real old value. The copy costs memory and time on every load of the model.

Assigning a new object (`obj.settings = {**obj.settings, "theme": "dark"}`) always records both values.

## Object ids

`object_id` is a string: `str(pk)` for a single-column key (a UUID in lowercase canonical form), and a compact JSON array of strings for a composite key, e.g. `["a","1"]`. To query by id, format it with the same functions the library uses:

```python
from audit_trail.diff import object_id_for, object_id_of

object_id_for(Order, 5)  # "5"
object_id_for(Membership, (3, "x"))  # '["3","x"]'
object_id_of(order)  # from an instance
```

## Checking models in CI

`check_models()` inspects every mapped class of a registry and returns all problems at once:

```python
from audit_trail import check_models


def test_audited_models() -> None:
    errors = [issue for issue in check_models(Base) if issue.level == "error"]
    assert not errors, "\n".join(map(str, errors))
```

| Code | Level | Problem |
|---|---|---|
| `sensitive-column` | error | a column whose name looks sensitive (`password`, `token`, `secret`, `*_key`, ...) has no explicit policy |
| `relationship-both-sides` | error | both sides of one relationship are tracked |
| `unknown-relationship` | error | `track_relationships` names something that is not a collection relationship |
| `json-in-place` | warning | a JSON column is neither `Mutable` nor in `snapshot_on_load` |

A column whose name only looks sensitive can be allowed with `check_models(Base, allow_names={"Invoice.token_count"})`.

## Sessions with binds

A session without a default bind, configured with `binds` per model or table, works as SQLAlchemy resolves it (`Session.get_bind`, including an override of it in a `Session` subclass):

- An `entity.*` entry, and a `log(obj=...)` entry, go on the connection the object is flushed on, resolved from its base mapper: in the same database transaction as the object's rows.
- `log()` without `obj`, and the queries of `trail.query`, use the connection for the audit tables: their bind in `binds`, else the session's default bind. With neither, they raise `UnboundExecutionError`.

```python
from sqlalchemy.orm import sessionmaker

tables = trail.tables
Session = sessionmaker(
    binds={
        Base: engine,
        tables.activity: engine,  # for log() without obj and trail.query
        tables.transaction: engine,
    }
)
trail.install(Session)
```

When one flush writes objects bound to different databases, each database gets its entries and an `audit_transaction` row of its own, in its transaction there, so one commit has one `transaction_id` per database. The audit tables must exist in each of them. Horizontal sharding (`ShardedSession`) is not supported.
