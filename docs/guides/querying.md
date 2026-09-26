# Querying the log

`audit.query` reads the audit tables with your own session. Each method has an async variant with an `a` prefix (`alist_groups`, `aget`, `aobject_history`, `arelated`, `aaccess_summary`) that takes an `AsyncSession` and the same arguments.

The log is always read newest first, with keyset pagination. There is no offset, no count and no sorting by other columns: those would have to read every partition.

## Listing groups

`list_groups()` returns a `Page` of `Group`s. A group is one database transaction: the entries one request or job wrote together.

```python
from datetime import datetime, timedelta, timezone

page = audit.query.list_groups(
    session,
    since=datetime.now(timezone.utc) - timedelta(days=30),
    severities={Severity.WARNING, Severity.CRITICAL},
    limit=20,
)
for group in page.groups:
    header = group.transaction
    print(header.issued_at, header.actor_label, header.path, group.max_severity)
    for activity in group.activities:
        print("  ", activity["verb"], activity["object_type"], activity["object_id"])

next_token = page.next_cursor.encode() if page.next_cursor else None
```

Filters (all optional, keyword-only):

| Argument | Selects entries |
|---|---|
| `severities` | with one of these severity values; `None` means every configured severity |
| `since`, `until` | with `since <= created_at < until`; timezone-aware datetimes. `since=ALL_HISTORY` sets no lower bound (see [the default window](#the-default-time-window)) |
| `actor_id` | of this actor |
| `object_type`, `object_id` | on this object type or object |
| `target_type`, `target_id` | whose parent is this type or object |
| `verbs` | with one of these verbs |
| `scope_ids` | in one of these scopes |
| `correlation_id` | with this correlation id |
| `visibility` | that the caller may see (see [below](#visibility)) |
| `extra_predicate` | matching your own SQL condition on `audit_activity` columns (its performance is yours to check) |

For collection filters, `None` means no restriction and an empty collection matches nothing. A transaction is listed when at least one of its entries matches every filter; the group then shows **all** entries of that transaction that `visibility` allows, of any severity. Filters narrow the list, they are not access control.

Paging: pass `cursor=page.next_cursor` to get the next page. A transaction appears on exactly one page, and the listing ends only when `next_cursor` is `None`: a page may hold fewer than `limit` groups even when more follow. To hand a cursor to a client, use `Cursor.encode()` and `Cursor.decode(token)`.

Give a time window (`since`) when you can. A query without one reads the indexes of every monthly partition of the requested severities.

### The default time window

Rather than passing `since` everywhere, configure a default window:

```python
from datetime import timedelta

audit = AuditTrail(engine, default_query_window=timedelta(days=30))
```

`list_groups()` without `since` then lists the entries of the last 30 days: from `until` (or now) minus the window. The default is `None`, which reads the whole log. `since` decides:

| `since` | Lower bound |
|---|---|
| not given (`None`) | the bound recorded in `cursor`, otherwise the default window, otherwise none |
| a datetime | that datetime |
| `ALL_HISTORY` | none, even with a default window |

```python
from audit_trail import ALL_HISTORY

everything = audit.query.list_groups(session, since=ALL_HISTORY)
```

The first page fixes the bound and `next_cursor` carries it, also through `Cursor.encode()`. Later pages therefore neither move the window nor drop it, and a listing started with `ALL_HISTORY` stays unbounded. `Page.since` reports the bound a page used (`None` for none).

To offer "load older", read the window before the current one: pass `Page.since` as `until`. The windows meet without overlap, since `since` is inclusive and `until` exclusive:

```python
def load_older(session, page):
    """The window before `page`'s, or None when `page` already reached the start."""
    if page.since is None:
        return None
    return audit.query.list_groups(session, until=page.since)
```

or, to walk back window by window:

```python
def walk_back(session, stop: datetime):
    """Every group down to the window that reaches `stop`."""
    until = None
    while True:
        page = audit.query.list_groups(session, until=until)
        while True:
            show(page.groups)
            if page.next_cursor is None:
                break
            page = audit.query.list_groups(session, cursor=page.next_cursor)
        if page.since is None or page.since <= stop:
            return  # no lower bound: that was the whole log
        until = page.since
```

With a default window `page.since` is never `None`, and an empty window does not mean the log ends there: give the walk a stop of your own, as `stop` here.

The window applies to `list_groups()` and `alist_groups()` only. `object_history()` and `related()` read one record's or one correlation's entries through their own indexes, and a window would hide exactly what they are for, such as the entry that created a record. `access_summary()` counts every access. Their `since` stays optional, and their cursors carry it the same way.

## Groups and entries

`Group.transaction` is a `TransactionHeader` with the `audit_transaction` row: `issued_at`, the actor fields, `remote_addr`, `user_agent`, `method`, `path`, `channel`, `auth_method`, `request_id`, `correlation_id`, `meta`. When that row has already been dropped by retention, the header is rebuilt from the earliest entry's `data["context"]` and columns, and `from_snapshot` is `True`.

`Group.activities` are dicts (`ActivityRow`) with the `audit_activity` columns: `id`, `transaction_id`, `verb`, `severity`, `object_type`, `object_id`, `object_label`, `target_type`, `target_id`, `actor_id`, `scope_id`, `correlation_id`, `created_at` and `data`. `data["changes"]` holds an entity change, `data["payload"]` an event's payload and `data["context"]` the context snapshot. `changed_fields(activity)` from `audit_trail.query` returns the changed field names, for a list view that does not expand entries.

`Group.change_count` is the number of entries and `Group.max_severity` the highest severity among them.

### Typing API responses

`audit_trail.query` also exports the types of an entry's `data`: `ActivityData` for the envelope and `FieldChange` for one value of `data["changes"]` (a column change `[old, new]` or a relationship change `{"added": [...], "removed": [...]}`). Use them to type the code that reads entries.

They are `TypedDict`s over a recursive JSON alias, which pydantic cannot use as field types: it rejects `typing.TypedDict` on Python below 3.12, and it cannot build the recursive alias on any version. For a pydantic (or FastAPI) response model, describe the values with `pydantic.JsonValue` and convert each `ActivityRow`:

```python
from datetime import datetime

from pydantic import BaseModel, JsonValue

from audit_trail.query import ActivityData, ActivityRow, FieldChange


class EntryOut(BaseModel):
    id: int
    verb: str
    object_type: str | None
    object_id: str | None
    object_label: str | None
    actor_id: str | None
    created_at: datetime
    changes: dict[str, list[JsonValue] | dict[str, list[str]]]
    payload: dict[str, JsonValue]


def entry_out(activity: ActivityRow) -> EntryOut:
    data: ActivityData = activity["data"]
    changes: dict[str, FieldChange] = data.get("changes", {})
    return EntryOut.model_validate(
        {**activity, "changes": changes, "payload": data.get("payload", {})}
    )
```

### Compaction

The library writes one row per object and flush, so one transaction can hold several rows for the same object. By default (`compact=True`) they are merged into the net change of the transaction:

- column changes merge to `[first old, last new]`; an `entity.updated` column that ends where it started is dropped, and an update left with no change is hidden;
- `created` followed by updates is one `entity.created` with the final values; updates followed by `deleted` is one `entity.deleted`;
- an object created and deleted in the same transaction never existed outside it and is hidden;
- deleting and re-inserting the same id becomes one `entity.updated`;
- relationship changes merge net.

Rows of one object with different `actor_id`s are not merged. Pass `compact=False` for the rows as written.

## Visibility

`Visibility` restricts what the caller may see. The library knows nothing about your permissions; you build a `Visibility` from them:

```python
from audit_trail import Visibility

visibility = Visibility(
    object_types={"Invoice", "Customer"},
    scope_ids={str(user.tenant_id)},
)
page = audit.query.list_groups(session, visibility=visibility)
```

Each field is a set of allowed values: `object_types`, `verbs` and `scope_ids`. `None` means no restriction and an empty set allows nothing. A `NULL` column never passes a restriction that is set, so with `scope_ids={"t1"}`, entries without a scope are hidden. In `list_groups` it restricts both which transactions are listed and which of their entries a group shows. `get`, `object_history`, `related`, `access_summary` and `LabelResolver.resolve` take the same `visibility` argument; pass it to every call.

## One entry

```python
detail = audit.query.get(session, activity_id, created_at, severity=severity)
```

`get(session, id, created_at, *, severity=None, visibility=None)` returns an `ActivityDetail` (`activity` and its `transaction` header) or `None`. Pass the entry's `created_at` too: an id alone would read every partition. `severity`, when you have it, narrows the read to one partition.

## A record's history

```python
from audit_trail.diff import object_id_for

page = audit.query.object_history(session, "Order", object_id_for(Order, 5))
```

`object_history(session, object_type, object_id, *, include_children=True, since=None, until=None, visibility=None, cursor=None, limit=50, compact=True)` pages through the entries on the record and, with `include_children`, the entries whose target is the record (see [targets](models.md#labels-scope-and-target)). Each group shows only those entries, not the rest of its transaction. `visibility` applies to every entry separately, so children of types the caller may not see are left out.

`object_id` must be formatted as the library stores it; see [object ids](models.md#object-ids).

## Related transactions

`related(session, correlation_id, *, since=None, until=None, visibility=None, cursor=None, limit=50, compact=True)` lists the transactions that share a correlation id, for example the several commits of one request, or of one operation across services that pass the id along.

## Access summaries

```python
for count in audit.query.access_summary(
    session, "Patient", "17", "record.sensitive_viewed"
):
    print(count.actor_id, count.entries, count.first_at, count.last_at)
```

`access_summary(session, object_type, object_id, verb, *, since=None, until=None, visibility=None)` returns one `AccessCount` per actor, most recent first: who accessed a record, and how often.

## Labels for ids in changes

A change such as `{"customer_id": [3, 4]}` stores ids. `LabelResolver` turns them into labels:

```python
from audit_trail import LabelResolver

resolver = LabelResolver(audit.tables, Base)
activities = [activity for group in page.groups for activity in group.activities]
labels = resolver.resolve(session, activities, visibility=visibility)
# {activity_id: {"customer_id": ["Acme", "Globex"]}}
```

It finds the fields that refer to other objects from the model metadata (single-column foreign keys to a primary key, and relationships), then looks each referenced object up **in the audit trail**: the label is the newest `object_label` among the entries the caller may see. Objects without a labelled entry, and objects the caller may not see, get `#<id>`. `aresolve()` is the async variant.

## Exporting and tailing

An entry's `created_at` is the time its database transaction *started*, and it becomes visible only when that transaction commits. A loop that remembers "I have read everything up to T" can therefore miss a transaction that started before T and committed after the read. Read up to a boundary that lags behind the current time by at least the longest time a transaction may stay open (your statement or request timeout, or `idle_in_transaction_session_timeout`):

```python
from sqlalchemy import func, select

TAIL_LAG = timedelta(minutes=10)


def export_since(session, mark: datetime) -> datetime:
    boundary = session.scalar(select(func.now())) - TAIL_LAG
    cursor = None
    while True:
        page = audit.query.list_groups(
            session, since=mark, until=boundary, cursor=cursor, limit=500, compact=False
        )
        for group in page.groups:
            export(group)
        if page.next_cursor is None:
            return boundary  # the next call starts here
        cursor = page.next_cursor
```

The library does not apply a lag itself; an interactive list view does not need one. An export always passes `since`: with a default window, a first export that should read the whole log passes `since=ALL_HISTORY`.
