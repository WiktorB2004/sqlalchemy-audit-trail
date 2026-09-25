# Quickstart

Three small programs: one with a sync `Session`, one with an `AsyncSession`, and a FastAPI application. Each is a complete script in the repository's [`examples/`](https://github.com/WiktorB2004/sqlalchemy-audit-trail/tree/main/examples) directory, and the test suite runs all three against PostgreSQL, so the code below works as shown.

You need a PostgreSQL 14+ database and the extras for your driver:

```bash
pip install "sqlalchemy-audit-trail[psycopg]"            # sync
pip install "sqlalchemy-audit-trail[asyncpg]"            # async
pip install "sqlalchemy-audit-trail[asyncpg,fastapi]"    # FastAPI
```

## Sync

### Models and events

A model is audited when it mixes in `Audited`. Per-column policies go in `mapped_column(info={"audit": ...})`, model options in `__audit__`. Domain events are members of an `AuditEvent` enum.

<!-- fmt: off -->
```python
--8<-- "examples/quickstart_sync.py:models"
```
<!-- fmt: on -->

### Setup

`AuditTrail` holds the configuration; `install()` registers the listeners on your session factory only, not on every `Session` in the process. The audit tables are partitioned, and PostgreSQL has no partition to put a row in until `ensure_partitions()` has created the current month's partitions: run it before the first write and then on a schedule (see [operations](guides/operations.md)).

<!-- fmt: off -->
```python
--8<-- "examples/quickstart_sync.py:setup"
```
<!-- fmt: on -->

In an application, create the tables in a migration rather than at start-up; see [partitions and retention](guides/partitions.md#creating-the-tables).

### Writing

Changes are recorded when the session flushes, with the context that is active at that moment. `audit.log()` records a domain event in the same transaction.

<!-- fmt: off -->
```python
--8<-- "examples/quickstart_sync.py:write"
```
<!-- fmt: on -->

### Reading

`object_history()` pages through one record's history, grouped by database transaction, newest first:

<!-- fmt: off -->
```python
--8<-- "examples/quickstart_sync.py:read"
```
<!-- fmt: on -->

Running the script prints something like:

```text
2026-09-25 22:22 by ada@example.com
  billing.invoice_sent {'channel': 'email'}
  entity.updated {'status': ['draft', 'sent'], 'payment_token': [None, '***']}
2026-09-25 22:22 by ada@example.com
  entity.created {'id': [None, 1], 'total': [None, '120.00'], 'status': [None, 'draft'], 'customer': [None, 'Acme'], 'payment_token': [None, None]}
```

`payment_token` is redacted: the log shows that it was set, never its value.

## Async

Under asyncio the listeners run on the `Session` that `AsyncSession` drives, so the `async_sessionmaker` needs a `sync_session_class` of your own; `install()` refuses the base `Session`, which would audit every session in the process.

<!-- fmt: off -->
```python
--8<-- "examples/quickstart_async.py:setup"
```
<!-- fmt: on -->

This example also tracks a relationship and points each task at its project as the *target*, so a task's changes appear in the project's history:

<!-- fmt: off -->
```python
--8<-- "examples/quickstart_async.py:models"
```
<!-- fmt: on -->

<!-- fmt: off -->
```python
--8<-- "examples/quickstart_async.py:write"
```
<!-- fmt: on -->

`AsyncSession` cannot lazy-load, so load a tracked collection (here with `selectinload`) before you change it; see [limitations](limitations.md#tracked-collections-under-asyncsession).

Every query has an `a`-prefixed async variant:

<!-- fmt: off -->
```python
--8<-- "examples/quickstart_async.py:read"
```
<!-- fmt: on -->

```text
entity.created Task Review {'id': [None, 2], 'title': [None, 'Review'], 'project_id': [None, 1]}
entity.updated Project Launch {'tasks': {'added': ['2'], 'removed': []}}
entity.created Project Launch {'id': [None, 1], 'name': [None, 'Launch'], 'tasks': {'added': ['1'], 'removed': []}}
entity.created Task Draft {'id': [None, 1], 'title': [None, 'Draft'], 'project_id': [None, 1]}
```

## FastAPI

`AuditMiddleware` fills in the request part of the context (client address, user agent, method, path, request id); `session_dependency()` hands out sessions of the installed factory; `set_actor()` records who is calling once they are authenticated.

<!-- fmt: off -->
```python
--8<-- "examples/quickstart_fastapi.py:setup"
```
<!-- fmt: on -->

<!-- fmt: off -->
```python
--8<-- "examples/quickstart_fastapi.py:auth"
```
<!-- fmt: on -->

<!-- fmt: off -->
```python
--8<-- "examples/quickstart_fastapi.py:endpoints"
```
<!-- fmt: on -->

After `POST /notes` as `ada` and `PATCH /notes/1` as `bob`, `GET /notes/1/history` returns:

```json
[
  {"actor_id": "bob", "verb": "entity.updated", "changes": {"title": ["Hello", "Hi"]}, "path": "/notes/1"},
  {"actor_id": "ada", "verb": "entity.created", "changes": {"id": [null, 1], "title": [null, "Hello"]}, "path": "/notes"}
]
```

The [FastAPI guide](guides/fastapi.md) covers proxies, request ids and sync applications.
