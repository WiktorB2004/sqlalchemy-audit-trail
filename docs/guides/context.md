# Request context

Every entry records who made the change, from where and how. That information lives in an `AuditContext`:

| Field | Meaning |
|---|---|
| `actor_type` | kind of actor, defined by you: `"user"`, `"system"`, `"api_key"`, ...; defaults to `"anonymous"` |
| `actor_id` | opaque id of the actor (see [privacy](privacy.md#actor-ids)) |
| `actor_label` | human-readable snapshot, e.g. an e-mail address; survives deletion of the user |
| `remote_addr`, `user_agent`, `method`, `path` | where the request came from |
| `channel` | entry point: `"api"`, `"admin"`, `"cli"`, `"worker"`, ... |
| `auth_method` | how the actor authenticated |
| `request_id` | id of the request |
| `correlation_id` | links several database transactions of one operation; defaults to `request_id` |
| `scope_id` | scope of the change, e.g. a tenant; used when the model has no `scope` option |
| `extra` | a dict of anything else, stored as `meta`; must be JSON-encodable |

## Activating a context

`audit.context(...)` activates a context for a block of code, sync or async. It takes either the fields as keyword arguments or a ready `AuditContext`:

```python
with audit.context(
    actor_type="system", actor_label="nightly-cleanup", channel="worker"
):
    run_cleanup()

async with audit.context(AuditContext(actor_type="system", channel="worker")):
    await run_cleanup()
```

A nested block replaces the outer context for its duration; it does not inherit the outer fields. Outside any block, entries are written with an anonymous context.

## Setting the actor later

The actor is usually known only after authentication, when the context is already active. `audit.set_actor()` updates the active context in place:

```python
with audit.context(channel="api", remote_addr=client_ip):
    user = authenticate(request)
    audit.set_actor(Actor(type="user", id=str(user.id), label=user.email))
    handle(request)
```

Because the object is mutated rather than replaced, an actor set from a worker thread (for example a synchronous FastAPI dependency) is visible to the code that started it. `set_actor()` raises `RuntimeError` when no `context()` block is active.

The `audit_transaction` row of a database transaction is created by its first audit entry, with the context of that moment. Each entry also stores a snapshot of the context in `data["context"]` and its own `actor_id`, so an actor set after the first entry of a transaction is still recorded on the later entries.

## Binding a context to a session

Code without context variables (scripts, some task queues, tests) can attach a context to one session instead:

```python
with SessionLocal() as session:
    audit.bind(session, AuditContext(actor_type="system", channel="import"))
    import_customers(session)
    session.commit()
```

A bound context takes precedence over everything else for that session, and `set_actor()` does not reach it: change its fields directly. Binding does not turn auditing on; the session still has to come from an installed factory.

## Providers

`AuditTrail(context_provider=...)` takes a callable that returns the current `AuditContext`, or `None` to fall through. It is for applications that already keep request state somewhere else.

The context of an entry is resolved in this order:

1. a context bound to the session with `bind()`;
2. `context_provider()`, when it returns a context;
3. the context activated with `audit.context(...)`;
4. an anonymous context.

## What is stored

The `audit_transaction` row holds all fields except `scope_id`. Each entry's `data["context"]` holds the snapshot at the time of the entry, leaving out empty fields and `actor_id`, which has a column of its own:

```json
{"actor_type": "user", "actor_label": "ada@example.com", "remote_addr": "203.0.113.9",
 "method": "PATCH", "path": "/notes/1", "channel": "api", "request_id": "5d0c4c8e-...", "meta": {"ticket": "OPS-12"}}
```

The snapshot keeps each entry's context for as long as the entry itself is kept, even after the `audit_transaction` row has been dropped by a shorter retention (see [partitions](partitions.md#retention)).
