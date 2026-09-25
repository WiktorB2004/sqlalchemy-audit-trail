# FastAPI

`audit_trail.integrations.fastapi` connects the request to the audit context. It needs the `fastapi` extra:

```bash
pip install "sqlalchemy-audit-trail[fastapi]"
```

The [quickstart](../quickstart.md#fastapi) has a complete application.

## Middleware

```python
from audit_trail.integrations.fastapi import AuditMiddleware

app.add_middleware(AuditMiddleware)
```

`AuditMiddleware` is plain ASGI middleware. For each HTTP and websocket request it activates an `AuditContext` with `remote_addr`, `user_agent`, `method` (`None` for a websocket), `path` (without the query string), `channel` and a `request_id`, and keeps it active for the whole request, including synchronous dependencies and endpoints that FastAPI runs in its thread pool.

`AuditMiddleware(app, *, channel="api", request_id_header="x-request-id", trusted_proxies=())`:

- `channel` is stored as the context's `channel`.
- `trusted_proxies` lists the addresses or networks (`"10.0.0.0/8"`) of your reverse proxies. By default none is trusted, and `remote_addr` is the direct peer's address. When the peer is a trusted proxy, the client address is taken from `X-Forwarded-For`, read from right to left, skipping trusted proxies. `Forwarded` (RFC 7239) is not read.
- `request_id_header` names the header carrying a request id set by a trusted proxy. It is used only when the peer is trusted and the value is a UUID; otherwise every request gets a new UUID, so a client cannot choose the id. `None` always generates one.

```python
app.add_middleware(AuditMiddleware, channel="admin", trusted_proxies=["10.0.0.0/8"])
```

An address that is not a valid IP is stored as `None`.

## Sessions

`session_dependency(factory)` builds a dependency that yields a session of the factory you passed to `install()`, and closes it after the request. It never commits: your endpoint does.

```python
from audit_trail.integrations.fastapi import session_dependency

get_session = session_dependency(SessionLocal)


@app.post("/notes")
def create_note(
    note_in: NoteIn, session: Annotated[Session, Depends(get_session)]
) -> dict[str, int]: ...
```

With a `sessionmaker` the dependency is synchronous; with an `async_sessionmaker` it is asynchronous. It raises `TypeError` when the factory has no `AuditTrail` installed.

`session_provider()` returns the session such a dependency opened for the current request, or `None`, for code that needs the request's session without having it passed in. Pass it to `AuditTrail` and `audit.log()` finds the request's session by itself:

```python
from audit_trail.integrations.fastapi import session_provider

audit = AuditTrail(engine, session_provider=session_provider)


def record_export(report: Report) -> None:
    # Called from an endpoint that depends on get_session.
    audit.log(ReportEvent.EXPORTED, obj=report)
```

The entry is written in the request's session and committed with it, as if the session had been passed. Use `alog()` with an `async_sessionmaker`. Outside a request, or in a request without a `session_dependency`, there is no session and the call raises `RuntimeError`.

## The actor

After authentication, record who is calling with `set_actor()` from `audit_trail.integrations.fastapi`:

```python
from audit_trail import Actor
from audit_trail.integrations.fastapi import set_actor


def current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    user = authenticate(token)
    set_actor(
        Actor(type="user", id=str(user.id), label=user.email), auth_method="bearer"
    )
    return user
```

`set_actor(actor, *, auth_method=None)` updates the request's context in place, so it works from a synchronous dependency running in the thread pool, and it works when the session was opened before the user was known: the listener reads the context when the session flushes. It raises `RuntimeError` outside a request handled by `AuditMiddleware`.

Unlike `audit.set_actor()`, it always updates the request's own context, even inside a nested `audit.context(...)` block.

## Nested contexts

Inside a request you can still run code under another context, for example a system action triggered by the user:

```python
with audit.context(actor_type="system", actor_label="auto-archive", channel="api"):
    archive_old_notes(session)
    session.commit()
```

Pass `AuditTrail(context_provider=context_provider)` from `audit_trail.integrations.fastapi` if you want to be explicit; it returns the innermost `audit.context(...)` block, else the request's context. It is optional: the middleware activates the request's context in the same place `audit.context()` does, which the listener reads anyway. `request_context()` returns the request's own context.
