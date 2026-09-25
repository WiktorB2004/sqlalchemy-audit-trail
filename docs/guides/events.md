# Domain events

Entity changes are recorded on their own. Everything else worth auditing (a login, a failed login, a document download, someone reading sensitive data) is a *domain event* that you declare and log explicitly.

## Declaring events

Events are members of an `AuditEvent` subclass, built with `event()`:

```python
from pydantic import BaseModel

from audit_trail import AuditEvent, Pseudonymized, Severity, event


class LoginFailed(BaseModel):
    login: Pseudonymized[str]
    reason: str


class AuthEvent(AuditEvent):
    LOGIN = event("auth.login", Severity.INFO)
    LOGIN_FAILED = event(
        "auth.login_failed", Severity.WARNING, LoginFailed, durable=True
    )


class RecordEvent(AuditEvent):
    SENSITIVE_VIEWED = event(
        "record.sensitive_viewed", Severity.NOTICE, fail_closed=True
    )
```

`event(value, severity, schema=None, *, durable=False, fail_closed=False)`:

- `value` is the verb stored in `audit_activity.verb`, written as `domain.action` in snake_case. The prefixes `entity.` and `audit.` are reserved for the library.
- `severity` is a member of the severity enum configured on `AuditTrail`.
- `schema` is an optional pydantic model that validates the payload (needs the `pydantic` extra). Without one, the payload is any JSON-encodable mapping.
- `durable` and `fail_closed` are described [below](#durable-and-fail-closed-events).

An event member compares equal to its verb, and `str(AuthEvent.LOGIN)` is `"auth.login"`. To look an event up by its verb, use `audit.registry.get("auth.login")`.

### Registering

`AuditTrail(events=None)`, the default, registers every `AuditEvent` subclass that has members when the `AuditTrail` is created, so the modules that define events must be imported first. Listing the classes is more predictable:

```python
audit = AuditTrail(engine, events=[AuthEvent, RecordEvent])
```

Registration fails with `EventRegistryError` when two events share a verb, a severity is not a member of the configured enum, or a verb uses a reserved prefix. Logging an event that is not registered raises `UnknownEventError`.

## Severities

The library does not name severity levels for you. By default it uses `Severity` (`INFO=10`, `NOTICE=20`, `WARNING=30`, `CRITICAL=40`); to use your own, pass any `IntEnum`:

```python
from enum import IntEnum


class Level(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


audit = AuditTrail(
    engine,
    severities=Level,
    default_severity=Level.LOW,  # entity.* entries of models that set none
    system_severity=Level.HIGH,  # the library's own audit.scrubbed entries
    events=[AuthEvent],
)
```

Each severity value gets its own partition, and retention is set per severity (see [partitions](partitions.md)). `default_severity` defaults to the lowest level and `system_severity` to the highest; set `system_severity` when the highest level is not the one you keep longest.

## Logging

```python
audit.log(
    session,
    AuthEvent.LOGIN,
    actor=Actor(type="user", id=str(user.id), label=user.email),
)

audit.log(
    session, RecordEvent.SENSITIVE_VIEWED, obj=patient, payload={"reason": "support"}
)

await audit.alog(session, AuthEvent.LOGIN, actor=Actor(type="user", id=str(user.id)))
```

`log(session, event, *, obj=None, target=None, payload=None, actor=None, durable=None)` (and `alog` for an `AsyncSession`):

- `session` must be a session of a factory this `AuditTrail` is installed on.
- `obj` is the object the event is about. It sets `object_type`, `object_id` and `object_label`, and through its model's options `scope_id` and the default target. It needs a primary key, so flush a new object first.
- `target` is the parent object: an instance, a `Target(type, id)` or a `(type, id)` tuple. It defaults to the `target` option of `obj`'s model.
- `payload` is a mapping or an instance of the event's schema, validated against the schema (`PayloadError` when it does not match).
- `actor` sets the actor of this entry only, for example at login, before the request context knows who the user is. The `audit_transaction` row keeps the context's actor.
- `durable` overrides the event's `durable` flag for this call. It cannot weaken a `fail_closed` event.

A non-durable entry is inserted right away on the session's connection, in the session's transaction: it is committed or rolled back with your changes. It is written even when `session.info["audit_enabled"]` is `False`.

## Durable and fail-closed events

Some events must be recorded whatever happens to the request's transaction.

- `durable=True`: the entry is written on a separate connection, in a transaction of its own, and committed before `log()` returns, so it survives a rollback of the session. Use it for failed logins and denied access. A failed durable write is logged, or raises `AuditWriteError` with `AuditTrail(on_error="raise")`.
- `fail_closed=True`: implies `durable`, and a failed write always raises `AuditWriteError`. Log the event before returning the data it protects; if the audit write fails, the data is not returned. The entry exists even when the rest of the request later fails: the access was attempted.

```python
from audit_trail import AuditWriteError

try:
    audit.log(session, RecordEvent.SENSITIVE_VIEWED, obj=patient)
except AuditWriteError:
    raise HTTPException(status_code=503) from None
return patient.medical_history
```

Durable writes use `AuditTrail(durable_engine=...)`, or by default a small pool the library builds from the URL of `engine` (5 connections, no overflow, 5 s pool timeout). It uses only the URL: pass your own `durable_engine` if you need `connect_args` or other engine settings. `log()` needs a sync durable engine and `alog()` an async one. Close the library's pool on shutdown with `audit.dispose()` or `await audit.adispose()`.

## Write errors

With `on_error="log"` (the default), a database error while writing entries in the session's transaction is logged on the `audit_trail.writer` logger and swallowed: the write runs in a savepoint, and your transaction continues without its audit rows. With `on_error="raise"`, the error propagates and your transaction fails. Errors from your own code (a `label` callable, an unserializable value) always propagate.

## Pseudonymized values

Some payload values should be correlatable without being stored, such as the login typed into a failed login form (it may be a password typed into the wrong field). Mark such fields `Pseudonymized[...]` on the schema; the writer replaces the value with an HMAC token, using the field name as the purpose:

```python
audit.log(
    session,
    AuthEvent.LOGIN_FAILED,
    payload=LoginFailed(login=form.login, reason="bad password"),
)
# payload stored as {"login": "audit.login.v1:9f86...", "reason": "bad password"}
```

For a payload without a schema, call `audit.pseudonymize(value, purpose="login")` yourself. Both need `AuditTrail(pseudonymize_key=...)`; see [privacy](privacy.md#keys-and-rotation).
