# Testing your application

`audit_trail.testing` has assertions for your own tests, and `audit_trail.pytest_plugin` sets the audit tables up on a test database. Neither changes how the library writes.

## Assertions

```python
from unittest.mock import ANY

from audit_trail.testing import assert_audited, assert_not_audited


def test_sending_an_invoice_is_audited(session, audit) -> None:
    invoice = send_invoice(session, invoice_id=1)

    assert_audited(
        audit,
        session,
        verb="entity.updated",
        obj=invoice,
        actor_id="42",
        changes={"status": ["draft", "sent"], "sent_at": [None, ANY]},
    )
    assert_audited(
        audit, session, verb=BillingEvent.INVOICE_SENT, payload={"channel": "email"}
    )
    assert_not_audited(audit, session, verb="entity.deleted")
```

`assert_audited(audit, bind, *, verb, obj, target, actor_id, scope_id, severity, changes, payload)` passes when at least one entry matches every filter you give, and returns the matching entries. Filters you leave out are not checked; `None` means the column is `NULL`.

- `bind` is a `Session`, `Connection` or `Engine`. A session is flushed first, and a session or connection also sees rows it has not committed; an engine sees committed rows only.
- `verb` takes a verb or an `AuditEvent` member.
- `obj` and `target` take a mapped instance, a `Target` or a `(type, id)` tuple.
- `changes` and `payload` must be contained in the entry: other keys are ignored. Values are compared in their stored form: an ISO string for a datetime, `"***"` for a redacted value. `unittest.mock.ANY` matches anything.
- Entries are read as written, not compacted: two flushes in one transaction are two entries.

On failure, the message lists the closest entries and how each differs. `assert_not_audited()` takes the same filters and fails when an entry matches. `aassert_audited()` and `aassert_not_audited()` do the same with an `AsyncSession`, `AsyncConnection` or `AsyncEngine`.

## The pytest plugin

If your test database is not built by migrations that include the audit tables, the plugin creates them. Enable it in the root `conftest.py` and override its `audit_trail` fixture to return your application's `AuditTrail`, on an engine that points at the test database:

```python
# conftest.py
import pytest

from myapp.audit import audit

pytest_plugins = ["audit_trail.pytest_plugin"]


@pytest.fixture(scope="session")
def audit_trail():
    return audit
```

Fixtures:

- `audit_tables` (session scope): creates the audit tables and the partitions of the current and next month, and drops the tables at the end of the session;
- `audit_clean` (function scope): `audit_tables`, with both tables emptied before the test.

Both return the `AuditTrail`. With an `AsyncEngine`, they run on a private copy of the engine's pool in an event loop of their own, so they work whatever loop your tests use.

```python
def test_login_is_audited(audit_clean, client) -> None:
    client.post("/login", data={"user": "ada", "password": "..."})
    assert_audited(audit_clean, audit_clean.engine, verb="auth.login")
```

Without pytest, `create_test_tables(audit, connection, months_ahead=1)`, `drop_test_tables(audit, connection)` and `clear_audit_entries(audit, connection)` do the same on a connection you provide.

## Checking models

Add [`check_models()`](models.md#checking-models-in-ci) to your test suite, so a new sensitive column without a policy fails CI.
