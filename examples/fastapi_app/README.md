# Example: an audited multi-tenant CRM on FastAPI

A small async FastAPI application (asyncpg) whose audit log answers the usual questions: who changed this customer, from where, and what changed; who read its bank details; who tried to log in and failed. Each tenant sees only its own log, and personal data can be erased from it on request.

| File | What it shows |
|---|---|
| [`models.py`](models.py) | Audited models with column policies (`hash`, `redact`, `exclude`), a tenant `scope`, a tracked relationship, and the domain events |
| [`db.py`](db.py) | The application's `AuditTrail` and a separate one for maintenance and scrubbing |
| [`auth.py`](auth.py) | Fake login, and `set_actor` once the user is known |
| [`main.py`](main.py) | The endpoints: CRUD, a fail-closed read, the history of a customer, the tenant's activity feed, and GDPR erasure |
| [`maintenance.py`](maintenance.py) | The daily job: partitions ahead, retention, health |

The test suite runs the walkthrough below against a real database (`tests/db/test_example_app.py`).

## Run it

You need Docker, [uv](https://docs.astral.sh/uv/) and a clone of this repository. Start PostgreSQL:

```bash
docker run --rm -d --name audit-demo -p 5432:5432 \
    -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=app postgres:18
```

Then, from the repository root, start the application:

```bash
uv sync
uv run --with uvicorn uvicorn examples.fastapi_app.main:app
```

uvicorn is not a dependency of the library, so `--with` adds it for this command only. Outside this repository, `pip install "sqlalchemy-audit-trail[fastapi,asyncpg]" uvicorn` installs everything the application imports.

The application connects to `postgresql+asyncpg://postgres:postgres@localhost:5432/app`; set `DATABASE_URL` to use another database. At startup it creates its tables, the audit tables and this month's partitions. The interactive API docs are at <http://localhost:8000/docs>.

## Walk through it

In another terminal, three users are ready: `ada` (admin of tenant `acme`), `bob` (`acme`) and `eve` (`globex`). The password is the login followed by `-pass`.

```bash
API=localhost:8000
JSON='Content-Type: application/json'
login() {
    curl -s -X POST $API/login -H "$JSON" -d "{\"login\": \"$1\", \"password\": \"$2\"}" |
        python3 -c 'import json, sys; print(json.load(sys.stdin)["token"])'
}
show() { python3 -m json.tool; }
```

**1. A failed login, then three good ones.**

```bash
curl -s -X POST $API/login -H "$JSON" -d '{"login": "ada", "password": "wrong"}'
ADA=$(login ada ada-pass); BOB=$(login bob bob-pass); EVE=$(login eve eve-pass)
```

**2. Ada creates a customer, Bob changes its e-mail and IBAN, Ada adds a contact.**

```bash
curl -s -X POST $API/customers -H "$JSON" -H "Authorization: Bearer $ADA" \
    -d '{"name": "Initech", "email": "billing@initech.test", "iban": "DE89370400440532013000"}'
curl -s -X PATCH $API/customers/1 -H "$JSON" -H "Authorization: Bearer $BOB" \
    -d '{"email": "accounts@initech.test", "iban": "GB29NWBK60161331926819"}'
curl -s -X POST $API/customers/1/contacts -H "$JSON" -H "Authorization: Bearer $ADA" \
    -d '{"name": "Peter Gibbons", "email": "peter@initech.test"}'
```

**3. Bob reads the bank details.**

```bash
curl -s $API/customers/1/payment-details -H "Authorization: Bearer $BOB"
```

**4. Ada looks at the customer's history.**

```bash
curl -s $API/customers/1/history -H "Authorization: Bearer $ADA" | show
```

**5. Eve, of another tenant, sees nothing of it.**

```bash
curl -s $API/customers/1/history -H "Authorization: Bearer $EVE"   # 404
curl -s $API/activity -H "Authorization: Bearer $EVE" | show        # her own login only
```

**6. Ada pages through her tenant's activity feed, two groups at a time.**

```bash
curl -s "$API/activity?limit=2" -H "Authorization: Bearer $ADA" | show
curl -s "$API/activity?limit=2&cursor=<next_cursor from the last page>" \
    -H "Authorization: Bearer $ADA" | show
```

**7. GDPR: Ada, as admin, erases Bob's personal context from the log, then erases the customer.**

```bash
curl -s -X POST $API/admin/users/u2/scrub -H "Authorization: Bearer $ADA"
curl -s -X POST $API/admin/customers/1/erase -H "Authorization: Bearer $ADA"
curl -s $API/customers/1/history -H "Authorization: Bearer $ADA" | show
```

**8. The raw rows**, for what the API does not show:

```bash
docker exec audit-demo psql -U postgres -d app -c \
    "SELECT verb, severity, actor_id, scope_id, data->'payload' AS payload
     FROM audit.audit_activity WHERE verb NOT LIKE 'entity.%' ORDER BY id"
docker exec audit-demo psql -U postgres -d app -c \
    "SELECT actor_id, actor_label, remote_addr, method, path FROM audit.audit_transaction ORDER BY id"
```

When you are done: `docker stop audit-demo`.

## What to look for

- **Every change is attributed.** Each group of the history is one database transaction, with the user (`actor`) and the request (`PATCH /customers/1`) that made it. The endpoints never pass the user to the audit trail: the `current_user` dependency calls `set_actor` once, and `AuditMiddleware` fills in the address, user agent, path and request id.
- **Column policies.** `email` is stored as `hv1:...`, an HMAC: equal addresses give equal tokens, so you can tell that it changed, and to what, if you already know the candidate value, but the log never holds the address. `iban` is `"***"`, so the log records that it was set or changed. `updated_at` is not there at all.
- **Children and labels.** The contact's creation shows up in the customer's history, because `Contact` sets its customer as `target`. The customer's own entry records `contacts: {"added": ["1"]}`, and `LabelResolver` adds `"labels": {"contacts": {"added": ["Peter Gibbons"]}}` from the log itself, not from the contact table.
- **Reads can be audited too.** `customer.payment_details_viewed` is `fail_closed`: the entry is committed before the IBAN is returned, and if it cannot be written the endpoint answers 503 instead.
- **The failed login survives the 401.** `auth.login_failed` is durable, written on its own connection, so the request's rollback does not remove it. Its payload holds `audit.login.v1:...` instead of the login typed, which might have been a password.
- **Tenants are isolated by the log's own `scope_id`.** Both audit views pass `Visibility(scope_ids={tenant})`, so Eve gets a 404 for Initech's history and a feed with nothing of `acme`. Logins have no model to take a scope from; `auth.py` puts the tenant on the request's context.
- **The feed has a window and a cursor.** It reads the last 30 days (`default_query_window`; `window_start` in the response), newest first, and `next_cursor` is an opaque token for the next page. There is no offset and no total: those would read every partition.
- **Erasure keeps the shape of the history.** After `scrub_actor`, Bob's entries still say `actor_id: u2`, but his e-mail, address and user agent are gone from the transactions and from each entry's context. After the erase, the customer's history still shows who changed which fields when, with every value `"[erased]"` and no label. Each scrub records itself as `audit.scrubbed`, with who did it and how many rows it changed.

## Demo shortcuts

This is a demo. Do not copy these parts:

- **Authentication is fake.** Users and plain-text passwords are a dict in `auth.py`, and tokens live in memory until restart. Use a real identity provider; keep the `set_actor` call.
- **The tables are created at startup.** In production, create your tables and the audit tables in migrations (see the [partitions guide](https://wiktorb2004.github.io/sqlalchemy-audit-trail/guides/partitions/)), and run `maintenance.py` on a schedule: `uv run python -m examples.fastapi_app.maintenance`.
- **One database role does everything.** The application should connect as a role that can only insert into and read the audit tables. Creating partitions, dropping expired ones and scrubbing need the maintenance role (see [`examples/roles.sql`](../roles.sql) and the [permissions guide](https://wiktorb2004.github.io/sqlalchemy-audit-trail/guides/permissions/)). Point `MAINTENANCE_DATABASE_URL` at it; the scrub endpoints and `maintenance.py` use that connection.
- **The pseudonymization key is a constant.** Set `AUDIT_PSEUDONYMIZE_KEY` to a secret of at least 32 random bytes, and keep it: it is what makes the `hv1:` and `audit.login.v1:` tokens correlatable.
- **The erase endpoint checks the tenant itself.** `scrub()` erases every entry of an object type and id, in any tenant, so the endpoint loads the customer within the admin's tenant before deleting it and scrubbing.
