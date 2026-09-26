"""The example application under ``examples/fastapi_app``, end to end.

Walks the curl flow of its README through httpx's ``ASGITransport``, in a
database of its own, and checks what the audit trail recorded.
"""

from __future__ import annotations

import importlib
import sys
import uuid
from collections.abc import Iterator
from types import ModuleType
from typing import Any

import httpx
import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.ext.asyncio import create_async_engine

from audit_trail import AuditTrail, check_models
from audit_trail.testing import assert_audited, assert_not_audited
from tests.db.test_examples import url_of

PACKAGE = "examples.fastapi_app"
CLIENT = ("203.0.113.9", 50000)
CUSTOMER = ("Customer", "1")


@pytest.fixture
def database(engine: Engine) -> Iterator[str]:
    """Name of a new, empty database, dropped after the test."""
    name = f"example_app_{uuid.uuid4().hex[:12]}"
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    yield name
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))


@pytest.fixture
def database_engine(engine: Engine, database: str) -> Iterator[Engine]:
    eng = create_engine(engine.url.set(database=database))
    yield eng
    eng.dispose()


@pytest.fixture
def example(
    engine: Engine, database: str, monkeypatch: pytest.MonkeyPatch
) -> Iterator[ModuleType]:
    """``examples.fastapi_app.main``, imported afresh on ``database``."""
    monkeypatch.setenv("DATABASE_URL", url_of(engine, database, "asyncpg"))
    monkeypatch.delenv("MAINTENANCE_DATABASE_URL", raising=False)
    monkeypatch.delenv("AUDIT_PSEUDONYMIZE_KEY", raising=False)
    yield importlib.import_module(f"{PACKAGE}.main")
    for name in [name for name in sys.modules if name.startswith(PACKAGE)]:
        del sys.modules[name]


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def activities(page: dict[str, Any]) -> list[dict[str, Any]]:
    return [activity for group in page["groups"] for activity in group["activities"]]


async def test_readme_flow(
    engine: Engine, database: str, example: ModuleType, database_engine: Engine
) -> None:
    app = example.app
    audit: AuditTrail = example.audit
    transport = httpx.ASGITransport(app=app, client=CLIENT)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://test") as client,
    ):

        async def login(name: str) -> str:
            response = await client.post(
                "/login", json={"login": name, "password": f"{name}-pass"}
            )
            assert response.status_code == 200
            token: str = response.json()["token"]
            return token

        # 1. A failed login: durable, the login pseudonymized.
        failed = await client.post("/login", json={"login": "ada", "password": "x"})
        assert failed.status_code == 401
        [row] = assert_audited(
            audit, database_engine, verb="auth.login_failed", actor_id=None
        )
        assert row["data"]["payload"] == {
            "login": audit.pseudonymize("ada", purpose="login"),
            "reason": "bad credentials",
        }
        assert row["data"]["context"]["remote_addr"] == CLIENT[0]

        # 2. Logins, scoped to the user's tenant.
        ada, bob, eve = [await login(name) for name in ("ada", "bob", "eve")]
        assert_audited(
            audit, database_engine, verb="auth.login", actor_id="u1", scope_id="acme"
        )
        assert_audited(
            audit, database_engine, verb="auth.login", actor_id="u3", scope_id="globex"
        )

        # 3. Changes by two users of acme.
        created = await client.post(
            "/customers",
            json={
                "name": "Initech",
                "email": "billing@initech.test",
                "iban": "DE89370400440532013000",
            },
            headers=bearer(ada),
        )
        assert created.status_code == 201
        assert created.json()["id"] == 1
        patched = await client.patch(
            "/customers/1",
            json={"email": "accounts@initech.test", "iban": "GB29NWBK60161331926819"},
            headers=bearer(bob),
        )
        assert patched.status_code == 200
        contact = await client.post(
            "/customers/1/contacts",
            json={"name": "Peter Gibbons", "email": "peter@initech.test"},
            headers=bearer(ada),
        )
        assert contact.status_code == 201

        [update] = assert_audited(
            audit, database_engine, verb="entity.updated", obj=CUSTOMER, actor_id="u2"
        )
        changes = update["data"]["changes"]
        assert set(changes) == {"email", "iban"}  # updated_at is excluded
        assert changes["iban"] == ["***", "***"]
        assert all(str(value).startswith("hv1:") for value in changes["email"])
        assert "initech" not in str(changes)
        assert_audited(
            audit,
            database_engine,
            verb="entity.created",
            obj=("Contact", "1"),
            target=CUSTOMER,
            scope_id="acme",
        )

        # 4. Reading the IBAN is recorded first.
        details = await client.get("/customers/1/payment-details", headers=bearer(bob))
        assert details.json() == {"iban": "GB29NWBK60161331926819"}
        assert_audited(
            audit,
            database_engine,
            verb="customer.payment_details_viewed",
            obj=CUSTOMER,
            actor_id="u2",
            severity=20,
        )
        # ... and when that cannot be recorded, the IBAN is not returned.
        durable_engine = audit.durable_engine
        # Every audit write fails, as on a read-only replica after a failover.
        broken = create_async_engine(
            url_of(engine, database, "asyncpg"),
            connect_args={"server_settings": {"default_transaction_read_only": "on"}},
        )
        audit.durable_engine = broken
        try:
            refused = await client.get(
                "/customers/1/payment-details", headers=bearer(bob)
            )
        finally:
            audit.durable_engine = durable_engine
            await broken.dispose()
        assert refused.status_code == 503
        assert "GB29" not in refused.text

        # 5. History: children included, ids labelled, values protected.
        history = await client.get("/customers/1/history", headers=bearer(ada))
        assert history.status_code == 200
        groups = history.json()["groups"]
        assert [group["request"] for group in groups] == [
            "GET /customers/1/payment-details",
            "POST /customers/1/contacts",
            "PATCH /customers/1",
            "POST /customers",
        ]
        assert groups[2]["actor"] == "bob@acme.test"
        labelled = {
            (activity["object_type"], activity["verb"]): activity["labels"]
            for activity in groups[1]["activities"]
        }
        assert labelled == {
            ("Contact", "entity.created"): {"customer_id": [None, "Initech"]},
            ("Customer", "entity.updated"): {
                "contacts": {"added": ["Peter Gibbons"], "removed": []}
            },
        }

        # 6. Another tenant sees none of it.
        assert (
            await client.get("/customers/1", headers=bearer(eve))
        ).status_code == 404
        eve_history = await client.get("/customers/1/history", headers=bearer(eve))
        assert eve_history.status_code == 404
        eve_feed = (await client.get("/activity", headers=bearer(eve))).json()
        assert [a["verb"] for a in activities(eve_feed)] == ["auth.login"]

        # 7. The feed, two groups a page, within the default window.
        pages = [(await client.get("/activity?limit=2", headers=bearer(ada))).json()]
        assert pages[0]["window_start"] is not None
        while pages[-1]["next_cursor"] is not None:
            cursor = pages[-1]["next_cursor"]
            pages.append(
                (
                    await client.get(
                        "/activity",
                        params={"limit": 2, "cursor": cursor},
                        headers=bearer(ada),
                    )
                ).json()
            )
        requests = [group["request"] for page in pages for group in page["groups"]]
        assert requests == [
            "GET /customers/1/payment-details",
            "POST /customers/1/contacts",
            "PATCH /customers/1",
            "POST /customers",
            "POST /login",
            "POST /login",
        ]
        assert len(pages) == 3
        bad = await client.get("/activity?cursor=nope", headers=bearer(ada))
        assert bad.status_code == 400

        # 8. GDPR: admins only.
        denied = await client.post("/admin/users/u2/scrub", headers=bearer(bob))
        assert denied.status_code == 403
        scrubbed = await client.post("/admin/users/u2/scrub", headers=bearer(ada))
        assert scrubbed.json() == {"activity_rows": 3, "transaction_rows": 3}
        with database_engine.connect() as conn:
            labels = conn.execute(
                text(
                    "SELECT actor_label, remote_addr FROM audit.audit_transaction"
                    " WHERE actor_id = 'u2'"
                )
            ).all()
        assert labels == [(None, None)] * 3
        [update] = assert_audited(
            audit, database_engine, verb="entity.updated", obj=CUSTOMER, actor_id="u2"
        )
        assert "remote_addr" not in update["data"]["context"]
        assert "actor_label" not in update["data"]["context"]

        erased = await client.post("/admin/customers/1/erase", headers=bearer(ada))
        assert erased.json() == {"activity_rows": 7, "transaction_rows": 0}
        assert (
            await client.get("/customers/1", headers=bearer(ada))
        ).status_code == 404
        after = (await client.get("/customers/1/history", headers=bearer(ada))).json()
        assert [a["verb"] for a in activities(after)][:2] == [
            "audit.scrubbed",
            "entity.deleted",
        ]
        for activity in activities(after):
            assert activity["object_label"] is None
            assert "Initech" not in str(activity["changes"])
        assert_audited(
            audit,
            database_engine,
            verb="audit.scrubbed",
            actor_id="u1",
            payload={"operation": "scrub", "object_id": "1", "activity_rows": 7},
        )
        assert_not_audited(audit, database_engine, verb="audit.scrubbed", actor_id="u2")

    # 9. The models pass the CI check, and the maintenance job runs.
    assert not [i for i in check_models(example.Base) if i.level == "error"]
    maintenance = importlib.import_module(f"{PACKAGE}.maintenance")
    assert await maintenance.run() == 0
