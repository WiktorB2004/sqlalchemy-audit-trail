"""The HTTP API: customers, their audit history and the tenant's activity feed.

Run from the repository root, against the database in ``DATABASE_URL``::

    uv run --with uvicorn uvicorn examples.fastapi_app.main:app
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from audit_trail import AuditWriteError, Cursor, LabelResolver, Page, Visibility
from audit_trail.diff import object_id_for
from audit_trail.integrations.fastapi import AuditMiddleware, session_dependency

from .auth import (
    USERS,
    User,
    check_password,
    current_user,
    issue_token,
    record_user,
    require_admin,
)
from .db import SessionLocal, audit, create_schema, dispose, maintenance
from .models import AuthEvent, Base, Contact, Customer, CustomerEvent, LoginFailed


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    await create_schema()  # for the demo; use migrations in production
    yield
    await dispose()


app = FastAPI(title="Audited CRM", lifespan=lifespan)
# One audit context per request: address, user agent, method, path, request id.
app.add_middleware(AuditMiddleware)
get_session = session_dependency(SessionLocal)
labels = LabelResolver(audit.tables, Base)

SessionDep = Annotated[AsyncSession, Depends(get_session)]
UserDep = Annotated[User, Depends(current_user)]
AdminDep = Annotated[User, Depends(require_admin)]


# --- Schemas -----------------------------------------------------------------


class LoginIn(BaseModel):
    login: str
    password: str


class TokenOut(BaseModel):
    token: str


class CustomerIn(BaseModel):
    name: str
    email: str
    iban: str | None = None


class CustomerPatch(BaseModel):
    name: str | None = None
    email: str | None = None
    iban: str | None = None


class ContactIn(BaseModel):
    name: str
    email: str


class ContactOut(BaseModel):
    id: int
    name: str
    email: str


class CustomerOut(BaseModel):
    id: int
    name: str
    email: str
    updated_at: datetime
    contacts: list[ContactOut]


class PaymentDetailsOut(BaseModel):
    iban: str | None


class ActivityOut(BaseModel):
    verb: str
    object_type: str | None
    object_id: str | None
    object_label: str | None
    changes: Mapping[str, object] | None
    payload: Mapping[str, object] | None
    # Labels of the objects that `changes` refers to by id.
    labels: Mapping[str, object] | None


class GroupOut(BaseModel):
    at: datetime
    actor_id: str | None
    actor: str | None
    request: str | None
    activities: list[ActivityOut]


class PageOut(BaseModel):
    groups: list[GroupOut]
    next_cursor: str | None
    window_start: datetime | None


class ScrubOut(BaseModel):
    activity_rows: int
    transaction_rows: int


# --- Helpers -----------------------------------------------------------------


def tenant_visibility(user: User) -> Visibility:
    """The caller sees their own tenant's entries, nothing else."""
    return Visibility(scope_ids={user.tenant_id})


async def load_customer(
    session: AsyncSession, customer_id: int, user: User
) -> Customer:
    customer = await session.scalar(
        select(Customer)
        .where(Customer.id == customer_id, Customer.tenant_id == user.tenant_id)
        # contacts is tracked: an AsyncSession must load it before it changes.
        .options(selectinload(Customer.contacts))
    )
    if customer is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such customer")
    return customer


def customer_out(customer: Customer) -> CustomerOut:
    return CustomerOut(
        id=customer.id,
        name=customer.name,
        email=customer.email,
        updated_at=customer.updated_at,
        contacts=[
            ContactOut(id=contact.id, name=contact.name, email=contact.email)
            for contact in customer.contacts
        ],
    )


def parse_cursor(token: str | None) -> Cursor | None:
    if token is None:
        return None
    try:
        return Cursor.decode(token)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "bad cursor") from None


async def page_out(
    session: AsyncSession, page: Page, visibility: Visibility
) -> PageOut:
    activities = [activity for group in page.groups for activity in group.activities]
    resolved = await labels.aresolve(session, activities, visibility=visibility)
    groups = []
    for group in page.groups:
        header = group.transaction
        request = (
            f"{header.method} {header.path}" if header.method and header.path else None
        )
        groups.append(
            GroupOut(
                at=header.issued_at,
                actor_id=header.actor_id,
                actor=header.actor_label,
                request=request,
                activities=[
                    ActivityOut(
                        verb=activity["verb"],
                        object_type=activity["object_type"],
                        object_id=activity["object_id"],
                        object_label=activity["object_label"],
                        changes=activity["data"].get("changes"),
                        payload=activity["data"].get("payload"),
                        labels=resolved.get(activity["id"]),
                    )
                    for activity in group.activities
                ],
            )
        )
    return PageOut(
        groups=groups,
        next_cursor=None if page.next_cursor is None else page.next_cursor.encode(),
        window_start=page.since,
    )


# --- Login -------------------------------------------------------------------


@app.post("/login")
async def login(form: LoginIn, session: SessionDep) -> TokenOut:
    user = check_password(form.login, form.password)
    if user is None:
        # Durable: committed on its own connection before the 401 is sent.
        # The login is stored as an HMAC token, never as typed.
        await audit.alog(
            session,
            AuthEvent.LOGIN_FAILED,
            payload=LoginFailed(login=form.login, reason="bad credentials"),
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bad credentials")
    record_user(user, "password")
    await audit.alog(session, AuthEvent.LOGIN)
    await session.commit()
    return TokenOut(token=issue_token(user))


# --- Customers ---------------------------------------------------------------


@app.post("/customers", status_code=status.HTTP_201_CREATED)
async def create_customer(
    body: CustomerIn, user: UserDep, session: SessionDep
) -> CustomerOut:
    customer = Customer(tenant_id=user.tenant_id, contacts=[], **body.model_dump())
    session.add(customer)
    await session.commit()
    return customer_out(customer)


@app.get("/customers")
async def list_customers(user: UserDep, session: SessionDep) -> list[CustomerOut]:
    customers = await session.scalars(
        select(Customer)
        .where(Customer.tenant_id == user.tenant_id)
        .options(selectinload(Customer.contacts))
        .order_by(Customer.id)
    )
    return [customer_out(customer) for customer in customers]


@app.get("/customers/{customer_id}")
async def get_customer(
    customer_id: int, user: UserDep, session: SessionDep
) -> CustomerOut:
    return customer_out(await load_customer(session, customer_id, user))


@app.patch("/customers/{customer_id}")
async def update_customer(
    customer_id: int, body: CustomerPatch, user: UserDep, session: SessionDep
) -> CustomerOut:
    customer = await load_customer(session, customer_id, user)
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(customer, field, value)
    await session.commit()
    return customer_out(customer)


@app.delete("/customers/{customer_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_customer(customer_id: int, user: UserDep, session: SessionDep) -> None:
    await session.delete(await load_customer(session, customer_id, user))
    await session.commit()


@app.post("/customers/{customer_id}/contacts", status_code=status.HTTP_201_CREATED)
async def add_contact(
    customer_id: int, body: ContactIn, user: UserDep, session: SessionDep
) -> CustomerOut:
    customer = await load_customer(session, customer_id, user)
    customer.contacts.append(Contact(tenant_id=user.tenant_id, **body.model_dump()))
    await session.commit()
    return customer_out(customer)


@app.get("/customers/{customer_id}/payment-details")
async def payment_details(
    customer_id: int, user: UserDep, session: SessionDep
) -> PaymentDetailsOut:
    customer = await load_customer(session, customer_id, user)
    # Fail-closed: no audit entry, no IBAN.
    try:
        await audit.alog(session, CustomerEvent.PAYMENT_DETAILS_VIEWED, obj=customer)
    except AuditWriteError:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "audit log unavailable"
        ) from None
    return PaymentDetailsOut(iban=customer.iban)


# --- Audit views -------------------------------------------------------------


@app.get("/customers/{customer_id}/history")
async def customer_history(
    customer_id: int,
    user: UserDep,
    session: SessionDep,
    cursor: str | None = None,
) -> PageOut:
    # Read from the log, not the customer table: works after a deletion too.
    visibility = tenant_visibility(user)
    page = await audit.query.aobject_history(
        session,
        "Customer",
        object_id_for(Customer, customer_id),
        visibility=visibility,
        cursor=parse_cursor(cursor),
    )
    if not page.groups and cursor is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such customer")
    return await page_out(session, page, visibility)


@app.get("/activity")
async def activity_feed(
    user: UserDep,
    session: SessionDep,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> PageOut:
    # Newest first, last 30 days (default_query_window), one tenant only.
    visibility = tenant_visibility(user)
    page = await audit.query.alist_groups(
        session, visibility=visibility, cursor=parse_cursor(cursor), limit=limit
    )
    return await page_out(session, page, visibility)


# --- GDPR (admins) -----------------------------------------------------------
# Scrubbing updates audit rows, so it runs on `maintenance`, whose engine
# should connect as the maintenance role; the application's role cannot.


@app.post("/admin/customers/{customer_id}/erase")
async def erase_customer(
    customer_id: int, admin: AdminDep, session: SessionDep
) -> ScrubOut:
    """Delete a customer, then erase the values its audit entries hold."""
    # scrub() knows nothing about tenants: check ownership while the row exists.
    await session.delete(await load_customer(session, customer_id, admin))
    await session.commit()
    result = await maintenance.ascrub("Customer", object_id_for(Customer, customer_id))
    return ScrubOut(**result._asdict())


@app.post("/admin/users/{user_id}/scrub")
async def scrub_user(user_id: str, admin: AdminDep) -> ScrubOut:
    """Erase a user's personal context (label, address, user agent) from the log."""
    if not any(
        user.id == user_id and user.tenant_id == admin.tenant_id
        for user in USERS.values()
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    result = await maintenance.ascrub_actor(user_id)
    return ScrubOut(**result._asdict())
