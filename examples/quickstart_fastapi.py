"""Quickstart: a FastAPI application with an audited model.

Run against an empty PostgreSQL database::

    DATABASE_URL=postgresql+asyncpg://user:password@localhost/app \
        uvicorn examples.quickstart_fastapi:app

then, for example::

    curl -X POST -H 'X-User: ada' -H 'Content-Type: application/json' \
        -d '{"title": "Hello"}' localhost:8000/notes
    curl localhost:8000/notes/1/history
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from audit_trail import Actor, Audited, AuditOptions, AuditTrail
from audit_trail.integrations.fastapi import (
    AuditMiddleware,
    session_dependency,
    set_actor,
)
from audit_trail.migrations import create_audit_tables

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/app"
)


class Base(DeclarativeBase):
    pass


class Note(Base, Audited):
    __tablename__ = "note"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str]

    __audit__ = AuditOptions(label=lambda note: note.title)


class AppSession(Session):
    pass


# --8<-- [start:setup]
engine = create_async_engine(DATABASE_URL)
audit = AuditTrail(engine, events=[])
SessionLocal = async_sessionmaker(
    engine, sync_session_class=AppSession, expire_on_commit=False
)
audit.install(SessionLocal)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Tables belong in migrations; partitions are also created on a schedule.
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        await connection.run_sync(create_audit_tables, audit.tables, audit.severities)
    await audit.maintenance.aensure_partitions()
    yield
    await audit.adispose()
    await engine.dispose()


app = FastAPI(lifespan=lifespan)
app.add_middleware(AuditMiddleware)
get_session = session_dependency(SessionLocal)
# --8<-- [end:setup]


# --8<-- [start:auth]
def current_user(x_user: Annotated[str, Header()]) -> str:
    # Stand-in for real authentication. A sync dependency runs in the thread
    # pool; set_actor still reaches the request's audit context.
    set_actor(Actor(type="user", id=x_user), auth_method="header")
    return x_user


# --8<-- [end:auth]


# --8<-- [start:endpoints]
class NoteIn(BaseModel):
    title: str


@app.post("/notes", status_code=201)
async def create_note(
    note_in: NoteIn,
    user: Annotated[str, Depends(current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, int]:
    note = Note(title=note_in.title)
    session.add(note)
    await session.commit()
    return {"id": note.id}


@app.patch("/notes/{note_id}")
async def rename_note(
    note_id: int,
    note_in: NoteIn,
    user: Annotated[str, Depends(current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, int]:
    note = await session.get(Note, note_id)
    if note is None:
        raise HTTPException(status_code=404)
    note.title = note_in.title
    await session.commit()
    return {"id": note_id}


@app.get("/notes/{note_id}/history")
async def note_history(
    note_id: int, session: Annotated[AsyncSession, Depends(get_session)]
) -> list[dict[str, Any]]:
    page = await audit.query.aobject_history(session, "Note", str(note_id))
    return [
        {
            "actor_id": activity["actor_id"],
            "verb": activity["verb"],
            "changes": activity["data"]["changes"],
            "path": activity["data"]["context"].get("path"),
        }
        for group in page.groups
        for activity in group.activities
    ]


# --8<-- [end:endpoints]
