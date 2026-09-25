"""Quickstart: audit a model with an ``AsyncSession`` on asyncpg.

Run against an empty PostgreSQL database::

    DATABASE_URL=postgresql+asyncpg://user:password@localhost/app \
        python examples/quickstart_async.py
"""

from __future__ import annotations

import asyncio
import os

from sqlalchemy import ForeignKey
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    selectinload,
)

from audit_trail import Actor, Audited, AuditOptions, AuditTrail
from audit_trail.migrations import create_audit_tables

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/app"
)


class Base(DeclarativeBase):
    pass


# --8<-- [start:models]
class Project(Base, Audited):
    __tablename__ = "project"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    tasks: Mapped[list[Task]] = relationship(back_populates="project")

    __audit__ = AuditOptions(
        label=lambda project: project.name,
        track_relationships={"tasks"},
    )


class Task(Base, Audited):
    __tablename__ = "task"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str]
    project_id: Mapped[int] = mapped_column(ForeignKey("project.id"))
    project: Mapped[Project] = relationship(back_populates="tasks")

    __audit__ = AuditOptions(
        label=lambda task: task.title,
        # Changes of a task also show up in its project's history.
        target=lambda task: ("Project", task.project_id),
    )


# --8<-- [end:models]


# --8<-- [start:setup]
class AppSession(Session):
    """The listeners are registered on this class, not on every Session."""


engine = create_async_engine(DATABASE_URL)
audit = AuditTrail(engine, events=[])
SessionLocal = async_sessionmaker(engine, sync_session_class=AppSession)
audit.install(SessionLocal)


async def create_tables() -> None:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        await connection.run_sync(create_audit_tables, audit.tables, audit.severities)
    await audit.maintenance.aensure_partitions()


# --8<-- [end:setup]


# --8<-- [start:write]
async def work() -> None:
    actor = Actor(type="user", id="7", label="grace@example.com")
    async with audit.context(channel="worker"):
        audit.set_actor(actor)
        async with SessionLocal() as session:
            project = Project(id=1, name="Launch", tasks=[Task(id=1, title="Draft")])
            session.add(project)
            await session.commit()

        async with SessionLocal() as session:
            # A tracked collection must be loaded before it is changed:
            # AsyncSession cannot lazy-load it.
            project = await session.get_one(
                Project, 1, options=[selectinload(Project.tasks)]
            )
            project.tasks.append(Task(id=2, title="Review"))
            await session.commit()


# --8<-- [end:write]


# --8<-- [start:read]
async def show_history() -> None:
    async with SessionLocal() as session:
        page = await audit.query.aobject_history(session, "Project", "1")
        for group in page.groups:
            for activity in group.activities:
                print(
                    activity["verb"],
                    activity["object_type"],
                    activity["object_label"],
                    activity["data"]["changes"],
                )


# --8<-- [end:read]


async def main() -> None:
    await create_tables()
    await work()
    await show_history()
    await audit.adispose()
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
