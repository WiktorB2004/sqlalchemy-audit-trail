"""``AuditTrail`` wiring and ``install()`` checks that need no database."""

from __future__ import annotations

import gc
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

import pytest
from sqlalchemy import Column, Engine, ForeignKey, Table, create_engine
from sqlalchemy import event as sa_event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    registry,
    relationship,
    sessionmaker,
)

from audit_trail import Audited, AuditEvent, AuditOptions, AuditTrail, event, listener
from audit_trail.context import bind, context, current_context, set_actor
from audit_trail.events import EventRegistryError, Severity
from audit_trail.listener import installed_trail
from audit_trail.maintenance import PartitionManager
from audit_trail.relations import pop_relationship_changes
from audit_trail.serialization import KeyRing, pseudonymize

KEY = b"k" * 32


class Level(IntEnum):
    LOW = 1
    MID = 2
    TOP = 3


@pytest.fixture
def engine() -> Engine:
    return create_engine("postgresql+psycopg://localhost/unused")


def test_defaults(engine: Engine) -> None:
    audit = AuditTrail(engine, events=[])
    assert audit.severities is Severity
    assert audit.registry.default_severity is Severity.INFO
    assert audit.registry.system_severity is Severity.CRITICAL
    assert audit.keys is None
    assert audit.global_redact == frozenset()
    assert audit.tables.transaction.schema == "audit"


def test_severity_settings_reach_the_registry(engine: Engine) -> None:
    class ShopEvent(AuditEvent):
        ORDER_PLACED = event("config_test.order_placed", Level.MID)

    audit = AuditTrail(
        engine,
        severities=Level,
        default_severity=Level.MID,
        system_severity=Level.LOW,
        events=[ShopEvent],
    )
    assert audit.registry.default_severity is Level.MID
    assert audit.registry.system_severity is Level.LOW
    assert audit.registry.get("config_test.order_placed") is ShopEvent.ORDER_PLACED
    with pytest.raises(EventRegistryError):
        AuditTrail(engine, severities=Level, default_severity=Severity.INFO)


def test_events_default_to_discovery(engine: Engine) -> None:
    gc.collect()  # drop event classes other tests defined locally

    class Discovered(AuditEvent):
        FOUND = event("config_test.found", Severity.INFO)

    audit = AuditTrail(engine)
    assert audit.registry.get("config_test.found") is Discovered.FOUND
    explicit = AuditTrail(engine, events=[])
    assert "config_test.found" not in explicit.registry.events


def test_tables_maintenance_and_redaction(engine: Engine) -> None:
    audit = AuditTrail(
        engine,
        schema="log",
        severities=Level,
        indexes={"severity"},
        global_redact=["password"],
        events=[],
    )
    assert audit.tables.activity.schema == "log"
    assert {index.name for index in audit.tables.activity.indexes} == {
        "audit_activity_severity_idx"
    }
    assert isinstance(audit.maintenance, PartitionManager)
    assert audit.maintenance.tables is audit.tables
    assert audit.maintenance.severities == [1, 2, 3]
    assert audit.global_redact == frozenset({"password"})


def test_pseudonymize_uses_the_configured_key(engine: Engine) -> None:
    audit = AuditTrail(engine, pseudonymize_key={2: KEY}, events=[])
    assert isinstance(audit.keys, KeyRing)
    assert audit.pseudonymize("x", purpose="login") == pseudonymize(
        "x", purpose="login", keys=KeyRing({2: KEY})
    )
    with pytest.raises(ValueError, match="pseudonymize_key"):
        AuditTrail(engine, events=[]).pseudonymize("x", purpose="login")
    with pytest.raises(ValueError, match="shorter"):
        AuditTrail(engine, pseudonymize_key=b"short", events=[])


def test_context_helpers_are_exposed(engine: Engine) -> None:
    audit = AuditTrail(engine, events=[])
    assert audit.context is context
    assert audit.set_actor is set_actor
    assert audit.bind is bind
    with audit.context(actor_type="system") as ctx:
        assert current_context() is ctx


def test_install_accepts_a_sessionmaker(engine: Engine) -> None:
    audit = AuditTrail(engine, events=[])
    factory = sessionmaker(engine)
    audit.install(factory)
    assert installed_trail(factory()) is audit
    assert installed_trail(Session(engine)) is None
    assert installed_trail(sessionmaker(engine)()) is None


def test_install_refuses_the_base_session(engine: Engine) -> None:
    with pytest.raises(ValueError, match="base Session"):
        AuditTrail(engine, events=[]).install(Session)


@pytest.mark.parametrize("factory", [object(), Session.__init__, int])
def test_install_refuses_other_objects(engine: Engine, factory: Any) -> None:
    with pytest.raises(TypeError, match="sessionmaker or a Session subclass"):
        AuditTrail(engine, events=[]).install(factory)


def test_install_refuses_async_sessions(engine: Engine) -> None:
    audit = AuditTrail(engine, events=[])

    class AppAsyncSession(AsyncSession):
        pass

    for factory in (async_sessionmaker(), AppAsyncSession):
        with pytest.raises(TypeError, match="async sessions are not supported yet"):
            audit.install(factory)  # type: ignore[arg-type]


def test_install_twice_is_refused(engine: Engine) -> None:
    class AppSession(Session):
        pass

    class SubSession(AppSession):
        pass

    class BaseOfAppSession(Session):
        pass

    audit = AuditTrail(engine, events=[])
    audit.install(AppSession)
    for cls in (AppSession, SubSession):
        with pytest.raises(ValueError, match=r"already installed on \S*AppSession;"):
            AuditTrail(engine, events=[]).install(cls)
    with pytest.raises(ValueError, match="already installed"):
        audit.install(sessionmaker(engine, class_=AppSession))
    # A sibling is independent.
    AuditTrail(engine, events=[]).install(BaseOfAppSession)
    assert installed_trail(SubSession()) is audit


@dataclass
class _Tracked:
    Owner: Any
    Tag: Any
    registry: registry

    def records_changes(self) -> bool:
        owner = self.Owner(id=1)
        owner.tags.append(self.Tag(id=2))
        changes = pop_relationship_changes(owner)
        return changes == {"tags": {"added": ["2"], "removed": []}}


def _tracked_model(name: str, track: str = "tags") -> _Tracked:
    class Base(DeclarativeBase):
        pass

    association = Table(
        f"{name}_tags",
        Base.metadata,
        Column("owner_id", ForeignKey(f"{name}.id"), primary_key=True),
        Column("tag_id", ForeignKey(f"{name}_tag.id"), primary_key=True),
    )

    class Tag(Base):
        __tablename__ = f"{name}_tag"
        id: Mapped[int] = mapped_column(primary_key=True)

    class Owner(Base, Audited):
        __tablename__ = name
        id: Mapped[int] = mapped_column(primary_key=True)
        tags: Mapped[list[Tag]] = relationship(secondary=association)
        __audit__ = AuditOptions(track_relationships={track})

    return _Tracked(Owner, Tag, Base.registry)


def test_install_tracks_relationships_before_and_after_configuration(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Start from a process where install() never ran.
    if listener._tracking_registered:
        sa_event.remove(Audited, "mapper_configured", listener._track_model)
    monkeypatch.setattr(listener, "_tracking_registered", False)

    early = _tracked_model("early")
    early.registry.configure()
    assert not early.records_changes()

    AuditTrail(engine, events=[]).install(sessionmaker(engine))
    assert early.records_changes()  # configured before install
    late = _tracked_model("late")
    late.registry.configure()
    assert late.records_changes()  # configured after install


def test_track_relationships_must_name_a_relationship(engine: Engine) -> None:
    AuditTrail(engine, events=[]).install(sessionmaker(engine))
    broken = _tracked_model("broken", track="missing")
    try:
        with pytest.raises(ValueError, match="'missing', which is not a relationship"):
            broken.registry.configure()
    finally:
        broken.registry.dispose()  # a failed mapper breaks later configuration
