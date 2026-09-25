from __future__ import annotations

import subprocess
import sys
from enum import Enum, IntEnum

import pytest
from pydantic import BaseModel, ValidationError

from audit_trail import events as events_module
from audit_trail.config import AuditOptions
from audit_trail.events import (
    AuditEvent,
    AuditSystem,
    Crud,
    EventRegistry,
    EventRegistryError,
    PayloadError,
    Severity,
    UnknownEventError,
    WriteFlags,
    event,
    resolve_write_flags,
    validate_payload,
)
from tests.unit.discovery_support import isolate_discovery

BUILTIN_VERBS = {"entity.created", "entity.updated", "entity.deleted", "audit.scrubbed"}


class HostSeverity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class OrderPlaced(BaseModel):
    order_id: int
    total: str


class Other(BaseModel):
    note: str


def test_member_carries_metadata() -> None:
    class Shop(AuditEvent):
        PLACED = "shop.order_placed", Severity.INFO, OrderPlaced
        REFUND_DENIED = event("shop.refund_denied", Severity.WARNING, durable=True)
        CARD_VIEWED = event("shop.card_viewed", Severity.CRITICAL, fail_closed=True)

    placed = Shop.PLACED
    assert (placed.severity, placed.schema) == (Severity.INFO, OrderPlaced)
    assert (placed.durable, placed.fail_closed) == (False, False)
    assert (Shop.REFUND_DENIED.durable, Shop.REFUND_DENIED.fail_closed) == (True, False)
    assert (Shop.CARD_VIEWED.durable, Shop.CARD_VIEWED.fail_closed) == (True, True)

    assert placed == "shop.order_placed"
    assert str(placed) == f"{placed}" == "shop.order_placed"


def test_event_helper_passes_every_field() -> None:
    assert event("shop.x", Severity.INFO) == (
        "shop.x",
        Severity.INFO,
        None,
        False,
        False,
    )
    assert event(
        "shop.x", Severity.INFO, OrderPlaced, durable=True, fail_closed=True
    ) == ("shop.x", Severity.INFO, OrderPlaced, True, True)


def test_default_severity_levels() -> None:
    assert [(s.name, s.value) for s in Severity] == [
        ("INFO", 10),
        ("NOTICE", 20),
        ("WARNING", 30),
        ("CRITICAL", 40),
    ]


def test_builtin_events() -> None:
    assert [e.value for e in Crud] == [
        "entity.created",
        "entity.updated",
        "entity.deleted",
    ]
    assert all(e.severity is None and not e.durable for e in Crud)
    scrubbed = AuditSystem.SCRUBBED
    assert scrubbed == "audit.scrubbed"
    assert (scrubbed.severity, scrubbed.durable, scrubbed.fail_closed) == (
        None,
        True,
        False,
    )


def test_registry_discovers_subclasses(monkeypatch: pytest.MonkeyPatch) -> None:
    isolate_discovery(monkeypatch)

    class ShopBase(AuditEvent):
        pass

    class Shop(ShopBase):
        PLACED = "shop.order_placed", Severity.INFO

    assert events_module._discover() == [Shop]
    registry = EventRegistry(Severity)

    assert registry.get("shop.order_placed") is Shop.PLACED
    assert set(registry.events) >= BUILTIN_VERBS


def test_registry_events_restricts_classes() -> None:
    class Shop(AuditEvent):
        PLACED = "shop.order_placed", Severity.INFO

    assert set(EventRegistry(Severity, events=[]).events) == BUILTIN_VERBS
    assert set(EventRegistry(Severity, events=[Shop, Crud]).events) == BUILTIN_VERBS | {
        "shop.order_placed"
    }


def test_duplicate_verb_across_classes_is_rejected() -> None:
    class Shop(AuditEvent):
        PLACED = "shop.order_placed", Severity.INFO

    class Legacy(AuditEvent):
        ORDER = "shop.order_placed", Severity.WARNING

    with pytest.raises(
        EventRegistryError, match=r"both Shop\.PLACED and Legacy\.ORDER"
    ):
        EventRegistry(Severity, events=[Shop, Legacy])


def test_duplicate_verb_within_class_is_rejected() -> None:
    class Shop(AuditEvent):
        PLACED = "shop.order_placed", Severity.INFO
        PLACED_AGAIN = "shop.order_placed", Severity.CRITICAL

    with pytest.raises(EventRegistryError, match=r"Shop\.PLACED_AGAIN repeats"):
        EventRegistry(Severity, events=[Shop])


def test_severity_outside_enum_is_rejected() -> None:
    class Shop(AuditEvent):
        PLACED = "shop.order_placed", Severity.INFO

    class Raw(AuditEvent):
        PLAIN_INT = "raw.plain_int", 1

    with pytest.raises(EventRegistryError, match=r"Shop\.PLACED .*HostSeverity"):
        EventRegistry(HostSeverity, events=[Shop])
    with pytest.raises(EventRegistryError, match=r"Raw\.PLAIN_INT"):
        EventRegistry(HostSeverity, events=[Raw])


@pytest.mark.parametrize("verb", ["entity.archived", "audit.exported"])
def test_reserved_prefix_is_rejected(verb: str) -> None:
    class Shop(AuditEvent):
        SNEAKY = verb, Severity.INFO

    with pytest.raises(EventRegistryError, match="reserved prefix"):
        EventRegistry(Severity, events=[Shop])


def test_host_event_needs_severity() -> None:
    class Shop(AuditEvent):
        PLACED = "shop.order_placed", None

    with pytest.raises(EventRegistryError, match=r"Shop\.PLACED has no severity"):
        EventRegistry(Severity, events=[Shop])


def test_schema_must_be_pydantic_model() -> None:
    class NotAModel:
        pass

    class Shop(AuditEvent):
        PLACED = "shop.order_placed", Severity.INFO, NotAModel

    with pytest.raises(EventRegistryError, match="not a pydantic BaseModel"):
        EventRegistry(Severity, events=[Shop])


def test_host_severity_enum_works_without_default_severity() -> None:
    class Shop(AuditEvent):
        PLACED = "shop.order_placed", HostSeverity.MEDIUM

    registry = EventRegistry(HostSeverity, events=[Shop])

    assert registry.default_severity is HostSeverity.LOW
    assert registry.system_severity is HostSeverity.CRITICAL
    assert registry.severity_of(Shop.PLACED) is HostSeverity.MEDIUM
    assert registry.severity_of(Crud.CREATED) is HostSeverity.LOW
    assert registry.severity_of(AuditSystem.SCRUBBED) is HostSeverity.CRITICAL


def test_default_and_system_severity_can_be_set() -> None:
    registry = EventRegistry(
        HostSeverity,
        events=[],
        default_severity=HostSeverity.MEDIUM,
        system_severity=HostSeverity.HIGH,
    )

    assert registry.severity_of(Crud.UPDATED) is HostSeverity.MEDIUM
    assert registry.severity_of("audit.scrubbed") is HostSeverity.HIGH


@pytest.mark.parametrize("setting", ["default_severity", "system_severity"])
def test_default_and_system_severity_must_be_in_enum(setting: str) -> None:
    with pytest.raises(EventRegistryError, match=setting):
        EventRegistry(HostSeverity, events=[], **{setting: Severity.INFO})


def test_severities_must_be_int_enum() -> None:
    class Plain(Enum):
        LOW = "low"

    with pytest.raises(EventRegistryError, match="IntEnum subclass"):
        EventRegistry(Plain, events=[])  # type: ignore[arg-type]


def test_empty_severity_enum_is_rejected() -> None:
    class Empty(IntEnum):
        pass

    with pytest.raises(EventRegistryError, match="no members"):
        EventRegistry(Empty, events=[])


def test_crud_severity_follows_audit_options() -> None:
    class Shop(AuditEvent):
        PLACED = "shop.order_placed", HostSeverity.MEDIUM

    registry = EventRegistry(HostSeverity, events=[Shop])
    options = AuditOptions(
        severity=HostSeverity.HIGH,
        verb_severity={"entity.deleted": HostSeverity.CRITICAL},
    )
    only_deleted = AuditOptions(verb_severity={"entity.deleted": HostSeverity.HIGH})

    assert registry.severity_of(Crud.CREATED, options) is HostSeverity.HIGH
    assert registry.severity_of(Crud.DELETED, options) is HostSeverity.CRITICAL
    assert registry.severity_of(Crud.UPDATED, only_deleted) is HostSeverity.LOW
    assert registry.severity_of(Crud.DELETED, only_deleted) is HostSeverity.HIGH
    assert registry.severity_of(Shop.PLACED, options) is HostSeverity.MEDIUM


def test_crud_severity_override_must_be_in_enum() -> None:
    registry = EventRegistry(HostSeverity, events=[])

    with pytest.raises(EventRegistryError, match=r"entity\.created"):
        registry.severity_of(Crud.CREATED, AuditOptions(severity=Severity.CRITICAL))


def test_severity_of_unknown_event() -> None:
    class Shop(AuditEvent):
        PLACED = "shop.order_placed", Severity.INFO

    class Legacy(AuditEvent):
        ORDER = "shop.order_placed", Severity.WARNING

    with pytest.raises(UnknownEventError, match=r"shop\.order_placed"):
        EventRegistry(Severity, events=[]).severity_of("shop.order_placed")
    with pytest.raises(UnknownEventError, match=r"Shop\.PLACED is not registered"):
        EventRegistry(Severity, events=[Legacy]).severity_of(Shop.PLACED)


def test_payload_without_schema() -> None:
    class Shop(AuditEvent):
        NOTE = "shop.note", Severity.INFO

    payload = {"text": "hi"}
    result = validate_payload(Shop.NOTE, payload)

    assert result == payload
    assert result is not payload
    assert validate_payload(Shop.NOTE, None) is None
    with pytest.raises(PayloadError, match="must be a mapping"):
        validate_payload(Shop.NOTE, Other(note="x"))


def test_payload_with_schema() -> None:
    class Shop(AuditEvent):
        PLACED = "shop.order_placed", Severity.INFO, OrderPlaced

    model = OrderPlaced(order_id=1, total="9.99")

    assert validate_payload(Shop.PLACED, model) is model
    assert validate_payload(Shop.PLACED, {"order_id": 2, "total": "5"}) == OrderPlaced(
        order_id=2, total="5"
    )
    with pytest.raises(PayloadError, match=r"Shop\.PLACED") as excinfo:
        validate_payload(Shop.PLACED, {"order_id": "not a number"})
    assert isinstance(excinfo.value.__cause__, ValidationError)
    with pytest.raises(PayloadError, match="got Other"):
        validate_payload(Shop.PLACED, Other(note="x"))
    with pytest.raises(
        PayloadError, match="needs a payload of type OrderPlaced, got NoneType"
    ):
        validate_payload(Shop.PLACED, None)


@pytest.mark.parametrize(
    ("durable", "fail_closed", "override", "expected"),
    [
        (False, False, None, WriteFlags(durable=False, fail_closed=False)),
        (False, False, True, WriteFlags(durable=True, fail_closed=False)),
        (True, False, None, WriteFlags(durable=True, fail_closed=False)),
        (True, False, False, WriteFlags(durable=False, fail_closed=False)),
        (False, True, None, WriteFlags(durable=True, fail_closed=True)),
        (False, True, True, WriteFlags(durable=True, fail_closed=True)),
    ],
)
def test_resolve_write_flags(
    durable: bool, fail_closed: bool, override: bool | None, expected: WriteFlags
) -> None:
    class Shop(AuditEvent):
        EVENT = event(
            "shop.event", Severity.INFO, durable=durable, fail_closed=fail_closed
        )

    assert resolve_write_flags(Shop.EVENT, override) == expected


def test_durable_override_cannot_weaken_fail_closed() -> None:
    class Shop(AuditEvent):
        CARD_VIEWED = event("shop.card_viewed", Severity.CRITICAL, fail_closed=True)

    with pytest.raises(ValueError, match="fail_closed"):
        resolve_write_flags(Shop.CARD_VIEWED, durable=False)


def test_import_does_not_load_pydantic() -> None:
    # pydantic is an optional extra: only events with a schema may need it.
    code = (
        "import sys, audit_trail, audit_trail.events;"
        " sys.exit('pydantic' in sys.modules)"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


def test_events_work_without_pydantic(monkeypatch: pytest.MonkeyPatch) -> None:
    class Shop(AuditEvent):
        NOTE = "shop.note", Severity.INFO

    class Typed(AuditEvent):
        PLACED = "typed.order_placed", Severity.INFO, OrderPlaced

    monkeypatch.setitem(sys.modules, "pydantic", None)

    registry = EventRegistry(Severity, events=[Shop])
    assert registry.severity_of(Shop.NOTE) is Severity.INFO
    assert validate_payload(Shop.NOTE, {"text": "hi"}) == {"text": "hi"}
    with pytest.raises(EventRegistryError, match=r"Typed\.PLACED .*need pydantic"):
        EventRegistry(Severity, events=[Typed])
    with pytest.raises(PayloadError, match="need pydantic"):
        validate_payload(Typed.PLACED, {"order_id": 1, "total": "1"})
