"""Audit events, severities and the event registry."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from enum import Enum, IntEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from pydantic import BaseModel
    from typing_extensions import Self

    from audit_trail.config import AuditOptions

RESERVED_PREFIXES: tuple[str, ...] = ("entity.", "audit.")
"""Verb prefixes reserved for the library's built-in events."""


class Severity(IntEnum):
    """Default severity levels, used when the host does not configure its own."""

    INFO = 10
    NOTICE = 20
    WARNING = 30
    CRITICAL = 40


def event(
    value: str,
    severity: IntEnum | None,
    schema: type[BaseModel] | None = None,
    *,
    durable: bool = False,
    fail_closed: bool = False,
) -> tuple[str, IntEnum | None, type[BaseModel] | None, bool, bool]:
    """Build an ``AuditEvent`` member value with the flags named.

    Enum passes a member's value to ``__new__`` positionally, so this helper
    exists to keep member definitions readable.

    Args:
        value: The verb, ``domain.action`` in snake_case.
        severity: Member of the configured severity enum.
        schema: Pydantic model that validates the payload.
        durable: Write on a separate connection and commit immediately.
        fail_closed: Commit the entry before data is returned and raise on a
            write failure. Implies ``durable``.

    Returns:
        The member value: the positional arguments of ``AuditEvent.__new__``.
    """
    return (value, severity, schema, durable, fail_closed)


class AuditEvent(str, Enum):
    """Base class for audit events. It has no members, so it can be subclassed.

    Each member is a verb carrying its metadata, built with ``event``:

    ```python
    class ShopEvent(AuditEvent):
        ORDER_PLACED = event("shop.order_placed", MySeverity.LOW, OrderPlaced)
        REFUND_DENIED = event("shop.refund_denied", MySeverity.HIGH, durable=True)
    ```

    Members compare equal to their verb string, and ``str()`` returns the verb.
    Type checkers reject calling the class with a verb (``ShopEvent("...")``)
    because of the custom ``__new__``; look verbs up with
    ``EventRegistry.get`` instead.

    Attributes:
        severity: Member of the configured severity enum. ``None`` only on
            library built-ins, whose severity comes from configuration (see
            ``EventRegistry.severity_of``).
        schema: Pydantic model that validates the payload, or ``None`` for a
            free-form mapping.
        durable: Written on a separate connection and committed immediately,
            whatever happens to the caller's transaction.
        fail_closed: The entry is committed before data is returned; a write
            failure always raises. Implies ``durable``.
    """

    _value_: str
    severity: IntEnum | None
    schema: type[BaseModel] | None
    durable: bool
    fail_closed: bool

    def __new__(
        cls,
        value: str,
        severity: IntEnum | None,
        schema: type[BaseModel] | None = None,
        durable: bool = False,
        fail_closed: bool = False,
    ) -> Self:
        """Create a member from its verb and metadata.

        Args:
            value: The verb, ``domain.action`` in snake_case.
            severity: Member of the configured severity enum.
            schema: Pydantic model that validates the payload.
            durable: Write on a separate connection and commit immediately.
            fail_closed: Commit the entry before data is returned and raise on
                a write failure. Implies ``durable``.

        Returns:
            The new member.
        """
        obj = str.__new__(cls, value)
        obj._value_ = value
        obj.severity = severity
        obj.schema = schema
        obj.fail_closed = fail_closed
        obj.durable = durable or fail_closed
        return obj

    def __str__(self) -> str:
        return self._value_


class Crud(AuditEvent):
    """Entity changes recorded by the session listener.

    Their severity depends on the model (``AuditOptions``), so it is resolved
    by ``EventRegistry.severity_of`` rather than fixed here.
    """

    CREATED = event("entity.created", None)
    UPDATED = event("entity.updated", None)
    DELETED = event("entity.deleted", None)


class AuditSystem(AuditEvent):
    """Operations of the library itself.

    Their severity is the registry's ``system_severity``.
    """

    SCRUBBED = event("audit.scrubbed", None, durable=True)


_BUILTINS: tuple[type[AuditEvent], ...] = (Crud, AuditSystem)


class EventRegistryError(ValueError):
    """An event definition or a severity setting is invalid."""


class UnknownEventError(LookupError):
    """An event or verb is not registered."""


class PayloadError(ValueError):
    """A payload does not match its event's schema."""


class WriteFlags(NamedTuple):
    """Effective write mode of one entry.

    Attributes:
        durable: Write on a separate connection and commit immediately.
        fail_closed: Raise on a write failure, before data is returned.
    """

    durable: bool
    fail_closed: bool


class EventRegistry:
    """All known events, validated against the configured severity enum.

    Args:
        severities: The host's severity ``IntEnum`` (or ``Severity``).
        events: Event classes to register. ``None`` collects every
            ``AuditEvent`` subclass that has members. The built-ins are
            always registered. Pass the classes explicitly when discovery
            would see a module twice (reloaded, or imported under two names),
            which otherwise fails as a duplicate verb.
        default_severity: Severity of ``entity.*`` entries whose model sets
            none. ``None`` uses the lowest member of ``severities``.
        system_severity: Severity of the library's ``audit.*`` events.
            ``None`` uses the highest member of ``severities``. Retention is
            configured per severity, so the highest level is not necessarily
            the one kept longest; set this when it is not.

    Raises:
        EventRegistryError: ``severities`` is not a non-empty ``IntEnum``,
            a verb is defined twice, a severity is not a
            member of ``severities``, a host event uses a reserved prefix or
            has no severity, or a payload schema is not a pydantic model (or
            pydantic is not installed).
    """

    def __init__(
        self,
        severities: type[IntEnum],
        *,
        events: Iterable[type[AuditEvent]] | None = None,
        default_severity: IntEnum | None = None,
        system_severity: IntEnum | None = None,
    ) -> None:
        if not (isinstance(severities, type) and issubclass(severities, IntEnum)):
            raise EventRegistryError(
                f"severities must be an IntEnum subclass, got {severities!r}"
            )
        if not len(severities):
            raise EventRegistryError(f"{severities.__name__} has no members")
        self.severities = severities
        self.default_severity = (
            min(severities)
            if default_severity is None
            else self._check_severity(default_severity, "default_severity")
        )
        self.system_severity = (
            max(severities)
            if system_severity is None
            else self._check_severity(system_severity, "system_severity")
        )

        classes = _discover() if events is None else list(events)
        classes += [cls for cls in _BUILTINS if cls not in classes]
        by_verb: dict[str, AuditEvent] = {}
        for cls in dict.fromkeys(classes):
            self._register(cls, by_verb)
        self._events = MappingProxyType(by_verb)

    @property
    def events(self) -> Mapping[str, AuditEvent]:
        """Read-only mapping of verb to event."""
        return self._events

    def get(self, verb: str) -> AuditEvent:
        """Return the event registered for ``verb``.

        Args:
            verb: The event's value, e.g. ``"entity.created"``.

        Returns:
            The registered event.

        Raises:
            UnknownEventError: ``verb`` is not registered.
        """
        try:
            return self._events[verb]
        except KeyError:
            raise UnknownEventError(f"Unknown audit event {verb!r}") from None

    def severity_of(
        self, event: AuditEvent | str, options: AuditOptions | None = None
    ) -> IntEnum:
        """Return the severity of an event or verb.

        ``Crud`` events use ``options.verb_severity[verb]``, then
        ``options.severity``, then ``default_severity``. Library events without
        a fixed severity use ``system_severity``. ``options`` is ignored for
        every other event.

        Args:
            event: A registered event or its verb.
            options: The audited model's options, for ``Crud`` events.

        Returns:
            A member of ``severities``.

        Raises:
            UnknownEventError: The event is not registered.
            EventRegistryError: An ``AuditOptions`` severity is not a member of
                ``severities``.
        """
        verb = event.value if isinstance(event, AuditEvent) else event
        member = self.get(verb)
        if isinstance(event, AuditEvent) and member is not event:
            raise UnknownEventError(f"{_label(event)} is not registered")

        if isinstance(member, Crud):
            if options is not None:
                override = options.verb_severity.get(verb, options.severity)
                if override is not None:
                    return self._check_severity(
                        override, f"AuditOptions severity for {verb!r}"
                    )
            return self.default_severity
        if member.severity is None:
            return self.system_severity
        return member.severity

    def _register(self, cls: type[AuditEvent], by_verb: dict[str, AuditEvent]) -> None:
        # Enum turns a repeated value into an alias of the first member, which
        # silently drops the alias's metadata.
        for name, member in cls.__members__.items():
            if member.name != name:
                raise EventRegistryError(
                    f"{cls.__name__}.{name} repeats the value {member.value!r}"
                    f" of {_label(member)}"
                )

        builtin = cls in _BUILTINS
        for member in cls:
            if not builtin and member.value.startswith(RESERVED_PREFIXES):
                raise EventRegistryError(
                    f"{_label(member)} uses a reserved prefix"
                    f" ({', '.join(RESERVED_PREFIXES)}): {member.value!r}"
                )
            if member.severity is None:
                if not builtin:
                    raise EventRegistryError(f"{_label(member)} has no severity")
            else:
                self._check_severity(member.severity, f"severity of {_label(member)}")
            _check_schema(member)
            if member.value in by_verb:
                raise EventRegistryError(
                    f"{member.value!r} is defined by both"
                    f" {_label(by_verb[member.value])} and {_label(member)}"
                )
            by_verb[member.value] = member

    def _check_severity(self, severity: IntEnum, what: str) -> IntEnum:
        if not isinstance(severity, self.severities):
            raise EventRegistryError(
                f"{what} is {severity!r},"
                f" which is not a member of {self.severities.__name__}"
            )
        return severity


def validate_payload(
    event: AuditEvent, payload: Mapping[str, object] | BaseModel | None
) -> dict[str, object] | BaseModel | None:
    """Check a payload against its event's schema.

    Args:
        event: The event being logged.
        payload: A mapping, an instance of ``event.schema``, or ``None``.

    Returns:
        Without a schema, a copy of the mapping (or ``None``). With a schema,
        the validated model instance.

    Raises:
        PayloadError: The payload does not match the schema, is missing while
            a schema is declared, or is not a mapping while none is.
    """
    schema = event.schema
    if schema is None:
        if payload is None:
            return None
        if isinstance(payload, Mapping):
            return dict(payload)
        raise PayloadError(
            f"{_label(event)} has no schema; its payload must be a mapping or"
            f" None, got {type(payload).__name__}"
        )

    if _base_model() is None:
        raise PayloadError(f"{_label(event)} declares a schema; {_PYDANTIC_MISSING}")
    if isinstance(payload, schema):
        return payload
    if not isinstance(payload, Mapping):
        raise PayloadError(
            f"{_label(event)} needs a payload of type {schema.__name__},"
            f" got {type(payload).__name__}"
        )

    from pydantic import ValidationError

    try:
        return schema.model_validate(payload)
    except ValidationError as exc:
        raise PayloadError(f"Invalid payload for {_label(event)}: {exc}") from exc


def resolve_write_flags(event: AuditEvent, durable: bool | None = None) -> WriteFlags:
    """Combine an event's write mode with a per-call ``durable`` override.

    Args:
        event: The event being logged.
        durable: ``None`` keeps the event's setting; a bool overrides it.

    Returns:
        The effective flags.

    Raises:
        ValueError: ``durable=False`` for a ``fail_closed`` event, which would
            weaken it.
    """
    if event.fail_closed:
        if durable is False:
            raise ValueError(
                f"{_label(event)} is fail_closed; durable=False cannot weaken it"
            )
        return WriteFlags(durable=True, fail_closed=True)
    return WriteFlags(
        durable=event.durable if durable is None else durable, fail_closed=False
    )


_PYDANTIC_MISSING = (
    "payload schemas need pydantic: pip install 'sqlalchemy-audit-trail[pydantic]'"
)


def _base_model() -> type[BaseModel] | None:
    # Imported lazily so that hosts without payload schemas never load pydantic.
    try:
        from pydantic import BaseModel
    except ImportError:
        return None
    return BaseModel


def _check_schema(event: AuditEvent) -> None:
    if event.schema is None:
        return
    base_model = _base_model()
    if base_model is None:
        raise EventRegistryError(
            f"{_label(event)} declares a schema; {_PYDANTIC_MISSING}"
        )
    if not (isinstance(event.schema, type) and issubclass(event.schema, base_model)):
        raise EventRegistryError(
            f"Schema of {_label(event)} is {event.schema!r},"
            " which is not a pydantic BaseModel subclass"
        )


def _discover() -> list[type[AuditEvent]]:
    found: list[type[AuditEvent]] = []
    pending = list(AuditEvent.__subclasses__())
    while pending:
        cls = pending.pop(0)
        pending.extend(cls.__subclasses__())
        if cls.__members__:
            found.append(cls)
    return found


def _label(event: AuditEvent) -> str:
    return f"{type(event).__name__}.{event.name}"
