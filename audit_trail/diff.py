"""Entity change sets and per-column field policies.

Everything here reads the in-memory state of ORM instances and never emits
SQL, so it is safe to call from ``after_flush`` (also under ``AsyncSession``).

A column's policy is set where the column is defined::

    hook_secret: Mapped[str] = mapped_column(info={"audit": "redact"})
    email: Mapped[str] = mapped_column(info={"audit": "hash"})
    embeddings: Mapped[bytes] = mapped_column(info={"audit": "exclude"})
"""

from __future__ import annotations

import functools
import json
import logging
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Literal, TypeAlias, cast

from sqlalchemy import Column, inspect
from sqlalchemy.orm import ColumnProperty
from sqlalchemy.orm.attributes import instance_state
from sqlalchemy.orm.base import NO_VALUE

from audit_trail._typing import assert_never
from audit_trail.config import AuditOptions
from audit_trail.serialization import JSONValue, KeyRing, encode_value, hash_value

if TYPE_CHECKING:
    from sqlalchemy.orm import InstanceState, Mapper

logger = logging.getLogger(__name__)

FieldPolicy: TypeAlias = Literal["exclude", "redact", "hash"]
"""Policy of one column, from ``mapped_column(info={"audit": ...})``."""

ChangeKind: TypeAlias = Literal["created", "updated", "deleted"]
"""Which change set to build: a new, a modified or a deleted instance."""

Changes: TypeAlias = dict[str, list[JSONValue]]
"""``{attribute key: [old, new]}`` with JSON-ready values."""

REDACTED = "***"
"""Stored in place of a non-null value of a ``redact`` column."""

UNKNOWN = "<unknown>"
"""Marker stored where a value is not available without SQL."""

SNAPSHOT_INFO_KEY = "audit_trail.snapshot"
"""``InstanceState.info`` key holding the ``snapshot_on_load`` copies."""

_POLICIES: dict[str, FieldPolicy] = {
    "exclude": "exclude",
    "redact": "redact",
    "hash": "hash",
}

_ValuePolicy: TypeAlias = Literal["redact", "hash"]


class FieldPolicyError(ValueError):
    """A column's audit policy is invalid or cannot be applied."""


class AuditOptionError(TypeError):
    """An audit option (``label``, ``scope``, ``target``) is misconfigured."""


class UseContext(Enum):
    """Result of :func:`resolve_scope` meaning "take the scope from context"."""

    USE_CONTEXT = "use_context"


USE_CONTEXT = UseContext.USE_CONTEXT


class _Missing(Enum):
    VALUE = "missing"


_MISSING = _Missing.VALUE


@dataclass(frozen=True)
class _AuditedColumn:
    key: str
    column: Column[Any]
    policy: _ValuePolicy | None


def options_of(model: type[Any]) -> AuditOptions:
    """Return the model's ``__audit__`` options, or the defaults.

    Args:
        model: A mapped class.

    Returns:
        The model's ``AuditOptions``.
    """
    options = getattr(model, "__audit__", None)
    return options if isinstance(options, AuditOptions) else AuditOptions()


def object_type_of(obj: object) -> str:
    """Return the ``object_type`` of an instance.

    Args:
        obj: A mapped instance.

    Returns:
        ``AuditOptions.object_type``, or the class name when it is not set.
    """
    cls = type(obj)
    return options_of(cls).object_type or cls.__name__


def field_policy(model: type[Any], key: str, column: Column[Any]) -> FieldPolicy | None:
    """Return the audit policy set on a column.

    Args:
        model: The mapped class, named in the error message.
        key: The column's attribute key, named in the error message.
        column: The column.

    Returns:
        The policy, or ``None`` when the column has none.

    Raises:
        FieldPolicyError: ``info["audit"]`` is not a known policy.
    """
    raw = column.info.get("audit")
    if raw is None:
        return None
    policy = _POLICIES.get(raw) if isinstance(raw, str) else None
    if policy is None:
        raise FieldPolicyError(
            f"{model.__qualname__}.{key}: unknown audit policy {raw!r}; "
            f"expected one of {', '.join(map(repr, _POLICIES))}"
        )
    return policy


def _audited_columns(
    mapper: Mapper[Any], global_redact: frozenset[str] = frozenset()
) -> list[_AuditedColumn]:
    result = []
    for prop in mapper.column_attrs:
        column = prop.columns[0]
        if not isinstance(column, Column):
            continue  # column_property() over an SQL expression
        policy = field_policy(mapper.class_, prop.key, column)
        match policy:
            case "exclude":
                continue
            case None:
                redact = prop.key in global_redact or column.name in global_redact
                result.append(
                    _AuditedColumn(prop.key, column, "redact" if redact else None)
                )
            case "redact" | "hash":
                result.append(_AuditedColumn(prop.key, column, policy))
            case _:
                assert_never(policy)
    return result


def entity_changes(
    obj: object,
    kind: ChangeKind,
    *,
    keys: KeyRing | None = None,
    json_encoder: type[json.JSONEncoder] | None = None,
    global_redact: Collection[str] = (),
) -> Changes:
    """Build the ``changes`` of an ``entity.*`` entry from an instance.

    Meant for ``after_flush``, while ``session.new`` / ``dirty`` / ``deleted``
    and attribute history still describe the flush. Reads only what is in
    memory and never emits SQL.

    - ``created``: every audited column as ``[None, value]``, empty ones too.
    - ``updated``: only columns with a net change. Old and new raw values are
      compared with ``column.type.compare_values`` before any redaction or
      encoding, so ``Decimal("1.5")`` vs ``Decimal("1.50")`` is no change.
      An empty result means there is nothing to record.
    - ``deleted``: every audited column as ``[value, None]``.

    ``exclude`` columns are left out. ``redact`` stores ``"***"`` and
    ``hash`` stores ``hv{n}:<hex>``; both keep null as null. Every other value
    goes through ``encode_value``.

    ``"<unknown>"`` is a marker, not a value: it stands where the value is not
    in memory. That is the old value of a JSON column changed in place
    (``MutableDict``) without ``snapshot_on_load``, a ``deleted`` column that
    is not loaded (for example ``deferred``), and a ``created`` column filled
    by a server-side default (``server_default``, ``Computed``, ``Identity``)
    that was not fetched back. Set ``eager_defaults=True`` on the mapper to
    get real server defaults in ``created`` entries. A ``created`` column that
    was not set and has no server-side default is ``None``, as stored.

    Args:
        obj: A mapped instance.
        kind: Which change set to build.
        keys: Key ring for ``hash`` columns.
        json_encoder: Host encoder for types ``encode_value`` does not handle.
        global_redact: Attribute keys or column names redacted when the column
            has no explicit policy. An extra safety net, not a replacement for
            per-column policies.

    Returns:
        ``{attribute key: [old, new]}`` with JSON-ready values.

    Raises:
        FieldPolicyError: A column has an unknown policy, or the model has a
            ``hash`` column and ``keys`` is ``None``.
        UnserializableValueError: A value cannot be encoded.
    """
    state = instance_state(obj)
    columns = _audited_columns(state.mapper, frozenset(global_redact))
    if keys is None:
        for spec in columns:
            if spec.policy == "hash":
                raise FieldPolicyError(
                    f"{state.class_.__qualname__}.{spec.key}: the hash policy "
                    "needs a key ring (pseudonymize_key)"
                )

    def render(value: object, spec: _AuditedColumn) -> JSONValue:
        return _render(value, spec.policy, keys, json_encoder)

    changes: Changes = {}
    match kind:
        case "created":
            for spec in columns:
                new = state.dict.get(spec.key, _MISSING)
                if new is _MISSING and spec.column.server_default is None:
                    # Identity and Computed also live in server_default.
                    new = None
                changes[spec.key] = [None, render(new, spec)]
        case "deleted":
            for spec in columns:
                old = state.dict.get(spec.key, _MISSING)
                changes[spec.key] = [render(old, spec), None]
        case "updated":
            snapshot: dict[str, object] = state.info.get(SNAPSHOT_INFO_KEY, {})
            for spec in columns:
                history = state.attrs[spec.key].history
                if not history.added and not history.deleted:
                    continue
                new = history.added[0] if history.added else None
                if history.deleted:
                    old = history.deleted[0]
                else:
                    # Changed in place (MutableDict): the committed value is
                    # gone unless snapshot_on_load kept a copy.
                    old = snapshot.get(spec.key, _MISSING)
                if old is not _MISSING and spec.column.type.compare_values(old, new):
                    continue
                changes[spec.key] = [render(old, spec), render(new, spec)]
        case _:
            assert_never(kind)
    return changes


def _render(
    value: object,
    policy: _ValuePolicy | None,
    keys: KeyRing | None,
    json_encoder: type[json.JSONEncoder] | None,
) -> JSONValue:
    if value is _MISSING:
        return UNKNOWN
    match policy:
        case None:
            return encode_value(value, json_encoder=json_encoder)
        case "redact":
            return None if value is None else REDACTED
        case "hash":
            if value is None:
                return None
            assert keys is not None  # entity_changes checks this up front
            return hash_value(value, keys=keys, json_encoder=json_encoder)
        case _:
            assert_never(policy)


def object_id_of(obj: object) -> str:
    """Return the ``object_id`` of an instance.

    Uses the identity key when the instance has one. Inside ``after_flush``
    that is still the key from before the flush, so a changed primary key
    yields the old id. Objects inserted by the flush have no identity key yet;
    their primary key is read from the instance.

    Args:
        obj: A mapped instance.

    Returns:
        ``str(pk)`` for a single-column key (a UUID in canonical lowercase
        form), a compact JSON array of strings (``["a","1"]``) for a
        composite one.

    Raises:
        ValueError: The instance has no primary key value yet.
    """
    object_id = state_object_id(instance_state(obj))
    if object_id is None:
        raise ValueError(f"{type(obj).__qualname__} instance has no primary key yet")
    return object_id


def state_object_id(state: InstanceState[Any]) -> str | None:
    """Return the ``object_id`` of an instance state, as :func:`object_id_of`.

    Args:
        state: The state of a mapped instance.

    Returns:
        The id, or ``None`` when the instance has no primary key value yet.
    """
    if state.key is not None:
        return _format_identity(state.key[1])
    mapper = state.mapper
    values = tuple(
        state.dict.get(mapper.get_property_by_column(column).key)
        for column in mapper.primary_key
    )
    if any(value is None for value in values):
        return None
    return _format_identity(values)


def object_id_for(model: type[Any], pk: object) -> str:
    """Return the ``object_id`` for a primary key of ``model``.

    Args:
        model: A mapped class.
        pk: The key value, or a tuple of values in primary key column order
            for a composite key.

    Returns:
        The same string ``object_id_of`` returns for that instance.

    Raises:
        ValueError: The number of values does not match the primary key, or
            a value is ``None``.
    """
    mapper: Mapper[Any] = inspect(model)
    values = pk if isinstance(pk, tuple) else (pk,)
    if len(values) != len(mapper.primary_key):
        raise ValueError(
            f"{model.__qualname__} has a {len(mapper.primary_key)}-column primary "
            f"key, got {len(values)} value(s)"
        )
    if any(value is None for value in values):
        raise ValueError(f"primary key of {model.__qualname__} contains None")
    return _format_identity(values)


def _format_identity(values: Sequence[object]) -> str:
    if len(values) == 1:
        return str(values[0])
    return json.dumps([str(value) for value in values], separators=(",", ":"))


class _UnloadedAttributeError(Exception):
    """Internal signal: an option read an attribute that is not loaded."""

    def __init__(self, model: type[Any], attribute: str) -> None:
        super().__init__(f"{model.__qualname__}.{attribute} is not loaded")
        self.model = model
        self.attribute = attribute


class _CachedPropertyError(Exception):
    """Internal: an option read a ``functools.cached_property``."""

    def __init__(self, model: type[Any], attribute: str) -> None:
        super().__init__(f"{model.__qualname__}.{attribute} is a cached_property")
        self.model = model
        self.attribute = attribute


class _LoadedOnly:
    """Read-only view of an instance that never loads anything.

    Mapped attributes come from the instance's loaded state; one that would
    need SQL raises ``_UnloadedAttributeError``. A column never set on an
    instance without an identity yet is ``None``, unless it has a server-side
    default. Properties, hybrids and
    methods of the class run with the view as ``self``, so they cannot load
    through the real instance either; so do ``__repr__`` and ``__str__``.
    Loaded related instances are wrapped, also inside collections.
    ``functools.cached_property`` is refused: it would have to store its
    result on the view.
    """

    __slots__ = ("_audit_obj", "_audit_state")
    _audit_obj: object
    _audit_state: InstanceState[Any]

    def __init__(self, obj: object) -> None:
        object.__setattr__(self, "_audit_obj", obj)
        object.__setattr__(self, "_audit_state", instance_state(obj))

    def __getattr__(self, name: str) -> Any:
        obj = self._audit_obj
        state = self._audit_state
        cls = type(obj)
        if name in state.manager:
            value = state.dict.get(name, NO_VALUE)
            if value is NO_VALUE:
                if _unset_is_null(state, name):
                    return None
                raise _UnloadedAttributeError(cls, name)
            return _wrap_related(state.mapper, name, value)
        instance_dict: dict[str, Any] = getattr(obj, "__dict__", {})
        for klass in cls.__mro__:
            if name in vars(klass):
                attr = vars(klass)[name]
                break
        else:
            if name in instance_dict:
                return instance_dict[name]
            raise AttributeError(
                f"{cls.__qualname__!r} object has no attribute {name!r}"
            )
        descriptor = type(attr)
        is_data_descriptor = hasattr(descriptor, "__set__") or hasattr(
            descriptor, "__delete__"
        )
        if not is_data_descriptor and name in instance_dict:
            return instance_dict[name]
        if isinstance(attr, functools.cached_property):
            raise _CachedPropertyError(cls, name)
        if hasattr(descriptor, "__get__"):
            return attr.__get__(self, cls)
        return attr

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("audit options must not modify the instance")

    def __repr__(self) -> str:
        obj = self._audit_obj
        cls: type[object] = type(obj)
        method: Callable[[object], str] = cls.__repr__
        if method is object.__repr__:
            return object.__repr__(obj)
        return str(method(self))

    def __str__(self) -> str:
        cls: type[object] = type(self._audit_obj)
        method: Callable[[object], str] = cls.__str__
        if method is object.__str__:
            # object.__str__ defers to __repr__, which applies the same rules.
            return self.__repr__()
        return str(method(self))


def _unset_is_null(state: InstanceState[Any], key: str) -> bool:
    # A column never set on an instance that has no identity yet (new, or
    # inserted by the flush being audited) is NULL in the row, as in
    # entity_changes' "created" set, unless the database fills it in.
    if state.key is not None:
        return False
    prop = state.mapper.get_property(key)
    return isinstance(prop, ColumnProperty) and all(
        isinstance(column, Column) and column.server_default is None
        for column in prop.columns
    )


def _wrap_related(mapper: Mapper[Any], name: str, value: object) -> object:
    if name not in mapper.relationships or value is None:
        return value
    if isinstance(value, Mapping):
        return {key: _LoadedOnly(item) for key, item in value.items()}
    if mapper.relationships[name].uselist:
        return [_LoadedOnly(item) for item in cast(Iterable[object], value)]
    return _LoadedOnly(value)


_OptionName: TypeAlias = Literal["label", "scope", "target"]

# (model, attribute, option) already reported, so a misconfigured option on a
# busy model logs once per process instead of once per flush.
_warned: set[tuple[type[Any], str, _OptionName]] = set()


def _call_option(
    obj: object, option: _OptionName, fn: Callable[[Any], Any]
) -> tuple[bool, Any]:
    try:
        return True, fn(_LoadedOnly(obj))
    except _UnloadedAttributeError as exc:
        key = (exc.model, exc.attribute, option)
        if key not in _warned:
            _warned.add(key)
            logger.warning(
                "AuditOptions.%s of %s read %r, which is not loaded; using the "
                "fallback. Options may only read attributes already loaded on "
                "the instance. Logged once per process.",
                option,
                exc.model.__qualname__,
                exc.attribute,
            )
        return False, None
    except _CachedPropertyError as exc:
        raise AuditOptionError(
            f"AuditOptions.{option} of {exc.model.__qualname__} read "
            f"{exc.attribute!r}: cached_property is not supported in audit "
            "options; read the underlying column"
        ) from None


def resolve_label(obj: object, options: AuditOptions) -> str | None:
    """Evaluate ``options.label`` for ``object_label`` without emitting SQL.

    Args:
        obj: A mapped instance.
        options: The model's options.

    Returns:
        The label as a string, or ``None`` when there is no ``label`` option,
        it returns ``None``, or it read an attribute that is not loaded (then
        logged once per model, attribute and option on the
        ``audit_trail.diff`` logger).

    Raises:
        AuditOptionError: The option read a ``functools.cached_property``.
    """
    if options.label is None:
        return None
    ok, value = _call_option(obj, "label", options.label)
    return str(value) if ok and value is not None else None


def resolve_scope(obj: object, options: AuditOptions) -> str | None | UseContext:
    """Evaluate ``options.scope`` for ``scope_id`` without emitting SQL.

    Args:
        obj: A mapped instance.
        options: The model's options.

    Returns:
        ``USE_CONTEXT`` when there is no ``scope`` option or it read an
        attribute that is not loaded (then logged once per model, attribute
        and option on the ``audit_trail.diff`` logger). Otherwise ``None``
        when the option returned ``None`` (an explicit "no scope"), else the
        value as a string.

    Raises:
        AuditOptionError: The option read a ``functools.cached_property``.
    """
    if options.scope is None:
        return USE_CONTEXT
    ok, value = _call_option(obj, "scope", options.scope)
    if not ok:
        return USE_CONTEXT
    return None if value is None else str(value)


def resolve_target(obj: object, options: AuditOptions) -> tuple[str, str] | None:
    """Evaluate ``options.target`` for ``target_type``/``target_id``.

    Never emits SQL. The id is formatted like ``object_id``: a tuple becomes
    a composite id, anything else ``str()``.

    Args:
        obj: A mapped instance.
        options: The model's options.

    Returns:
        ``(target_type, target_id)``, or ``None`` when there is no ``target``
        option, it returns ``None`` or an id of ``None``, or it read an
        attribute that is not loaded (then logged once per model, attribute
        and option on the ``audit_trail.diff`` logger).

    Raises:
        AuditOptionError: The option read a ``functools.cached_property``.
    """
    if options.target is None:
        return None
    ok, value = _call_option(obj, "target", options.target)
    if not ok or value is None:
        return None
    return format_target(value)


def format_target(target: tuple[str, object]) -> tuple[str, str] | None:
    """Format a ``(type, id)`` pair as stored in ``target_type``/``target_id``.

    Args:
        target: The type name and the id; a tuple id is a composite key.

    Returns:
        ``(target_type, target_id)`` with the id formatted like an
        ``object_id``, or ``None`` when the id is ``None``.
    """
    target_type, target_id = target
    if target_id is None:
        return None
    ids = target_id if isinstance(target_id, tuple) else (target_id,)
    return str(target_type), _format_identity(ids)
