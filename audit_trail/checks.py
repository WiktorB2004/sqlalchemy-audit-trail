"""Static checks of audited models, meant for CI.

``check_models`` inspects the mapped classes of a registry and returns every
problem it finds instead of raising on the first one, so a single CI run
reports all of them, warnings included::

    def test_audited_models() -> None:
        errors = [i for i in check_models(Base) if i.level == "error"]
        assert not errors, "\\n".join(map(str, errors))
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, TypeAlias

from sqlalchemy import Column
from sqlalchemy.ext.mutable import Mutable
from sqlalchemy.orm import registry
from sqlalchemy.types import JSON, TypeDecorator

from audit_trail._typing import assert_never
from audit_trail.config import AuditOptions
from audit_trail.diff import field_policy, options_of
from audit_trail.mixin import Audited
from audit_trail.relations import _tracked, _TrackedAttribute

if TYPE_CHECKING:
    from sqlalchemy.orm import Mapper, RelationshipProperty
    from sqlalchemy.types import TypeEngine

__all__ = ["IssueCode", "IssueLevel", "ModelIssue", "check_models"]

IssueCode: TypeAlias = Literal[
    "sensitive-column",
    "json-in-place",
    "relationship-both-sides",
    "unknown-relationship",
]
"""What a ``ModelIssue`` is about."""

IssueLevel: TypeAlias = Literal["error", "warning"]
"""How serious a ``ModelIssue`` is."""


@dataclass(frozen=True)
class ModelIssue:
    """One problem found by :func:`check_models`.

    Attributes:
        code: What the problem is about.
        model: The mapped class it was found on.
        attribute: The attribute key it concerns.
        message: A human-readable explanation, with the fix.
    """

    code: IssueCode
    model: type[Any]
    attribute: str
    message: str

    @property
    def level(self) -> IssueLevel:
        """``"error"`` for a leak or a corrupt trail, ``"warning"`` otherwise."""
        match self.code:
            case (
                "sensitive-column" | "relationship-both-sides" | "unknown-relationship"
            ):
                return "error"
            case "json-in-place":
                return "warning"
            case _:
                assert_never(self.code)

    def __str__(self) -> str:
        return (
            f"{self.level}: {self.model.__qualname__}.{self.attribute}: "
            f"{self.message} [{self.code}]"
        )


def check_models(
    base: registry | type[Any], *, allow_names: Collection[str] = ()
) -> list[ModelIssue]:
    """Check the audited models of a registry for configuration mistakes.

    Configures the registry's mappers first. Reports:

    - ``sensitive-column`` (error): a column of an ``Audited`` model whose
      attribute key or database column name looks sensitive and that has no
      explicit ``info={"audit": ...}`` policy. A name looks sensitive when it
      contains ``password`` or ``passwd``, has one of the words ``pwd``,
      ``secret(s)``, ``token(s)``, ``credential(s)``, ``apikey`` or
      ``encrypted``, or ends in ``_key``; words are split on ``_`` and
      camelCase. Names given to ``global_redact`` do not count: they are an
      extra safety net, not a decision about the column.
    - ``json-in-place`` (warning): an audited JSON column that is neither
      tracked by ``sqlalchemy.ext.mutable`` nor listed in
      ``AuditOptions.snapshot_on_load``. Its in-place changes
      (``obj.data["a"] = 1``) are not detected. ``Mutable`` detects them but
      leaves the old value unknown; ``snapshot_on_load`` alone keeps the old
      value but only helps when the change is flagged (``flag_modified``).
    - ``relationship-both-sides`` (error): both sides of one relationship
      (``back_populates`` or ``backref``) are tracked, through
      ``AuditOptions.track_relationships`` or ``track_relationships()``;
      every membership change would be recorded twice.
    - ``unknown-relationship`` (error): ``AuditOptions.track_relationships``
      names something that is not a collection relationship of the model
      (a missing name, a column or a scalar relationship).

    Whether a column is ``Mutable`` is found by assigning ``{}`` and ``[]``
    to the attribute of a throwaway instance created without ``__init__``;
    no session and no SQL are involved, but the model's own ``set``
    listeners and validators run.

    Args:
        base: A ``registry``, or a declarative base class that has one.
        allow_names: ``"Model.attribute"`` entries (class ``__qualname__``
            and attribute key) whose names only look sensitive; they are not
            reported as ``sensitive-column``.

    Returns:
        The issues, sorted by model, attribute and code. Empty when there
        are none.

    Raises:
        TypeError: ``base`` is neither a registry nor has one.
        FieldPolicyError: A column has an unknown audit policy.
    """
    reg = _registry_of(base)
    reg.configure()
    allowed = frozenset(allow_names)
    # Base classes first, so an inherited column is reported where it is
    # declared rather than once per subclass.
    mappers = sorted(
        reg.mappers, key=lambda m: (len(m.class_.__mro__), m.class_.__qualname__)
    )
    issues: list[ModelIssue] = []
    seen_columns: set[Column[Any]] = set()
    for mapper in mappers:
        if issubclass(mapper.class_, Audited):
            issues.extend(_check_columns(mapper, allowed, seen_columns))
    issues.extend(_check_relationships(mappers))
    issues.sort(key=lambda i: (i.model.__qualname__, i.attribute, i.code))
    return issues


def _registry_of(base: registry | type[Any]) -> registry:
    if isinstance(base, registry):
        return base
    reg = getattr(base, "registry", None)
    if isinstance(reg, registry):
        return reg
    raise TypeError(f"expected a registry or a declarative base, got {base!r}")


def _check_columns(
    mapper: Mapper[Any], allowed: frozenset[str], seen: set[Column[Any]]
) -> Iterator[ModelIssue]:
    cls = mapper.class_
    options = options_of(cls)
    for prop in mapper.column_attrs:
        column = prop.columns[0]
        if not isinstance(column, Column) or column in seen:
            continue
        seen.add(column)
        key = prop.key
        policy = field_policy(cls, key, column)
        if policy is None and f"{cls.__qualname__}.{key}" not in allowed:
            matched = [n for n in (key, column.name) if _looks_sensitive(n)]
            if matched:
                yield ModelIssue(
                    "sensitive-column",
                    cls,
                    key,
                    f"name {matched[0]!r} looks sensitive but the column has no "
                    'audit policy; set info={"audit": "redact"} (or "hash" / '
                    f'"exclude"), or pass "{cls.__qualname__}.{key}" in '
                    "allow_names",
                )
        if (
            policy != "exclude"
            and _is_json(column.type)
            and key not in options.snapshot_on_load
            and not _is_mutable(mapper, key)
        ):
            yield ModelIssue(
                "json-in-place",
                cls,
                key,
                "in-place changes of this JSON column are not detected; wrap its "
                "type with sqlalchemy.ext.mutable (MutableDict/MutableList) and "
                "list it in snapshot_on_load to also keep the old value, or "
                "always assign a new object",
            )


_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
_SENSITIVE_WORDS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "secrets",
        "token",
        "tokens",
        "credential",
        "credentials",
        "apikey",
        "encrypted",
    }
)


def _looks_sensitive(name: str) -> bool:
    # "apiKey", "APIKey" and "api_key" all give ["api", "key"].
    words = [word.lower() for word in _WORD.findall(name)]
    flat = "".join(words)
    if "password" in flat or "passwd" in flat:
        return True
    if _SENSITIVE_WORDS.intersection(words):
        return True
    return len(words) > 1 and words[-1] == "key"


def _is_json(type_: TypeEngine[Any]) -> bool:
    if isinstance(type_, TypeDecorator):
        type_ = type_.impl_instance
    return isinstance(type_, JSON)


def _is_mutable(mapper: Mapper[Any], key: str) -> bool:
    # Mutable coerces the value on assignment; a Mutable of the other shape
    # (MutableList given a dict) rejects it with ValueError.
    probes: tuple[object, ...] = ({}, [])
    for probe in probes:
        obj = mapper.class_manager.new_instance()
        try:
            setattr(obj, key, probe)
        except Exception:  # a host validator may reject it; then warn
            continue
        if isinstance(getattr(obj, key), Mutable):
            return True
    return False


def _check_relationships(mappers: list[Mapper[Any]]) -> Iterator[ModelIssue]:
    # The first (most base) class tracking each relationship property.
    tracked: dict[RelationshipProperty[Any], type[Any]] = {}
    reported_names: set[tuple[int, str]] = set()
    for mapper in mappers:
        cls = mapper.class_
        options = options_of(cls) if issubclass(cls, Audited) else AuditOptions()
        names = set(options.track_relationships)
        relationships = mapper.relationships
        for key, prop in relationships.items():
            if (key in names and prop.uselist) or any(
                _TrackedAttribute(klass, key) in _tracked for klass in cls.__mro__
            ):
                tracked.setdefault(prop, cls)
        for name in sorted(names):
            relationship = relationships.get(name)
            if relationship is not None and relationship.uselist:
                continue
            # Subclasses inherit the same options object; report it once.
            if (id(options), name) in reported_names:
                continue
            reported_names.add((id(options), name))
            if relationship is not None:
                what = "a scalar relationship; only collections can be tracked"
            elif name in mapper.column_attrs:
                what = "a column, not a relationship of the model"
            else:
                what = "not an attribute, not a relationship of the model"
            yield ModelIssue(
                "unknown-relationship",
                cls,
                name,
                f"track_relationships names {name!r}, which is {what}",
            )
    reported_pairs: set[frozenset[RelationshipProperty[Any]]] = set()
    for prop, cls in tracked.items():
        for reverse in prop._reverse_property:
            pair = frozenset((prop, reverse))
            if reverse not in tracked or pair in reported_pairs:
                continue
            reported_pairs.add(pair)
            (first_cls, first_key), (other_cls, other_key) = sorted(
                [(cls, prop.key), (tracked[reverse], reverse.key)],
                key=lambda side: (side[0].__qualname__, side[1]),
            )
            yield ModelIssue(
                "relationship-both-sides",
                first_cls,
                first_key,
                "both sides of one relationship are tracked "
                f"({first_cls.__qualname__}.{first_key} and "
                f"{other_cls.__qualname__}.{other_key}); every change would be "
                "recorded twice, track only one side",
            )
