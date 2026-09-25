"""The ``Audited`` mixin for audited ORM models.

Mixing ``Audited`` into a mapped class, when its mappers are configured:

- validates the column policies and ``snapshot_on_load`` of ``__audit__``;
- turns on ``active_history`` for every audited column, so assigning to an
  expired attribute loads its old value at assignment time rather than
  leaving the old value unknown at flush time;
- deep-copies the ``snapshot_on_load`` columns whenever the instance is
  loaded or refreshed, so an in-place change still has an old value.
"""

from __future__ import annotations

import copy
from collections.abc import Collection
from typing import TYPE_CHECKING, Any, ClassVar, TypeVar

from sqlalchemy import event
from sqlalchemy.orm.attributes import instance_state

from audit_trail.config import AuditOptions
from audit_trail.diff import SNAPSHOT_INFO_KEY, _audited_columns, options_of

if TYPE_CHECKING:
    from sqlalchemy.orm import AttributeEventToken, InstanceState, Mapper, QueryContext


class Audited:
    """Mixin marking a mapped class as audited.

    Options go in ``__audit__``; per-column policies in
    ``mapped_column(info={"audit": ...})``::

        class Tenant(Base, Audited):
            __tablename__ = "tenant"
            id: Mapped[int] = mapped_column(primary_key=True)
            hook_secret: Mapped[str] = mapped_column(info={"audit": "redact"})

            __audit__ = AuditOptions(label=lambda obj: obj.name)

    Attributes:
        __audit__: The model's audit options.
    """

    __audit__: ClassVar[AuditOptions] = AuditOptions()


_A = TypeVar("_A", bound=Audited)


def refresh_snapshot(obj: object) -> None:
    """Replace the ``snapshot_on_load`` copies with the instance's current values.

    The audit listener calls this in ``after_flush`` for new and updated
    instances, after it has computed their changes: the flushed values are the
    new committed state, and the next in-place change must be compared with
    them. It cannot be done by the mixin itself: the mapper's
    ``after_insert``/``after_update`` events fire during the flush, before
    ``after_flush``, and would overwrite the old value before the change set
    reads it.

    Does nothing for a model without ``snapshot_on_load``.

    Args:
        obj: A mapped instance.
    """
    _take_snapshot(instance_state(obj), None)


def _take_snapshot(state: InstanceState[Any], attrs: Collection[str] | None) -> None:
    keys = options_of(state.class_).snapshot_on_load
    if not keys:
        return
    snapshot: dict[str, object] = state.info.setdefault(SNAPSHOT_INFO_KEY, {})
    for key in keys:
        if attrs is not None and key not in attrs:
            continue
        if key in state.dict:
            snapshot[key] = copy.deepcopy(state.dict[key])
        else:
            snapshot.pop(key, None)


def _on_load(target: Audited, context: QueryContext) -> None:
    _take_snapshot(instance_state(target), None)


def _on_refresh(
    target: Audited, context: QueryContext, attrs: Collection[str] | None
) -> None:
    _take_snapshot(instance_state(target), attrs)


def _keep_old_value(
    target: object, value: object, oldvalue: object, initiator: AttributeEventToken
) -> None:
    """No-op ``set`` listener; registering it enables ``active_history``."""


def _on_mapper_configured(mapper: Mapper[_A], cls: type[_A]) -> None:
    columns = _audited_columns(mapper)
    column_keys = {prop.key for prop in mapper.column_attrs}
    unknown = sorted(set(options_of(cls).snapshot_on_load) - column_keys)
    if unknown:
        raise ValueError(
            f"{cls.__qualname__}: snapshot_on_load names {', '.join(unknown)}, "
            "which are not column attributes"
        )
    for spec in columns:
        event.listen(
            mapper.class_manager[spec.key], "set", _keep_old_value, active_history=True
        )


event.listen(Audited, "mapper_configured", _on_mapper_configured, propagate=True)
event.listen(Audited, "load", _on_load, propagate=True)
event.listen(Audited, "refresh", _on_refresh, propagate=True)
