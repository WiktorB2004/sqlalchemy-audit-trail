"""Change sets, field policies, object ids and option proxies on in-memory objects.

Nothing here touches a database: the instances are transient, and committed
state is set with ``set_committed_value`` where a test needs history.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

import pytest
from sqlalchemy import Column, ForeignKey, PickleType, String, text
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    registry,
    relationship,
)
from sqlalchemy.orm.attributes import set_committed_value

from audit_trail.config import AuditOptions
from audit_trail.diff import (
    REDACTED,
    UNKNOWN,
    USE_CONTEXT,
    FieldPolicyError,
    entity_changes,
    field_policy,
    object_id_for,
    object_id_of,
    object_type_of,
    resolve_label,
    resolve_scope,
    resolve_target,
)
from audit_trail.mixin import Audited
from audit_trail.serialization import KeyRing, UnserializableValueError, hash_value

KEYS = KeyRing(b"1" * 32)


class Base(DeclarativeBase):
    pass


class Account(Base, Audited):
    __tablename__ = "account"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str | None] = mapped_column(String)
    password: Mapped[str | None] = mapped_column(String, info={"audit": "redact"})
    email: Mapped[str | None] = mapped_column(String, info={"audit": "hash"})
    blob: Mapped[bytes | None] = mapped_column(info={"audit": "exclude"})
    # Attribute key and column name differ on purpose.
    api_token: Mapped[str | None] = mapped_column("token_value", String)
    marker: Mapped[str | None] = mapped_column(String, server_default=text("'x'"))
    payload: Mapped[Any] = mapped_column(PickleType, nullable=True)
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("parent.id"))
    parent: Mapped[Parent | None] = relationship()

    @property
    def shouting_name(self) -> str:
        return str(self.name).upper()


class Parent(Base):
    __tablename__ = "parent"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str | None] = mapped_column(String)


class Pair(Base, Audited):
    __tablename__ = "pair"

    a: Mapped[str] = mapped_column(primary_key=True)
    b: Mapped[int] = mapped_column(primary_key=True)


class Thing(Base, Audited):
    __tablename__ = "thing"
    __audit__ = AuditOptions(object_type="Widget")

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)


def account(**values: Any) -> Account:
    values.setdefault("id", 1)
    return Account(**values)


# --- object ids --------------------------------------------------------------


def test_object_id_for_single_key_is_str() -> None:
    assert object_id_for(Account, 42) == "42"
    assert object_id_for(Account, (42,)) == "42"


def test_object_id_for_uuid_is_canonical_lowercase() -> None:
    value = uuid.UUID("0E4F5A1C-7B2D-4C3E-9F80-112233445566")
    assert object_id_for(Thing, value) == "0e4f5a1c-7b2d-4c3e-9f80-112233445566"


def test_object_id_for_composite_key_is_compact_json_array() -> None:
    assert object_id_for(Pair, ("a", 1)) == '["a","1"]'
    assert json.loads(object_id_for(Pair, ("a", 1))) == ["a", "1"]


def test_object_id_for_rejects_wrong_arity_and_none() -> None:
    with pytest.raises(ValueError, match="2-column primary key, got 1"):
        object_id_for(Pair, "a")
    with pytest.raises(ValueError, match="contains None"):
        object_id_for(Account, None)


def test_object_id_of_reads_primary_key_of_instance_without_identity() -> None:
    assert object_id_of(account(id=7)) == "7"
    assert object_id_of(Pair(a="a", b=1)) == object_id_for(Pair, ("a", 1))


def test_object_id_of_without_primary_key_raises() -> None:
    with pytest.raises(ValueError, match="Account instance has no primary key"):
        object_id_of(Account())


def test_object_type_defaults_to_class_name() -> None:
    assert object_type_of(account()) == "Account"
    assert object_type_of(Thing(id=uuid.uuid4())) == "Widget"


# --- field policies ----------------------------------------------------------


def test_field_policy_reads_column_info() -> None:
    assert field_policy(Account, "x", Column(String, info={"audit": "hash"})) == "hash"
    assert field_policy(Account, "x", Column(String)) is None


@pytest.mark.parametrize("raw", ["Redact", "mask", 1])
def test_unknown_field_policy_names_model_and_column(raw: object) -> None:
    with pytest.raises(
        FieldPolicyError, match=r"Account\.secret: unknown audit policy"
    ):
        field_policy(Account, "secret", Column(String, info={"audit": raw}))


def test_unknown_policy_fails_mapper_configuration() -> None:
    reg = registry()

    class Bad(Audited):
        __tablename__ = "bad"
        id: Mapped[int] = mapped_column(primary_key=True)
        secret: Mapped[str] = mapped_column(info={"audit": "encrypt"})

    try:
        reg.mapped(Bad)
        with pytest.raises(
            FieldPolicyError, match=r"Bad\.secret: unknown audit policy"
        ):
            reg.configure()
    finally:
        reg.dispose()


def test_snapshot_on_load_must_name_columns() -> None:
    reg = registry()

    class BadSnapshot(Audited):
        __tablename__ = "bad_snapshot"
        __audit__ = AuditOptions(snapshot_on_load={"settings"})
        id: Mapped[int] = mapped_column(primary_key=True)

    try:
        reg.mapped(BadSnapshot)
        with pytest.raises(
            ValueError, match="BadSnapshot: snapshot_on_load names settings"
        ):
            reg.configure()
    finally:
        reg.dispose()


# --- created / deleted -------------------------------------------------------


def test_created_lists_every_audited_column_including_empty_ones() -> None:
    changes = entity_changes(account(name="Acme", marker="m"), "created", keys=KEYS)
    assert changes == {
        "id": [None, 1],
        "name": [None, "Acme"],
        "password": [None, None],
        "email": [None, None],
        "api_token": [None, None],
        "marker": [None, "m"],
        "payload": [None, None],
        "parent_id": [None, None],
    }


def test_created_unset_column_with_server_default_is_unknown() -> None:
    changes = entity_changes(account(), "created", keys=KEYS)
    assert changes["marker"] == [None, UNKNOWN]
    assert changes["name"] == [None, None]


def test_deleted_lists_old_values_and_unknown_for_unloaded() -> None:
    obj = account(name="Acme", password="pw")
    changes = entity_changes(obj, "deleted", keys=KEYS)
    assert changes["name"] == ["Acme", None]
    assert changes["password"] == [REDACTED, None]
    # Never set, so not in memory: unknown rather than a guess.
    assert changes["email"] == [UNKNOWN, None]


def test_redact_and_hash_keep_null_distinct_from_a_value() -> None:
    changes = entity_changes(
        account(password="pw", email="a@b.c"), "created", keys=KEYS
    )
    assert changes["password"] == [None, REDACTED]
    assert changes["email"] == [None, hash_value("a@b.c", keys=KEYS)]
    assert "blob" not in changes

    empty = entity_changes(account(password=None, email=None), "created", keys=KEYS)
    assert empty["password"] == [None, None]
    assert empty["email"] == [None, None]


def test_hash_policy_without_key_ring_raises() -> None:
    with pytest.raises(FieldPolicyError, match=r"Account\.email: the hash policy"):
        entity_changes(account(), "created")


def test_models_without_hash_columns_need_no_key_ring() -> None:
    assert entity_changes(Pair(a="a", b=1), "created") == {
        "a": [None, "a"],
        "b": [None, 1],
    }


def test_global_redact_matches_attribute_key() -> None:
    changes = entity_changes(
        account(name="Acme"), "created", keys=KEYS, global_redact={"name"}
    )
    assert changes["name"] == [None, REDACTED]


def test_global_redact_matches_column_name() -> None:
    changes = entity_changes(
        account(api_token="t0k"), "created", keys=KEYS, global_redact={"token_value"}
    )
    assert changes["api_token"] == [None, REDACTED]


def test_explicit_policy_wins_over_global_redact() -> None:
    changes = entity_changes(
        account(email="a@b.c"), "created", keys=KEYS, global_redact={"email", "blob"}
    )
    assert changes["email"] == [None, hash_value("a@b.c", keys=KEYS)]
    assert "blob" not in changes


def test_unserializable_value_propagates() -> None:
    with pytest.raises(UnserializableValueError):
        entity_changes(account(payload=object()), "created", keys=KEYS)


# --- updated -----------------------------------------------------------------


def committed_account(**values: Any) -> Account:
    obj = Account()
    for key, value in {"id": 1, **values}.items():
        set_committed_value(obj, key, value)
    return obj


def test_updated_lists_only_changed_columns() -> None:
    obj = committed_account(name="a", password=None, email="x@y.z")
    obj.name = "b"
    obj.password = "pw"
    obj.email = "x@y.z"
    assert entity_changes(obj, "updated", keys=KEYS) == {
        "name": ["a", "b"],
        "password": [None, REDACTED],
    }


def test_updated_to_null_keeps_null_for_redact_and_hash() -> None:
    obj = committed_account(password="pw", email="x@y.z")
    obj.password = None
    obj.email = None
    assert entity_changes(obj, "updated", keys=KEYS) == {
        "password": [REDACTED, None],
        "email": [hash_value("x@y.z", keys=KEYS), None],
    }


# --- option proxies ----------------------------------------------------------


def test_label_reads_loaded_attribute() -> None:
    options = AuditOptions(label=lambda obj: obj.name)
    assert resolve_label(account(name="Acme"), options) == "Acme"


def test_label_reading_unloaded_attribute_falls_back_and_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    options = AuditOptions(label=lambda obj: obj.name)
    with caplog.at_level(logging.WARNING, logger="audit_trail.diff"):
        assert resolve_label(account(), options) is None
    [record] = caplog.records
    assert record.name == "audit_trail.diff"
    message = record.getMessage()
    assert "AuditOptions.label" in message
    assert "Account" in message
    assert "'name'" in message


def test_property_runs_against_the_proxy() -> None:
    options = AuditOptions(label=lambda obj: obj.shouting_name)
    assert resolve_label(account(name="acme"), options) == "ACME"
    assert resolve_label(account(), options) is None


def test_unloaded_related_object_falls_back() -> None:
    options = AuditOptions(label=lambda obj: obj.parent.title)
    assert resolve_label(account(), options) is None
    assert resolve_label(account(parent=Parent(id=1, title="P")), options) == "P"


def test_other_exceptions_from_options_propagate() -> None:
    def broken(obj: Any) -> str:
        raise ZeroDivisionError

    options = AuditOptions(label=broken)
    with pytest.raises(ZeroDivisionError):
        resolve_label(account(), options)


def test_options_cannot_modify_the_instance() -> None:
    def rename(obj: Any) -> str:
        obj.name = "changed"
        return "x"

    obj = account(name="Acme")
    with pytest.raises(AttributeError):
        resolve_label(obj, AuditOptions(label=rename))
    assert obj.name == "Acme"


def test_scope_fallback_to_context_versus_explicit_none() -> None:
    obj = account(name="t1")
    assert resolve_scope(obj, AuditOptions()) is USE_CONTEXT
    assert resolve_scope(obj, AuditOptions(scope=lambda o: o.parent_id)) is USE_CONTEXT
    assert resolve_scope(obj, AuditOptions(scope=lambda o: None)) is None
    assert resolve_scope(obj, AuditOptions(scope=lambda o: o.name)) == "t1"


def test_target_formats_id_like_object_id() -> None:
    obj = account(parent_id=5)
    assert resolve_target(obj, AuditOptions()) is None
    assert resolve_target(
        obj, AuditOptions(target=lambda o: ("Parent", o.parent_id))
    ) == ("Parent", "5")
    assert resolve_target(obj, AuditOptions(target=lambda o: ("Pair", ("a", 1)))) == (
        "Pair",
        '["a","1"]',
    )
    assert resolve_target(obj, AuditOptions(target=lambda o: ("Parent", None))) is None
    assert (
        resolve_target(account(), AuditOptions(target=lambda o: ("P", o.name))) is None
    )
