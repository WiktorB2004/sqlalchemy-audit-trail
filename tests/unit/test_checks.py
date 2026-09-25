"""``check_models`` on freshly mapped classes; no database involved.

Every test declares its own base, so mappings (and tracked relationships)
of one test never reach another's registry.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import JSON, Column, ForeignKey, Integer, String, Table
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.mutable import MutableDict, MutableList
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    backref,
    mapped_column,
    registry,
    relationship,
)
from sqlalchemy.types import TypeDecorator

from audit_trail.checks import IssueCode, ModelIssue, check_models
from audit_trail.config import AuditOptions
from audit_trail.diff import FieldPolicyError
from audit_trail.mixin import Audited
from audit_trail.relations import track_relationships


class _AssociatedJSON(JSON):
    """JSON subtype made mutable globally, without touching plain ``JSON``."""


MutableDict.associate_with(_AssociatedJSON)


class _WrappedJSON(TypeDecorator[Any]):
    impl = JSON
    cache_ok = True


def _found(issues: list[ModelIssue]) -> list[tuple[str, str, IssueCode]]:
    return [(i.model.__name__, i.attribute, i.code) for i in issues]


def _model(name: str, column: Column[Any] | Any, **extra: Any) -> type[Any]:
    """An audited model ``M`` with one extra attribute ``name``."""

    class Base(DeclarativeBase):
        pass

    namespace: dict[str, Any] = {
        "__tablename__": "m",
        "id": mapped_column(Integer, primary_key=True),
        name: column,
        **extra,
    }
    return type("M", (Base, Audited), namespace)


# --- sensitive-column --------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "password",
        "password_hash",
        "hashedpassword",
        "passwd",
        "pwd",
        "hook_secret",
        "secrets",
        "access_token",
        "refreshTokens",
        "client_credentials",
        "apikey",
        "api_key",
        "apiKey",
        "APIKey",
        "private_key",
        "ssn_encrypted",
        "encrypted_ssn",
    ],
)
def test_sensitive_name_without_policy_is_an_error(name: str) -> None:
    model = _model(name, mapped_column(String))

    issues = check_models(model)

    assert _found(issues) == [("M", name, "sensitive-column")]
    assert issues[0].level == "error"
    assert repr(name) in issues[0].message


@pytest.mark.parametrize(
    "name",
    ["key", "keys", "api_keys", "keyboard", "monkey", "secretary", "tokenizer", "name"],
)
def test_ordinary_name_is_not_reported(name: str) -> None:
    assert check_models(_model(name, mapped_column(String))) == []


def test_sensitive_column_name_behind_a_plain_key_is_an_error() -> None:
    issues = check_models(_model("data", mapped_column("api_key", String)))

    assert _found(issues) == [("M", "data", "sensitive-column")]
    assert "'api_key'" in issues[0].message


def test_sensitive_key_over_a_plain_column_name_is_an_error() -> None:
    issues = check_models(_model("api_key", mapped_column("data", String)))

    assert _found(issues) == [("M", "api_key", "sensitive-column")]


@pytest.mark.parametrize("policy", ["exclude", "redact", "hash"])
def test_explicit_policy_silences_a_sensitive_name(policy: str) -> None:
    model = _model("password", mapped_column(String, info={"audit": policy}))

    assert check_models(model) == []


def test_allow_names_silences_only_the_named_column() -> None:
    model = _model("sort_key", mapped_column(String), api_token=mapped_column(String))

    issues = check_models(model, allow_names={"M.sort_key", "Other.api_token"})

    assert _found(issues) == [("M", "api_token", "sensitive-column")]


def test_sensitive_name_on_a_model_that_is_not_audited_is_ignored() -> None:
    class Base(DeclarativeBase):
        pass

    class Plain(Base):
        __tablename__ = "plain"
        id: Mapped[int] = mapped_column(primary_key=True)
        password: Mapped[str]

    assert check_models(Base) == []


def test_inherited_sensitive_column_is_reported_once_where_declared() -> None:
    class Base(DeclarativeBase):
        pass

    class Account(Base, Audited):
        __tablename__ = "account"
        id: Mapped[int] = mapped_column(primary_key=True)
        kind: Mapped[str]
        password: Mapped[str]
        __mapper_args__ = {  # noqa: RUF012
            "polymorphic_on": "kind",
            "polymorphic_identity": "a",
        }

    class Admin(Account):
        __mapper_args__ = {"polymorphic_identity": "admin"}  # noqa: RUF012

    class Staff(Account):
        __tablename__ = "staff"
        id: Mapped[int] = mapped_column(ForeignKey("account.id"), primary_key=True)
        __mapper_args__ = {"polymorphic_identity": "staff"}  # noqa: RUF012

    assert _found(check_models(Base)) == [("Account", "password", "sensitive-column")]


def test_unknown_policy_raises() -> None:
    model = _model("password", mapped_column(String, info={"audit": "hide"}))

    with pytest.raises(FieldPolicyError, match="unknown audit policy"):
        check_models(model)


# --- json-in-place -----------------------------------------------------------


@pytest.mark.parametrize("type_", [JSON(), JSONB(), _WrappedJSON()])
def test_json_without_mutable_or_snapshot_is_a_warning(type_: Any) -> None:
    issues = check_models(_model("settings", mapped_column(type_)))

    assert _found(issues) == [("M", "settings", "json-in-place")]
    assert issues[0].level == "warning"


@pytest.mark.parametrize(
    "type_",
    [
        MutableDict.as_mutable(JSONB),
        MutableDict.as_mutable(JSON),
        MutableList.as_mutable(JSON),
        _AssociatedJSON(),
    ],
)
def test_mutable_json_is_not_reported(type_: Any) -> None:
    assert check_models(_model("settings", mapped_column(type_))) == []


def test_json_in_snapshot_on_load_is_not_reported() -> None:
    model = _model(
        "settings",
        mapped_column(JSONB),
        __audit__=AuditOptions(snapshot_on_load={"settings"}),
    )

    assert check_models(model) == []


def test_excluded_json_is_not_reported() -> None:
    model = _model("settings", mapped_column(JSONB, info={"audit": "exclude"}))

    assert check_models(model) == []


# --- relationship-both-sides -------------------------------------------------


def _back_populates_models(
    course_options: AuditOptions, student_options: AuditOptions
) -> tuple[type[DeclarativeBase], Any, Any]:
    class Base(DeclarativeBase):
        pass

    enrollment = Table(
        "enrollment",
        Base.metadata,
        Column("course_id", ForeignKey("course.id"), primary_key=True),
        Column("student_id", ForeignKey("student.id"), primary_key=True),
    )

    class Course(Base, Audited):
        __tablename__ = "course"
        id: Mapped[int] = mapped_column(primary_key=True)
        students: Mapped[list[Student]] = relationship(
            secondary=enrollment, back_populates="courses"
        )
        __audit__ = course_options

    class Student(Base, Audited):
        __tablename__ = "student"
        id: Mapped[int] = mapped_column(primary_key=True)
        courses: Mapped[list[Course]] = relationship(
            secondary=enrollment, back_populates="students"
        )
        __audit__ = student_options

    return Base, Course, Student


def test_both_sides_by_back_populates_are_an_error() -> None:
    base, _, _ = _back_populates_models(
        AuditOptions(track_relationships={"students"}),
        AuditOptions(track_relationships={"courses"}),
    )

    issues = check_models(base)

    assert _found(issues) == [("Course", "students", "relationship-both-sides")]
    assert issues[0].level == "error"
    assert "Course.students and " in issues[0].message
    assert issues[0].message.count("Student.courses") == 1


def test_one_side_by_back_populates_is_fine() -> None:
    base, _, _ = _back_populates_models(
        AuditOptions(track_relationships={"students"}), AuditOptions()
    )

    assert check_models(base) == []


def _backref_models() -> tuple[type[DeclarativeBase], Any, Any]:
    class Base(DeclarativeBase):
        pass

    post_tag = Table(
        "post_tag",
        Base.metadata,
        Column("post_id", ForeignKey("post.id"), primary_key=True),
        Column("tag_id", ForeignKey("tag.id"), primary_key=True),
    )

    class Tag(Base, Audited):
        __tablename__ = "tag"
        id: Mapped[int] = mapped_column(primary_key=True)

    class Post(Base, Audited):
        __tablename__ = "post"
        id: Mapped[int] = mapped_column(primary_key=True)
        tags = relationship(Tag, secondary=post_tag, backref=backref("posts"))

    Base.registry.configure()
    return Base, Post, Tag


def test_both_sides_by_backref_are_an_error() -> None:
    base, post, tag = _backref_models()
    track_relationships(post.tags, tag.posts)

    assert _found(check_models(base)) == [("Post", "tags", "relationship-both-sides")]


def test_one_side_by_backref_is_fine() -> None:
    base, post, _ = _backref_models()
    track_relationships(post.tags)

    assert check_models(base) == []


def test_both_sides_from_options_and_registry_are_an_error() -> None:
    base, _, student = _back_populates_models(
        AuditOptions(track_relationships={"students"}), AuditOptions()
    )
    track_relationships(student.courses)

    assert _found(check_models(base)) == [
        ("Course", "students", "relationship-both-sides")
    ]


# --- unknown-relationship ----------------------------------------------------


@pytest.mark.parametrize(
    ("name", "what"), [("tags", "not an attribute"), ("title", "a column")]
)
def test_unknown_tracked_relationship_is_an_error(name: str, what: str) -> None:
    model = _model(
        "title",
        mapped_column(String),
        __audit__=AuditOptions(track_relationships={name}),
    )

    issues = check_models(model)

    assert _found(issues) == [("M", name, "unknown-relationship")]
    assert issues[0].level == "error"
    assert what in issues[0].message


def test_tracked_scalar_relationship_is_an_error() -> None:
    class Base(DeclarativeBase):
        pass

    class Owner(Base, Audited):
        __tablename__ = "owner"
        id: Mapped[int] = mapped_column(primary_key=True)
        pets: Mapped[list[Pet]] = relationship(back_populates="owner")
        __audit__ = AuditOptions(track_relationships={"pets"})

    class Pet(Base, Audited):
        __tablename__ = "pet"
        id: Mapped[int] = mapped_column(primary_key=True)
        owner_id: Mapped[int] = mapped_column(ForeignKey("owner.id"))
        owner: Mapped[Owner] = relationship(back_populates="pets")
        __audit__ = AuditOptions(track_relationships={"owner"})

    issues = check_models(Base)

    assert _found(issues) == [("Pet", "owner", "unknown-relationship")]
    assert "a scalar relationship; only collections can be tracked" in (
        issues[0].message
    )


def test_inherited_unknown_relationship_is_reported_once() -> None:
    class Base(DeclarativeBase):
        pass

    class Doc(Base, Audited):
        __tablename__ = "doc"
        id: Mapped[int] = mapped_column(primary_key=True)
        kind: Mapped[str]
        __mapper_args__ = {  # noqa: RUF012
            "polymorphic_on": "kind",
            "polymorphic_identity": "d",
        }
        __audit__ = AuditOptions(track_relationships={"pages"})

    class Memo(Doc):
        __mapper_args__ = {"polymorphic_identity": "m"}  # noqa: RUF012

    assert _found(check_models(Base)) == [("Doc", "pages", "unknown-relationship")]


# --- report ------------------------------------------------------------------


def test_report_is_sorted_and_readable() -> None:
    class Base(DeclarativeBase):
        pass

    class Zeta(Base, Audited):
        __tablename__ = "zeta"
        id: Mapped[int] = mapped_column(primary_key=True)
        token: Mapped[str]

    class Alpha(Base, Audited):
        __tablename__ = "alpha"
        id: Mapped[int] = mapped_column(primary_key=True)
        secret: Mapped[str]
        data: Mapped[dict[str, Any]] = mapped_column(JSON)

    issues = check_models(Base)

    assert _found(issues) == [
        ("Alpha", "data", "json-in-place"),
        ("Alpha", "secret", "sensitive-column"),
        ("Zeta", "token", "sensitive-column"),
    ]
    alpha, zeta = Alpha.__qualname__, Zeta.__qualname__
    assert (
        str(issues[0]) == f"warning: {alpha}.data: {issues[0].message} [json-in-place]"
    )
    assert str(issues[2]).startswith(f"error: {zeta}.token: ")


def test_accepts_a_registry() -> None:
    reg = registry()

    @reg.mapped
    class Vault(Audited):
        __tablename__ = "vault"
        id: Mapped[int] = mapped_column(primary_key=True)
        secret: Mapped[str]

    assert _found(check_models(reg)) == [("Vault", "secret", "sensitive-column")]


def test_rejects_something_without_a_registry() -> None:
    with pytest.raises(TypeError, match="expected a registry"):
        check_models(object)
