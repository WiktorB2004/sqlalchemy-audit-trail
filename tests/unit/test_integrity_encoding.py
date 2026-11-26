"""The canonical encoder and commitments of the integrity feature."""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from audit_trail.integrity._canonical import (
    MAX_INT_DIGITS,
    CanonicalEncodingError,
    canonical,
)
from audit_trail.integrity._commit import (
    SALT_LENGTH,
    activity_groups,
    commitment,
    inet_text,
    leaf_hash,
    seal_columns,
    transaction_groups,
)

VECTORS = Path(__file__).parent.parent / "fixtures" / "integrity" / "vectors"


def load(name: str) -> Any:
    return json.loads((VECTORS / name).read_text())


CANONICAL = load("canonical.json")


@pytest.mark.parametrize(
    "case", CANONICAL["encode"], ids=[c["name"] for c in CANONICAL["encode"]]
)
def test_canonical_vectors(case: dict[str, str]) -> None:
    assert canonical(json.loads(case["input"])) == case["canonical"].encode()


@pytest.mark.parametrize(
    "case", CANONICAL["refuse"], ids=[c["name"] for c in CANONICAL["refuse"]]
)
def test_canonical_refusals(case: dict[str, str]) -> None:
    with pytest.raises(CanonicalEncodingError):
        canonical(json.loads(case["input"]))


def test_vectors_cover_the_edge_cases() -> None:
    # The plan's required cases are present, so the vectors stay meaningful.
    names = " ".join(c["name"] for c in CANONICAL["encode"])
    for needed in ("negative zero", "1e16", "supplementary plane", "U+E000"):
        assert needed in names


@pytest.fixture
def no_int_limit() -> Iterator[None]:
    previous = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(0)
    yield
    sys.set_int_max_str_digits(previous)


def test_int_digit_limit() -> None:
    assert canonical(10 ** (MAX_INT_DIGITS - 1)) == b"1" + b"0" * (MAX_INT_DIGITS - 1)
    with pytest.raises(CanonicalEncodingError, match="4300 digits"):
        canonical(10**MAX_INT_DIGITS)
    with pytest.raises(CanonicalEncodingError, match="4300 digits"):
        canonical(-(10**MAX_INT_DIGITS))


@pytest.mark.usefixtures("no_int_limit")
def test_int_digit_limit_holds_without_pythons_limit() -> None:
    with pytest.raises(CanonicalEncodingError, match="4300 digits"):
        canonical(10**MAX_INT_DIGITS)


def test_numbers_are_never_rounded() -> None:
    # Decimal.normalize() would round this to 28 digits.
    long = "1.2345678901234567890123456789012345678901"
    assert canonical(Decimal(long + "000")) == long.encode()
    assert canonical(Decimal("-0.000")) == b"0"
    assert canonical(Decimal("1E+3")) == b"1000"
    assert len(canonical(1e300)) == 301
    assert len(canonical(5e-324)) == 326


def test_decimal_digit_limit() -> None:
    assert canonical(Decimal(f"1E+{MAX_INT_DIGITS - 1}")) == canonical(
        10 ** (MAX_INT_DIGITS - 1)
    )
    # "0." and the fraction: 1 + (MAX_INT_DIGITS - 1) digits.
    assert len(canonical(Decimal(f"1E-{MAX_INT_DIGITS - 1}"))) == MAX_INT_DIGITS + 1
    # Trailing fraction zeros are not written, so they do not count.
    assert canonical(Decimal("1." + "0" * MAX_INT_DIGITS)) == b"1"
    for text in (f"1E+{MAX_INT_DIGITS}", f"-1E-{MAX_INT_DIGITS}", "1E+999999999"):
        with pytest.raises(CanonicalEncodingError, match="4300 digits"):
            canonical(Decimal(text))
    assert canonical(Decimal("0E+999999999")) == canonical(Decimal("-0E-9")) == b"0"


def test_deep_nesting_is_refused() -> None:
    value: list[object] = []
    for _ in range(sys.getrecursionlimit() * 2):
        value = [value]
    with pytest.raises(CanonicalEncodingError, match="nested"):
        canonical(value)
    with pytest.raises(CanonicalEncodingError, match="nested"):
        canonical({"a": value})


def test_readers_types_give_the_same_text() -> None:
    # JSONB may hand back an int, a float or a Decimal for the same number.
    assert canonical(1e16) == canonical(10**16) == canonical(Decimal("1E+16"))
    assert canonical(-0.0) == canonical(0) == canonical(Decimal("-0"))
    assert canonical(2.5) == canonical(Decimal("2.50"))


def test_a_number_never_equals_a_string() -> None:
    assert canonical(2**60) != canonical(str(2**60))


@pytest.mark.parametrize(
    "value",
    [object(), b"x", {1: "a"}, {"a": {2.0: 1}}, float("nan"), Decimal("NaN")],
    ids=["object", "bytes", "int key", "nested float key", "nan", "decimal nan"],
)
def test_canonical_refuses_other_values(value: object) -> None:
    with pytest.raises(CanonicalEncodingError):
        canonical(value)


def test_canonical_error_names_no_value() -> None:
    with pytest.raises(CanonicalEncodingError) as info:
        canonical({"email": "ann@example.com\x00"})
    assert "ann@example.com" not in str(info.value)


@pytest.mark.parametrize("case", load("commitments.json"), ids=lambda c: c["group"])
def test_commitment_vectors(case: dict[str, str]) -> None:
    salt = bytes.fromhex(case["salt"])
    value = json.loads(case["value"])
    assert canonical(value) == case["canonical"].encode()
    assert commitment(case["group"], salt, value).hex() == case["commitment"]
    # The vector itself follows the documented preimage.
    group = case["group"].encode()
    preimage = (
        b"sqlalchemy-audit-trail/commit/v1\x00"
        + bytes([len(group)])
        + group
        + salt
        + case["canonical"].encode()
    )
    assert hashlib.sha256(preimage).hexdigest() == case["commitment"]


LEAVES = load("leaves.json")


@pytest.mark.parametrize("case", LEAVES, ids=[c["name"] for c in LEAVES])
def test_leaf_vectors(case: dict[str, str]) -> None:
    row = json.loads(case["row"])
    assert canonical(row) == case["canonical"].encode()
    assert leaf_hash(row).hex() == case["leaf"]
    preimage = b"\x00sqlalchemy-audit-trail/leaf/v1" + case["canonical"].encode()
    assert hashlib.sha256(preimage).hexdigest() == case["leaf"]


def test_commitment_checks_its_inputs() -> None:
    with pytest.raises(ValueError, match="salt"):
        commitment("label", b"short", "x")
    with pytest.raises(ValueError, match="255 bytes"):
        commitment("g" * 256, bytes(SALT_LENGTH), "x")


def test_seal_columns_commit_to_present_groups_with_fresh_salts() -> None:
    sealed = seal_columns({"label": "Doc", "changes": None, "payload": {"a": 1}})
    assert set(sealed) == {"seal_commitments", "seal_salts", "seal_erased"}
    assert set(sealed["seal_commitments"]) == {"label", "payload"}
    assert set(sealed["seal_salts"]) == {"label", "payload"}
    assert sealed["seal_erased"] is None
    again = seal_columns({"label": "Doc", "changes": None, "payload": {"a": 1}})
    assert again["seal_salts"]["label"] != sealed["seal_salts"]["label"]
    assert again["seal_commitments"]["label"] != sealed["seal_commitments"]["label"]


def test_seal_columns_of_a_row_without_groups() -> None:
    assert seal_columns({"actor": None}) == {
        "seal_commitments": {},
        "seal_salts": {},
        "seal_erased": None,
    }


def test_activity_groups() -> None:
    data = {
        "v": 1,
        "changes": {"a": [1, 2]},
        "context": {"actor_type": "user", "actor_label": "Ann", "path": "/x"},
    }
    assert activity_groups("Doc", data) == {
        "label": "Doc",
        "changes": {"a": [1, 2]},
        "payload": None,
        "actor": {"actor_label": "Ann"},
    }
    assert activity_groups(None, {"v": 1, "context": {"path": "/x"}}) == {
        "label": None,
        "changes": None,
        "payload": None,
        "actor": None,
    }


def test_transaction_groups_use_postgres_inet_text() -> None:
    row = {"actor_type": "user", "remote_addr": "2001:DB8::0:1", "meta": {"t": 1}}
    assert transaction_groups(row) == {
        "actor": {"remote_addr": "2001:db8::1", "meta": {"t": 1}}
    }
    assert transaction_groups({"actor_type": "user"}) == {"actor": None}


@pytest.mark.parametrize(
    ("value", "text"),
    [
        ("10.0.0.1", "10.0.0.1"),
        ("10.0.0.1/32", "10.0.0.1"),
        ("10.0.0.1/8", "10.0.0.1/8"),
        ("::", "::"),
        ("::1", "::1"),
        ("1::", "1::"),
        ("1:0:0:2:0:0:0:3", "1:0:0:2::3"),
        ("1:0:2:3:4:5:6:7", "1:0:2:3:4:5:6:7"),
        ("::ffff:1.2.3.4", "::ffff:1.2.3.4"),
        ("::102:304", "::1.2.3.4"),
        ("2001:DB8::1/128", "2001:db8::1"),
        ("2001:db8::1/64", "2001:db8::1/64"),
        ("not an address", "not an address"),
    ],
)
def test_inet_text(value: str, text: str) -> None:
    assert inet_text(value) == text
