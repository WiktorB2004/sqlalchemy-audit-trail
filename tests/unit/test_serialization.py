from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
import sys
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from enum import Enum, IntEnum
from typing import Any
from uuid import UUID

import pytest
from pydantic import BaseModel

from audit_trail.serialization import (
    KeyRing,
    Pseudonymized,
    UnserializableValueError,
    encode_value,
    hash_value,
    pseudonymize,
    pseudonymized_fields,
    verify,
)

# Obviously fake keys, 32 bytes each.
KEY_V1 = b"1" * 32
KEY_V2 = b"2" * 32


class Color(Enum):
    RED = "red"


class Level(IntEnum):
    HIGH = 3


class Money:
    def __init__(self, cents: int) -> None:
        self.cents = cents


class MoneyEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, Money):
            return {"cents": o.cents}
        return super().default(o)


# --- encode_value ------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        (True, True),
        (7, 7),
        (1.5, 1.5),
        ("text", "text"),
        (Decimal("12.30"), "12.30"),
        (
            UUID("6F9619FF-8B86-D011-B42D-00C04FC964FF"),
            "6f9619ff-8b86-d011-b42d-00c04fc964ff",
        ),
        (Color.RED, "red"),
        (Level.HIGH, 3),
        (date(2026, 9, 25), "2026-09-25"),
        (time(8, 30, 5), "08:30:05"),
        (
            datetime(2026, 9, 25, 8, 30, tzinfo=timezone.utc),
            "2026-09-25T08:30:00+00:00",
        ),
        (
            b"abc",
            {"sha256": hashlib.sha256(b"abc").hexdigest(), "len": 3},
        ),
        (bytearray(b"abc"), {"sha256": hashlib.sha256(b"abc").hexdigest(), "len": 3}),
    ],
)
def test_encode_value_builtin_types(value: object, expected: object) -> None:
    assert encode_value(value) == expected


def test_encode_value_keeps_the_original_offset() -> None:
    warsaw_summer = timezone(timedelta(hours=2))
    value = datetime(2026, 9, 25, 10, 30, tzinfo=warsaw_summer)
    assert encode_value(value) == "2026-09-25T10:30:00+02:00"


def test_encode_value_aware_time_keeps_offset() -> None:
    value = time(10, 30, tzinfo=timezone(timedelta(hours=-5)))
    assert encode_value(value) == "10:30:00-05:00"


def test_encode_value_naive_datetime_gets_no_invented_offset() -> None:
    naive = datetime(2026, 9, 25, 10, 30)  # noqa: DTZ001
    assert encode_value(naive) == "2026-09-25T10:30:00"


def test_encode_value_decimal_is_not_normalized() -> None:
    assert encode_value(Decimal("1.0")) != encode_value(Decimal("1.00"))


def test_encode_value_recurses_into_containers() -> None:
    value = {"a": [Decimal(1), (Color.RED, None)], "b": {"c": b""}}
    assert encode_value(value) == {
        "a": ["1", ["red", None]],
        "b": {"c": {"sha256": hashlib.sha256(b"").hexdigest(), "len": 0}},
    }


def test_encode_value_unhandled_type_raises_with_type_name() -> None:
    with pytest.raises(UnserializableValueError, match=r"test_serialization\.Money"):
        encode_value(Money(5))


def test_encode_value_error_does_not_contain_the_value() -> None:
    class Secret:
        def __repr__(self) -> str:
            return "hunter2"

        __str__ = __repr__

    with pytest.raises(UnserializableValueError) as excinfo:
        encode_value(Secret())
    assert "hunter2" not in str(excinfo.value)


def test_encode_value_unhandled_nested_type_raises() -> None:
    with pytest.raises(UnserializableValueError, match="Money"):
        encode_value({"price": [Money(5)]})


def test_encode_value_set_is_not_encoded() -> None:
    with pytest.raises(UnserializableValueError, match="set"):
        encode_value({1, 2})


def test_encode_value_non_str_dict_key_raises() -> None:
    with pytest.raises(UnserializableValueError, match="dict key of type builtins.int"):
        encode_value({1: "a"})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_encode_value_non_finite_float_raises(value: float) -> None:
    with pytest.raises(UnserializableValueError):
        encode_value(value)


def test_encode_value_uses_host_encoder_for_unknown_types() -> None:
    assert encode_value([Money(5)], json_encoder=MoneyEncoder) == [{"cents": 5}]


def test_encode_value_host_encoder_fallthrough_raises_with_type_name() -> None:
    with pytest.raises(UnserializableValueError, match="builtins.object"):
        encode_value(object(), json_encoder=MoneyEncoder)


def test_encode_value_builtins_win_over_host_encoder() -> None:
    class DecimalAsFloat(json.JSONEncoder):
        def default(self, o: Any) -> Any:
            if isinstance(o, Decimal):
                return float(o)
            return super().default(o)

    assert encode_value(Decimal("1.10"), json_encoder=DecimalAsFloat) == "1.10"


# --- KeyRing -----------------------------------------------------------------


def test_key_ring_bytes_is_version_1() -> None:
    ring = KeyRing(KEY_V1)
    assert ring.current_version == 1
    assert ring.get(1) == KEY_V1


def test_key_ring_uses_highest_version() -> None:
    ring = KeyRing({2: KEY_V2, 1: KEY_V1})
    assert ring.current_version == 2
    assert ring.get(1) == KEY_V1
    assert ring.get(3) is None


@pytest.mark.parametrize(
    ("keys", "error"),
    [
        (None, TypeError),
        ("1" * 32, TypeError),
        ({0: KEY_V1}, ValueError),
        ({True: KEY_V1}, TypeError),
        ({"1": KEY_V1}, TypeError),
        ({1: "1" * 32}, TypeError),
        (b"", ValueError),
        (b"k" * 31, ValueError),
        ({1: KEY_V1, 2: b"k" * 31}, ValueError),
    ],
)
def test_key_ring_rejects_invalid_config_at_construction(
    keys: Any, error: type[Exception]
) -> None:
    with pytest.raises(error):
        KeyRing(keys)


def test_key_ring_empty_mapping_fails_loudly() -> None:
    with pytest.raises(ValueError, match="no keys"):
        KeyRing({})


def test_key_ring_accepts_minimum_key_length() -> None:
    assert KeyRing(b"k" * 32).current_version == 1


def test_key_ring_repr_hides_keys() -> None:
    text = repr(KeyRing({1: KEY_V1, 2: KEY_V2}))
    assert text == "KeyRing(versions=[1, 2])"
    assert "111" not in text


# --- pseudonymize / hash_value / verify --------------------------------------


def _expected(prefix: str, key: bytes, canonical: bytes) -> str:
    digest = hmac.new(key, prefix.encode() + canonical, hashlib.sha256).hexdigest()
    return prefix + digest


def test_hash_value_known_answer() -> None:
    token = hash_value("a@example.com", keys=KeyRing(KEY_V1))
    assert token == _expected("hv1:", KEY_V1, b'"a@example.com"')


def test_pseudonymize_known_answer() -> None:
    token = pseudonymize(
        {"b": 1, "a": "ł"}, purpose="login_attempt", keys=KeyRing(KEY_V1)
    )
    canonical = '{"a":"ł","b":1}'.encode()
    assert token == _expected("audit.login_attempt.v1:", KEY_V1, canonical)


def test_tokens_are_deterministic() -> None:
    ring = KeyRing(KEY_V1)
    assert hash_value("x", keys=ring) == hash_value("x", keys=KeyRing(KEY_V1))
    assert pseudonymize("x", purpose="p", keys=ring) == pseudonymize(
        "x", purpose="p", keys=ring
    )


def test_different_purposes_give_unrelated_digests() -> None:
    ring = KeyRing(KEY_V1)
    first = pseudonymize("x", purpose="login_attempt", keys=ring)
    second = pseudonymize("x", purpose="password_reset", keys=ring)
    assert first.split(":", 1)[1] != second.split(":", 1)[1]


def test_pseudonym_and_column_hash_do_not_share_a_digest() -> None:
    ring = KeyRing(KEY_V1)
    pseudonym = pseudonymize("x", purpose="p", keys=ring)
    column_hash = hash_value("x", keys=ring)
    assert pseudonym.split(":", 1)[1] != column_hash.split(":", 1)[1]


def test_same_logical_value_correlates() -> None:
    ring = KeyRing(KEY_V1)
    uuid = UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")
    assert hash_value(uuid, keys=ring) == hash_value(str(uuid), keys=ring)
    assert hash_value(Decimal("1.0"), keys=ring) == hash_value("1.0", keys=ring)


def test_differently_typed_values_do_not_collide() -> None:
    ring = KeyRing(KEY_V1)
    tokens = {hash_value(v, keys=ring) for v in (1, 1.5, "1", "1.5", True)}
    assert len(tokens) == 5
    assert hash_value(Decimal("1.0"), keys=ring) != hash_value(
        Decimal("1.00"), keys=ring
    )


@pytest.mark.parametrize("purpose", ["", "Login", "login.attempt", "a:b", "1st"])
def test_pseudonymize_rejects_invalid_purpose(purpose: str) -> None:
    with pytest.raises(ValueError, match="purpose"):
        pseudonymize("x", purpose=purpose, keys=KeyRing(KEY_V1))


def test_none_is_never_hashed() -> None:
    ring = KeyRing(KEY_V1)
    with pytest.raises(TypeError, match="None"):
        hash_value(None, keys=ring)
    with pytest.raises(TypeError, match="None"):
        pseudonymize(None, purpose="p", keys=ring)


def test_unhandled_type_is_not_hashed() -> None:
    with pytest.raises(UnserializableValueError, match="Money"):
        hash_value(Money(1), keys=KeyRing(KEY_V1))
    token = hash_value(Money(1), keys=KeyRing(KEY_V1), json_encoder=MoneyEncoder)
    assert token.startswith("hv1:")


def test_rotation_writes_with_highest_version() -> None:
    ring = KeyRing({1: KEY_V1, 2: KEY_V2})
    assert hash_value("x", keys=ring) == _expected("hv2:", KEY_V2, b'"x"')
    assert pseudonymize("x", purpose="p", keys=ring).startswith("audit.p.v2:")


def test_rotation_old_tokens_verify_with_kept_key() -> None:
    old_hash = hash_value("x", keys=KeyRing(KEY_V1))
    old_pseudonym = pseudonymize("x", purpose="p", keys=KeyRing(KEY_V1))
    ring = KeyRing({1: KEY_V1, 2: KEY_V2})
    assert verify(old_hash, "x", keys=ring)
    assert verify(old_pseudonym, "x", keys=ring)
    assert verify(hash_value("x", keys=ring), "x", keys=ring)
    assert not verify(old_hash, "y", keys=ring)


def test_rotation_missing_old_key_is_no_match_without_error() -> None:
    old_hash = hash_value("x", keys=KeyRing(KEY_V1))
    old_pseudonym = pseudonymize("x", purpose="p", keys=KeyRing(KEY_V1))
    ring = KeyRing({2: KEY_V2})
    assert verify(old_hash, "x", keys=ring) is False
    assert verify(old_pseudonym, "x", keys=ring) is False


def test_verify_does_not_accept_token_from_another_key_of_same_version() -> None:
    token = hash_value("x", keys=KeyRing(b"a" * 32))
    assert not verify(token, "x", keys=KeyRing(b"b" * 32))


@pytest.mark.parametrize(
    "stored",
    [
        "",
        "plain text",
        "hv1:",
        "hv1:" + "0" * 63,
        "hv1:" + "G" * 64,
        "hvx:" + "0" * 64,
        "audit.p.v:" + "0" * 64,
        "***",
        "<unknown>",
    ],
)
def test_verify_malformed_token_is_no_match(stored: str) -> None:
    assert verify(stored, "x", keys=KeyRing(KEY_V1)) is False


def test_verify_tampered_token_is_no_match() -> None:
    ring = KeyRing(KEY_V1)
    token = hash_value("x", keys=ring)
    last = "0" if token[-1] != "0" else "1"
    assert not verify(token[:-1] + last, "x", keys=ring)
    swapped = pseudonymize("x", purpose="p", keys=ring).replace("audit.p.", "audit.q.")
    assert not verify(swapped, "x", keys=ring)


# --- Pseudonymized -----------------------------------------------------------


class LoginFailed(BaseModel):
    login: Pseudonymized[str]
    reason: str


def test_pseudonymized_does_not_change_validation_or_schema() -> None:
    class Plain(BaseModel):
        login: str
        reason: str

    assert LoginFailed(login="a", reason="b").login == "a"
    with pytest.raises(ValueError):
        LoginFailed.model_validate({"login": 1, "reason": "b"})
    schema = LoginFailed.model_json_schema()
    assert schema["properties"] == Plain.model_json_schema()["properties"]


def test_pseudonymized_fields_lists_marked_fields() -> None:
    assert pseudonymized_fields(LoginFailed) == {"login"}


def test_serialization_imports_without_pydantic() -> None:
    code = (
        "import sys; sys.modules['pydantic'] = None; "
        "import audit_trail, audit_trail.serialization as s; "
        "s.Pseudonymized[str]"
    )
    subprocess.run([sys.executable, "-c", code], check=True)
