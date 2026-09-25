"""JSON encoding of audited values and keyed pseudonymization.

Values written to ``data`` go through :func:`encode_value`, which turns them
into JSON-native data deterministically. :func:`pseudonymize` and
:func:`hash_value` replace a value with an HMAC-SHA256 token whose prefix
carries the key version, so rows written before a key rotation stay
distinguishable and, while the old key is kept, correlatable via
:func:`verify`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import types
from collections.abc import Mapping
from datetime import date, datetime, time
from decimal import Decimal
from enum import Enum
from typing import (
    TYPE_CHECKING,
    Annotated,
    TypeAlias,
    TypeVar,
    Union,
    get_args,
    get_origin,
)
from uuid import UUID

if TYPE_CHECKING:
    from pydantic import BaseModel

JSONValue: TypeAlias = (
    bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"] | None
)

MIN_KEY_LENGTH = 32
"""Minimum HMAC key length in bytes (the SHA-256 output size)."""

_PURPOSE_RE = re.compile(r"[a-z][a-z0-9_]*")
_TOKEN_RE = re.compile(
    r"(?:hv(?P<hv>[0-9]+)|audit\.(?P<purpose>[a-z][a-z0-9_]*)\.v(?P<pv>[0-9]+)):"
    r"[0-9a-f]{64}"
)


class UnserializableValueError(TypeError):
    """A value has no JSON encoding for the audit log.

    Raised instead of falling back to ``str()``, so the flush aborts rather
    than writing a partial entry. The message names the type, never the value,
    because the value may be personal data.
    """


def _type_name(value: object) -> str:
    cls = type(value)
    return f"{cls.__module__}.{cls.__qualname__}"


def encode_value(
    value: object, *, json_encoder: type[json.JSONEncoder] | None = None
) -> JSONValue:
    """Encode a value into JSON-native data for the audit log.

    Built-in rules:

    - ``None``, ``bool``, ``int``, ``str`` and finite ``float`` unchanged;
      NaN and infinities raise.
    - ``Enum`` -> its value, encoded recursively.
    - ``datetime``, ``date``, ``time`` -> ISO 8601. An aware value keeps its
      own offset (it is not converted to UTC). A naive value is written
      without an offset, as stored: no zone is invented for it.
    - ``Decimal`` -> ``str(value)`` without normalization, so
      ``Decimal("1.0")`` and ``Decimal("1.00")`` encode (and hash)
      differently.
    - ``UUID`` -> canonical lowercase hyphenated string.
    - ``bytes``, ``bytearray``, ``memoryview`` ->
      ``{"sha256": <hex digest>, "len": <byte count>}``.
    - ``dict`` with ``str`` keys and ``list``/``tuple`` -> encoded
      recursively. Non-``str`` keys raise, since JSON would silently turn
      ``1`` into ``"1"``.

    Anything else, including ``set``/``frozenset`` (no stable order), goes to
    ``json_encoder().default()`` and the result is encoded again; a result of
    the same type as the input raises instead of recursing. The built-in
    rules always win: the host encoder only sees types they do not cover.

    Args:
        value: The value to encode.
        json_encoder: Host encoder class for additional types.

    Returns:
        JSON-native data.

    Raises:
        UnserializableValueError: Neither a built-in rule nor the host encoder
            handles the value (or a nested value), or a float is not finite.
    """
    match value:
        case Enum():
            return encode_value(value.value, json_encoder=json_encoder)
        case None | bool() | int() | str():
            return value
        case float():
            if not math.isfinite(value):
                raise UnserializableValueError(
                    f"cannot encode non-finite float {value}"
                )
            return value
        case datetime() | date() | time():
            return value.isoformat()
        case Decimal() | UUID():
            return str(value)
        case bytes() | bytearray() | memoryview():
            raw = bytes(value)
            return {"sha256": hashlib.sha256(raw).hexdigest(), "len": len(raw)}
        case dict():
            encoded: dict[str, JSONValue] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise UnserializableValueError(
                        f"cannot encode dict key of type {_type_name(key)}; "
                        "keys must be str"
                    )
                encoded[key] = encode_value(item, json_encoder=json_encoder)
            return encoded
        case list() | tuple():
            return [encode_value(item, json_encoder=json_encoder) for item in value]
    if json_encoder is not None:
        try:
            substitute = json_encoder().default(value)
        except TypeError as exc:
            raise UnserializableValueError(
                f"cannot encode value of type {_type_name(value)}"
            ) from exc
        if type(substitute) is type(value):
            raise UnserializableValueError(
                f"json_encoder returned {_type_name(value)} unchanged; "
                "cannot encode value of that type"
            )
        return encode_value(substitute, json_encoder=json_encoder)
    raise UnserializableValueError(f"cannot encode value of type {_type_name(value)}")


class KeyRing:
    """Versioned HMAC keys for pseudonymization and the ``hash`` field policy.

    New tokens always use the highest version; :func:`verify` picks the key by
    the version in a token's prefix. Rotating means adding a higher version and
    keeping old keys for as long as old rows must stay correlatable.

    Args:
        keys: One key as ``bytes`` (version 1) or ``{version: key}``.

    Attributes:
        current_version: The highest version, used for new tokens.

    Raises:
        TypeError: ``keys`` is not ``bytes`` or a mapping, a version is not an
            ``int``, or a key is not ``bytes``.
        ValueError: No keys, a version below 1, or a key shorter than
            ``MIN_KEY_LENGTH`` bytes.
    """

    __slots__ = ("_keys", "current_version")

    def __init__(self, keys: bytes | Mapping[int, bytes]) -> None:
        if isinstance(keys, bytes):
            keys = {1: keys}
        elif not isinstance(keys, Mapping):
            raise TypeError(
                "pseudonymize_key must be bytes or a mapping of version to bytes, "
                f"got {_type_name(keys)}"
            )
        if not keys:
            raise ValueError("pseudonymize_key has no keys")
        checked: dict[int, bytes] = {}
        for version, key in keys.items():
            if isinstance(version, bool) or not isinstance(version, int):
                raise TypeError(f"key version must be int, got {_type_name(version)}")
            if version < 1:
                raise ValueError(f"key version must be >= 1, got {version}")
            if not isinstance(key, bytes):
                raise TypeError(
                    f"key for version {version} must be bytes, got {_type_name(key)}"
                )
            if len(key) < MIN_KEY_LENGTH:
                raise ValueError(
                    f"key for version {version} is shorter than {MIN_KEY_LENGTH} bytes"
                )
            checked[version] = key
        self._keys = checked
        self.current_version = max(checked)

    def get(self, version: int) -> bytes | None:
        """Return the key for ``version``, or ``None`` when it is not kept.

        Args:
            version: Key version.

        Returns:
            The key, or ``None``.
        """
        return self._keys.get(version)

    def _current_key(self) -> bytes:
        return self._keys[self.current_version]

    def __repr__(self) -> str:
        return f"KeyRing(versions={sorted(self._keys)})"


def _canonical_bytes(
    value: object, json_encoder: type[json.JSONEncoder] | None
) -> bytes:
    if value is None:
        raise TypeError("None is not hashed or pseudonymized; keep it as null")
    text = json.dumps(
        encode_value(value, json_encoder=json_encoder),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode("utf-8")


def _token(prefix: str, key: bytes, canonical: bytes) -> str:
    # The prefix is part of the MAC input so that purposes, and pseudonyms vs
    # column hashes, never share a digest for the same value.
    digest = hmac.new(key, prefix.encode("ascii") + canonical, hashlib.sha256)
    return prefix + digest.hexdigest()


def pseudonymize(
    value: object,
    *,
    purpose: str,
    keys: KeyRing,
    json_encoder: type[json.JSONEncoder] | None = None,
) -> str:
    """Replace a value with a keyed pseudonym, e.g. ``audit.login_attempt.v2:<hex>``.

    The token is ``prefix + hex(HMAC-SHA256(key, prefix + canonical))`` with
    the highest key version. ``canonical`` is the UTF-8 encoding of
    ``json.dumps(encode_value(value), sort_keys=True, separators=(",", ":"),
    ensure_ascii=False)``. So a ``UUID`` and its canonical string, or
    ``Decimal("1.0")`` and ``"1.0"``, give the same token, while ``1``,
    ``1.0`` and ``"1"`` all differ. Strings are not normalized (no case
    folding). The same value under two purposes gives unrelated digests.

    Args:
        value: The value to pseudonymize. Must not be ``None``.
        purpose: Snake_case name separating unrelated uses
            (for example ``"login_attempt"``).
        keys: Key ring to sign with.
        json_encoder: Host encoder for types ``encode_value`` does not handle.

    Returns:
        The pseudonym token.

    Raises:
        TypeError: ``value`` is ``None``.
        ValueError: ``purpose`` is not snake_case.
        UnserializableValueError: ``value`` cannot be encoded.
    """
    if not _PURPOSE_RE.fullmatch(purpose):
        raise ValueError(f"purpose must match [a-z][a-z0-9_]*, got {purpose!r}")
    prefix = f"audit.{purpose}.v{keys.current_version}:"
    return _token(prefix, keys._current_key(), _canonical_bytes(value, json_encoder))


def hash_value(
    value: object,
    *,
    keys: KeyRing,
    json_encoder: type[json.JSONEncoder] | None = None,
) -> str:
    """Hash a column value for the ``hash`` field policy, e.g. ``hv2:<hex>``.

    Same construction and canonical encoding as ``pseudonymize``, with the
    prefix ``hv{n}:``. ``None`` is not hashed: the caller keeps null as null,
    so null and a value stay distinguishable.

    Args:
        value: The value to hash. Must not be ``None``.
        keys: Key ring to sign with.
        json_encoder: Host encoder for types ``encode_value`` does not handle.

    Returns:
        The hash token.

    Raises:
        TypeError: ``value`` is ``None``.
        UnserializableValueError: ``value`` cannot be encoded.
    """
    prefix = f"hv{keys.current_version}:"
    return _token(prefix, keys._current_key(), _canonical_bytes(value, json_encoder))


def verify(
    stored: str,
    value: object,
    *,
    keys: KeyRing,
    json_encoder: type[json.JSONEncoder] | None = None,
) -> bool:
    """Check whether a stored token was made from ``value``.

    Works for tokens from both ``pseudonymize`` and ``hash_value``. The key is
    chosen by the version in the token's prefix, so tokens written before a
    rotation still verify while their key is kept in ``keys``.

    Args:
        stored: A token read from the log.
        value: The candidate value.
        keys: Key ring holding the versions to check against.
        json_encoder: Host encoder for types ``encode_value`` does not handle.

    Returns:
        ``True`` on a match. ``False`` when the value differs, the token is
        malformed, or its key version is not in ``keys``; none of those raise.

    Raises:
        TypeError: ``value`` is ``None``.
        UnserializableValueError: ``value`` cannot be encoded.
    """
    canonical = _canonical_bytes(value, json_encoder)
    match = _TOKEN_RE.fullmatch(stored)
    if match is None:
        return False
    if match["hv"] is not None:
        version = int(match["hv"])
        prefix = f"hv{version}:"
    else:
        version = int(match["pv"])
        prefix = f"audit.{match['purpose']}.v{version}:"
    key = keys.get(version)
    if key is None:
        return False
    return hmac.compare_digest(_token(prefix, key, canonical), stored)


class _PseudonymizedMarker:
    __slots__ = ()

    def __repr__(self) -> str:
        return "Pseudonymized"


_PSEUDONYMIZED = _PseudonymizedMarker()
_T = TypeVar("_T")

Pseudonymized: TypeAlias = Annotated[_T, _PSEUDONYMIZED]
"""Marks a payload schema field whose value is stored pseudonymized.

Use as ``login: Pseudonymized[str]`` on a pydantic model. Validation and the
JSON schema are unchanged; the writer pseudonymizes the fields listed by
``pseudonymized_fields``. Built from ``typing`` only, so importing it does not
need pydantic.
"""


def _is_pseudonymized(annotation: object) -> bool:
    origin = get_origin(annotation)
    if origin is Annotated:
        inner, *metadata = get_args(annotation)
        return any(item is _PSEUDONYMIZED for item in metadata) or _is_pseudonymized(
            inner
        )
    if origin is Union or origin is types.UnionType:
        return any(_is_pseudonymized(arg) for arg in get_args(annotation))
    return False


def pseudonymized_fields(schema: type[BaseModel]) -> frozenset[str]:
    """Return the names of top-level fields annotated with ``Pseudonymized``.

    The marker is found on the field itself (``Pseudonymized[str | None]``)
    and inside a union (``Pseudonymized[str] | None``,
    ``Optional[Pseudonymized[str]]``). Fields of nested models and items of
    containers are not included.

    Args:
        schema: A pydantic model class.

    Returns:
        Names of the marked fields.
    """
    return frozenset(
        name
        for name, field in schema.model_fields.items()
        if any(item is _PSEUDONYMIZED for item in field.metadata)
        or _is_pseudonymized(field.annotation)
    )
