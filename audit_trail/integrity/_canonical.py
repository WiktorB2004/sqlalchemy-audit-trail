"""The canonical byte encoding of JSON values that commitments and leaves hash.

The writer encodes the values it is about to store, and the verifier the
values it reads back from JSONB, so the encoding must give the same bytes for
both. It is a custom format close to JCS (RFC 8785), not JCS: numbers are
written differently.

- ``None``, ``True`` and ``False`` are ``null``, ``true`` and ``false``.
- A string is quoted as ``json.dumps(..., ensure_ascii=False)`` quotes it:
  ``"`` and ``\\`` escaped, ``\\b \\f \\n \\r \\t`` short, other control
  characters as ``\\u00xx``, everything else as UTF-8. ``\\u0000`` and lone
  surrogates are refused, since JSONB rejects both.
- An int, float or ``Decimal`` is plain decimal text without exponent,
  trailing fraction zeros or a trailing dot, and ``-0`` is ``0``: ``1e16``
  is ``10000000000000000``, ``1.50`` is ``1.5``. JSONB reads ``-0.0`` back as
  ``0`` and an integral float of 1e16 or more as an int, and both give the
  same text. A number written with more than ``MAX_INT_DIGITS`` digits is
  refused, and so is a value nested deeper than Python's recursion limit.
- An object's keys are sorted by their UTF-16 code units, as in JCS.
- No whitespace anywhere; the result is UTF-8.

A change to any of these rules needs a new context string in ``_commit``,
never an edit of the existing one.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from decimal import Decimal

MAX_INT_DIGITS = 4300
"""Most digits of an encoded int or ``Decimal``, Python's default ``str()`` limit."""


class CanonicalEncodingError(ValueError):
    """A value has no canonical encoding.

    The message names the problem, never the value, which may be personal
    data.
    """


def canonical(value: object) -> bytes:
    """Encode a JSON value canonically.

    Args:
        value: ``None``, ``bool``, ``int``, ``float``, ``Decimal``, ``str``, a
            ``list`` or ``tuple`` of values, or a ``dict`` with ``str`` keys.

    Returns:
        The UTF-8 bytes of the encoding.

    Raises:
        CanonicalEncodingError: The value or a nested one has another type, is
            a non-finite number, a number of more than ``MAX_INT_DIGITS``
            digits, a string holding ``\\u0000`` or a lone surrogate, or is
            nested deeper than the recursion limit.
    """
    parts: list[str] = []
    try:
        _encode(value, parts)
    except RecursionError:
        raise CanonicalEncodingError(
            "cannot encode a value nested this deeply"
        ) from None
    return "".join(parts).encode()


def _encode(value: object, parts: list[str]) -> None:
    # bool before int: True is an int.
    if value is None:
        parts.append("null")
    elif value is True:
        parts.append("true")
    elif value is False:
        parts.append("false")
    elif isinstance(value, str):
        parts.append(_string(value))
    elif isinstance(value, int):
        parts.append(_int(value))
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalEncodingError("cannot encode a non-finite float")
        parts.append(_decimal(Decimal(repr(value))))
    elif isinstance(value, Decimal):
        if not value.is_finite():
            raise CanonicalEncodingError("cannot encode a non-finite Decimal")
        parts.append(_decimal(value))
    elif isinstance(value, Mapping):
        _object(value, parts)
    elif isinstance(value, list | tuple):
        _array(value, parts)
    else:
        raise CanonicalEncodingError(
            f"cannot encode a value of type {type(value).__qualname__}"
        )


def _int(value: int) -> str:
    try:
        text = str(int(value))
    except ValueError:  # over sys.get_int_max_str_digits()
        text = ""
    if not text or len(text.lstrip("-")) > MAX_INT_DIGITS:
        raise CanonicalEncodingError(
            f"cannot encode an int of more than {MAX_INT_DIGITS} digits"
        )
    return text


def _decimal(value: Decimal) -> str:
    if value.is_zero():
        return "0"
    # Count the digits of the text before writing it: Decimal("1E+999999999")
    # is small, its text is not.
    _sign, digits, exponent = value.as_tuple()
    assert isinstance(exponent, int)  # the callers pass finite values only
    length = len(digits)
    if exponent < 0:
        # Trailing zeros of the fraction are not written.
        kept = length
        while kept > 1 and digits[kept - 1] == 0 and length - kept < -exponent:
            kept -= 1
        exponent += length - kept
        length = kept
    if exponent >= 0:
        written = length + exponent
    else:
        written = max(length + exponent, 1) - exponent
    if written > MAX_INT_DIGITS:
        raise CanonicalEncodingError(
            f"cannot encode a Decimal of more than {MAX_INT_DIGITS} digits"
        )
    # format(..., "f") writes every digit and never rounds; normalize() would
    # round to the 28-digit context.
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return "0" if text == "-0" else text


def _string(value: str) -> str:
    if "\x00" in value:
        raise CanonicalEncodingError("cannot encode a string holding \\u0000")
    try:
        value.encode()
    except UnicodeEncodeError:
        raise CanonicalEncodingError(
            "cannot encode a string holding a lone surrogate"
        ) from None
    return json.dumps(value, ensure_ascii=False)


def _object(value: Mapping[object, object], parts: list[str]) -> None:
    keys: list[str] = []
    for key in value:
        if not isinstance(key, str):
            raise CanonicalEncodingError(
                f"cannot encode an object key of type {type(key).__qualname__}"
            )
        _string(key)  # refuses \u0000 and lone surrogates first
        keys.append(key)
    keys.sort(key=lambda key: key.encode("utf-16-be"))
    parts.append("{")
    for index, key in enumerate(keys):
        if index:
            parts.append(",")
        parts.append(_string(key))
        parts.append(":")
        _encode(value[key], parts)
    parts.append("}")


def _array(value: Sequence[object], parts: list[str]) -> None:
    parts.append("[")
    for index, item in enumerate(value):
        if index:
            parts.append(",")
        _encode(item, parts)
    parts.append("]")
