"""Typing helpers shared across modules."""

from __future__ import annotations

from typing import NoReturn


def assert_never(value: NoReturn) -> NoReturn:
    """Mark a branch that exhaustive matching makes unreachable.

    ``typing.assert_never`` needs Python 3.11; this is the 3.10-compatible
    equivalent. Type checkers report an error when a value can still reach it.

    Raises:
        AssertionError: Always, if reached at runtime.
    """
    raise AssertionError(f"unhandled value: {value!r}")
