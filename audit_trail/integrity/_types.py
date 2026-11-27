"""The ``xid8`` column type, which SQLAlchemy does not have."""

from __future__ import annotations

from typing import Any

from sqlalchemy import Text, cast
from sqlalchemy.engine import Dialect
from sqlalchemy.sql.elements import BindParameter, ColumnElement
from sqlalchemy.types import TypeDecorator, UserDefinedType


class _Xid8(UserDefinedType[int]):
    cache_ok = True

    def get_col_spec(self, **kw: Any) -> str:
        return "xid8"


class Xid8(TypeDecorator[int]):
    """PostgreSQL's 64-bit transaction id, as a Python ``int``.

    There is no cast from an integer type to ``xid8``, and psycopg sends a
    small int as ``int2``, so a bare ``CAST(:p AS xid8)`` fails. A value is
    therefore bound as ``str(int(value))`` and rendered as
    ``CAST(CAST(:p AS TEXT) AS xid8)``. Results are read with ``int()``.
    """

    impl = _Xid8
    cache_ok = True

    def bind_expression(self, bindvalue: BindParameter[int]) -> ColumnElement[int]:
        return cast(cast(bindvalue, Text), _Xid8())

    def process_bind_param(self, value: int | None, dialect: Dialect) -> Any:
        return None if value is None else str(int(value))

    def process_result_value(self, value: Any, dialect: Dialect) -> int | None:
        return None if value is None else int(value)
