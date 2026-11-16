"""Which audited columns the flush treats as written by SQL, without a database.

``derived`` columns get their old value captured before the UPDATE;
``server_side`` ones are recorded only when the new value was fetched back.
"""

from __future__ import annotations

from sqlalchemy import Computed, FetchedValue, func, inspect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from audit_trail.diff import _keys_for_flush
from audit_trail.mixin import Audited


def test_keys_for_flush_classifies_sql_written_columns() -> None:
    class Base(DeclarativeBase):
        pass

    class Row(Base, Audited):
        __tablename__ = "row"
        id: Mapped[int] = mapped_column(primary_key=True)
        name: Mapped[str]
        stamped: Mapped[int] = mapped_column(onupdate=func.now())
        trig: Mapped[int] = mapped_column(server_onupdate=FetchedValue())
        calc: Mapped[int] = mapped_column(Computed("id * 2"))
        ver: Mapped[int] = mapped_column(server_default=FetchedValue())
        __mapper_args__ = {  # noqa: RUF012
            "version_id_col": ver,
            "version_id_generator": False,
        }

    keys = _keys_for_flush(inspect(Row))
    assert set(keys.derived) == {"stamped", "trig", "calc", "ver"}
    # A server-side version counter is written by the database, like a trigger.
    assert keys.server_side == {"trig", "calc", "ver"}
