"""Partitions scanned, from ``EXPLAIN (ANALYZE, FORMAT JSON)``.

The statements a library call sends are captured with a
``before_cursor_execute`` listener, then each ``SELECT`` is explained with
the same parameters on the same connection, in the same transaction (after
the library's ``SET LOCAL plan_cache_mode``). Needs no superuser, unlike
``auto_explain``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any, NamedTuple, TypedDict

from sqlalchemy import Connection, Engine, event


class StatementPlan(TypedDict):
    """One statement, the partitions its plan touched, and its server time.

    The times are those ``EXPLAIN ANALYZE`` reports for one run, with its
    instrumentation overhead; they show where the time goes, not latency.
    """

    sql: str
    partitions_scanned: list[str]
    partitions_in_plan: int
    planning_ms: float
    execution_ms: float


class _Captured(NamedTuple):
    statement: str
    parameters: object


def nodes(plan: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Every node of a JSON plan, depth first."""
    yield plan
    for child in plan.get("Plans", []):
        yield from nodes(child)


def scanned(plan: dict[str, Any]) -> tuple[list[str], int]:
    """Relations a plan executed, and the number of scan nodes it holds.

    A scan node that the executor pruned at run time stays in the plan with
    ``Actual Loops`` 0 ("never executed"); partitions pruned at plan time are
    not in it at all.
    """
    executed: set[str] = set()
    planned = 0
    for node in nodes(plan):
        relation = node.get("Relation Name")
        if relation is None:
            continue
        planned += 1
        if node.get("Actual Loops", 0) > 0:
            executed.add(str(relation))
    return sorted(executed), planned


def explain_call(
    engine: Engine,
    connection_of: Callable[[], Connection],
    call: Callable[[], object],
) -> list[StatementPlan]:
    """Run ``call`` and explain every ``SELECT`` it sent.

    Args:
        engine: Engine whose statements are captured.
        connection_of: Returns the connection ``call`` ran on, still in its
            transaction.
        call: The library call.
    """
    captured: list[_Captured] = []

    def capture(
        conn: Connection,
        cursor: object,
        statement: str,
        parameters: object,
        context: object,
        executemany: bool,
    ) -> None:
        if statement.lstrip().upper().startswith("SELECT") and not executemany:
            captured.append(_Captured(statement, parameters))

    event.listen(engine, "before_cursor_execute", capture)
    try:
        call()
    finally:
        event.remove(engine, "before_cursor_execute", capture)

    connection = connection_of()
    plans: list[StatementPlan] = []
    for item in captured:
        result = connection.exec_driver_sql(
            "EXPLAIN (ANALYZE, FORMAT JSON) " + item.statement,
            item.parameters,  # type: ignore[arg-type]
        )
        document: list[dict[str, Any]] = result.scalar_one()
        executed, planned = scanned(document[0]["Plan"])
        plans.append(
            StatementPlan(
                sql=" ".join(item.statement.split()),
                partitions_scanned=executed,
                partitions_in_plan=planned,
                planning_ms=float(document[0]["Planning Time"]),
                execution_ms=float(document[0]["Execution Time"]),
            )
        )
    return plans
