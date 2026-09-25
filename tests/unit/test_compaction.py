from __future__ import annotations

import copy
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TypeAlias
from uuid import UUID

import pytest

from audit_trail._compaction import ActivityData, ActivityRow, FieldChange, compact_rows
from audit_trail.context import ContextSnapshot
from audit_trail.serialization import JSONValue

CREATED = "entity.created"
UPDATED = "entity.updated"
DELETED = "entity.deleted"
CUSTOM = "shop.order_placed"

CREATED_AT = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)
CORRELATION = UUID("00000000-0000-0000-0000-000000000001")


def context_of(row_id: int) -> ContextSnapshot:
    return {"request_id": f"request-{row_id}"}


def row(
    row_id: int,
    verb: str,
    changes: dict[str, FieldChange] | None = None,
    *,
    object_id: str = "1",
    object_type: str = "Order",
    transaction_id: int = 1,
    actor_id: str | None = "u1",
    severity: int = 10,
    label: str | None = None,
    context_from: int | None = None,
) -> ActivityRow:
    data: ActivityData = {"v": 1, "context": context_of(context_from or row_id)}
    if changes is not None:
        data["changes"] = changes
    else:
        data["payload"] = {"order_id": row_id}
    return {
        "id": row_id,
        "transaction_id": transaction_id,
        "verb": verb,
        "severity": severity,
        "object_type": object_type,
        "object_id": object_id,
        "object_label": label,
        "target_type": None,
        "target_id": None,
        "actor_id": actor_id,
        "scope_id": None,
        "correlation_id": CORRELATION,
        "created_at": CREATED_AT,
        "data": data,
    }


@dataclass(frozen=True)
class Case:
    name: str
    raw: list[ActivityRow]
    expected: list[ActivityRow]

    def rows(self) -> list[ActivityRow]:
        """A deep copy of ``raw``, so no test can change the shared cases."""
        return copy.deepcopy(self.raw)


CASES = [
    Case(
        "updates merge to first old and last new",
        [
            row(1, UPDATED, {"a": [1, 2]}),
            row(2, UPDATED, {"a": [2, 3], "b": ["x", "y"]}),
        ],
        [row(1, UPDATED, {"a": [1, 3], "b": ["x", "y"]}, context_from=2)],
    ),
    Case(
        "a field that nets to no change is dropped",
        [
            row(1, UPDATED, {"a": [1, 2], "b": [0, 5]}),
            row(2, UPDATED, {"a": [2, 1]}),
        ],
        [row(1, UPDATED, {"b": [0, 5]}, context_from=2)],
    ),
    Case(
        "updates with no net change are hidden",
        [row(1, UPDATED, {"a": [1, 2]}), row(2, UPDATED, {"a": [2, 1]})],
        [],
    ),
    Case(
        "created and updated become created with final values",
        [
            row(1, CREATED, {"a": [None, 1], "b": [None, None]}),
            row(2, UPDATED, {"a": [1, 2]}),
        ],
        [row(1, CREATED, {"a": [None, 2], "b": [None, None]}, context_from=2)],
    ),
    Case(
        "updated and deleted become deleted with the first old values",
        [
            row(1, UPDATED, {"a": [1, 2]}),
            row(2, DELETED, {"a": [2, None], "b": [5, None], "c": [None, None]}),
        ],
        [
            row(
                1,
                DELETED,
                {"a": [1, None], "b": [5, None], "c": [None, None]},
                context_from=2,
            )
        ],
    ),
    Case(
        "created and deleted are hidden",
        [
            row(1, CREATED, {"a": [None, 1]}),
            row(2, UPDATED, {"a": [1, 2]}),
            row(3, DELETED, {"a": [2, None]}),
        ],
        [],
    ),
    Case(
        "deleted and created of the same id become the difference",
        [
            row(1, DELETED, {"a": [1, None], "b": [2, None]}),
            row(2, CREATED, {"a": [None, 1], "b": [None, 3]}),
        ],
        [row(1, UPDATED, {"b": [2, 3]}, context_from=2)],
    ),
    Case(
        "deleted and created with no difference are hidden",
        [
            row(1, DELETED, {"a": [1, None], "b": [None, None]}),
            row(2, CREATED, {"a": [None, 1], "b": [None, None]}),
        ],
        [],
    ),
    Case(
        "created, deleted and created again become created",
        [
            row(1, CREATED, {"a": [None, 1], "b": [None, 2]}),
            row(2, DELETED, {"a": [1, None], "b": [2, None]}),
            row(3, CREATED, {"a": [None, 3], "b": [None, None]}),
        ],
        [row(1, CREATED, {"a": [None, 3], "b": [None, None]}, context_from=3)],
    ),
    Case(
        "relationship changes merge net",
        [
            row(1, UPDATED, {"tags": {"added": ["1", "2"], "removed": ["7"]}}),
            row(2, UPDATED, {"tags": {"added": ["3", "7"], "removed": ["1", "8"]}}),
        ],
        [
            row(
                1,
                UPDATED,
                {"tags": {"added": ["2", "3"], "removed": ["8"]}},
                context_from=2,
            )
        ],
    ),
    Case(
        "a relationship with no net change is dropped",
        [
            row(1, CREATED, {"a": [None, 1], "tags": {"added": ["1"], "removed": []}}),
            row(2, UPDATED, {"tags": {"added": [], "removed": ["1"]}}),
        ],
        [row(1, CREATED, {"a": [None, 1]}, context_from=2)],
    ),
    Case(
        "redacted changes stay visible",
        [
            row(1, UPDATED, {"password": ["***", "***"]}),
            row(2, UPDATED, {"password": ["***", "***"]}),
        ],
        [row(1, UPDATED, {"password": ["***", "***"]}, context_from=2)],
    ),
    Case(
        "unknown markers pass through and are never equal",
        [
            row(1, UPDATED, {"settings": ["<unknown>", {"k": 1}]}),
            row(2, DELETED, {"settings": [{"k": 1}, None], "x": ["<unknown>", None]}),
            row(3, CREATED, {"settings": [None, {"k": 2}], "x": [None, "<unknown>"]}),
        ],
        [
            row(
                1,
                UPDATED,
                {"settings": ["<unknown>", {"k": 2}], "x": ["<unknown>", "<unknown>"]},
                context_from=3,
            )
        ],
    ),
    Case(
        "equality is on the JSON form",
        [
            row(1, UPDATED, {"flag": [1, 2], "doc": [{"x": 1, "y": 2}, {"x": 0}]}),
            row(2, UPDATED, {"flag": [2, True], "doc": [{"x": 0}, {"y": 2, "x": 1}]}),
        ],
        [row(1, UPDATED, {"flag": [1, True]}, context_from=2)],
    ),
    Case(
        "rows of different actors stay raw",
        [
            row(1, UPDATED, {"a": [1, 2]}, actor_id="u1"),
            row(2, UPDATED, {"a": [2, 3]}, actor_id="u2"),
        ],
        [
            row(1, UPDATED, {"a": [1, 2]}, actor_id="u1"),
            row(2, UPDATED, {"a": [2, 3]}, actor_id="u2"),
        ],
    ),
    Case(
        "an impossible verb sequence stays raw",
        [row(1, DELETED, {"a": [1, None]}), row(2, UPDATED, {"a": [None, 2]})],
        [row(1, DELETED, {"a": [1, None]}), row(2, UPDATED, {"a": [None, 2]})],
    ),
    Case(
        "a re-insert with relationship changes stays raw",
        [
            row(1, DELETED, {"a": [1, None]}),
            row(2, CREATED, {"a": [None, 1], "tags": {"added": ["1"], "removed": []}}),
        ],
        [
            row(1, DELETED, {"a": [1, None]}),
            row(2, CREATED, {"a": [None, 1], "tags": {"added": ["1"], "removed": []}}),
        ],
    ),
    Case(
        "the merged row takes the highest severity and the last label",
        [
            row(1, UPDATED, {"a": [1, 2]}, severity=10, label="old"),
            row(2, DELETED, {"a": [2, None]}, severity=30, label="new"),
            row(3, CREATED, {"a": [None, 3]}, severity=10, label="newer"),
        ],
        [row(1, UPDATED, {"a": [1, 3]}, severity=30, label="newer", context_from=3)],
    ),
    Case(
        "custom events keep their position",
        [
            row(1, UPDATED, {"a": [1, 2]}),
            row(2, CUSTOM, object_id="9"),
            row(3, UPDATED, {"a": [2, 3]}),
            row(4, UPDATED, {"a": [5, 6]}, object_id="2"),
            row(5, CUSTOM, object_id="1"),
        ],
        [
            row(1, UPDATED, {"a": [1, 3]}, context_from=3),
            row(2, CUSTOM, object_id="9"),
            row(4, UPDATED, {"a": [5, 6]}, object_id="2"),
            row(5, CUSTOM, object_id="1"),
        ],
    ),
    Case(
        "descending input stays descending",
        [
            row(4, UPDATED, {"a": [3, 4]}),
            row(3, UPDATED, {"a": [9, 8]}, object_id="2"),
            row(2, UPDATED, {"a": [2, 3]}),
            row(1, UPDATED, {"a": [1, 2]}),
        ],
        [
            row(3, UPDATED, {"a": [9, 8]}, object_id="2"),
            row(1, UPDATED, {"a": [1, 4]}, context_from=4),
        ],
    ),
    Case(
        "different transactions and object types are not merged",
        [
            row(1, UPDATED, {"a": [1, 2]}, transaction_id=1),
            row(2, UPDATED, {"a": [2, 3]}, transaction_id=2),
            row(3, UPDATED, {"a": [3, 4]}, transaction_id=2, object_type="Item"),
        ],
        [
            row(1, UPDATED, {"a": [1, 2]}, transaction_id=1),
            row(2, UPDATED, {"a": [2, 3]}, transaction_id=2),
            row(3, UPDATED, {"a": [3, 4]}, transaction_id=2, object_type="Item"),
        ],
    ),
]


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_compaction_rules(case: Case) -> None:
    assert compact_rows(case.rows()) == case.expected


def test_compact_false_returns_rows_unchanged() -> None:
    raw = CASES[0].rows()
    result = compact_rows(raw, compact=False)
    assert result == raw
    assert all(got is given for got, given in zip(result, raw, strict=True))


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_input_is_not_modified(case: Case) -> None:
    raw = case.rows()
    compact_rows(raw)
    assert raw == case.raw


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_compaction_is_idempotent(case: Case) -> None:
    once = compact_rows(case.rows())
    assert compact_rows(once) == once


# A replayed object: column values plus relationship members, or None when
# the object does not exist.
State: TypeAlias = dict[str, JSONValue | frozenset[str]] | None
ObjectKey: TypeAlias = tuple[int, str | None, str | None]


def initial_state(rows: Sequence[ActivityRow]) -> State:
    """The object's state before ``rows`` (sorted by id), as the rows imply it."""
    if rows[0]["verb"] == CREATED:
        return None
    state: dict[str, JSONValue | frozenset[str]] = {}
    seen: dict[str, set[str]] = {}
    for current in rows:
        for field, change in current["data"].get("changes", {}).items():
            if isinstance(change, list):
                state.setdefault(field, change[0])
                continue
            field_seen = seen.setdefault(field, set())
            # An id removed before it was ever added was a member already.
            members = {item for item in change["removed"] if item not in field_seen}
            if members:
                previous = state.get(field, frozenset())
                assert isinstance(previous, frozenset)
                state[field] = previous | members
            field_seen.update(change["added"], change["removed"])
    return state


def apply(state: State, current: ActivityRow) -> State:
    changes = current["data"].get("changes", {})
    if current["verb"] == DELETED:
        return None
    base: dict[str, JSONValue | frozenset[str]] = (
        {} if current["verb"] == CREATED or state is None else dict(state)
    )
    for field, change in changes.items():
        if isinstance(change, list):
            base[field] = change[1]
        else:
            members = base.get(field, frozenset())
            assert isinstance(members, frozenset)
            base[field] = (members - set(change["removed"])) | set(change["added"])
    # A relationship with no members is the same state as no entry.
    return {k: v for k, v in base.items() if v != frozenset()}


def entity_rows(rows: Sequence[ActivityRow]) -> dict[ObjectKey, list[ActivityRow]]:
    grouped: dict[ObjectKey, list[ActivityRow]] = {}
    for current in sorted(rows, key=lambda r: r["id"]):
        if current["verb"].startswith("entity."):
            key = (
                current["transaction_id"],
                current["object_type"],
                current["object_id"],
            )
            grouped.setdefault(key, []).append(current)
    return grouped


def replay(
    rows: Sequence[ActivityRow], initial: dict[ObjectKey, State]
) -> dict[ObjectKey, State]:
    final = dict(initial)
    for key, object_rows in entity_rows(rows).items():
        for current in object_rows:
            final[key] = apply(final[key], current)
    return final


MULTI_ROW = [case for case in CASES if len(case.raw) > 1]


@pytest.mark.parametrize("case", MULTI_ROW, ids=[case.name for case in MULTI_ROW])
def test_compacted_rows_replay_to_the_same_state(case: Case) -> None:
    raw = case.rows()
    initial = {key: initial_state(rows) for key, rows in entity_rows(raw).items()}
    assert replay(compact_rows(raw), initial) == replay(raw, initial)


def test_replay_detects_a_lost_change() -> None:
    raw = CASES[0].rows()
    initial = {key: initial_state(rows) for key, rows in entity_rows(raw).items()}
    assert replay(raw[:1], initial) != replay(raw, initial)


ERASED = "[erased]"


def test_erased_ids_never_cancel() -> None:
    raw = [
        row(1, UPDATED, {"tags": {"added": [ERASED, "3"], "removed": []}}),
        row(2, UPDATED, {"tags": {"added": [], "removed": [ERASED, "3"]}}),
    ]
    (merged,) = compact_rows(raw)
    assert merged["data"]["changes"] == {
        "tags": {"added": [ERASED], "removed": [ERASED]}
    }


def test_erased_ids_are_not_deduplicated() -> None:
    raw = [
        row(1, UPDATED, {"tags": {"added": ["4", ERASED], "removed": [ERASED]}}),
        row(2, UPDATED, {"tags": {"added": [ERASED], "removed": [ERASED, "5"]}}),
    ]
    (merged,) = compact_rows(raw)
    assert merged["data"]["changes"] == {
        "tags": {"added": ["4", ERASED, ERASED], "removed": ["5", ERASED, ERASED]}
    }
