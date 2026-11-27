"""``require_replicated``: what ``synchronous_standby_names`` asks for."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from audit_trail.integrity import _anchor
from audit_trail.integrity._anchor import (
    ReplicationError,
    SyncRule,
    replication_state,
    sync_rule,
    wait_replicated,
)


@pytest.mark.parametrize(
    ("names", "rule"),
    [
        ("FIRST 2 (s1, s2, s3)", ("FIRST", 2)),
        ("first 1 (s1)", ("FIRST", 1)),
        ("2 (s1, s2)", ("FIRST", 2)),
        ("ANY 2 (s1, s2, s3)", ("ANY", 2)),
        ("any 1(*)", ("ANY", 1)),
        ('ANY 3 ("a b", "c(d)", e)', ("ANY", 3)),
        ("s1, s2", ("FIRST", 1)),
        ("*", ("FIRST", 1)),
        ("first", ("FIRST", 1)),  # a standby named first
        ('"ANY 2 (s1)"', ("FIRST", 1)),  # one quoted name
        ("", None),
        ("   ", None),
        (None, None),
        ("FIRST 0 (s1)", None),
    ],
)
def test_synchronous_standby_names_is_parsed(
    names: str | None, rule: tuple[str, int] | None
) -> None:
    assert sync_rule(names) == rule


def test_replication_state_needs_as_many_standbys_as_asked() -> None:
    first1: SyncRule = ("FIRST", 1)
    first2: SyncRule = ("FIRST", 2)
    any1: SyncRule = ("ANY", 1)
    any2: SyncRule = ("ANY", 2)
    assert replication_state([("sync", True)], None) == "none"
    assert replication_state([], first1) == "none"
    assert replication_state([("async", True), ("potential", True)], first1) == ("none")
    assert replication_state([("sync", True)], first1) == "confirmed"
    assert replication_state([("sync", None)], first1) == "waiting"
    # FIRST 2: both standbys the server marks sync, not one of them.
    assert replication_state([("sync", True)], first2) == "none"
    assert replication_state([("sync", True), ("sync", False)], first2) == "waiting"
    assert replication_state([("sync", True), ("sync", True)], first2) == "confirmed"
    # ANY 2: two of the quorum, not any one.
    quorum = [("quorum", True), ("quorum", False), ("quorum", False)]
    assert replication_state(quorum, any1) == "confirmed"
    assert replication_state(quorum, any2) == "waiting"
    assert replication_state([("quorum", True)], any2) == "none"
    assert replication_state([*quorum[:2], ("quorum", True)], any2) == "confirmed"
    assert replication_state([("sync", True)], any1) == "none"


class FakeConnection:
    """Enough of a connection for the WAL position read."""

    def begin(self) -> Any:
        return self

    def __enter__(self) -> FakeConnection:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute(self, *args: Any) -> Any:
        return self

    def scalar(self) -> str:
        return "0/16B3748"


CONNECTION: Any = FakeConnection()


def polls(*answers: Any) -> Any:
    replies = list(answers)

    def poll(connection: Any, lsn: str) -> Any:
        reply = replies.pop(0) if len(replies) > 1 else replies[0]
        if isinstance(reply, Exception):
            raise reply
        return reply

    return poll


def test_a_standby_that_reconnects_is_waited_for(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gone: tuple[str, list[Any]] = ("FIRST 1 (s1)", [])
    back = ("FIRST 1 (s1)", [("sync", True)])
    monkeypatch.setattr(_anchor, "_poll", polls(gone, gone, back))
    lsn = wait_replicated(CONNECTION, 7, timedelta(seconds=30))
    assert lsn == "0/16B3748"


def test_a_standby_that_stays_away_is_no_sync_standby(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_anchor, "NO_STANDBY_GRACE", timedelta(milliseconds=200))
    monkeypatch.setattr(_anchor, "_poll", polls(("ANY 2 (s1, s2)", [("quorum", True)])))
    with pytest.raises(ReplicationError) as info:
        wait_replicated(CONNECTION, 7, timedelta(seconds=30))
    assert (info.value.reason, info.value.seq) == ("NO_SYNC_STANDBY", 7)
    assert "ANY 2" in str(info.value)
    # Nothing synchronous configured: no wait.
    monkeypatch.setattr(_anchor, "NO_STANDBY_GRACE", timedelta(hours=1))
    monkeypatch.setattr(_anchor, "_poll", polls(("", [])))
    with pytest.raises(ReplicationError) as info:
        wait_replicated(CONNECTION, 7, timedelta(seconds=30))
    assert info.value.reason == "NO_SYNC_STANDBY"


def test_an_error_while_polling_is_a_replication_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_anchor, "_poll", polls(RuntimeError("connection lost")))
    with pytest.raises(ReplicationError) as info:
        wait_replicated(CONNECTION, 7, timedelta(seconds=30))
    assert (info.value.reason, info.value.seq, info.value.lsn) == (
        "CHECK_FAILED",
        7,
        "0/16B3748",
    )
    assert isinstance(info.value.__cause__, RuntimeError)
