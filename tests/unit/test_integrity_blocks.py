"""The block format of the hash chain, frozen in golden vectors.

A change to any vector here is a format change: it needs a new ``v`` and new
context strings, never an edit of version 1.
"""

from __future__ import annotations

import hashlib
import itertools
import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from audit_trail.integrity._block import (
    ZERO_HASH,
    Segment,
    SegmentBuilder,
    activity_leaf_row,
    block_hash,
    clear_data,
    fork_body,
    genesis_body,
    parse_body,
    seal_body,
    transaction_leaf_row,
)
from audit_trail.integrity._canonical import CanonicalEncodingError, canonical
from audit_trail.integrity._codec import rfc3339
from audit_trail.integrity._commit import leaf_hash
from audit_trail.integrity._merkle import MerkleTree, merkle_root, node_hash

VECTOR_DIR = Path(__file__).parent.parent / "fixtures" / "integrity" / "vectors"
VECTORS = json.loads((VECTOR_DIR / "blocks.json").read_text())


def reference_root(leaves: Sequence[bytes]) -> bytes:
    """RFC 6962 section 2.1, written recursively."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    split = 1
    while split * 2 < len(leaves):
        split *= 2
    return node_hash(reference_root(leaves[:split]), reference_root(leaves[split:]))


@pytest.mark.parametrize(
    "case", VECTORS["merkle"], ids=[c["name"] for c in VECTORS["merkle"]]
)
def test_merkle_vectors(case: dict[str, Any]) -> None:
    leaves = [bytes.fromhex(leaf) for leaf in case["leaves"]]
    assert leaves == [leaf_hash({"n": n}) for n in range(len(leaves))]
    assert merkle_root(leaves).hex() == case["root"]
    assert reference_root(leaves).hex() == case["root"]


def test_streaming_root_matches_the_recursive_definition() -> None:
    leaves = [leaf_hash({"n": n}) for n in range(70)]
    tree = MerkleTree()
    for count, leaf in enumerate(leaves, start=1):
        tree.add(leaf)
        assert tree.size == count
        assert tree.root() == reference_root(leaves[:count])


def test_a_node_hash_is_rfc_6962() -> None:
    left, right = b"\x11" * 32, b"\x22" * 32
    assert node_hash(left, right) == hashlib.sha256(b"\x01" + left + right).digest()


@pytest.mark.parametrize(
    "case", VECTORS["blocks"], ids=[c["name"] for c in VECTORS["blocks"]]
)
def test_block_vectors(case: dict[str, str]) -> None:
    prev, body = bytes.fromhex(case["prev_hash"]), case["body"].encode()
    assert block_hash(prev, body).hex() == case["block_hash"]
    preimage = b"sqlalchemy-audit-trail/block/v1\x00" + prev + body
    assert hashlib.sha256(preimage).hexdigest() == case["block_hash"]
    # Stored exactly as hashed: canonical, so parsing and re-encoding gives
    # the same bytes.
    parsed = parse_body(body)
    assert canonical(parsed) == body
    assert parsed["v"] == 1


def test_the_vectors_form_one_chain() -> None:
    chain = VECTORS["blocks"]
    assert chain[0]["prev_hash"] == ZERO_HASH.hex()
    for before, after in itertools.pairwise(chain):
        assert after["prev_hash"] == before["block_hash"]
    seqs = [parse_body(case["body"].encode())["seq"] for case in chain]
    assert seqs == list(range(1, len(chain) + 1))


def body_of(name: str) -> bytes:
    (case,) = [c for c in VECTORS["blocks"] if c["name"] == name]
    return str(case["body"]).encode()


def test_body_builders_give_the_vectors() -> None:
    chain = "3f2b8c1e-6a4d-4e2f-9c1b-7d5e3a2f1b0c"
    assert genesis_body(chain, 759) == body_of("genesis")
    segments = [
        Segment(
            "activity.10",
            "audit_activity_10_p2026_11",
            3,
            merkle_root([leaf_hash({"n": n}) for n in range(3)]),
        ),
        Segment("transaction", "audit_transaction_p2026_11", 1, leaf_hash({"n": 0})),
    ]
    assert seal_body(chain, 2, 759, 4294968058, segments) == body_of(
        "seal with two segments"
    )
    assert seal_body(chain, 3, 4294968058, 4294968100, []) == body_of(
        "seal without segments"
    )
    blocks = {c["name"]: c for c in VECTORS["blocks"]}
    floors = {"transaction": 50, "activity.10": 148, "activity.30": 150}
    window = fork_body(
        chain,
        4,
        incarnation=2,
        reason="pg_restore into a managed service",
        prior_seq=3,
        prior_hash=bytes.fromhex(blocks["seal without segments"]["block_hash"]),
        xid_at_fork=1549,
        id_floor=floors,
        id_count={"transaction": 50, "activity.10": 140, "activity.30": 150},
    )
    assert window == body_of("fork with an id window")
    plain = fork_body(
        chain,
        5,
        incarnation=3,
        reason="PITR à 03:00",
        prior_seq=4,
        prior_hash=bytes.fromhex(blocks["fork with an id window"]["block_hash"]),
        xid_at_fork=1600,
        id_floor=None,
        id_count=None,
    )
    assert plain == body_of("fork without an id window")
    fork = parse_body(plain)
    assert (fork["id_floor"], fork["id_count"]) == (None, None)


def test_block_hash_checks_prev_hash() -> None:
    with pytest.raises(ValueError, match="32-byte"):
        block_hash(b"", b"{}")


def test_parse_body_needs_an_object() -> None:
    with pytest.raises(ValueError, match="JSON object"):
        parse_body(b"[]")


def test_segments_are_sorted_and_counted() -> None:
    builder = SegmentBuilder()
    rows = [("transaction", "t_p1", {"n": 0}), ("activity.10", "a_p1", {"n": 1})]
    rows += [("activity.10", "a_p1", {"n": 2}), ("activity.10", "a_p2", {"n": 3})]
    for stream, partition, row in rows:
        builder.add(stream, partition, row)
    assert builder.rows == 4
    assert [(s.stream, s.partition, s.rows) for s in builder.segments()] == [
        ("activity.10", "a_p1", 2),
        ("activity.10", "a_p2", 1),
        ("transaction", "t_p1", 1),
    ]
    (first, *_rest) = builder.segments()
    assert first.root == node_hash(leaf_hash({"n": 1}), leaf_hash({"n": 2}))


# -- leaf rows -----------------------------------------------------------------


def test_timestamps_are_utc_with_six_fraction_digits() -> None:
    plus_one = timezone(timedelta(hours=1))
    assert rfc3339(datetime(2026, 1, 2, 4, 5, 6, tzinfo=plus_one)) == (
        "2026-01-02T03:05:06.000000Z"
    )
    assert rfc3339(datetime(2026, 1, 2, 3, 4, 5, 7, tzinfo=UTC)) == (
        "2026-01-02T03:04:05.000007Z"
    )
    with pytest.raises(CanonicalEncodingError, match="naive"):
        rfc3339(datetime(2026, 1, 2))


TRANSACTION: dict[str, Any] = {
    "id": 1,
    "issued_at": datetime(2026, 1, 2, tzinfo=UTC),
    "actor_type": "user",
    "actor_id": "ann",
    "actor_label": "Ann",
    "remote_addr": "10.0.0.1",
    "user_agent": "Firefox",
    "method": None,
    "path": None,
    "channel": None,
    "auth_method": None,
    "request_id": UUID(int=1),
    "correlation_id": None,
    "meta": {"tenant": 1},
    "xid": 900,
    "seal_commitments": {"actor": "AAAA"},
    "seal_salts": {"actor": "BBBB"},
    "seal_erased": None,
}


def test_a_transaction_leaf_survives_scrub_actor() -> None:
    leaf = transaction_leaf_row(TRANSACTION)
    assert "actor_label" not in leaf
    assert "seal_salts" not in leaf
    assert leaf["request_id"] == str(UUID(int=1))
    scrubbed = {
        **TRANSACTION,
        "actor_label": None,
        "remote_addr": None,
        "user_agent": None,
        "meta": None,
        "seal_salts": {},
        "seal_erased": {"actor": "950"},
    }
    assert transaction_leaf_row(scrubbed) == leaf
    assert transaction_leaf_row({**TRANSACTION, "actor_id": "bob"}) != leaf


ACTIVITY: dict[str, Any] = {
    "id": 2,
    "transaction_id": 1,
    "verb": "entity.updated",
    "severity": 10,
    "object_type": "Doc",
    "object_id": "1",
    "object_label": "Doc One",
    "target_type": None,
    "target_id": None,
    "actor_id": "ann",
    "scope_id": None,
    "correlation_id": None,
    "created_at": datetime(2026, 1, 2, tzinfo=UTC),
    "data": {
        "v": 1,
        "changes": {"title": ["Old", "Doc One"]},
        "context": {"actor_type": "user", "actor_label": "Ann", "meta": {"a": 1}},
    },
    "xid": 900,
    "seal_commitments": {"label": "A", "changes": "B", "actor": "C"},
    "seal_salts": {"label": "D", "changes": "E", "actor": "F"},
    "seal_erased": None,
}


def test_an_activity_leaf_survives_both_scrubs() -> None:
    leaf = activity_leaf_row(ACTIVITY)
    assert leaf["data"] == {"v": 1, "context": {"actor_type": "user"}}
    assert "object_label" not in leaf
    scrubbed = {
        **ACTIVITY,
        "object_label": None,
        "data": {
            "v": 1,
            "changes": {"title": ["[erased]", "[erased]"]},
            "context": {"actor_type": "user"},
        },
        "seal_salts": {},
        "seal_erased": {"label": "950", "changes": "950", "actor": "951"},
    }
    assert activity_leaf_row(scrubbed) == leaf
    tampered = {**ACTIVITY, "data": {**ACTIVITY["data"], "v": 2}}
    assert activity_leaf_row(tampered) != leaf
    assert activity_leaf_row({**ACTIVITY, "verb": "entity.deleted"}) != leaf


def test_clear_data_keeps_unknown_keys() -> None:
    data = {"v": 1, "payload": {"a": 1}, "extra": [1], "context": "not a mapping"}
    assert clear_data(data) == {"v": 1, "extra": [1], "context": "not a mapping"}
