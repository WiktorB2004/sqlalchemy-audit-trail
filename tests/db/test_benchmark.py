"""The benchmark runner, at tiny sizes, so it does not rot between full runs.

The run itself goes through the command line in a subprocess: it defines the
benchmark's events, and ``AuditTrail(events=None)`` would discover them in
this process.
"""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine, text

from audit_trail import AuditTrail
from benchmark import write
from benchmark.models import BenchAudited
from benchmark.run_benchmark import ROOT, SCHEMA_VERSION, Report

BATCHES = [1, 3]


def test_benchmark_runs_and_writes_its_json(
    database_url: str, engine: Engine, tmp_path: Path
) -> None:
    command = [
        sys.executable,
        "-m",
        "benchmark.run_benchmark",
        f"--database-url={database_url}",
        f"--output-dir={tmp_path}",
        "--batch-sizes=1,3",
        "--iterations=3",
        "--iterations-large=2",
        "--large-batch=3",
        "--warmup=1",
        "--block=2",
        "--activity-rows=2000",
        "--read-iterations=2",
        "--read-warmup=1",
        "--quiet",
    ]
    subprocess.run(command, cwd=ROOT, check=True, timeout=300)

    [path] = tmp_path.glob("run_*.json")
    written = json.loads(path.read_text(encoding="utf-8"))
    assert written["schema_version"] == SCHEMA_VERSION
    assert set(written) == set(Report.__annotations__)
    assert written["environment"]["postgres"]["version"]
    assert written["round_trip"]["p50_ms"] > 0

    writes = written["write"]
    assert writes["preconditions"] == list(write.PRECONDITIONS)
    kinds = {(c["operation"], c["objects"], c["variant"]) for c in writes["cases"]}
    expected = {
        (operation, objects, variant)
        for operation in ("insert", "update")
        for objects in BATCHES
        for variant in ("plain", "disabled", "audited", "audited_raise")
    } | {
        (operation, 1, variant)
        for operation in ("log", "log_durable")
        for variant in ("plain", "audited", "audited_raise")
    }
    assert kinds == expected
    for case in writes["cases"]:
        large = case["objects"] >= 3 and case["operation"] in ("insert", "update")
        assert case["iterations"] == (2 if large else 3)
        assert 0 < case["min_ms"] <= case["p50_ms"] <= case["p95_ms"]
        assert case["statements_per_op"] >= 1
    by_kind = {(c["operation"], c["objects"], c["variant"]): c for c in writes["cases"]}
    # Capturing writes the transaction row and the entries: more statements.
    for operation in ("insert", "update"):
        for objects in BATCHES:
            plain = by_kind[operation, objects, "plain"]["statements_per_op"]
            disabled = by_kind[operation, objects, "disabled"]["statements_per_op"]
            audited = by_kind[operation, objects, "audited"]["statements_per_op"]
            raising = by_kind[operation, objects, "audited_raise"]
            assert disabled == plain
            assert audited > plain
            # on_error="raise" skips the savepoint and its release.
            assert raising["statements_per_op"] == audited - 2
    overhead = {
        (o["operation"], o["objects"], o["variant"]) for o in writes["overhead"]
    }
    assert overhead == {kind for kind in expected if kind[2] != "plain"}

    reads = written["read"]
    dataset = reads["dataset"]
    assert dataset["activity_rows"] >= 2000
    assert dataset["transaction_rows"] == 1000
    assert dataset["partitions"]["activity"] == 4 * 16
    assert dataset["seed_s"] > 0
    names = [case["name"] for case in reads["cases"]]
    assert "list_groups first page" in names
    assert "list_groups first page, 30-day window" in names
    assert "list_groups next page" in names
    assert "list_groups by actor" in names
    assert "object_history" in names
    assert "access_summary" in names
    for case in reads["cases"]:
        assert 0 < case["p50_ms"] <= case["p95_ms"]
        assert case["statements"], case["name"]
        assert case["partitions_scanned"] >= 1
        for statement in case["statements"]:
            assert statement["sql"].startswith("SELECT")
            assert statement["planning_ms"] >= 0
            assert statement["execution_ms"] >= 0
            assert (
                len(statement["partitions_scanned"]) <= statement["partitions_in_plan"]
            )
    first = next(c for c in reads["cases"] if c["name"] == "list_groups first page")
    assert first["groups"] == 50

    run_id = path.stem.rsplit("_", 1)[1]
    with engine.connect() as conn:
        left = conn.execute(
            text("SELECT nspname FROM pg_namespace WHERE nspname LIKE :p"),
            {"p": f"bench_{run_id}_%"},
        ).all()
    assert left == []


@pytest.fixture
def write_setup(engine: Engine) -> Iterator[write.Setup]:
    name = f"bench_{uuid.uuid4().hex[:8]}"
    with engine.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{name}_app"'))
    app_engine = engine.execution_options(schema_translate_map={None: f"{name}_app"})
    setup = write.setup(engine, app_engine, f"{name}_write", events=())
    yield setup
    setup.audit.dispose()
    setup.audit_raise.dispose()
    with engine.begin() as conn:
        for schema in (f"{name}_app", f"{name}_write"):
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))


def test_check_setup_accepts_the_real_setup(write_setup: write.Setup) -> None:
    assert write.check_setup(write_setup) == list(write.PRECONDITIONS)


@pytest.mark.parametrize(
    ("swap", "failed"),
    [
        ("plain", "plain session has no trail installed"),
        # disabled and audited share a factory; disabled is checked first.
        ("audited", "disabled session has the on_error='log' trail"),
        ("audited_raise", "audited_raise session has the on_error='raise' trail"),
    ],
)
def test_check_setup_rejects_a_wrong_session(
    write_setup: write.Setup, swap: str, failed: str
) -> None:
    # Each variant gets another variant's session factory.
    sessions = write_setup.sessions
    others = {
        "plain": sessions.audited,
        "audited": sessions.plain,
        "audited_raise": sessions.audited,
    }
    broken = write_setup._replace(sessions=sessions._replace(**{swap: others[swap]}))
    with pytest.raises(write.SetupError, match=failed):
        write.check_setup(broken)


def test_check_setup_rejects_an_audited_baseline(
    write_setup: write.Setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(write, "_model", lambda variant: BenchAudited)
    with pytest.raises(write.SetupError, match="plain model is not Audited"):
        write.check_setup(write_setup)


def test_importing_the_benchmark_defines_no_events(engine: Engine) -> None:
    # This module imported every benchmark module. Discovery must not find
    # benchmark events in this process: with a host's own severity enum,
    # their built-in Severity would make AuditTrail(events=None) fail.
    trail = AuditTrail(engine, events=None)
    assert not [v for v in trail.registry.events if v.startswith("benchmark.")]


def test_bench_events_use_their_own_prefix_and_the_default_severity() -> None:
    check = (
        "from audit_trail import Severity\n"
        "from benchmark.models import bench_events\n"
        "members = list(bench_events())\n"
        "assert {m.value for m in members} == "
        "{'benchmark.viewed', 'benchmark.exported'}\n"
        "assert all(isinstance(m.severity, Severity) for m in members)\n"
    )
    subprocess.run([sys.executable, "-c", check], cwd=ROOT, check=True, timeout=60)
