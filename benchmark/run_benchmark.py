"""What does auditing cost? Write overhead and read latency on PostgreSQL.

Full run (starts a throwaway postgres:18 container with testcontainers):

    uv run python -m benchmark.run_benchmark

Against a server you already have (the runner creates and drops its own
schemas there):

    uv run python -m benchmark.run_benchmark --database-url postgresql+psycopg://...

Raw results are written as JSON to ``benchmark/results/`` (gitignored).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

from sqlalchemy import Engine, create_engine, make_url, text

from benchmark import read, write
from benchmark.env import Environment, environment
from benchmark.stats import summarize, timed

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = ROOT / "benchmark" / "results"
SCHEMA_VERSION = 1


class Config(TypedDict):
    """The sizes a run used."""

    batch_sizes: list[int]
    iterations: int
    iterations_large: int
    large_batch: int
    warmup: int
    block: int
    activity_rows: int
    read_iterations: int
    read_warmup: int


class RoundTrip(TypedDict):
    """Latency of ``SELECT 1`` on an open connection: the cost of one round trip."""

    iterations: int
    p50_ms: float
    p95_ms: float


class Report(TypedDict):
    """The JSON a run writes."""

    schema_version: int
    created_at: str
    duration_s: float
    config: Config
    environment: Environment
    round_trip: RoundTrip
    write: write.WriteResult | None
    read: read.ReadResult | None


def _sizes(value: str) -> list[int]:
    try:
        sizes = [int(part) for part in value.split(",") if part.strip()]
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"not a list of integers: {value}") from error
    if not sizes or min(sizes) < 1:
        raise argparse.ArgumentTypeError("batch sizes must be >= 1")
    return sizes


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the command line."""
    parser = argparse.ArgumentParser(
        description="Measure sqlalchemy-audit-trail write overhead and read latency."
    )
    parser.add_argument(
        "--database-url",
        help="PostgreSQL URL (driver is set to psycopg). Default: start a "
        "testcontainers container.",
    )
    parser.add_argument("--image", default="postgres:18", help="Container image.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--batch-sizes", type=_sizes, default=[1, 10, 100])
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument(
        "--iterations-large",
        type=int,
        default=300,
        help="Iterations for batches of --large-batch objects or more.",
    )
    parser.add_argument("--large-batch", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument(
        "--block", type=int, default=50, help="Iterations per interleaved block."
    )
    parser.add_argument("--activity-rows", type=int, default=5_000_000)
    parser.add_argument("--read-iterations", type=int, default=200)
    parser.add_argument("--read-warmup", type=int, default=20)
    parser.add_argument("--skip-write", action="store_true")
    parser.add_argument("--skip-read", action="store_true")
    parser.add_argument(
        "--keep", action="store_true", help="Keep the benchmark schemas."
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    for name in ("iterations", "iterations_large", "block", "read_iterations"):
        if getattr(args, name) < 1:
            parser.error(f"--{name.replace('_', '-')} must be >= 1")
    for name in ("warmup", "read_warmup"):
        if getattr(args, name) < 0:
            parser.error(f"--{name.replace('_', '-')} must be >= 0")
    if args.activity_rows < 2:
        parser.error("--activity-rows must be >= 2")
    return args


@contextmanager
def _database(args: argparse.Namespace) -> Iterator[tuple[str, str]]:
    # (psycopg URL, description of where the database runs)
    if args.database_url:
        url = (
            make_url(args.database_url)
            .set(drivername="postgresql+psycopg")
            .render_as_string(hide_password=False)
        )
        yield url, "given by --database-url"
        return
    from testcontainers.community.postgres import PostgresContainer

    with PostgresContainer(args.image, driver="psycopg") as pg:
        yield (
            pg.get_connection_url(),
            f"Docker {args.image} (testcontainers), stock config",
        )


def _config(args: argparse.Namespace) -> Config:
    return Config(
        batch_sizes=list(args.batch_sizes),
        iterations=args.iterations,
        iterations_large=args.iterations_large,
        large_batch=args.large_batch,
        warmup=args.warmup,
        block=args.block,
        activity_rows=args.activity_rows,
        read_iterations=args.read_iterations,
        read_warmup=args.read_warmup,
    )


def _round_trip(engine: Engine, iterations: int) -> RoundTrip:
    with engine.connect() as conn:
        for _ in range(10):
            conn.execute(text("SELECT 1"))
        summary = summarize(
            [timed(lambda: conn.execute(text("SELECT 1"))) for _ in range(iterations)]
        )
    return RoundTrip(
        iterations=summary.iterations, p50_ms=summary.p50_ms, p95_ms=summary.p95_ms
    )


def _drop(engine: Engine, schemas: list[str]) -> None:
    with engine.begin() as conn:
        for name in schemas:
            conn.execute(text(f'DROP SCHEMA IF EXISTS "{name}" CASCADE'))


def _print_tables(report: Report) -> None:
    trip = report["round_trip"]
    print(f"\nround trip (SELECT 1): p50 {trip['p50_ms']:.3f} ms")
    result = report["write"]
    if result is not None:
        print("\nwrite (ms per transaction)")
        print(
            f"{'operation':<12}{'n':>5}{'variant':>14}{'p50':>9}{'p95':>9}{'obj/s':>10}"
        )
        for case in result["cases"]:
            print(
                f"{case['operation']:<12}{case['objects']:>5}{case['variant']:>14}"
                f"{case['p50_ms']:>9.3f}{case['p95_ms']:>9.3f}"
                f"{case['objects_per_s']:>10.0f}{case['statements_per_op']:>7.1f}"
            )
        print("\noverhead vs plain")
        for row in result["overhead"]:
            print(
                f"{row['operation']:<12}{row['objects']:>5}{row['variant']:>14}"
                f"  p50 {row['p50_pct']:+7.1f}%  p95 {row['p95_pct']:+7.1f}%"
                f"  {row['added_p50_ms']:+.3f} ms"
                f"  {row['added_p50_us_per_object']:.0f} us/object"
            )
    reads = report["read"]
    if reads is not None:
        print("\nread (ms)")
        for read_case in reads["cases"]:
            print(
                f"{read_case['name']:<40}{read_case['p50_ms']:>9.3f}"
                f"{read_case['p95_ms']:>9.3f}"
                f"  partitions {read_case['partitions_scanned']}"
                f"  statements {len(read_case['statements'])}"
                f"  plan {read_case['explain_planning_ms']:.2f}"
                f"  exec {read_case['explain_execution_ms']:.2f}"
            )


def run(args: argparse.Namespace) -> tuple[Report, Path]:
    """Run the benchmark and write its JSON; return the report and the path."""

    def progress(message: str) -> None:
        if not args.quiet:
            print(message, flush=True)

    started = time.perf_counter()
    run_id = uuid.uuid4().hex[:8]
    app_schema = f"bench_{run_id}_app"
    write_schema = f"bench_{run_id}_write"
    read_schema = f"bench_{run_id}_read"
    with _database(args) as (url, database):
        engine = create_engine(url)
        try:
            progress(f"database: {database}")
            env = environment(engine, database)
            round_trip = _round_trip(engine, args.iterations)
            with engine.begin() as conn:
                conn.execute(text(f'CREATE SCHEMA "{app_schema}"'))
            write_result = None
            read_result = None
            try:
                if not args.skip_write:
                    app_engine = engine.execution_options(
                        schema_translate_map={None: app_schema}
                    )
                    write_result = write.run(
                        engine,
                        app_engine,
                        write_schema,
                        write.WriteConfig(
                            batch_sizes=tuple(args.batch_sizes),
                            iterations=args.iterations,
                            iterations_large=args.iterations_large,
                            large_batch=args.large_batch,
                            warmup=args.warmup,
                            block=args.block,
                        ),
                        progress,
                    )
                if not args.skip_read:
                    read_result = read.run(
                        engine,
                        read_schema,
                        read.ReadConfig(
                            activity_rows=args.activity_rows,
                            iterations=args.read_iterations,
                            warmup=args.read_warmup,
                        ),
                        progress,
                    )
            finally:
                if not args.keep:
                    _drop(engine, [app_schema, write_schema, read_schema])
        finally:
            engine.dispose()

    report = Report(
        schema_version=SCHEMA_VERSION,
        created_at=datetime.now(timezone.utc).isoformat(),
        duration_s=time.perf_counter() - started,
        config=_config(args),
        environment=env,
        round_trip=round_trip,
        write=write_result,
        read=read_result,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = args.output_dir / f"run_{stamp}_{run_id}.json"
    path.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
    if not args.quiet:
        _print_tables(report)
        print(f"\nWrote {path} in {report['duration_s']:.0f} s")
    return report, path


def main(argv: Sequence[str] | None = None) -> None:
    """Command-line entry point."""
    run(parse_args(argv))


if __name__ == "__main__":
    main(sys.argv[1:])
