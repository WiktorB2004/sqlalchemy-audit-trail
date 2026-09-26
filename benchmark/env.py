"""The machine, server and library versions a run was measured on."""

from __future__ import annotations

import os
import platform
import subprocess
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TypedDict

from sqlalchemy import Engine, text

ROOT = Path(__file__).resolve().parents[1]

PG_SETTINGS = (
    "shared_buffers",
    "work_mem",
    "effective_cache_size",
    "maintenance_work_mem",
    "max_parallel_workers_per_gather",
    "jit",
    "random_page_cost",
    "synchronous_commit",
    "fsync",
)


class Postgres(TypedDict):
    """The PostgreSQL server."""

    version: str
    server: str
    settings: dict[str, str]


class Environment(TypedDict):
    """Where a run was measured."""

    cpu: str
    threads: int | None
    ram_gb: float | None
    os: str
    database: str
    postgres: Postgres
    python: str
    sqlalchemy: str
    psycopg: str
    audit_trail: str
    commit: str | None


def _cpu() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or platform.machine()


def _ram_gb() -> float | None:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return round(int(line.split()[1]) / 1024 / 1024, 1)
    except OSError:
        pass
    return None


def _package(name: str) -> str:
    try:
        return version(name)
    except PackageNotFoundError:
        return "not installed"


def _commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip() or None


def environment(engine: Engine, database: str) -> Environment:
    """Describe the machine, the server and the versions in use.

    Args:
        engine: Engine connected to the benchmark database.
        database: How the database was provided, e.g. the container image.
    """
    with engine.connect() as conn:
        server = str(conn.execute(text("SELECT version()")).scalar_one())
        short = str(conn.execute(text("SHOW server_version")).scalar_one())
        rows = conn.execute(
            text(
                "SELECT name, setting, unit FROM pg_settings WHERE name = ANY(:names)"
            ),
            {"names": list(PG_SETTINGS)},
        )
        settings = {
            name: setting if unit is None else f"{setting} ({unit})"
            for name, setting, unit in rows
        }
    return Environment(
        cpu=_cpu(),
        threads=os.cpu_count(),
        ram_gb=_ram_gb(),
        os=platform.platform(),
        database=database,
        postgres=Postgres(version=short, server=server, settings=settings),
        python=platform.python_version(),
        sqlalchemy=_package("sqlalchemy"),
        psycopg=_package("psycopg"),
        audit_trail=_package("sqlalchemy-audit-trail"),
        commit=_commit(),
    )
