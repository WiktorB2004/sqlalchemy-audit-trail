"""Audit maintenance: run daily (cron, a Kubernetes CronJob, ...).

From the repository root::

    uv run python -m examples.fastapi_app.maintenance
"""

from __future__ import annotations

import asyncio
import logging
import sys

from audit_trail.maintenance import PartitionLockTimeoutError

from .db import RETENTION, maintenance, maintenance_engine

log = logging.getLogger(__name__)


async def main() -> int:
    manager = maintenance.maintenance
    try:
        created = await manager.aensure_partitions(months_ahead=3)
        dropped = await manager.adrop_expired(RETENTION)
        log.info("created %d partitions, dropped %d", len(created), len(dropped))
    except PartitionLockTimeoutError:
        log.warning("a lock was not granted in time; the next run retries")
    report = await manager.ahealth()
    if not report.ok:
        log.error("audit partitions need attention: %s", report)
        return 1
    log.info("audit partitions are healthy")
    return 0


async def run() -> int:
    try:
        return await main()
    finally:
        await maintenance.adispose()
        await maintenance_engine.dispose()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sys.exit(asyncio.run(run()))
