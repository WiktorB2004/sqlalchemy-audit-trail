"""Read latency on a large, synthetic audit log.

The log is seeded with plain SQL (``generate_series``), not through the ORM:
``audit_transaction`` rows spread evenly over the last 365 days, and one to
three ``audit_activity`` rows per transaction (two on average) with the
transaction's ``issued_at`` as ``created_at``, as the library writes them.

Row mix (deterministic, from a hash of the row number):

- severity: INFO 70%, NOTICE 20%, WARNING 8%, CRITICAL 2%;
- verb: 10% ``person.viewed`` on 1,000 ``Person`` ids; otherwise
  ``entity.created`` (10%), ``entity.deleted`` (5%) or ``entity.updated``
  on nine object types with 100,000 ids each;
- 20% of the entity rows have an ``Order`` target (5,000 ids);
- 1,000 actors, 50 scopes.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import NamedTuple, TypedDict

from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from audit_trail import ALL_HISTORY, AuditTrail, Cursor, Page
from audit_trail.maintenance import ensure_partitions
from audit_trail.migrations import create_audit_tables
from benchmark.explain import StatementPlan, explain_call
from benchmark.stats import summarize, timed

WINDOW = timedelta(days=30)
SPAN = timedelta(days=365)

HISTORY_OBJECT = ("Order", "42")
ACCESS_OBJECT = ("Person", "7")
ACCESS_VERB = "person.viewed"
ACTOR = "user-7"

SEVERITY_MIX = {"INFO": 0.70, "NOTICE": 0.20, "WARNING": 0.08, "CRITICAL": 0.02}

_TRANSACTIONS = """
INSERT INTO {transaction} (
    id, issued_at, actor_type, actor_id, actor_label, remote_addr, user_agent,
    method, path, channel, auth_method, request_id, correlation_id
)
OVERRIDING SYSTEM VALUE
SELECT
    g,
    CAST(:start AS timestamptz) + (g - 1) * CAST(:step AS interval),
    'user',
    'user-' || (g % 1000),
    'user' || (g % 1000) || '@example.com',
    CAST('10.0.0.0' AS inet) + (g % 65536),
    'Mozilla/5.0 (benchmark)',
    'POST',
    '/api/orders/' || (g % 100000),
    'api',
    'session',
    CAST(md5('r' || g) AS uuid),
    CAST(md5('c' || g) AS uuid)
FROM generate_series(1, :n) AS g
"""

_ACTIVITIES = """
INSERT INTO {activity} (
    transaction_id, verb, severity, object_type, object_id, object_label,
    target_type, target_id, actor_id, scope_id, correlation_id, created_at, data
)
SELECT
    g, v.verb, v.severity, v.object_type, v.object_id,
    v.object_type || ' ' || v.object_id,
    CASE WHEN v.targeted THEN 'Order' END,
    CASE WHEN v.targeted THEN CAST((r.h2 / 5) % 5000 AS text) END,
    'user-' || (g % 1000),
    'tenant-' || (g % 50),
    CAST(md5('c' || g) AS uuid),
    CAST(:start AS timestamptz) + (g - 1) * CAST(:step AS interval),
    CASE WHEN v.viewed
        THEN jsonb_build_object(
            'v', 1,
            'payload', jsonb_build_object(
                'fields', jsonb_build_array('email', 'phone')),
            'context', v.context)
        ELSE jsonb_build_object(
            'v', 1,
            'changes', jsonb_build_object(
                'status', jsonb_build_array('draft', 'sent'),
                'amount', jsonb_build_array(
                    (r.h % 1000) || '.00', (r.h % 1000 + 1) || '.00')),
            'context', v.context)
    END
FROM generate_series(1, :n) AS g
CROSS JOIN LATERAL generate_series(1, g % 3 + 1) AS j
CROSS JOIN LATERAL (
    SELECT
        CAST(hashint8(CAST(g * 4 + j AS bigint)) AS bigint) & 2147483647 AS h,
        CAST(hashint8(CAST(g * 4 + j AS bigint) + 1000000000000) AS bigint)
            & 2147483647 AS h2
) AS r
CROSS JOIN LATERAL (
    SELECT (r.h / 100) % 20 < 2 AS viewed
) AS k
CROSS JOIN LATERAL (
    SELECT
        k.viewed,
        CASE
            WHEN r.h % 100 < 70 THEN 10
            WHEN r.h % 100 < 90 THEN 20
            WHEN r.h % 100 < 98 THEN 30
            ELSE 40
        END AS severity,
        CASE
            WHEN k.viewed THEN 'person.viewed'
            WHEN (r.h / 100) % 20 < 4 THEN 'entity.created'
            WHEN (r.h / 100) % 20 = 4 THEN 'entity.deleted'
            ELSE 'entity.updated'
        END AS verb,
        CASE
            WHEN k.viewed THEN 'Person'
            ELSE (ARRAY['Order', 'OrderLine', 'Invoice', 'Customer',
                        'Product', 'Payment', 'Shipment', 'Ticket',
                        'Comment'])[1 + (r.h / 2000) % 9]
        END AS object_type,
        CASE
            WHEN k.viewed THEN CAST((r.h / 18000) % 1000 AS text)
            ELSE CAST((r.h / 18000) % 100000 AS text)
        END AS object_id,
        NOT k.viewed AND r.h2 % 5 = 0 AS targeted,
        jsonb_build_object(
            'actor_type', 'user',
            'actor_label', 'user' || (g % 1000) || '@example.com',
            'remote_addr', '10.0.' || (g % 256) || '.' || (g / 256 % 256),
            'channel', 'api',
            'method', 'POST',
            'path', '/api/orders/' || (g % 100000)) AS context
) AS v
"""


class Sizes(TypedDict):
    """On-disk size of the seeded tables, indexes included."""

    activity_bytes: int
    transaction_bytes: int


class Partitions(TypedDict):
    """Leaf partitions of the audit tables."""

    activity: int
    transaction: int


class Dataset(TypedDict):
    """The seeded log."""

    activity_rows: int
    transaction_rows: int
    days: int
    severity_mix: dict[str, float]
    partitions: Partitions
    sizes: Sizes
    seed_s: float
    vacuum_analyze_s: float


class ReadCase(TypedDict):
    """Latency and partitions of one read."""

    name: str
    description: str
    iterations: int
    p50_ms: float
    p95_ms: float
    mean_ms: float
    min_ms: float
    groups: int
    rows: int
    partitions_scanned: int
    explain_planning_ms: float
    explain_execution_ms: float
    statements: list[StatementPlan]


class ReadResult(TypedDict):
    """Everything the read benchmark measured."""

    dataset: Dataset
    cases: list[ReadCase]


class ReadConfig(NamedTuple):
    """Sizes of the read benchmark."""

    activity_rows: int
    iterations: int
    warmup: int


class _Scenario(NamedTuple):
    name: str
    description: str
    call: Callable[[Session], object]


def seed(engine: Engine, audit: AuditTrail, activity_rows: int) -> Dataset:
    """Create the audit tables in ``audit``'s schema and fill them."""
    transactions = max(activity_rows // 2, 1)
    with engine.begin() as conn:
        end: datetime = conn.execute(
            text("SELECT date_trunc('second', now()) - interval '1 minute'")
        ).scalar_one()
        start = end - SPAN
        create_audit_tables(conn, audit.tables, audit.severities)
        ensure_partitions(
            conn, audit.tables, audit.severities, months_ahead=15, now=start
        )
    params = {"start": start, "step": SPAN / transactions, "n": transactions}
    started = time.perf_counter()
    with engine.begin() as conn:
        conn.execute(
            text(_TRANSACTIONS.format(transaction=audit.tables.transaction.fullname)),
            params,
        )
        conn.execute(
            text(_ACTIVITIES.format(activity=audit.tables.activity.fullname)), params
        )
    seed_s = time.perf_counter() - started
    started = time.perf_counter()
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        for table in (audit.tables.transaction, audit.tables.activity):
            conn.execute(text(f"VACUUM (ANALYZE) {table.fullname}"))
    vacuum_s = time.perf_counter() - started
    with engine.connect() as conn:

        def count(sql: str, table: str) -> int:
            return int(conn.execute(text(sql), {"t": table}).scalar_one())

        leaves = "SELECT count(*) FROM pg_partition_tree(:t) WHERE isleaf"
        size = "SELECT sum(pg_total_relation_size(relid)) FROM pg_partition_tree(:t)"
        rows = "SELECT count(*) FROM {}"
        activity = audit.tables.activity.fullname
        transaction = audit.tables.transaction.fullname
        return Dataset(
            activity_rows=int(conn.execute(text(rows.format(activity))).scalar_one()),
            transaction_rows=int(
                conn.execute(text(rows.format(transaction))).scalar_one()
            ),
            days=SPAN.days,
            severity_mix=SEVERITY_MIX,
            partitions=Partitions(
                activity=count(leaves, activity), transaction=count(leaves, transaction)
            ),
            sizes=Sizes(
                activity_bytes=count(size, activity),
                transaction_bytes=count(size, transaction),
            ),
            seed_s=seed_s,
            vacuum_analyze_s=vacuum_s,
        )


def _scenarios(
    audit: AuditTrail, windowed: AuditTrail, sessions: sessionmaker[Session]
) -> list[_Scenario]:
    with sessions() as session:
        first = audit.query.list_groups(session)
        first_windowed = windowed.query.list_groups(session)
        newest = first.groups[0].transaction.issued_at if first.groups else None
    deep = None
    if newest is not None:
        deep = Cursor(newest - timedelta(days=182), 2**62, ALL_HISTORY)

    scenarios = [
        _Scenario(
            "list_groups first page",
            "list_groups(), no window: all severities, one query per severity",
            audit.query.list_groups,
        ),
        _Scenario(
            "list_groups first page, 30-day window",
            "list_groups() with default_query_window=30 days",
            windowed.query.list_groups,
        ),
    ]
    if first.next_cursor is not None:
        cursor = first.next_cursor
        scenarios.append(
            _Scenario(
                "list_groups next page",
                "list_groups(cursor=page 1's next_cursor), no window",
                lambda s: audit.query.list_groups(s, cursor=cursor),
            )
        )
    if first_windowed.next_cursor is not None:
        windowed_cursor = first_windowed.next_cursor
        scenarios.append(
            _Scenario(
                "list_groups next page, 30-day window",
                "list_groups(cursor=page 1's next_cursor), 30-day window",
                lambda s: windowed.query.list_groups(s, cursor=windowed_cursor),
            )
        )
    if deep is not None:
        deep_cursor = deep
        scenarios.append(
            _Scenario(
                "list_groups page 6 months back",
                "list_groups(cursor=a position 182 days back), no window",
                lambda s: audit.query.list_groups(s, cursor=deep_cursor),
            )
        )
    scenarios += [
        _Scenario(
            "list_groups by actor",
            f"list_groups(actor_id={ACTOR!r}), no window: one query over all "
            "severities",
            lambda s: audit.query.list_groups(s, actor_id=ACTOR),
        ),
        _Scenario(
            "object_history",
            f"object_history{HISTORY_OBJECT}, with children, first page",
            lambda s: audit.query.object_history(s, *HISTORY_OBJECT),
        ),
        _Scenario(
            "access_summary",
            f"access_summary{(*ACCESS_OBJECT, ACCESS_VERB)}, whole history",
            lambda s: audit.query.access_summary(s, *ACCESS_OBJECT, ACCESS_VERB),
        ),
    ]
    return scenarios


def _size(result: object) -> tuple[int, int]:
    # Groups and entries of a page; rows of a list (access_summary).
    if isinstance(result, Page):
        return len(result.groups), sum(len(g.activities) for g in result.groups)
    if isinstance(result, list):
        return 0, len(result)
    raise TypeError(f"unexpected result {type(result).__name__}")


def _measure(
    engine: Engine,
    sessions: sessionmaker[Session],
    scenario: _Scenario,
    config: ReadConfig,
) -> ReadCase:
    def once() -> float:
        # A session (and so a transaction) per call, as a request would.
        with sessions() as session:
            return timed(lambda: scenario.call(session))

    for _ in range(config.warmup):
        once()
    summary = summarize([once() for _ in range(config.iterations)])
    with sessions() as session:
        results: list[object] = []
        plans = explain_call(
            engine,
            session.connection,
            lambda: results.append(scenario.call(session)),
        )
    groups, rows = _size(results[0])
    partitions = {name for plan in plans for name in plan["partitions_scanned"]}
    return ReadCase(
        name=scenario.name,
        description=scenario.description,
        iterations=summary.iterations,
        p50_ms=summary.p50_ms,
        p95_ms=summary.p95_ms,
        mean_ms=summary.mean_ms,
        min_ms=summary.min_ms,
        groups=groups,
        rows=rows,
        partitions_scanned=len(partitions),
        explain_planning_ms=sum(plan["planning_ms"] for plan in plans),
        explain_execution_ms=sum(plan["execution_ms"] for plan in plans),
        statements=plans,
    )


def run(
    engine: Engine,
    audit_schema: str,
    config: ReadConfig,
    progress: Callable[[str], None],
) -> ReadResult:
    """Seed the log, then time every read scenario and explain it."""
    audit = AuditTrail(engine, schema=audit_schema, events=[])
    windowed = AuditTrail(
        engine, schema=audit_schema, events=[], default_query_window=WINDOW
    )
    progress(f"read: seeding {config.activity_rows:,} activity rows")
    dataset = seed(engine, audit, config.activity_rows)
    progress(
        f"read: seeded in {dataset['seed_s']:.0f} s, "
        f"VACUUM ANALYZE {dataset['vacuum_analyze_s']:.0f} s"
    )
    sessions = sessionmaker(engine)
    cases: list[ReadCase] = []
    for scenario in _scenarios(audit, windowed, sessions):
        progress(f"read: {scenario.name} ({config.iterations} it)")
        cases.append(_measure(engine, sessions, scenario, config))
    audit.dispose()
    windowed.dispose()
    return ReadResult(dataset=dataset, cases=cases)
