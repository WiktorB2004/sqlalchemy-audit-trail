"""Write overhead: the same flush with and without auditing.

Variants:

- ``plain``: ``BenchPlain`` (not ``Audited``) on a session class the library
  is not installed on. Nothing of the library runs: the true zero.
- ``disabled``: ``BenchAudited`` on the installed session class with
  ``session.info["audit_enabled"] = False``. No entries are written, but the
  mixin's ``active_history`` set listeners and the session listeners still
  run.
- ``audited``: ``BenchAudited`` on the installed session class, capturing
  with the default ``on_error="log"``: the audit inserts run inside a
  savepoint, so a failed audit write does not fail the transaction.
- ``audited_raise``: the same with ``on_error="raise"``, installed on its
  own session class: no savepoint, and a failed audit write fails the
  transaction.

``check_setup`` verifies these preconditions before anything is measured.

Every timed operation is one database transaction, ended by ``commit()``.
The variants of a case run in interleaved blocks, so drift (table growth,
autovacuum, a noisy neighbour) spreads over all of them.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from typing import Literal, NamedTuple, TypedDict, cast

from sqlalchemy import Engine, event, select
from sqlalchemy.orm import Session, sessionmaker

from audit_trail import Audited, AuditEvent, AuditTrail
from audit_trail._typing import assert_never
from audit_trail.listener import AUDIT_ENABLED_KEY, installed_trail
from audit_trail.maintenance import ensure_partitions
from audit_trail.migrations import create_audit_tables
from benchmark.models import Base, BenchAudited, BenchPlain, bench_events, row_values
from benchmark.stats import summarize, timed

Operation = Literal["insert", "update", "log", "log_durable"]
Variant = Literal["plain", "disabled", "audited", "audited_raise"]


class WriteCase(TypedDict):
    """Latency of one operation, batch size and variant."""

    operation: Operation
    objects: int
    variant: Variant
    iterations: int
    p50_ms: float
    p95_ms: float
    mean_ms: float
    min_ms: float
    ops_per_s: float
    objects_per_s: float
    statements_per_op: float


class Overhead(TypedDict):
    """A variant compared with the ``plain`` baseline."""

    operation: Operation
    objects: int
    variant: Variant
    baseline: Variant
    p50_pct: float
    p95_pct: float
    added_p50_ms: float
    added_p50_us_per_object: float


class WriteResult(TypedDict):
    """Everything the write benchmark measured."""

    preconditions: list[str]
    cases: list[WriteCase]
    overhead: list[Overhead]


class WriteConfig(NamedTuple):
    """Sizes of the write benchmark."""

    batch_sizes: tuple[int, ...]
    iterations: int
    iterations_large: int
    large_batch: int
    warmup: int
    block: int


class Sessions(NamedTuple):
    """Session factories of the variants."""

    plain: sessionmaker[Session]
    audited: sessionmaker[Session]
    audited_raise: sessionmaker[Session]


class Setup(NamedTuple):
    """The trails and session factories of a write run."""

    audit: AuditTrail
    audit_raise: AuditTrail
    sessions: Sessions


class SetupError(RuntimeError):
    """A variant is not what it claims to be; measuring it would mislead."""


Step = Callable[[], "_Timing"]


def setup(
    engine: Engine,
    app_engine: Engine,
    audit_schema: str,
    events: Sequence[type[AuditEvent]] | None = None,
) -> Setup:
    """Create the model tables and the audit tables; install the listeners.

    ``events`` defaults to ``bench_events()``; pass ``()`` to set up without
    defining them (the test suite does, to keep its process free of them).
    """
    registered = [bench_events()] if events is None else list(events)
    audit = AuditTrail(engine, schema=audit_schema, events=registered)
    audit_raise = AuditTrail(
        engine, schema=audit_schema, events=registered, on_error="raise"
    )
    with engine.begin() as conn:
        create_audit_tables(conn, audit.tables, audit.severities)
        ensure_partitions(conn, audit.tables, audit.severities)
    Base.metadata.create_all(app_engine)

    def factory(name: str) -> sessionmaker[Session]:
        # A fresh Session subclass per run: install() is process-wide per class.
        return sessionmaker(app_engine, class_=type(name, (Session,), {}))

    sessions = Sessions(
        plain=factory("PlainSession"),
        audited=factory("AuditedSession"),
        audited_raise=factory("AuditedRaiseSession"),
    )
    audit.install(sessions.audited)
    audit_raise.install(sessions.audited_raise)
    return Setup(audit, audit_raise, sessions)


class _Statements:
    """Counts the statements sent through the cursor (not BEGIN/COMMIT)."""

    def __init__(self, engines: list[Engine]) -> None:
        self.count = 0
        self.engines = engines

    def _seen(self, *args: object) -> None:
        self.count += 1

    @contextmanager
    def listening(self) -> Iterator[None]:
        for engine in self.engines:
            event.listen(engine, "before_cursor_execute", self._seen)
        try:
            yield
        finally:
            for engine in self.engines:
                event.remove(engine, "before_cursor_execute", self._seen)


class _Timing(NamedTuple):
    seconds: float
    statements: int


def _timed(statements: _Statements, work: Callable[[], object]) -> _Timing:
    # Only the timed work counts: the untimed SELECT of an update does not.
    before = statements.count
    seconds = timed(work)
    return _Timing(seconds, statements.count - before)


class _Counter:
    def __init__(self) -> None:
        self.value = 0

    def take(self, count: int) -> list[int]:
        start = self.value
        self.value += count
        return list(range(start, start + count))


_AUDITED: tuple[Variant, ...] = ("disabled", "audited", "audited_raise")


def _session(sessions: Sessions, variant: Variant) -> Session:
    match variant:
        case "plain":
            return sessions.plain()
        case "disabled":
            session = sessions.audited()
            session.info[AUDIT_ENABLED_KEY] = False
            return session
        case "audited":
            return sessions.audited()
        case "audited_raise":
            return sessions.audited_raise()
        case _:
            assert_never(variant)


def _model(variant: Variant) -> type[BenchPlain] | type[BenchAudited]:
    return BenchPlain if variant == "plain" else BenchAudited


def _trail(setup: Setup, variant: Variant) -> AuditTrail | None:
    # The trail a variant's log() goes through: the one installed on its
    # session class.
    return setup.audit_raise if variant == "audited_raise" else setup.audit


PRECONDITIONS = (
    "plain model is not Audited",
    "other variants use the Audited model",
    "plain session has no trail installed",
    "disabled session has the on_error='log' trail and capture off",
    "audited session has the on_error='log' trail and capture on",
    "audited_raise session has the on_error='raise' trail and capture on",
)
"""What ``check_setup`` verifies, in order."""


def check_setup(setup: Setup) -> list[str]:
    """Verify that every variant is what it claims to be, before measuring.

    Checks the models and sessions the steps actually use (``_model`` and
    ``_session``), so a mistake there fails the run instead of producing a
    wrong baseline.

    Args:
        setup: What ``setup`` returned.

    Returns:
        ``PRECONDITIONS``, all verified.

    Raises:
        SetupError: A precondition does not hold.
    """

    def installed(variant: Variant, trail: AuditTrail | None, on: bool) -> bool:
        with _session(setup.sessions, variant) as session:
            enabled = session.info.get(AUDIT_ENABLED_KEY) is not False
            return installed_trail(session) is trail and enabled is on

    checks = (
        not issubclass(_model("plain"), Audited),
        all(issubclass(_model(variant), Audited) for variant in _AUDITED),
        installed("plain", None, True),
        installed("disabled", setup.audit, False) and setup.audit.on_error == "log",
        installed("audited", setup.audit, True),
        installed("audited_raise", setup.audit_raise, True)
        and setup.audit_raise.on_error == "raise",
    )
    for name, ok in zip(PRECONDITIONS, checks, strict=True):
        if not ok:
            raise SetupError(f"benchmark precondition failed: {name}")
    return list(PRECONDITIONS)


def _insert_step(
    sessions: Sessions,
    variant: Variant,
    objects: int,
    counter: _Counter,
    statements: _Statements,
) -> Step:
    model = _model(variant)

    def step() -> _Timing:
        rows = [model(**row_values(i)) for i in counter.take(objects)]
        with _session(sessions, variant) as session:

            def work() -> None:
                session.add_all(rows)
                session.commit()

            return _timed(statements, work)

    return step


def _update_step(
    sessions: Sessions, variant: Variant, objects: int, statements: _Statements
) -> Step:
    model = _model(variant)
    with sessions.plain() as session:
        rows = [model(**row_values(i)) for i in range(objects)]
        session.add_all(rows)
        session.commit()
        ids = [row.id for row in rows]

    def step() -> _Timing:
        with _session(sessions, variant) as session:
            # Loaded in their own transaction first, untimed: the timed part
            # is the change and its flush, not the SELECT.
            loaded = cast(
                "Sequence[BenchPlain | BenchAudited]",
                session.scalars(select(model).where(model.id.in_(ids))).all(),
            )

            def work() -> None:
                for row in loaded:
                    row.counter += 1
                    row.status = "sent" if row.status == "draft" else "draft"
                session.commit()

            return _timed(statements, work)

    return step


def _log_step(
    setup: Setup,
    variant: Variant,
    durable: bool,
    counter: _Counter,
    statements: _Statements,
) -> Step:
    # One plain row, as a request would write, then the event.
    event = bench_events()["EXPORTED" if durable else "VIEWED"]

    def step() -> _Timing:
        row = BenchPlain(**row_values(counter.take(1)[0]))
        trail = None if variant == "plain" else _trail(setup, variant)
        with _session(setup.sessions, variant) as session:

            def work() -> None:
                session.add(row)
                if trail is not None:
                    trail.log(session, event, payload={"format": "csv"})
                session.commit()

            return _timed(statements, work)

    return step


class _Samples(NamedTuple):
    seconds: list[float]
    statements: int


def _measure(
    steps: dict[Variant, Step],
    iterations: int,
    warmup: int,
    block: int,
) -> dict[Variant, _Samples]:
    for step in steps.values():
        for _ in range(warmup):
            step()
    seconds: dict[Variant, list[float]] = {variant: [] for variant in steps}
    counts: dict[Variant, int] = dict.fromkeys(steps, 0)
    done = 0
    while done < iterations:
        size = min(block, iterations - done)
        for variant, step in steps.items():
            for _ in range(size):
                timing = step()
                seconds[variant].append(timing.seconds)
                counts[variant] += timing.statements
        done += size
    return {variant: _Samples(seconds[variant], counts[variant]) for variant in steps}


def _case(
    operation: Operation, objects: int, variant: Variant, samples: _Samples
) -> WriteCase:
    summary = summarize(samples.seconds)
    ops = 1000 / summary.mean_ms
    return WriteCase(
        operation=operation,
        objects=objects,
        variant=variant,
        iterations=summary.iterations,
        p50_ms=summary.p50_ms,
        p95_ms=summary.p95_ms,
        mean_ms=summary.mean_ms,
        min_ms=summary.min_ms,
        ops_per_s=ops,
        objects_per_s=ops * objects,
        statements_per_op=samples.statements / summary.iterations,
    )


def overhead(cases: list[WriteCase]) -> list[Overhead]:
    """Compare every non-``plain`` case with the ``plain`` case of its kind."""
    base = {
        (case["operation"], case["objects"]): case
        for case in cases
        if case["variant"] == "plain"
    }
    result: list[Overhead] = []
    for case in cases:
        plain = base.get((case["operation"], case["objects"]))
        if case["variant"] == "plain" or plain is None:
            continue
        added = case["p50_ms"] - plain["p50_ms"]
        result.append(
            Overhead(
                operation=case["operation"],
                objects=case["objects"],
                variant=case["variant"],
                baseline="plain",
                p50_pct=100 * added / plain["p50_ms"],
                p95_pct=100 * (case["p95_ms"] - plain["p95_ms"]) / plain["p95_ms"],
                added_p50_ms=added,
                added_p50_us_per_object=1000 * added / case["objects"],
            )
        )
    return result


@contextmanager
def _context(audit: AuditTrail) -> Iterator[None]:
    with audit.context(
        actor_type="user",
        actor_id="42",
        actor_label="bench@example.com",
        channel="api",
        path="/bench",
        method="POST",
    ):
        yield


def run(
    engine: Engine,
    app_engine: Engine,
    audit_schema: str,
    config: WriteConfig,
    progress: Callable[[str], None],
) -> WriteResult:
    """Measure insert, update and ``log()`` with and without auditing."""
    run_setup = setup(engine, app_engine, audit_schema)
    preconditions = check_setup(run_setup)
    audit, sessions = run_setup.audit, run_setup.sessions
    durable_engines = [audit.durable_engine, run_setup.audit_raise.durable_engine]
    statements = _Statements(
        [engine, *(e for e in durable_engines if isinstance(e, Engine))]
    )
    counter = _Counter()
    cases: list[WriteCase] = []
    variants: tuple[Variant, ...] = ("plain", "disabled", "audited", "audited_raise")
    try:
        with _context(audit), statements.listening():
            for operation in ("insert", "update"):
                for objects in config.batch_sizes:
                    iterations = (
                        config.iterations_large
                        if objects >= config.large_batch
                        else config.iterations
                    )
                    progress(f"write: {operation} x{objects} ({iterations} it)")
                    steps: dict[Variant, Step] = {
                        variant: (
                            _insert_step(
                                sessions, variant, objects, counter, statements
                            )
                            if operation == "insert"
                            else _update_step(sessions, variant, objects, statements)
                        )
                        for variant in variants
                    }
                    samples = _measure(steps, iterations, config.warmup, config.block)
                    cases.extend(
                        _case(operation, objects, variant, samples[variant])
                        for variant in variants
                    )
            log_ops: tuple[tuple[Operation, bool], ...] = (
                ("log", False),
                ("log_durable", True),
            )
            for log_op, durable in log_ops:
                progress(f"write: {log_op} ({config.iterations} it)")
                log_variants: tuple[Variant, ...] = (
                    "plain",
                    "audited",
                    "audited_raise",
                )
                steps = {
                    variant: _log_step(run_setup, variant, durable, counter, statements)
                    for variant in log_variants
                }
                samples = _measure(
                    steps, config.iterations, config.warmup, config.block
                )
                cases.extend(
                    _case(log_op, 1, variant, samples[variant])
                    for variant in log_variants
                )
    finally:
        audit.dispose()
        run_setup.audit_raise.dispose()
    return WriteResult(
        preconditions=preconditions, cases=cases, overhead=overhead(cases)
    )
