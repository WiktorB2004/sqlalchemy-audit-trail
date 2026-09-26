"""Latency summaries."""

from __future__ import annotations

import statistics
import time
from collections.abc import Callable
from typing import NamedTuple


class Summary(NamedTuple):
    """Latency of one case, in milliseconds."""

    iterations: int
    p50_ms: float
    p95_ms: float
    mean_ms: float
    min_ms: float


def summarize(seconds: list[float]) -> Summary:
    """Summarize measured durations (seconds) as milliseconds.

    Percentiles use ``statistics.quantiles`` with the inclusive method, so a
    percentile always lies between the smallest and the largest sample.
    """
    if not seconds:
        raise ValueError("no samples")
    ms = [value * 1000 for value in seconds]
    if len(ms) == 1:
        p50 = p95 = ms[0]
    else:
        cuts = statistics.quantiles(ms, n=100, method="inclusive")
        p50, p95 = cuts[49], cuts[94]
    return Summary(len(ms), p50, p95, statistics.fmean(ms), min(ms))


def timed(call: Callable[[], object]) -> float:
    """Run ``call`` once and return its duration in seconds."""
    started = time.perf_counter()
    call()
    return time.perf_counter() - started
