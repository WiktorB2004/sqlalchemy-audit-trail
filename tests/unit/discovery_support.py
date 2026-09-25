"""Isolation for tests of event discovery.

``AuditTrail(events=None)`` walks every live ``AuditEvent`` subclass. Classes
that other test modules define at module level, or locally in tests whose
classes the garbage collector has not freed yet, would otherwise take part in
a discovery test's registry, so its result would depend on which tests ran
before it.
"""

from __future__ import annotations

import pytest

from audit_trail import events


def isolate_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hide the event classes that exist now from registry discovery.

    Call it before the test defines its own classes. Discovery still runs the
    real walk; only its result is filtered.
    """
    discover = events._discover
    existing = set(discover())
    monkeypatch.setattr(
        events, "_discover", lambda: [cls for cls in discover() if cls not in existing]
    )
