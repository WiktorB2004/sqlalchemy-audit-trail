"""The writer-side integrity option."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Integrity:
    """Integrity settings of the processes that write audit entries.

    With ``AuditTrail(integrity=Integrity())`` the audit tables declare the
    integrity columns, and every write stores the row's transaction id (the
    column default) and salted commitments to its erasable parts. The tables
    need those columns: ``migrations.add_integrity`` adds them to an existing
    install. There are no settings yet.
    """
