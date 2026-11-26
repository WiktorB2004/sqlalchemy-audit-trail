"""Tamper evidence for the audit log.

Work in progress and private: nothing here is part of the public API yet.
With ``AuditTrail(integrity=Integrity())`` every audit row carries its
PostgreSQL transaction id (``xid``) and salted commitments to the parts of
the entry that scrubbing may erase; ``scrub`` and ``scrub_actor`` delete the
salt of each erased part and stamp the part with the scrub's own ``xid``.
"""
