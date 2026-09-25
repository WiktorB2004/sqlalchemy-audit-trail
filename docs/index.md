# sqlalchemy-audit-trail

Audit trail for SQLAlchemy on PostgreSQL. Entity changes are recorded automatically as field-level diffs, and explicit domain events are logged next to them, in one chronological table partitioned by severity and month.

!!! warning "Pre-alpha"
    The package is under active development. The API will change before 1.0.
