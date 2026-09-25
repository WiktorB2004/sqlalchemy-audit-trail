-- Database roles for sqlalchemy-audit-trail.
-- Replace "app" with your database name and set passwords with \password.

-- --8<-- [start:roles]
-- Run as a superuser (or a CREATEROLE role that owns the database).
CREATE ROLE audit_maintenance LOGIN;
CREATE ROLE app_user LOGIN;

-- create_audit_tables() runs CREATE SCHEMA IF NOT EXISTS, which PostgreSQL
-- checks against CREATE on the database even when the schema exists.
GRANT CREATE ON DATABASE app TO audit_maintenance;
-- --8<-- [end:roles]

-- --8<-- [start:grants]
-- Run as audit_maintenance, after create_audit_tables() (for example at the
-- end of the migration that creates the audit tables). Partitions created
-- later need no grants: privileges are checked on the partitioned parents.
GRANT USAGE ON SCHEMA audit TO app_user;
GRANT SELECT, INSERT ON audit.audit_transaction, audit.audit_activity TO app_user;
-- --8<-- [end:grants]

-- --8<-- [start:scrubber]
-- Optional: a role that may scrub but not manage partitions.
-- Run as a superuser, after create_audit_tables().
CREATE ROLE audit_scrubber LOGIN;
GRANT USAGE ON SCHEMA audit TO audit_scrubber;
GRANT SELECT, INSERT, UPDATE
    ON audit.audit_transaction, audit.audit_activity TO audit_scrubber;
-- --8<-- [end:scrubber]
