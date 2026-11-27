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
GRANT SELECT, INSERT ON audit.audit_transaction, audit.audit_activity
    TO audit_scrubber;
-- UPDATE of the columns scrub() and scrub_actor() erase, and no others.
-- Before 0.4.0 this role had UPDATE on the whole tables, and a column grant
-- does not narrow a table grant: the REVOKE removes it (on a new role it
-- does nothing).
REVOKE UPDATE ON audit.audit_transaction, audit.audit_activity
    FROM audit_scrubber;
GRANT UPDATE (actor_label, remote_addr, user_agent, meta)
    ON audit.audit_transaction TO audit_scrubber;
GRANT UPDATE (object_label, data) ON audit.audit_activity TO audit_scrubber;
-- --8<-- [end:scrubber]

-- --8<-- [start:integrity]
-- With integrity. Run as audit_maintenance, after migrations.add_integrity().
-- The application inserts every column except id and xid, so it cannot
-- backdate a row into a sealed range of transaction ids. A column grant does
-- not narrow a table grant, so the table-wide INSERT is revoked first.
REVOKE INSERT ON audit.audit_transaction, audit.audit_activity FROM app_user;
GRANT INSERT (
    issued_at, actor_type, actor_id, actor_label, remote_addr, user_agent,
    method, path, channel, auth_method, request_id, correlation_id, meta,
    seal_commitments, seal_salts, seal_erased
) ON audit.audit_transaction TO app_user;
GRANT INSERT (
    transaction_id, verb, severity, object_type, object_id, object_label,
    target_type, target_id, actor_id, scope_id, correlation_id, created_at,
    data, seal_commitments, seal_salts, seal_erased
) ON audit.audit_activity TO app_user;
-- health() reads the chain to report the sealing lag.
GRANT SELECT ON audit.audit_seal_block TO app_user;
-- --8<-- [end:integrity]

-- --8<-- [start:integrity-scrubber]
-- With integrity, for the optional scrub-only role. Run as audit_maintenance.
-- Scrubbing deletes a salt and stamps the erased part; it writes its record
-- with the same column grants as the application.
REVOKE INSERT ON audit.audit_transaction, audit.audit_activity
    FROM audit_scrubber;
GRANT INSERT (
    issued_at, actor_type, actor_id, actor_label, remote_addr, user_agent,
    method, path, channel, auth_method, request_id, correlation_id, meta,
    seal_commitments, seal_salts, seal_erased
) ON audit.audit_transaction TO audit_scrubber;
GRANT INSERT (
    transaction_id, verb, severity, object_type, object_id, object_label,
    target_type, target_id, actor_id, scope_id, correlation_id, created_at,
    data, seal_commitments, seal_salts, seal_erased
) ON audit.audit_activity TO audit_scrubber;
GRANT UPDATE (seal_salts, seal_erased)
    ON audit.audit_transaction, audit.audit_activity TO audit_scrubber;
-- --8<-- [end:integrity-scrubber]

-- --8<-- [start:sealer]
-- With integrity: the role of the sealer job. Run as a superuser, after
-- migrations.add_integrity(). It reads the audit tables and appends blocks,
-- and never updates or deletes anything.
CREATE ROLE audit_sealer LOGIN;
GRANT USAGE ON SCHEMA audit TO audit_sealer;
GRANT SELECT ON audit.audit_transaction, audit.audit_activity TO audit_sealer;
GRANT SELECT, INSERT ON audit.audit_seal_block TO audit_sealer;
-- After a fork with an id window, every seal reads the identity sequences.
GRANT SELECT ON SEQUENCE audit.audit_transaction_id_seq,
    audit.audit_activity_id_seq TO audit_sealer;
-- Only for export_checkpoint(require_replicated=True): the standbys' WAL
-- positions in pg_stat_replication are hidden from other roles.
GRANT pg_monitor TO audit_sealer;
-- --8<-- [end:sealer]

-- --8<-- [start:verifier]
-- With integrity: a read-only role for verify(). Run as a superuser, after
-- migrations.add_integrity(). verify() reads each partition by name, and a
-- partition read by name checks its own privileges, not its parent's, so
-- the grant covers every table in the schema, including the partitions
-- audit_maintenance creates later.
CREATE ROLE audit_verifier LOGIN;
GRANT USAGE ON SCHEMA audit TO audit_verifier;
GRANT SELECT ON ALL TABLES IN SCHEMA audit TO audit_verifier;
ALTER DEFAULT PRIVILEGES FOR ROLE audit_maintenance IN SCHEMA audit
    GRANT SELECT ON TABLES TO audit_verifier;
-- --8<-- [end:verifier]
