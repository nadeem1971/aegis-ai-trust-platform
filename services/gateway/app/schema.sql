-- AEGIS gateway schema
-- Threat model refs: T-13 (audit tamper-evidence), T-12 (DB role separation)

CREATE TABLE IF NOT EXISTS audit_log (
    sequence     BIGINT PRIMARY KEY,
    timestamp    TEXT        NOT NULL,
    event_type   TEXT        NOT NULL,
    payload      JSONB       NOT NULL,
    prev_hash    CHAR(64)    NOT NULL,
    record_hash  CHAR(64)    NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log (event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp  ON audit_log (timestamp);

-- ── Append-only enforcement (T-13) ───────────────────────────────────
-- Defence in depth: even if the application is compromised and tries to
-- rewrite history, the database role cannot. The chain makes tampering
-- *detectable*; these grants make it *difficult*.
--
-- Run once as the server admin, after creating the application role:
--
--   CREATE ROLE aegis_app LOGIN PASSWORD '<from Key Vault>';
--   GRANT CONNECT ON DATABASE aegis TO aegis_app;
--   GRANT USAGE  ON SCHEMA public TO aegis_app;
--   GRANT SELECT, INSERT ON audit_log TO aegis_app;
--   REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM aegis_app;
--
-- The demo tamper script deliberately connects as the *admin* role to
-- prove the chain detects modification that the app role could not make.

-- Trigger as a further guard: blocks UPDATE/DELETE for any role that
-- somehow retains the privilege (belt and braces for the live demo).
CREATE OR REPLACE FUNCTION audit_log_immutable()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only (AEGIS threat model T-13)';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_log_no_update ON audit_log;
CREATE TRIGGER trg_audit_log_no_update
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
