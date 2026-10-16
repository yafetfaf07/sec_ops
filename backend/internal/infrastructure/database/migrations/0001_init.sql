-- 0001_init: full SecOps schema.
-- Enum values are the exact strings used by the frontend (app/lib/types.ts)
-- and by internal/domain/enums. Keep them in sync.
-- All timestamps are timestamptz (stored as UTC).

-- ---------------------------------------------------------------------------
-- Append-only enforcement (FR-SEC-001 raw logs, FR-SEC-031 audit log).
-- Raises SQLSTATE 23001 (restrict_violation); the repository layer maps it to
-- interfaces.ErrImmutable.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION forbid_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'table "%" is append-only: % is not allowed', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

-- ---------------------------------------------------------------------------
-- Users / RBAC (FR-SEC-030)
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    email         text        NOT NULL,
    password_hash text        NOT NULL,
    role          text        NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    -- Incremented on logout / role change / disable; tokens carrying an older
    -- version are rejected, which revokes every session for the user.
    token_version integer     NOT NULL DEFAULT 0,
    disabled      boolean     NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_lower_uq ON users (lower(email));

-- ---------------------------------------------------------------------------
-- Raw logs (FR-SEC-001) — immutable
-- ---------------------------------------------------------------------------
CREATE TABLE raw_logs (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    log_id      text        NOT NULL UNIQUE CHECK (length(log_id) BETWEEN 1 AND 128),
    ts          timestamptz NOT NULL,
    user_id     text        NOT NULL CHECK (length(user_id) BETWEEN 1 AND 256),
    -- text, validated with netip in Go (avoids driver-specific inet mapping).
    ip_address  text        NOT NULL CHECK (length(ip_address) BETWEEN 2 AND 45),
    country     text        NOT NULL DEFAULT '',
    city        text        NOT NULL DEFAULT '',
    action      text        NOT NULL CHECK (action IN ('Login Success', 'Login Failed', 'Privilege Escalation')),
    user_agent  text        NOT NULL DEFAULT '' CHECK (length(user_agent) <= 1024),
    flagged     boolean     NOT NULL,
    ingested_at timestamptz NOT NULL DEFAULT now(),
    -- The flag is derived from the action, never trusted from the client.
    CONSTRAINT raw_logs_flag_matches_action
        CHECK (flagged = (action IN ('Login Failed', 'Privilege Escalation')))
);
CREATE INDEX raw_logs_ts_idx              ON raw_logs (ts DESC);
CREATE INDEX raw_logs_flagged_ts_idx      ON raw_logs (ts DESC) WHERE flagged;
CREATE INDEX raw_logs_ip_ts_idx           ON raw_logs (ip_address, ts DESC);
CREATE INDEX raw_logs_user_ts_idx         ON raw_logs (user_id, ts DESC);
CREATE INDEX raw_logs_country_action_idx  ON raw_logs (country, action, ts DESC);

CREATE TRIGGER raw_logs_no_update_delete BEFORE UPDATE OR DELETE ON raw_logs
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER raw_logs_no_truncate BEFORE TRUNCATE ON raw_logs
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();

-- ---------------------------------------------------------------------------
-- Scan runs (FR-SEC-003)
-- ---------------------------------------------------------------------------
CREATE TABLE scan_runs (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    trigger      text        NOT NULL CHECK (trigger IN ('scheduler', 'manual')),
    actor        text        NOT NULL,
    status       text        NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'succeeded', 'failed')),
    started_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz,
    logs_fetched integer     NOT NULL DEFAULT 0 CHECK (logs_fetched >= 0),
    analyzed     integer     NOT NULL DEFAULT 0 CHECK (analyzed >= 0),
    new_alerts   integer     NOT NULL DEFAULT 0 CHECK (new_alerts >= 0),
    error        text
);
CREATE INDEX scan_runs_started_idx ON scan_runs (started_at DESC);
-- At most one running scan. This is the scan lock: unlike session advisory
-- locks it works behind transaction-mode poolers (Neon, Supabase).
CREATE UNIQUE INDEX scan_runs_one_running_uq ON scan_runs ((true)) WHERE status = 'running';

-- ---------------------------------------------------------------------------
-- AI analysis batches (FR-SEC-002)
-- ---------------------------------------------------------------------------
CREATE TABLE analysis_batches (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id        uuid        REFERENCES scan_runs (id),
    window_start       timestamptz NOT NULL,
    window_end         timestamptz NOT NULL,
    status             text        NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'running', 'done', 'failed', 'deferred')),
    attempts           integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    model              text        NOT NULL DEFAULT '',
    risk_score         text        CHECK (risk_score IN ('Low', 'Medium', 'High', 'Critical')),
    summary            text        NOT NULL DEFAULT '',
    recommended_action text        NOT NULL DEFAULT '',
    suspicious_ips     jsonb       NOT NULL DEFAULT '[]'::jsonb,
    patterns           jsonb       NOT NULL DEFAULT '[]'::jsonb,
    affected_users     jsonb       NOT NULL DEFAULT '[]'::jsonb,
    top_ip             text        NOT NULL DEFAULT '',
    raw_response       jsonb,
    error              text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    analyzed_at        timestamptz,
    CHECK (window_end >= window_start),
    CHECK (status <> 'done' OR risk_score IS NOT NULL)
);
CREATE INDEX analysis_batches_status_idx ON analysis_batches (status, created_at);

-- A log belongs to at most one batch: this is how "unanalyzed" is defined
-- without ever updating raw_logs. Immutable once written.
CREATE TABLE batch_logs (
    log_id   text PRIMARY KEY REFERENCES raw_logs (log_id),
    batch_id uuid NOT NULL REFERENCES analysis_batches (id)
);
CREATE INDEX batch_logs_batch_idx ON batch_logs (batch_id);

CREATE TRIGGER batch_logs_no_update_delete BEFORE UPDATE OR DELETE ON batch_logs
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER batch_logs_no_truncate BEFORE TRUNCATE ON batch_logs
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();

-- ---------------------------------------------------------------------------
-- Incidents (FR-SEC-010, FR-SEC-012)
-- ---------------------------------------------------------------------------
CREATE TABLE incidents (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id             uuid        NOT NULL REFERENCES analysis_batches (id),
    fingerprint          text        NOT NULL,
    ai_risk_score        text        NOT NULL CHECK (ai_risk_score IN ('Low', 'Medium', 'High', 'Critical')),
    risk_score           text        NOT NULL CHECK (risk_score IN ('Low', 'Medium', 'High', 'Critical')),
    status               text        NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'Acknowledged', 'Resolved')),
    ai_summary           text        NOT NULL,
    recommended_action   text        NOT NULL,
    suspicious_ips       jsonb       NOT NULL DEFAULT '[]'::jsonb,
    patterns             jsonb       NOT NULL DEFAULT '[]'::jsonb,
    affected_users       jsonb       NOT NULL DEFAULT '[]'::jsonb,
    top_ip               text        NOT NULL DEFAULT '',
    country              text        NOT NULL DEFAULT '',
    abuseipdb_confidence integer     NOT NULL DEFAULT 0 CHECK (abuseipdb_confidence BETWEEN 0 AND 100),
    detected_at          timestamptz NOT NULL DEFAULT now(),
    acknowledged_at      timestamptz,
    acknowledged_by      uuid REFERENCES users (id),
    resolved_at          timestamptz,
    resolved_by          uuid REFERENCES users (id),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    CHECK (status <> 'Acknowledged' OR acknowledged_at IS NOT NULL),
    CHECK (status <> 'Resolved' OR resolved_at IS NOT NULL)
);
-- Only one unresolved incident per fingerprint; repeats while open are merged.
CREATE UNIQUE INDEX incidents_open_fingerprint_uq ON incidents (fingerprint) WHERE status <> 'Resolved';
CREATE INDEX incidents_fingerprint_resolved_idx  ON incidents (fingerprint, resolved_at DESC) WHERE status = 'Resolved';
CREATE INDEX incidents_detected_idx              ON incidents (detected_at DESC);
CREATE INDEX incidents_status_risk_idx           ON incidents (status, risk_score);

-- Resolution comments and notes. Immutable: a comment is evidence.
CREATE TABLE incident_comments (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id uuid        NOT NULL REFERENCES incidents (id),
    author      text        NOT NULL,
    role        text        NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer', 'SYSTEM')),
    body        text        NOT NULL CHECK (length(body) BETWEEN 1 AND 2000),
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX incident_comments_incident_idx ON incident_comments (incident_id, created_at);

CREATE TRIGGER incident_comments_no_update_delete BEFORE UPDATE OR DELETE ON incident_comments
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER incident_comments_no_truncate BEFORE TRUNCATE ON incident_comments
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();

-- ---------------------------------------------------------------------------
-- Threat intel cache (FR-SEC-004): 24h TTL via expires_at.
-- ---------------------------------------------------------------------------
CREATE TABLE threat_intel_cache (
    ip               text PRIMARY KEY,
    abuse_confidence integer     NOT NULL CHECK (abuse_confidence BETWEEN 0 AND 100),
    total_reports    integer     NOT NULL DEFAULT 0,
    country          text        NOT NULL DEFAULT '',
    raw              jsonb,
    fetched_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL
);
CREATE INDEX threat_intel_cache_expires_idx ON threat_intel_cache (expires_at);

-- ---------------------------------------------------------------------------
-- Alert deliveries (FR-SEC-005) — immutable delivery record.
-- ---------------------------------------------------------------------------
CREATE TABLE alert_deliveries (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id  uuid        NOT NULL REFERENCES incidents (id),
    channel      text        NOT NULL CHECK (channel IN ('slack', 'discord')),
    status       text        NOT NULL CHECK (status IN ('success', 'failed')),
    http_status  integer,
    error        text,
    attempted_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX alert_deliveries_incident_idx ON alert_deliveries (incident_id, attempted_at DESC);

CREATE TRIGGER alert_deliveries_no_update_delete BEFORE UPDATE OR DELETE ON alert_deliveries
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER alert_deliveries_no_truncate BEFORE TRUNCATE ON alert_deliveries
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();

-- ---------------------------------------------------------------------------
-- Audit log (FR-SEC-031) — immutable, hash-chained.
-- hash = sha256(prev_hash || canonical row); computed by the audit recorder
-- under an advisory transaction lock so the chain is strictly ordered.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_logs (
    id          bigserial PRIMARY KEY,
    ts          timestamptz NOT NULL DEFAULT now(),
    user_id     text        NOT NULL,
    action_type text        NOT NULL CHECK (length(action_type) BETWEEN 1 AND 64),
    entity_type text        NOT NULL DEFAULT '',
    entity_id   text        NOT NULL DEFAULT '',
    details     text        NOT NULL DEFAULT '',
    metadata    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    prev_hash   text        NOT NULL DEFAULT '',
    hash        text        NOT NULL
);
CREATE INDEX audit_logs_ts_idx     ON audit_logs (ts DESC);
CREATE INDEX audit_logs_action_idx ON audit_logs (action_type, ts DESC);
CREATE INDEX audit_logs_user_idx   ON audit_logs (user_id, ts DESC);

CREATE TRIGGER audit_logs_no_update_delete BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();

-- ---------------------------------------------------------------------------
-- Free-tier quota budget (FR-SEC-032)
-- ---------------------------------------------------------------------------
CREATE TABLE api_usage (
    day      date    NOT NULL,
    provider text    NOT NULL CHECK (provider IN ('gemini', 'abuseipdb')),
    count    integer NOT NULL DEFAULT 0 CHECK (count >= 0),
    PRIMARY KEY (day, provider)
);

-- ---------------------------------------------------------------------------
-- Non-secret runtime settings (FR-SEC-030). API keys never live here.
-- ---------------------------------------------------------------------------
CREATE TABLE settings (
    key        text PRIMARY KEY,
    value      jsonb       NOT NULL,
    updated_by text        NOT NULL DEFAULT 'SYSTEM',
    updated_at timestamptz NOT NULL DEFAULT now()
);
