-- Single-file bootstrap schema for appliance deployment.
-- Apply this once to an empty PostgreSQL database:
--   psql -d passive_asset_intel -f passive_asset_intel/schema.sql

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS assets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    mac_address varchar NOT NULL UNIQUE,
    first_seen timestamp NOT NULL DEFAULT NOW(),
    last_seen timestamp NOT NULL DEFAULT NOW(),
    vendor varchar,
    oui varchar,
    asset_status varchar NOT NULL DEFAULT 'active',
    confidence_score double precision NOT NULL DEFAULT 0,
    merged_into uuid REFERENCES assets(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS asset_ips (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    ip_address inet NOT NULL,
    first_seen timestamp NOT NULL DEFAULT NOW(),
    last_seen timestamp NOT NULL DEFAULT NOW(),
    is_primary boolean NOT NULL DEFAULT false,
    CONSTRAINT uq_asset_ips_asset_ip UNIQUE (asset_id, ip_address)
);

CREATE TABLE IF NOT EXISTS asset_hostnames (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    hostname varchar NOT NULL,
    source varchar,
    first_seen timestamp NOT NULL DEFAULT NOW(),
    last_seen timestamp NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_asset_hostnames_asset_hostname UNIQUE (asset_id, hostname)
);

CREATE TABLE IF NOT EXISTS fingerprints (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    ja3 varchar,
    ja3s varchar,
    user_agent text,
    dhcp_vendor varchar,
    os_guess varchar,
    first_seen timestamp NOT NULL DEFAULT NOW(),
    last_seen timestamp NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS behaviors (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    protocol varchar NOT NULL,
    port integer NOT NULL DEFAULT 0,
    service varchar NOT NULL DEFAULT '',
    frequency integer NOT NULL DEFAULT 1,
    first_seen timestamp NOT NULL DEFAULT NOW(),
    last_seen timestamp NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_behaviors_asset_proto_port_svc UNIQUE (asset_id, protocol, port, service)
);

CREATE TABLE IF NOT EXISTS connections (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    src_asset_id uuid REFERENCES assets(id) ON DELETE SET NULL,
    dst_asset_id uuid REFERENCES assets(id) ON DELETE SET NULL,
    src_ip inet NOT NULL,
    dst_ip inet NOT NULL,
    src_port integer,
    dst_port integer,
    protocol varchar NOT NULL,
    service varchar,
    duration double precision,
    bytes_sent bigint,
    bytes_received bigint,
    timestamp timestamp NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS dns_queries (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    query varchar,
    answer varchar,
    query_type varchar,
    timestamp timestamp NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tls_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    ja3 varchar,
    ja3s varchar,
    server_name varchar,
    certificate_issuer varchar,
    version varchar,
    next_protocol varchar,
    validation_status varchar,
    sni_matches_cert boolean,
    ssl_history varchar,
    timestamp timestamp NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS http_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    host varchar,
    uri text,
    user_agent text,
    method varchar,
    status_code integer,
    timestamp timestamp NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS inference_results (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    device_type varchar,
    os varchar,
    os_version varchar,
    cpe varchar,
    confidence double precision,
    method varchar,
    behavior_type varchar,
    created_at timestamp NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_inference_results_asset UNIQUE (asset_id)
);

CREATE TABLE IF NOT EXISTS inference_evidence (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    inference_id uuid NOT NULL REFERENCES inference_results(id) ON DELETE CASCADE,
    evidence_type varchar NOT NULL,
    value text NOT NULL,
    weight double precision NOT NULL
);

CREATE TABLE IF NOT EXISTS inference_anomalies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    inference_id uuid NOT NULL REFERENCES inference_results(id) ON DELETE CASCADE,
    anomaly_id varchar NOT NULL,
    severity varchar NOT NULL DEFAULT 'medium',
    message text NOT NULL,
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamp NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_inference_anomalies_inference ON inference_anomalies (inference_id);
CREATE INDEX IF NOT EXISTS idx_inference_anomalies_severity ON inference_anomalies (severity);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id varchar,
    cpe varchar,
    cvss_score double precision,
    severity varchar,
    description text,
    CONSTRAINT uq_vulnerabilities_cve_id UNIQUE (cve_id)
);

CREATE TABLE IF NOT EXISTS asset_vulnerabilities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    vulnerability_id uuid NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    detected_at timestamp NOT NULL DEFAULT NOW(),
    risk_score double precision,
    CONSTRAINT uq_asset_vulnerabilities_asset_vuln UNIQUE (asset_id, vulnerability_id)
);

CREATE TABLE IF NOT EXISTS tags (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name varchar NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS asset_tags (
    asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    tag_id uuid NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (asset_id, tag_id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_type varchar NOT NULL,
    severity varchar NOT NULL DEFAULT 'medium',
    message text NOT NULL,
    source_ip varchar,
    asset_id uuid REFERENCES assets(id) ON DELETE SET NULL,
    status varchar NOT NULL DEFAULT 'new',
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamp NOT NULL DEFAULT NOW(),
    updated_at timestamp NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    status varchar NOT NULL DEFAULT 'stopped',
    log_dir varchar,
    started_at timestamp,
    stopped_at timestamp,
    logs_processed integer NOT NULL DEFAULT 0,
    assets_discovered integer NOT NULL DEFAULT 0,
    error_message text,
    created_at timestamp NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS integrations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name varchar(64) NOT NULL UNIQUE,
    api_key text,
    config jsonb NOT NULL DEFAULT '{}'::jsonb,
    last_sync_at timestamp,
    created_at timestamp NOT NULL DEFAULT NOW(),
    updated_at timestamp NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS file_offsets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    log_type varchar(20) NOT NULL,
    log_path varchar(1024) NOT NULL,
    byte_offset bigint NOT NULL DEFAULT 0,
    updated_at timestamp NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_file_offsets_path_type UNIQUE (log_path, log_type)
);

CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username varchar(64) NOT NULL UNIQUE,
    hashed_password text NOT NULL,
    role varchar(20) NOT NULL DEFAULT 'analyst',
    is_active boolean NOT NULL DEFAULT true,
    created_at timestamp NOT NULL DEFAULT NOW(),
    updated_at timestamp NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_fingerprints_composite
    ON fingerprints (
        asset_id,
        COALESCE(ja3, ''),
        COALESCE(ja3s, ''),
        COALESCE(user_agent, ''),
        COALESCE(dhcp_vendor, '')
    );

CREATE UNIQUE INDEX IF NOT EXISTS uq_connections_flow
    ON connections (
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        date_trunc('minute', COALESCE(timestamp, '1970-01-01'::timestamp))
    );

DROP INDEX IF EXISTS uq_alerts_dedup;

CREATE UNIQUE INDEX IF NOT EXISTS uq_alerts_runtime_dedup
    ON alerts (
        alert_type,
        COALESCE(source_ip, ''),
        date_trunc('hour', created_at)
    )
    WHERE alert_type <> 'vulnerability';

CREATE UNIQUE INDEX IF NOT EXISTS uq_alerts_vulnerability_dedup
    ON alerts (
        alert_type,
        asset_id,
        COALESCE(metadata->>'vulnerability_id', '')
    )
    WHERE alert_type = 'vulnerability';

CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_connections_timestamp ON connections (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_dns_queries_timestamp ON dns_queries (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_tls_sessions_timestamp ON tls_sessions (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_http_sessions_timestamp ON http_sessions (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_inference_results_asset_created ON inference_results (asset_id, created_at DESC);

CREATE TABLE IF NOT EXISTS merge_history (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    canonical_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    merged_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    merge_reason varchar NOT NULL,
    merge_evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamp NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_merge_history_canonical ON merge_history (canonical_id);
CREATE INDEX IF NOT EXISTS idx_merge_history_merged ON merge_history (merged_id);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets (asset_status) WHERE asset_status != 'active';
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cpe ON vulnerabilities (cpe);
CREATE INDEX IF NOT EXISTS idx_asset_vulns_asset ON asset_vulnerabilities (asset_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_asset_id ON alerts (asset_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs (status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_created_at ON scan_jobs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_file_offsets_log_path ON file_offsets (log_path);

INSERT INTO users (username, hashed_password, role)
VALUES (
    'admin',
    '$2b$12$YPkbyaA.auX4DawwaeR29.RNDNUqsr1ZSxksFmkpx1yiUyWGXhPPi',
    'admin'
)
ON CONFLICT (username) DO NOTHING;