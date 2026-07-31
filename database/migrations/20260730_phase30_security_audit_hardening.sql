SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE TABLE IF NOT EXISTS security_audit_heads (
    account_scope BIGINT UNSIGNED NOT NULL DEFAULT 0,
    last_sequence BIGINT UNSIGNED NOT NULL DEFAULT 0,
    last_chain_hash CHAR(64) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (account_scope)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO security_audit_heads
(account_scope,last_sequence,last_chain_hash,updated_at)
VALUES (0,0,REPEAT('0',64),UTC_TIMESTAMP(6));

CREATE TABLE IF NOT EXISTS security_audit_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    account_scope BIGINT UNSIGNED NOT NULL DEFAULT 0,
    sequence_number BIGINT UNSIGNED NOT NULL,
    request_id VARCHAR(80) NOT NULL,
    correlation_id VARCHAR(80) NULL,
    event_type VARCHAR(120) NOT NULL,
    category ENUM(
        'authentication',
        'session',
        'mfa',
        'team',
        'billing',
        'domain',
        'pod',
        'homeserver',
        'settings',
        'integrity',
        'platform'
    ) NOT NULL,
    risk_level ENUM('info','low','medium','high','critical') NOT NULL DEFAULT 'info',
    result ENUM('success','failure','denied','ignored') NOT NULL,
    actor_type VARCHAR(40) NOT NULL,
    actor_id BIGINT UNSIGNED NULL,
    actor_public_id VARCHAR(64) NULL,
    resource_type VARCHAR(80) NULL,
    resource_public_id VARCHAR(128) NULL,
    ip_hash CHAR(64) NULL,
    user_agent_hash CHAR(64) NULL,
    metadata_json JSON NULL,
    metadata_hash CHAR(64) NOT NULL,
    previous_chain_hash CHAR(64) NOT NULL,
    chain_hash CHAR(64) NOT NULL,
    occurred_at DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    UNIQUE KEY uq_security_audit_public (public_id),
    UNIQUE KEY uq_security_audit_scope_sequence (account_scope, sequence_number),
    UNIQUE KEY uq_security_audit_chain_hash (chain_hash),
    KEY idx_security_audit_scope_time (account_scope, occurred_at),
    KEY idx_security_audit_event_time (event_type, occurred_at),
    KEY idx_security_audit_risk_time (risk_level, occurred_at),
    KEY idx_security_audit_request (request_id),
    KEY idx_security_audit_actor_time (actor_id, occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS security_audit_retention_policies (
    account_scope BIGINT UNSIGNED NOT NULL DEFAULT 0,
    event_retention_days SMALLINT UNSIGNED NOT NULL DEFAULT 2555,
    export_retention_days SMALLINT UNSIGNED NOT NULL DEFAULT 7,
    legal_hold TINYINT(1) NOT NULL DEFAULT 0,
    updated_by BIGINT UNSIGNED NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (account_scope)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO security_audit_retention_policies
(account_scope,event_retention_days,export_retention_days,legal_hold,updated_by,created_at,updated_at)
VALUES (0,2555,7,0,NULL,UTC_TIMESTAMP(),UTC_TIMESTAMP());

CREATE TABLE IF NOT EXISTS security_audit_exports (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    account_scope BIGINT UNSIGNED NOT NULL DEFAULT 0,
    requested_by BIGINT UNSIGNED NOT NULL,
    format ENUM('csv','jsonl') NOT NULL,
    status ENUM('queued','building','ready','failed','expired') NOT NULL DEFAULT 'queued',
    filter_hash CHAR(64) NOT NULL,
    row_count INT UNSIGNED NOT NULL DEFAULT 0,
    content_hash CHAR(64) NULL,
    failure_hash CHAR(64) NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    completed_at DATETIME NULL,
    UNIQUE KEY uq_security_audit_export_public (public_id),
    KEY idx_security_audit_export_scope_time (account_scope, created_at),
    KEY idx_security_audit_export_status_expiry (status, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS security_reauthentication_challenges (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    account_scope BIGINT UNSIGNED NOT NULL DEFAULT 0,
    user_id BIGINT UNSIGNED NOT NULL,
    action_type VARCHAR(120) NOT NULL,
    challenge_hash CHAR(64) NOT NULL,
    context_hash CHAR(64) NOT NULL,
    status ENUM('pending','satisfied','expired','revoked') NOT NULL DEFAULT 'pending',
    expires_at DATETIME NOT NULL,
    satisfied_at DATETIME NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_security_reauth_public (public_id),
    UNIQUE KEY uq_security_reauth_challenge_hash (challenge_hash),
    KEY idx_security_reauth_user_status (user_id, status, expires_at),
    KEY idx_security_reauth_scope_action (account_scope, action_type, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS security_rate_limit_buckets (
    bucket_hash CHAR(64) NOT NULL,
    scope_type VARCHAR(40) NOT NULL,
    action_type VARCHAR(120) NOT NULL,
    window_started_at DATETIME(6) NOT NULL,
    attempt_count INT UNSIGNED NOT NULL DEFAULT 0,
    denied_count INT UNSIGNED NOT NULL DEFAULT 0,
    blocked_until DATETIME(6) NULL,
    last_request_id VARCHAR(80) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (bucket_hash),
    KEY idx_security_rate_limit_blocked (blocked_until),
    KEY idx_security_rate_limit_scope_action (scope_type, action_type, updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
