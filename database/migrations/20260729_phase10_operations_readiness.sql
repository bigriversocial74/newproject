SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE TABLE IF NOT EXISTS operational_health_signals (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_scope BIGINT UNSIGNED NOT NULL DEFAULT 0,
    source_type VARCHAR(80) NOT NULL,
    source_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
    health_status ENUM('healthy','unhealthy') NOT NULL,
    severity ENUM('info','warning','critical') NOT NULL DEFAULT 'warning',
    evidence_hash CHAR(64) NOT NULL,
    observed_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_operational_signal_source (account_scope, source_type, source_id),
    KEY idx_operational_signal_health (health_status, observed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS operational_incidents (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    account_scope BIGINT UNSIGNED NOT NULL DEFAULT 0,
    incident_key CHAR(64) NOT NULL,
    source_type VARCHAR(80) NOT NULL,
    source_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
    severity ENUM('info','warning','critical') NOT NULL,
    status ENUM('open','acknowledged','resolved') NOT NULL DEFAULT 'open',
    active_marker TINYINT UNSIGNED NULL DEFAULT 1,
    monitor_managed TINYINT(1) NOT NULL DEFAULT 0,
    title VARCHAR(190) NOT NULL,
    summary_hash CHAR(64) NOT NULL,
    evidence_hash CHAR(64) NOT NULL,
    occurrence_count INT UNSIGNED NOT NULL DEFAULT 1,
    first_detected_at DATETIME NOT NULL,
    last_detected_at DATETIME NOT NULL,
    acknowledged_at DATETIME NULL,
    acknowledged_by BIGINT UNSIGNED NULL,
    resolved_at DATETIME NULL,
    resolved_by BIGINT UNSIGNED NULL,
    resolution_hash CHAR(64) NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_operational_incident_public (public_id),
    UNIQUE KEY uq_operational_active_incident (account_scope, incident_key, active_marker),
    KEY idx_operational_incident_account_status (account_scope, status, severity),
    KEY idx_operational_incident_source (source_type, source_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS operational_incident_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    incident_id BIGINT UNSIGNED NOT NULL,
    event_type VARCHAR(80) NOT NULL,
    event_status ENUM('open','acknowledged','resolved') NOT NULL,
    severity ENUM('info','warning','critical') NOT NULL,
    actor_type VARCHAR(40) NOT NULL,
    actor_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
    payload_hash CHAR(64) NOT NULL,
    previous_chain_hash CHAR(64) NOT NULL,
    chain_hash CHAR(64) NOT NULL,
    occurred_at DATETIME(6) NOT NULL,
    UNIQUE KEY uq_operational_incident_event_chain (chain_hash),
    KEY idx_operational_incident_event_time (incident_id, occurred_at),
    CONSTRAINT fk_operational_event_incident FOREIGN KEY (incident_id) REFERENCES operational_incidents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS operational_notification_channels (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    account_scope BIGINT UNSIGNED NOT NULL DEFAULT 0,
    channel_type VARCHAR(40) NOT NULL,
    label VARCHAR(190) NOT NULL,
    status ENUM('active','paused','revoked') NOT NULL DEFAULT 'active',
    severity_threshold ENUM('info','warning','critical') NOT NULL DEFAULT 'warning',
    destination_ciphertext LONGTEXT NOT NULL,
    destination_nonce VARCHAR(64) NOT NULL,
    destination_tag VARCHAR(64) NOT NULL,
    encryption_key_id VARCHAR(80) NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,
    UNIQUE KEY uq_operational_channel_public (public_id),
    UNIQUE KEY uq_operational_channel_identity (account_scope, channel_type, label),
    KEY idx_operational_channel_account_status (account_scope, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS operational_notifications (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    incident_id BIGINT UNSIGNED NOT NULL,
    incident_event_id BIGINT UNSIGNED NOT NULL,
    channel_id BIGINT UNSIGNED NOT NULL,
    event_type VARCHAR(80) NOT NULL,
    event_status ENUM('open','acknowledged','resolved') NOT NULL,
    severity ENUM('info','warning','critical') NOT NULL,
    delivery_key CHAR(64) NOT NULL,
    payload_hash CHAR(64) NOT NULL,
    status ENUM('queued','running','delivered','failed','canceled') NOT NULL DEFAULT 'queued',
    attempts SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    max_attempts SMALLINT UNSIGNED NOT NULL DEFAULT 5,
    available_at DATETIME NOT NULL,
    locked_at DATETIME NULL,
    locked_by VARCHAR(128) NULL,
    last_error_hash CHAR(64) NULL,
    created_at DATETIME NOT NULL,
    delivered_at DATETIME NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_operational_notification_public (public_id),
    UNIQUE KEY uq_operational_notification_delivery (delivery_key),
    KEY idx_operational_notification_claim (status, available_at, id),
    CONSTRAINT fk_operational_notification_incident FOREIGN KEY (incident_id) REFERENCES operational_incidents(id) ON DELETE CASCADE,
    CONSTRAINT fk_operational_notification_event FOREIGN KEY (incident_event_id) REFERENCES operational_incident_events(id) ON DELETE CASCADE,
    CONSTRAINT fk_operational_notification_channel FOREIGN KEY (channel_id) REFERENCES operational_notification_channels(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS operational_notification_receipts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    notification_id BIGINT UNSIGNED NOT NULL,
    result ENUM('delivered','failed','ignored') NOT NULL,
    receipt_hash CHAR(64) NOT NULL,
    response_hash CHAR(64) NULL,
    created_at DATETIME NOT NULL,
    KEY idx_operational_notification_receipt_time (notification_id, created_at),
    CONSTRAINT fk_operational_receipt_notification FOREIGN KEY (notification_id) REFERENCES operational_notifications(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS operational_audit_heads (
    id TINYINT UNSIGNED PRIMARY KEY,
    last_chain_hash CHAR(64) NOT NULL,
    updated_at DATETIME(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO operational_audit_heads (id,last_chain_hash,updated_at)
VALUES (1,REPEAT('0',64),UTC_TIMESTAMP(6));

CREATE TABLE IF NOT EXISTS operational_audit_chain (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scope_type VARCHAR(80) NOT NULL,
    scope_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
    event_type VARCHAR(100) NOT NULL,
    actor_type VARCHAR(40) NOT NULL,
    actor_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
    payload_hash CHAR(64) NOT NULL,
    previous_chain_hash CHAR(64) NOT NULL,
    chain_hash CHAR(64) NOT NULL,
    occurred_at DATETIME(6) NOT NULL,
    UNIQUE KEY uq_operational_audit_chain_hash (chain_hash),
    KEY idx_operational_audit_scope_time (scope_type, scope_id, occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS operational_monitor_runs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    worker_id VARCHAR(128) NOT NULL,
    status ENUM('running','completed','failed') NOT NULL DEFAULT 'running',
    checked_count INT UNSIGNED NOT NULL DEFAULT 0,
    opened_count INT UNSIGNED NOT NULL DEFAULT 0,
    resolved_count INT UNSIGNED NOT NULL DEFAULT 0,
    evidence_hash CHAR(64) NULL,
    started_at DATETIME NOT NULL,
    completed_at DATETIME NULL,
    UNIQUE KEY uq_operational_monitor_public (public_id),
    KEY idx_operational_monitor_time (status, started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS operational_readiness_assessments (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    status ENUM('ready','warning','blocked') NOT NULL,
    score DECIMAL(5,2) NOT NULL,
    blocker_count INT UNSIGNED NOT NULL DEFAULT 0,
    warning_count INT UNSIGNED NOT NULL DEFAULT 0,
    evidence_hash CHAR(64) NOT NULL,
    assessor_type VARCHAR(40) NOT NULL,
    assessor_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_operational_readiness_public (public_id),
    KEY idx_operational_readiness_time (status, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS operational_readiness_checks (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    assessment_id BIGINT UNSIGNED NOT NULL,
    check_code VARCHAR(100) NOT NULL,
    status ENUM('pass','warning','fail') NOT NULL,
    severity ENUM('advisory','warning','blocker') NOT NULL,
    evidence_hash CHAR(64) NOT NULL,
    details_hash CHAR(64) NOT NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_operational_readiness_check (assessment_id, check_code),
    CONSTRAINT fk_operational_readiness_assessment FOREIGN KEY (assessment_id) REFERENCES operational_readiness_assessments(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS operational_request_receipts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_scope BIGINT UNSIGNED NOT NULL DEFAULT 0,
    request_id VARCHAR(80) NOT NULL,
    operation VARCHAR(100) NOT NULL,
    result ENUM('success','failure','denied','ignored') NOT NULL,
    resource_type VARCHAR(80) NULL,
    resource_id BIGINT UNSIGNED NULL,
    receipt_hash CHAR(64) NOT NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_operational_request_receipt (account_scope, request_id, operation),
    KEY idx_operational_request_time (account_scope, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
