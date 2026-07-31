SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE TABLE IF NOT EXISTS reliability_components (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(40) NOT NULL,
    account_scope BIGINT UNSIGNED NOT NULL,
    component_key VARCHAR(80) NOT NULL,
    display_name VARCHAR(160) NOT NULL,
    component_type ENUM('platform','http','dns','ssl','database','worker','queue','storage','provider','pod','homeserver') NOT NULL,
    visibility ENUM('public','private') NOT NULL DEFAULT 'private',
    environment_id BIGINT UNSIGNED NULL,
    current_status ENUM('operational','degraded','major_outage','maintenance','unknown') NOT NULL DEFAULT 'unknown',
    status_since DATETIME(6) NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    display_order INT UNSIGNED NOT NULL DEFAULT 100,
    created_by_user_id BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_reliability_component_public (public_id),
    UNIQUE KEY uq_reliability_component_key (account_scope, component_key),
    KEY idx_reliability_component_status (account_scope, enabled, current_status, display_order),
    CONSTRAINT fk_reliability_component_account FOREIGN KEY (account_scope)
        REFERENCES accounts (id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CONSTRAINT fk_reliability_component_environment FOREIGN KEY (environment_id)
        REFERENCES platform_deployment_environments (id) ON DELETE SET NULL ON UPDATE RESTRICT,
    CONSTRAINT fk_reliability_component_created_by FOREIGN KEY (created_by_user_id)
        REFERENCES users (id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS reliability_objectives (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(40) NOT NULL,
    component_id BIGINT UNSIGNED NOT NULL,
    availability_target_bps SMALLINT UNSIGNED NOT NULL DEFAULT 9990,
    latency_target_ms INT UNSIGNED NULL,
    evaluation_window_minutes INT UNSIGNED NOT NULL DEFAULT 43200,
    warning_burn_rate DECIMAL(8,2) NOT NULL DEFAULT 2.00,
    critical_burn_rate DECIMAL(8,2) NOT NULL DEFAULT 14.40,
    consecutive_failure_threshold SMALLINT UNSIGNED NOT NULL DEFAULT 3,
    recovery_success_threshold SMALLINT UNSIGNED NOT NULL DEFAULT 2,
    created_by_user_id BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_reliability_objective_public (public_id),
    UNIQUE KEY uq_reliability_objective_component (component_id),
    CONSTRAINT fk_reliability_objective_component FOREIGN KEY (component_id)
        REFERENCES reliability_components (id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CONSTRAINT fk_reliability_objective_created_by FOREIGN KEY (created_by_user_id)
        REFERENCES users (id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS reliability_probes (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(40) NOT NULL,
    component_id BIGINT UNSIGNED NOT NULL,
    probe_type ENUM('http','dns','ssl','database','worker','queue','storage','manual') NOT NULL,
    target_value VARCHAR(500) NOT NULL,
    target_hash CHAR(64) NOT NULL,
    interval_seconds INT UNSIGNED NOT NULL DEFAULT 300,
    timeout_ms INT UNSIGNED NOT NULL DEFAULT 5000,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    next_due_at DATETIME(6) NOT NULL,
    locked_by_hash CHAR(64) NULL,
    lock_expires_at DATETIME(6) NULL,
    last_started_at DATETIME(6) NULL,
    last_finished_at DATETIME(6) NULL,
    created_by_user_id BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_reliability_probe_public (public_id),
    UNIQUE KEY uq_reliability_probe_component_type (component_id, probe_type),
    KEY idx_reliability_probe_due (enabled, next_due_at, lock_expires_at),
    CONSTRAINT fk_reliability_probe_component FOREIGN KEY (component_id)
        REFERENCES reliability_components (id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CONSTRAINT fk_reliability_probe_created_by FOREIGN KEY (created_by_user_id)
        REFERENCES users (id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS reliability_probe_results (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(40) NOT NULL,
    probe_id BIGINT UNSIGNED NOT NULL,
    component_id BIGINT UNSIGNED NOT NULL,
    release_candidate_id BIGINT UNSIGNED NULL,
    result_status ENUM('success','failure','maintenance') NOT NULL,
    latency_ms INT UNSIGNED NULL,
    value_numeric DECIMAL(20,4) NULL,
    error_code VARCHAR(100) NULL,
    evidence_hash CHAR(64) NOT NULL,
    observed_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_reliability_result_public (public_id),
    KEY idx_reliability_result_component_time (component_id, observed_at),
    KEY idx_reliability_result_probe_time (probe_id, observed_at),
    CONSTRAINT fk_reliability_result_probe FOREIGN KEY (probe_id)
        REFERENCES reliability_probes (id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CONSTRAINT fk_reliability_result_component FOREIGN KEY (component_id)
        REFERENCES reliability_components (id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CONSTRAINT fk_reliability_result_candidate FOREIGN KEY (release_candidate_id)
        REFERENCES platform_release_candidates (id) ON DELETE SET NULL ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS reliability_budget_snapshots (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(40) NOT NULL,
    component_id BIGINT UNSIGNED NOT NULL,
    window_started_at DATETIME(6) NOT NULL,
    window_ended_at DATETIME(6) NOT NULL,
    total_probes INT UNSIGNED NOT NULL,
    failed_probes INT UNSIGNED NOT NULL,
    availability_bps SMALLINT UNSIGNED NOT NULL,
    budget_consumed_bps INT UNSIGNED NOT NULL,
    burn_rate DECIMAL(12,4) NOT NULL,
    budget_status ENUM('healthy','warning','exhausted') NOT NULL,
    evidence_hash CHAR(64) NOT NULL,
    captured_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_reliability_budget_public (public_id),
    KEY idx_reliability_budget_component_time (component_id, captured_at),
    CONSTRAINT fk_reliability_budget_component FOREIGN KEY (component_id)
        REFERENCES reliability_components (id) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS reliability_incident_links (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    component_id BIGINT UNSIGNED NOT NULL,
    operational_incident_id BIGINT UNSIGNED NOT NULL,
    opened_result_id BIGINT UNSIGNED NOT NULL,
    resolved_result_id BIGINT UNSIGNED NULL,
    link_status ENUM('open','resolved') NOT NULL DEFAULT 'open',
    active_marker TINYINT(1) NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_reliability_incident_active (component_id, active_marker),
    KEY idx_reliability_incident_operational (operational_incident_id),
    CONSTRAINT fk_reliability_incident_component FOREIGN KEY (component_id)
        REFERENCES reliability_components (id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CONSTRAINT fk_reliability_incident_operational FOREIGN KEY (operational_incident_id)
        REFERENCES operational_incidents (id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CONSTRAINT fk_reliability_incident_open_result FOREIGN KEY (opened_result_id)
        REFERENCES reliability_probe_results (id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_reliability_incident_resolved_result FOREIGN KEY (resolved_result_id)
        REFERENCES reliability_probe_results (id) ON DELETE SET NULL ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS reliability_status_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    component_id BIGINT UNSIGNED NOT NULL,
    previous_status ENUM('operational','degraded','major_outage','maintenance','unknown') NOT NULL,
    current_status ENUM('operational','degraded','major_outage','maintenance','unknown') NOT NULL,
    reason_code VARCHAR(100) NOT NULL,
    evidence_hash CHAR(64) NOT NULL,
    previous_hash CHAR(64) NULL,
    event_hash CHAR(64) NOT NULL,
    occurred_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_reliability_status_event_hash (event_hash),
    KEY idx_reliability_status_component (component_id, id),
    CONSTRAINT fk_reliability_status_component FOREIGN KEY (component_id)
        REFERENCES reliability_components (id) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS reliability_status_settings (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    account_scope BIGINT UNSIGNED NOT NULL,
    public_slug VARCHAR(80) NOT NULL,
    page_title VARCHAR(160) NOT NULL,
    page_description VARCHAR(500) NOT NULL,
    public_enabled TINYINT(1) NOT NULL DEFAULT 0,
    show_history TINYINT(1) NOT NULL DEFAULT 1,
    created_by_user_id BIGINT UNSIGNED NOT NULL,
    updated_by_user_id BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_reliability_status_account (account_scope),
    UNIQUE KEY uq_reliability_status_slug (public_slug),
    CONSTRAINT fk_reliability_status_account FOREIGN KEY (account_scope)
        REFERENCES accounts (id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CONSTRAINT fk_reliability_status_created_by FOREIGN KEY (created_by_user_id)
        REFERENCES users (id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_reliability_status_updated_by FOREIGN KEY (updated_by_user_id)
        REFERENCES users (id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS reliability_status_messages (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(40) NOT NULL,
    account_scope BIGINT UNSIGNED NOT NULL,
    component_id BIGINT UNSIGNED NULL,
    request_id VARCHAR(80) NOT NULL,
    title VARCHAR(160) NOT NULL,
    message VARCHAR(1000) NOT NULL,
    message_status ENUM('scheduled','published','resolved','cancelled') NOT NULL DEFAULT 'published',
    starts_at DATETIME(6) NOT NULL,
    ends_at DATETIME(6) NULL,
    created_by_user_id BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_reliability_message_public (public_id),
    UNIQUE KEY uq_reliability_message_request (account_scope, request_id),
    KEY idx_reliability_message_publication (account_scope, message_status, starts_at, ends_at),
    CONSTRAINT fk_reliability_message_account FOREIGN KEY (account_scope)
        REFERENCES accounts (id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CONSTRAINT fk_reliability_message_component FOREIGN KEY (component_id)
        REFERENCES reliability_components (id) ON DELETE SET NULL ON UPDATE RESTRICT,
    CONSTRAINT fk_reliability_message_created_by FOREIGN KEY (created_by_user_id)
        REFERENCES users (id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS reliability_action_receipts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(40) NOT NULL,
    account_scope BIGINT UNSIGNED NOT NULL,
    request_id VARCHAR(80) NOT NULL,
    action_type VARCHAR(80) NOT NULL,
    result ENUM('success','failure','denied','ignored') NOT NULL,
    resource_public_id VARCHAR(40) NULL,
    evidence_hash CHAR(64) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_reliability_receipt_public (public_id),
    UNIQUE KEY uq_reliability_receipt_request (account_scope, request_id, action_type),
    KEY idx_reliability_receipt_account (account_scope, created_at),
    CONSTRAINT fk_reliability_receipt_account FOREIGN KEY (account_scope)
        REFERENCES accounts (id) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
