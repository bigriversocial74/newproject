SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE TABLE IF NOT EXISTS security_incident_cases (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    account_scope BIGINT UNSIGNED NOT NULL,
    operational_incident_id BIGINT UNSIGNED NOT NULL,
    source_audit_event_id BIGINT UNSIGNED NOT NULL,
    case_status ENUM('triage','investigating','contained','resolved') NOT NULL DEFAULT 'triage',
    assigned_user_id BIGINT UNSIGNED NULL,
    created_by_user_id BIGINT UNSIGNED NOT NULL,
    last_action_at DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    UNIQUE KEY uq_security_incident_case_public (public_id),
    UNIQUE KEY uq_security_incident_case_event (source_audit_event_id),
    UNIQUE KEY uq_security_incident_case_operational (operational_incident_id),
    KEY idx_security_incident_case_account_status (account_scope, case_status, updated_at),
    KEY idx_security_incident_case_assignee (account_scope, assigned_user_id, case_status),
    CONSTRAINT fk_security_incident_case_operational FOREIGN KEY (operational_incident_id) REFERENCES operational_incidents(id) ON DELETE CASCADE,
    CONSTRAINT fk_security_incident_case_event FOREIGN KEY (source_audit_event_id) REFERENCES security_audit_events(id) ON DELETE RESTRICT,
    CONSTRAINT fk_security_incident_case_assignee FOREIGN KEY (assigned_user_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_security_incident_case_creator FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS security_incident_notes (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    case_id BIGINT UNSIGNED NOT NULL,
    author_user_id BIGINT UNSIGNED NOT NULL,
    note_ciphertext LONGTEXT NOT NULL,
    note_nonce VARCHAR(64) NOT NULL,
    note_tag VARCHAR(64) NOT NULL,
    encryption_key_id VARCHAR(80) NOT NULL,
    note_hash CHAR(64) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    UNIQUE KEY uq_security_incident_note_public (public_id),
    KEY idx_security_incident_note_case_time (case_id, created_at),
    CONSTRAINT fk_security_incident_note_case FOREIGN KEY (case_id) REFERENCES security_incident_cases(id) ON DELETE CASCADE,
    CONSTRAINT fk_security_incident_note_author FOREIGN KEY (author_user_id) REFERENCES users(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS security_alert_preferences (
    account_scope BIGINT UNSIGNED PRIMARY KEY,
    automatic_promotion_enabled TINYINT(1) NOT NULL DEFAULT 0,
    minimum_risk ENUM('low','medium','high','critical') NOT NULL DEFAULT 'high',
    include_integrity_failures TINYINT(1) NOT NULL DEFAULT 1,
    notify_on_promotion TINYINT(1) NOT NULL DEFAULT 1,
    notify_on_emergency_action TINYINT(1) NOT NULL DEFAULT 1,
    updated_by_user_id BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    KEY idx_security_alert_automatic (automatic_promotion_enabled, minimum_risk, account_scope),
    CONSTRAINT fk_security_alert_preference_user FOREIGN KEY (updated_by_user_id) REFERENCES users(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS security_response_actions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    account_scope BIGINT UNSIGNED NOT NULL,
    case_id BIGINT UNSIGNED NULL,
    actor_user_id BIGINT UNSIGNED NOT NULL,
    target_user_id BIGINT UNSIGNED NULL,
    request_id VARCHAR(80) NOT NULL,
    action_type VARCHAR(100) NOT NULL,
    result ENUM('success','failure','denied','ignored') NOT NULL,
    evidence_hash CHAR(64) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    UNIQUE KEY uq_security_response_action_public (public_id),
    UNIQUE KEY uq_security_response_action_request (account_scope, request_id, action_type),
    KEY idx_security_response_action_case_time (case_id, created_at),
    KEY idx_security_response_action_account_time (account_scope, created_at),
    CONSTRAINT fk_security_response_action_case FOREIGN KEY (case_id) REFERENCES security_incident_cases(id) ON DELETE SET NULL,
    CONSTRAINT fk_security_response_action_actor FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE RESTRICT,
    CONSTRAINT fk_security_response_action_target FOREIGN KEY (target_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
