SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE TABLE IF NOT EXISTS platform_operator_accounts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(40) NOT NULL,
    account_scope BIGINT UNSIGNED NOT NULL,
    operator_status ENUM('active','revoked') NOT NULL DEFAULT 'active',
    granted_by_user_id BIGINT UNSIGNED NOT NULL,
    granted_at DATETIME(6) NOT NULL,
    revoked_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_platform_operator_public (public_id),
    UNIQUE KEY uq_platform_operator_account (account_scope),
    KEY idx_platform_operator_status (operator_status, granted_at),
    CONSTRAINT fk_platform_operator_account FOREIGN KEY (account_scope)
        REFERENCES accounts (id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CONSTRAINT fk_platform_operator_granted_by FOREIGN KEY (granted_by_user_id)
        REFERENCES users (id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS platform_release_candidates (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(40) NOT NULL,
    release_version VARCHAR(64) NOT NULL,
    commit_sha VARCHAR(64) NOT NULL,
    schema_level INT UNSIGNED NOT NULL,
    manifest_sha256 CHAR(64) NOT NULL,
    installer_sha256 CHAR(64) NOT NULL,
    source_tree_sha256 CHAR(64) NOT NULL,
    source_file_count INT UNSIGNED NOT NULL,
    migration_count INT UNSIGNED NOT NULL,
    signing_key_id VARCHAR(64) NOT NULL,
    signature_base64 VARCHAR(128) NOT NULL,
    artifact_root_hash CHAR(64) NOT NULL,
    candidate_status ENUM('verified','approved','promoted','rejected','superseded') NOT NULL DEFAULT 'verified',
    registered_by_user_id BIGINT UNSIGNED NULL,
    verified_at DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_platform_candidate_public (public_id),
    UNIQUE KEY uq_platform_candidate_identity (release_version, commit_sha),
    KEY idx_platform_candidate_status (candidate_status, verified_at),
    CONSTRAINT fk_platform_candidate_registered_by FOREIGN KEY (registered_by_user_id)
        REFERENCES users (id) ON DELETE SET NULL ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS platform_deployment_environments (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(40) NOT NULL,
    environment_key ENUM('staging','production') NOT NULL,
    display_name VARCHAR(120) NOT NULL,
    base_url VARCHAR(500) NOT NULL,
    environment_status ENUM('active','maintenance','disabled') NOT NULL DEFAULT 'active',
    readiness_status ENUM('unknown','ready','blocked') NOT NULL DEFAULT 'unknown',
    current_candidate_id BIGINT UNSIGNED NULL,
    config_fingerprint CHAR(64) NULL,
    readiness_evidence_hash CHAR(64) NULL,
    worker_id_hash CHAR(64) NULL,
    worker_last_seen_at DATETIME(6) NULL,
    last_health_at DATETIME(6) NULL,
    created_by_user_id BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_platform_environment_public (public_id),
    UNIQUE KEY uq_platform_environment_key (environment_key),
    KEY idx_platform_environment_status (environment_status, readiness_status),
    CONSTRAINT fk_platform_environment_candidate FOREIGN KEY (current_candidate_id)
        REFERENCES platform_release_candidates (id) ON DELETE SET NULL ON UPDATE RESTRICT,
    CONSTRAINT fk_platform_environment_created_by FOREIGN KEY (created_by_user_id)
        REFERENCES users (id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS platform_maintenance_windows (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(40) NOT NULL,
    environment_id BIGINT UNSIGNED NOT NULL,
    account_scope BIGINT UNSIGNED NOT NULL,
    request_id VARCHAR(80) NOT NULL,
    window_status ENUM('scheduled','open','closed','cancelled') NOT NULL DEFAULT 'scheduled',
    starts_at DATETIME(6) NOT NULL,
    ends_at DATETIME(6) NOT NULL,
    reason VARCHAR(500) NOT NULL,
    created_by_user_id BIGINT UNSIGNED NOT NULL,
    approved_by_user_id BIGINT UNSIGNED NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_platform_window_public (public_id),
    UNIQUE KEY uq_platform_window_request (account_scope, request_id),
    KEY idx_platform_window_account (account_scope, starts_at),
    KEY idx_platform_window_due (environment_id, window_status, starts_at, ends_at),
    CONSTRAINT fk_platform_window_environment FOREIGN KEY (environment_id)
        REFERENCES platform_deployment_environments (id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CONSTRAINT fk_platform_window_account FOREIGN KEY (account_scope)
        REFERENCES accounts (id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CONSTRAINT fk_platform_window_created_by FOREIGN KEY (created_by_user_id)
        REFERENCES users (id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_platform_window_approved_by FOREIGN KEY (approved_by_user_id)
        REFERENCES users (id) ON DELETE SET NULL ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS platform_release_promotions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(40) NOT NULL,
    account_scope BIGINT UNSIGNED NOT NULL,
    release_candidate_id BIGINT UNSIGNED NOT NULL,
    previous_candidate_id BIGINT UNSIGNED NULL,
    source_environment_id BIGINT UNSIGNED NOT NULL,
    target_environment_id BIGINT UNSIGNED NOT NULL,
    maintenance_window_id BIGINT UNSIGNED NULL,
    deployment_run_public_id VARCHAR(40) NULL,
    backup_public_id VARCHAR(40) NULL,
    request_id VARCHAR(80) NOT NULL,
    promotion_status ENUM('requested','approved','scheduled','queued','deploying','completed','failed','cancelled','rollback_queued','rolling_back','rolled_back') NOT NULL DEFAULT 'requested',
    requested_by_user_id BIGINT UNSIGNED NOT NULL,
    approved_by_user_id BIGINT UNSIGNED NULL,
    scheduled_for DATETIME(6) NULL,
    backup_required TINYINT(1) NOT NULL DEFAULT 1,
    health_required TINYINT(1) NOT NULL DEFAULT 1,
    failure_code VARCHAR(100) NULL,
    evidence_hash CHAR(64) NULL,
    worker_id_hash CHAR(64) NULL,
    lease_expires_at DATETIME(6) NULL,
    attempt_count INT UNSIGNED NOT NULL DEFAULT 0,
    requested_at DATETIME(6) NOT NULL,
    approved_at DATETIME(6) NULL,
    started_at DATETIME(6) NULL,
    finished_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_platform_promotion_public (public_id),
    UNIQUE KEY uq_platform_promotion_request (account_scope, request_id),
    KEY idx_platform_promotion_queue (target_environment_id, promotion_status, scheduled_for, lease_expires_at),
    KEY idx_platform_promotion_account (account_scope, requested_at),
    CONSTRAINT fk_platform_promotion_account FOREIGN KEY (account_scope)
        REFERENCES accounts (id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CONSTRAINT fk_platform_promotion_candidate FOREIGN KEY (release_candidate_id)
        REFERENCES platform_release_candidates (id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_platform_promotion_previous_candidate FOREIGN KEY (previous_candidate_id)
        REFERENCES platform_release_candidates (id) ON DELETE SET NULL ON UPDATE RESTRICT,
    CONSTRAINT fk_platform_promotion_source FOREIGN KEY (source_environment_id)
        REFERENCES platform_deployment_environments (id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_platform_promotion_target FOREIGN KEY (target_environment_id)
        REFERENCES platform_deployment_environments (id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_platform_promotion_window FOREIGN KEY (maintenance_window_id)
        REFERENCES platform_maintenance_windows (id) ON DELETE SET NULL ON UPDATE RESTRICT,
    CONSTRAINT fk_platform_promotion_requested_by FOREIGN KEY (requested_by_user_id)
        REFERENCES users (id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_platform_promotion_approved_by FOREIGN KEY (approved_by_user_id)
        REFERENCES users (id) ON DELETE SET NULL ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS platform_release_promotion_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    promotion_id BIGINT UNSIGNED NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    actor_user_id BIGINT UNSIGNED NULL,
    event_result ENUM('success','failure','denied','ignored') NOT NULL,
    metadata_hash CHAR(64) NOT NULL,
    previous_hash CHAR(64) NULL,
    event_hash CHAR(64) NOT NULL,
    occurred_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_platform_promotion_event_hash (event_hash),
    KEY idx_platform_promotion_events (promotion_id, id),
    CONSTRAINT fk_platform_promotion_event_promotion FOREIGN KEY (promotion_id)
        REFERENCES platform_release_promotions (id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CONSTRAINT fk_platform_promotion_event_actor FOREIGN KEY (actor_user_id)
        REFERENCES users (id) ON DELETE SET NULL ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS platform_release_promotion_steps (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    promotion_id BIGINT UNSIGNED NOT NULL,
    step_order INT UNSIGNED NOT NULL,
    step_key VARCHAR(120) NOT NULL,
    migration_path VARCHAR(255) NULL,
    step_status ENUM('pending','running','completed','failed','skipped','rolled_back') NOT NULL,
    evidence_hash CHAR(64) NULL,
    error_code VARCHAR(100) NULL,
    started_at DATETIME(6) NULL,
    completed_at DATETIME(6) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_platform_promotion_step (promotion_id, step_key),
    KEY idx_platform_promotion_step_status (promotion_id, step_status, step_order),
    CONSTRAINT fk_platform_promotion_step_promotion FOREIGN KEY (promotion_id)
        REFERENCES platform_release_promotions (id) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS platform_environment_health_snapshots (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(40) NOT NULL,
    environment_id BIGINT UNSIGNED NOT NULL,
    release_candidate_id BIGINT UNSIGNED NULL,
    health_status ENUM('ready','degraded','blocked') NOT NULL,
    checks_json JSON NOT NULL,
    evidence_hash CHAR(64) NOT NULL,
    captured_by VARCHAR(64) NOT NULL,
    captured_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_platform_health_public (public_id),
    KEY idx_platform_health_environment (environment_id, captured_at),
    CONSTRAINT fk_platform_health_environment FOREIGN KEY (environment_id)
        REFERENCES platform_deployment_environments (id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CONSTRAINT fk_platform_health_candidate FOREIGN KEY (release_candidate_id)
        REFERENCES platform_release_candidates (id) ON DELETE SET NULL ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS platform_release_control_receipts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(40) NOT NULL,
    account_scope BIGINT UNSIGNED NOT NULL,
    promotion_id BIGINT UNSIGNED NULL,
    request_id VARCHAR(80) NOT NULL,
    action_type VARCHAR(80) NOT NULL,
    result ENUM('success','failure','denied','ignored') NOT NULL,
    evidence_hash CHAR(64) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_platform_control_receipt_public (public_id),
    UNIQUE KEY uq_platform_control_receipt_request (account_scope, request_id, action_type),
    KEY idx_platform_control_receipt_account (account_scope, created_at),
    CONSTRAINT fk_platform_control_receipt_account FOREIGN KEY (account_scope)
        REFERENCES accounts (id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CONSTRAINT fk_platform_control_receipt_promotion FOREIGN KEY (promotion_id)
        REFERENCES platform_release_promotions (id) ON DELETE SET NULL ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
