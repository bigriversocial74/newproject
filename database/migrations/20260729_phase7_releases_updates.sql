SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE TABLE IF NOT EXISTS software_products (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    code VARCHAR(64) NOT NULL,
    name VARCHAR(190) NOT NULL,
    target_type ENUM('pod','homeserver') NOT NULL,
    status ENUM('active','retired') NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_software_product_public (public_id),
    UNIQUE KEY uq_software_product_code (code),
    UNIQUE KEY uq_software_product_target (target_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS software_releases (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    product_id BIGINT UNSIGNED NOT NULL,
    version VARCHAR(80) NOT NULL,
    channel ENUM('stable','beta','security') NOT NULL,
    status ENUM('draft','published','paused','withdrawn') NOT NULL DEFAULT 'draft',
    release_notes_hash CHAR(64) NULL,
    manifest_hash CHAR(64) NULL,
    manifest_signature VARCHAR(512) NULL,
    signature_algorithm VARCHAR(40) NULL,
    signing_key_id VARCHAR(80) NULL,
    emergency_override TINYINT(1) NOT NULL DEFAULT 0,
    published_at DATETIME NULL,
    withdrawn_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_software_release_public (public_id),
    UNIQUE KEY uq_software_release_version (product_id, version, channel),
    KEY idx_software_release_product_status (product_id, status, channel),
    CONSTRAINT fk_software_release_product FOREIGN KEY (product_id) REFERENCES software_products(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS release_artifacts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    release_id BIGINT UNSIGNED NOT NULL,
    platform VARCHAR(80) NOT NULL,
    architecture VARCHAR(80) NOT NULL,
    storage_reference VARCHAR(512) NOT NULL,
    sha256 CHAR(64) NOT NULL,
    size_bytes BIGINT UNSIGNED NOT NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_release_artifact_target (release_id, platform, architecture),
    CONSTRAINT fk_release_artifact_release FOREIGN KEY (release_id) REFERENCES software_releases(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS release_compatibility_rules (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    release_id BIGINT UNSIGNED NOT NULL,
    minimum_current_version VARCHAR(80) NULL,
    maximum_current_version VARCHAR(80) NULL,
    minimum_php_version VARCHAR(40) NULL,
    database_family ENUM('any','mysql','mariadb') NOT NULL DEFAULT 'any',
    minimum_database_version VARCHAR(40) NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_release_compatibility_release (release_id),
    CONSTRAINT fk_release_compatibility_release FOREIGN KEY (release_id) REFERENCES software_releases(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS release_rollouts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    release_id BIGINT UNSIGNED NOT NULL,
    status ENUM('planned','active','paused','completed','canceled') NOT NULL DEFAULT 'planned',
    percentage TINYINT UNSIGNED NOT NULL DEFAULT 0,
    cohort_seed VARCHAR(128) NOT NULL,
    starts_at DATETIME NULL,
    ends_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_release_rollout_release (release_id),
    KEY idx_release_rollout_active (status, starts_at, ends_at),
    CONSTRAINT fk_release_rollout_release FOREIGN KEY (release_id) REFERENCES software_releases(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS update_jobs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    target_type ENUM('pod','homeserver') NOT NULL,
    pod_deployment_id BIGINT UNSIGNED NULL,
    homeserver_device_id BIGINT UNSIGNED NULL,
    release_id BIGINT UNSIGNED NOT NULL,
    status ENUM('queued','running','validating','backing_up','downloading','installing','migrating','verifying','completed','rolling_back','rolled_back','failed','paused','canceled') NOT NULL DEFAULT 'queued',
    current_stage VARCHAR(80) NULL,
    previous_version VARCHAR(80) NULL,
    target_version VARCHAR(80) NOT NULL,
    pre_update_backup_reference VARCHAR(512) NULL,
    pre_update_backup_hash CHAR(64) NULL,
    pre_update_backup_verified TINYINT(1) NOT NULL DEFAULT 0,
    attempts SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    max_attempts SMALLINT UNSIGNED NOT NULL DEFAULT 3,
    idempotency_key VARCHAR(128) NOT NULL,
    request_id VARCHAR(64) NOT NULL,
    available_at DATETIME NOT NULL,
    locked_at DATETIME NULL,
    locked_by VARCHAR(128) NULL,
    started_at DATETIME NULL,
    completed_at DATETIME NULL,
    last_error_code VARCHAR(100) NULL,
    last_error_message VARCHAR(1000) NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_update_job_public (public_id),
    UNIQUE KEY uq_update_job_idempotency (account_id, idempotency_key),
    KEY idx_update_job_claim (status, available_at, id),
    KEY idx_update_job_pod (pod_deployment_id, created_at),
    KEY idx_update_job_homeserver (homeserver_device_id, created_at),
    CONSTRAINT fk_update_job_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_update_job_pod FOREIGN KEY (pod_deployment_id) REFERENCES pod_deployments(id) ON DELETE RESTRICT,
    CONSTRAINT fk_update_job_homeserver FOREIGN KEY (homeserver_device_id) REFERENCES homeserver_devices(id) ON DELETE RESTRICT,
    CONSTRAINT fk_update_job_release FOREIGN KEY (release_id) REFERENCES software_releases(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS update_steps (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    job_id BIGINT UNSIGNED NOT NULL,
    stage VARCHAR(80) NOT NULL,
    sequence_no SMALLINT UNSIGNED NOT NULL,
    status ENUM('pending','running','completed','failed','skipped','rolled_back') NOT NULL DEFAULT 'pending',
    attempts SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    receipt_hash CHAR(64) NULL,
    started_at DATETIME NULL,
    completed_at DATETIME NULL,
    rolled_back_at DATETIME NULL,
    last_error_code VARCHAR(100) NULL,
    last_error_message VARCHAR(1000) NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_update_step_job_stage (job_id, stage),
    UNIQUE KEY uq_update_step_job_sequence (job_id, sequence_no),
    CONSTRAINT fk_update_step_job FOREIGN KEY (job_id) REFERENCES update_jobs(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS update_receipts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    job_id BIGINT UNSIGNED NOT NULL,
    step_id BIGINT UNSIGNED NULL,
    request_id VARCHAR(64) NOT NULL,
    operation VARCHAR(100) NOT NULL,
    result ENUM('success','failure','denied','ignored') NOT NULL,
    receipt_hash CHAR(64) NULL,
    metadata_json JSON NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_update_receipt_public (public_id),
    KEY idx_update_receipt_job_time (job_id, created_at),
    KEY idx_update_receipt_account_time (account_id, created_at),
    CONSTRAINT fk_update_receipt_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_update_receipt_job FOREIGN KEY (job_id) REFERENCES update_jobs(id) ON DELETE CASCADE,
    CONSTRAINT fk_update_receipt_step FOREIGN KEY (step_id) REFERENCES update_steps(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS release_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    release_id BIGINT UNSIGNED NOT NULL,
    request_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    result ENUM('success','failure','denied') NOT NULL,
    metadata_json JSON NULL,
    created_at DATETIME NOT NULL,
    KEY idx_release_event_release_time (release_id, created_at),
    CONSTRAINT fk_release_event_release FOREIGN KEY (release_id) REFERENCES software_releases(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
