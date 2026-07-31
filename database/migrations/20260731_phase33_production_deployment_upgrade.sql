SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE TABLE IF NOT EXISTS platform_schema_migrations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    migration_path VARCHAR(255) NOT NULL,
    migration_sha256 CHAR(64) NOT NULL,
    applied_release_version VARCHAR(64) NOT NULL,
    application_mode ENUM('baseline','fresh_install','upgrade') NOT NULL,
    applied_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_platform_schema_migration_path (migration_path),
    KEY idx_platform_schema_migration_release (applied_release_version, applied_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS platform_release_records (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(40) NOT NULL,
    release_version VARCHAR(64) NOT NULL,
    commit_sha VARCHAR(64) NOT NULL,
    schema_level INT UNSIGNED NOT NULL,
    installer_sha256 CHAR(64) NOT NULL,
    source_manifest_sha256 CHAR(64) NOT NULL,
    release_manifest_sha256 CHAR(64) NOT NULL,
    migration_count INT UNSIGNED NOT NULL,
    release_status ENUM('candidate','deploying','active','superseded','failed') NOT NULL DEFAULT 'candidate',
    activated_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_platform_release_public (public_id),
    UNIQUE KEY uq_platform_release_identity (release_version, commit_sha),
    KEY idx_platform_release_status (release_status, activated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS platform_deployment_runs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(40) NOT NULL,
    request_id VARCHAR(80) NOT NULL,
    operation ENUM('install','upgrade','verify','rollback') NOT NULL,
    from_release_version VARCHAR(64) NULL,
    to_release_version VARCHAR(64) NOT NULL,
    run_status ENUM('planned','preflight','backing_up','applying','verifying','completed','failed','rolling_back','rolled_back') NOT NULL DEFAULT 'planned',
    backup_public_id VARCHAR(40) NULL,
    lock_owner_hash CHAR(64) NOT NULL,
    error_code VARCHAR(80) NULL,
    evidence_hash CHAR(64) NULL,
    started_at DATETIME(6) NOT NULL,
    finished_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_platform_deployment_public (public_id),
    UNIQUE KEY uq_platform_deployment_request (request_id, operation),
    KEY idx_platform_deployment_status (run_status, started_at),
    KEY idx_platform_deployment_release (to_release_version, started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS platform_deployment_backups (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(40) NOT NULL,
    deployment_run_id BIGINT UNSIGNED NOT NULL,
    file_path_hash CHAR(64) NOT NULL,
    file_sha256 CHAR(64) NOT NULL,
    file_bytes BIGINT UNSIGNED NOT NULL,
    database_engine VARCHAR(32) NOT NULL,
    database_version VARCHAR(80) NOT NULL,
    backup_status ENUM('created','verified','restored','deleted','failed') NOT NULL DEFAULT 'created',
    created_at DATETIME(6) NOT NULL,
    verified_at DATETIME(6) NULL,
    restored_at DATETIME(6) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_platform_backup_public (public_id),
    UNIQUE KEY uq_platform_backup_run (deployment_run_id),
    KEY idx_platform_backup_status (backup_status, created_at),
    CONSTRAINT fk_platform_backup_run FOREIGN KEY (deployment_run_id)
        REFERENCES platform_deployment_runs (id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS platform_deployment_steps (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    deployment_run_id BIGINT UNSIGNED NOT NULL,
    step_order INT UNSIGNED NOT NULL,
    step_key VARCHAR(120) NOT NULL,
    migration_path VARCHAR(255) NULL,
    step_status ENUM('pending','running','completed','failed','skipped','rolled_back') NOT NULL DEFAULT 'pending',
    evidence_hash CHAR(64) NULL,
    error_code VARCHAR(80) NULL,
    started_at DATETIME(6) NULL,
    completed_at DATETIME(6) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_platform_deployment_step (deployment_run_id, step_key),
    KEY idx_platform_deployment_step_status (step_status, step_order),
    CONSTRAINT fk_platform_step_run FOREIGN KEY (deployment_run_id)
        REFERENCES platform_deployment_runs (id) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS platform_deployment_receipts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id VARCHAR(40) NOT NULL,
    deployment_run_id BIGINT UNSIGNED NULL,
    request_id VARCHAR(80) NOT NULL,
    action_type VARCHAR(80) NOT NULL,
    result ENUM('success','failure','denied','ignored') NOT NULL,
    evidence_hash CHAR(64) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_platform_receipt_public (public_id),
    UNIQUE KEY uq_platform_receipt_request (request_id, action_type),
    KEY idx_platform_receipt_run (deployment_run_id, created_at),
    CONSTRAINT fk_platform_receipt_run FOREIGN KEY (deployment_run_id)
        REFERENCES platform_deployment_runs (id) ON DELETE SET NULL ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
