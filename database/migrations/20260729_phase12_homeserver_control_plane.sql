SET NAMES utf8mb4;
SET time_zone = '+00:00';

DROP PROCEDURE IF EXISTS vp3_phase12_homeserver_index_upgrade;
DELIMITER $$
CREATE PROCEDURE vp3_phase12_homeserver_index_upgrade()
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = 'homeserver_devices'
          AND index_name = 'idx_homeserver_license_status'
    ) THEN
        ALTER TABLE homeserver_devices ADD KEY idx_homeserver_license_status (license_id,status);
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = 'homeserver_devices'
          AND index_name = 'uq_homeserver_license'
    ) THEN
        ALTER TABLE homeserver_devices DROP INDEX uq_homeserver_license;
    END IF;
END$$
DELIMITER ;
CALL vp3_phase12_homeserver_index_upgrade();
DROP PROCEDURE IF EXISTS vp3_phase12_homeserver_index_upgrade;

CREATE TABLE IF NOT EXISTS homeserver_installer_grants (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    device_id BIGINT UNSIGNED NOT NULL,
    release_id BIGINT UNSIGNED NOT NULL,
    artifact_id BIGINT UNSIGNED NOT NULL,
    token_hash CHAR(64) NOT NULL,
    status ENUM('active','consumed','expired','revoked') NOT NULL DEFAULT 'active',
    max_uses TINYINT UNSIGNED NOT NULL DEFAULT 3,
    use_count TINYINT UNSIGNED NOT NULL DEFAULT 0,
    expires_at DATETIME NOT NULL,
    last_used_at DATETIME NULL,
    consumed_at DATETIME NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_homeserver_installer_grant_public (public_id),
    UNIQUE KEY uq_homeserver_installer_grant_hash (token_hash),
    KEY idx_homeserver_installer_device_status (device_id,status,expires_at),
    CONSTRAINT fk_homeserver_installer_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_homeserver_installer_device FOREIGN KEY (device_id) REFERENCES homeserver_devices(id) ON DELETE CASCADE,
    CONSTRAINT fk_homeserver_installer_release FOREIGN KEY (release_id) REFERENCES software_releases(id) ON DELETE CASCADE,
    CONSTRAINT fk_homeserver_installer_artifact FOREIGN KEY (artifact_id) REFERENCES release_artifacts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS homeserver_update_receipts_v1 (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    device_id BIGINT UNSIGNED NOT NULL,
    release_id BIGINT UNSIGNED NULL,
    request_id VARCHAR(64) NOT NULL,
    update_id VARCHAR(128) NOT NULL,
    disposition ENUM('downloaded','staged','installed','rolled_back','failed') NOT NULL,
    failure_code VARCHAR(100) NULL,
    receipt_hash CHAR(64) NULL,
    metadata_hash CHAR(64) NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_homeserver_update_receipt_public (public_id),
    UNIQUE KEY uq_homeserver_update_receipt_request (device_id,request_id),
    KEY idx_homeserver_update_receipt_device_time (device_id,created_at),
    CONSTRAINT fk_homeserver_update_receipt_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_homeserver_update_receipt_device FOREIGN KEY (device_id) REFERENCES homeserver_devices(id) ON DELETE CASCADE,
    CONSTRAINT fk_homeserver_update_receipt_release FOREIGN KEY (release_id) REFERENCES software_releases(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS homeserver_transfer_requests (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    device_id BIGINT UNSIGNED NOT NULL,
    source_account_id BIGINT UNSIGNED NOT NULL,
    target_account_id BIGINT UNSIGNED NOT NULL,
    transfer_code_hash CHAR(64) NOT NULL,
    status ENUM('pending','accepted','expired','canceled') NOT NULL DEFAULT 'pending',
    expires_at DATETIME NOT NULL,
    accepted_at DATETIME NULL,
    canceled_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_homeserver_transfer_public (public_id),
    UNIQUE KEY uq_homeserver_transfer_code (transfer_code_hash),
    KEY idx_homeserver_transfer_target_status (target_account_id,status,expires_at),
    CONSTRAINT fk_homeserver_transfer_device FOREIGN KEY (device_id) REFERENCES homeserver_devices(id) ON DELETE CASCADE,
    CONSTRAINT fk_homeserver_transfer_source FOREIGN KEY (source_account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_homeserver_transfer_target FOREIGN KEY (target_account_id) REFERENCES accounts(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS homeserver_control_plane_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,
    device_id BIGINT UNSIGNED NULL,
    request_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    result ENUM('success','failure','denied') NOT NULL,
    metadata_hash CHAR(64) NULL,
    created_at DATETIME NOT NULL,
    KEY idx_homeserver_control_account_time (account_id,created_at),
    KEY idx_homeserver_control_device_time (device_id,created_at),
    CONSTRAINT fk_homeserver_control_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_homeserver_control_device FOREIGN KEY (device_id) REFERENCES homeserver_devices(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
