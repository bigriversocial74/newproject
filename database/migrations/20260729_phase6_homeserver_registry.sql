SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE TABLE IF NOT EXISTS homeserver_devices (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    subscription_id BIGINT UNSIGNED NOT NULL,
    domain_registration_id BIGINT UNSIGNED NOT NULL,
    license_id BIGINT UNSIGNED NOT NULL,
    device_fingerprint CHAR(64) NOT NULL,
    credential_hash CHAR(64) NOT NULL,
    credential_version INT UNSIGNED NOT NULL DEFAULT 1,
    status ENUM('pending_pairing','paired','online','degraded','offline','suspended','revoked') NOT NULL DEFAULT 'pending_pairing',
    pairing_status ENUM('unpaired','code_issued','paired','revoked') NOT NULL DEFAULT 'unpaired',
    software_version VARCHAR(80) NULL,
    mcp_version VARCHAR(80) NULL,
    update_channel VARCHAR(32) NOT NULL DEFAULT 'stable',
    frontend_limit INT UNSIGNED NOT NULL DEFAULT 1,
    paired_frontend_count INT UNSIGNED NOT NULL DEFAULT 0,
    last_heartbeat_at DATETIME NULL,
    paired_at DATETIME NULL,
    suspended_at DATETIME NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_homeserver_public (public_id),
    UNIQUE KEY uq_homeserver_license (license_id),
    UNIQUE KEY uq_homeserver_fingerprint (device_fingerprint),
    KEY idx_homeserver_account_status (account_id, status),
    KEY idx_homeserver_heartbeat (status, last_heartbeat_at),
    CONSTRAINT fk_homeserver_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_homeserver_subscription FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE RESTRICT,
    CONSTRAINT fk_homeserver_domain FOREIGN KEY (domain_registration_id) REFERENCES domain_registrations(id) ON DELETE RESTRICT,
    CONSTRAINT fk_homeserver_license FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS homeserver_pairing_codes (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    device_id BIGINT UNSIGNED NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    code_hash CHAR(64) NOT NULL,
    purpose ENUM('device_enrollment','frontend_pairing') NOT NULL,
    status ENUM('active','consumed','expired','revoked') NOT NULL DEFAULT 'active',
    expires_at DATETIME NOT NULL,
    consumed_at DATETIME NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_homeserver_pairing_public (public_id),
    UNIQUE KEY uq_homeserver_pairing_hash (code_hash),
    KEY idx_homeserver_pairing_device_status (device_id, status, expires_at),
    CONSTRAINT fk_homeserver_pairing_device FOREIGN KEY (device_id) REFERENCES homeserver_devices(id) ON DELETE CASCADE,
    CONSTRAINT fk_homeserver_pairing_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS homeserver_frontend_pairs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    device_id BIGINT UNSIGNED NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    deployment_id BIGINT UNSIGNED NOT NULL,
    wrapper_type VARCHAR(64) NOT NULL DEFAULT 'pod',
    status ENUM('active','revoked') NOT NULL DEFAULT 'active',
    permission_scope_hash CHAR(64) NOT NULL,
    paired_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_homeserver_frontend_public (public_id),
    UNIQUE KEY uq_homeserver_frontend_pair (device_id, deployment_id),
    KEY idx_homeserver_frontend_account_status (account_id, status),
    CONSTRAINT fk_homeserver_frontend_device FOREIGN KEY (device_id) REFERENCES homeserver_devices(id) ON DELETE CASCADE,
    CONSTRAINT fk_homeserver_frontend_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_homeserver_frontend_deployment FOREIGN KEY (deployment_id) REFERENCES pod_deployments(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS homeserver_credential_rotations (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    device_id BIGINT UNSIGNED NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    request_id VARCHAR(64) NOT NULL,
    previous_version INT UNSIGNED NOT NULL,
    new_version INT UNSIGNED NOT NULL,
    previous_hash CHAR(64) NOT NULL,
    new_hash CHAR(64) NOT NULL,
    reason VARCHAR(190) NOT NULL,
    rotated_at DATETIME NOT NULL,
    UNIQUE KEY uq_homeserver_rotation_version (device_id, new_version),
    KEY idx_homeserver_rotation_account_time (account_id, rotated_at),
    CONSTRAINT fk_homeserver_rotation_device FOREIGN KEY (device_id) REFERENCES homeserver_devices(id) ON DELETE CASCADE,
    CONSTRAINT fk_homeserver_rotation_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS homeserver_entitlement_leases (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    device_id BIGINT UNSIGNED NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    license_id BIGINT UNSIGNED NOT NULL,
    entitlement_snapshot_hash CHAR(64) NOT NULL,
    document_hash CHAR(64) NOT NULL,
    signature_hash CHAR(64) NOT NULL,
    signing_key_id VARCHAR(80) NOT NULL,
    status ENUM('active','superseded','expired','revoked') NOT NULL DEFAULT 'active',
    issued_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    superseded_at DATETIME NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_homeserver_lease_public (public_id),
    KEY idx_homeserver_lease_device_status (device_id, status, expires_at),
    CONSTRAINT fk_homeserver_lease_device FOREIGN KEY (device_id) REFERENCES homeserver_devices(id) ON DELETE CASCADE,
    CONSTRAINT fk_homeserver_lease_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_homeserver_lease_license FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS homeserver_request_receipts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,
    device_id BIGINT UNSIGNED NULL,
    operation VARCHAR(100) NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    request_id VARCHAR(64) NOT NULL,
    request_hash CHAR(64) NOT NULL,
    status ENUM('processing','completed') NOT NULL DEFAULT 'processing',
    response_json LONGTEXT NULL,
    created_at DATETIME NOT NULL,
    completed_at DATETIME NULL,
    UNIQUE KEY uq_homeserver_request (account_id, operation, idempotency_key),
    KEY idx_homeserver_request_request (request_id),
    CONSTRAINT fk_homeserver_request_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_homeserver_request_device FOREIGN KEY (device_id) REFERENCES homeserver_devices(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS homeserver_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    device_id BIGINT UNSIGNED NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    request_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    result ENUM('success','failure','denied') NOT NULL,
    metadata_json JSON NULL,
    created_at DATETIME NOT NULL,
    KEY idx_homeserver_event_device_time (device_id, created_at),
    KEY idx_homeserver_event_account_time (account_id, created_at),
    CONSTRAINT fk_homeserver_event_device FOREIGN KEY (device_id) REFERENCES homeserver_devices(id) ON DELETE CASCADE,
    CONSTRAINT fk_homeserver_event_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
