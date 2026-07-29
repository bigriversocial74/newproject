SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE TABLE IF NOT EXISTS account_contacts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,
    contact_type ENUM('billing','support','technical','legal') NOT NULL,
    name VARCHAR(190) NOT NULL,
    email VARCHAR(254) NOT NULL,
    phone VARCHAR(50) NULL,
    is_primary TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_account_contact_type_email (account_id, contact_type, email),
    KEY idx_account_contacts_account_type (account_id, contact_type),
    CONSTRAINT fk_account_contacts_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS security_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(40) NOT NULL,
    request_id VARCHAR(64) NOT NULL,
    actor_type ENUM('system','user','administrator') NOT NULL,
    actor_id BIGINT UNSIGNED NULL,
    account_id BIGINT UNSIGNED NULL,
    event_type VARCHAR(100) NOT NULL,
    risk_level ENUM('info','low','medium','high','critical') NOT NULL DEFAULT 'info',
    result ENUM('success','failure','denied') NOT NULL,
    ip_hash CHAR(64) NULL,
    user_agent_hash CHAR(64) NULL,
    metadata_json JSON NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_security_events_public_id (public_id),
    KEY idx_security_events_account_time (account_id, created_at),
    KEY idx_security_events_type_time (event_type, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS idempotency_keys (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NULL,
    operation VARCHAR(100) NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    request_hash CHAR(64) NOT NULL,
    response_code SMALLINT UNSIGNED NULL,
    response_body_json JSON NULL,
    locked_until DATETIME NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_idempotency_operation_key (operation, idempotency_key),
    KEY idx_idempotency_expiry (expires_at),
    CONSTRAINT fk_idempotency_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
