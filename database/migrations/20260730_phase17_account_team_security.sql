SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE TABLE IF NOT EXISTS account_invitations (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(40) NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    invited_email VARCHAR(254) NOT NULL,
    invited_email_normalized VARCHAR(254) NOT NULL,
    role ENUM('customer_owner','customer_admin','billing_manager','support_member') NOT NULL,
    token_hash CHAR(64) NOT NULL,
    status ENUM('pending','accepted','revoked','expired') NOT NULL DEFAULT 'pending',
    invited_by_user_id BIGINT UNSIGNED NOT NULL,
    accepted_by_user_id BIGINT UNSIGNED NULL,
    request_id VARCHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    accepted_at DATETIME NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_account_invitations_public (public_id),
    UNIQUE KEY uq_account_invitations_token (token_hash),
    UNIQUE KEY uq_account_invitations_request (account_id, invited_by_user_id, request_id),
    KEY idx_account_invitations_account_status (account_id, status, expires_at),
    KEY idx_account_invitations_email_status (invited_email_normalized, status, expires_at),
    CONSTRAINT fk_account_invitations_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    CONSTRAINT fk_account_invitations_inviter FOREIGN KEY (invited_by_user_id) REFERENCES users(id) ON DELETE RESTRICT,
    CONSTRAINT fk_account_invitations_acceptor FOREIGN KEY (accepted_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS auth_mfa_methods (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    method_type ENUM('totp') NOT NULL DEFAULT 'totp',
    status ENUM('pending','active','disabled') NOT NULL DEFAULT 'pending',
    secret_ciphertext TEXT NOT NULL,
    secret_nonce VARCHAR(64) NOT NULL,
    secret_tag VARCHAR(64) NOT NULL,
    secret_key_id VARCHAR(64) NOT NULL,
    label VARCHAR(190) NULL,
    last_used_counter BIGINT UNSIGNED NULL,
    activated_at DATETIME NULL,
    disabled_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_auth_mfa_user_type (user_id, method_type),
    KEY idx_auth_mfa_status (status),
    CONSTRAINT fk_auth_mfa_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS auth_mfa_recovery_codes (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    code_hash CHAR(64) NOT NULL,
    used_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_auth_mfa_recovery_hash (code_hash),
    KEY idx_auth_mfa_recovery_user (user_id, used_at),
    CONSTRAINT fk_auth_mfa_recovery_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS auth_mfa_challenges (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    token_hash CHAR(64) NOT NULL,
    ip_hash CHAR(64) NOT NULL,
    user_agent_hash CHAR(64) NOT NULL,
    attempt_count SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    max_attempts SMALLINT UNSIGNED NOT NULL DEFAULT 6,
    expires_at DATETIME NOT NULL,
    consumed_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_auth_mfa_challenge_public (public_id),
    UNIQUE KEY uq_auth_mfa_challenge_token (token_hash),
    KEY idx_auth_mfa_challenge_user (user_id, consumed_at, expires_at),
    CONSTRAINT fk_auth_mfa_challenge_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS account_security_receipts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    account_id BIGINT UNSIGNED NULL,
    actor_user_id BIGINT UNSIGNED NULL,
    target_user_id BIGINT UNSIGNED NULL,
    action VARCHAR(100) NOT NULL,
    result ENUM('success','failure','denied') NOT NULL,
    request_id VARCHAR(64) NOT NULL,
    evidence_hash CHAR(64) NOT NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_account_security_receipt_public (public_id),
    UNIQUE KEY uq_account_security_receipt_request (account_id, action, request_id),
    KEY idx_account_security_receipt_account_time (account_id, created_at),
    KEY idx_account_security_receipt_actor_time (actor_user_id, created_at),
    CONSTRAINT fk_account_security_receipt_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE SET NULL,
    CONSTRAINT fk_account_security_receipt_actor FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_account_security_receipt_target FOREIGN KEY (target_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
