SET NAMES utf8mb4;
SET time_zone = '+00:00';

ALTER TABLE account_users
    MODIFY role ENUM(
        'customer_owner',
        'customer_admin',
        'billing_manager',
        'support_member',
        'vp3_support',
        'vp3_operations',
        'vp3_admin',
        'vp3_super_admin'
    ) NOT NULL DEFAULT 'customer_owner';

CREATE TABLE IF NOT EXISTS auth_role_permissions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    role VARCHAR(64) NOT NULL,
    permission VARCHAR(100) NOT NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_auth_role_permission (role, permission)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS auth_session_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    session_public_id VARCHAR(64) NULL,
    user_id BIGINT UNSIGNED NULL,
    request_id VARCHAR(64) NOT NULL,
    event_type ENUM('created','rotated','revoked','expired','rejected') NOT NULL,
    ip_hash CHAR(64) NULL,
    user_agent_hash CHAR(64) NULL,
    created_at DATETIME NOT NULL,
    KEY idx_auth_session_events_user_time (user_id, created_at),
    KEY idx_auth_session_events_session_time (session_public_id, created_at),
    CONSTRAINT fk_auth_session_events_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO auth_role_permissions (role, permission, created_at) VALUES
('customer_owner', 'account.manage', UTC_TIMESTAMP()),
('customer_owner', 'billing.manage', UTC_TIMESTAMP()),
('customer_owner', 'members.manage', UTC_TIMESTAMP()),
('customer_admin', 'account.manage', UTC_TIMESTAMP()),
('customer_admin', 'members.manage', UTC_TIMESTAMP()),
('billing_manager', 'billing.manage', UTC_TIMESTAMP()),
('support_member', 'support.manage', UTC_TIMESTAMP()),
('vp3_support', 'platform.support', UTC_TIMESTAMP()),
('vp3_operations', 'platform.operations', UTC_TIMESTAMP()),
('vp3_admin', 'platform.admin', UTC_TIMESTAMP()),
('vp3_super_admin', 'platform.super_admin', UTC_TIMESTAMP());
