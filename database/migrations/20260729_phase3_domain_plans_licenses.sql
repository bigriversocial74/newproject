SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE TABLE IF NOT EXISTS plans (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(40) NOT NULL,
    code VARCHAR(64) NOT NULL,
    name VARCHAR(190) NOT NULL,
    status ENUM('draft','active','retired') NOT NULL DEFAULT 'draft',
    billing_interval ENUM('monthly','annual','custom') NOT NULL DEFAULT 'monthly',
    currency CHAR(3) NOT NULL DEFAULT 'USD',
    price_minor BIGINT UNSIGNED NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_plans_public_id (public_id),
    UNIQUE KEY uq_plans_code (code),
    KEY idx_plans_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS plan_entitlements (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    plan_id BIGINT UNSIGNED NOT NULL,
    entitlement_key VARCHAR(100) NOT NULL,
    value_type ENUM('boolean','integer','string','json') NOT NULL,
    value_json JSON NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_plan_entitlement (plan_id, entitlement_key),
    CONSTRAINT fk_plan_entitlements_plan FOREIGN KEY (plan_id) REFERENCES plans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS subscriptions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(40) NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    plan_id BIGINT UNSIGNED NOT NULL,
    status ENUM('trialing','active','past_due','grace','canceled','expired') NOT NULL,
    provider VARCHAR(40) NULL,
    provider_customer_id VARCHAR(190) NULL,
    provider_subscription_id VARCHAR(190) NULL,
    starts_at DATETIME NOT NULL,
    current_period_starts_at DATETIME NULL,
    current_period_ends_at DATETIME NULL,
    grace_ends_at DATETIME NULL,
    canceled_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_subscriptions_public_id (public_id),
    UNIQUE KEY uq_subscriptions_provider_subscription (provider, provider_subscription_id),
    KEY idx_subscriptions_account_status (account_id, status),
    CONSTRAINT fk_subscriptions_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_subscriptions_plan FOREIGN KEY (plan_id) REFERENCES plans(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS subscription_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    subscription_id BIGINT UNSIGNED NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    request_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    from_status VARCHAR(32) NULL,
    to_status VARCHAR(32) NULL,
    metadata_json JSON NULL,
    created_at DATETIME NOT NULL,
    KEY idx_subscription_events_subscription_time (subscription_id, created_at),
    CONSTRAINT fk_subscription_events_subscription FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE,
    CONSTRAINT fk_subscription_events_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS domain_registrations (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(40) NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    subscription_id BIGINT UNSIGNED NOT NULL,
    label VARCHAR(63) NOT NULL,
    hostname VARCHAR(253) NOT NULL,
    status ENUM('reserved','pending','active','grace','suspended','expired','transferred','released') NOT NULL,
    routing_status ENUM('pending','active','degraded','disabled') NOT NULL DEFAULT 'pending',
    ssl_status ENUM('pending','active','renewing','failed','disabled') NOT NULL DEFAULT 'pending',
    reserved_until DATETIME NULL,
    registered_at DATETIME NULL,
    renews_at DATETIME NULL,
    expires_at DATETIME NULL,
    suspended_at DATETIME NULL,
    released_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_domain_public_id (public_id),
    UNIQUE KEY uq_domain_hostname (hostname),
    UNIQUE KEY uq_domain_label (label),
    KEY idx_domain_account_status (account_id, status),
    KEY idx_domain_subscription_status (subscription_id, status),
    CONSTRAINT fk_domain_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_domain_subscription FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS entitlement_bundles (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    subscription_id BIGINT UNSIGNED NOT NULL,
    domain_registration_id BIGINT UNSIGNED NOT NULL,
    plan_id BIGINT UNSIGNED NOT NULL,
    snapshot_hash CHAR(64) NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_entitlement_bundle_public_id (public_id),
    UNIQUE KEY uq_entitlement_bundle_domain (domain_registration_id),
    KEY idx_entitlement_bundle_subscription (subscription_id),
    CONSTRAINT fk_entitlement_bundle_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_entitlement_bundle_subscription FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE RESTRICT,
    CONSTRAINT fk_entitlement_bundle_domain FOREIGN KEY (domain_registration_id) REFERENCES domain_registrations(id) ON DELETE RESTRICT,
    CONSTRAINT fk_entitlement_bundle_plan FOREIGN KEY (plan_id) REFERENCES plans(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS licenses (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    subscription_id BIGINT UNSIGNED NOT NULL,
    domain_registration_id BIGINT UNSIGNED NOT NULL,
    entitlement_bundle_id BIGINT UNSIGNED NOT NULL,
    product_type ENUM('pod','homeserver') NOT NULL,
    status ENUM('active','grace','suspended','expired','terminated') NOT NULL,
    starts_at DATETIME NOT NULL,
    renews_at DATETIME NULL,
    expires_at DATETIME NULL,
    grace_ends_at DATETIME NULL,
    suspended_at DATETIME NULL,
    terminated_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_license_public_id (public_id),
    UNIQUE KEY uq_domain_product_license (domain_registration_id, product_type),
    KEY idx_license_account_status (account_id, status),
    KEY idx_license_bundle (entitlement_bundle_id),
    CONSTRAINT fk_license_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_license_subscription FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE RESTRICT,
    CONSTRAINT fk_license_domain FOREIGN KEY (domain_registration_id) REFERENCES domain_registrations(id) ON DELETE RESTRICT,
    CONSTRAINT fk_license_bundle FOREIGN KEY (entitlement_bundle_id) REFERENCES entitlement_bundles(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS license_entitlements (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    license_id BIGINT UNSIGNED NOT NULL,
    entitlement_key VARCHAR(100) NOT NULL,
    value_type ENUM('boolean','integer','string','json') NOT NULL,
    value_json JSON NOT NULL,
    source_plan_id BIGINT UNSIGNED NOT NULL,
    effective_at DATETIME NOT NULL,
    expires_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_license_entitlement (license_id, entitlement_key),
    CONSTRAINT fk_license_entitlements_license FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE,
    CONSTRAINT fk_license_entitlements_plan FOREIGN KEY (source_plan_id) REFERENCES plans(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS domain_admin_holds (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    domain_registration_id BIGINT UNSIGNED NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    status ENUM('active','released') NOT NULL DEFAULT 'active',
    reason VARCHAR(500) NOT NULL,
    placed_by_actor_id BIGINT UNSIGNED NULL,
    released_by_actor_id BIGINT UNSIGNED NULL,
    placed_at DATETIME NOT NULL,
    released_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_domain_hold_public_id (public_id),
    KEY idx_domain_holds_domain_status (domain_registration_id, status),
    CONSTRAINT fk_domain_holds_domain FOREIGN KEY (domain_registration_id) REFERENCES domain_registrations(id) ON DELETE CASCADE,
    CONSTRAINT fk_domain_holds_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS domain_aliases (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    domain_registration_id BIGINT UNSIGNED NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    alias_hostname VARCHAR(253) NOT NULL,
    status ENUM('pending','active','suspended','removed') NOT NULL DEFAULT 'pending',
    routing_status ENUM('pending','active','degraded','disabled') NOT NULL DEFAULT 'pending',
    ssl_status ENUM('pending','active','renewing','failed','disabled') NOT NULL DEFAULT 'pending',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_domain_alias_public_id (public_id),
    UNIQUE KEY uq_domain_alias_hostname (alias_hostname),
    KEY idx_domain_alias_domain_status (domain_registration_id, status),
    CONSTRAINT fk_domain_alias_domain FOREIGN KEY (domain_registration_id) REFERENCES domain_registrations(id) ON DELETE CASCADE,
    CONSTRAINT fk_domain_alias_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS domain_redirects (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    domain_registration_id BIGINT UNSIGNED NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    source_path VARCHAR(1024) NOT NULL,
    source_path_hash CHAR(64) NOT NULL,
    target_url VARCHAR(2048) NOT NULL,
    http_status SMALLINT UNSIGNED NOT NULL DEFAULT 302,
    status ENUM('active','disabled','removed') NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_domain_redirect_public_id (public_id),
    UNIQUE KEY uq_domain_redirect_path_hash (domain_registration_id, source_path_hash),
    KEY idx_domain_redirect_domain_status (domain_registration_id, status),
    CONSTRAINT fk_domain_redirect_domain FOREIGN KEY (domain_registration_id) REFERENCES domain_registrations(id) ON DELETE CASCADE,
    CONSTRAINT fk_domain_redirect_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS domain_transfer_requests (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    domain_registration_id BIGINT UNSIGNED NOT NULL,
    source_account_id BIGINT UNSIGNED NOT NULL,
    target_account_id BIGINT UNSIGNED NULL,
    token_hash CHAR(64) NOT NULL,
    status ENUM('pending','accepted','canceled','expired') NOT NULL DEFAULT 'pending',
    expires_at DATETIME NOT NULL,
    accepted_at DATETIME NULL,
    canceled_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_domain_transfer_public_id (public_id),
    UNIQUE KEY uq_domain_transfer_token_hash (token_hash),
    KEY idx_domain_transfer_domain_status (domain_registration_id, status),
    CONSTRAINT fk_domain_transfer_domain FOREIGN KEY (domain_registration_id) REFERENCES domain_registrations(id) ON DELETE CASCADE,
    CONSTRAINT fk_domain_transfer_source_account FOREIGN KEY (source_account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_domain_transfer_target_account FOREIGN KEY (target_account_id) REFERENCES accounts(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS domain_transfer_active (
    domain_registration_id BIGINT UNSIGNED PRIMARY KEY,
    transfer_request_id BIGINT UNSIGNED NOT NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_domain_transfer_active_request (transfer_request_id),
    CONSTRAINT fk_domain_transfer_active_domain FOREIGN KEY (domain_registration_id) REFERENCES domain_registrations(id) ON DELETE CASCADE,
    CONSTRAINT fk_domain_transfer_active_request FOREIGN KEY (transfer_request_id) REFERENCES domain_transfer_requests(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS domain_request_receipts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,
    domain_registration_id BIGINT UNSIGNED NULL,
    operation VARCHAR(100) NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    request_id VARCHAR(64) NOT NULL,
    request_hash CHAR(64) NOT NULL,
    status ENUM('processing','completed') NOT NULL DEFAULT 'processing',
    response_json LONGTEXT NULL,
    created_at DATETIME NOT NULL,
    completed_at DATETIME NULL,
    UNIQUE KEY uq_domain_request_receipt (account_id, operation, idempotency_key),
    KEY idx_domain_request_receipt_request (request_id),
    CONSTRAINT fk_domain_request_receipt_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_domain_request_receipt_domain FOREIGN KEY (domain_registration_id) REFERENCES domain_registrations(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS domain_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    domain_registration_id BIGINT UNSIGNED NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    result ENUM('success','failure','denied') NOT NULL,
    metadata_json JSON NULL,
    created_at DATETIME NOT NULL,
    KEY idx_domain_events_domain_time (domain_registration_id, created_at),
    KEY idx_domain_events_account_time (account_id, created_at),
    CONSTRAINT fk_domain_events_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_domain_events_domain FOREIGN KEY (domain_registration_id) REFERENCES domain_registrations(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO plans (public_id, code, name, status, billing_interval, currency, price_minor, created_at, updated_at)
VALUES ('PLAN-VP3-STANDARD', 'standard', 'VP3 Standard', 'active', 'monthly', 'USD', 0, UTC_TIMESTAMP(), UTC_TIMESTAMP());

INSERT IGNORE INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
SELECT id, 'storage_bytes', 'integer', JSON_EXTRACT('10737418240', '$'), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM plans WHERE code='standard';
INSERT IGNORE INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
SELECT id, 'pod_installation_limit', 'integer', JSON_EXTRACT('1', '$'), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM plans WHERE code='standard';
INSERT IGNORE INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
SELECT id, 'homeserver_limit', 'integer', JSON_EXTRACT('1', '$'), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM plans WHERE code='standard';
INSERT IGNORE INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
SELECT id, 'mcp_client_limit', 'integer', JSON_EXTRACT('8', '$'), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM plans WHERE code='standard';
INSERT IGNORE INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
SELECT id, 'update_channel', 'string', JSON_QUOTE('stable'), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM plans WHERE code='standard';
INSERT IGNORE INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
SELECT id, 'automatic_updates', 'boolean', JSON_EXTRACT('true', '$'), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM plans WHERE code='standard';
INSERT IGNORE INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
SELECT id, 'managed_security', 'boolean', JSON_EXTRACT('true', '$'), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM plans WHERE code='standard';
INSERT IGNORE INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
SELECT id, 'backup_retention_days', 'integer', JSON_EXTRACT('30', '$'), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM plans WHERE code='standard';
INSERT IGNORE INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
SELECT id, 'support_tier', 'string', JSON_QUOTE('standard'), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM plans WHERE code='standard';
INSERT IGNORE INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
SELECT id, 'custom_domain_alias_limit', 'integer', JSON_EXTRACT('3', '$'), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM plans WHERE code='standard';
INSERT IGNORE INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
SELECT id, 'pod_user_limit', 'integer', JSON_EXTRACT('25', '$'), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM plans WHERE code='standard';
INSERT IGNORE INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
SELECT id, 'api_access', 'boolean', JSON_EXTRACT('true', '$'), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM plans WHERE code='standard';
INSERT IGNORE INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
SELECT id, 'security_update_access', 'boolean', JSON_EXTRACT('true', '$'), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM plans WHERE code='standard';
