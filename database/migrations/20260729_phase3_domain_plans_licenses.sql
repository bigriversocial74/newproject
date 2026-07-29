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
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_domain_public_id (public_id),
    UNIQUE KEY uq_domain_hostname (hostname),
    UNIQUE KEY uq_domain_label (label),
    KEY idx_domain_account_status (account_id, status),
    CONSTRAINT fk_domain_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_domain_subscription FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS licenses (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    subscription_id BIGINT UNSIGNED NOT NULL,
    domain_registration_id BIGINT UNSIGNED NOT NULL,
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
    CONSTRAINT fk_license_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_license_subscription FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE RESTRICT,
    CONSTRAINT fk_license_domain FOREIGN KEY (domain_registration_id) REFERENCES domain_registrations(id) ON DELETE RESTRICT
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

CREATE TABLE IF NOT EXISTS domain_license_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL,
    idempotency_key VARCHAR(128) NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    domain_registration_id BIGINT UNSIGNED NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    result ENUM('success','failure','denied') NOT NULL,
    metadata_json JSON NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_domain_license_event_idempotency (event_type, idempotency_key),
    KEY idx_domain_license_events_domain_time (domain_registration_id, created_at),
    CONSTRAINT fk_domain_license_events_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_domain_license_events_domain FOREIGN KEY (domain_registration_id) REFERENCES domain_registrations(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO plans (public_id, code, name, status, billing_interval, currency, price_minor, created_at, updated_at)
VALUES ('PLAN-VP3-STANDARD', 'standard', 'VP3 Standard', 'active', 'monthly', 'USD', 0, UTC_TIMESTAMP(), UTC_TIMESTAMP());

INSERT IGNORE INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
SELECT id, 'storage_bytes', 'integer', CAST(10737418240 AS JSON), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM plans WHERE code='standard';
INSERT IGNORE INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
SELECT id, 'pod_installation_limit', 'integer', CAST(1 AS JSON), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM plans WHERE code='standard';
INSERT IGNORE INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
SELECT id, 'homeserver_limit', 'integer', CAST(1 AS JSON), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM plans WHERE code='standard';
INSERT IGNORE INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
SELECT id, 'automatic_updates', 'boolean', CAST(TRUE AS JSON), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM plans WHERE code='standard';
INSERT IGNORE INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
SELECT id, 'managed_security', 'boolean', CAST(TRUE AS JSON), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM plans WHERE code='standard';
INSERT IGNORE INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
SELECT id, 'backup_retention_days', 'integer', CAST(30 AS JSON), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM plans WHERE code='standard';
INSERT IGNORE INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
SELECT id, 'update_channel', 'string', JSON_QUOTE('stable'), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM plans WHERE code='standard';
