SET NAMES utf8mb4;
SET time_zone = '+00:00';

ALTER TABLE subscriptions
    ADD COLUMN IF NOT EXISTS provider_status VARCHAR(40) NULL AFTER status;

CREATE TABLE IF NOT EXISTS stripe_customers (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,
    stripe_customer_id VARCHAR(190) NOT NULL,
    email VARCHAR(320) NULL,
    livemode TINYINT(1) NOT NULL DEFAULT 0,
    metadata_json JSON NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_stripe_customers_account (account_id),
    UNIQUE KEY uq_stripe_customers_external (stripe_customer_id),
    CONSTRAINT fk_stripe_customers_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS stripe_product_mappings (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    plan_id BIGINT UNSIGNED NOT NULL,
    stripe_product_id VARCHAR(190) NOT NULL,
    active TINYINT(1) NOT NULL DEFAULT 1,
    metadata_json JSON NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_stripe_product_plan (plan_id),
    UNIQUE KEY uq_stripe_product_external (stripe_product_id),
    CONSTRAINT fk_stripe_product_plan FOREIGN KEY (plan_id) REFERENCES plans(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS stripe_price_mappings (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    plan_id BIGINT UNSIGNED NOT NULL,
    stripe_product_mapping_id BIGINT UNSIGNED NOT NULL,
    stripe_price_id VARCHAR(190) NOT NULL,
    lookup_key VARCHAR(190) NULL,
    billing_interval ENUM('monthly','annual','custom') NOT NULL,
    currency CHAR(3) NOT NULL,
    unit_amount BIGINT UNSIGNED NOT NULL,
    active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_stripe_price_external (stripe_price_id),
    KEY idx_stripe_price_plan_active (plan_id, active),
    CONSTRAINT fk_stripe_price_plan FOREIGN KEY (plan_id) REFERENCES plans(id) ON DELETE RESTRICT,
    CONSTRAINT fk_stripe_price_product FOREIGN KEY (stripe_product_mapping_id) REFERENCES stripe_product_mappings(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS stripe_checkout_sessions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    plan_id BIGINT UNSIGNED NOT NULL,
    stripe_price_mapping_id BIGINT UNSIGNED NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    request_hash CHAR(64) NOT NULL,
    stripe_session_id VARCHAR(190) NOT NULL,
    stripe_customer_id VARCHAR(190) NULL,
    stripe_subscription_id VARCHAR(190) NULL,
    status ENUM('open','complete','expired') NOT NULL DEFAULT 'open',
    session_url VARCHAR(2048) NULL,
    success_url VARCHAR(2048) NOT NULL,
    cancel_url VARCHAR(2048) NOT NULL,
    expires_at DATETIME NULL,
    completed_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_stripe_checkout_public (public_id),
    UNIQUE KEY uq_stripe_checkout_external (stripe_session_id),
    UNIQUE KEY uq_stripe_checkout_idempotency (account_id, idempotency_key),
    CONSTRAINT fk_stripe_checkout_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_stripe_checkout_plan FOREIGN KEY (plan_id) REFERENCES plans(id) ON DELETE RESTRICT,
    CONSTRAINT fk_stripe_checkout_price FOREIGN KEY (stripe_price_mapping_id) REFERENCES stripe_price_mappings(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS stripe_portal_sessions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    request_hash CHAR(64) NOT NULL,
    stripe_session_id VARCHAR(190) NOT NULL,
    session_url VARCHAR(2048) NOT NULL,
    return_url VARCHAR(2048) NOT NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_stripe_portal_public (public_id),
    UNIQUE KEY uq_stripe_portal_external (stripe_session_id),
    UNIQUE KEY uq_stripe_portal_idempotency (account_id, idempotency_key),
    CONSTRAINT fk_stripe_portal_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS stripe_webhook_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    stripe_event_id VARCHAR(190) NOT NULL,
    event_type VARCHAR(190) NOT NULL,
    api_version VARCHAR(40) NULL,
    livemode TINYINT(1) NOT NULL DEFAULT 0,
    payload_hash CHAR(64) NOT NULL,
    payload_json LONGTEXT NOT NULL,
    status ENUM('processing','completed','ignored','failed') NOT NULL DEFAULT 'processing',
    attempts SMALLINT UNSIGNED NOT NULL DEFAULT 1,
    error_code VARCHAR(100) NULL,
    error_message VARCHAR(1000) NULL,
    received_at DATETIME NOT NULL,
    processed_at DATETIME NULL,
    UNIQUE KEY uq_stripe_webhook_event (stripe_event_id),
    KEY idx_stripe_webhook_status_time (status, received_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS billing_subscription_items (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    subscription_id BIGINT UNSIGNED NOT NULL,
    plan_id BIGINT UNSIGNED NOT NULL,
    stripe_subscription_item_id VARCHAR(190) NULL,
    stripe_price_id VARCHAR(190) NOT NULL,
    quantity INT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_billing_subscription_item_subscription (subscription_id),
    UNIQUE KEY uq_billing_subscription_item_external (stripe_subscription_item_id),
    CONSTRAINT fk_billing_item_subscription FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE,
    CONSTRAINT fk_billing_item_plan FOREIGN KEY (plan_id) REFERENCES plans(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS billing_invoices (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,
    subscription_id BIGINT UNSIGNED NULL,
    stripe_invoice_id VARCHAR(190) NOT NULL,
    stripe_subscription_id VARCHAR(190) NULL,
    stripe_customer_id VARCHAR(190) NOT NULL,
    status VARCHAR(40) NOT NULL,
    billing_reason VARCHAR(80) NULL,
    currency CHAR(3) NOT NULL,
    amount_due BIGINT UNSIGNED NOT NULL DEFAULT 0,
    amount_paid BIGINT UNSIGNED NOT NULL DEFAULT 0,
    amount_remaining BIGINT UNSIGNED NOT NULL DEFAULT 0,
    hosted_invoice_url VARCHAR(2048) NULL,
    invoice_pdf_url VARCHAR(2048) NULL,
    period_start DATETIME NULL,
    period_end DATETIME NULL,
    due_at DATETIME NULL,
    paid_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_billing_invoice_external (stripe_invoice_id),
    KEY idx_billing_invoice_account_status (account_id, status),
    CONSTRAINT fk_billing_invoice_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_billing_invoice_subscription FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS billing_payment_intents (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,
    subscription_id BIGINT UNSIGNED NULL,
    billing_invoice_id BIGINT UNSIGNED NULL,
    stripe_payment_intent_id VARCHAR(190) NOT NULL,
    status VARCHAR(40) NOT NULL,
    currency CHAR(3) NOT NULL,
    amount BIGINT UNSIGNED NOT NULL DEFAULT 0,
    amount_received BIGINT UNSIGNED NOT NULL DEFAULT 0,
    payment_method_type VARCHAR(80) NULL,
    failure_code VARCHAR(100) NULL,
    failure_message VARCHAR(1000) NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_billing_payment_intent_external (stripe_payment_intent_id),
    KEY idx_billing_payment_account_status (account_id, status),
    CONSTRAINT fk_billing_payment_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_billing_payment_subscription FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE SET NULL,
    CONSTRAINT fk_billing_payment_invoice FOREIGN KEY (billing_invoice_id) REFERENCES billing_invoices(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS billing_refunds (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,
    subscription_id BIGINT UNSIGNED NULL,
    billing_payment_intent_id BIGINT UNSIGNED NULL,
    stripe_refund_id VARCHAR(190) NOT NULL,
    stripe_payment_intent_id VARCHAR(190) NULL,
    status VARCHAR(40) NOT NULL,
    currency CHAR(3) NOT NULL,
    amount BIGINT UNSIGNED NOT NULL,
    reason VARCHAR(100) NULL,
    failure_reason VARCHAR(190) NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_billing_refund_external (stripe_refund_id),
    KEY idx_billing_refund_account_status (account_id, status),
    CONSTRAINT fk_billing_refund_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_billing_refund_subscription FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE SET NULL,
    CONSTRAINT fk_billing_refund_payment FOREIGN KEY (billing_payment_intent_id) REFERENCES billing_payment_intents(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS billing_outbox (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    job_type ENUM('provisioning','license_sync','billing_reconciliation') NOT NULL,
    dedupe_key VARCHAR(190) NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    subscription_id BIGINT UNSIGNED NULL,
    payload_json JSON NOT NULL,
    status ENUM('pending','processing','completed','failed','canceled') NOT NULL DEFAULT 'pending',
    attempts SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    available_at DATETIME NOT NULL,
    locked_at DATETIME NULL,
    completed_at DATETIME NULL,
    last_error VARCHAR(1000) NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_billing_outbox_dedupe (dedupe_key),
    KEY idx_billing_outbox_claim (status, available_at),
    CONSTRAINT fk_billing_outbox_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_billing_outbox_subscription FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS billing_receipts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    request_id VARCHAR(64) NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    subscription_id BIGINT UNSIGNED NULL,
    event_type VARCHAR(100) NOT NULL,
    external_request_id VARCHAR(190) NULL,
    result ENUM('success','failure','ignored') NOT NULL,
    metadata_json JSON NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_billing_receipt_public (public_id),
    KEY idx_billing_receipt_account_time (account_id, created_at),
    KEY idx_billing_receipt_external (external_request_id),
    CONSTRAINT fk_billing_receipt_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_billing_receipt_subscription FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
