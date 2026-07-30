SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE TABLE IF NOT EXISTS federated_setting_catalog (
    setting_key VARCHAR(120) NOT NULL PRIMARY KEY,
    label VARCHAR(160) NOT NULL,
    description VARCHAR(500) NOT NULL,
    category VARCHAR(60) NOT NULL,
    authority ENUM('vp3','homeserver','shared') NOT NULL,
    value_type ENUM('boolean','integer','string','enum') NOT NULL,
    default_value_json JSON NOT NULL,
    allowed_values_json JSON NULL,
    visible_in_vp3 TINYINT(1) NOT NULL DEFAULT 1,
    visible_in_homeserver TINYINT(1) NOT NULL DEFAULT 1,
    sensitivity ENUM('non_secret') NOT NULL DEFAULT 'non_secret',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    KEY idx_federated_catalog_category (category,setting_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS federated_settings (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,
    device_id BIGINT UNSIGNED NULL,
    scope_type ENUM('account','device') NOT NULL,
    scope_key VARCHAR(64) NOT NULL,
    setting_key VARCHAR(120) NOT NULL,
    value_json JSON NOT NULL,
    value_hash CHAR(64) NOT NULL,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    source_authority ENUM('vp3','homeserver') NOT NULL,
    updated_by_user_id BIGINT UNSIGNED NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uq_federated_setting_scope (account_id,scope_type,scope_key,setting_key),
    KEY idx_federated_setting_account_revision (account_id,revision),
    KEY idx_federated_setting_device_revision (device_id,revision),
    CONSTRAINT fk_federated_setting_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    CONSTRAINT fk_federated_setting_device FOREIGN KEY (device_id) REFERENCES homeserver_devices(id) ON DELETE CASCADE,
    CONSTRAINT fk_federated_setting_user FOREIGN KEY (updated_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_federated_setting_catalog FOREIGN KEY (setting_key) REFERENCES federated_setting_catalog(setting_key) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS federated_settings_sync_receipts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_id VARCHAR(48) NOT NULL,
    account_id BIGINT UNSIGNED NOT NULL,
    device_id BIGINT UNSIGNED NULL,
    request_id VARCHAR(64) NOT NULL,
    direction ENUM('vp3_update','device_push','device_pull') NOT NULL,
    base_revision BIGINT UNSIGNED NOT NULL DEFAULT 0,
    applied_revision BIGINT UNSIGNED NOT NULL DEFAULT 0,
    snapshot_hash CHAR(64) NOT NULL,
    result ENUM('applied','partial','conflict','replayed') NOT NULL,
    conflict_count INT UNSIGNED NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_federated_sync_public (public_id),
    UNIQUE KEY uq_federated_sync_device_request (device_id,request_id),
    KEY idx_federated_sync_account_time (account_id,created_at),
    CONSTRAINT fk_federated_sync_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    CONSTRAINT fk_federated_sync_device FOREIGN KEY (device_id) REFERENCES homeserver_devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO federated_setting_catalog
(setting_key,label,description,category,authority,value_type,default_value_json,allowed_values_json,visible_in_vp3,visible_in_homeserver,sensitivity,created_at,updated_at)
VALUES
('appearance.theme','Appearance','Use the same light, dark, or system appearance across VP3 and HomeServer.','appearance','shared','enum','"system"','["system","light","dark"]',1,1,'non_secret',UTC_TIMESTAMP(),UTC_TIMESTAMP()),
('regional.locale','Language and locale','Preferred interface locale for supported VP3 and HomeServer surfaces.','regional','shared','string','"en-US"',NULL,1,1,'non_secret',UTC_TIMESTAMP(),UTC_TIMESTAMP()),
('regional.timezone','Time zone','IANA time zone used for schedules, receipts, and operational timestamps.','regional','shared','string','"UTC"',NULL,1,1,'non_secret',UTC_TIMESTAMP(),UTC_TIMESTAMP()),
('updates.channel','Update channel','Permitted HomeServer software update channel.','updates','vp3','enum','"stable"','["stable","beta","security"]',1,1,'non_secret',UTC_TIMESTAMP(),UTC_TIMESTAMP()),
('updates.auto_download','Automatic downloads','Download verified HomeServer updates automatically when permitted.','updates','shared','boolean','false',NULL,1,1,'non_secret',UTC_TIMESTAMP(),UTC_TIMESTAMP()),
('updates.install_window','Local install window','Local hour range when an already verified update may be installed.','updates','homeserver','string','"02:00-05:00"',NULL,0,1,'non_secret',UTC_TIMESTAMP(),UTC_TIMESTAMP()),
('notifications.email_enabled','Email notifications','Allow VP3 operational and billing notifications by email.','notifications','vp3','boolean','true',NULL,1,1,'non_secret',UTC_TIMESTAMP(),UTC_TIMESTAMP()),
('notifications.desktop_enabled','Desktop notifications','Allow local HomeServer desktop notifications.','notifications','homeserver','boolean','true',NULL,0,1,'non_secret',UTC_TIMESTAMP(),UTC_TIMESTAMP()),
('privacy.telemetry_level','Operational telemetry','Choose the non-content operational telemetry level shared with VP3.','privacy','shared','enum','"essential"','["off","essential","diagnostic"]',1,1,'non_secret',UTC_TIMESTAMP(),UTC_TIMESTAMP()),
('commerce.default_currency','Default commerce currency','Default ISO currency for new HomeServer-created commerce applications.','commerce','shared','enum','"usd"','["usd","cad","eur","gbp","aud"]',1,1,'non_secret',UTC_TIMESTAMP(),UTC_TIMESTAMP()),
('commerce.receipt_email_enabled','Commerce receipt email','Enable receipt email by default for newly authorized commerce applications.','commerce','shared','boolean','true',NULL,1,1,'non_secret',UTC_TIMESTAMP(),UTC_TIMESTAMP())
ON DUPLICATE KEY UPDATE
label=VALUES(label),description=VALUES(description),category=VALUES(category),authority=VALUES(authority),value_type=VALUES(value_type),default_value_json=VALUES(default_value_json),allowed_values_json=VALUES(allowed_values_json),visible_in_vp3=VALUES(visible_in_vp3),visible_in_homeserver=VALUES(visible_in_homeserver),sensitivity='non_secret',updated_at=UTC_TIMESTAMP();
