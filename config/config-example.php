<?php

declare(strict_types=1);

return [
    'app' => [
        'name' => 'VP3.me',
        'env' => getenv('APP_ENV') ?: 'production',
        'base_url' => rtrim((string) (getenv('APP_BASE_URL') ?: 'https://vp3.me'), '/'),
        'session_name' => getenv('APP_SESSION_NAME') ?: 'vp3_session',
        'session_secure' => filter_var(getenv('APP_SESSION_SECURE') ?: '1', FILTER_VALIDATE_BOOL),
    ],
    'database' => [
        'dsn' => getenv('DB_DSN') ?: 'mysql:host=127.0.0.1;dbname=vp3;charset=utf8mb4',
        'username' => getenv('DB_USERNAME') ?: 'vp3',
        'password' => getenv('DB_PASSWORD') ?: '',
        'options' => [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ],
    ],
    'auth' => [
        'password_min_length' => 12,
        'verification_ttl_seconds' => 86400,
        'password_reset_ttl_seconds' => 3600,
        'login_attempt_limit' => 8,
        'login_attempt_window_seconds' => 900,
    ],
    'stripe' => [
        'secret_key' => getenv('STRIPE_SECRET_KEY') ?: '',
        'webhook_secret' => getenv('STRIPE_WEBHOOK_SECRET') ?: '',
        'api_base' => rtrim((string) (getenv('STRIPE_API_BASE') ?: 'https://api.stripe.com/v1'), '/'),
        'signature_tolerance_seconds' => max(60, (int) (getenv('STRIPE_SIGNATURE_TOLERANCE_SECONDS') ?: 300)),
        'grace_days' => max(1, (int) (getenv('STRIPE_GRACE_DAYS') ?: 7)),
    ],
    'provisioning' => [
        'provider_driver' => getenv('VP3_PROVISIONING_DRIVER') ?: 'null',
        'protected_configuration_paths' => array_values(array_filter(array_map(
            'trim',
            explode(',', getenv('VP3_PROTECTED_CONFIGURATION_PATHS') ?: 'database.password,app.key,customer')
        ))),
    ],
    'homeserver' => [
        'lease_signing_key' => getenv('HOMESERVER_LEASE_SIGNING_KEY') ?: '',
        'lease_signing_key_id' => getenv('HOMESERVER_LEASE_SIGNING_KEY_ID') ?: 'homeserver-hs256-v1',
        'pairing_ttl_seconds' => max(60, (int) (getenv('HOMESERVER_PAIRING_TTL_SECONDS') ?: 900)),
        'lease_ttl_seconds' => max(300, (int) (getenv('HOMESERVER_LEASE_TTL_SECONDS') ?: 3600)),
        'offline_after_minutes' => max(1, (int) (getenv('HOMESERVER_OFFLINE_AFTER_MINUTES') ?: 10)),
    ],
    'releases' => [
        'signing_private_key_base64' => getenv('RELEASE_SIGNING_PRIVATE_KEY_B64') ?: '',
        'signing_public_key_base64' => getenv('RELEASE_SIGNING_PUBLIC_KEY_B64') ?: '',
        'signing_key_id' => getenv('RELEASE_SIGNING_KEY_ID') ?: 'release-ed25519-v1',
        'update_provider_driver' => getenv('VP3_UPDATE_PROVIDER_DRIVER') ?: 'null',
    ],
    'backups' => [
        'metadata_encryption_key_base64' => getenv('BACKUP_METADATA_ENCRYPTION_KEY_B64') ?: '',
        'metadata_encryption_key_id' => getenv('BACKUP_METADATA_ENCRYPTION_KEY_ID') ?: 'backup-aes256gcm-v1',
        'provider_driver' => getenv('VP3_BACKUP_PROVIDER_DRIVER') ?: 'null',
        'warning_threshold_percent' => min(100.0, max(1.0, (float) (getenv('STORAGE_WARNING_THRESHOLD_PERCENT') ?: 80))),
        'critical_threshold_percent' => min(100.0, max(1.0, (float) (getenv('STORAGE_CRITICAL_THRESHOLD_PERCENT') ?: 95))),
    ],
    'infrastructure' => [
        'provider_driver' => getenv('VP3_INFRASTRUCTURE_PROVIDER_DRIVER') ?: 'null',
        'secret_encryption_key_base64' => getenv('PROVIDER_SECRET_ENCRYPTION_KEY_B64') ?: '',
        'secret_encryption_key_id' => getenv('PROVIDER_SECRET_ENCRYPTION_KEY_ID') ?: 'provider-aes256gcm-v1',
    ],
    'operations' => [
        'notification_driver' => getenv('VP3_OPERATIONS_NOTIFICATION_DRIVER') ?: 'null',
        'secret_encryption_key_base64' => getenv('OPERATIONS_SECRET_ENCRYPTION_KEY_B64') ?: '',
        'secret_encryption_key_id' => getenv('OPERATIONS_SECRET_ENCRYPTION_KEY_ID') ?: 'operations-aes256gcm-v1',
        'pod_offline_after_minutes' => max(1, (int) (getenv('OPERATIONS_POD_OFFLINE_AFTER_MINUTES') ?: 10)),
        'homeserver_offline_after_minutes' => max(1, (int) (getenv('OPERATIONS_HOMESERVER_OFFLINE_AFTER_MINUTES') ?: 10)),
    ],
];
