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
];
