<?php

declare(strict_types=1);

/*
 * VP3 BROWSER / CONTROL-PANEL INSTALLATION
 * ----------------------------------------
 * 1. Rename this file to config.php.
 * 2. Edit the values in $vp3LocalSettings below.
 * 3. Import database/vp3-single-install.sql with phpMyAdmin.
 * 4. Open /setup.php to create the first administrator.
 *
 * The full advanced defaults remain in config-example.php. This short file
 * inherits them and overrides only the values required for a basic install.
 */
$vp3LocalSettings = [
    'app_base_url' => 'https://YOUR-DOMAIN.example',
    'database_dsn' => 'mysql:host=localhost;dbname=YOUR_DATABASE;charset=utf8mb4',
    'database_username' => 'YOUR_DATABASE_USER',
    'database_password' => 'YOUR_DATABASE_PASSWORD',
    'auth_secret_encryption_key_base64' => 'CHANGE_THIS_TO_A_BASE64_32_BYTE_KEY',
    'first_user_setup_key' => 'CHANGE_THIS_TO_A_PRIVATE_SETUP_KEY_AT_LEAST_20_CHARACTERS',
];

$config = require __DIR__ . '/config-example.php';
$config['app']['env'] = 'production';
$config['app']['base_url'] = rtrim($vp3LocalSettings['app_base_url'], '/');
$config['app']['session_secure'] = true;
$config['database']['dsn'] = $vp3LocalSettings['database_dsn'];
$config['database']['username'] = $vp3LocalSettings['database_username'];
$config['database']['password'] = $vp3LocalSettings['database_password'];
$config['auth']['secret_encryption_key_base64'] = $vp3LocalSettings['auth_secret_encryption_key_base64'];
$config['setup'] = [
    'enabled' => true,
    'first_user_key' => $vp3LocalSettings['first_user_setup_key'],
    'grant_platform_operator_to_first_owner' => true,
];

return $config;
