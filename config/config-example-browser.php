<?php

declare(strict_types=1);

/*
 * VP3 BROWSER / CONTROL-PANEL INSTALLATION
 * ----------------------------------------
 * 1. Rename this file to config.php.
 * 2. Edit only the domain and database values below.
 * 3. Import database/vp3-single-install.sql with phpMyAdmin.
 * 4. Open /setup.php to create the first administrator.
 *
 * VP3 automatically creates and preserves its private encryption key in
 * config/config-generated-secrets.php. Keep that generated file private and
 * preserve it with config.php during future deployments.
 */
$vp3LocalSettings = [
    'app_base_url' => 'https://YOUR-DOMAIN.example',
    'database_dsn' => 'mysql:host=localhost;dbname=YOUR_DATABASE;charset=utf8mb4',
    'database_username' => 'YOUR_DATABASE_USER',
    'database_password' => 'YOUR_DATABASE_PASSWORD',
];

$vp3GeneratedSecretsPath = __DIR__ . '/config-generated-secrets.php';
$vp3LoadOrCreateGeneratedSecrets = static function (string $path): array {
    $load = static function (string $secretPath): array {
        $secrets = require $secretPath;
        $encoded = is_array($secrets)
            ? (string) ($secrets['auth_secret_encryption_key_base64'] ?? '')
            : '';
        $decoded = base64_decode($encoded, true);
        if (!is_string($decoded) || strlen($decoded) !== 32) {
            throw new RuntimeException('The generated VP3 encryption key file is invalid.');
        }
        return ['auth_secret_encryption_key_base64' => $encoded];
    };

    if (is_file($path)) {
        return $load($path);
    }

    $encoded = base64_encode(random_bytes(32));
    $document = "<?php\n\ndeclare(strict_types=1);\n\nreturn [\n"
        . "    'auth_secret_encryption_key_base64' => " . var_export($encoded, true) . ",\n"
        . "];\n";
    $temporaryPath = $path . '.tmp.' . bin2hex(random_bytes(6));
    $written = file_put_contents($temporaryPath, $document, LOCK_EX);
    if ($written !== strlen($document)) {
        @unlink($temporaryPath);
        throw new RuntimeException('VP3 could not create its generated encryption key file.');
    }
    @chmod($temporaryPath, 0600);
    if (!@rename($temporaryPath, $path)) {
        @unlink($temporaryPath);
        if (!is_file($path)) {
            throw new RuntimeException('VP3 could not activate its generated encryption key file.');
        }
    }
    clearstatcache(true, $path);
    return $load($path);
};
$vp3GeneratedSecrets = $vp3LoadOrCreateGeneratedSecrets($vp3GeneratedSecretsPath);

$config = require __DIR__ . '/config-example.php';
$config['app']['env'] = 'production';
$config['app']['base_url'] = rtrim($vp3LocalSettings['app_base_url'], '/');
$config['app']['session_secure'] = true;
$config['database']['dsn'] = $vp3LocalSettings['database_dsn'];
$config['database']['username'] = $vp3LocalSettings['database_username'];
$config['database']['password'] = $vp3LocalSettings['database_password'];
$config['auth']['secret_encryption_key_base64'] = $vp3GeneratedSecrets['auth_secret_encryption_key_base64'];
$config['setup'] = [
    'enabled' => true,
    'grant_platform_operator_to_first_owner' => true,
];

unset(
    $vp3GeneratedSecrets,
    $vp3GeneratedSecretsPath,
    $vp3LoadOrCreateGeneratedSecrets,
    $vp3LocalSettings
);

return $config;
