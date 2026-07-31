<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$read = static function (string $path) use ($root): string {
    $content = file_get_contents($root . '/' . $path);
    if (!is_string($content)) {
        throw new RuntimeException('Unable to read ' . $path);
    }
    return $content;
};
$assert = static function (bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
};

$config = $read('config/config-example-browser.php');
$entrypoint = $read('public/setup.php');
$page = $read('public/setup-first-user.php');
$service = $read('src/Deployment/WebInitialSetupService.php');
$gitignore = $read('.gitignore');

$assert(str_contains($config, '$vp3LocalSettings'), 'The browser config example must expose one clearly marked editable settings block.');
$assert(str_contains($config, "require __DIR__ . '/config-example.php'"), 'The browser config must inherit the complete advanced defaults.');
foreach (['app_base_url', 'database_dsn', 'database_username', 'database_password'] as $editableSetting) {
    $assert(str_contains($config, "'" . $editableSetting . "'"), 'The browser config is missing editable setting ' . $editableSetting . '.');
}
$assert(!str_contains($config, "'first_user_setup_key'"), 'The browser config must not require a manual setup key.');
$assert(!str_contains($config, "'auth_secret_encryption_key_base64' => 'CHANGE_THIS"), 'The browser config must not require a manual encryption key.');
$assert(str_contains($config, "config-generated-secrets.php"), 'The browser config must use a persistent generated secret file.');
$assert(str_contains($config, 'base64_encode(random_bytes(32))'), 'The browser config must generate a cryptographically secure 32-byte key.');
$assert(str_contains($config, 'file_put_contents($temporaryPath, $document, LOCK_EX)'), 'Generated secret creation must use an exclusive write.');
$assert(str_contains($config, '@chmod($temporaryPath, 0600)'), 'Generated secret permissions must be restricted when supported.');
$assert(str_contains($gitignore, '/config/config-generated-secrets.php'), 'The generated secret file must be excluded from Git.');
$assert(str_contains($config, "'grant_platform_operator_to_first_owner' => true"), 'The first administrator must receive platform-operator authority by default.');
$assert(str_contains($entrypoint, "require __DIR__ . '/setup-first-user.php'"), 'The stable setup entrypoint must load the dedicated implementation.');

$assert(str_contains($page, 'config/config-example-browser.php'), 'The setup page must explain the rename-first browser configuration path.');
$assert(str_contains($page, 'database/vp3-single-install.sql'), 'The setup page must explain the SQL import prerequisite.');
$assert(str_contains($page, "hash_equals((string) \$_SESSION['vp3_setup_csrf']"), 'The setup form must verify a CSRF token.');
$assert(!str_contains($page, 'name="setup_key"'), 'The setup form must not ask for a private setup key.');
$assert(!str_contains($page, '$configuredSetupKey'), 'The setup handler must not depend on a configured setup key.');
$assert(str_contains($page, 'SELECT COUNT(*) FROM accounts'), 'The setup page must lock when an account exists.');
$assert(str_contains($page, 'SELECT COUNT(*) FROM users'), 'The setup page must lock when a user exists.');
$assert(str_contains($page, 'strlen($authKey) !== 32'), 'The setup page must reject a missing or invalid generated encryption key.');
$assert(str_contains($page, 'X-Frame-Options: DENY'), 'The setup page must deny framing.');
$assert(str_contains($page, 'Cache-Control: no-store'), 'The setup page must disable response caching.');
$assert(!str_contains($page, 'VP3_BOOTSTRAP_OWNER_PASSWORD'), 'The browser setup path must not require shell environment variables.');
$assert(!str_contains($page, 'name="password" value='), 'The setup page must not reflect a password value.');

$assert(str_contains($service, '$this->database->transaction'), 'Owner creation and operator grant must share an outer transaction.');
$assert(str_contains($service, '$this->owners->bootstrap'), 'The web setup must reuse the certified owner bootstrap service.');
$assert(str_contains($service, '$this->operators->grant'), 'The web setup must reuse the certified platform-operator grant service.');

$tempDirectory = sys_get_temp_dir() . '/vp3-browser-config-' . bin2hex(random_bytes(6));
if (!mkdir($tempDirectory, 0700, true) && !is_dir($tempDirectory)) {
    throw new RuntimeException('Unable to create browser config test directory.');
}
try {
    copy($root . '/config/config-example.php', $tempDirectory . '/config-example.php');
    copy($root . '/config/config-example-browser.php', $tempDirectory . '/config-example-browser.php');
    $first = require $tempDirectory . '/config-example-browser.php';
    $second = require $tempDirectory . '/config-example-browser.php';
    $firstKey = (string) ($first['auth']['secret_encryption_key_base64'] ?? '');
    $secondKey = (string) ($second['auth']['secret_encryption_key_base64'] ?? '');
    $decoded = base64_decode($firstKey, true);
    $assert(is_file($tempDirectory . '/config-generated-secrets.php'), 'The browser config did not create its persistent secret file.');
    $assert(is_string($decoded) && strlen($decoded) === 32, 'The generated browser encryption key is not 32 bytes.');
    $assert(hash_equals($firstKey, $secondKey), 'The generated browser encryption key was not stable across loads.');
} finally {
    foreach (glob($tempDirectory . '/*') ?: [] as $path) {
        @unlink($path);
    }
    @rmdir($tempDirectory);
}

fwrite(STDOUT, "Phase 35 browser first-administrator automatic-secret setup contract passed.\n");
