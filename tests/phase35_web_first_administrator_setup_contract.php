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

$config = $read('config/config-example.php');
$page = $read('public/setup.php');
$service = $read('src/Deployment/WebInitialSetupService.php');

$assert(str_contains($config, '$vp3LocalSettings'), 'The config example must expose one clearly marked editable settings block.');
$assert(str_contains($config, "'first_user_setup_key'"), 'The config example must include a private first-user setup key.');
$assert(str_contains($config, "'grant_platform_operator_to_first_owner' => true"), 'The first administrator must receive platform-operator authority by default.');
$assert(str_contains($config, "'enabled' => true"), 'One-time browser setup must be explicitly enabled in the example.');

$assert(str_contains($page, 'config/config-example.php'), 'The setup page must explain the rename-first configuration path.');
$assert(str_contains($page, 'database/vp3-single-install.sql'), 'The setup page must explain the SQL import prerequisite.');
$assert(str_contains($page, "hash_equals((string) \$_SESSION['vp3_setup_csrf']"), 'The setup form must verify a CSRF token.');
$assert(str_contains($page, 'hash_equals($configuredSetupKey, $submittedSetupKey)'), 'The setup key must be checked with constant-time comparison.');
$assert(str_contains($page, "SELECT COUNT(*) FROM accounts"), 'The setup page must lock when an account exists.');
$assert(str_contains($page, "SELECT COUNT(*) FROM users"), 'The setup page must lock when a user exists.');
$assert(str_contains($page, 'strlen($authKey) !== 32'), 'The setup page must reject an invalid encryption key.');
$assert(str_contains($page, 'X-Frame-Options: DENY'), 'The setup page must deny framing.');
$assert(str_contains($page, 'Cache-Control: no-store'), 'The setup page must disable response caching.');
$assert(!str_contains($page, 'VP3_BOOTSTRAP_OWNER_PASSWORD'), 'The browser setup path must not require shell environment variables.');
$assert(!str_contains($page, 'name="password" value='), 'The setup page must not reflect a password value.');

$assert(str_contains($service, '$this->database->transaction'), 'Owner creation and operator grant must share an outer transaction.');
$assert(str_contains($service, '$this->owners->bootstrap'), 'The web setup must reuse the certified owner bootstrap service.');
$assert(str_contains($service, '$this->operators->grant'), 'The web setup must reuse the certified platform-operator grant service.');

fwrite(STDOUT, "Phase 35 browser first-administrator setup contract passed.\n");
