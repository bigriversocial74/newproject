<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

$config = file_get_contents($root . '/config/config-example.php');
$page = file_get_contents($root . '/public/setup.php');
$service = file_get_contents($root . '/src/Deployment/WebInitialSetupService.php');

$assert(is_string($config), 'The editable config example must exist.');
$assert(is_string($page), 'The browser setup page must exist.');
$assert(is_string($service), 'The transactional web setup service must exist.');

if (is_string($config)) {
    $assert(str_contains($config, '$vp3LocalSettings'), 'The config example must expose one clearly marked editable settings block.');
    $assert(str_contains($config, "'first_user_setup_key'"), 'The config example must include a private first-user setup key.');
    $assert(str_contains($config, "'grant_platform_operator_to_first_owner' => true"), 'The config example must make the first administrator a platform operator.');
    $assert(str_contains($config, "'enabled' => true"), 'The config example must explicitly enable one-time browser setup.');
}

if (is_string($page)) {
    $assert(str_contains($page, "config/config-example.php"), 'The setup page must explain the rename-first configuration path.');
    $assert(str_contains($page, "database/vp3-single-install.sql"), 'The setup page must explain the SQL import prerequisite.');
    $assert(str_contains($page, "hash_equals((string) \$_SESSION['vp3_setup_csrf']"), 'The setup form must verify a CSRF token.');
    $assert(str_contains($page, 'hash_equals($configuredSetupKey, $submittedSetupKey)'), 'The setup page must verify the private setup key with constant-time comparison.');
    $assert(str_contains($page, "SELECT COUNT(*) FROM accounts"), 'The setup page must lock when an account already exists.');
    $assert(str_contains($page, "SELECT COUNT(*) FROM users"), 'The setup page must lock when a user already exists.');
    $assert(str_contains($page, "X-Frame-Options: DENY"), 'The setup page must deny framing.');
    $assert(str_contains($page, "Cache-Control: no-store"), 'The setup page must disable response caching.');
    $assert(!str_contains($page, "name=\"password\" value="), 'The setup page must never reflect a password value.');
    $assert(!str_contains($page, 'VP3_BOOTSTRAP_OWNER_PASSWORD'), 'The browser setup path must not require shell environment variables.');
}

if (is_string($service)) {
    $assert(str_contains($service, '$this->database->transaction'), 'Owner creation and platform-operator grant must share an outer transaction.');
    $assert(str_contains($service, '$this->owners->bootstrap'), 'The web service must reuse the certified owner bootstrap service.');
    $assert(str_contains($service, '$this->operators->grant'), 'The web service must reuse the certified platform-operator grant service.');
}

if ($failures !== []) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}

fwrite(STDOUT, "Phase 35 browser first-administrator setup contract passed.\n");
