<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$required = [
    'database/migrations/20260730_phase15_federated_settings.sql',
    'src/Settings/FederatedSettingsService.php',
    'public/settings.php',
    'public/assets/federated-settings.js',
    'public/assets/federated-settings.css',
    'public/api/settings/v1/snapshot.php',
    'public/api/settings/v1/update.php',
    'public/api/homeserver/v1/settings-sync.php',
];
$failures = [];
foreach ($required as $file) {
    if (!is_file($root . '/' . $file)) $failures[] = "Missing {$file}";
}
$read = static fn (string $path): string => (string) file_get_contents($root . '/' . $path);
$migration = $read('database/migrations/20260730_phase15_federated_settings.sql');
$installer = $read('database/vp3-single-install.sql');
$service = $read('src/Settings/FederatedSettingsService.php');
$deviceEndpoint = $read('public/api/homeserver/v1/settings-sync.php');
$browserEndpoint = $read('public/api/settings/v1/update.php');
$javascript = $read('public/assets/federated-settings.js');

$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) $failures[] = $message;
};
$assert(str_contains($installer, '20260730_phase15_federated_settings.sql'), 'Cumulative installer omits Phase 15.');
$assert(str_contains($migration, "authority ENUM('vp3','homeserver','shared')"), 'Settings catalog authority boundary is missing.');
$assert(str_contains($migration, "sensitivity ENUM('non_secret')"), 'Settings catalog does not enforce non-secret values.');
$assert(str_contains($migration, 'federated_settings_sync_receipts'), 'Settings sync receipts are missing.');
$assert(str_contains($service, 'expectedRevision !== $currentRevision'), 'Optimistic revision enforcement is missing.');
$assert(str_contains($service, "'vp3_authority'"), 'Device writes do not reject VP3-owned settings.');
$assert(str_contains($service, 'authenticateDevice'), 'Device settings synchronization is not credential authenticated.');
$assert(str_contains($deviceEndpoint, 'bearerCredential'), 'Device sync endpoint does not require a bearer credential.');
$assert(str_contains($deviceEndpoint, 'requestId'), 'Device sync endpoint does not require a request ID.');
$assert(str_contains($browserEndpoint, 'accountContext'), 'Browser setting mutation is not account scoped.');
$assert(!str_contains($javascript, 'localStorage') && !str_contains($javascript, 'sessionStorage'), 'Browser settings UI persists state in browser storage.');
foreach (['secret_key','private_key','password','credential'] as $forbidden) {
    $assert(!str_contains($migration, "'{$forbidden}."), "Secret-like setting key {$forbidden} entered the federated catalog.");
}

if ($failures !== []) {
    fwrite(STDERR, implode("\n", $failures) . "\n");
    exit(1);
}
echo "Phase 15 federated settings contract passed.\n";
