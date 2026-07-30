<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};
$read = static function (string $path) use ($root): string {
    $content = file_get_contents($root . '/' . $path);
    if ($content === false) {
        throw new RuntimeException('Unable to read ' . $path);
    }
    return $content;
};

$required = [
    'src/Settings/FederatedSettingsControlCenterService.php',
    'src/Settings/FederatedSettingsControlCenterSigner.php',
    'public/settings.php',
    'public/api/settings/v1/snapshot.php',
    'public/api/settings/v1/update.php',
    'public/assets/federated-settings.js',
    'public/assets/federated-settings.css',
    'tests/phase22_federated_settings_control_center_database_integration.php',
];
foreach ($required as $path) {
    $assert(is_file($root . '/' . $path), 'Missing Phase 22 file ' . $path . '.');
}

$service = $read('src/Settings/FederatedSettingsControlCenterService.php');
$signer = $read('src/Settings/FederatedSettingsControlCenterSigner.php');
$page = $read('public/settings.php');
$snapshot = $read('public/api/settings/v1/snapshot.php');
$update = $read('public/api/settings/v1/update.php');
$browser = $read('public/assets/federated-settings.js');
$shell = $read('src/ControlCenter/ControlCenterPage.php');
$deviceSync = $read('public/api/homeserver/v1/settings-sync.php');

$assert(str_contains($page, "resolveForRoles(\$container, ['customer_owner', 'customer_admin'])"), 'Settings page is not owner/admin-only.');
$assert(str_contains($page, "'settings'"), 'Settings page is not integrated into the shared shell.');
$assert(str_contains($page, 'ControlCenterPage::renderStart'), 'Settings page bypasses the shared Control Center shell.');
$assert(str_contains($shell, "'settings' => ['/settings.php'"), 'Control Center navigation omits Settings & Authority.');
$assert(str_contains($shell, '/assets/federated-settings.css'), 'Shared shell does not load the scoped settings stylesheet.');

foreach ([$snapshot, $update] as $endpoint) {
    $assert(str_contains($endpoint, 'ControlCenterEndpoint::requireMethod'), 'A browser settings endpoint is not POST-only.');
    $assert(str_contains($endpoint, 'accountContextForRoles'), 'A browser settings endpoint bypasses role-aware account authorization.');
    $assert(!str_contains($endpoint, 'HomeServerEndpoint'), 'A browser settings endpoint still uses the HomeServer error boundary.');
}
$assert(str_contains($update, 'ControlCenterEndpoint::requestId'), 'Settings updates do not require a bounded request identity.');
$assert(str_contains($service, 'LIMIT 1 FOR UPDATE'), 'Settings updates do not lock membership/resources.');
$assert(str_contains($service, 'hash_equals($storedRole, $role)'), 'Settings updates trust stale caller roles.');
$assert(str_contains($service, "\$authority === 'shared'"), 'Shared settings are not explicitly device scoped.');
$assert(str_contains($service, "\$authority === 'homeserver'"), 'HomeServer-authority settings are not blocked in VP3.');
$assert(str_contains($service, "\$scopeType = 'account'"), 'VP3 settings are not account scoped.');
$assert(str_contains($service, "\$scopeType = 'device'"), 'Shared settings are not device scoped.');
$assert(str_contains($service, 'settings_revision_conflict'), 'Optimistic settings conflicts lack a stable public code.');
$assert(str_contains($service, 'settings_request_conflict'), 'Settings request replay mismatches lack a stable public code.');
$assert(str_contains($service, 'federated_settings_sync_receipts'), 'Browser settings updates do not persist replay receipts.');
$assert(str_contains($service, 'audit_events'), 'Settings authorization and updates lack audit evidence.');

$assert(str_contains($signer, "algorithm() !== 'Ed25519'"), 'Browser settings signatures do not fail closed without Ed25519.');
$assert(str_contains($signer, "'account_public_id'"), 'Browser settings signature omits the public account identity.');
$assert(!str_contains($signer, "'account_id' =>"), 'Browser settings signature embeds an internal account ID.');
$assert(str_contains($signer, "'devices' =>"), 'Browser settings signature does not bind the public HomeServer list.');
$assert(str_contains($signer, "'replayed' =>"), 'Browser settings signature does not bind replay state.');

$assert(str_contains($browser, 'device_public_id'), 'Browser settings requests omit the selected public HomeServer identity.');
$assert(str_contains($browser, "credentials: 'same-origin'"), 'Browser settings requests are not same-origin credentialed.');
$assert(str_contains($browser, "cache: 'no-store'"), 'Browser settings responses can be cached.');
$assert(str_contains($browser, "headers['X-Request-ID']"), 'Browser settings mutations omit a request ID header.');
$assert(str_contains($browser, 'setting.requires_device'), 'Shared controls do not enforce HomeServer selection.');
$assert(!str_contains($browser, 'localStorage') && !str_contains($browser, 'sessionStorage'), 'Settings UI persists account or device state in browser storage.');
$assert(!str_contains($browser, 'credential_hash') && !str_contains($browser, 'device_fingerprint'), 'Settings UI references private HomeServer authentication fields.');

$browserMappingStart = strpos($service, 'private function browserSnapshot');
$browserMappingEnd = strpos($service, 'private function existingReceipt', $browserMappingStart === false ? 0 : $browserMappingStart);
$browserMapping = $browserMappingStart === false
    ? ''
    : substr($service, $browserMappingStart, $browserMappingEnd === false ? null : $browserMappingEnd - $browserMappingStart);
$forbiddenOutputKeys = [
    "'id' =>", "'account_id' =>", "'device_id' =>", "'credential_hash' =>",
    "'device_fingerprint' =>", "'lease_token' =>", "'private_key' =>", "'password_hash' =>",
];
foreach ($forbiddenOutputKeys as $needle) {
    $assert(!str_contains($browserMapping, $needle), 'Settings browser snapshot exposes forbidden output mapping ' . $needle . '.');
}

$assert(str_contains($deviceSync, 'HomeServerEndpoint::bearerCredential'), 'Certified HomeServer settings sync credential boundary changed.');
$assert(str_contains($deviceSync, 'FederatedSettingsSigner'), 'Certified HomeServer settings sync signer changed.');

if ($failures !== []) {
    fwrite(STDERR, "Phase 22 Federated Settings Control Center contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 22 Federated Settings Control Center contract passed.\n");
