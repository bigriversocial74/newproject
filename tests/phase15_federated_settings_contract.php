<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$required = [
    'database/migrations/20260730_phase15_federated_settings.sql',
    'src/Settings/FederatedSettingsService.php',
    'src/Settings/FederatedSettingsSigner.php',
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
$signerSource = $read('src/Settings/FederatedSettingsSigner.php');
$deviceEndpoint = $read('public/api/homeserver/v1/settings-sync.php');
$browserEndpoint = $read('public/api/settings/v1/update.php');
$snapshotEndpoint = $read('public/api/settings/v1/snapshot.php');
$endpointBoundary = $read('src/Http/HomeServerEndpoint.php');
$settingsPage = $read('public/settings.php');
$fleetPage = $read('public/homeservers.php');
$javascript = $read('public/assets/federated-settings.js');

$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) $failures[] = $message;
};
$assert(str_contains($installer, '20260730_phase15_federated_settings.sql'), 'Cumulative installer omits Phase 15.');
$assert(str_contains($migration, "authority ENUM('vp3','homeserver','shared')"), 'Settings catalog authority boundary is missing.');
$assert(str_contains($migration, "sensitivity ENUM('non_secret')"), 'Settings catalog does not enforce non-secret values.');
$assert(str_contains($migration, 'federated_settings_sync_receipts'), 'Settings sync receipts are missing.');
$assert(str_contains($migration, 'request_hash CHAR(64) NOT NULL'), 'Settings sync receipts do not bind request IDs to canonical payload hashes.');
$assert(str_contains($service, 'expectedRevision !== $currentRevision'), 'Optimistic revision enforcement is missing.');
$assert(str_contains($service, "'vp3_authority'"), 'Device writes do not reject VP3-owned settings.');
$assert(str_contains($service, 'authenticateDevice'), 'Device settings synchronization is not credential authenticated.');
$assert(str_contains($service, "SELECT request_hash FROM federated_settings_sync_receipts"), 'Request replay does not load the canonical request hash.');
$assert(str_contains($service, 'request ID was reused with a different payload'), 'Request IDs are not bound to one canonical payload.');
$assert(str_contains($service, 'duplicate setting key'), 'Duplicate setting keys are not rejected before synchronization.');
$assert(str_contains($signerSource, "algorithm() !== 'Ed25519'"), 'Federated settings do not fail closed without Ed25519.');
foreach (['generated_at', 'replayed', 'applied', 'conflicts'] as $signedField) {
    $assert(str_contains($signerSource, "'{$signedField}' =>"), "Federated settings signature does not bind {$signedField}.");
}
$assert(str_contains($deviceEndpoint, 'bearerCredential'), 'Device sync endpoint does not require a bearer credential.');
$assert(str_contains($deviceEndpoint, 'requestId'), 'Device sync endpoint does not require a request ID.');
$assert(str_contains($deviceEndpoint, 'FederatedSettingsSigner'), 'Device sync response is not signed.');
$assert(str_contains($browserEndpoint, 'accountContext'), 'Browser setting mutation is not account scoped.');
$assert(str_contains($browserEndpoint, 'FederatedSettingsSigner') && str_contains($snapshotEndpoint, 'FederatedSettingsSigner'), 'Browser settings snapshots are not signed.');
foreach ([$endpointBoundary, $settingsPage, $fleetPage] as $roleBoundary) {
    $assert(str_contains($roleBoundary, 'customer_owner') && str_contains($roleBoundary, 'customer_admin'), 'A dashboard authorization boundary uses obsolete account roles.');
}
$assert(!str_contains($javascript, 'localStorage') && !str_contains($javascript, 'sessionStorage'), 'Browser settings UI persists state in browser storage.');
foreach (['secret_key','private_key','password','credential'] as $forbidden) {
    $assert(!str_contains($migration, "'{$forbidden}."), "Secret-like setting key {$forbidden} entered the federated catalog.");
}

if (function_exists('sodium_crypto_sign_keypair')) {
    require_once $root . '/src/HomeServers/HomeServerLeaseSigner.php';
    require_once $root . '/src/Settings/FederatedSettingsSigner.php';
    $pair = sodium_crypto_sign_keypair();
    $private = base64_encode(sodium_crypto_sign_secretkey($pair));
    $public = base64_encode(sodium_crypto_sign_publickey($pair));
    $leaseSigner = new Vp3\HomeServers\HomeServerLeaseSigner($private, $public, 'homeserver-lease-test-v1');
    $settingsSigner = new Vp3\Settings\FederatedSettingsSigner($leaseSigner);
    $applied = [['setting_key' => 'appearance.theme', 'revision' => 2, 'index' => 0]];
    $conflicts = [['setting_key' => 'updates.channel', 'reason' => 'vp3_authority', 'current_revision' => 1]];
    $signed = $settingsSigner->sign([
        'schema' => 'vp3.federated-settings.v1',
        'account_id' => 7,
        'device_public_id' => 'HS-TEST',
        'max_revision' => 2,
        'settings' => [['setting_key' => 'appearance.theme', 'value' => 'dark']],
        'generated_at' => '2026-07-30T07:00:00+00:00',
        'snapshot_hash' => str_repeat('a', 64),
        'replayed' => false,
        'applied' => $applied,
        'conflicts' => $conflicts,
    ]);
    $assert($signed['signature_algorithm'] === 'Ed25519', 'Federated settings signer did not emit Ed25519.');
    $assert($signed['signing_key_id'] === 'homeserver-lease-test-v1', 'Federated settings signer emitted the wrong key ID.');
    $assert($leaseSigner->verify($signed['signed_document'], $signed['signature']), 'Federated settings signature cannot be verified.');
    $document = strtr((string) $signed['signed_document'], '-_', '+/');
    $padding = strlen($document) % 4;
    if ($padding > 0) $document .= str_repeat('=', 4 - $padding);
    $claims = json_decode((string) base64_decode($document, true), true, 32, JSON_THROW_ON_ERROR);
    $assert(($claims['snapshot_hash'] ?? null) === str_repeat('a', 64), 'Signed settings document does not bind the snapshot hash.');
    $assert(($claims['generated_at'] ?? null) === '2026-07-30T07:00:00+00:00', 'Signed settings document does not bind generation time.');
    $assert(($claims['applied'] ?? null) === $applied, 'Signed settings document does not bind applied updates.');
    $assert(($claims['conflicts'] ?? null) === $conflicts, 'Signed settings document does not bind conflicts.');
    $assert(($claims['replayed'] ?? null) === false, 'Signed settings document does not bind replay state.');
    $assert((int) ($claims['exp'] ?? 0) > (int) ($claims['iat'] ?? 0), 'Signed settings document expiration is invalid.');
} else {
    $failures[] = 'The sodium extension is required for the Phase 15 signing contract.';
}

if ($failures !== []) {
    fwrite(STDERR, implode("\n", $failures) . "\n");
    exit(1);
}
echo "Phase 15 federated settings contract passed.\n";
