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

$service = $read('src/HomeServers/HomeServerControlPlaneService.php');
$endpoint = $read('src/Http/HomeServerEndpoint.php');
$migration = $read('database/migrations/20260729_phase12_homeserver_control_plane.sql');
$cutoverMigration = $read('database/migrations/20260729_phase13_homeserver_cutover_contract.sql');
$installer = $read('database/vp3-single-install.sql');
$download = $read('public/api/homeserver/v1/installer-download.php');
$catalog = $read('src/Releases/ReleaseCatalogService.php');

foreach ([
    'registerDevice', 'activateDevice', 'heartbeat', 'refreshLease', 'latestRelease',
    'consumeInstallerGrant', 'recordUpdateReceipt', 'setSuspended', 'revokeDevice',
    'replaceDevice', 'requestTransfer', 'acceptTransfer',
] as $method) {
    $assert(str_contains($service, 'function ' . $method . '('), 'Missing control-plane method: ' . $method);
}
foreach ([
    'register.php', 'activate.php', 'heartbeat.php', 'lease.php', 'manifest.php',
    'installer-download.php', 'update-receipt.php', 'suspend.php', 'revoke.php',
    'replace.php', 'transfer-request.php', 'transfer-accept.php',
] as $file) {
    $assert(is_file($root . '/public/api/homeserver/v1/' . $file), 'Missing HomeServer API endpoint: ' . $file);
}
$assert(str_contains($endpoint, 'MAX_JSON_BYTES = 65536'), 'HomeServer JSON body limit is missing.');
$assert(str_contains($endpoint, 'Bearer\\s+'), 'Bearer device authentication is missing.');
$assert(str_contains($endpoint, 'assertCsrf'), 'Account mutation CSRF enforcement is missing.');
$assert(str_contains($endpoint, "role IN ('customer_owner','customer_admin')"), 'Current customer owner/administrator authorization is missing.');
$assert(str_contains($service, "hash('sha256', \$token)"), 'Installer grant hashing is missing.');
$assert(str_contains($service, 'function revokeSoftwareAuthority('), 'Software-only suspension revocation helper is missing.');
$assert(str_contains($service, "\$this->revokeSoftwareAuthority(\$pdo, (int) \$device['id']);"), 'Suspension does not use the software-only authority boundary.');
$assert(str_contains($service, 'function revokeDeviceAuthority('), 'Full device revocation helper is missing.');
$assert(!str_contains($migration, 'credential TEXT') && !str_contains($migration, 'token TEXT'), 'Plaintext credentials or grant tokens are stored.');
$assert(str_contains($migration, 'token_hash CHAR(64)'), 'Installer grant token hash column is missing.');
$assert(str_contains($migration, "status ENUM('active','consumed','expired','revoked')"), 'Installer grant lifecycle is incomplete.');
$assert(str_contains($migration, 'homeserver_transfer_requests'), 'HomeServer transfer schema is missing.');
$assert(str_contains($migration, 'homeserver_update_receipts_v1'), 'HomeServer update receipt schema is missing.');
$assert(str_contains($cutoverMigration, 'authenticode_thumbprint'), 'Phase 13 Authenticode trust metadata migration is missing.');
$assert(str_contains($cutoverMigration, 'file_name'), 'Phase 13 canonical installer filename migration is missing.');
$assert(str_contains($catalog, 'HomeServer release artifacts require a valid Authenticode signer thumbprint.'), 'HomeServer release Authenticode enforcement is missing.');
$assert(str_contains($catalog, "'authenticode_thumbprint'"), 'Authenticode thumbprint is omitted from the signed release manifest.');
$assert(str_contains($catalog, "'file_name'"), 'Canonical installer filename is omitted from the signed release manifest.');
$assert(str_contains($installer, '20260729_phase12_homeserver_control_plane.sql'), 'Cumulative installer omits Phase 12.');
$assert(str_contains($installer, '20260729_phase13_homeserver_cutover_contract.sql'), 'Cumulative installer omits Phase 13.');
$assert(str_contains($download, "str_contains(\$reference, '..')"), 'Installer traversal rejection is missing.');
$assert(str_contains($download, "preg_match('#^[a-z]+://#i'"), 'Remote installer URL rejection is missing.');
$assert(str_contains($download, "hash_file('sha256'"), 'Installer SHA-256 verification is missing.');
$assert(str_contains($download, 'X-Content-Type-Options: nosniff'), 'Installer download hardening headers are missing.');
$assert(!str_contains($service, 'Microgifter'), 'VP3 control-plane service depends on Microgifter authority.');

if ($failures !== []) {
    fwrite(STDERR, implode("\n", $failures) . "\n");
    exit(1);
}

echo "Phase 12 HomeServer control-plane contract passed.\n";
