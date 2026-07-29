<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

foreach ([
    'database/migrations/20260729_phase6_homeserver_registry.sql',
    'src/HomeServers/HomeServerLeaseSigner.php',
    'src/HomeServers/HomeServerRegistryService.php',
] as $file) {
    $assert(is_file($root . '/' . $file), 'Missing Phase 6 file: ' . $file);
}

$migration = file_get_contents($root . '/database/migrations/20260729_phase6_homeserver_registry.sql') ?: '';
foreach ([
    'homeserver_devices', 'homeserver_pairing_codes', 'homeserver_frontend_pairs',
    'homeserver_credential_rotations', 'homeserver_entitlement_leases',
    'homeserver_request_receipts', 'homeserver_events',
] as $table) {
    $assert(str_contains($migration, 'CREATE TABLE IF NOT EXISTS ' . $table), 'Missing HomeServer table: ' . $table);
}
$assert(str_contains($migration, 'UNIQUE KEY uq_homeserver_license'), 'One device per HomeServer license is not enforced.');
$assert(str_contains($migration, 'UNIQUE KEY uq_homeserver_fingerprint'), 'Unique HomeServer device identity is not enforced.');
$assert(str_contains($migration, 'credential_hash CHAR(64)'), 'HomeServer credentials are not hash-only.');
$assert(str_contains($migration, 'code_hash CHAR(64)'), 'HomeServer pairing codes are not hash-only.');

$forbidden = [
    'knowledge_content', 'prompt_content', 'conversation_content', 'model_blob', 'tool_credential',
    'private_file', 'mcp_payload', 'local_execution_receipt', 'plaintext_credential', 'plaintext_code',
];
foreach ($forbidden as $column) {
    $assert(!str_contains(strtolower($migration), $column), 'Forbidden private HomeServer field exists: ' . $column);
}

$service = file_get_contents($root . '/src/HomeServers/HomeServerRegistryService.php') ?: '';
foreach ([
    'registerDevice', 'activateDevice', 'issueFrontendPairingCode', 'pairFrontend', 'unpairFrontend',
    'rotateCredential', 'heartbeat', 'issueEntitlementLease', 'revokeDevice', 'markOffline',
] as $method) {
    $assert(str_contains($service, 'function ' . $method), 'Missing HomeServer lifecycle operation: ' . $method);
}
$assert(str_contains($service, "hash('sha256', $credential)"), 'Device credentials are not hashed before storage.');
$assert(str_contains($service, "hash('sha256', $code)"), 'Pairing codes are not hashed before storage.');
$assert(str_contains($service, 'frontend_limit'), 'Licensed paired-front-end limit is not enforced.');
$assert(str_contains($service, 'HomeServerLeaseSigner'), 'Signed entitlement lease dependency is missing.');
$assert(str_contains($service, 'entitlement_snapshot_hash'), 'Entitlement snapshot receipt is missing.');

if ($failures !== []) {
    fwrite(STDERR, "Phase 6 contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 6 HomeServer privacy and static contract certification passed.\n");
