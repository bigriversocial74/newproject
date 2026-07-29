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
    'database/migrations/20260729_phase9_provider_adapters.sql',
    'src/Infrastructure/ProviderSecretCipher.php',
    'src/Infrastructure/HostingProviderAdapter.php',
    'src/Infrastructure/DnsProviderAdapter.php',
    'src/Infrastructure/CertificateProviderAdapter.php',
    'src/Infrastructure/NullInfrastructureProviderAdapter.php',
    'src/Infrastructure/InfrastructureProviderService.php',
    'workers/infrastructure.php',
] as $file) {
    $assert(is_file($root . '/' . $file), 'Missing Phase 9 file: ' . $file);
}
$migration = file_get_contents($root . '/database/migrations/20260729_phase9_provider_adapters.sql') ?: '';
foreach ([
    'provider_connections', 'infrastructure_bindings', 'hosting_allocations', 'dns_bindings',
    'certificate_orders', 'provider_operations', 'provider_operation_steps', 'provider_receipts',
] as $table) {
    $assert(str_contains($migration, 'CREATE TABLE IF NOT EXISTS ' . $table), 'Missing infrastructure table: ' . $table);
}
foreach (['credentials_ciphertext', 'credentials_nonce', 'credentials_tag', 'provider_reference_ciphertext'] as $column) {
    $assert(str_contains($migration, $column), 'Missing encrypted provider field: ' . $column);
}
$assert(!str_contains($migration, 'api_secret VARCHAR'), 'Plaintext provider secret field exists.');
$cipher = file_get_contents($root . '/src/Infrastructure/ProviderSecretCipher.php') ?: '';
$assert(str_contains($cipher, 'aes-256-gcm'), 'AES-256-GCM provider secret encryption is missing.');
$service = file_get_contents($root . '/src/Infrastructure/InfrastructureProviderService.php') ?: '';
foreach (['saveConnection', 'enqueueProvision', 'enqueueReconcile', 'enqueueTeardown', 'processNext', 'pause', 'resume', 'revokeConnection'] as $method) {
    $assert(str_contains($service, 'function ' . $method), 'Missing infrastructure lifecycle operation: ' . $method);
}
foreach (['FOR UPDATE SKIP LOCKED', 'hosting_allocate', 'dns_bind', 'certificate_request', 'certificate_revoke', 'dns_remove', 'hosting_release'] as $contract) {
    $assert(str_contains($service, $contract), 'Missing infrastructure safety contract: ' . $contract);
}
$installer = file_get_contents($root . '/database/vp3-single-install.sql') ?: '';
$assert(str_contains($installer, '20260729_phase9_provider_adapters.sql'), 'Phase 9 migration is missing from the cumulative installer.');
$config = file_get_contents($root . '/config/config-example.php') ?: '';
foreach (['PROVIDER_SECRET_ENCRYPTION_KEY_B64', 'PROVIDER_SECRET_ENCRYPTION_KEY_ID', 'VP3_INFRASTRUCTURE_PROVIDER_DRIVER'] as $setting) {
    $assert(str_contains($config, $setting), 'Missing Phase 9 production configuration: ' . $setting);
}
$bootstrap = file_get_contents($root . '/bootstrap.php') ?: '';
foreach (['ProviderSecretCipher', 'NullInfrastructureProviderAdapter', 'InfrastructureProviderService', "'infrastructure' => $infrastructure"] as $wiring) {
    $assert(str_contains($bootstrap, $wiring), 'Missing Phase 9 production bootstrap wiring: ' . $wiring);
}
if ($failures !== []) {
    fwrite(STDERR, "Phase 9 contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 9 provider adapter and secret-boundary certification passed.\n");
