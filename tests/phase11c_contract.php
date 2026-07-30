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
    'src/Provisioning/LocalPodProvisioningAdapter.php',
    'src/Provisioning/DatabaseAwareLocalPodProvisioningAdapter.php',
    'src/Infrastructure/WildcardLocalInfrastructureAdapter.php',
] as $path) {
    $assert(is_file($root . '/' . $path), 'Phase 11C implementation file is missing: ' . $path);
}

$composer = json_decode((string) file_get_contents($root . '/composer.json'), true);
$requires = is_array($composer) ? (array) ($composer['require'] ?? []) : [];
$assert(array_key_exists('ext-zip', $requires), 'Composer does not declare the ZIP runtime extension.');

$local = (string) file_get_contents($root . '/src/Provisioning/LocalPodProvisioningAdapter.php');
foreach ([
    'hash_file',
    'ZipArchive',
    'maximumArchiveFiles',
    'maximumArchiveBytes',
    'zipEntryIsSymlink',
    'archiveEntryName',
    'CREATE DATABASE IF NOT EXISTS',
    'CREATE USER IF NOT EXISTS',
    'ALTER USER',
    'GRANT ALL PRIVILEGES',
    'configuration_written',
    'installation_verified',
    'DROP DATABASE IF EXISTS',
    'DROP USER IF EXISTS',
] as $contract) {
    $assert(str_contains($local, $contract), 'Local POD adapter is missing contract: ' . $contract);
}
$assert(!str_contains($local, 'extractTo('), 'Local POD adapter uses unsafe bulk ZIP extraction.');
foreach (['shell_exec(', 'passthru(', 'system('] as $forbiddenShellCall) {
    $assert(!str_contains($local, $forbiddenShellCall), 'Local POD adapter invokes a forbidden shell command: ' . $forbiddenShellCall);
}

$wrapper = (string) file_get_contents($root . '/src/Provisioning/DatabaseAwareLocalPodProvisioningAdapter.php');
foreach (['domain_registrations', 'license_public_id', 'account_public_id', 'shared/config', 'symlink'] as $contract) {
    $assert(str_contains($wrapper, $contract), 'Database-aware local adapter is missing contract: ' . $contract);
}

$wildcard = (string) file_get_contents($root . '/src/Infrastructure/WildcardLocalInfrastructureAdapter.php');
foreach (['wildcard_dns_ready', 'wildcard_tls_ready', 'shared_wildcard_record_preserved', 'shared_wildcard_certificate_preserved'] as $contract) {
    $assert(str_contains($wildcard, $contract), 'Wildcard infrastructure adapter is missing contract: ' . $contract);
}

$factory = (string) file_get_contents($root . '/src/Runtime/AdapterFactory.php');
foreach (['DatabaseAwareLocalPodProvisioningAdapter', "driver === 'local'", 'WildcardLocalInfrastructureAdapter', "driver === 'wildcard-local'"] as $contract) {
    $assert(str_contains($factory, $contract), 'Adapter factory is missing Phase 11C wiring: ' . $contract);
}

$config = (string) file_get_contents($root . '/config/config-example.php');
foreach ([
    'VP3_POD_DEPLOYMENT_ROOT',
    'VP3_POD_RELEASE_ZIP',
    'VP3_POD_RELEASE_VERSION',
    'VP3_POD_RELEASE_SHA256',
    'VP3_POD_DB_ADMIN_DSN',
    'VP3_POD_DB_ADMIN_USERNAME',
    'VP3_POD_DB_ADMIN_PASSWORD',
    'VP3_WILDCARD_BASE_DOMAIN',
    'VP3_WILDCARD_DNS_READY',
    'VP3_WILDCARD_TLS_READY',
] as $contract) {
    $assert(str_contains($config, $contract), 'Example configuration is missing Phase 11C setting: ' . $contract);
}

$validator = (string) file_get_contents($root . '/src/Runtime/RuntimeConfigurationValidator.php');
foreach ([
    'validateLocalProvisioning',
    'validateWildcardInfrastructure',
    'VP3_POD_RELEASE_SHA256 does not match',
    'VP3_WILDCARD_DNS_READY must be true',
    'VP3_WILDCARD_TLS_READY must be true',
    'Local POD provisioning currently requires the wildcard-local infrastructure adapter',
] as $contract) {
    $assert(str_contains($validator, $contract), 'Production validation is missing Phase 11C contract: ' . $contract);
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 11C contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

echo "Phase 11C production-adapter contract passed.\n";
