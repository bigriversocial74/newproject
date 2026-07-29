<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

$composer = json_decode((string) file_get_contents($root . '/composer.json'), true);
$requires = is_array($composer) ? (array) ($composer['require'] ?? []) : [];
foreach (['ext-pdo_mysql', 'ext-mbstring', 'ext-openssl', 'ext-sodium'] as $extension) {
    $assert(array_key_exists($extension, $requires), 'Composer does not declare required runtime extension: ' . $extension);
}

$installer = (string) file_get_contents($root . '/database/vp3-single-install.sql');
$assert(str_contains($installer, '20260729_phase11a_runtime_queue_hardening.sql'), 'Phase 11A migration is missing from the cumulative installer.');
$migration = (string) file_get_contents($root . '/database/migrations/20260729_phase11a_runtime_queue_hardening.sql');
foreach (['billing_outbox', 'pod_provisioning_jobs', 'update_jobs', 'backup_jobs', 'restore_jobs', 'provider_operations', 'operational_notifications'] as $table) {
    $assert(str_contains($migration, "TABLE_NAME='{$table}'"), 'Phase 11A migration does not harden queue: ' . $table);
}
foreach (['locked_until', 'lease_token', 'idx_update_job_lease', 'idx_backup_job_lease', 'idx_restore_job_lease'] as $contract) {
    $assert(str_contains($migration, $contract), 'Phase 11A migration is missing lease contract: ' . $contract);
}

foreach (['src/Queue/QueueLease.php', 'src/Queue/QueueLeaseLostException.php', 'src/Runtime/RuntimeConfigurationValidator.php', 'src/Runtime/AdapterFactory.php'] as $path) {
    $assert(is_file($root . '/' . $path), 'Phase 11A implementation file is missing: ' . $path);
}

$config = (string) file_get_contents($root . '/config/config-example.php');
$assert(str_contains($config, "'development'"), 'Example configuration must not default to production.');
$assert(str_contains($config, 'VP3_QUEUE_LEASE_SECONDS'), 'Queue lease duration is not configurable.');

$bootstrap = (string) file_get_contents($root . '/bootstrap.php');
foreach (['RuntimeConfigurationValidator', 'AdapterFactory::provisioning', 'AdapterFactory::updates', 'AdapterFactory::backups', 'AdapterFactory::infrastructure', 'AdapterFactory::notifications', '$queueLeaseSeconds'] as $contract) {
    $assert(str_contains($bootstrap, $contract), 'Production bootstrap is missing Phase 11A wiring: ' . $contract);
}

$files = [
    'src/Provisioning/PodProvisioningService.php',
    'src/Updates/SoftwareUpdateService.php',
    'src/Backups/BackupService.php',
    'src/Infrastructure/InfrastructureProviderService.php',
    'src/Operations/OperationalNotificationService.php',
];
foreach ($files as $path) {
    $source = (string) file_get_contents($root . '/' . $path);
    $assert(str_contains($source, 'lease_token'), $path . ' does not enforce lease-token ownership.');
    $assert(str_contains($source, 'locked_until'), $path . ' does not use expiring queue leases.');
}
$backup = (string) file_get_contents($root . '/src/Backups/BackupService.php');
$updates = (string) file_get_contents($root . '/src/Updates/SoftwareUpdateService.php');
$assert(!str_contains($backup, "status IN ('queued','running')"), 'Backup/restore workers can still claim actively running jobs.');
$assert(!str_contains($updates, "status IN ('queued','running')"), 'Update workers can still claim actively running jobs.');

$phase9 = (string) file_get_contents($root . '/tests/phase9_contract.php');
$assert(!str_contains($phase9, '"\'infrastructure\' => $infrastructure"'), 'Phase 9 contract still interpolates an undefined variable.');

if ($failures !== []) {
    fwrite(STDERR, "Phase 11A contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 11A runtime and queue-hardening contract passed.\n");
