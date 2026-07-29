<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

$requiredFiles = [
    'database/migrations/20260729_phase5_pod_provisioning.sql',
    'src/Provisioning/PodProvisioningAdapter.php',
    'src/Provisioning/NullPodProvisioningAdapter.php',
    'src/Provisioning/ProtectedConfigurationMerger.php',
    'src/Provisioning/PodProvisioningService.php',
    'src/Deployments/PodHealthService.php',
    'workers/pod-provisioning.php',
];
foreach ($requiredFiles as $file) {
    $assert(is_file($root . '/' . $file), 'Missing Phase 5 file: ' . $file);
}

$migration = file_get_contents($root . '/database/migrations/20260729_phase5_pod_provisioning.sql') ?: '';
foreach (['pod_deployments', 'pod_provisioning_jobs', 'pod_provisioning_steps', 'pod_provisioning_receipts', 'pod_configuration_receipts', 'pod_deployment_events'] as $table) {
    $assert(str_contains($migration, 'CREATE TABLE IF NOT EXISTS ' . $table), 'Missing Phase 5 table: ' . $table);
}
$assert(str_contains($migration, 'UNIQUE KEY uq_pod_deployment_domain'), 'One deployment per Domain is not enforced.');
$assert(str_contains($migration, 'UNIQUE KEY uq_pod_deployment_license'), 'One deployment per POD license is not enforced.');
$assert(str_contains($migration, 'UNIQUE KEY uq_pod_job_idempotency'), 'Provisioning idempotency is not enforced.');

$service = file_get_contents($root . '/src/Provisioning/PodProvisioningService.php') ?: '';
foreach ([
    'payment_confirmed', 'domain_registered', 'hosting_allocated', 'database_created', 'pod_installed',
    'configuration_written', 'owner_account_created', 'license_injected', 'ssl_requested',
    'installation_verified', 'deployment_active',
] as $stage) {
    $assert(str_contains($service, "'{$stage}'"), 'Missing provisioning stage: ' . $stage);
}
foreach (['FOR UPDATE SKIP LOCKED', 'reconcileBillingOutbox', 'enqueueRollback', 'rollback(', 'pause(', 'resume(', 'retry('] as $contract) {
    $assert(str_contains($service, $contract), 'Missing provisioning contract: ' . $contract);
}
$assert(!str_contains($migration, 'configuration_json'), 'Configuration secrets must not be stored in VP3.');
$assert(str_contains($service, 'configuration_hash'), 'Configuration hash receipt is missing.');
$assert(str_contains($service, 'preserve-existing-protected-paths'), 'Configuration preservation contract is missing.');

if ($failures !== []) {
    fwrite(STDERR, "Phase 5 contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 5 static contract certification passed.\n");
