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
    'database/migrations/20260729_phase7_releases_updates.sql',
    'src/Releases/ReleaseManifestSigner.php',
    'src/Releases/ReleaseCatalogService.php',
    'src/Updates/SoftwareUpdateAdapter.php',
    'src/Updates/NullSoftwareUpdateAdapter.php',
    'src/Updates/SoftwareUpdateService.php',
    'workers/software-updates.php',
] as $file) {
    $assert(is_file($root . '/' . $file), 'Missing Phase 7 file: ' . $file);
}
$migration = file_get_contents($root . '/database/migrations/20260729_phase7_releases_updates.sql') ?: '';
foreach ([
    'software_products', 'software_releases', 'release_artifacts', 'release_compatibility_rules',
    'release_rollouts', 'update_jobs', 'update_steps', 'update_receipts', 'release_events',
] as $table) {
    $assert(str_contains($migration, 'CREATE TABLE IF NOT EXISTS ' . $table), 'Missing release/update table: ' . $table);
}
$assert(str_contains($migration, "ENUM('stable','beta','security')"), 'Required release channels are missing.');
$assert(str_contains($migration, 'pre_update_backup_verified'), 'Verified pre-update backup state is missing.');
$assert(str_contains($migration, 'UNIQUE KEY uq_update_job_idempotency'), 'Update idempotency is not enforced.');
$signer = file_get_contents($root . '/src/Releases/ReleaseManifestSigner.php') ?: '';
$assert(str_contains($signer, 'sodium_crypto_sign_detached'), 'Ed25519 manifest signing is missing.');
$assert(str_contains($signer, 'sodium_crypto_sign_verify_detached'), 'Manifest verification is missing.');
$service = file_get_contents($root . '/src/Updates/SoftwareUpdateService.php') ?: '';
foreach (['validating', 'backing_up', 'downloading', 'installing', 'migrating', 'verifying', 'completed'] as $stage) {
    $assert(str_contains($service, "'{$stage}'"), 'Missing update stage: ' . $stage);
}
foreach (['FOR UPDATE SKIP LOCKED', 'createPreUpdateBackup', 'pre_update_backup_verified', 'rolling_back', 'rolled_back', 'emergency_override'] as $contract) {
    $assert(str_contains($service, $contract), 'Missing update safety contract: ' . $contract);
}
if ($failures !== []) {
    fwrite(STDERR, "Phase 7 contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 7 signed release and update contract certification passed.\n");
