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
    'database/migrations/20260729_phase8_backups_storage.sql',
    'database/migrations/20260729_phase8_backup_job_snapshots.sql',
    'src/Backups/BackupMetadataCipher.php',
    'src/Backups/BackupProviderAdapter.php',
    'src/Backups/NullBackupProviderAdapter.php',
    'src/Backups/BackupService.php',
    'workers/backups.php',
] as $file) {
    $assert(is_file($root . '/' . $file), 'Missing Phase 8 file: ' . $file);
}
$migration = file_get_contents($root . '/database/migrations/20260729_phase8_backups_storage.sql') ?: '';
foreach ([
    'backup_policies', 'backup_jobs', 'backup_snapshots', 'backup_verifications',
    'restore_jobs', 'backup_receipts', 'storage_observations', 'storage_alerts',
] as $table) {
    $assert(str_contains($migration, 'CREATE TABLE IF NOT EXISTS ' . $table), 'Missing backup/storage table: ' . $table);
}
foreach (['provider_reference_ciphertext', 'provider_reference_nonce', 'provider_reference_tag', 'encryption_key_id'] as $column) {
    $assert(str_contains($migration, $column), 'Missing encrypted backup reference field: ' . $column);
}
$assert(!str_contains($migration, 'backup_content'), 'Customer backup content must not be stored in VP3.');
$cipher = file_get_contents($root . '/src/Backups/BackupMetadataCipher.php') ?: '';
$assert(str_contains($cipher, 'aes-256-gcm'), 'AES-256-GCM backup metadata encryption is missing.');
$service = file_get_contents($root . '/src/Backups/BackupService.php') ?: '';
foreach (['enqueueDuePolicies', 'enqueueBackup', 'processNextBackup', 'enqueueRestore', 'processNextRestore', 'applyRetention', 'observeStorage'] as $method) {
    $assert(str_contains($service, 'function ' . $method), 'Missing backup/storage lifecycle operation: ' . $method);
}
foreach (['FOR UPDATE SKIP LOCKED', 'verifyBackup', 'restoreBackup', 'deleteBackup', 'verification_status', 'retention_delete'] as $contract) {
    $assert(str_contains($service, $contract), 'Missing backup safety contract: ' . $contract);
}
if ($failures !== []) {
    fwrite(STDERR, "Phase 8 contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 8 backup and storage contract certification passed.\n");
