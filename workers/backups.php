<?php

declare(strict_types=1);

$services = require dirname(__DIR__) . '/bootstrap.php';
$backups = $services['backups'] ?? null;
if (!$backups instanceof \Vp3\Backups\BackupService) {
    fwrite(STDERR, "Backup service is unavailable.\n");
    exit(1);
}
$workerId = getenv('VP3_BACKUP_WORKER_ID') ?: (gethostname() . ':' . getmypid());
$limit = max(1, min(100, (int) (getenv('VP3_BACKUP_WORKER_LIMIT') ?: 25)));
$scheduled = $backups->enqueueDuePolicies($limit);
$retention = $backups->applyRetention($limit);
$processedBackups = 0;
while ($processedBackups < $limit) {
    $result = $backups->processNextBackup($workerId);
    if ($result === null) {
        break;
    }
    fwrite(STDOUT, json_encode(['type' => 'backup', 'result' => $result], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    $processedBackups++;
}
$processedRestores = 0;
while ($processedRestores < $limit) {
    $result = $backups->processNextRestore($workerId);
    if ($result === null) {
        break;
    }
    fwrite(STDOUT, json_encode(['type' => 'restore', 'result' => $result], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    $processedRestores++;
}
fwrite(STDOUT, json_encode([
    'scheduled_jobs' => $scheduled,
    'retention_jobs' => $retention,
    'processed_backups' => $processedBackups,
    'processed_restores' => $processedRestores,
], JSON_THROW_ON_ERROR) . PHP_EOL);
