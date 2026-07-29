<?php

declare(strict_types=1);

$services = require dirname(__DIR__) . '/bootstrap.php';
$operations = $services['operations'] ?? null;
if (!$operations instanceof \Vp3\Operations\OperationsReadinessService) {
    fwrite(STDERR, "Operations readiness service is unavailable.\n");
    exit(1);
}

$workerId = getenv('VP3_OPERATIONS_WORKER_ID') ?: (gethostname() . ':' . getmypid());
$mode = strtolower((string) (getenv('VP3_OPERATIONS_MODE') ?: 'all'));
$limit = max(1, min(100, (int) (getenv('VP3_OPERATIONS_NOTIFICATION_LIMIT') ?: 25)));

if (in_array($mode, ['all', 'monitor'], true)) {
    fwrite(STDOUT, json_encode($operations->runMonitoringPass($workerId), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL);
}
if (in_array($mode, ['all', 'notifications'], true)) {
    for ($processed = 0; $processed < $limit; $processed++) {
        $result = $operations->processNextNotification($workerId);
        if ($result === null) {
            break;
        }
        fwrite(STDOUT, json_encode($result, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    }
}
if (in_array($mode, ['all', 'readiness'], true)) {
    fwrite(STDOUT, json_encode($operations->assessReadiness('worker', 0), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL);
}
