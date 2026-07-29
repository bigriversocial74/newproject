<?php

declare(strict_types=1);

$services = require dirname(__DIR__) . '/bootstrap.php';
$updates = $services['software_updates'] ?? null;
if (!$updates instanceof \Vp3\Updates\SoftwareUpdateService) {
    fwrite(STDERR, "Software update service is unavailable.\n");
    exit(1);
}
$workerId = getenv('VP3_UPDATE_WORKER_ID') ?: (gethostname() . ':' . getmypid());
$limit = max(1, min(100, (int) (getenv('VP3_UPDATE_WORKER_LIMIT') ?: 25)));
$processed = 0;
while ($processed < $limit) {
    $result = $updates->processNext($workerId);
    if ($result === null) {
        break;
    }
    fwrite(STDOUT, json_encode($result, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    $processed++;
}
