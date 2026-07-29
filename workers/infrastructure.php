<?php

declare(strict_types=1);

$services = require dirname(__DIR__) . '/bootstrap.php';
$infrastructure = $services['infrastructure'] ?? null;
if (!$infrastructure instanceof \Vp3\Infrastructure\InfrastructureProviderService) {
    fwrite(STDERR, "Infrastructure provider service is unavailable.\n");
    exit(1);
}
$workerId = getenv('VP3_INFRASTRUCTURE_WORKER_ID') ?: (gethostname() . ':' . getmypid());
$limit = max(1, min(100, (int) (getenv('VP3_INFRASTRUCTURE_WORKER_LIMIT') ?: 25)));
$processed = 0;
while ($processed < $limit) {
    $result = $infrastructure->processNext($workerId);
    if ($result === null) {
        break;
    }
    fwrite(STDOUT, json_encode($result, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    $processed++;
}
