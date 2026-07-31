<?php

declare(strict_types=1);

use Vp3\Reliability\ReliabilityProbeExecutor;
use Vp3\Reliability\ReliabilityWorkerService;

$root = dirname(__DIR__);
$container = require $root . '/bootstrap.php';
$workerId = trim((string) (getenv('VP3_RELIABILITY_WORKER_ID') ?: gethostname() . '-reliability'));
$maximum = max(1, min(100, (int) (getenv('VP3_RELIABILITY_MAX_PER_RUN') ?: 25)));

$executor = new ReliabilityProbeExecutor($container['database'], $root);
$worker = new ReliabilityWorkerService(
    $container['database'],
    $executor,
    $container['operational_incidents'],
    max(60, min(3600, (int) (getenv('VP3_RELIABILITY_LEASE_SECONDS') ?: 300)))
);

$processed = [];
for ($index = 0; $index < $maximum; $index++) {
    $result = $worker->processNext($workerId);
    if ($result === null) {
        break;
    }
    $processed[] = $result;
}

fwrite(STDOUT, json_encode([
    'processed' => count($processed),
    'results' => $processed,
    'completed_at' => gmdate('Y-m-d\TH:i:s\Z'),
], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL);
