<?php

declare(strict_types=1);

$services = require dirname(__DIR__) . '/bootstrap.php';
$service = $services['pod_provisioning'] ?? null;
if (!$service instanceof \Vp3\Provisioning\PodProvisioningService) {
    fwrite(STDERR, "POD provisioning service is unavailable.\n");
    exit(1);
}

$workerId = getenv('VP3_WORKER_ID') ?: (gethostname() . ':' . getmypid());
$limit = max(1, min(100, (int) (getenv('VP3_WORKER_LIMIT') ?: 25)));
$service->reconcileBillingOutbox($limit);
$processed = 0;
while ($processed < $limit) {
    $result = $service->processNext($workerId);
    if ($result === null) {
        break;
    }
    fwrite(STDOUT, json_encode($result, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    $processed++;
}
