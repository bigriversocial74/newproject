<?php

declare(strict_types=1);

$services = require dirname(__DIR__) . '/bootstrap.php';
$homeServers = $services['homeservers'] ?? null;
if (!$homeServers instanceof \Vp3\HomeServers\HomeServerRegistryService) {
    fwrite(STDERR, "HomeServer registry service is unavailable.\n");
    exit(1);
}
$minutes = max(1, (int) ($services['config']['homeserver']['offline_after_minutes'] ?? 10));
$count = $homeServers->markOffline($minutes);
fwrite(STDOUT, json_encode(['offline_devices' => $count, 'threshold_minutes' => $minutes], JSON_THROW_ON_ERROR) . PHP_EOL);
