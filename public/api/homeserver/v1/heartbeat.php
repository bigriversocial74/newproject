<?php

declare(strict_types=1);

use Vp3\Http\HomeServerEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
HomeServerEndpoint::requireMethod('POST');
try {
    $payload = HomeServerEndpoint::payload();
    $health = is_array($payload['health'] ?? null) ? $payload['health'] : [];
    $result = $container['homeserver_control_plane']->heartbeat(
        (string) ($payload['device_public_id'] ?? ''),
        HomeServerEndpoint::bearerCredential(),
        (string) ($payload['device_fingerprint'] ?? ''),
        $health,
        HomeServerEndpoint::requestId($payload)
    );
    JsonResponse::send(['data' => $result]);
} catch (Throwable $exception) {
    HomeServerEndpoint::sendException($exception);
}
