<?php

declare(strict_types=1);

use Vp3\Http\HomeServerEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
HomeServerEndpoint::requireMethod('POST');
try {
    $payload = HomeServerEndpoint::payload();
    $result = $container['homeserver_control_plane']->latestRelease(
        (string) ($payload['device_public_id'] ?? ''),
        HomeServerEndpoint::bearerCredential(),
        (string) ($payload['current_version'] ?? ''),
        (string) ($payload['platform'] ?? 'windows'),
        (string) ($payload['architecture'] ?? 'x86_64'),
        HomeServerEndpoint::requestId($payload)
    );
    JsonResponse::send(['data' => $result]);
} catch (Throwable $exception) {
    HomeServerEndpoint::sendException($exception);
}
