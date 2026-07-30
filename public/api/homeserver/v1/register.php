<?php

declare(strict_types=1);

use Vp3\Http\HomeServerEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
HomeServerEndpoint::requireMethod('POST');
try {
    $payload = HomeServerEndpoint::payload();
    $account = HomeServerEndpoint::accountContext($container, $payload);
    $result = $container['homeserver_control_plane']->registerDevice(
        $account['account_id'],
        (int) ($payload['license_id'] ?? 0),
        (string) ($payload['device_fingerprint'] ?? ''),
        HomeServerEndpoint::requestId($payload),
        HomeServerEndpoint::idempotencyKey($payload)
    );
    unset($result['device_id']);
    $result['account_public_id'] = $account['account_public_id'];
    JsonResponse::send(['data' => $result], 201);
} catch (Throwable $exception) {
    HomeServerEndpoint::sendException($exception);
}
