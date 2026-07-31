<?php

declare(strict_types=1);

use Vp3\Http\HomeServerEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
HomeServerEndpoint::requireBrowserMethod('POST');
try {
    $payload = HomeServerEndpoint::payload();
    $account = HomeServerEndpoint::accountContext($container, $payload);
    $result = $container['homeserver_control_plane']->replaceDevice(
        $account['account_id'],
        (string) ($payload['device_public_id'] ?? ''),
        (string) ($payload['replacement_fingerprint'] ?? ''),
        HomeServerEndpoint::requestId($payload),
        HomeServerEndpoint::idempotencyKey($payload)
    );
    JsonResponse::send(['data' => $result], 201);
} catch (Throwable $exception) {
    HomeServerEndpoint::sendException($exception);
}
