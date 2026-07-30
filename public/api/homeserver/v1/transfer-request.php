<?php

declare(strict_types=1);

use Vp3\Http\HomeServerEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
HomeServerEndpoint::requireMethod('POST');
try {
    $payload = HomeServerEndpoint::payload();
    $account = HomeServerEndpoint::accountContext($container, $payload);
    $result = $container['homeserver_control_plane']->requestTransfer(
        $account['account_id'],
        (string) ($payload['device_public_id'] ?? ''),
        (int) ($payload['target_account_id'] ?? 0),
        HomeServerEndpoint::requestId($payload)
    );
    JsonResponse::send(['data' => $result], 201);
} catch (Throwable $exception) {
    HomeServerEndpoint::sendException($exception);
}
