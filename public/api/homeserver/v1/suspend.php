<?php

declare(strict_types=1);

use Vp3\Http\HomeServerEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
HomeServerEndpoint::requireBrowserMethod('POST');
try {
    $payload = HomeServerEndpoint::payload();
    $account = HomeServerEndpoint::accountContext($container, $payload);
    $suspended = filter_var($payload['suspended'] ?? true, FILTER_VALIDATE_BOOL);
    $container['homeserver_control_plane']->setSuspended(
        $account['account_id'],
        (string) ($payload['device_public_id'] ?? ''),
        $suspended,
        HomeServerEndpoint::requestId($payload)
    );
    JsonResponse::send(['data' => ['device_public_id' => (string) ($payload['device_public_id'] ?? ''), 'status' => $suspended ? 'suspended' : 'paired']]);
} catch (Throwable $exception) {
    HomeServerEndpoint::sendException($exception);
}
