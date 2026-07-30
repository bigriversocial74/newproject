<?php

declare(strict_types=1);

use Vp3\Http\HomeServerEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
HomeServerEndpoint::requireMethod('POST');
try {
    $payload = HomeServerEndpoint::payload();
    $account = HomeServerEndpoint::accountContext($container, $payload);
    $result = $container['homeserver_control_plane']->acceptTransfer(
        $account['account_id'],
        (string) ($payload['transfer_code'] ?? ''),
        (int) ($payload['target_license_id'] ?? 0),
        HomeServerEndpoint::requestId($payload)
    );
    unset($result['license_id']);
    $result['account_public_id'] = $account['account_public_id'];
    JsonResponse::send(['data' => $result]);
} catch (Throwable $exception) {
    HomeServerEndpoint::sendException($exception);
}
