<?php

declare(strict_types=1);

use Vp3\Deployment\PlatformOperatorAuthorizer;
use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;
use Vp3\Reliability\ReliabilityControlCenterQueryService;

$container = require __DIR__ . '/_bootstrap.php';
ControlCenterEndpoint::requireMethod('POST');

try {
    $payload = ControlCenterEndpoint::payload();
    $account = ControlCenterEndpoint::accountContextForRoles(
        $container,
        $payload,
        ['customer_owner', 'customer_admin']
    );
    $authorizer = new PlatformOperatorAuthorizer($container['database']);
    $service = new ReliabilityControlCenterQueryService($container['database'], $authorizer);
    $data = $service->snapshot(
        (int) $account['account_id'],
        (int) $account['user']['id'],
        (string) $account['role']
    );
    JsonResponse::send(['data' => $data]);
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
