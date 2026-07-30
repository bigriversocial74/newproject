<?php

declare(strict_types=1);

use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
ControlCenterEndpoint::requireMethod('POST');

try {
    $payload = ControlCenterEndpoint::payload();
    $account = ControlCenterEndpoint::accountContextForRoles(
        $container,
        $payload,
        ['customer_owner', 'customer_admin', 'support_member']
    );
    JsonResponse::send(['data' => $container['operations_control_center_query']->snapshot(
        $account['account_id'],
        (int) $account['user']['id'],
        $account['role']
    )]);
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
