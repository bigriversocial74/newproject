<?php

declare(strict_types=1);

use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;
use Vp3\Security\SecurityAuditQueryService;

$container = require __DIR__ . '/_bootstrap.php';
ControlCenterEndpoint::requireMethod('POST');

try {
    $payload = ControlCenterEndpoint::payload();
    $account = ControlCenterEndpoint::accountContextForRoles(
        $container,
        $payload,
        ['customer_owner', 'customer_admin', 'billing_manager', 'support_member']
    );

    $filters = isset($payload['filters']) && is_array($payload['filters'])
        ? $payload['filters']
        : [];
    $limit = isset($payload['limit']) ? (int) $payload['limit'] : 100;

    $query = new SecurityAuditQueryService($container['database']);
    JsonResponse::send(['data' => $query->snapshot(
        $account['account_id'],
        (int) $account['user']['id'],
        $account['role'],
        $filters,
        $limit
    )]);
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
