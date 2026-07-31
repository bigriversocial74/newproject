<?php

declare(strict_types=1);

use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;
use Vp3\Security\SecurityAlertPreferenceService;
use Vp3\Security\SecurityAuditService;
use Vp3\Security\SecurityCenterQueryService;

$container = require __DIR__ . '/_bootstrap.php';
ControlCenterEndpoint::requireMethod('POST');

try {
    $payload = ControlCenterEndpoint::payload();
    $account = ControlCenterEndpoint::accountContextForRoles(
        $container,
        $payload,
        ['customer_owner', 'customer_admin']
    );

    $filters = isset($payload['filters']) && is_array($payload['filters'])
        ? $payload['filters']
        : [];
    $limit = isset($payload['limit']) ? (int) $payload['limit'] : 100;
    $userId = (int) $account['user']['id'];
    $role = (string) $account['role'];

    $service = new SecurityCenterQueryService(
        $container['database'],
        $container['operations_secret_cipher']
    );
    $data = $service->snapshot(
        $account['account_id'],
        $userId,
        $role,
        $filters,
        $limit
    );
    $audit = new SecurityAuditService($container['database']);
    $alerts = new SecurityAlertPreferenceService(
        $container['database'],
        $container['operational_incidents'],
        $audit
    );
    $data['alert_preferences'] = $alerts->snapshot(
        $account['account_id'],
        $userId,
        $role
    );

    JsonResponse::send(['data' => $data]);
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
