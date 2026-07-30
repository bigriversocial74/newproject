<?php

declare(strict_types=1);

use Vp3\ControlCenter\AccountSecurityQueryService;
use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
ControlCenterEndpoint::requireMethod('POST');

try {
    $payload = ControlCenterEndpoint::payload();
    $account = ControlCenterEndpoint::accountContext(
        $container,
        $payload,
        ['customer_owner', 'customer_admin', 'billing_manager', 'support_member']
    );
    $query = new AccountSecurityQueryService($container['database'], $container['mfa']);
    JsonResponse::send(['data' => $query->snapshot(
        $account['account_id'],
        (int) $account['user']['id'],
        $account['role'],
        (string) $account['session']['public_id']
    )]);
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
