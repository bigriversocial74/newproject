<?php

declare(strict_types=1);

use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;
use Vp3\Lifecycle\DomainPodLifecycleQueryService;

$container = require __DIR__ . '/_bootstrap.php';
ControlCenterEndpoint::requireMethod('POST');

try {
    $payload = ControlCenterEndpoint::payload();
    $account = ControlCenterEndpoint::accountContextForRoles(
        $container,
        $payload,
        ['customer_owner', 'customer_admin']
    );
    $query = new DomainPodLifecycleQueryService($container['database']);
    JsonResponse::send(['data' => $query->snapshot($account['account_id'])]);
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
