<?php

declare(strict_types=1);

use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;
use Vp3\Lifecycle\DomainPodLifecycleActionService;

$container = require __DIR__ . '/_bootstrap.php';
ControlCenterEndpoint::requireMethod('POST');

try {
    $payload = ControlCenterEndpoint::payload();
    $account = ControlCenterEndpoint::accountContextForRoles(
        $container,
        $payload,
        ['customer_owner', 'customer_admin']
    );
    $service = new DomainPodLifecycleActionService(
        $container['database'],
        $container['domain_registry'],
        $container['pod_provisioning']
    );
    $action = strtolower(trim((string) ($payload['action'] ?? '')));
    $actorId = (int) $account['user']['id'];

    if ($action === 'availability') {
        JsonResponse::send(['data' => $service->availability(
            $account['account_id'],
            $actorId,
            $account['role'],
            (string) ($payload['label'] ?? '')
        )]);
    }

    $requestId = ControlCenterEndpoint::requestId($payload);
    $idempotencyKey = ControlCenterEndpoint::idempotencyKey($payload);
    $result = match ($action) {
        'register' => $service->registerDomain(
            $account['account_id'],
            $actorId,
            $account['role'],
            (string) ($payload['subscription_public_id'] ?? ''),
            (string) ($payload['label'] ?? ''),
            $requestId,
            $idempotencyKey
        ),
        'activate_reserved' => $service->activateReservedDomain(
            $account['account_id'],
            $actorId,
            $account['role'],
            (string) ($payload['domain_public_id'] ?? ''),
            $requestId,
            $idempotencyKey
        ),
        'suspend' => $service->suspendDomain(
            $account['account_id'],
            $actorId,
            $account['role'],
            (string) ($payload['domain_public_id'] ?? ''),
            (string) ($payload['reason'] ?? ''),
            $requestId,
            $idempotencyKey
        ),
        'release' => $service->releaseDomain(
            $account['account_id'],
            $actorId,
            $account['role'],
            (string) ($payload['domain_public_id'] ?? ''),
            (string) ($payload['confirmation'] ?? ''),
            $requestId,
            $idempotencyKey
        ),
        default => throw new RuntimeException('The requested Domain lifecycle action is not supported.'),
    };

    JsonResponse::send(['data' => $result]);
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
