<?php

declare(strict_types=1);

use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;
use Vp3\Lifecycle\DomainPodLifecycleActionService;
use Vp3\Lifecycle\PodRollbackLifecycleService;

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
    $rollback = new PodRollbackLifecycleService(
        $container['database'],
        $container['pod_provisioning']
    );
    $action = strtolower(trim((string) ($payload['action'] ?? '')));
    $actorId = (int) $account['user']['id'];
    $requestId = ControlCenterEndpoint::requestId($payload);

    $result = match ($action) {
        'provision' => $service->provisionPod(
            $account['account_id'],
            $actorId,
            $account['role'],
            (string) ($payload['domain_public_id'] ?? ''),
            $requestId,
            ControlCenterEndpoint::idempotencyKey($payload)
        ),
        'pause', 'resume', 'retry' => $service->transitionPodJob(
            $account['account_id'],
            $actorId,
            $account['role'],
            (string) ($payload['job_public_id'] ?? ''),
            $action,
            $requestId
        ),
        'rollback' => $rollback->enqueue(
            $account['account_id'],
            $actorId,
            $account['role'],
            (string) ($payload['deployment_public_id'] ?? ''),
            (string) ($payload['confirmation'] ?? ''),
            $requestId,
            ControlCenterEndpoint::idempotencyKey($payload)
        ),
        default => throw new RuntimeException('The requested POD lifecycle action is not supported.'),
    };

    JsonResponse::send(['data' => $result]);
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
