<?php

declare(strict_types=1);

use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;
use Vp3\Infrastructure\InfrastructureControlCenterActionService;

$container = require __DIR__ . '/_bootstrap.php';
ControlCenterEndpoint::requireMethod('POST');

try {
    $payload = ControlCenterEndpoint::payload();
    $account = ControlCenterEndpoint::accountContextForRoles(
        $container,
        $payload,
        ['customer_owner', 'customer_admin']
    );
    $service = new InfrastructureControlCenterActionService(
        $container['database'],
        $container['provider_secret_cipher']
    );
    $action = strtolower(trim((string) ($payload['action'] ?? '')));
    $requestId = ControlCenterEndpoint::requestId($payload);
    $actorId = (int) $account['user']['id'];

    $result = match ($action) {
        'save_connection' => $service->saveConnection(
            $account['account_id'],
            $actorId,
            $account['role'],
            (string) ($payload['provider_type'] ?? ''),
            (string) ($payload['provider_code'] ?? ''),
            (string) ($payload['display_name'] ?? ''),
            is_array($payload['auth_context'] ?? null) ? $payload['auth_context'] : [],
            $requestId
        ),
        'revoke_connection' => $service->revokeConnection(
            $account['account_id'],
            $actorId,
            $account['role'],
            (string) ($payload['connection_public_id'] ?? ''),
            $requestId
        ),
        'provision' => $service->enqueueProvision(
            $account['account_id'],
            $actorId,
            $account['role'],
            (string) ($payload['pod_public_id'] ?? ''),
            (string) ($payload['hosting_connection_public_id'] ?? ''),
            (string) ($payload['dns_connection_public_id'] ?? ''),
            (string) ($payload['certificate_connection_public_id'] ?? ''),
            $requestId,
            ControlCenterEndpoint::idempotencyKey($payload)
        ),
        'reconcile', 'teardown' => $service->enqueueBindingOperation(
            $account['account_id'],
            $actorId,
            $account['role'],
            (string) ($payload['binding_public_id'] ?? ''),
            $action,
            (string) ($payload['confirmation'] ?? ''),
            $requestId,
            ControlCenterEndpoint::idempotencyKey($payload)
        ),
        'pause_operation', 'resume_operation' => $service->transitionOperation(
            $account['account_id'],
            $actorId,
            $account['role'],
            (string) ($payload['operation_public_id'] ?? ''),
            $action === 'pause_operation' ? 'pause' : 'resume',
            $requestId
        ),
        default => throw new RuntimeException('The requested infrastructure action is not supported.'),
    };

    JsonResponse::send(['data' => $result]);
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
