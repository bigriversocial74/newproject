<?php

declare(strict_types=1);

use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;
use Vp3\Recovery\RecoveryControlCenterActionService;

$container = require __DIR__ . '/_bootstrap.php';
ControlCenterEndpoint::requireMethod('POST');
try {
    $payload = ControlCenterEndpoint::payload();
    $account = ControlCenterEndpoint::accountContextForRoles($container, $payload, ['customer_owner', 'customer_admin']);
    $service = new RecoveryControlCenterActionService($container['database']);
    $action = strtolower(trim((string) ($payload['action'] ?? '')));
    $requestId = ControlCenterEndpoint::requestId($payload);
    $actorId = (int) $account['user']['id'];
    $role = (string) $account['role'];

    $result = match ($action) {
        'save_policy' => $service->savePolicy(
            $account['account_id'], $actorId, $role, trim((string) ($payload['pod_public_id'] ?? '')),
            (int) ($payload['interval_minutes'] ?? 0), (int) ($payload['retention_count'] ?? 0),
            (int) ($payload['retention_days'] ?? 0), $requestId
        ),
        'backup_now' => $service->enqueueBackup(
            $account['account_id'], $actorId, $role, trim((string) ($payload['pod_public_id'] ?? '')),
            $requestId, ControlCenterEndpoint::idempotencyKey($payload)
        ),
        'restore' => $service->enqueueRestore(
            $account['account_id'], $actorId, $role, trim((string) ($payload['snapshot_public_id'] ?? '')),
            (string) ($payload['confirmation'] ?? ''), $requestId, ControlCenterEndpoint::idempotencyKey($payload)
        ),
        'update' => $service->enqueueUpdate(
            $account['account_id'], $actorId, $role, trim((string) ($payload['pod_public_id'] ?? '')),
            trim((string) ($payload['release_public_id'] ?? '')), $requestId,
            ControlCenterEndpoint::idempotencyKey($payload)
        ),
        'pause_update', 'resume_update' => (function () use ($service, $account, $actorId, $role, $payload, $action, $requestId): array {
            $service->transitionUpdate(
                $account['account_id'], $actorId, $role, trim((string) ($payload['job_public_id'] ?? '')),
                $action, $requestId
            );
            return ['status' => $action === 'pause_update' ? 'paused' : 'queued'];
        })(),
        default => throw new RuntimeException('The requested recovery action is not supported.'),
    };
    JsonResponse::send(['data' => $result]);
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
