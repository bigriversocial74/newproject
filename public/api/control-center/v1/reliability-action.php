<?php

declare(strict_types=1);

use Vp3\Deployment\PlatformOperatorAuthorizer;
use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;
use Vp3\Reliability\ReliabilityControlCenterActionService;
use Vp3\Reliability\ReliabilityProbeExecutor;
use Vp3\Reliability\ReliabilityWorkerService;

$container = require __DIR__ . '/_bootstrap.php';
ControlCenterEndpoint::requireMethod('POST');

try {
    $payload = ControlCenterEndpoint::payload();
    $account = ControlCenterEndpoint::accountContextForRoles(
        $container,
        $payload,
        ['customer_owner', 'customer_admin']
    );
    $accountId = (int) $account['account_id'];
    $actorId = (int) $account['user']['id'];
    $role = (string) $account['role'];
    $action = strtolower(trim((string) ($payload['action'] ?? '')));
    $requestId = ControlCenterEndpoint::requestId($payload);

    $authorizer = new PlatformOperatorAuthorizer($container['database']);
    $executor = new ReliabilityProbeExecutor($container['database'], dirname(__DIR__, 5));
    $worker = new ReliabilityWorkerService(
        $container['database'],
        $executor,
        $container['operational_incidents']
    );
    $service = new ReliabilityControlCenterActionService(
        $container['database'],
        $authorizer,
        $worker
    );

    switch ($action) {
        case 'save_component':
            $data = $service->saveComponent(
                $accountId,
                $actorId,
                $role,
                isset($payload['component_public_id']) ? (string) $payload['component_public_id'] : null,
                (string) ($payload['component_key'] ?? ''),
                (string) ($payload['display_name'] ?? ''),
                (string) ($payload['component_type'] ?? ''),
                (string) ($payload['visibility'] ?? 'private'),
                isset($payload['environment_public_id']) ? (string) $payload['environment_public_id'] : null,
                (bool) ($payload['enabled'] ?? true),
                (int) ($payload['display_order'] ?? 100),
                $requestId
            );
            break;

        case 'save_objective':
            $data = $service->saveObjective(
                $accountId,
                $actorId,
                $role,
                (string) ($payload['component_public_id'] ?? ''),
                (int) ($payload['availability_target_bps'] ?? 9990),
                isset($payload['latency_target_ms']) && $payload['latency_target_ms'] !== ''
                    ? (int) $payload['latency_target_ms'] : null,
                (int) ($payload['evaluation_window_minutes'] ?? 43200),
                (float) ($payload['warning_burn_rate'] ?? 2.0),
                (float) ($payload['critical_burn_rate'] ?? 14.4),
                (int) ($payload['consecutive_failure_threshold'] ?? 3),
                (int) ($payload['recovery_success_threshold'] ?? 2),
                $requestId
            );
            break;

        case 'save_probe':
            $data = $service->saveProbe(
                $accountId,
                $actorId,
                $role,
                (string) ($payload['component_public_id'] ?? ''),
                isset($payload['probe_public_id']) ? (string) $payload['probe_public_id'] : null,
                (string) ($payload['probe_type'] ?? ''),
                (string) ($payload['target_value'] ?? ''),
                (int) ($payload['interval_seconds'] ?? 300),
                (int) ($payload['timeout_ms'] ?? 5000),
                (bool) ($payload['enabled'] ?? true),
                $requestId
            );
            break;

        case 'save_status_settings':
            $data = $service->saveStatusSettings(
                $accountId,
                $actorId,
                $role,
                (string) ($payload['public_slug'] ?? ''),
                (string) ($payload['page_title'] ?? ''),
                (string) ($payload['page_description'] ?? ''),
                (bool) ($payload['public_enabled'] ?? false),
                (bool) ($payload['show_history'] ?? true),
                $requestId
            );
            break;

        case 'publish_status_message':
            $data = $service->publishStatusMessage(
                $accountId,
                $actorId,
                $role,
                isset($payload['component_public_id']) ? (string) $payload['component_public_id'] : null,
                (string) ($payload['title'] ?? ''),
                (string) ($payload['message'] ?? ''),
                (string) ($payload['starts_at'] ?? ''),
                isset($payload['ends_at']) ? (string) $payload['ends_at'] : null,
                $requestId
            );
            break;

        case 'resolve_status_message':
            $data = $service->resolveStatusMessage(
                $accountId,
                $actorId,
                $role,
                (string) ($payload['message_public_id'] ?? ''),
                $requestId
            );
            break;

        case 'record_manual_observation':
            $data = $service->recordManualObservation(
                $accountId,
                $actorId,
                $role,
                (string) ($payload['probe_public_id'] ?? ''),
                (string) ($payload['status'] ?? ''),
                isset($payload['latency_ms']) && $payload['latency_ms'] !== '' ? (int) $payload['latency_ms'] : null,
                isset($payload['value_numeric']) && $payload['value_numeric'] !== '' ? (float) $payload['value_numeric'] : null,
                isset($payload['error_code']) ? (string) $payload['error_code'] : null,
                $requestId
            );
            break;

        default:
            throw new InvalidArgumentException('A valid reliability action is required.');
    }

    JsonResponse::send(['data' => $data]);
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
