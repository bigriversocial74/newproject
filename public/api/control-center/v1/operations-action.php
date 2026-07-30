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
    $requestId = ControlCenterEndpoint::requestId($payload);
    $action = strtolower(trim((string) ($payload['action'] ?? '')));
    $service = $container['operations_control_center_actions'];
    $actorId = (int) $account['user']['id'];
    $role = $account['role'];

    if ($action === 'acknowledge_incident') {
        $service->acknowledgeIncident(
            $account['account_id'],
            $actorId,
            $role,
            (string) ($payload['incident_public_id'] ?? ''),
            $requestId
        );
        JsonResponse::send(['data' => ['status' => 'acknowledged']]);
    }
    if ($action === 'resolve_incident') {
        $service->resolveIncident(
            $account['account_id'],
            $actorId,
            $role,
            (string) ($payload['incident_public_id'] ?? ''),
            $requestId,
            (string) ($payload['resolution_summary'] ?? '')
        );
        JsonResponse::send(['data' => ['status' => 'resolved']]);
    }
    if ($action === 'save_notification_channel') {
        JsonResponse::send(['data' => $service->saveSmtpChannel(
            $account['account_id'],
            $actorId,
            $role,
            (string) ($payload['label'] ?? ''),
            (string) ($payload['email'] ?? ''),
            (string) ($payload['severity_threshold'] ?? ''),
            $requestId
        )]);
    }
    if ($action === 'set_notification_channel_status') {
        $service->setChannelStatus(
            $account['account_id'],
            $actorId,
            $role,
            (string) ($payload['channel_public_id'] ?? ''),
            (string) ($payload['status'] ?? ''),
            $requestId
        );
        JsonResponse::send(['data' => ['status' => 'updated']]);
    }

    JsonResponse::send([
        'error' => ['code' => 'operations_action_invalid', 'message' => 'The requested operations action is invalid.'],
    ], 422);
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
