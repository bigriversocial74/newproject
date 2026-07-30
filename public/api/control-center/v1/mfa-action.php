<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
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
    $action = strtolower(trim((string) ($payload['action'] ?? '')));
    $requestId = ControlCenterEndpoint::requestId($payload);
    $user = $account['user'];
    if ($action === 'begin') {
        if ($container['mfa']->status((int) $user['id'])['enabled']) {
            throw new AuthPublicException('mfa_already_enabled', 'Disable the current MFA method before starting a new enrollment.', 409);
        }
        JsonResponse::send(['data' => $container['mfa']->beginEnrollment(
            (int) $user['id'],
            (string) $user['email'],
            (string) $user['display_name'],
            $requestId
        )]);
    }
    if ($action === 'confirm') {
        JsonResponse::send(['data' => $container['mfa']->confirmEnrollment(
            (int) $user['id'],
            (string) ($payload['code'] ?? ''),
            $requestId
        )]);
    }
    if ($action === 'disable') {
        $container['mfa']->disable(
            (int) $user['id'],
            (string) ($payload['password'] ?? ''),
            $requestId
        );
        JsonResponse::send(['data' => ['enabled' => false]]);
    }
    throw new RuntimeException('The requested MFA action is not supported.');
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
