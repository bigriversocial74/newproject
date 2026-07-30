<?php

declare(strict_types=1);

use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
ControlCenterEndpoint::requireMethod('POST');

try {
    $payload = ControlCenterEndpoint::payload();
    $account = ControlCenterEndpoint::accountContext($container, $payload);
    $action = strtolower(trim((string) ($payload['action'] ?? '')));
    $service = $container['domain_registry'];

    $result = match ($action) {
        'availability' => $service->availability((string) ($payload['label'] ?? '')),
        'register' => $service->registerAndActivate(
            $account['account_id'],
            max(0, (int) ($payload['subscription_id'] ?? 0)),
            (string) ($payload['label'] ?? ''),
            ControlCenterEndpoint::requestId($payload),
            ControlCenterEndpoint::idempotencyKey($payload)
        ),
        'activate_reserved' => $service->activateReservedDomain(
            $account['account_id'],
            (string) ($payload['domain_public_id'] ?? ''),
            ControlCenterEndpoint::requestId($payload),
            ControlCenterEndpoint::idempotencyKey($payload)
        ),
        'suspend' => $service->suspendDomain(
            $account['account_id'],
            (string) ($payload['domain_public_id'] ?? ''),
            ControlCenterEndpoint::requestId($payload),
            ControlCenterEndpoint::idempotencyKey($payload),
            (string) ($payload['reason'] ?? '')
        ),
        'release' => (static function () use ($payload, $account, $service): array {
            if (($payload['confirmation'] ?? '') !== 'RELEASE') {
                throw new RuntimeException('Domain release requires the exact confirmation RELEASE.');
            }
            return $service->releaseDomain(
                $account['account_id'],
                (string) ($payload['domain_public_id'] ?? ''),
                ControlCenterEndpoint::requestId($payload),
                ControlCenterEndpoint::idempotencyKey($payload)
            );
        })(),
        default => throw new RuntimeException('The requested Domain action is not supported.'),
    };

    JsonResponse::send(['data' => $result]);
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
