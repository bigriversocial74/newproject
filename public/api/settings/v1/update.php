<?php

declare(strict_types=1);

use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;
use Vp3\Settings\FederatedSettingsControlCenterService;
use Vp3\Settings\FederatedSettingsControlCenterSigner;
use Vp3\Settings\FederatedSettingsService;

$container = require dirname(__DIR__, 4) . '/bootstrap.php';
ControlCenterEndpoint::requireMethod('POST');

try {
    $payload = ControlCenterEndpoint::payload();
    $account = ControlCenterEndpoint::accountContextForRoles(
        $container,
        $payload,
        ['customer_owner', 'customer_admin']
    );
    $service = new FederatedSettingsControlCenterService(
        $container['database'],
        new FederatedSettingsService($container['database'])
    );
    $signer = new FederatedSettingsControlCenterSigner($container['homeserver_lease_signer']);
    JsonResponse::send(['data' => $signer->sign($service->update(
        $account['account_id'],
        (int) $account['user']['id'],
        $account['role'],
        (string) ($payload['setting_key'] ?? ''),
        $payload['value'] ?? null,
        max(0, (int) ($payload['expected_revision'] ?? 0)),
        isset($payload['device_public_id']) ? (string) $payload['device_public_id'] : null,
        ControlCenterEndpoint::requestId($payload)
    ))]);
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
