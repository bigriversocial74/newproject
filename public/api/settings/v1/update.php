<?php

declare(strict_types=1);

use Vp3\Http\HomeServerEndpoint;
use Vp3\Http\JsonResponse;
use Vp3\Settings\FederatedSettingsService;

$container = require dirname(__DIR__, 4) . '/bootstrap.php';
HomeServerEndpoint::requireMethod('POST');

try {
    $payload = HomeServerEndpoint::payload();
    $account = HomeServerEndpoint::accountContext($container, $payload);
    $service = new FederatedSettingsService($container['database']);
    JsonResponse::send(['data' => $service->updateFromBrowser(
        $account['account_id'],
        (int) $account['user']['id'],
        (string) ($payload['setting_key'] ?? ''),
        $payload['value'] ?? null,
        max(0, (int) ($payload['expected_revision'] ?? 0)),
        isset($payload['device_public_id']) ? (string) $payload['device_public_id'] : null
    )]);
} catch (Throwable $exception) {
    HomeServerEndpoint::sendException($exception);
}
