<?php

declare(strict_types=1);

use Vp3\Http\HomeServerEndpoint;
use Vp3\Http\JsonResponse;
use Vp3\Settings\FederatedSettingsService;

$container = require __DIR__ . '/_bootstrap.php';
HomeServerEndpoint::requireMethod('POST');

try {
    $payload = HomeServerEndpoint::payload();
    $service = new FederatedSettingsService($container['database']);
    $updates = $payload['updates'] ?? [];
    if (!is_array($updates)) {
        throw new RuntimeException('The settings sync update list is invalid.');
    }
    JsonResponse::send(['data' => $service->synchronizeDevice(
        (string) ($payload['device_public_id'] ?? ''),
        HomeServerEndpoint::bearerCredential(),
        HomeServerEndpoint::requestId($payload),
        max(0, (int) ($payload['base_revision'] ?? 0)),
        $updates
    )]);
} catch (Throwable $exception) {
    HomeServerEndpoint::sendException($exception);
}
