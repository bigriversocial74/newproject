<?php

declare(strict_types=1);

use Vp3\Http\HomeServerEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
HomeServerEndpoint::requireMethod('POST');
try {
    $payload = HomeServerEndpoint::payload();
    $metadata = is_array($payload['metadata'] ?? null) ? $payload['metadata'] : [];
    $result = $container['homeserver_control_plane']->recordUpdateReceipt(
        (string) ($payload['device_public_id'] ?? ''),
        HomeServerEndpoint::bearerCredential(),
        HomeServerEndpoint::requestId($payload),
        (string) ($payload['update_id'] ?? ''),
        isset($payload['release_public_id']) ? (string) $payload['release_public_id'] : null,
        (string) ($payload['disposition'] ?? ''),
        isset($payload['failure_code']) ? (string) $payload['failure_code'] : null,
        isset($payload['receipt_hash']) ? strtolower((string) $payload['receipt_hash']) : null,
        $metadata
    );
    JsonResponse::send(['data' => $result], 202);
} catch (Throwable $exception) {
    HomeServerEndpoint::sendException($exception);
}
