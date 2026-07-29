<?php

declare(strict_types=1);

use Vp3\Http\AuthEndpoint;
use Vp3\Http\JsonResponse;

$container = require dirname(__DIR__, 3) . '/bootstrap.php';
AuthEndpoint::requireMethod('POST');

try {
    $payload = AuthEndpoint::payload();
    $container['session']->assertCsrf(AuthEndpoint::csrf($payload));
    $current = $container['authentication_context']->requireCurrent(AuthEndpoint::ip(), AuthEndpoint::userAgent(), false);
    $publicId = trim((string) ($payload['session_public_id'] ?? ''));
    if ($publicId === '' || !$container['database_sessions']->revokeSelected(
        $current['user']['id'],
        $publicId,
        AuthEndpoint::ip(),
        AuthEndpoint::userAgent()
    )) {
        JsonResponse::send(['error' => ['code' => 'session_not_found', 'message' => 'The selected session could not be revoked.']], 404);
    }
    if (hash_equals($current['session']['public_id'], $publicId)) {
        $container['session']->destroy();
    }
    JsonResponse::send(['data' => ['status' => 'session_revoked']]);
} catch (Throwable $exception) {
    AuthEndpoint::sendException($exception);
}
