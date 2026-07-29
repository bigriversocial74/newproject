<?php

declare(strict_types=1);

use Vp3\Http\AuthEndpoint;
use Vp3\Http\JsonResponse;

$container = require dirname(__DIR__, 3) . '/bootstrap.php';
AuthEndpoint::requireMethod('POST');

try {
    $payload = AuthEndpoint::payload();
    $container['session']->assertCsrf(AuthEndpoint::csrf($payload));
    $current = $container['authentication_context']->requireCurrent(
        AuthEndpoint::ip(),
        AuthEndpoint::userAgent(),
        false
    );
    $result = $container['password_changes']->change(
        $current['user']['id'],
        (string) ($payload['current_password'] ?? ''),
        (string) ($payload['new_password'] ?? ''),
        $current['session']['public_id'],
        AuthEndpoint::ip(),
        AuthEndpoint::userAgent()
    );
    JsonResponse::send(['data' => [
        'status' => 'password_changed',
        'revoked_sessions' => $result['revoked_sessions'],
    ]]);
} catch (Throwable $exception) {
    AuthEndpoint::sendException($exception);
}
