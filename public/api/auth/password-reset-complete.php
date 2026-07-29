<?php

declare(strict_types=1);

use Vp3\Http\AuthEndpoint;
use Vp3\Http\JsonResponse;

$container = require dirname(__DIR__, 3) . '/bootstrap.php';
AuthEndpoint::requireMethod('POST');

try {
    $payload = AuthEndpoint::payload();
    if (!$container['account_security']->resetPassword(
        (string) ($payload['token'] ?? ''),
        (string) ($payload['password'] ?? '')
    )) {
        JsonResponse::send(['error' => ['code' => 'invalid_or_expired_token', 'message' => 'Reset token is invalid or expired.']], 422);
    }
    $container['session']->destroy();
    JsonResponse::send(['data' => ['status' => 'password_reset']]);
} catch (Throwable $exception) {
    AuthEndpoint::sendException($exception);
}
