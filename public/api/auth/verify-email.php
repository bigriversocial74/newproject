<?php

declare(strict_types=1);

use Vp3\Http\AuthEndpoint;
use Vp3\Http\JsonResponse;

$container = require dirname(__DIR__, 3) . '/bootstrap.php';
AuthEndpoint::requireMethod('POST');

try {
    $payload = AuthEndpoint::payload();
    if (!$container['account_security']->verifyEmail((string) ($payload['token'] ?? ''))) {
        JsonResponse::send(['error' => ['code' => 'invalid_or_expired_token', 'message' => 'Verification token is invalid or expired.']], 422);
    }
    JsonResponse::send(['data' => ['status' => 'verified']]);
} catch (Throwable $exception) {
    AuthEndpoint::sendException($exception);
}
