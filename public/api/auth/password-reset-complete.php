<?php

declare(strict_types=1);

use Vp3\Http\JsonResponse;

$container = require dirname(__DIR__, 3) . '/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    JsonResponse::send(['error' => ['code' => 'method_not_allowed', 'message' => 'POST required.']], 405);
}

try {
    $payload = json_decode((string) file_get_contents('php://input'), true, 16, JSON_THROW_ON_ERROR);
    $reset = $container['account_security']->resetPassword(
        (string) ($payload['token'] ?? ''),
        (string) ($payload['password'] ?? '')
    );
    if (!$reset) {
        JsonResponse::send(['error' => ['code' => 'invalid_or_expired_token', 'message' => 'Reset token is invalid or expired.']], 422);
    }
    JsonResponse::send(['data' => ['status' => 'password_reset']], 200);
} catch (JsonException) {
    JsonResponse::send(['error' => ['code' => 'invalid_json', 'message' => 'The request body is not valid JSON.']], 400);
} catch (Throwable $exception) {
    JsonResponse::send(['error' => ['code' => 'password_reset_failed', 'message' => $exception->getMessage()]], 422);
}
