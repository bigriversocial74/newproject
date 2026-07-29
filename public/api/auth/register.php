<?php

declare(strict_types=1);

use Vp3\Http\AuthEndpoint;
use Vp3\Http\JsonResponse;

$container = require dirname(__DIR__, 3) . '/bootstrap.php';
AuthEndpoint::requireMethod('POST');

try {
    $payload = AuthEndpoint::payload();
    $result = $container['auth']->register(
        (string) ($payload['email'] ?? ''),
        (string) ($payload['password'] ?? ''),
        (string) ($payload['display_name'] ?? ''),
        AuthEndpoint::ip(),
        AuthEndpoint::userAgent()
    );
    JsonResponse::send(['data' => [
        'account_id' => $result['account_id'],
        'user_id' => $result['user_id'],
        'status' => 'pending_verification',
    ]], 201);
} catch (Throwable $exception) {
    AuthEndpoint::sendException($exception);
}
