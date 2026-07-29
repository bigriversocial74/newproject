<?php

declare(strict_types=1);

use Vp3\Http\AuthEndpoint;
use Vp3\Http\JsonResponse;

$container = require dirname(__DIR__, 3) . '/bootstrap.php';
AuthEndpoint::requireMethod('POST');

try {
    $payload = AuthEndpoint::payload();
    $container['account_security']->requestPasswordReset((string) ($payload['email'] ?? ''));
    JsonResponse::send(['data' => [
        'status' => 'accepted',
        'message' => 'If the account is eligible, password reset instructions will be sent.',
    ]], 202);
} catch (Throwable $exception) {
    AuthEndpoint::sendException($exception);
}
