<?php

declare(strict_types=1);

use Vp3\Http\AuthEndpoint;
use Vp3\Http\JsonResponse;

$container = require dirname(__DIR__, 3) . '/bootstrap.php';
AuthEndpoint::requireMethod('POST');

try {
    $payload = AuthEndpoint::payload();
    $container['account_security']->resendVerification((string) ($payload['email'] ?? ''));
    JsonResponse::send(['data' => [
        'status' => 'accepted',
        'message' => 'If verification is still required, a new email will be sent.',
    ]], 202);
} catch (Throwable $exception) {
    AuthEndpoint::sendException($exception);
}
