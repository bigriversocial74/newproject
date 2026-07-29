<?php

declare(strict_types=1);

use Vp3\Http\AuthEndpoint;
use Vp3\Http\JsonResponse;

$container = require dirname(__DIR__, 3) . '/bootstrap.php';
AuthEndpoint::requireMethod('POST');

try {
    $payload = AuthEndpoint::payload();
    $container['session']->assertCsrf(AuthEndpoint::csrf($payload));
    $rotated = $container['database_sessions']->rotate(
        $container['session']->applicationToken(),
        AuthEndpoint::ip(),
        AuthEndpoint::userAgent()
    );
    $container['session']->regenerate();
    $container['session']->setApplicationToken($rotated['token']);
    unset($rotated['token']);
    JsonResponse::send(['data' => [
        'status' => 'session_rotated',
        'session' => $rotated,
        'csrf_token' => $container['session']->csrfToken(),
    ]]);
} catch (Throwable $exception) {
    AuthEndpoint::sendException($exception);
}
