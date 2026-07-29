<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\Http\AuthEndpoint;
use Vp3\Http\JsonResponse;

$container = require dirname(__DIR__, 3) . '/bootstrap.php';
AuthEndpoint::requireMethod('POST');

try {
    $payload = AuthEndpoint::payload();
    $container['session']->assertCsrf(AuthEndpoint::csrf($payload));
    $token = $container['session']->applicationToken();
    if ($token !== '') {
        try {
            $container['database_sessions']->revokeCurrent(
                $token,
                AuthEndpoint::ip(),
                AuthEndpoint::userAgent(),
                'logout'
            );
        } catch (AuthPublicException) {
            // Logout remains idempotent when the database session is already invalid.
        }
    }
    $container['session']->destroy();
    JsonResponse::send(['data' => ['status' => 'logged_out']]);
} catch (Throwable $exception) {
    AuthEndpoint::sendException($exception);
}
