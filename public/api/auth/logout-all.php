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
    $revoked = $container['database_sessions']->revokeAllForUser($current['user']['id'], 'logout_all');
    $container['session']->destroy();
    JsonResponse::send(['data' => ['status' => 'logged_out', 'revoked_sessions' => $revoked]]);
} catch (Throwable $exception) {
    AuthEndpoint::sendException($exception);
}
