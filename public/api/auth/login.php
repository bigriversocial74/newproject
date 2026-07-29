<?php

declare(strict_types=1);

use Vp3\Http\AuthEndpoint;
use Vp3\Http\JsonResponse;

$container = require dirname(__DIR__, 3) . '/bootstrap.php';
AuthEndpoint::requireMethod('POST');

try {
    $payload = AuthEndpoint::payload();
    $ip = AuthEndpoint::ip();
    $userAgent = AuthEndpoint::userAgent();
    $user = $container['auth']->authenticate(
        (string) ($payload['email'] ?? ''),
        (string) ($payload['password'] ?? ''),
        $ip,
        $userAgent
    );
    if ($user === null) {
        JsonResponse::send(['error' => ['code' => 'invalid_credentials', 'message' => 'The email or password is incorrect.']], 401);
    }

    $container['session']->regenerate();
    $applicationSession = $container['database_sessions']->create($user['id'], $ip, $userAgent);
    $container['session']->setApplicationToken($applicationSession['token']);
    unset($applicationSession['token']);

    JsonResponse::send(['data' => [
        'user' => $user,
        'session' => $applicationSession,
        'csrf_token' => $container['session']->csrfToken(),
    ]]);
} catch (Throwable $exception) {
    AuthEndpoint::sendException($exception);
}
