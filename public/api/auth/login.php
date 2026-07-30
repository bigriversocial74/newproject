<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
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
        $userAgent,
        true
    );
    if ($user === null) {
        JsonResponse::send(['error' => ['code' => 'invalid_credentials', 'message' => 'The email or password is incorrect.']], 401);
    }

    if ($container['mfa']->requiresMfa($user['id'])) {
        $challenge = $container['mfa']->createChallenge($user['id'], $ip, $userAgent);
        JsonResponse::send(['data' => [
            'mfa_required' => true,
            'challenge_token' => $challenge['challenge_token'],
            'challenge_public_id' => $challenge['challenge_public_id'],
            'expires_at' => $challenge['expires_at'],
        ]], 202);
    }

    $existingToken = $container['session']->applicationToken();
    if ($existingToken !== '') {
        try {
            $container['database_sessions']->revokeCurrent($existingToken, $ip, $userAgent, 'reauthenticated');
        } catch (AuthPublicException) {
            // An invalid or expired prior browser token is replaced below.
        }
        $container['session']->clearApplicationToken();
    }

    $container['session']->regenerate();
    $applicationSession = $container['database_sessions']->create($user['id'], $ip, $userAgent);
    $container['session']->setApplicationToken($applicationSession['token']);
    unset($applicationSession['token']);
    $container['auth']->completeLogin($user['id'], $user['public_id']);

    JsonResponse::send(['data' => [
        'mfa_required' => false,
        'user' => $user,
        'session' => $applicationSession,
        'csrf_token' => $container['session']->csrfToken(),
    ]]);
} catch (Throwable $exception) {
    AuthEndpoint::sendException($exception);
}
