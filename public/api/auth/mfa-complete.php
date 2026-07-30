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
    $requestId = trim((string) ($payload['request_id'] ?? ''));
    if (!preg_match('/^[A-Za-z0-9._:-]{8,64}$/', $requestId)) {
        $requestId = 'MFAREQ-' . strtoupper(bin2hex(random_bytes(10)));
    }
    $challengeToken = trim((string) ($payload['challenge_token'] ?? ''));
    $tokenHash = hash('sha256', $challengeToken);
    $attempt = $container['database']->pdo()->prepare(
        'UPDATE auth_mfa_challenges
         SET attempt_count=attempt_count+1
         WHERE token_hash=:hash AND consumed_at IS NULL AND expires_at>UTC_TIMESTAMP()
           AND attempt_count<max_attempts'
    );
    $attempt->execute(['hash' => $tokenHash]);
    if ($attempt->rowCount() !== 1) {
        throw new AuthPublicException('mfa_challenge_invalid', 'The MFA challenge is invalid, expired, or locked.', 401);
    }

    try {
        $user = $container['mfa']->completeChallenge(
            $challengeToken,
            (string) ($payload['code'] ?? ''),
            $ip,
            $userAgent,
            $requestId
        );
    } catch (AuthPublicException $exception) {
        $container['database']->pdo()->prepare(
            'UPDATE auth_mfa_challenges
             SET consumed_at=CASE WHEN attempt_count>=max_attempts THEN UTC_TIMESTAMP() ELSE consumed_at END
             WHERE token_hash=:hash AND consumed_at IS NULL'
        )->execute(['hash' => $tokenHash]);
        throw $exception;
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
    $container['auth']->completeLogin($user['id'], $user['public_id'], $requestId);

    JsonResponse::send(['data' => [
        'user' => $user,
        'session' => $applicationSession,
        'csrf_token' => $container['session']->csrfToken(),
    ]]);
} catch (Throwable $exception) {
    AuthEndpoint::sendException($exception);
}
