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
    $statement = $container['database']->pdo()->prepare(
        "SELECT a.public_id AS account_public_id,u.public_id AS user_public_id
         FROM accounts a
         JOIN users u ON u.id=:user
         JOIN account_users au ON au.account_id=a.id AND au.user_id=u.id AND au.status='active'
         WHERE a.id=:account
         LIMIT 1"
    );
    $statement->execute(['user' => (int) $result['user_id'], 'account' => (int) $result['account_id']]);
    $identities = $statement->fetch();
    if (!is_array($identities)
        || trim((string) ($identities['account_public_id'] ?? '')) === ''
        || trim((string) ($identities['user_public_id'] ?? '')) === '') {
        throw new RuntimeException('Registration identities are unavailable.');
    }
    JsonResponse::send(['data' => [
        'account_public_id' => (string) $identities['account_public_id'],
        'user_public_id' => (string) $identities['user_public_id'],
        'status' => 'pending_verification',
    ]], 201);
} catch (Throwable $exception) {
    AuthEndpoint::sendException($exception);
}
