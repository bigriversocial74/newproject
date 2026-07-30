<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
ControlCenterEndpoint::requireMethod('POST');

try {
    $payload = ControlCenterEndpoint::payload();
    $account = ControlCenterEndpoint::accountContextForRoles(
        $container,
        $payload,
        ['customer_owner', 'customer_admin', 'billing_manager', 'support_member']
    );
    $requestId = ControlCenterEndpoint::requestId($payload);
    $displayName = trim((string) ($payload['display_name'] ?? ''));
    $password = (string) ($payload['current_password'] ?? '');
    if ($displayName === '' || mb_strlen($displayName) > 190) {
        throw new AuthPublicException('profile_display_name_invalid', 'A valid display name is required.', 422);
    }
    $userId = (int) $account['user']['id'];
    $container['database']->transaction(function (PDO $pdo) use ($container, $account, $requestId, $displayName, $password, $userId): void {
        $statement = $pdo->prepare('SELECT password_hash,public_id FROM users WHERE id=:user AND status=\'active\' LIMIT 1 FOR UPDATE');
        $statement->execute(['user' => $userId]);
        $user = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($user) || !password_verify($password, (string) $user['password_hash'])) {
            throw new AuthPublicException('password_invalid', 'The current password is incorrect.', 403);
        }
        $pdo->prepare('UPDATE users SET display_name=:name,updated_at=UTC_TIMESTAMP() WHERE id=:user')
            ->execute(['name' => $displayName, 'user' => $userId]);
        $evidence = ['action' => 'profile.display_name_changed', 'account_id' => $account['account_id'], 'actor_user_id' => $userId, 'display_name_hash' => hash('sha256', $displayName)];
        $pdo->prepare('INSERT INTO account_security_receipts (public_id,account_id,actor_user_id,target_user_id,action,result,request_id,evidence_hash,created_at) VALUES (:public,:account,:actor,:target,\'profile.display_name_changed\',\'success\',:request,:hash,UTC_TIMESTAMP())')
            ->execute(['public' => 'SEC-' . strtoupper(bin2hex(random_bytes(10))), 'account' => $account['account_id'], 'actor' => $userId, 'target' => $userId, 'request' => $requestId, 'hash' => hash('sha256', json_encode($evidence, JSON_THROW_ON_ERROR))]);
        $container['auth_audit']->record('profile.display_name_changed', 'success', $userId, $account['account_id'], 'user', (string) $user['public_id'], ['display_name_hash' => hash('sha256', $displayName)], $requestId);
    });
    JsonResponse::send(['data' => ['display_name' => $displayName]]);
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
