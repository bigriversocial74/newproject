<?php

declare(strict_types=1);

use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
ControlCenterEndpoint::requireMethod('POST');

try {
    $payload = ControlCenterEndpoint::payload();
    $account = ControlCenterEndpoint::accountContext(
        $container,
        $payload,
        ['customer_owner', 'customer_admin']
    );
    $action = strtolower(trim((string) ($payload['action'] ?? '')));
    $requestId = ControlCenterEndpoint::requestId($payload);
    $event = match ($action) {
        'invite' => 'team.invited',
        'revoke_invitation' => 'team.invitation_revoked',
        'change_role' => 'team.role_changed',
        'set_status' => 'team.status_changed',
        default => throw new RuntimeException('The requested team action is not supported.'),
    };
    $replay = $container['database']->pdo()->prepare(
        'SELECT public_id FROM account_security_receipts
         WHERE account_id=:account AND action=:action AND request_id=:request AND result=\'success\' LIMIT 1'
    );
    $replay->execute(['account' => $account['account_id'], 'action' => $event, 'request' => $requestId]);
    $receipt = $replay->fetchColumn();
    if (is_string($receipt) && $receipt !== '') {
        JsonResponse::send(['data' => ['status' => 'already_completed', 'replayed' => true, 'receipt_public_id' => $receipt]]);
    }

    $service = $container['team_security'];
    if ($action === 'invite') {
        $result = $service->invite(
            $account['account_id'],
            (int) $account['user']['id'],
            $account['role'],
            (string) ($payload['email'] ?? ''),
            (string) ($payload['role'] ?? ''),
            $requestId
        );
        JsonResponse::send(['data' => array_merge($result, ['replayed' => false])], 201);
    }
    if ($action === 'revoke_invitation') {
        $service->revokeInvitation(
            $account['account_id'],
            (int) $account['user']['id'],
            (string) ($payload['invitation_public_id'] ?? ''),
            $requestId
        );
    } elseif ($action === 'change_role') {
        $service->changeRole(
            $account['account_id'],
            (int) $account['user']['id'],
            $account['role'],
            (string) ($payload['member_public_id'] ?? ''),
            (string) ($payload['role'] ?? ''),
            $requestId
        );
    } else {
        $service->setMembershipStatus(
            $account['account_id'],
            (int) $account['user']['id'],
            $account['role'],
            (string) ($payload['member_public_id'] ?? ''),
            (string) ($payload['status'] ?? ''),
            $requestId
        );
    }
    JsonResponse::send(['data' => ['status' => 'completed', 'replayed' => false]]);
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
