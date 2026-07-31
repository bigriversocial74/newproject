<?php

declare(strict_types=1);

use Vp3\Http\AuthEndpoint;
use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;
use Vp3\Security\SecurityAuditService;
use Vp3\Security\SecurityIncidentResponseService;
use Vp3\Security\SecurityReauthenticationProofService;
use Vp3\Security\SecurityReauthenticationService;

$container = require __DIR__ . '/_bootstrap.php';
ControlCenterEndpoint::requireMethod('POST');

try {
    $payload = ControlCenterEndpoint::payload();
    $account = ControlCenterEndpoint::accountContextForRoles(
        $container,
        $payload,
        ['customer_owner', 'customer_admin', 'support_member']
    );
    $action = strtolower(trim((string) ($payload['action'] ?? '')));
    $requestId = ControlCenterEndpoint::requestId($payload);
    $audit = new SecurityAuditService($container['database']);
    $reauthentication = new SecurityReauthenticationService($container['database']);
    $response = new SecurityIncidentResponseService(
        $container['database'],
        $container['operational_incidents'],
        $container['operations_secret_cipher'],
        $reauthentication,
        $audit
    );
    $proof = new SecurityReauthenticationProofService(
        $container['database'],
        $container['mfa'],
        $reauthentication,
        $audit
    );
    $actorId = (int) $account['user']['id'];
    $role = (string) $account['role'];

    $data = match ($action) {
        'promote_event' => $response->promoteAuditEvent(
            $account['account_id'],
            $actorId,
            $role,
            (string) ($payload['event_public_id'] ?? ''),
            $requestId
        ),
        'assign_case' => (function () use ($response, $account, $actorId, $role, $payload, $requestId): array {
            $response->assignCase(
                $account['account_id'],
                $actorId,
                $role,
                (string) ($payload['case_public_id'] ?? ''),
                (string) ($payload['assignee_user_public_id'] ?? ''),
                $requestId
            );
            return ['assigned' => true];
        })(),
        'add_note' => $response->addEncryptedNote(
            $account['account_id'],
            $actorId,
            $role,
            (string) ($payload['case_public_id'] ?? ''),
            (string) ($payload['note'] ?? ''),
            $requestId
        ),
        'begin_emergency_reauthentication' => $proof->begin(
            $account['account_id'],
            $actorId,
            $role,
            'security.emergency_revoke_sessions',
            [
                'target_user_public_id' => trim((string) ($payload['target_user_public_id'] ?? '')),
                'case_public_id' => isset($payload['case_public_id']) ? trim((string) $payload['case_public_id']) : null,
            ],
            AuthEndpoint::ip(),
            AuthEndpoint::userAgent()
        ),
        'complete_emergency_reauthentication' => (function () use ($proof, $account, $actorId, $role, $payload, $requestId): array {
            $proof->complete(
                $account['account_id'],
                $actorId,
                $role,
                'security.emergency_revoke_sessions',
                [
                    'target_user_public_id' => trim((string) ($payload['target_user_public_id'] ?? '')),
                    'case_public_id' => isset($payload['case_public_id']) ? trim((string) $payload['case_public_id']) : null,
                ],
                (string) ($payload['reauthentication_public_id'] ?? ''),
                (string) ($payload['challenge'] ?? ''),
                (string) ($payload['current_password'] ?? ''),
                isset($payload['mfa_challenge_token']) ? (string) $payload['mfa_challenge_token'] : null,
                isset($payload['mfa_code']) ? (string) $payload['mfa_code'] : null,
                AuthEndpoint::ip(),
                AuthEndpoint::userAgent(),
                $requestId
            );
            return ['satisfied' => true];
        })(),
        'emergency_revoke_sessions' => [
            'revoked_count' => $response->emergencyRevokeUserSessions(
                $account['account_id'],
                $actorId,
                $role,
                (string) ($payload['target_user_public_id'] ?? ''),
                isset($payload['case_public_id']) ? (string) $payload['case_public_id'] : null,
                (string) ($payload['reauthentication_public_id'] ?? ''),
                $requestId
            ),
        ],
        default => throw new InvalidArgumentException('A valid security response action is required.'),
    };

    JsonResponse::send(['data' => $data]);
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
