<?php

declare(strict_types=1);

use Vp3\Http\AuthEndpoint;
use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;
use Vp3\Security\SecurityAlertPreferenceService;
use Vp3\Security\SecurityAuditService;
use Vp3\Security\SecurityIncidentResolutionService;
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
    $alerts = new SecurityAlertPreferenceService(
        $container['database'],
        $container['operational_incidents'],
        $audit
    );
    $resolution = new SecurityIncidentResolutionService(
        $container['database'],
        $container['operational_incidents'],
        $reauthentication,
        $audit
    );
    $actorId = (int) $account['user']['id'];
    $role = (string) $account['role'];
    $accountId = (int) $account['account_id'];

    switch ($action) {
        case 'promote_event':
            $data = $response->promoteAuditEvent(
                $accountId,
                $actorId,
                $role,
                (string) ($payload['event_public_id'] ?? ''),
                $requestId
            );
            break;

        case 'assign_case':
            $response->assignCase(
                $accountId,
                $actorId,
                $role,
                (string) ($payload['case_public_id'] ?? ''),
                (string) ($payload['assignee_user_public_id'] ?? ''),
                $requestId
            );
            $data = ['assigned' => true];
            break;

        case 'add_note':
            $data = $response->addEncryptedNote(
                $accountId,
                $actorId,
                $role,
                (string) ($payload['case_public_id'] ?? ''),
                (string) ($payload['note'] ?? ''),
                $requestId
            );
            break;

        case 'save_alert_preferences':
            $data = $alerts->save(
                $accountId,
                $actorId,
                $role,
                (bool) ($payload['automatic_promotion_enabled'] ?? false),
                (string) ($payload['minimum_risk'] ?? 'high'),
                (bool) ($payload['include_integrity_failures'] ?? true),
                (bool) ($payload['notify_on_promotion'] ?? true),
                (bool) ($payload['notify_on_emergency_action'] ?? true),
                $requestId
            );
            break;

        case 'begin_emergency_reauthentication':
            $data = $proof->begin(
                $accountId,
                $actorId,
                $role,
                'security.emergency_revoke_sessions',
                [
                    'target_user_public_id' => trim((string) ($payload['target_user_public_id'] ?? '')),
                    'case_public_id' => isset($payload['case_public_id']) && trim((string) $payload['case_public_id']) !== ''
                        ? trim((string) $payload['case_public_id'])
                        : null,
                ],
                AuthEndpoint::ip(),
                AuthEndpoint::userAgent()
            );
            break;

        case 'complete_emergency_reauthentication':
            $proof->complete(
                $accountId,
                $actorId,
                $role,
                'security.emergency_revoke_sessions',
                [
                    'target_user_public_id' => trim((string) ($payload['target_user_public_id'] ?? '')),
                    'case_public_id' => isset($payload['case_public_id']) && trim((string) $payload['case_public_id']) !== ''
                        ? trim((string) $payload['case_public_id'])
                        : null,
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
            $data = ['satisfied' => true];
            break;

        case 'emergency_revoke_sessions':
            $revokedCount = $response->emergencyRevokeUserSessions(
                $accountId,
                $actorId,
                $role,
                (string) ($payload['target_user_public_id'] ?? ''),
                isset($payload['case_public_id']) ? (string) $payload['case_public_id'] : null,
                (string) ($payload['reauthentication_public_id'] ?? ''),
                $requestId
            );
            $alerts->routeEmergencyAction($accountId, $actorId, $requestId);
            $data = ['revoked_count' => $revokedCount];
            break;

        case 'begin_case_resolution_reauthentication':
            $resolutionSummary = trim((string) ($payload['resolution_summary'] ?? ''));
            $data = $proof->begin(
                $accountId,
                $actorId,
                $role,
                'security.resolve_incident_case',
                [
                    'case_public_id' => trim((string) ($payload['case_public_id'] ?? '')),
                    'resolution_hash' => hash('sha256', $resolutionSummary),
                ],
                AuthEndpoint::ip(),
                AuthEndpoint::userAgent()
            );
            break;

        case 'complete_case_resolution_reauthentication':
            $resolutionSummary = trim((string) ($payload['resolution_summary'] ?? ''));
            $proof->complete(
                $accountId,
                $actorId,
                $role,
                'security.resolve_incident_case',
                [
                    'case_public_id' => trim((string) ($payload['case_public_id'] ?? '')),
                    'resolution_hash' => hash('sha256', $resolutionSummary),
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
            $data = ['satisfied' => true];
            break;

        case 'resolve_case':
            $data = [
                'resolved' => $resolution->resolve(
                    $accountId,
                    $actorId,
                    $role,
                    (string) ($payload['case_public_id'] ?? ''),
                    (string) ($payload['resolution_summary'] ?? ''),
                    (string) ($payload['reauthentication_public_id'] ?? ''),
                    $requestId
                ),
            ];
            break;

        default:
            throw new InvalidArgumentException('A valid security response action is required.');
    }

    JsonResponse::send(['data' => $data]);
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
