<?php

declare(strict_types=1);

use Vp3\Deployment\PlatformOperatorAuthorizer;
use Vp3\Deployment\ReleaseDeploymentControlCenterActionService;
use Vp3\Http\AuthEndpoint;
use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;
use Vp3\Security\SecurityAuditService;
use Vp3\Security\SecurityReauthenticationProofService;
use Vp3\Security\SecurityReauthenticationService;

$container = require __DIR__ . '/_bootstrap.php';
ControlCenterEndpoint::requireMethod('POST');

try {
    $payload = ControlCenterEndpoint::payload();
    $account = ControlCenterEndpoint::accountContextForRoles(
        $container,
        $payload,
        ['customer_owner', 'customer_admin']
    );
    $accountId = (int) $account['account_id'];
    $actorId = (int) $account['user']['id'];
    $role = (string) $account['role'];
    $action = strtolower(trim((string) ($payload['action'] ?? '')));
    $requestId = ControlCenterEndpoint::requestId($payload);

    $authorizer = new PlatformOperatorAuthorizer($container['database']);
    $authorizer->assertOperator($accountId, $actorId, $role);
    $audit = new SecurityAuditService($container['database']);
    $reauthentication = new SecurityReauthenticationService($container['database']);
    $proof = new SecurityReauthenticationProofService(
        $container['database'],
        $container['mfa'],
        $reauthentication,
        $audit
    );
    $service = new ReleaseDeploymentControlCenterActionService(
        $container['database'],
        $authorizer,
        $reauthentication
    );

    switch ($action) {
        case 'save_environment':
            $data = $service->saveEnvironment(
                $accountId,
                $actorId,
                $role,
                (string) ($payload['environment_key'] ?? ''),
                (string) ($payload['display_name'] ?? ''),
                (string) ($payload['base_url'] ?? ''),
                (string) ($payload['config_fingerprint'] ?? ''),
                $requestId
            );
            break;

        case 'schedule_maintenance':
            $data = $service->scheduleMaintenanceWindow(
                $accountId,
                $actorId,
                $role,
                (string) ($payload['environment_public_id'] ?? ''),
                (string) ($payload['starts_at'] ?? ''),
                (string) ($payload['ends_at'] ?? ''),
                (string) ($payload['reason'] ?? ''),
                $requestId
            );
            break;

        case 'approve_maintenance':
            $data = $service->approveMaintenanceWindow(
                $accountId,
                $actorId,
                $role,
                (string) ($payload['maintenance_window_public_id'] ?? ''),
                $requestId
            );
            break;

        case 'request_staging_deployment':
            $data = $service->requestStagingDeployment(
                $accountId,
                $actorId,
                $role,
                (string) ($payload['candidate_public_id'] ?? ''),
                (string) ($payload['staging_environment_public_id'] ?? ''),
                $requestId
            );
            break;

        case 'request_promotion':
            $data = $service->requestPromotion(
                $accountId,
                $actorId,
                $role,
                (string) ($payload['candidate_public_id'] ?? ''),
                (string) ($payload['source_environment_public_id'] ?? ''),
                (string) ($payload['target_environment_public_id'] ?? ''),
                (string) ($payload['maintenance_window_public_id'] ?? ''),
                isset($payload['scheduled_for']) ? (string) $payload['scheduled_for'] : null,
                $requestId
            );
            break;

        case 'begin_promotion_reauthentication':
            $context = ['promotion_public_id' => trim((string) ($payload['promotion_public_id'] ?? ''))];
            $data = $proof->begin(
                $accountId,
                $actorId,
                $role,
                'platform.approve_release_promotion',
                $context,
                AuthEndpoint::ip(),
                AuthEndpoint::userAgent()
            );
            break;

        case 'complete_promotion_reauthentication':
            $context = ['promotion_public_id' => trim((string) ($payload['promotion_public_id'] ?? ''))];
            $proof->complete(
                $accountId,
                $actorId,
                $role,
                'platform.approve_release_promotion',
                $context,
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

        case 'approve_promotion':
            $data = $service->approvePromotion(
                $accountId,
                $actorId,
                $role,
                (string) ($payload['promotion_public_id'] ?? ''),
                (string) ($payload['reauthentication_public_id'] ?? ''),
                $requestId
            );
            break;

        case 'cancel_promotion':
            $data = $service->cancelPromotion(
                $accountId,
                $actorId,
                $role,
                (string) ($payload['promotion_public_id'] ?? ''),
                $requestId
            );
            break;

        case 'begin_rollback_reauthentication':
            $context = ['promotion_public_id' => trim((string) ($payload['promotion_public_id'] ?? ''))];
            $data = $proof->begin(
                $accountId,
                $actorId,
                $role,
                'platform.rollback_release',
                $context,
                AuthEndpoint::ip(),
                AuthEndpoint::userAgent()
            );
            break;

        case 'complete_rollback_reauthentication':
            $context = ['promotion_public_id' => trim((string) ($payload['promotion_public_id'] ?? ''))];
            $proof->complete(
                $accountId,
                $actorId,
                $role,
                'platform.rollback_release',
                $context,
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

        case 'queue_rollback':
            $data = $service->queueRollback(
                $accountId,
                $actorId,
                $role,
                (string) ($payload['promotion_public_id'] ?? ''),
                (string) ($payload['reauthentication_public_id'] ?? ''),
                $requestId
            );
            break;

        default:
            throw new InvalidArgumentException('A valid release and deployment action is required.');
    }

    JsonResponse::send(['data' => $data]);
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
