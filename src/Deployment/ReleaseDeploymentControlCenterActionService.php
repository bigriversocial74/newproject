<?php

declare(strict_types=1);

namespace Vp3\Deployment;

use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;
use PDO;
use RuntimeException;
use Vp3\Database;
use Vp3\Security\SecurityReauthenticationService;

final class ReleaseDeploymentControlCenterActionService
{
    public function __construct(
        private readonly Database $database,
        private readonly PlatformOperatorAuthorizer $authorizer,
        private readonly SecurityReauthenticationService $reauthentication
    ) {
    }

    /** @return array<string,mixed> */
    public function saveEnvironment(
        int $accountId,
        int $actorUserId,
        string $role,
        string $environmentKey,
        string $displayName,
        string $baseUrl,
        string $configFingerprint,
        string $requestId
    ): array {
        $environmentKey = strtolower(trim($environmentKey));
        $this->authorizer->assertOperator($accountId, $actorUserId, $role, $environmentKey === 'production');
        $displayName = trim($displayName);
        $baseUrl = rtrim(trim($baseUrl), '/');
        $configFingerprint = strtolower(trim($configFingerprint));
        $requestId = $this->requestId($requestId);
        if (!in_array($environmentKey, ['staging', 'production'], true)) {
            throw new InvalidArgumentException('A staging or production environment is required.');
        }
        if ($displayName === '' || mb_strlen($displayName) > 120) {
            throw new InvalidArgumentException('The environment display name is invalid.');
        }
        $parts = parse_url($baseUrl);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])
            || strtolower((string) $parts['scheme']) !== 'https'
            || isset($parts['user'], $parts['pass'], $parts['query'], $parts['fragment'])
            || (($parts['path'] ?? '') !== '' && ($parts['path'] ?? '') !== '/')) {
            throw new InvalidArgumentException('A canonical HTTPS environment origin is required.');
        }
        if (!preg_match('/^[a-f0-9]{64}$/', $configFingerprint)) {
            throw new InvalidArgumentException('The environment configuration fingerprint must be SHA-256.');
        }
        $evidence = hash('sha256', implode('|', [$environmentKey, $displayName, $baseUrl, $configFingerprint]));

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $actorUserId,
            $environmentKey,
            $displayName,
            $baseUrl,
            $configFingerprint,
            $requestId,
            $evidence
        ): array {
            $prior = $this->priorReceipt($pdo, $accountId, $requestId, 'save_environment', $evidence);
            if ($prior !== null) {
                return $this->environmentByKey($pdo, $environmentKey);
            }
            $now = $this->now();
            $existing = $pdo->prepare('SELECT id FROM platform_deployment_environments WHERE environment_key=:environment_key LIMIT 1 FOR UPDATE');
            $existing->execute(['environment_key' => $environmentKey]);
            $id = $existing->fetchColumn();
            if ($id !== false) {
                $pdo->prepare(
                    'UPDATE platform_deployment_environments
                     SET display_name=:display_name,base_url=:base_url,config_fingerprint=:fingerprint,
                         readiness_status=\'unknown\',readiness_evidence_hash=NULL,updated_at=:updated_at WHERE id=:id'
                )->execute([
                    'display_name' => $displayName,
                    'base_url' => $baseUrl,
                    'fingerprint' => $configFingerprint,
                    'updated_at' => $now,
                    'id' => (int) $id,
                ]);
            } else {
                $pdo->prepare(
                    "INSERT INTO platform_deployment_environments
                     (public_id,environment_key,display_name,base_url,environment_status,readiness_status,
                      current_candidate_id,config_fingerprint,readiness_evidence_hash,worker_id_hash,
                      worker_last_seen_at,last_health_at,created_by_user_id,created_at,updated_at)
                     VALUES (:public_id,:environment_key,:display_name,:base_url,'active','unknown',
                      NULL,:fingerprint,NULL,NULL,NULL,NULL,:actor,:created_at,:updated_at)"
                )->execute([
                    'public_id' => 'PENV-' . strtoupper(bin2hex(random_bytes(10))),
                    'environment_key' => $environmentKey,
                    'display_name' => $displayName,
                    'base_url' => $baseUrl,
                    'fingerprint' => $configFingerprint,
                    'actor' => $actorUserId,
                    'created_at' => $now,
                    'updated_at' => $now,
                ]);
            }
            $this->receipt($pdo, $accountId, null, $requestId, 'save_environment', 'success', $evidence);
            return $this->environmentByKey($pdo, $environmentKey);
        });
    }

    /** @return array<string,mixed> */
    public function scheduleMaintenanceWindow(
        int $accountId,
        int $actorUserId,
        string $role,
        string $environmentPublicId,
        string $startsAt,
        string $endsAt,
        string $reason,
        string $requestId
    ): array {
        $this->authorizer->assertOperator($accountId, $actorUserId, $role);
        $requestId = $this->requestId($requestId);
        $start = $this->utcDate($startsAt);
        $end = $this->utcDate($endsAt);
        $reason = trim($reason);
        if ($end <= $start || $start < new DateTimeImmutable('-5 minutes', new DateTimeZone('UTC'))
            || $end->getTimestamp() - $start->getTimestamp() > 21600) {
            throw new InvalidArgumentException('The maintenance window must be future-facing and no longer than six hours.');
        }
        if ($reason === '' || mb_strlen($reason) > 500) {
            throw new InvalidArgumentException('A bounded maintenance reason is required.');
        }
        $evidence = hash('sha256', implode('|', [$environmentPublicId, $start->format('c'), $end->format('c'), $reason]));

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $actorUserId,
            $role,
            $environmentPublicId,
            $start,
            $end,
            $reason,
            $requestId,
            $evidence
        ): array {
            $prior = $this->priorReceipt($pdo, $accountId, $requestId, 'schedule_maintenance', $evidence);
            if ($prior !== null) {
                return $this->windowByRequest($pdo, $accountId, $requestId);
            }
            $environment = $this->environmentByPublicId($pdo, $environmentPublicId, true);
            if (!hash_equals('production', (string) $environment['environment_key'])) {
                throw new RuntimeException('Maintenance windows are reserved for the production environment.');
            }
            $overlap = $pdo->prepare(
                "SELECT COUNT(*) FROM platform_maintenance_windows
                 WHERE environment_id=:environment_id AND window_status IN ('scheduled','open')
                   AND starts_at<:ends_at AND ends_at>:starts_at"
            );
            $overlap->execute([
                'environment_id' => (int) $environment['id'],
                'ends_at' => $end->format('Y-m-d H:i:s') . '.000000',
                'starts_at' => $start->format('Y-m-d H:i:s') . '.000000',
            ]);
            if ((int) $overlap->fetchColumn() > 0) {
                throw new RuntimeException('The maintenance window overlaps an active or scheduled window.');
            }
            $now = $this->now();
            $approvedBy = $role === 'customer_owner' ? $actorUserId : null;
            $publicId = 'PMW-' . strtoupper(bin2hex(random_bytes(10)));
            $pdo->prepare(
                "INSERT INTO platform_maintenance_windows
                 (public_id,environment_id,account_scope,request_id,window_status,starts_at,ends_at,reason,
                  created_by_user_id,approved_by_user_id,created_at,updated_at)
                 VALUES (:public_id,:environment_id,:account_scope,:request_id,'scheduled',:starts_at,:ends_at,:reason,
                  :created_by,:approved_by,:created_at,:updated_at)"
            )->execute([
                'public_id' => $publicId,
                'environment_id' => (int) $environment['id'],
                'account_scope' => $accountId,
                'request_id' => $requestId,
                'starts_at' => $start->format('Y-m-d H:i:s') . '.000000',
                'ends_at' => $end->format('Y-m-d H:i:s') . '.000000',
                'reason' => $reason,
                'created_by' => $actorUserId,
                'approved_by' => $approvedBy,
                'created_at' => $now,
                'updated_at' => $now,
            ]);
            $this->receipt($pdo, $accountId, null, $requestId, 'schedule_maintenance', 'success', $evidence);
            return $this->windowByPublicId($pdo, $accountId, $publicId);
        });
    }

    /** @return array<string,mixed> */
    public function approveMaintenanceWindow(
        int $accountId,
        int $actorUserId,
        string $role,
        string $windowPublicId,
        string $requestId
    ): array {
        $this->authorizer->assertOperator($accountId, $actorUserId, $role, true);
        $requestId = $this->requestId($requestId);
        $evidence = hash('sha256', trim($windowPublicId));
        return $this->database->transaction(function (PDO $pdo) use ($accountId, $actorUserId, $windowPublicId, $requestId, $evidence): array {
            $prior = $this->priorReceipt($pdo, $accountId, $requestId, 'approve_maintenance', $evidence);
            if ($prior !== null) {
                return $this->windowByPublicId($pdo, $accountId, $windowPublicId);
            }
            $window = $this->windowByPublicId($pdo, $accountId, $windowPublicId, true);
            if (!in_array((string) $window['window_status'], ['scheduled', 'open'], true)) {
                throw new RuntimeException('Only an active or scheduled maintenance window can be approved.');
            }
            $pdo->prepare('UPDATE platform_maintenance_windows SET approved_by_user_id=:actor,updated_at=:updated_at WHERE id=:id')
                ->execute(['actor' => $actorUserId, 'updated_at' => $this->now(), 'id' => (int) $window['id']]);
            $this->receipt($pdo, $accountId, null, $requestId, 'approve_maintenance', 'success', $evidence);
            return $this->windowByPublicId($pdo, $accountId, $windowPublicId);
        });
    }

    /** @return array<string,mixed> */
    public function requestStagingDeployment(
        int $accountId,
        int $actorUserId,
        string $role,
        string $candidatePublicId,
        string $stagingEnvironmentPublicId,
        string $requestId
    ): array {
        $this->authorizer->assertOperator($accountId, $actorUserId, $role);
        $requestId = $this->requestId($requestId);
        $evidence = hash('sha256', implode('|', [$candidatePublicId, $stagingEnvironmentPublicId, 'staging']));

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $actorUserId,
            $candidatePublicId,
            $stagingEnvironmentPublicId,
            $requestId,
            $evidence
        ): array {
            $prior = $this->priorReceipt($pdo, $accountId, $requestId, 'request_staging_deployment', $evidence);
            if ($prior !== null) {
                return $this->promotionByRequest($pdo, $accountId, $requestId);
            }
            $candidate = $this->candidateByPublicId($pdo, $candidatePublicId, true);
            if (!in_array((string) $candidate['candidate_status'], ['verified', 'approved', 'promoted'], true)) {
                throw new RuntimeException('Only a verified release candidate can be deployed to staging.');
            }
            $staging = $this->environmentByPublicId($pdo, $stagingEnvironmentPublicId, true);
            if (!hash_equals('staging', (string) $staging['environment_key'])
                || !hash_equals('active', (string) $staging['environment_status'])) {
                throw new RuntimeException('An active staging environment is required.');
            }
            $duplicate = $pdo->prepare(
                "SELECT COUNT(*) FROM platform_release_promotions
                 WHERE target_environment_id=:environment_id
                   AND promotion_status IN ('requested','approved','scheduled','queued','deploying','rollback_queued','rolling_back')"
            );
            $duplicate->execute(['environment_id' => (int) $staging['id']]);
            if ((int) $duplicate->fetchColumn() > 0) {
                throw new RuntimeException('The staging environment already has an active deployment or rollback.');
            }
            $now = $this->now();
            $publicId = 'PPR-' . strtoupper(bin2hex(random_bytes(12)));
            $pdo->prepare(
                "INSERT INTO platform_release_promotions
                 (public_id,account_scope,release_candidate_id,previous_candidate_id,source_environment_id,target_environment_id,
                  maintenance_window_id,deployment_run_public_id,backup_public_id,request_id,promotion_status,requested_by_user_id,
                  approved_by_user_id,scheduled_for,backup_required,health_required,failure_code,evidence_hash,
                  requested_at,approved_at,started_at,finished_at,created_at,updated_at)
                 VALUES (:public_id,:account_scope,:candidate_id,:previous_candidate_id,:source_environment_id,:target_environment_id,
                  NULL,NULL,NULL,:request_id,'queued',:requested_by,:approved_by,NULL,1,1,NULL,NULL,
                  :requested_at,:approved_at,NULL,NULL,:created_at,:updated_at)"
            )->execute([
                'public_id' => $publicId,
                'account_scope' => $accountId,
                'candidate_id' => (int) $candidate['id'],
                'previous_candidate_id' => $staging['current_candidate_id'] === null ? null : (int) $staging['current_candidate_id'],
                'source_environment_id' => (int) $staging['id'],
                'target_environment_id' => (int) $staging['id'],
                'request_id' => $requestId,
                'requested_by' => $actorUserId,
                'approved_by' => $actorUserId,
                'requested_at' => $now,
                'approved_at' => $now,
                'created_at' => $now,
                'updated_at' => $now,
            ]);
            $promotionId = (int) $pdo->lastInsertId();
            $this->appendEvent($pdo, $promotionId, 'staging.deployment.queued', $actorUserId, 'success', $evidence);
            $this->receipt($pdo, $accountId, $promotionId, $requestId, 'request_staging_deployment', 'success', $evidence);
            return $this->promotionById($pdo, $promotionId);
        });
    }

    /** @return array<string,mixed> */
    public function requestPromotion(
        int $accountId,
        int $actorUserId,
        string $role,
        string $candidatePublicId,
        string $sourceEnvironmentPublicId,
        string $targetEnvironmentPublicId,
        string $maintenanceWindowPublicId,
        ?string $scheduledFor,
        string $requestId
    ): array {
        $this->authorizer->assertOperator($accountId, $actorUserId, $role);
        $requestId = $this->requestId($requestId);
        $scheduled = $scheduledFor === null || trim($scheduledFor) === '' ? null : $this->utcDate($scheduledFor);
        $evidence = hash('sha256', implode('|', [
            $candidatePublicId,
            $sourceEnvironmentPublicId,
            $targetEnvironmentPublicId,
            $maintenanceWindowPublicId,
            $scheduled?->format('c') ?? '',
        ]));

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $actorUserId,
            $candidatePublicId,
            $sourceEnvironmentPublicId,
            $targetEnvironmentPublicId,
            $maintenanceWindowPublicId,
            $scheduled,
            $requestId,
            $evidence
        ): array {
            $prior = $this->priorReceipt($pdo, $accountId, $requestId, 'request_promotion', $evidence);
            if ($prior !== null) {
                return $this->promotionByRequest($pdo, $accountId, $requestId);
            }
            $candidate = $this->candidateByPublicId($pdo, $candidatePublicId, true);
            if (!in_array((string) $candidate['candidate_status'], ['verified', 'approved', 'promoted'], true)) {
                throw new RuntimeException('Only a verified release candidate can be promoted.');
            }
            $source = $this->environmentByPublicId($pdo, $sourceEnvironmentPublicId, true);
            $target = $this->environmentByPublicId($pdo, $targetEnvironmentPublicId, true);
            if ((int) $source['id'] === (int) $target['id']
                || !hash_equals('staging', (string) $source['environment_key'])
                || !hash_equals('production', (string) $target['environment_key'])) {
                throw new RuntimeException('Platform releases must be promoted from staging to production.');
            }
            if (!hash_equals('ready', (string) $source['readiness_status'])
                || !hash_equals('ready', (string) $target['readiness_status'])
                || (int) ($source['current_candidate_id'] ?? 0) !== (int) $candidate['id']) {
                throw new RuntimeException('Staging and production readiness must be current, and staging must run the selected candidate.');
            }
            $window = $this->windowByPublicId($pdo, $accountId, $maintenanceWindowPublicId, true);
            if ((int) $window['environment_id'] !== (int) $target['id']
                || $window['approved_by_user_id'] === null
                || !in_array((string) $window['window_status'], ['scheduled', 'open'], true)) {
                throw new RuntimeException('An owner-approved production maintenance window is required.');
            }
            $scheduledAt = $scheduled?->format('Y-m-d H:i:s') . ($scheduled === null ? '' : '.000000');
            if ($scheduled !== null) {
                $windowStart = new DateTimeImmutable((string) $window['starts_at'], new DateTimeZone('UTC'));
                $windowEnd = new DateTimeImmutable((string) $window['ends_at'], new DateTimeZone('UTC'));
                if ($scheduled < $windowStart || $scheduled >= $windowEnd) {
                    throw new RuntimeException('The scheduled promotion time must be inside the maintenance window.');
                }
            }
            $duplicate = $pdo->prepare(
                "SELECT COUNT(*) FROM platform_release_promotions
                 WHERE target_environment_id=:target_id
                   AND promotion_status IN ('requested','approved','scheduled','queued','deploying','rollback_queued','rolling_back')"
            );
            $duplicate->execute(['target_id' => (int) $target['id']]);
            if ((int) $duplicate->fetchColumn() > 0) {
                throw new RuntimeException('The production environment already has an active promotion or rollback.');
            }
            $now = $this->now();
            $publicId = 'PPR-' . strtoupper(bin2hex(random_bytes(12)));
            $pdo->prepare(
                "INSERT INTO platform_release_promotions
                 (public_id,account_scope,release_candidate_id,previous_candidate_id,source_environment_id,target_environment_id,
                  maintenance_window_id,deployment_run_public_id,backup_public_id,request_id,promotion_status,requested_by_user_id,
                  approved_by_user_id,scheduled_for,backup_required,health_required,failure_code,evidence_hash,
                  requested_at,approved_at,started_at,finished_at,created_at,updated_at)
                 VALUES (:public_id,:account_scope,:candidate_id,:previous_candidate_id,:source_id,:target_id,:window_id,NULL,NULL,:request_id,
                  'requested',:requested_by,NULL,:scheduled_for,1,1,NULL,NULL,:requested_at,NULL,NULL,NULL,:created_at,:updated_at)"
            )->execute([
                'public_id' => $publicId,
                'account_scope' => $accountId,
                'candidate_id' => (int) $candidate['id'],
                'previous_candidate_id' => $target['current_candidate_id'] === null ? null : (int) $target['current_candidate_id'],
                'source_id' => (int) $source['id'],
                'target_id' => (int) $target['id'],
                'window_id' => (int) $window['id'],
                'request_id' => $requestId,
                'requested_by' => $actorUserId,
                'scheduled_for' => $scheduledAt === '' ? null : $scheduledAt,
                'requested_at' => $now,
                'created_at' => $now,
                'updated_at' => $now,
            ]);
            $promotionId = (int) $pdo->lastInsertId();
            $this->appendEvent($pdo, $promotionId, 'promotion.requested', $actorUserId, 'success', $evidence);
            $this->receipt($pdo, $accountId, $promotionId, $requestId, 'request_promotion', 'success', $evidence);
            return $this->promotionById($pdo, $promotionId);
        });
    }

    /** @return array<string,mixed> */
    public function approvePromotion(
        int $accountId,
        int $actorUserId,
        string $role,
        string $promotionPublicId,
        string $reauthenticationPublicId,
        string $requestId
    ): array {
        $this->authorizer->assertOperator($accountId, $actorUserId, $role, true);
        $requestId = $this->requestId($requestId);
        $context = ['promotion_public_id' => trim($promotionPublicId)];
        $evidence = hash('sha256', implode('|', [$promotionPublicId, $reauthenticationPublicId]));
        return $this->database->transaction(function (PDO $pdo) use ($accountId, $actorUserId, $promotionPublicId, $reauthenticationPublicId, $requestId, $context, $evidence): array {
            $prior = $this->priorReceipt($pdo, $accountId, $requestId, 'approve_promotion', $evidence);
            if ($prior !== null) {
                return $this->promotionByPublicId($pdo, $accountId, $promotionPublicId);
            }
            $promotion = $this->promotionByPublicId($pdo, $accountId, $promotionPublicId, true);
            if (!hash_equals('requested', (string) $promotion['promotion_status'])) {
                throw new RuntimeException('Only a requested promotion can be approved.');
            }
            if ((int) $promotion['requested_by_user_id'] === $actorUserId) {
                throw new RuntimeException('Production promotion approval requires a second platform owner.');
            }
            $source = $this->environmentById($pdo, (int) $promotion['source_environment_id'], true);
            $target = $this->environmentById($pdo, (int) $promotion['target_environment_id'], true);
            $window = $promotion['maintenance_window_id'] === null
                ? null
                : $this->windowById($pdo, $accountId, (int) $promotion['maintenance_window_id'], true);
            if (!hash_equals('staging', (string) $source['environment_key'])
                || !hash_equals('production', (string) $target['environment_key'])
                || !hash_equals('ready', (string) $source['readiness_status'])
                || !hash_equals('ready', (string) $target['readiness_status'])
                || (int) ($source['current_candidate_id'] ?? 0) !== (int) $promotion['release_candidate_id']
                || !is_array($window)
                || $window['approved_by_user_id'] === null
                || !in_array((string) $window['window_status'], ['scheduled', 'open'], true)) {
                throw new RuntimeException('The staging, production, or maintenance approval state changed before promotion approval.');
            }
            $this->reauthentication->consume(
                trim($reauthenticationPublicId),
                $accountId,
                $actorUserId,
                'platform.approve_release_promotion',
                $context
            );
            $status = $promotion['scheduled_for'] === null ? 'queued' : 'scheduled';
            $now = $this->now();
            $pdo->prepare(
                'UPDATE platform_release_promotions
                 SET promotion_status=:status,approved_by_user_id=:actor,approved_at=:approved_at,updated_at=:updated_at
                 WHERE id=:id'
            )->execute([
                'status' => $status,
                'actor' => $actorUserId,
                'approved_at' => $now,
                'updated_at' => $now,
                'id' => (int) $promotion['id'],
            ]);
            $this->appendEvent($pdo, (int) $promotion['id'], 'promotion.approved', $actorUserId, 'success', $evidence);
            $this->receipt($pdo, $accountId, (int) $promotion['id'], $requestId, 'approve_promotion', 'success', $evidence);
            return $this->promotionById($pdo, (int) $promotion['id']);
        });
    }

    /** @return array<string,mixed> */
    public function cancelPromotion(
        int $accountId,
        int $actorUserId,
        string $role,
        string $promotionPublicId,
        string $requestId
    ): array {
        $this->authorizer->assertOperator($accountId, $actorUserId, $role);
        $requestId = $this->requestId($requestId);
        $evidence = hash('sha256', trim($promotionPublicId));
        return $this->database->transaction(function (PDO $pdo) use ($accountId, $actorUserId, $promotionPublicId, $requestId, $evidence): array {
            $prior = $this->priorReceipt($pdo, $accountId, $requestId, 'cancel_promotion', $evidence);
            if ($prior !== null) {
                return $this->promotionByPublicId($pdo, $accountId, $promotionPublicId);
            }
            $promotion = $this->promotionByPublicId($pdo, $accountId, $promotionPublicId, true);
            if (!in_array((string) $promotion['promotion_status'], ['requested', 'approved', 'scheduled', 'queued'], true)) {
                throw new RuntimeException('This promotion can no longer be cancelled.');
            }
            $pdo->prepare("UPDATE platform_release_promotions SET promotion_status='cancelled',finished_at=:finished_at,updated_at=:updated_at WHERE id=:id")
                ->execute(['finished_at' => $this->now(), 'updated_at' => $this->now(), 'id' => (int) $promotion['id']]);
            $this->appendEvent($pdo, (int) $promotion['id'], 'promotion.cancelled', $actorUserId, 'success', $evidence);
            $this->receipt($pdo, $accountId, (int) $promotion['id'], $requestId, 'cancel_promotion', 'success', $evidence);
            return $this->promotionById($pdo, (int) $promotion['id']);
        });
    }

    /** @return array<string,mixed> */
    public function queueRollback(
        int $accountId,
        int $actorUserId,
        string $role,
        string $promotionPublicId,
        string $reauthenticationPublicId,
        string $requestId
    ): array {
        $this->authorizer->assertOperator($accountId, $actorUserId, $role, true);
        $requestId = $this->requestId($requestId);
        $context = ['promotion_public_id' => trim($promotionPublicId)];
        $evidence = hash('sha256', implode('|', [$promotionPublicId, $reauthenticationPublicId]));

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $actorUserId,
            $promotionPublicId,
            $reauthenticationPublicId,
            $requestId,
            $context,
            $evidence
        ): array {
            $prior = $this->priorReceipt($pdo, $accountId, $requestId, 'queue_rollback', $evidence);
            if ($prior !== null) {
                return $this->promotionByPublicId($pdo, $accountId, $promotionPublicId);
            }
            $promotion = $this->promotionByPublicId($pdo, $accountId, $promotionPublicId, true);
            if (!in_array((string) $promotion['promotion_status'], ['completed', 'failed'], true)
                || $promotion['deployment_run_public_id'] === null
                || $promotion['backup_public_id'] === null) {
                throw new RuntimeException('Only a completed or failed deployment with a verified backup can be rolled back.');
            }
            $this->reauthentication->consume(
                trim($reauthenticationPublicId),
                $accountId,
                $actorUserId,
                'platform.rollback_release',
                $context
            );
            $pdo->prepare("UPDATE platform_release_promotions SET promotion_status='rollback_queued',updated_at=:updated_at WHERE id=:id")
                ->execute(['updated_at' => $this->now(), 'id' => (int) $promotion['id']]);
            $this->appendEvent($pdo, (int) $promotion['id'], 'rollback.queued', $actorUserId, 'success', $evidence);
            $this->receipt($pdo, $accountId, (int) $promotion['id'], $requestId, 'queue_rollback', 'success', $evidence);
            return $this->promotionById($pdo, (int) $promotion['id']);
        });
    }

    /** @return array<string,mixed>|null */
    private function priorReceipt(PDO $pdo, int $accountId, string $requestId, string $action, string $evidence): ?array
    {
        $statement = $pdo->prepare(
            'SELECT result,evidence_hash FROM platform_release_control_receipts
             WHERE account_scope=:account_scope AND request_id=:request_id AND action_type=:action LIMIT 1 FOR UPDATE'
        );
        $statement->execute(['account_scope' => $accountId, 'request_id' => $requestId, 'action' => $action]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            return null;
        }
        if (!hash_equals((string) $row['evidence_hash'], $evidence)) {
            throw new RuntimeException('The request ID has already been used with different release-control evidence.');
        }
        return $row;
    }

    private function receipt(PDO $pdo, int $accountId, ?int $promotionId, string $requestId, string $action, string $result, string $evidence): void
    {
        $pdo->prepare(
            'INSERT INTO platform_release_control_receipts
             (public_id,account_scope,promotion_id,request_id,action_type,result,evidence_hash,created_at)
             VALUES (:public_id,:account_scope,:promotion_id,:request_id,:action,:result,:evidence,:created_at)'
        )->execute([
            'public_id' => 'PRR-' . strtoupper(bin2hex(random_bytes(10))),
            'account_scope' => $accountId,
            'promotion_id' => $promotionId,
            'request_id' => $requestId,
            'action' => $action,
            'result' => $result,
            'evidence' => $evidence,
            'created_at' => $this->now(),
        ]);
    }

    private function appendEvent(PDO $pdo, int $promotionId, string $eventType, ?int $actorUserId, string $result, string $metadataHash): void
    {
        $previousStatement = $pdo->prepare(
            'SELECT event_hash FROM platform_release_promotion_events
             WHERE promotion_id=:promotion_id ORDER BY id DESC LIMIT 1 FOR UPDATE'
        );
        $previousStatement->execute(['promotion_id' => $promotionId]);
        $previous = $previousStatement->fetchColumn();
        $previous = is_string($previous) ? $previous : null;
        $occurredAt = $this->now();
        $eventHash = hash('sha256', implode('|', [
            $promotionId,
            $eventType,
            $actorUserId === null ? '' : $actorUserId,
            $result,
            $metadataHash,
            $previous ?? '',
            $occurredAt,
        ]));
        $pdo->prepare(
            'INSERT INTO platform_release_promotion_events
             (promotion_id,event_type,actor_user_id,event_result,metadata_hash,previous_hash,event_hash,occurred_at)
             VALUES (:promotion_id,:event_type,:actor_user_id,:event_result,:metadata_hash,:previous_hash,:event_hash,:occurred_at)'
        )->execute([
            'promotion_id' => $promotionId,
            'event_type' => mb_substr($eventType, 0, 100),
            'actor_user_id' => $actorUserId,
            'event_result' => $result,
            'metadata_hash' => $metadataHash,
            'previous_hash' => $previous,
            'event_hash' => $eventHash,
            'occurred_at' => $occurredAt,
        ]);
    }

    /** @return array<string,mixed> */
    private function environmentByKey(PDO $pdo, string $key): array
    {
        $statement = $pdo->prepare('SELECT * FROM platform_deployment_environments WHERE environment_key=:environment_key LIMIT 1');
        $statement->execute(['environment_key' => $key]);
        return $this->publicEnvironment($statement->fetch(PDO::FETCH_ASSOC));
    }

    /** @return array<string,mixed> */
    private function environmentByPublicId(PDO $pdo, string $publicId, bool $lock = false): array
    {
        $sql = 'SELECT * FROM platform_deployment_environments WHERE public_id=:public_id LIMIT 1' . ($lock ? ' FOR UPDATE' : '');
        $statement = $pdo->prepare($sql);
        $statement->execute(['public_id' => trim($publicId)]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('The deployment environment was not found.');
        }
        return $row;
    }

    /** @return array<string,mixed> */
    private function environmentById(PDO $pdo, int $id, bool $lock = false): array
    {
        $sql = 'SELECT * FROM platform_deployment_environments WHERE id=:id LIMIT 1' . ($lock ? ' FOR UPDATE' : '');
        $statement = $pdo->prepare($sql);
        $statement->execute(['id' => $id]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('The deployment environment was not found.');
        }
        return $row;
    }

    /** @return array<string,mixed> */
    private function windowById(PDO $pdo, int $accountId, int $id, bool $lock = false): array
    {
        $sql = 'SELECT * FROM platform_maintenance_windows WHERE account_scope=:account_scope AND id=:id LIMIT 1'
            . ($lock ? ' FOR UPDATE' : '');
        $statement = $pdo->prepare($sql);
        $statement->execute(['account_scope' => $accountId, 'id' => $id]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('The maintenance window was not found.');
        }
        return $row;
    }

    /** @return array<string,mixed> */
    private function candidateByPublicId(PDO $pdo, string $publicId, bool $lock = false): array
    {
        $sql = 'SELECT * FROM platform_release_candidates WHERE public_id=:public_id LIMIT 1' . ($lock ? ' FOR UPDATE' : '');
        $statement = $pdo->prepare($sql);
        $statement->execute(['public_id' => trim($publicId)]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('The release candidate was not found.');
        }
        return $row;
    }

    /** @return array<string,mixed> */
    private function windowByPublicId(PDO $pdo, int $accountId, string $publicId, bool $lock = false): array
    {
        $sql = 'SELECT * FROM platform_maintenance_windows WHERE account_scope=:account_scope AND public_id=:public_id LIMIT 1' . ($lock ? ' FOR UPDATE' : '');
        $statement = $pdo->prepare($sql);
        $statement->execute(['account_scope' => $accountId, 'public_id' => trim($publicId)]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('The maintenance window was not found.');
        }
        return $row;
    }

    /** @return array<string,mixed> */
    private function windowByRequest(PDO $pdo, int $accountId, string $requestId): array
    {
        $statement = $pdo->prepare('SELECT * FROM platform_maintenance_windows WHERE account_scope=:account_scope AND request_id=:request_id LIMIT 1');
        $statement->execute(['account_scope' => $accountId, 'request_id' => $requestId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('The maintenance window was not found.');
        }
        return $row;
    }

    /** @return array<string,mixed> */
    private function promotionByPublicId(PDO $pdo, int $accountId, string $publicId, bool $lock = false): array
    {
        $sql = 'SELECT * FROM platform_release_promotions WHERE account_scope=:account_scope AND public_id=:public_id LIMIT 1'
            . ($lock ? ' FOR UPDATE' : '');
        $statement = $pdo->prepare($sql);
        $statement->execute(['account_scope' => $accountId, 'public_id' => trim($publicId)]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('The release promotion was not found.');
        }
        return $row;
    }

    /** @return array<string,mixed> */
    private function promotionByRequest(PDO $pdo, int $accountId, string $requestId): array
    {
        $statement = $pdo->prepare('SELECT * FROM platform_release_promotions WHERE account_scope=:account_scope AND request_id=:request_id LIMIT 1');
        $statement->execute(['account_scope' => $accountId, 'request_id' => $requestId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('The release promotion was not found.');
        }
        return $row;
    }

    /** @return array<string,mixed> */
    private function promotionById(PDO $pdo, int $id): array
    {
        $statement = $pdo->prepare('SELECT * FROM platform_release_promotions WHERE id=:id LIMIT 1');
        $statement->execute(['id' => $id]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('The release promotion was not found.');
        }
        return $row;
    }

    /** @param mixed $row @return array<string,mixed> */
    private function publicEnvironment(mixed $row): array
    {
        if (!is_array($row)) {
            throw new RuntimeException('The deployment environment was not found.');
        }
        unset($row['id'], $row['created_by_user_id'], $row['current_candidate_id']);
        return $row;
    }

    private function requestId(string $requestId): string
    {
        $requestId = trim($requestId);
        if (!preg_match('/^[A-Za-z0-9._:-]{8,64}$/', $requestId)) {
            throw new InvalidArgumentException('A valid release-control request ID is required.');
        }
        return $requestId;
    }

    private function utcDate(string $value): DateTimeImmutable
    {
        $value = trim($value);
        if ($value === '') {
            throw new InvalidArgumentException('A UTC date and time is required.');
        }
        try {
            $date = new DateTimeImmutable($value, new DateTimeZone('UTC'));
        } catch (\Throwable) {
            throw new InvalidArgumentException('The UTC date and time is invalid.');
        }
        return $date->setTimezone(new DateTimeZone('UTC'));
    }

    private function now(): string
    {
        return gmdate('Y-m-d H:i:s') . '.000000';
    }
}
