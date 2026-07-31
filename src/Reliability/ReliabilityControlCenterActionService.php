<?php

declare(strict_types=1);

namespace Vp3\Reliability;

use DateTimeImmutable;
use DateTimeZone;
use PDO;
use RuntimeException;
use Vp3\Database;
use Vp3\Deployment\PlatformOperatorAuthorizer;

final class ReliabilityControlCenterActionService
{
    public function __construct(
        private readonly Database $database,
        private readonly PlatformOperatorAuthorizer $authorizer,
        private readonly ?ReliabilityWorkerService $worker = null
    ) {
    }

    /** @return array<string,mixed> */
    public function saveComponent(
        int $accountId,
        int $actorId,
        string $role,
        ?string $componentPublicId,
        string $componentKey,
        string $displayName,
        string $componentType,
        string $visibility,
        ?string $environmentPublicId,
        bool $enabled,
        int $displayOrder,
        string $requestId
    ): array {
        $this->authorizer->assertOperator($accountId, $actorId, $role);
        $componentPublicId = trim((string) $componentPublicId);
        $componentKey = strtolower(trim($componentKey));
        $displayName = trim($displayName);
        $componentType = strtolower(trim($componentType));
        $visibility = strtolower(trim($visibility));
        $environmentPublicId = trim((string) $environmentPublicId);
        $requestId = $this->requestId($requestId);
        $displayOrder = max(0, min(10000, $displayOrder));
        $types = ['platform','http','dns','ssl','database','worker','queue','storage','provider','pod','homeserver'];
        if (!preg_match('/^[a-z0-9][a-z0-9._-]{2,79}$/', $componentKey)
            || $displayName === '' || mb_strlen($displayName) > 160
            || !in_array($componentType, $types, true)
            || !in_array($visibility, ['public', 'private'], true)
            || ($componentPublicId !== '' && !preg_match('/^REL-CMP-[A-F0-9]{20}$/', $componentPublicId))) {
            throw new RuntimeException('A valid reliability component is required.');
        }
        $payload = [
            'component_public_id' => $componentPublicId,
            'component_key' => $componentKey,
            'display_name' => $displayName,
            'component_type' => $componentType,
            'visibility' => $visibility,
            'environment_public_id' => $environmentPublicId,
            'enabled' => $enabled,
            'display_order' => $displayOrder,
        ];
        $evidence = $this->hashValue($payload);

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId, $actorId, $componentPublicId, $componentKey, $displayName, $componentType,
            $visibility, $environmentPublicId, $enabled, $displayOrder, $requestId, $evidence
        ): array {
            $prior = $this->receipt($pdo, $accountId, $requestId, 'save_component', $evidence);
            if ($prior !== null) {
                return $this->componentByPublicId($pdo, $accountId, (string) $prior['resource_public_id']);
            }
            $environmentId = $this->environmentId($pdo, $environmentPublicId);
            $now = $this->now();
            if ($componentPublicId === '') {
                $publicId = 'REL-CMP-' . strtoupper(bin2hex(random_bytes(10)));
                $pdo->prepare(
                    "INSERT INTO reliability_components
                     (public_id,account_scope,component_key,display_name,component_type,visibility,environment_id,
                      current_status,status_since,enabled,display_order,created_by_user_id,created_at,updated_at)
                     VALUES (:public_id,:account_id,:component_key,:display_name,:component_type,:visibility,:environment_id,
                             'unknown',:status_since,:enabled,:display_order,:actor_id,:created,:updated)"
                )->execute([
                    'public_id' => $publicId,
                    'account_id' => $accountId,
                    'component_key' => $componentKey,
                    'display_name' => $displayName,
                    'component_type' => $componentType,
                    'visibility' => $visibility,
                    'environment_id' => $environmentId,
                    'status_since' => $now,
                    'enabled' => $enabled ? 1 : 0,
                    'display_order' => $displayOrder,
                    'actor_id' => $actorId,
                    'created' => $now,
                    'updated' => $now,
                ]);
                $componentId = (int) $pdo->lastInsertId();
                $pdo->prepare(
                    "INSERT INTO reliability_objectives
                     (public_id,component_id,availability_target_bps,latency_target_ms,evaluation_window_minutes,
                      warning_burn_rate,critical_burn_rate,consecutive_failure_threshold,recovery_success_threshold,
                      created_by_user_id,created_at,updated_at)
                     VALUES (:public_id,:component_id,9990,NULL,43200,2.00,14.40,3,2,:actor_id,:created,:updated)"
                )->execute([
                    'public_id' => 'REL-SLO-' . strtoupper(bin2hex(random_bytes(10))),
                    'component_id' => $componentId,
                    'actor_id' => $actorId,
                    'created' => $now,
                    'updated' => $now,
                ]);
            } else {
                $row = $this->componentByPublicId($pdo, $accountId, $componentPublicId, true);
                $publicId = (string) $row['public_id'];
                $pdo->prepare(
                    'UPDATE reliability_components
                     SET component_key=:component_key,display_name=:display_name,component_type=:component_type,
                         visibility=:visibility,environment_id=:environment_id,enabled=:enabled,
                         display_order=:display_order,updated_at=:updated
                     WHERE id=:id'
                )->execute([
                    'component_key' => $componentKey,
                    'display_name' => $displayName,
                    'component_type' => $componentType,
                    'visibility' => $visibility,
                    'environment_id' => $environmentId,
                    'enabled' => $enabled ? 1 : 0,
                    'display_order' => $displayOrder,
                    'updated' => $now,
                    'id' => (int) $row['id'],
                ]);
            }
            $this->insertReceipt($pdo, $accountId, $requestId, 'save_component', 'success', $publicId, $evidence);
            return $this->componentByPublicId($pdo, $accountId, $publicId);
        });
    }

    /** @return array<string,mixed> */
    public function saveObjective(
        int $accountId,
        int $actorId,
        string $role,
        string $componentPublicId,
        int $availabilityTargetBps,
        ?int $latencyTargetMs,
        int $evaluationWindowMinutes,
        float $warningBurnRate,
        float $criticalBurnRate,
        int $failureThreshold,
        int $recoveryThreshold,
        string $requestId
    ): array {
        $this->authorizer->assertOperator($accountId, $actorId, $role);
        $requestId = $this->requestId($requestId);
        $availabilityTargetBps = max(9000, min(10000, $availabilityTargetBps));
        $latencyTargetMs = $latencyTargetMs === null ? null : max(1, min(300000, $latencyTargetMs));
        $evaluationWindowMinutes = max(60, min(525600, $evaluationWindowMinutes));
        $warningBurnRate = max(1.0, min(1000.0, $warningBurnRate));
        $criticalBurnRate = max($warningBurnRate, min(10000.0, $criticalBurnRate));
        $failureThreshold = max(1, min(50, $failureThreshold));
        $recoveryThreshold = max(1, min(50, $recoveryThreshold));
        $payload = compact(
            'componentPublicId', 'availabilityTargetBps', 'latencyTargetMs', 'evaluationWindowMinutes',
            'warningBurnRate', 'criticalBurnRate', 'failureThreshold', 'recoveryThreshold'
        );
        $evidence = $this->hashValue($payload);

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId, $componentPublicId, $availabilityTargetBps, $latencyTargetMs, $evaluationWindowMinutes,
            $warningBurnRate, $criticalBurnRate, $failureThreshold, $recoveryThreshold, $requestId, $evidence
        ): array {
            $prior = $this->receipt($pdo, $accountId, $requestId, 'save_objective', $evidence);
            if ($prior !== null) {
                return $this->objectiveByComponent($pdo, $accountId, $componentPublicId);
            }
            $component = $this->componentByPublicId($pdo, $accountId, trim($componentPublicId), true);
            $pdo->prepare(
                'UPDATE reliability_objectives
                 SET availability_target_bps=:availability,latency_target_ms=:latency,
                     evaluation_window_minutes=:window_minutes,warning_burn_rate=:warning_burn,
                     critical_burn_rate=:critical_burn,consecutive_failure_threshold=:failure_threshold,
                     recovery_success_threshold=:recovery_threshold,updated_at=:updated
                 WHERE component_id=:component_id'
            )->execute([
                'availability' => $availabilityTargetBps,
                'latency' => $latencyTargetMs,
                'window_minutes' => $evaluationWindowMinutes,
                'warning_burn' => number_format($warningBurnRate, 2, '.', ''),
                'critical_burn' => number_format($criticalBurnRate, 2, '.', ''),
                'failure_threshold' => $failureThreshold,
                'recovery_threshold' => $recoveryThreshold,
                'updated' => $this->now(),
                'component_id' => (int) $component['id'],
            ]);
            $this->insertReceipt(
                $pdo, $accountId, $requestId, 'save_objective', 'success', (string) $component['public_id'], $evidence
            );
            return $this->objectiveByComponent($pdo, $accountId, (string) $component['public_id']);
        });
    }

    /** @return array<string,mixed> */
    public function saveProbe(
        int $accountId,
        int $actorId,
        string $role,
        string $componentPublicId,
        ?string $probePublicId,
        string $probeType,
        string $targetValue,
        int $intervalSeconds,
        int $timeoutMs,
        bool $enabled,
        string $requestId
    ): array {
        $this->authorizer->assertOperator($accountId, $actorId, $role);
        $probePublicId = trim((string) $probePublicId);
        $probeType = strtolower(trim($probeType));
        $targetValue = $this->normalizeTarget($probeType, $targetValue);
        $intervalSeconds = max(60, min(86400, $intervalSeconds));
        $timeoutMs = max(250, min(30000, $timeoutMs));
        $requestId = $this->requestId($requestId);
        if ($probePublicId !== '' && !preg_match('/^REL-PRB-[A-F0-9]{20}$/', $probePublicId)) {
            throw new RuntimeException('A valid reliability probe identity is required.');
        }
        $payload = compact(
            'componentPublicId', 'probePublicId', 'probeType', 'targetValue', 'intervalSeconds', 'timeoutMs', 'enabled'
        );
        $evidence = $this->hashValue($payload);

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId, $actorId, $componentPublicId, $probePublicId, $probeType, $targetValue,
            $intervalSeconds, $timeoutMs, $enabled, $requestId, $evidence
        ): array {
            $prior = $this->receipt($pdo, $accountId, $requestId, 'save_probe', $evidence);
            if ($prior !== null) {
                return $this->probeByPublicId($pdo, $accountId, (string) $prior['resource_public_id']);
            }
            $component = $this->componentByPublicId($pdo, $accountId, trim($componentPublicId), true);
            $now = $this->now();
            if ($probePublicId === '') {
                $publicId = 'REL-PRB-' . strtoupper(bin2hex(random_bytes(10)));
                $pdo->prepare(
                    'INSERT INTO reliability_probes
                     (public_id,component_id,probe_type,target_value,target_hash,interval_seconds,timeout_ms,
                      enabled,next_due_at,created_by_user_id,created_at,updated_at)
                     VALUES (:public_id,:component_id,:probe_type,:target_value,:target_hash,:interval_seconds,:timeout_ms,
                             :enabled,:next_due,:actor_id,:created,:updated)'
                )->execute([
                    'public_id' => $publicId,
                    'component_id' => (int) $component['id'],
                    'probe_type' => $probeType,
                    'target_value' => $targetValue,
                    'target_hash' => hash('sha256', $targetValue),
                    'interval_seconds' => $intervalSeconds,
                    'timeout_ms' => $timeoutMs,
                    'enabled' => $enabled ? 1 : 0,
                    'next_due' => $now,
                    'actor_id' => $actorId,
                    'created' => $now,
                    'updated' => $now,
                ]);
            } else {
                $probe = $this->probeByPublicId($pdo, $accountId, $probePublicId, true);
                if ((int) $probe['component_id'] !== (int) $component['id']) {
                    throw new RuntimeException('Reliability probe does not belong to the selected component.');
                }
                $publicId = (string) $probe['public_id'];
                $pdo->prepare(
                    'UPDATE reliability_probes
                     SET probe_type=:probe_type,target_value=:target_value,target_hash=:target_hash,
                         interval_seconds=:interval_seconds,timeout_ms=:timeout_ms,enabled=:enabled,
                         next_due_at=:next_due,locked_by_hash=NULL,lock_expires_at=NULL,updated_at=:updated
                     WHERE id=:id'
                )->execute([
                    'probe_type' => $probeType,
                    'target_value' => $targetValue,
                    'target_hash' => hash('sha256', $targetValue),
                    'interval_seconds' => $intervalSeconds,
                    'timeout_ms' => $timeoutMs,
                    'enabled' => $enabled ? 1 : 0,
                    'next_due' => $now,
                    'updated' => $now,
                    'id' => (int) $probe['id'],
                ]);
            }
            $this->insertReceipt($pdo, $accountId, $requestId, 'save_probe', 'success', $publicId, $evidence);
            return $this->probeByPublicId($pdo, $accountId, $publicId);
        });
    }

    /** @return array<string,mixed> */
    public function saveStatusSettings(
        int $accountId,
        int $actorId,
        string $role,
        string $publicSlug,
        string $pageTitle,
        string $pageDescription,
        bool $publicEnabled,
        bool $showHistory,
        string $requestId
    ): array {
        $this->authorizer->assertOperator($accountId, $actorId, $role, true);
        $publicSlug = strtolower(trim($publicSlug));
        $pageTitle = trim($pageTitle);
        $pageDescription = trim($pageDescription);
        $requestId = $this->requestId($requestId);
        if (!preg_match('/^[a-z0-9][a-z0-9-]{2,79}$/', $publicSlug)
            || $pageTitle === '' || mb_strlen($pageTitle) > 160
            || $pageDescription === '' || mb_strlen($pageDescription) > 500) {
            throw new RuntimeException('Valid public status-page settings are required.');
        }
        $payload = compact('publicSlug', 'pageTitle', 'pageDescription', 'publicEnabled', 'showHistory');
        $evidence = $this->hashValue($payload);

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId, $actorId, $publicSlug, $pageTitle, $pageDescription,
            $publicEnabled, $showHistory, $requestId, $evidence
        ): array {
            $prior = $this->receipt($pdo, $accountId, $requestId, 'save_status_settings', $evidence);
            if ($prior !== null) {
                return $this->statusSettings($pdo, $accountId);
            }
            $existing = $pdo->prepare('SELECT id FROM reliability_status_settings WHERE account_scope=:account_id LIMIT 1 FOR UPDATE');
            $existing->execute(['account_id' => $accountId]);
            $id = $existing->fetchColumn();
            $now = $this->now();
            if ($id === false) {
                $pdo->prepare(
                    'INSERT INTO reliability_status_settings
                     (account_scope,public_slug,page_title,page_description,public_enabled,show_history,
                      created_by_user_id,updated_by_user_id,created_at,updated_at)
                     VALUES (:account_id,:slug,:title,:description,:enabled,:history,:created_by_user_id,:updated_by_user_id,:created,:updated)'
                )->execute([
                    'account_id' => $accountId,
                    'slug' => $publicSlug,
                    'title' => $pageTitle,
                    'description' => $pageDescription,
                    'enabled' => $publicEnabled ? 1 : 0,
                    'history' => $showHistory ? 1 : 0,
                    'created_by_user_id' => $actorId,
                    'updated_by_user_id' => $actorId,
                    'created' => $now,
                    'updated' => $now,
                ]);
            } else {
                $pdo->prepare(
                    'UPDATE reliability_status_settings
                     SET public_slug=:slug,page_title=:title,page_description=:description,
                         public_enabled=:enabled,show_history=:history,updated_by_user_id=:actor_id,updated_at=:updated
                     WHERE id=:id'
                )->execute([
                    'slug' => $publicSlug,
                    'title' => $pageTitle,
                    'description' => $pageDescription,
                    'enabled' => $publicEnabled ? 1 : 0,
                    'history' => $showHistory ? 1 : 0,
                    'actor_id' => $actorId,
                    'updated' => $now,
                    'id' => (int) $id,
                ]);
            }
            $this->insertReceipt($pdo, $accountId, $requestId, 'save_status_settings', 'success', null, $evidence);
            return $this->statusSettings($pdo, $accountId);
        });
    }

    /** @return array<string,mixed> */
    public function publishStatusMessage(
        int $accountId,
        int $actorId,
        string $role,
        ?string $componentPublicId,
        string $title,
        string $message,
        string $startsAt,
        ?string $endsAt,
        string $requestId
    ): array {
        $this->authorizer->assertOperator($accountId, $actorId, $role);
        $componentPublicId = trim((string) $componentPublicId);
        $title = trim($title);
        $message = trim($message);
        $startsAt = $this->timestamp($startsAt);
        $endsAt = trim((string) $endsAt) === '' ? null : $this->timestamp((string) $endsAt);
        $requestId = $this->requestId($requestId);
        if ($title === '' || mb_strlen($title) > 160 || $message === '' || mb_strlen($message) > 1000
            || ($endsAt !== null && strcmp($endsAt, $startsAt) <= 0)) {
            throw new RuntimeException('A valid public status message is required.');
        }
        $payload = compact('componentPublicId', 'title', 'message', 'startsAt', 'endsAt');
        $evidence = $this->hashValue($payload);

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId, $actorId, $componentPublicId, $title, $message, $startsAt,
            $endsAt, $requestId, $evidence
        ): array {
            $prior = $this->receipt($pdo, $accountId, $requestId, 'publish_status_message', $evidence);
            if ($prior !== null) {
                return $this->messageByPublicId($pdo, $accountId, (string) $prior['resource_public_id']);
            }
            $componentId = null;
            if ($componentPublicId !== '') {
                $component = $this->componentByPublicId($pdo, $accountId, $componentPublicId, true);
                $componentId = (int) $component['id'];
            }
            $publicId = 'REL-MSG-' . strtoupper(bin2hex(random_bytes(10)));
            $now = $this->now();
            $status = strcmp($startsAt, $now) <= 0 ? 'published' : 'scheduled';
            $pdo->prepare(
                'INSERT INTO reliability_status_messages
                 (public_id,account_scope,component_id,request_id,title,message,message_status,
                  starts_at,ends_at,created_by_user_id,created_at,updated_at)
                 VALUES (:public_id,:account_id,:component_id,:request_id,:title,:message,:status,
                         :starts_at,:ends_at,:actor_id,:created,:updated)'
            )->execute([
                'public_id' => $publicId,
                'account_id' => $accountId,
                'component_id' => $componentId,
                'request_id' => $requestId,
                'title' => $title,
                'message' => $message,
                'status' => $status,
                'starts_at' => $startsAt,
                'ends_at' => $endsAt,
                'actor_id' => $actorId,
                'created' => $now,
                'updated' => $now,
            ]);
            $this->insertReceipt($pdo, $accountId, $requestId, 'publish_status_message', 'success', $publicId, $evidence);
            return $this->messageByPublicId($pdo, $accountId, $publicId);
        });
    }

    /** @return array<string,mixed> */
    public function resolveStatusMessage(
        int $accountId,
        int $actorId,
        string $role,
        string $messagePublicId,
        string $requestId
    ): array {
        $this->authorizer->assertOperator($accountId, $actorId, $role);
        $messagePublicId = trim($messagePublicId);
        $requestId = $this->requestId($requestId);
        $evidence = $this->hashValue(['message_public_id' => $messagePublicId]);

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId, $messagePublicId, $requestId, $evidence
        ): array {
            $prior = $this->receipt($pdo, $accountId, $requestId, 'resolve_status_message', $evidence);
            if ($prior !== null) {
                return $this->messageByPublicId($pdo, $accountId, $messagePublicId);
            }
            $message = $this->messageByPublicId($pdo, $accountId, $messagePublicId, true);
            $pdo->prepare(
                "UPDATE reliability_status_messages
                 SET message_status='resolved',ends_at=COALESCE(ends_at,UTC_TIMESTAMP(6)),updated_at=UTC_TIMESTAMP(6)
                 WHERE id=:id"
            )->execute(['id' => (int) $message['id']]);
            $this->insertReceipt($pdo, $accountId, $requestId, 'resolve_status_message', 'success', $messagePublicId, $evidence);
            return $this->messageByPublicId($pdo, $accountId, $messagePublicId);
        });
    }

    /** @return array<string,mixed> */
    public function recordManualObservation(
        int $accountId,
        int $actorId,
        string $role,
        string $probePublicId,
        string $status,
        ?int $latencyMs,
        ?float $valueNumeric,
        ?string $errorCode,
        string $requestId
    ): array {
        $this->authorizer->assertOperator($accountId, $actorId, $role);
        if ($this->worker === null) {
            throw new RuntimeException('Manual reliability observation service is unavailable.');
        }
        $probePublicId = trim($probePublicId);
        $status = strtolower(trim($status));
        $requestId = $this->requestId($requestId);
        $payload = compact('probePublicId', 'status', 'latencyMs', 'valueNumeric', 'errorCode');
        $evidence = $this->hashValue($payload);
        $prior = $this->database->transaction(function (PDO $pdo) use (
            $accountId, $probePublicId, $requestId, $evidence
        ): ?array {
            $probe = $this->probeByPublicId($pdo, $accountId, $probePublicId, true);
            if ((string) $probe['probe_type'] !== 'manual') {
                throw new RuntimeException('The selected probe does not accept manual observations.');
            }
            $prior = $this->receipt($pdo, $accountId, $requestId, 'manual_observation', $evidence);
            return $prior === null ? null : ['resource_public_id' => $prior['resource_public_id']];
        });
        if ($prior !== null) {
            return ['result_public_id' => (string) $prior['resource_public_id'], 'replayed' => true];
        }
        $result = $this->worker->recordManual($probePublicId, [
            'status' => $status,
            'latency_ms' => $latencyMs,
            'value_numeric' => $valueNumeric,
            'error_code' => $errorCode,
            'evidence' => ['actor_user_id' => $actorId, 'request_id_hash' => hash('sha256', $requestId)],
        ]);
        $this->database->transaction(function (PDO $pdo) use (
            $accountId, $requestId, $evidence, $result
        ): void {
            $this->insertReceipt(
                $pdo,
                $accountId,
                $requestId,
                'manual_observation',
                'success',
                (string) $result['result_public_id'],
                $evidence
            );
        });
        return $result + ['replayed' => false];
    }

    private function normalizeTarget(string $probeType, string $target): string
    {
        $target = trim($target);
        return match ($probeType) {
            'http' => $this->httpsTarget($target),
            'dns', 'ssl' => $this->hostnameTarget($target),
            'database' => $target === 'primary' ? $target : throw new RuntimeException('Database probes require the protected primary target.'),
            'worker' => preg_match('/^(staging|production):([6-9][0-9]|[1-9][0-9]{2,3})$/', strtolower($target))
                ? strtolower($target) : throw new RuntimeException('Worker probes require environment:max-age-seconds.'),
            'queue' => ctype_digit($target) && (int) $target >= 1 && (int) $target <= 10000
                ? (string) (int) $target : throw new RuntimeException('Queue probes require a numeric depth threshold.'),
            'storage' => $target === 'application_root' ? $target : throw new RuntimeException('Storage probes support application_root only.'),
            'manual' => $target === '' || $target === 'manual' ? 'manual' : throw new RuntimeException('Manual probes use the manual target.'),
            default => throw new RuntimeException('A supported reliability probe type is required.'),
        };
    }

    private function httpsTarget(string $target): string
    {
        $parts = parse_url($target);
        if (!is_array($parts)
            || strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || trim((string) ($parts['host'] ?? '')) === ''
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])) {
            throw new RuntimeException('HTTP reliability targets must be canonical HTTPS URLs without credentials or fragments.');
        }
        return $target;
    }

    private function hostnameTarget(string $target): string
    {
        $target = strtolower(rtrim($target, '.'));
        if (!filter_var($target, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            throw new RuntimeException('A valid reliability hostname is required.');
        }
        return $target;
    }

    private function environmentId(PDO $pdo, string $publicId): ?int
    {
        if ($publicId === '') {
            return null;
        }
        $statement = $pdo->prepare(
            "SELECT id FROM platform_deployment_environments
             WHERE public_id=:public_id AND environment_status<>'disabled' LIMIT 1"
        );
        $statement->execute(['public_id' => $publicId]);
        $id = $statement->fetchColumn();
        if ($id === false) {
            throw new RuntimeException('The selected deployment environment is unavailable.');
        }
        return (int) $id;
    }

    /** @return array<string,mixed> */
    private function componentByPublicId(PDO $pdo, int $accountId, string $publicId, bool $lock = false): array
    {
        $statement = $pdo->prepare(
            'SELECT * FROM reliability_components
             WHERE account_scope=:account_id AND public_id=:public_id LIMIT 1' . ($lock ? ' FOR UPDATE' : '')
        );
        $statement->execute(['account_id' => $accountId, 'public_id' => trim($publicId)]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('Reliability component was not found.');
        }
        unset($row['account_scope'], $row['created_by_user_id'], $row['environment_id']);
        if (!$lock) {
            unset($row['id']);
        }
        $row['enabled'] = (bool) $row['enabled'];
        return $row;
    }

    /** @return array<string,mixed> */
    private function objectiveByComponent(PDO $pdo, int $accountId, string $componentPublicId): array
    {
        $statement = $pdo->prepare(
            'SELECT o.*,c.public_id AS component_public_id
             FROM reliability_objectives o
             INNER JOIN reliability_components c ON c.id=o.component_id
             WHERE c.account_scope=:account_id AND c.public_id=:public_id LIMIT 1'
        );
        $statement->execute(['account_id' => $accountId, 'public_id' => $componentPublicId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('Reliability objective was not found.');
        }
        unset($row['id'], $row['component_id'], $row['created_by_user_id']);
        return $row;
    }

    /** @return array<string,mixed> */
    private function probeByPublicId(PDO $pdo, int $accountId, string $publicId, bool $lock = false): array
    {
        $statement = $pdo->prepare(
            'SELECT p.*,c.account_scope,c.public_id AS component_public_id
             FROM reliability_probes p
             INNER JOIN reliability_components c ON c.id=p.component_id
             WHERE c.account_scope=:account_id AND p.public_id=:public_id LIMIT 1' . ($lock ? ' FOR UPDATE' : '')
        );
        $statement->execute(['account_id' => $accountId, 'public_id' => trim($publicId)]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('Reliability probe was not found.');
        }
        unset($row['account_scope'], $row['target_value'], $row['target_hash'], $row['locked_by_hash'], $row['created_by_user_id']);
        if (!$lock) {
            unset($row['id'], $row['component_id']);
        }
        $row['enabled'] = (bool) $row['enabled'];
        return $row;
    }

    /** @return array<string,mixed> */
    private function statusSettings(PDO $pdo, int $accountId): array
    {
        $statement = $pdo->prepare(
            'SELECT public_slug,page_title,page_description,public_enabled,show_history,created_at,updated_at
             FROM reliability_status_settings WHERE account_scope=:account_id LIMIT 1'
        );
        $statement->execute(['account_id' => $accountId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            return [
                'public_slug' => '',
                'page_title' => '',
                'page_description' => '',
                'public_enabled' => false,
                'show_history' => true,
            ];
        }
        $row['public_enabled'] = (bool) $row['public_enabled'];
        $row['show_history'] = (bool) $row['show_history'];
        return $row;
    }

    /** @return array<string,mixed> */
    private function messageByPublicId(PDO $pdo, int $accountId, string $publicId, bool $lock = false): array
    {
        $statement = $pdo->prepare(
            'SELECT m.id,m.public_id,m.title,m.message,m.message_status,m.starts_at,m.ends_at,
                    c.public_id AS component_public_id,c.display_name AS component_name
             FROM reliability_status_messages m
             LEFT JOIN reliability_components c ON c.id=m.component_id
             WHERE m.account_scope=:account_id AND m.public_id=:public_id LIMIT 1' . ($lock ? ' FOR UPDATE' : '')
        );
        $statement->execute(['account_id' => $accountId, 'public_id' => trim($publicId)]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('Reliability status message was not found.');
        }
        if (!$lock) {
            unset($row['id']);
        }
        return $row;
    }

    /** @return array<string,mixed>|null */
    private function receipt(PDO $pdo, int $accountId, string $requestId, string $actionType, string $evidence): ?array
    {
        $statement = $pdo->prepare(
            'SELECT result,resource_public_id,evidence_hash FROM reliability_action_receipts
             WHERE account_scope=:account_id AND request_id=:request_id AND action_type=:action_type LIMIT 1'
        );
        $statement->execute(['account_id' => $accountId, 'request_id' => $requestId, 'action_type' => $actionType]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            return null;
        }
        if (!hash_equals((string) $row['evidence_hash'], $evidence)) {
            throw new RuntimeException('reliability_request_conflict');
        }
        return $row;
    }

    private function insertReceipt(
        PDO $pdo,
        int $accountId,
        string $requestId,
        string $actionType,
        string $result,
        ?string $resourcePublicId,
        string $evidence
    ): void {
        $pdo->prepare(
            'INSERT INTO reliability_action_receipts
             (public_id,account_scope,request_id,action_type,result,resource_public_id,evidence_hash,created_at)
             VALUES (:public_id,:account_id,:request_id,:action_type,:result,:resource_public_id,:evidence,:created_at)'
        )->execute([
            'public_id' => 'REL-RCT-' . strtoupper(bin2hex(random_bytes(10))),
            'account_id' => $accountId,
            'request_id' => $requestId,
            'action_type' => $actionType,
            'result' => $result,
            'resource_public_id' => $resourcePublicId,
            'evidence' => $evidence,
            'created_at' => $this->now(),
        ]);
    }

    private function requestId(string $requestId): string
    {
        $requestId = trim($requestId);
        if (!preg_match('/^[A-Za-z0-9._:@-]{8,80}$/', $requestId)) {
            throw new RuntimeException('A valid reliability request identity is required.');
        }
        return $requestId;
    }

    private function timestamp(string $value): string
    {
        try {
            return (new DateTimeImmutable(trim($value), new DateTimeZone('UTC')))
                ->setTimezone(new DateTimeZone('UTC'))
                ->format('Y-m-d H:i:s.u');
        } catch (\Throwable) {
            throw new RuntimeException('A valid UTC reliability timestamp is required.');
        }
    }

    private function now(): string
    {
        return (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s.u');
    }

    private function hashValue(mixed $value): string
    {
        return hash('sha256', json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }
}
