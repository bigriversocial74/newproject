<?php

declare(strict_types=1);

namespace Vp3\Deployment;

use DateTimeImmutable;
use DateTimeZone;
use PDO;
use RuntimeException;
use Throwable;
use Vp3\Database;
use Vp3\Operations\OperationalIncidentService;

final class ReleaseDeploymentWorkerService
{
    public function __construct(
        private readonly Database $database,
        private readonly Database $targetDatabase,
        private readonly ReleaseManifestService $releaseManifest,
        private readonly DeploymentPreflightService $preflight,
        private readonly PlatformUpgradeService $upgrades,
        private readonly DeploymentHealthService $health,
        private readonly OperationalIncidentService $incidents,
        private readonly string $actualConfigFingerprint,
        private readonly int $leaseSeconds = 3600
    ) {
        if (!preg_match('/^[a-f0-9]{64}$/', strtolower($this->actualConfigFingerprint))) {
            throw new RuntimeException('A valid target environment configuration fingerprint is required.');
        }
        if ($this->leaseSeconds < 300 || $this->leaseSeconds > 7200) {
            throw new RuntimeException('The platform release worker lease must be between 300 and 7200 seconds.');
        }
    }

    /** @return array<string,mixed>|null */
    public function processNext(string $environmentKey, string $workerId): ?array
    {
        $environmentKey = strtolower(trim($environmentKey));
        $workerId = trim($workerId);
        if (!in_array($environmentKey, ['staging', 'production'], true)
            || !preg_match('/^[A-Za-z0-9._:@-]{4,120}$/', $workerId)) {
            throw new RuntimeException('A valid platform release worker identity is required.');
        }

        $this->heartbeat($environmentKey, $workerId);
        $this->refreshReadiness($environmentKey, $workerId);
        $job = $this->claim($environmentKey, $workerId);
        if ($job === null) {
            return null;
        }

        try {
            if ((string) $job['operation'] === 'rollback') {
                return $this->executeRollback($job, $environmentKey, $workerId);
            }
            return $this->executePromotion($job, $environmentKey, $workerId);
        } catch (Throwable $exception) {
            try {
                $this->recordFailure($job, $environmentKey, $workerId, $exception);
            } catch (Throwable $recordingFailure) {
                throw new RuntimeException(
                    'The platform release worker could not persist failure evidence.',
                    0,
                    $recordingFailure
                );
            }
            throw $exception;
        }
    }

    public function heartbeat(string $environmentKey, string $workerId): void
    {
        $statement = $this->database->pdo()->prepare(
            "UPDATE platform_deployment_environments
             SET worker_id_hash=:worker_hash,worker_last_seen_at=:seen_at,updated_at=:updated_at
             WHERE environment_key=:environment_key AND environment_status<>'disabled'"
        );
        $now = $this->now();
        $statement->execute([
            'worker_hash' => hash('sha256', $workerId),
            'seen_at' => $now,
            'updated_at' => $now,
            'environment_key' => $environmentKey,
        ]);
        if ($statement->rowCount() !== 1) {

            $exists = $this->database->pdo()->prepare(

                "SELECT COUNT(*) FROM platform_deployment_environments

                 WHERE environment_key=:environment_key AND environment_status<>'disabled'"

            );

            $exists->execute(['environment_key' => $environmentKey]);

            if ((int) $exists->fetchColumn() !== 1) {

                throw new RuntimeException('The platform deployment environment is not registered or is disabled.');

            }

        }
    }

    private function refreshReadiness(string $environmentKey, string $workerId): void
    {
        $environmentStatement = $this->database->pdo()->prepare(
            'SELECT id,current_candidate_id,config_fingerprint
             FROM platform_deployment_environments
             WHERE environment_key=:environment_key AND environment_status<>\'disabled\' LIMIT 1'
        );
        $environmentStatement->execute(['environment_key' => $environmentKey]);
        $environment = $environmentStatement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($environment)) {
            throw new RuntimeException('The platform deployment environment is not registered.');
        }
        $expectedFingerprint = strtolower((string) ($environment['config_fingerprint'] ?? ''));
        $configurationMatches = preg_match('/^[a-f0-9]{64}$/', $expectedFingerprint) === 1
            && hash_equals($expectedFingerprint, strtolower($this->actualConfigFingerprint));

        try {
            $report = $this->preflight->inspect($this->targetDatabase->pdo());
            $checks = [
                'php_version' => (bool) ($report['checks']['php_version']['ok'] ?? false),
                'php_extensions' => (bool) ($report['checks']['php_extensions']['ok'] ?? false),
                'application_config' => (bool) ($report['checks']['application_config']['ok'] ?? false),
                'https_origin' => (bool) ($report['checks']['https_origin']['ok'] ?? false),
                'database_version' => (bool) ($report['checks']['database_version']['ok'] ?? false),
                'database_timezone' => (bool) ($report['checks']['database_timezone']['ok'] ?? false),
                'backup_root' => (bool) ($report['checks']['backup_root']['ok'] ?? false),
                'mysqldump_binary' => (bool) ($report['checks']['mysqldump_binary']['ok'] ?? false),
                'mysql_binary' => (bool) ($report['checks']['mysql_binary']['ok'] ?? false),
                'installer' => (bool) ($report['checks']['installer']['ok'] ?? false),
                'worker_entrypoints' => (bool) ($report['checks']['workers']['ok'] ?? false),
                'active_deployment' => (bool) ($report['checks']['active_deployment']['ok'] ?? false),
                'configuration_fingerprint' => $configurationMatches,
            ];
            $ready = ($report['ok'] ?? false) === true && $configurationMatches;
        } catch (Throwable $exception) {
            $ready = false;
            $checks = [
                'preflight' => false,
                'configuration_fingerprint' => $configurationMatches,
                'error_code' => $this->errorCode($exception),
            ];
        }

        $candidateId = null;
        try {
            $active = $this->targetDatabase->pdo()->query(
                "SELECT release_version,commit_sha FROM platform_release_records
                 WHERE release_status='active' ORDER BY id DESC LIMIT 1"
            )->fetch(PDO::FETCH_ASSOC);
            if (is_array($active)) {
                $candidate = $this->database->pdo()->prepare(
                    'SELECT id FROM platform_release_candidates
                     WHERE release_version=:version AND commit_sha=:commit LIMIT 1'
                );
                $candidate->execute([
                    'version' => (string) $active['release_version'],
                    'commit' => (string) $active['commit_sha'],
                ]);
                $resolved = $candidate->fetchColumn();
                $candidateId = $resolved === false ? null : (int) $resolved;
            }
        } catch (Throwable) {
            $candidateId = null;
        }

        $checksJson = json_encode($checks, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $evidence = hash('sha256', $checksJson);
        $now = $this->now();
        $this->database->transaction(function (PDO $pdo) use (
            $environment,
            $workerId,
            $ready,
            $candidateId,
            $checksJson,
            $evidence,
            $now
        ): void {
            $locked = $pdo->prepare(
                'SELECT id,current_candidate_id FROM platform_deployment_environments WHERE id=:id LIMIT 1 FOR UPDATE'
            );
            $locked->execute(['id' => (int) $environment['id']]);
            $row = $locked->fetch(PDO::FETCH_ASSOC);
            if (!is_array($row)) {
                throw new RuntimeException('The platform deployment environment is not registered.');
            }
            $effectiveCandidate = $candidateId
                ?? ($row['current_candidate_id'] === null ? null : (int) $row['current_candidate_id']);
            $pdo->prepare(
                'UPDATE platform_deployment_environments
                 SET readiness_status=:readiness,current_candidate_id=:candidate_id,readiness_evidence_hash=:evidence,
                     last_health_at=:last_health,worker_id_hash=:worker_hash,worker_last_seen_at=:worker_seen,
                     updated_at=:updated_at WHERE id=:id'
            )->execute([
                'readiness' => $ready ? 'ready' : 'blocked',
                'candidate_id' => $effectiveCandidate,
                'evidence' => $evidence,
                'last_health' => $now,
                'worker_hash' => hash('sha256', $workerId),
                'worker_seen' => $now,
                'updated_at' => $now,
                'id' => (int) $row['id'],
            ]);

            $latest = $pdo->prepare(
                'SELECT evidence_hash,captured_at FROM platform_environment_health_snapshots
                 WHERE environment_id=:environment_id ORDER BY id DESC LIMIT 1'
            );
            $latest->execute(['environment_id' => (int) $row['id']]);
            $prior = $latest->fetch(PDO::FETCH_ASSOC);
            $recentDuplicate = is_array($prior)
                && hash_equals((string) $prior['evidence_hash'], $evidence)
                && strtotime((string) $prior['captured_at'] . ' UTC') >= time() - 300;
            if (!$recentDuplicate) {
                $pdo->prepare(
                    'INSERT INTO platform_environment_health_snapshots
                     (public_id,environment_id,release_candidate_id,health_status,checks_json,evidence_hash,captured_by,captured_at)
                     VALUES (:public_id,:environment_id,:candidate_id,:health_status,:checks_json,:evidence_hash,:captured_by,:captured_at)'
                )->execute([
                    'public_id' => 'PHS-' . strtoupper(bin2hex(random_bytes(10))),
                    'environment_id' => (int) $row['id'],
                    'candidate_id' => $effectiveCandidate,
                    'health_status' => $ready ? 'ready' : 'blocked',
                    'checks_json' => $checksJson,
                    'evidence_hash' => $evidence,
                    'captured_by' => mb_substr($workerId, 0, 64),
                    'captured_at' => $now,
                ]);
            }
            $pdo->prepare(
                'DELETE FROM platform_environment_health_snapshots
                 WHERE environment_id=:environment_id AND captured_at<DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 90 DAY)'
            )->execute(['environment_id' => (int) $row['id']]);
        });
    }

    /** @return array<string,mixed>|null */
    private function claim(string $environmentKey, string $workerId): ?array
    {
        return $this->database->transaction(function (PDO $pdo) use ($environmentKey, $workerId): ?array {
            $now = $this->now();
            $leaseExpires = $this->future($this->leaseSeconds);
            $pdo->prepare(
                "UPDATE platform_maintenance_windows SET window_status='open',updated_at=:updated_at
                 WHERE window_status='scheduled' AND starts_at<=:starts_at AND ends_at>:ends_at"
            )->execute(['updated_at' => $now, 'starts_at' => $now, 'ends_at' => $now]);
            $pdo->prepare(
                "UPDATE platform_maintenance_windows SET window_status='closed',updated_at=:updated_at
                 WHERE window_status IN ('scheduled','open') AND ends_at<=:ends_at"
            )->execute(['updated_at' => $now, 'ends_at' => $now]);

            $rollback = $pdo->prepare(
                "SELECT p.*,e.environment_key,c.release_version,c.commit_sha,c.schema_level,
                        c.manifest_sha256,c.installer_sha256,c.source_tree_sha256,c.source_file_count
                 FROM platform_release_promotions p
                 INNER JOIN platform_deployment_environments e ON e.id=p.target_environment_id
                 INNER JOIN platform_release_candidates c ON c.id=p.release_candidate_id
                 WHERE e.environment_key=:environment_key AND e.environment_status<>'disabled'
                   AND (
                     p.promotion_status='rollback_queued'
                     OR (p.promotion_status='rolling_back' AND p.lease_expires_at<=:current_time)
                   )
                 ORDER BY p.updated_at ASC,p.id ASC LIMIT 1 FOR UPDATE"
            );
            $rollback->execute(['environment_key' => $environmentKey, 'current_time' => $now]);
            $row = $rollback->fetch(PDO::FETCH_ASSOC);
            if (is_array($row)) {
                $pdo->prepare(
                    "UPDATE platform_release_promotions
                     SET promotion_status='rolling_back',started_at=COALESCE(started_at,:started_at),
                         worker_id_hash=:worker_hash,lease_expires_at=:lease_expires,
                         attempt_count=attempt_count+1,updated_at=:updated_at WHERE id=:id"
                )->execute([
                    'started_at' => $now,
                    'worker_hash' => hash('sha256', $workerId),
                    'lease_expires' => $leaseExpires,
                    'updated_at' => $now,
                    'id' => (int) $row['id'],
                ]);
                $this->appendEvent(
                    $pdo,
                    (int) $row['id'],
                    'rollback.started',
                    null,
                    'success',
                    hash('sha256', $workerId . '|' . $leaseExpires)
                );
                $row['operation'] = 'rollback';
                return $row;
            }

            $promotion = $pdo->prepare(
                "SELECT p.*,e.environment_key,e.current_candidate_id,e.readiness_status,
                        c.release_version,c.commit_sha,c.schema_level,c.manifest_sha256,c.installer_sha256,
                        c.source_tree_sha256,c.source_file_count,
                        src.current_candidate_id AS source_current_candidate_id,
                        src.readiness_status AS source_readiness_status,
                        w.starts_at,w.ends_at,w.window_status,w.approved_by_user_id AS window_approved_by,
                        w.account_scope AS window_account_scope
                 FROM platform_release_promotions p
                 INNER JOIN platform_deployment_environments e ON e.id=p.target_environment_id
                 INNER JOIN platform_deployment_environments src ON src.id=p.source_environment_id
                 INNER JOIN platform_release_candidates c ON c.id=p.release_candidate_id
                 LEFT JOIN platform_maintenance_windows w ON w.id=p.maintenance_window_id
                 WHERE e.environment_key=:environment_key AND e.environment_status='active'
                   AND (
                     (p.promotion_status IN ('queued','scheduled')
                      AND (p.scheduled_for IS NULL OR p.scheduled_for<=:scheduled_for)
                      AND e.readiness_status='ready'
                      AND (
                        (e.environment_key='staging' AND p.maintenance_window_id IS NULL)
                        OR
                        (e.environment_key='production'
                         AND src.environment_key='staging'
                         AND src.readiness_status='ready'
                         AND src.current_candidate_id=p.release_candidate_id
                         AND w.account_scope=p.account_scope
                         AND w.approved_by_user_id IS NOT NULL
                         AND w.window_status='open' AND w.starts_at<=:window_start AND w.ends_at>:window_end)
                      ))
                     OR
                     (p.promotion_status='deploying' AND p.lease_expires_at<=:current_time)
                   )
                 ORDER BY COALESCE(p.scheduled_for,p.approved_at),p.id LIMIT 1 FOR UPDATE"
            );
            $promotion->execute([
                'environment_key' => $environmentKey,
                'scheduled_for' => $now,
                'window_start' => $now,
                'window_end' => $now,
                'current_time' => $now,
            ]);
            $row = $promotion->fetch(PDO::FETCH_ASSOC);
            if (!is_array($row)) {
                return null;
            }
            $pdo->prepare(
                "UPDATE platform_release_promotions
                 SET promotion_status='deploying',started_at=COALESCE(started_at,:started_at),
                     worker_id_hash=:worker_hash,lease_expires_at=:lease_expires,
                     attempt_count=attempt_count+1,updated_at=:updated_at WHERE id=:id"
            )->execute([
                'started_at' => $now,
                'worker_hash' => hash('sha256', $workerId),
                'lease_expires' => $leaseExpires,
                'updated_at' => $now,
                'id' => (int) $row['id'],
            ]);
            $this->appendEvent(
                $pdo,
                (int) $row['id'],
                'promotion.started',
                null,
                'success',
                hash('sha256', $workerId . '|' . $leaseExpires)
            );
            $row['operation'] = 'promotion';
            return $row;
        });
    }

    /** @param array<string,mixed> $job @return array<string,mixed> */
    private function executePromotion(array $job, string $environmentKey, string $workerId): array
    {
        $manifest = $this->releaseManifest->build();
        foreach ([
            'version' => 'release_version',
            'commit_sha' => 'commit_sha',
            'schema_level' => 'schema_level',
            'manifest_sha256' => 'manifest_sha256',
        ] as $manifestKey => $jobKey) {
            if (!hash_equals((string) $manifest[$manifestKey], (string) $job[$jobKey])) {
                throw new RuntimeException('The queued release candidate does not match the deployed release artifact.');
            }
        }
        if (!hash_equals((string) $manifest['installer']['sha256'], (string) $job['installer_sha256'])
            || !hash_equals((string) $manifest['application_source']['tree_sha256'], (string) $job['source_tree_sha256'])
            || (int) $manifest['application_source']['file_count'] !== (int) $job['source_file_count']) {
            throw new RuntimeException('The queued release source or installer identity does not match the deployed artifact.');
        }

        $run = $this->upgrades->upgrade('promote-' . strtolower((string) $job['public_id']));
        $this->recordTargetRun($job, $run, $workerId);
        $health = $this->health->verify('health-' . strtolower((string) $job['public_id']));
        if (($health['ok'] ?? false) !== true) {
            throw new RuntimeException('The promoted release failed deployment health verification.');
        }

        return $this->database->transaction(function (PDO $pdo) use ($job, $run, $health, $environmentKey, $workerId): array {
            $targetRun = $this->targetRun((string) $run['public_id']);
            $now = $this->now();
            $healthChecks = [
                'database' => (bool) ($health['checks']['database']['ok'] ?? false),
                'schema' => (bool) ($health['checks']['schema']['ok'] ?? false),
                'active_release' => (bool) ($health['checks']['active_release']['ok'] ?? false),
                'latest_deployment' => (bool) ($health['checks']['latest_deployment']['ok'] ?? false),
                'failed_steps' => (bool) ($health['checks']['failed_steps']['ok'] ?? false),
                'worker_entrypoints' => (bool) ($health['checks']['worker_entrypoints']['ok'] ?? false),
                'release_version' => (string) ($health['release_version'] ?? ''),
                'worker_environment' => $environmentKey,
            ];
            $healthJson = json_encode($healthChecks, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            $healthEvidence = hash('sha256', $healthJson);
            $pdo->prepare(
                "UPDATE platform_release_promotions
                 SET deployment_run_public_id=:run_public_id,backup_public_id=:backup_public_id,
                     promotion_status='completed',failure_code=NULL,evidence_hash=:evidence,
                     lease_expires_at=NULL,worker_id_hash=:worker_hash,
                     finished_at=:finished_at,updated_at=:updated_at WHERE id=:id"
            )->execute([
                'run_public_id' => (string) $run['public_id'],
                'backup_public_id' => $targetRun['backup_public_id'] === null
                    ? null : (string) $targetRun['backup_public_id'],
                'evidence' => $healthEvidence,
                'worker_hash' => hash('sha256', $workerId),
                'finished_at' => $now,
                'updated_at' => $now,
                'id' => (int) $job['id'],
            ]);
            $pdo->prepare(
                "UPDATE platform_deployment_environments
                 SET current_candidate_id=:candidate_id,readiness_status='ready',readiness_evidence_hash=:evidence,
                     last_health_at=:last_health,worker_id_hash=:worker_hash,worker_last_seen_at=:worker_seen,
                     updated_at=:updated_at WHERE id=:environment_id"
            )->execute([
                'candidate_id' => (int) $job['release_candidate_id'],
                'evidence' => $healthEvidence,
                'last_health' => $now,
                'worker_hash' => hash('sha256', $workerId),
                'worker_seen' => $now,
                'updated_at' => $now,
                'environment_id' => (int) $job['target_environment_id'],
            ]);
            $pdo->prepare(
                "UPDATE platform_release_candidates SET candidate_status='promoted',updated_at=:updated_at WHERE id=:id"
            )->execute(['updated_at' => $now, 'id' => (int) $job['release_candidate_id']]);
            $pdo->prepare(
                "INSERT INTO platform_environment_health_snapshots
                 (public_id,environment_id,release_candidate_id,health_status,checks_json,evidence_hash,captured_by,captured_at)
                 VALUES (:public_id,:environment_id,:candidate_id,'ready',:checks_json,:evidence_hash,:captured_by,:captured_at)"
            )->execute([
                'public_id' => 'PHS-' . strtoupper(bin2hex(random_bytes(10))),
                'environment_id' => (int) $job['target_environment_id'],
                'candidate_id' => (int) $job['release_candidate_id'],
                'checks_json' => $healthJson,
                'evidence_hash' => $healthEvidence,
                'captured_by' => mb_substr($workerId, 0, 64),
                'captured_at' => $now,
            ]);
            $this->copyTargetSteps($pdo, (int) $job['id'], (string) $run['public_id']);
            $this->appendEvent($pdo, (int) $job['id'], 'promotion.completed', null, 'success', $healthEvidence);
            return [
                'promotion_public_id' => (string) $job['public_id'],
                'status' => 'completed',
                'deployment_run_public_id' => (string) $run['public_id'],
                'release_version' => (string) $job['release_version'],
                'environment' => $environmentKey,
                'evidence_hash' => $healthEvidence,
            ];
        });
    }

    /** @param array<string,mixed> $job @param array<string,mixed> $run */
    private function recordTargetRun(array $job, array $run, string $workerId): void
    {
        $targetRun = $this->targetRun((string) $run['public_id']);
        $this->database->transaction(function (PDO $pdo) use ($job, $run, $targetRun, $workerId): void {
            $evidence = (string) ($targetRun['evidence_hash'] ?? '');
            if (!preg_match('/^[a-f0-9]{64}$/', $evidence)) {
                $evidence = hash('sha256', implode('|', [
                    (string) $run['public_id'],
                    (string) $targetRun['run_status'],
                    (string) ($targetRun['backup_public_id'] ?? ''),
                ]));
            }
            $pdo->prepare(
                'UPDATE platform_release_promotions
                 SET deployment_run_public_id=:run_public_id,backup_public_id=:backup_public_id,
                     worker_id_hash=:worker_hash,evidence_hash=:evidence,updated_at=:updated_at WHERE id=:id'
            )->execute([
                'run_public_id' => (string) $run['public_id'],
                'backup_public_id' => $targetRun['backup_public_id'] === null
                    ? null : (string) $targetRun['backup_public_id'],
                'worker_hash' => hash('sha256', $workerId),
                'evidence' => $evidence,
                'updated_at' => $this->now(),
                'id' => (int) $job['id'],
            ]);
            $this->copyTargetSteps($pdo, (int) $job['id'], (string) $run['public_id']);
            $this->appendEvent($pdo, (int) $job['id'], 'deployment.applied', null, 'success', $evidence);
        });
    }

    /** @param array<string,mixed> $job @return array<string,mixed> */
    private function executeRollback(array $job, string $environmentKey, string $workerId): array
    {
        $result = $this->upgrades->rollback(
            (string) $job['deployment_run_public_id'],
            'rollback-' . strtolower((string) $job['public_id'])
        );
        return $this->database->transaction(function (PDO $pdo) use ($job, $result, $environmentKey, $workerId): array {
            $now = $this->now();
            $resultStatus = (string) ($result['run_status'] ?? $result['status'] ?? 'rolled_back');
            $evidence = hash('sha256', implode('|', [
                (string) $job['public_id'],
                (string) $job['deployment_run_public_id'],
                $resultStatus,
            ]));
            $pdo->prepare(
                "UPDATE platform_release_promotions
                 SET promotion_status='rolled_back',evidence_hash=:evidence,lease_expires_at=NULL,
                     worker_id_hash=:worker_hash,finished_at=:finished_at,updated_at=:updated_at WHERE id=:id"
            )->execute([
                'evidence' => $evidence,
                'worker_hash' => hash('sha256', $workerId),
                'finished_at' => $now,
                'updated_at' => $now,
                'id' => (int) $job['id'],
            ]);
            $pdo->prepare(
                "UPDATE platform_deployment_environments
                 SET current_candidate_id=:previous_candidate_id,readiness_status='unknown',
                     readiness_evidence_hash=NULL,last_health_at=NULL,worker_id_hash=:worker_hash,
                     worker_last_seen_at=:worker_seen,updated_at=:updated_at WHERE id=:environment_id"
            )->execute([
                'previous_candidate_id' => $job['previous_candidate_id'] === null
                    ? null : (int) $job['previous_candidate_id'],
                'worker_hash' => hash('sha256', $workerId),
                'worker_seen' => $now,
                'updated_at' => $now,
                'environment_id' => (int) $job['target_environment_id'],
            ]);
            $this->appendEvent($pdo, (int) $job['id'], 'rollback.completed', null, 'success', $evidence);
            return [
                'promotion_public_id' => (string) $job['public_id'],
                'status' => 'rolled_back',
                'environment' => $environmentKey,
                'evidence_hash' => $evidence,
            ];
        });
    }

    /** @param array<string,mixed> $job */
    private function recordFailure(array $job, string $environmentKey, string $workerId, Throwable $exception): void
    {
        $recovered = $this->recoverTargetRunIdentity($job);
        $errorCode = $this->errorCode($exception);
        $evidence = hash('sha256', implode('|', [
            (string) ($job['public_id'] ?? ''),
            $environmentKey,
            hash('sha256', $workerId),
            $errorCode,
            (string) ($recovered['public_id'] ?? ''),
        ]));
        $this->database->transaction(function (PDO $pdo) use ($job, $recovered, $errorCode, $evidence, $workerId): void {
            $now = $this->now();
            $pdo->prepare(
                "UPDATE platform_release_promotions
                 SET promotion_status='failed',failure_code=:failure_code,evidence_hash=:evidence,
                     deployment_run_public_id=COALESCE(:run_public_id,deployment_run_public_id),
                     backup_public_id=COALESCE(:backup_public_id,backup_public_id),
                     lease_expires_at=NULL,worker_id_hash=:worker_hash,
                     finished_at=:finished_at,updated_at=:updated_at WHERE id=:id"
            )->execute([
                'failure_code' => $errorCode,
                'evidence' => $evidence,
                'run_public_id' => $recovered['public_id'] ?? null,
                'backup_public_id' => $recovered['backup_public_id'] ?? null,
                'worker_hash' => hash('sha256', $workerId),
                'finished_at' => $now,
                'updated_at' => $now,
                'id' => (int) $job['id'],
            ]);
            $pdo->prepare(
                "UPDATE platform_deployment_environments
                 SET readiness_status='blocked',readiness_evidence_hash=:evidence,last_health_at=:last_health,
                     updated_at=:updated_at WHERE id=:environment_id"
            )->execute([
                'evidence' => $evidence,
                'last_health' => $now,
                'updated_at' => $now,
                'environment_id' => (int) $job['target_environment_id'],
            ]);
            if (isset($recovered['public_id'])) {
                $this->copyTargetSteps($pdo, (int) $job['id'], (string) $recovered['public_id']);
            }
            $this->appendEvent($pdo, (int) $job['id'], 'deployment.failed', null, 'failure', $evidence);
        });
        $this->incidents->open(
            (int) $job['account_scope'],
            'platform_release_promotion',
            (int) $job['id'],
            'critical',
            'Platform release deployment failed',
            [
                'promotion_public_id' => (string) $job['public_id'],
                'environment' => $environmentKey,
                'failure_code' => $errorCode,
                'evidence_hash' => $evidence,
            ]
        );
    }

    /** @param array<string,mixed> $job @return array<string,mixed> */
    private function recoverTargetRunIdentity(array $job): array
    {
        try {
            $statement = $this->targetDatabase->pdo()->prepare(
                "SELECT public_id,backup_public_id,run_status,evidence_hash
                 FROM platform_deployment_runs
                 WHERE request_id=:request_id AND operation='upgrade' ORDER BY id DESC LIMIT 1"
            );
            $statement->execute(['request_id' => 'promote-' . strtolower((string) $job['public_id'])]);
            $row = $statement->fetch(PDO::FETCH_ASSOC);
            return is_array($row) ? $row : [];
        } catch (Throwable) {
            return [];
        }
    }

    /** @return array<string,mixed> */
    private function targetRun(string $publicId): array
    {
        $statement = $this->targetDatabase->pdo()->prepare(
            'SELECT public_id,run_status,backup_public_id,error_code,evidence_hash,started_at,finished_at
             FROM platform_deployment_runs WHERE public_id=:public_id LIMIT 1'
        );
        $statement->execute(['public_id' => $publicId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('The target deployment run could not be loaded.');
        }
        return $row;
    }

    private function copyTargetSteps(PDO $control, int $promotionId, string $runPublicId): void
    {
        $statement = $this->targetDatabase->pdo()->prepare(
            "SELECT s.step_order,s.step_key,s.migration_path,s.step_status,s.evidence_hash,s.error_code,
                    s.started_at,s.completed_at
             FROM platform_deployment_steps s
             INNER JOIN platform_deployment_runs r ON r.id=s.deployment_run_id
             WHERE r.public_id=:public_id ORDER BY s.step_order,s.id"
        );
        $statement->execute(['public_id' => $runPublicId]);
        $control->prepare('DELETE FROM platform_release_promotion_steps WHERE promotion_id=:promotion_id')
            ->execute(['promotion_id' => $promotionId]);
        $insert = $control->prepare(
            'INSERT INTO platform_release_promotion_steps
             (promotion_id,step_order,step_key,migration_path,step_status,evidence_hash,error_code,started_at,completed_at)
             VALUES (:promotion_id,:step_order,:step_key,:migration_path,:step_status,:evidence_hash,:error_code,:started_at,:completed_at)'
        );
        foreach ($statement->fetchAll(PDO::FETCH_ASSOC) as $step) {
            $insert->execute([
                'promotion_id' => $promotionId,
                'step_order' => (int) $step['step_order'],
                'step_key' => (string) $step['step_key'],
                'migration_path' => $step['migration_path'] === null ? null : (string) $step['migration_path'],
                'step_status' => (string) $step['step_status'],
                'evidence_hash' => $step['evidence_hash'] === null ? null : (string) $step['evidence_hash'],
                'error_code' => $step['error_code'] === null ? null : mb_substr((string) $step['error_code'], 0, 100),
                'started_at' => $step['started_at'],
                'completed_at' => $step['completed_at'],
            ]);
        }
    }

    private function appendEvent(
        PDO $pdo,
        int $promotionId,
        string $eventType,
        ?int $actorUserId,
        string $result,
        string $metadataHash
    ): void {
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

    private function errorCode(Throwable $exception): string
    {
        $code = preg_replace(
            '/[^a-z0-9._:-]+/',
            '_',
            strtolower(trim($exception->getMessage()))
        ) ?: 'platform_release_worker_failed';
        return mb_substr(trim($code, '_'), 0, 100) ?: 'platform_release_worker_failed';
    }

    private function future(int $seconds): string
    {
        return (new DateTimeImmutable('+' . $seconds . ' seconds', new DateTimeZone('UTC')))
            ->format('Y-m-d H:i:s') . '.000000';
    }

    private function now(): string
    {
        return gmdate('Y-m-d H:i:s') . '.000000';
    }
}
