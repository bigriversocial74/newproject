<?php

declare(strict_types=1);

namespace Vp3\Deployment;

use PDO;
use RuntimeException;
use Throwable;
use Vp3\Database;

final class PlatformUpgradeService
{
    private const PHASE33_MIGRATION = 'migrations/20260731_phase33_production_deployment_upgrade.sql';

    /** @param array<string,mixed> $deploymentConfig */
    public function __construct(
        private readonly string $root,
        private readonly Database $database,
        private readonly array $deploymentConfig,
        private readonly ReleaseManifestService $releases,
        private readonly DeploymentPreflightService $preflight,
        private readonly DatabaseCommandService $commands
    ) {
    }

    /** @return array<string,mixed> */
    public function install(string $requestId): array
    {
        $requestId = $this->requestId($requestId);

        return $this->withLock(function (PDO $pdo) use ($requestId): array {
            $report = $this->preflight->inspect($pdo);
            if (($report['ok'] ?? false) !== true) {
                throw new RuntimeException(
                    'platform_install_preflight_failed:' . implode(',', (array) ($report['failures'] ?? []))
                );
            }
            if (!$this->databaseIsEmpty($pdo)) {
                throw new RuntimeException('platform_install_database_not_empty');
            }

            $release = $this->releases->build();
            $this->commands->importSqlFile($this->root . '/' . (string) $release['installer']['path']);
            $run = $this->createRun(
                $pdo,
                $requestId,
                'install',
                null,
                (string) $release['version'],
                'verifying'
            );
            $this->recordAllMigrations($pdo, (string) $release['version'], 'fresh_install');
            $verification = $this->verifyCurrentRelease($pdo, $release);
            $this->activateRelease($pdo, $release);
            $this->completeRun($pdo, (int) $run['id'], (string) $verification['evidence_hash']);
            $this->receipt(
                $pdo,
                (int) $run['id'],
                $requestId,
                'platform_install',
                'success',
                (string) $verification['evidence_hash']
            );

            return $this->publicRun($pdo, (int) $run['id']);
        });
    }

    /** @return array<string,mixed> */
    public function upgrade(string $requestId): array
    {
        $requestId = $this->requestId($requestId);

        return $this->withLock(function (PDO $pdo) use ($requestId): array {
            $release = $this->releases->build();
            if ($this->hasTable($pdo, 'platform_deployment_receipts')) {
                $prior = $this->priorRun($pdo, $requestId, 'platform_upgrade');
                if (is_array($prior)) {
                    if (hash_equals((string) $prior['to_release_version'], (string) $release['version'])) {
                        return $this->publicRun($pdo, (int) $prior['id']);
                    }
                    throw new RuntimeException('platform_upgrade_request_conflict');
                }
            }

            $report = $this->preflight->inspect($pdo);
            if (($report['ok'] ?? false) !== true) {
                throw new RuntimeException(
                    'platform_upgrade_preflight_failed:' . implode(',', (array) ($report['failures'] ?? []))
                );
            }
            if (!$this->hasTable($pdo, 'security_response_actions')) {
                throw new RuntimeException('platform_upgrade_phase32_baseline_required');
            }

            $fromRelease = $this->activeReleaseVersion($pdo) ?? '32.0.0';
            $backupPublicId = 'PLATFORM-BACKUP-' . strtoupper(bin2hex(random_bytes(10)));
            $runPublicId = 'PLATFORM-RUN-' . strtoupper(bin2hex(random_bytes(10)));
            $journal = $this->writeJournal([
                'run_public_id' => $runPublicId,
                'request_id' => $requestId,
                'operation' => 'upgrade',
                'from_release_version' => $fromRelease,
                'to_release_version' => (string) $release['version'],
                'backup_public_id' => $backupPublicId,
                'status' => 'backing_up',
            ]);

            $runId = null;
            $backup = null;
            try {
                if ($this->hasTable($pdo, 'platform_deployment_runs')) {
                    $run = $this->createRun(
                        $pdo,
                        $requestId,
                        'upgrade',
                        $fromRelease,
                        (string) $release['version'],
                        'backing_up',
                        $runPublicId
                    );
                    $runId = (int) $run['id'];
                }

                $backup = $this->commands->createBackup($pdo, $backupPublicId);
                $this->updateJournal($journal, [
                    'status' => 'backup_verified',
                    'backup_sha256' => (string) $backup['sha256'],
                ]);

                $phase33Bootstrapped = false;
                if (!$this->hasTable($pdo, 'platform_schema_migrations')) {
                    $this->commands->importSqlFile($this->root . '/database/' . self::PHASE33_MIGRATION);
                    $phase33Bootstrapped = true;
                }

                if ($runId === null) {
                    $run = $this->createRun(
                        $pdo,
                        $requestId,
                        'upgrade',
                        $fromRelease,
                        (string) $release['version'],
                        'applying',
                        $runPublicId
                    );
                    $runId = (int) $run['id'];
                }

                $this->attachBackup($pdo, $runId, $backupPublicId, $backup);
                $this->setRunStatus($pdo, $runId, 'applying');
                $this->baselinePhase32($pdo, (string) $release['version'], $phase33Bootstrapped);
                $applied = $this->applyPendingMigrations($pdo, $runId, (string) $release['version']);

                $this->setRunStatus($pdo, $runId, 'verifying');
                $verification = $this->verifyCurrentRelease($pdo, $release);
                $this->activateRelease($pdo, $release);
                $this->completeRun($pdo, $runId, (string) $verification['evidence_hash']);
                $this->receipt(
                    $pdo,
                    $runId,
                    $requestId,
                    'platform_upgrade',
                    'success',
                    (string) $verification['evidence_hash']
                );
                $this->updateJournal($journal, [
                    'status' => 'completed',
                    'evidence_hash' => (string) $verification['evidence_hash'],
                    'applied_migrations' => $applied,
                ]);

                return $this->publicRun($pdo, $runId);
            } catch (Throwable $exception) {
                $errorCode = $this->errorCode($exception);
                $this->updateJournal($journal, ['status' => 'failed', 'error_code' => $errorCode]);
                if ($runId !== null && $this->hasTable($pdo, 'platform_deployment_runs')) {
                    $this->failRun($pdo, $runId, $errorCode);
                }

                if (is_array($backup)) {
                    try {
                        if ($runId !== null && $this->hasTable($pdo, 'platform_deployment_runs')) {
                            $this->setRunStatus($pdo, $runId, 'rolling_back');
                        }
                        $this->commands->restoreBackup(
                            $pdo,
                            (string) $backup['path'],
                            (string) $backup['sha256']
                        );
                        $this->updateJournal($journal, ['status' => 'rolled_back']);
                        if ($this->hasTable($pdo, 'platform_deployment_runs')) {
                            $restoredRun = $this->runByPublicId($pdo, $runPublicId);
                            if (is_array($restoredRun)) {
                                $this->setRunStatus($pdo, (int) $restoredRun['id'], 'rolled_back');
                            }
                        }
                    } catch (Throwable $rollbackException) {
                        $this->updateJournal($journal, [
                            'status' => 'rollback_failed',
                            'rollback_error_code' => $this->errorCode($rollbackException),
                        ]);
                    }
                }

                throw $exception;
            }
        });
    }

    /** @return array<string,mixed> */
    public function verify(): array
    {
        return $this->withLock(function (PDO $pdo): array {
            $report = $this->preflight->inspect($pdo, true);
            $release = $this->releases->build();
            $verification = $this->verifyCurrentRelease($pdo, $release);

            return [
                'ok' => ($report['ok'] ?? false) === true,
                'preflight' => $report,
                'release' => $verification,
            ];
        });
    }

    /** @return array<string,mixed> */
    public function rollback(string $runPublicId, string $requestId): array
    {
        $requestId = $this->requestId($requestId);
        $runPublicId = trim($runPublicId);

        return $this->withLock(function (PDO $pdo) use ($runPublicId, $requestId): array {
            if (!$this->hasTable($pdo, 'platform_deployment_runs')) {
                throw new RuntimeException('platform_rollback_ledger_missing');
            }
            $run = $this->runByPublicId($pdo, $runPublicId);
            if (!is_array($run) || $run['backup_public_id'] === null) {
                throw new RuntimeException('platform_rollback_run_invalid');
            }
            $prior = $this->priorRun($pdo, $requestId, 'platform_rollback');
            if (is_array($prior)) {
                return $this->publicRun($pdo, (int) $prior['id']);
            }

            $backupStatement = $pdo->prepare(
                'SELECT * FROM platform_deployment_backups
                 WHERE deployment_run_id=:run_id AND public_id=:public_id LIMIT 1'
            );
            $backupStatement->execute([
                'run_id' => (int) $run['id'],
                'public_id' => (string) $run['backup_public_id'],
            ]);
            $backup = $backupStatement->fetch(PDO::FETCH_ASSOC);
            if (!is_array($backup)) {
                throw new RuntimeException('platform_rollback_backup_missing');
            }

            $journal = $this->writeJournal([
                'run_public_id' => $runPublicId,
                'request_id' => $requestId,
                'operation' => 'rollback',
                'backup_public_id' => (string) $backup['public_id'],
                'status' => 'rolling_back',
            ]);
            $path = rtrim((string) $this->deploymentConfig['backup_root'], DIRECTORY_SEPARATOR)
                . DIRECTORY_SEPARATOR . (string) $backup['public_id'] . '.sql';
            $this->setRunStatus($pdo, (int) $run['id'], 'rolling_back');
            $this->commands->restoreBackup($pdo, $path, (string) $backup['file_sha256']);
            $this->updateJournal($journal, ['status' => 'rolled_back']);

            if ($this->hasTable($pdo, 'platform_deployment_runs')) {
                $restored = $this->runByPublicId($pdo, $runPublicId);
                if (is_array($restored)) {
                    $this->setRunStatus($pdo, (int) $restored['id'], 'rolled_back');
                    $this->receipt(
                        $pdo,
                        (int) $restored['id'],
                        $requestId,
                        'platform_rollback',
                        'success',
                        hash('sha256', implode('|', [
                            $runPublicId,
                            (string) $backup['file_sha256'],
                            $requestId,
                        ]))
                    );
                    return $this->publicRun($pdo, (int) $restored['id']);
                }
            }

            return ['public_id' => $runPublicId, 'run_status' => 'rolled_back'];
        });
    }

    /** @param array<string,mixed> $release @return array<string,mixed> */
    private function verifyCurrentRelease(PDO $pdo, array $release): array
    {
        if (!$this->hasTable($pdo, 'platform_schema_migrations')) {
            throw new RuntimeException('platform_schema_migration_ledger_missing');
        }
        $stored = $pdo->query(
            'SELECT migration_path,migration_sha256 FROM platform_schema_migrations ORDER BY id ASC'
        )->fetchAll(PDO::FETCH_KEY_PAIR);
        $missing = [];
        $mismatched = [];
        foreach ($this->releases->migrationPaths() as $path) {
            $expected = $this->releases->migrationSha256($path);
            if (!isset($stored[$path])) {
                $missing[] = $path;
            } elseif (!hash_equals($expected, (string) $stored[$path])) {
                $mismatched[] = $path;
            }
        }
        if ($missing !== [] || $mismatched !== []) {
            throw new RuntimeException('platform_schema_verification_failed');
        }

        foreach ([
            'accounts',
            'auth_sessions',
            'pod_deployments',
            'homeserver_devices',
            'operational_incidents',
            'security_audit_events',
            'security_incident_cases',
            'platform_deployment_runs',
        ] as $table) {
            if (!$this->hasTable($pdo, $table)) {
                throw new RuntimeException('platform_smoke_table_missing_' . $table);
            }
        }
        if ((int) $pdo->query('SELECT 1')->fetchColumn() !== 1) {
            throw new RuntimeException('platform_database_smoke_failed');
        }

        $evidence = hash('sha256', $this->releases->canonicalJson([
            'release_version' => (string) $release['version'],
            'commit_sha' => (string) $release['commit_sha'],
            'manifest_sha256' => (string) $release['manifest_sha256'],
            'installer_sha256' => (string) $release['installer']['sha256'],
            'migration_count' => count($stored),
            'verified_paths' => array_keys($stored),
        ]));

        return [
            'version' => (string) $release['version'],
            'commit_sha' => (string) $release['commit_sha'],
            'schema_level' => (int) $release['schema_level'],
            'migration_count' => count($stored),
            'evidence_hash' => $evidence,
        ];
    }

    /** @return list<string> */
    private function applyPendingMigrations(PDO $pdo, int $runId, string $releaseVersion): array
    {
        $stored = $pdo->query(
            'SELECT migration_path,migration_sha256 FROM platform_schema_migrations'
        )->fetchAll(PDO::FETCH_KEY_PAIR);
        $applied = [];
        $stepOrder = 100;

        foreach ($this->releases->migrationPaths() as $path) {
            $sha = $this->releases->migrationSha256($path);
            if (isset($stored[$path])) {
                if (!hash_equals($sha, (string) $stored[$path])) {
                    throw new RuntimeException('platform_migration_checksum_changed');
                }
                continue;
            }

            $stepKey = 'migration:' . $path;
            $this->startStep($pdo, $runId, $stepOrder++, $stepKey, $path);
            try {
                $this->commands->importSqlFile($this->root . '/database/' . $path);
                $pdo->prepare(
                    "INSERT INTO platform_schema_migrations
                     (migration_path,migration_sha256,applied_release_version,application_mode,applied_at)
                     VALUES (:path,:sha,:release,'upgrade',:applied_at)"
                )->execute([
                    'path' => $path,
                    'sha' => $sha,
                    'release' => $releaseVersion,
                    'applied_at' => $this->now(),
                ]);
                $this->completeStep($pdo, $runId, $stepKey, hash('sha256', $path . '|' . $sha));
                $applied[] = $path;
            } catch (Throwable $exception) {
                $this->failStep($pdo, $runId, $stepKey, $this->errorCode($exception));
                throw $exception;
            }
        }

        return $applied;
    }

    private function baselinePhase32(PDO $pdo, string $releaseVersion, bool $phase33Bootstrapped): void
    {
        if ((int) $pdo->query('SELECT COUNT(*) FROM platform_schema_migrations')->fetchColumn() > 0) {
            return;
        }

        foreach ($this->releases->migrationPaths() as $path) {
            if ($path === self::PHASE33_MIGRATION && !$phase33Bootstrapped) {
                break;
            }
            $mode = $path === self::PHASE33_MIGRATION ? 'upgrade' : 'baseline';
            $pdo->prepare(
                'INSERT INTO platform_schema_migrations
                 (migration_path,migration_sha256,applied_release_version,application_mode,applied_at)
                 VALUES (:path,:sha,:release,:mode,:applied_at)'
            )->execute([
                'path' => $path,
                'sha' => $this->releases->migrationSha256($path),
                'release' => $releaseVersion,
                'mode' => $mode,
                'applied_at' => $this->now(),
            ]);
            if ($path === self::PHASE33_MIGRATION) {
                break;
            }
        }
    }

    private function recordAllMigrations(PDO $pdo, string $releaseVersion, string $mode): void
    {
        foreach ($this->releases->migrationPaths() as $path) {
            $pdo->prepare(
                'INSERT INTO platform_schema_migrations
                 (migration_path,migration_sha256,applied_release_version,application_mode,applied_at)
                 VALUES (:path,:sha,:release,:mode,:applied_at)
                 ON DUPLICATE KEY UPDATE migration_sha256=VALUES(migration_sha256),
                   applied_release_version=VALUES(applied_release_version),application_mode=VALUES(application_mode)'
            )->execute([
                'path' => $path,
                'sha' => $this->releases->migrationSha256($path),
                'release' => $releaseVersion,
                'mode' => $mode,
                'applied_at' => $this->now(),
            ]);
        }
    }

    /** @return array{id:int,public_id:string} */
    private function createRun(
        PDO $pdo,
        string $requestId,
        string $operation,
        ?string $fromRelease,
        string $toRelease,
        string $status,
        ?string $publicId = null
    ): array {
        $publicId ??= 'PLATFORM-RUN-' . strtoupper(bin2hex(random_bytes(10)));
        $now = $this->now();
        $pdo->prepare(
            'INSERT INTO platform_deployment_runs
             (public_id,request_id,operation,from_release_version,to_release_version,run_status,
              backup_public_id,lock_owner_hash,error_code,evidence_hash,started_at,finished_at,created_at,updated_at)
             VALUES (:public_id,:request_id,:operation,:from_release,:to_release,:status,
              NULL,:lock_owner_hash,NULL,NULL,:started_at,NULL,:created_at,:updated_at)'
        )->execute([
            'public_id' => $publicId,
            'request_id' => $requestId,
            'operation' => $operation,
            'from_release' => $fromRelease,
            'to_release' => $toRelease,
            'status' => $status,
            'lock_owner_hash' => hash('sha256', gethostname() . '|' . getmypid()),
            'started_at' => $now,
            'created_at' => $now,
            'updated_at' => $now,
        ]);

        return ['id' => (int) $pdo->lastInsertId(), 'public_id' => $publicId];
    }

    /** @param array<string,mixed> $backup */
    private function attachBackup(PDO $pdo, int $runId, string $publicId, array $backup): void
    {
        $now = $this->now();
        $pdo->prepare(
            "INSERT INTO platform_deployment_backups
             (public_id,deployment_run_id,file_path_hash,file_sha256,file_bytes,database_engine,database_version,
              backup_status,created_at,verified_at,restored_at)
             VALUES (:public_id,:run_id,:path_hash,:sha,:bytes,:engine,:version,'verified',:created_at,:verified_at,NULL)"
        )->execute([
            'public_id' => $publicId,
            'run_id' => $runId,
            'path_hash' => $backup['path_hash'],
            'sha' => $backup['sha256'],
            'bytes' => $backup['bytes'],
            'engine' => $backup['engine'],
            'version' => $backup['version'],
            'created_at' => $now,
            'verified_at' => $now,
        ]);
        $pdo->prepare(
            'UPDATE platform_deployment_runs
             SET backup_public_id=:backup,updated_at=:updated_at WHERE id=:id'
        )->execute(['backup' => $publicId, 'updated_at' => $now, 'id' => $runId]);
    }

    /** @param array<string,mixed> $release */
    private function activateRelease(PDO $pdo, array $release): void
    {
        $now = $this->now();
        $pdo->prepare(
            "UPDATE platform_release_records
             SET release_status='superseded',updated_at=:updated_at WHERE release_status='active'"
        )->execute(['updated_at' => $now]);
        $pdo->prepare(
            "INSERT INTO platform_release_records
             (public_id,release_version,commit_sha,schema_level,installer_sha256,source_manifest_sha256,
              release_manifest_sha256,migration_count,release_status,activated_at,created_at,updated_at)
             VALUES (:public_id,:version,:commit,:schema_level,:installer_sha,:source_sha,:manifest_sha,
              :migration_count,'active',:activated_at,:created_at,:updated_at)
             ON DUPLICATE KEY UPDATE schema_level=VALUES(schema_level),installer_sha256=VALUES(installer_sha256),
              source_manifest_sha256=VALUES(source_manifest_sha256),release_manifest_sha256=VALUES(release_manifest_sha256),
              migration_count=VALUES(migration_count),release_status='active',activated_at=VALUES(activated_at),updated_at=VALUES(updated_at)"
        )->execute([
            'public_id' => 'PLATFORM-RELEASE-' . strtoupper(bin2hex(random_bytes(10))),
            'version' => $release['version'],
            'commit' => $release['commit_sha'],
            'schema_level' => $release['schema_level'],
            'installer_sha' => $release['installer']['sha256'],
            'source_sha' => $release['migration_manifest']['sha256'],
            'manifest_sha' => $release['manifest_sha256'],
            'migration_count' => $release['migration_count'],
            'activated_at' => $now,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
    }

    /** @return array<string,mixed>|null */
    private function priorRun(PDO $pdo, string $requestId, string $action): ?array
    {
        $statement = $pdo->prepare(
            'SELECT r.* FROM platform_deployment_receipts p
             INNER JOIN platform_deployment_runs r ON r.id=p.deployment_run_id
             WHERE p.request_id=:request_id AND p.action_type=:action AND p.result=:result LIMIT 1'
        );
        $statement->execute([
            'request_id' => $requestId,
            'action' => $action,
            'result' => 'success',
        ]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $row : null;
    }

    private function receipt(
        PDO $pdo,
        ?int $runId,
        string $requestId,
        string $action,
        string $result,
        string $evidence
    ): void {
        $pdo->prepare(
            'INSERT INTO platform_deployment_receipts
             (public_id,deployment_run_id,request_id,action_type,result,evidence_hash,created_at)
             VALUES (:public_id,:run_id,:request_id,:action,:result,:evidence,:created_at)'
        )->execute([
            'public_id' => 'PLATFORM-RECEIPT-' . strtoupper(bin2hex(random_bytes(10))),
            'run_id' => $runId,
            'request_id' => $requestId,
            'action' => $action,
            'result' => $result,
            'evidence' => $evidence,
            'created_at' => $this->now(),
        ]);
    }

    private function startStep(PDO $pdo, int $runId, int $order, string $key, ?string $migration): void
    {
        $pdo->prepare(
            "INSERT INTO platform_deployment_steps
             (deployment_run_id,step_order,step_key,migration_path,step_status,evidence_hash,error_code,started_at,completed_at)
             VALUES (:run_id,:step_order,:step_key,:migration,'running',NULL,NULL,:started_at,NULL)"
        )->execute([
            'run_id' => $runId,
            'step_order' => $order,
            'step_key' => $key,
            'migration' => $migration,
            'started_at' => $this->now(),
        ]);
    }

    private function completeStep(PDO $pdo, int $runId, string $key, string $evidence): void
    {
        $pdo->prepare(
            "UPDATE platform_deployment_steps
             SET step_status='completed',evidence_hash=:evidence,completed_at=:completed_at
             WHERE deployment_run_id=:run_id AND step_key=:step_key"
        )->execute([
            'evidence' => $evidence,
            'completed_at' => $this->now(),
            'run_id' => $runId,
            'step_key' => $key,
        ]);
    }

    private function failStep(PDO $pdo, int $runId, string $key, string $errorCode): void
    {
        $pdo->prepare(
            "UPDATE platform_deployment_steps
             SET step_status='failed',error_code=:error_code,completed_at=:completed_at
             WHERE deployment_run_id=:run_id AND step_key=:step_key"
        )->execute([
            'error_code' => $errorCode,
            'completed_at' => $this->now(),
            'run_id' => $runId,
            'step_key' => $key,
        ]);
    }

    private function setRunStatus(PDO $pdo, int $runId, string $status): void
    {
        $pdo->prepare(
            'UPDATE platform_deployment_runs
             SET run_status=:status,updated_at=:updated_at WHERE id=:id'
        )->execute(['status' => $status, 'updated_at' => $this->now(), 'id' => $runId]);
    }

    private function completeRun(PDO $pdo, int $runId, string $evidence): void
    {
        $now = $this->now();
        $pdo->prepare(
            "UPDATE platform_deployment_runs
             SET run_status='completed',evidence_hash=:evidence,finished_at=:finished_at,updated_at=:updated_at
             WHERE id=:id"
        )->execute([
            'evidence' => $evidence,
            'finished_at' => $now,
            'updated_at' => $now,
            'id' => $runId,
        ]);
    }

    private function failRun(PDO $pdo, int $runId, string $errorCode): void
    {
        $now = $this->now();
        $pdo->prepare(
            "UPDATE platform_deployment_runs
             SET run_status='failed',error_code=:error_code,finished_at=:finished_at,updated_at=:updated_at
             WHERE id=:id"
        )->execute([
            'error_code' => $errorCode,
            'finished_at' => $now,
            'updated_at' => $now,
            'id' => $runId,
        ]);
    }

    /** @return array<string,mixed> */
    private function publicRun(PDO $pdo, int $runId): array
    {
        $statement = $pdo->prepare(
            'SELECT public_id,request_id,operation,from_release_version,to_release_version,run_status,
                    backup_public_id,error_code,evidence_hash,started_at,finished_at
             FROM platform_deployment_runs WHERE id=:id LIMIT 1'
        );
        $statement->execute(['id' => $runId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('platform_deployment_run_missing');
        }
        return $row;
    }

    /** @return array<string,mixed>|null */
    private function runByPublicId(PDO $pdo, string $publicId): ?array
    {
        $statement = $pdo->prepare(
            'SELECT * FROM platform_deployment_runs WHERE public_id=:public_id LIMIT 1'
        );
        $statement->execute(['public_id' => $publicId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $row : null;
    }

    private function activeReleaseVersion(PDO $pdo): ?string
    {
        if (!$this->hasTable($pdo, 'platform_release_records')) {
            return null;
        }
        $value = $pdo->query(
            "SELECT release_version FROM platform_release_records
             WHERE release_status='active' ORDER BY id DESC LIMIT 1"
        )->fetchColumn();
        return is_string($value) ? $value : null;
    }

    private function databaseIsEmpty(PDO $pdo): bool
    {
        return (int) $pdo->query(
            "SELECT COUNT(*) FROM information_schema.tables
             WHERE table_schema=DATABASE() AND table_type='BASE TABLE'"
        )->fetchColumn() === 0;
    }

    private function hasTable(PDO $pdo, string $table): bool
    {
        $statement = $pdo->prepare(
            'SELECT COUNT(*) FROM information_schema.tables
             WHERE table_schema=DATABASE() AND table_name=:table'
        );
        $statement->execute(['table' => $table]);
        return (int) $statement->fetchColumn() === 1;
    }

    /** @template T @param callable(PDO):T $callback @return T */
    private function withLock(callable $callback): mixed
    {
        $pdo = $this->database->pdo();
        $lockName = (string) ($this->deploymentConfig['lock_name'] ?? 'vp3-platform-deployment');
        if (!preg_match('/^[A-Za-z0-9._:-]{8,64}$/', $lockName)) {
            throw new RuntimeException('VP3_PLATFORM_DEPLOYMENT_LOCK_NAME is invalid.');
        }
        $statement = $pdo->prepare('SELECT GET_LOCK(:lock_name,0)');
        $statement->execute(['lock_name' => $lockName]);
        if ((int) $statement->fetchColumn() !== 1) {
            throw new RuntimeException('platform_deployment_lock_unavailable');
        }

        try {
            return $callback($pdo);
        } finally {
            $release = $pdo->prepare('SELECT RELEASE_LOCK(:lock_name)');
            $release->execute(['lock_name' => $lockName]);
        }
    }

    /** @param array<string,mixed> $document */
    private function writeJournal(array $document): string
    {
        $root = rtrim((string) ($this->deploymentConfig['backup_root'] ?? ''), DIRECTORY_SEPARATOR);
        if ($root === '' || !str_starts_with($root, DIRECTORY_SEPARATOR)) {
            throw new RuntimeException('VP3_PLATFORM_BACKUP_ROOT must be an absolute path.');
        }
        if (!is_dir($root) && !mkdir($root, 0700, true) && !is_dir($root)) {
            throw new RuntimeException('Unable to create the deployment journal directory.');
        }
        @chmod($root, 0700);
        $path = $root . DIRECTORY_SEPARATOR . (string) $document['run_public_id'] . '.json';
        $this->atomicJson($path, $document);
        return $path;
    }

    /** @param array<string,mixed> $changes */
    private function updateJournal(string $path, array $changes): void
    {
        $current = [];
        if (is_file($path)) {
            $decoded = json_decode((string) file_get_contents($path), true);
            if (is_array($decoded)) {
                $current = $decoded;
            }
        }
        $this->atomicJson($path, array_merge($current, $changes));
    }

    /** @param array<string,mixed> $document */
    private function atomicJson(string $path, array $document): void
    {
        $temporary = $path . '.tmp-' . bin2hex(random_bytes(5));
        $bytes = file_put_contents(
            $temporary,
            $this->releases->canonicalJson($document) . "\n",
            LOCK_EX
        );
        if (!is_int($bytes) || $bytes < 1) {
            @unlink($temporary);
            throw new RuntimeException('Unable to write the deployment journal.');
        }
        @chmod($temporary, 0600);
        if (!rename($temporary, $path)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to publish the deployment journal atomically.');
        }
    }

    private function requestId(string $requestId): string
    {
        $requestId = trim($requestId);
        if (!preg_match('/^[A-Za-z0-9._:-]{8,80}$/', $requestId)) {
            throw new RuntimeException('A valid deployment request ID is required.');
        }
        return $requestId;
    }

    private function errorCode(Throwable $exception): string
    {
        $message = strtolower($exception->getMessage());
        $code = preg_replace('/[^a-z0-9._:-]+/', '_', $message) ?: 'platform_deployment_failed';
        return mb_substr(trim($code, '_'), 0, 80) ?: 'platform_deployment_failed';
    }

    private function now(): string
    {
        return gmdate('Y-m-d H:i:s') . '.000000';
    }
}
