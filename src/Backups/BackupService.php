<?php

declare(strict_types=1);

namespace Vp3\Backups;

use PDO;
use RuntimeException;
use Throwable;
use Vp3\Database;

final class BackupService
{
    public function __construct(
        private readonly Database $database,
        private readonly BackupProviderAdapter $adapter,
        private readonly BackupMetadataCipher $cipher,
        private readonly float $warningThreshold = 80.0,
        private readonly float $criticalThreshold = 95.0
    ) {
    }

    /** @return array{policy_id:int,policy_public_id:string} */
    public function savePolicy(
        int $accountId,
        string $targetType,
        int $targetId,
        int $intervalMinutes,
        int $retentionCount,
        int $retentionDays,
        string $requestId
    ): array {
        $this->requiredAccountTarget($accountId, $targetType, $targetId);
        if ($intervalMinutes < 15 || $retentionCount < 1 || $retentionDays < 1 || trim($requestId) === '') {
            throw new RuntimeException('Backup policy interval, retention, and request ID are invalid.');
        }
        return $this->database->transaction(function (PDO $pdo) use (
            $accountId, $targetType, $targetId, $intervalMinutes, $retentionCount, $retentionDays, $requestId
        ): array {
            $this->target($pdo, $accountId, $targetType, $targetId, true);
            $column = $targetType === 'pod' ? 'pod_deployment_id' : 'homeserver_device_id';
            $find = $pdo->prepare("SELECT id,public_id FROM backup_policies WHERE {$column}=:target LIMIT 1 FOR UPDATE");
            $find->execute(['target' => $targetId]);
            $policy = $find->fetch(PDO::FETCH_ASSOC);
            if (!is_array($policy)) {
                $publicId = 'BACKUP-POLICY-' . strtoupper(bin2hex(random_bytes(12)));
                $pdo->prepare(
                    'INSERT INTO backup_policies
                     (public_id,account_id,target_type,pod_deployment_id,homeserver_device_id,status,
                      schedule_interval_minutes,retention_count,retention_days,require_verification,next_run_at,created_at,updated_at)
                     VALUES (:public,:account,:target_type,:pod,:homeserver,\'active\',:interval,:retention_count,:retention_days,1,
                             UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())'
                )->execute([
                    'public' => $publicId,
                    'account' => $accountId,
                    'target_type' => $targetType,
                    'pod' => $targetType === 'pod' ? $targetId : null,
                    'homeserver' => $targetType === 'homeserver' ? $targetId : null,
                    'interval' => $intervalMinutes,
                    'retention_count' => $retentionCount,
                    'retention_days' => $retentionDays,
                ]);
                $policy = ['id' => (int) $pdo->lastInsertId(), 'public_id' => $publicId];
            } else {
                $pdo->prepare(
                    "UPDATE backup_policies SET status='active',schedule_interval_minutes=:interval,
                     retention_count=:retention_count,retention_days=:retention_days,require_verification=1,
                     next_run_at=COALESCE(next_run_at,UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=:id AND account_id=:account"
                )->execute([
                    'interval' => $intervalMinutes,
                    'retention_count' => $retentionCount,
                    'retention_days' => $retentionDays,
                    'id' => $policy['id'],
                    'account' => $accountId,
                ]);
            }
            $this->receipt($pdo, $accountId, null, null, null, $requestId, 'backup_policy_saved', 'success', null, [
                'policy_id' => (int) $policy['id'],
                'target_type' => $targetType,
                'target_id' => $targetId,
                'interval_minutes' => $intervalMinutes,
                'retention_count' => $retentionCount,
                'retention_days' => $retentionDays,
            ]);
            return ['policy_id' => (int) $policy['id'], 'policy_public_id' => (string) $policy['public_id']];
        });
    }

    public function enqueueDuePolicies(int $limit = 50): int
    {
        $count = 0;
        while ($count < max(1, $limit)) {
            $policy = $this->database->transaction(function (PDO $pdo): ?array {
                $row = $pdo->query(
                    "SELECT * FROM backup_policies WHERE status='active' AND next_run_at<=UTC_TIMESTAMP()
                     ORDER BY next_run_at,id LIMIT 1 FOR UPDATE SKIP LOCKED"
                )->fetch(PDO::FETCH_ASSOC);
                if (!is_array($row)) {
                    return null;
                }
                $pdo->prepare(
                    'UPDATE backup_policies SET next_run_at=DATE_ADD(UTC_TIMESTAMP(),INTERVAL schedule_interval_minutes MINUTE),
                     last_run_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE id=:id'
                )->execute(['id' => $row['id']]);
                return $row;
            });
            if ($policy === null) {
                break;
            }
            $targetId = $policy['target_type'] === 'pod' ? (int) $policy['pod_deployment_id'] : (int) $policy['homeserver_device_id'];
            $bucket = gmdate('YmdHi');
            $this->enqueueBackup(
                (int) $policy['account_id'],
                (string) $policy['target_type'],
                $targetId,
                'scheduled',
                'BACKUP-SCHEDULE-' . $policy['id'] . '-' . $bucket,
                'scheduled:' . $policy['id'] . ':' . $bucket,
                (int) $policy['id']
            );
            $count++;
        }
        return $count;
    }

    /** @return array{job_id:int,job_public_id:string,replayed:bool} */
    public function enqueueBackup(
        int $accountId,
        string $targetType,
        int $targetId,
        string $jobType,
        string $requestId,
        string $idempotencyKey,
        ?int $policyId = null
    ): array {
        $this->requiredAccountTarget($accountId, $targetType, $targetId);
        if (!in_array($jobType, ['scheduled', 'on_demand', 'pre_update'], true)
            || trim($requestId) === '' || trim($idempotencyKey) === '') {
            throw new RuntimeException('Backup job type, request ID, and idempotency key are required.');
        }
        return $this->database->transaction(function (PDO $pdo) use (
            $accountId, $targetType, $targetId, $jobType, $requestId, $idempotencyKey, $policyId
        ): array {
            $this->target($pdo, $accountId, $targetType, $targetId, true);
            if ($policyId !== null) {
                $policy = $pdo->prepare('SELECT id FROM backup_policies WHERE id=:id AND account_id=:account AND target_type=:target_type LIMIT 1');
                $policy->execute(['id' => $policyId, 'account' => $accountId, 'target_type' => $targetType]);
                if (!$policy->fetchColumn()) {
                    throw new RuntimeException('Backup policy does not belong to this account and target type.');
                }
            }
            $existing = $pdo->prepare('SELECT id,public_id,target_type,pod_deployment_id,homeserver_device_id,job_type FROM backup_jobs WHERE account_id=:account AND idempotency_key=:key LIMIT 1 FOR UPDATE');
            $existing->execute(['account' => $accountId, 'key' => $idempotencyKey]);
            $row = $existing->fetch(PDO::FETCH_ASSOC);
            if (is_array($row)) {
                $existingTarget = $row['target_type'] === 'pod' ? (int) $row['pod_deployment_id'] : (int) $row['homeserver_device_id'];
                if ($row['target_type'] !== $targetType || $existingTarget !== $targetId || $row['job_type'] !== $jobType) {
                    throw new RuntimeException('Backup idempotency key was reused for another request.');
                }
                return ['job_id' => (int) $row['id'], 'job_public_id' => (string) $row['public_id'], 'replayed' => true];
            }
            $publicId = 'BACKUP-JOB-' . strtoupper(bin2hex(random_bytes(12)));
            $pdo->prepare(
                'INSERT INTO backup_jobs
                 (public_id,account_id,policy_id,target_type,pod_deployment_id,homeserver_device_id,job_type,status,
                  idempotency_key,request_id,available_at,created_at,updated_at)
                 VALUES (:public,:account,:policy,:target_type,:pod,:homeserver,:job_type,\'queued\',:key,:request,
                         UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())'
            )->execute([
                'public' => $publicId,
                'account' => $accountId,
                'policy' => $policyId,
                'target_type' => $targetType,
                'pod' => $targetType === 'pod' ? $targetId : null,
                'homeserver' => $targetType === 'homeserver' ? $targetId : null,
                'job_type' => $jobType,
                'key' => $idempotencyKey,
                'request' => $requestId,
            ]);
            $jobId = (int) $pdo->lastInsertId();
            $this->receipt($pdo, $accountId, $jobId, null, null, $requestId, 'backup_queued', 'success', null, [
                'target_type' => $targetType,
                'target_id' => $targetId,
                'job_type' => $jobType,
            ]);
            return ['job_id' => $jobId, 'job_public_id' => $publicId, 'replayed' => false];
        });
    }

    /** @return array<string,mixed>|null */
    public function processNextBackup(string $workerId): ?array
    {
        if (trim($workerId) === '') {
            throw new RuntimeException('Backup worker ID is required.');
        }
        $job = $this->database->transaction(function (PDO $pdo) use ($workerId): ?array {
            $row = $pdo->query(
                "SELECT * FROM backup_jobs WHERE status IN ('queued','running') AND available_at<=UTC_TIMESTAMP()
                 ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED"
            )->fetch(PDO::FETCH_ASSOC);
            if (!is_array($row)) {
                return null;
            }
            $pdo->prepare(
                "UPDATE backup_jobs SET status='running',attempts=attempts+1,locked_at=UTC_TIMESTAMP(),locked_by=:worker,
                 started_at=COALESCE(started_at,UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=:id"
            )->execute(['worker' => $workerId, 'id' => $row['id']]);
            $row['attempts'] = (int) $row['attempts'] + 1;
            return $row;
        });
        if ($job === null) {
            return null;
        }
        return $job['job_type'] === 'retention_delete' ? $this->deleteSnapshot($job) : $this->createAndVerify($job);
    }

    /** @return array{restore_job_id:int,restore_job_public_id:string,replayed:bool} */
    public function enqueueRestore(int $accountId, int $snapshotId, string $requestId, string $idempotencyKey): array
    {
        if ($accountId < 1 || $snapshotId < 1 || trim($requestId) === '' || trim($idempotencyKey) === '') {
            throw new RuntimeException('Account, snapshot, request ID, and idempotency key are required.');
        }
        return $this->database->transaction(function (PDO $pdo) use ($accountId, $snapshotId, $requestId, $idempotencyKey): array {
            $snapshot = $pdo->prepare("SELECT id FROM backup_snapshots WHERE id=:id AND account_id=:account AND status='verified' AND verification_status='verified' LIMIT 1 FOR UPDATE");
            $snapshot->execute(['id' => $snapshotId, 'account' => $accountId]);
            if (!$snapshot->fetchColumn()) {
                throw new RuntimeException('Only an account-owned verified snapshot can be restored.');
            }
            $existing = $pdo->prepare('SELECT id,public_id,snapshot_id FROM restore_jobs WHERE account_id=:account AND idempotency_key=:key LIMIT 1 FOR UPDATE');
            $existing->execute(['account' => $accountId, 'key' => $idempotencyKey]);
            $row = $existing->fetch(PDO::FETCH_ASSOC);
            if (is_array($row)) {
                if ((int) $row['snapshot_id'] !== $snapshotId) {
                    throw new RuntimeException('Restore idempotency key was reused for another snapshot.');
                }
                return ['restore_job_id' => (int) $row['id'], 'restore_job_public_id' => (string) $row['public_id'], 'replayed' => true];
            }
            $publicId = 'RESTORE-JOB-' . strtoupper(bin2hex(random_bytes(12)));
            $pdo->prepare(
                'INSERT INTO restore_jobs
                 (public_id,account_id,snapshot_id,status,idempotency_key,request_id,available_at,created_at,updated_at)
                 VALUES (:public,:account,:snapshot,\'queued\',:key,:request,UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())'
            )->execute([
                'public' => $publicId,
                'account' => $accountId,
                'snapshot' => $snapshotId,
                'key' => $idempotencyKey,
                'request' => $requestId,
            ]);
            $id = (int) $pdo->lastInsertId();
            $this->receipt($pdo, $accountId, null, $id, $snapshotId, $requestId, 'restore_queued', 'success', null, null);
            return ['restore_job_id' => $id, 'restore_job_public_id' => $publicId, 'replayed' => false];
        });
    }

    /** @return array<string,mixed>|null */
    public function processNextRestore(string $workerId): ?array
    {
        if (trim($workerId) === '') {
            throw new RuntimeException('Restore worker ID is required.');
        }
        $job = $this->database->transaction(function (PDO $pdo) use ($workerId): ?array {
            $row = $pdo->query(
                "SELECT * FROM restore_jobs WHERE status IN ('queued','running') AND available_at<=UTC_TIMESTAMP()
                 ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED"
            )->fetch(PDO::FETCH_ASSOC);
            if (!is_array($row)) {
                return null;
            }
            $pdo->prepare(
                "UPDATE restore_jobs SET status='running',attempts=attempts+1,locked_at=UTC_TIMESTAMP(),locked_by=:worker,
                 started_at=COALESCE(started_at,UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=:id"
            )->execute(['worker' => $workerId, 'id' => $row['id']]);
            return $row;
        });
        if ($job === null) {
            return null;
        }
        $pdo = $this->database->pdo();
        try {
            $pdo->prepare("UPDATE restore_jobs SET status='validating',updated_at=UTC_TIMESTAMP() WHERE id=:id")
                ->execute(['id' => $job['id']]);
            $snapshot = $this->snapshot($pdo, (int) $job['account_id'], (int) $job['snapshot_id'], true);
            if ($snapshot['status'] !== 'verified' || $snapshot['verification_status'] !== 'verified') {
                throw new RuntimeException('Snapshot lost verified status before restore.');
            }
            $targetId = $snapshot['target_type'] === 'pod' ? (int) $snapshot['pod_deployment_id'] : (int) $snapshot['homeserver_device_id'];
            $target = $this->target($pdo, (int) $job['account_id'], (string) $snapshot['target_type'], $targetId, false);
            $reference = $this->decryptReference($snapshot);
            $pdo->prepare("UPDATE restore_jobs SET status='restoring',updated_at=UTC_TIMESTAMP() WHERE id=:id")
                ->execute(['id' => $job['id']]);
            $result = $this->adapter->restoreBackup($target, $reference, (string) $snapshot['snapshot_hash']);
            $verificationHash = strtolower(trim((string) ($result['verification_hash'] ?? '')));
            if (($result['restored'] ?? false) !== true || !preg_match('/^[a-f0-9]{64}$/', $verificationHash)) {
                throw new RuntimeException('Provider did not verify the restored snapshot.');
            }
            $pdo->prepare("UPDATE restore_jobs SET status='completed',completed_at=UTC_TIMESTAMP(),locked_at=NULL,locked_by=NULL,updated_at=UTC_TIMESTAMP() WHERE id=:id")
                ->execute(['id' => $job['id']]);
            $this->receipt($pdo, (int) $job['account_id'], null, (int) $job['id'], (int) $snapshot['id'], (string) $job['request_id'], 'restore_verified', 'success', $verificationHash, $this->safeMetadata($result));
            return ['restore_job_id' => (int) $job['id'], 'snapshot_id' => (int) $snapshot['id'], 'status' => 'completed'];
        } catch (Throwable $exception) {
            $pdo->prepare(
                "UPDATE restore_jobs SET status='failed',locked_at=NULL,locked_by=NULL,last_error_code=:code,
                 last_error_message=:message,updated_at=UTC_TIMESTAMP() WHERE id=:id"
            )->execute(['code' => substr($exception::class, 0, 100), 'message' => substr($exception->getMessage(), 0, 1000), 'id' => $job['id']]);
            $this->receipt($pdo, (int) $job['account_id'], null, (int) $job['id'], (int) $job['snapshot_id'], (string) $job['request_id'], 'restore_failed', 'failure', null, ['error' => substr($exception->getMessage(), 0, 500)]);
            return ['restore_job_id' => (int) $job['id'], 'status' => 'failed', 'error' => $exception->getMessage()];
        }
    }

    public function applyRetention(int $limit = 100): int
    {
        $pdo = $this->database->pdo();
        $policies = $pdo->query("SELECT * FROM backup_policies WHERE status IN ('active','paused') ORDER BY id")->fetchAll(PDO::FETCH_ASSOC);
        foreach ($policies as $policy) {
            $column = $policy['target_type'] === 'pod' ? 's.pod_deployment_id' : 's.homeserver_device_id';
            $targetId = $policy['target_type'] === 'pod' ? (int) $policy['pod_deployment_id'] : (int) $policy['homeserver_device_id'];
            $query = $pdo->prepare(
                "SELECT s.id FROM backup_snapshots s JOIN backup_jobs j ON j.id=s.backup_job_id
                 WHERE s.account_id=:account AND s.target_type=:target_type AND {$column}=:target
                 AND s.status='verified' ORDER BY s.created_at DESC,s.id DESC"
            );
            $query->execute(['account' => $policy['account_id'], 'target_type' => $policy['target_type'], 'target' => $targetId]);
            $ids = array_map('intval', array_column($query->fetchAll(PDO::FETCH_ASSOC), 'id'));
            foreach (array_slice($ids, (int) $policy['retention_count']) as $id) {
                $pdo->prepare("UPDATE backup_snapshots SET status='expired',expires_at=COALESCE(expires_at,UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=:id AND status='verified'")
                    ->execute(['id' => $id]);
            }
        }
        $pdo->exec("UPDATE backup_snapshots SET status='expired',updated_at=UTC_TIMESTAMP() WHERE status='verified' AND expires_at IS NOT NULL AND expires_at<=UTC_TIMESTAMP()");
        $select = $pdo->prepare(
            "SELECT s.* FROM backup_snapshots s LEFT JOIN backup_jobs j ON j.snapshot_id=s.id AND j.job_type='retention_delete' AND j.status IN ('queued','running','completed')
             WHERE s.status='expired' AND j.id IS NULL ORDER BY s.expires_at,s.id LIMIT :limit"
        );
        $select->bindValue('limit', max(1, $limit), PDO::PARAM_INT);
        $select->execute();
        $count = 0;
        foreach ($select->fetchAll(PDO::FETCH_ASSOC) as $snapshot) {
            $publicId = 'BACKUP-DELETE-' . strtoupper(bin2hex(random_bytes(12)));
            $pdo->prepare(
                'INSERT INTO backup_jobs
                 (public_id,account_id,target_type,pod_deployment_id,homeserver_device_id,snapshot_id,job_type,status,
                  idempotency_key,request_id,available_at,created_at,updated_at)
                 VALUES (:public,:account,:target_type,:pod,:homeserver,:snapshot,\'retention_delete\',\'queued\',:key,:request,
                         UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())'
            )->execute([
                'public' => $publicId,
                'account' => $snapshot['account_id'],
                'target_type' => $snapshot['target_type'],
                'pod' => $snapshot['pod_deployment_id'],
                'homeserver' => $snapshot['homeserver_device_id'],
                'snapshot' => $snapshot['id'],
                'key' => 'retention-delete:' . $snapshot['id'],
                'request' => 'RETENTION-' . $snapshot['id'],
            ]);
            $count++;
        }
        return $count;
    }

    /** @return array{observation_id:int,utilization_percent:float,alert_severity:?string} */
    public function observeStorage(
        int $accountId,
        string $targetType,
        int $targetId,
        int $usageBytes,
        int $allowanceBytes,
        string $requestId
    ): array {
        $this->requiredAccountTarget($accountId, $targetType, $targetId);
        if ($usageBytes < 0 || $allowanceBytes < 1 || trim($requestId) === '') {
            throw new RuntimeException('Storage usage, allowance, and request ID are invalid.');
        }
        return $this->database->transaction(function (PDO $pdo) use (
            $accountId, $targetType, $targetId, $usageBytes, $allowanceBytes, $requestId
        ): array {
            $this->target($pdo, $accountId, $targetType, $targetId, true);
            $percent = round(($usageBytes / $allowanceBytes) * 100, 2);
            $pdo->prepare(
                'INSERT INTO storage_observations
                 (account_id,target_type,pod_deployment_id,homeserver_device_id,usage_bytes,allowance_bytes,utilization_percent,observed_at)
                 VALUES (:account,:target_type,:pod,:homeserver,:usage,:allowance,:percent,UTC_TIMESTAMP())'
            )->execute([
                'account' => $accountId,
                'target_type' => $targetType,
                'pod' => $targetType === 'pod' ? $targetId : null,
                'homeserver' => $targetType === 'homeserver' ? $targetId : null,
                'usage' => $usageBytes,
                'allowance' => $allowanceBytes,
                'percent' => $percent,
            ]);
            $observationId = (int) $pdo->lastInsertId();
            $severity = $percent >= $this->criticalThreshold ? 'critical' : ($percent >= $this->warningThreshold ? 'warning' : null);
            $targetColumn = $targetType === 'pod' ? 'o.pod_deployment_id' : 'o.homeserver_device_id';
            $open = $pdo->prepare(
                "SELECT a.id FROM storage_alerts a JOIN storage_observations o ON o.id=a.observation_id
                 WHERE a.account_id=:account AND a.status='open' AND o.target_type=:target_type AND {$targetColumn}=:target
                 ORDER BY a.id DESC LIMIT 1 FOR UPDATE"
            );
            $open->execute(['account' => $accountId, 'target_type' => $targetType, 'target' => $targetId]);
            $openId = $open->fetchColumn();
            if ($severity !== null && !$openId) {
                $threshold = $severity === 'critical' ? $this->criticalThreshold : $this->warningThreshold;
                $pdo->prepare(
                    'INSERT INTO storage_alerts
                     (public_id,account_id,observation_id,severity,status,threshold_percent,opened_at,created_at,updated_at)
                     VALUES (:public,:account,:observation,:severity,\'open\',:threshold,UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())'
                )->execute([
                    'public' => 'STORAGE-ALERT-' . strtoupper(bin2hex(random_bytes(12))),
                    'account' => $accountId,
                    'observation' => $observationId,
                    'severity' => $severity,
                    'threshold' => $threshold,
                ]);
            } elseif ($severity === null && $openId) {
                $pdo->prepare("UPDATE storage_alerts SET status='resolved',resolved_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE id=:id")
                    ->execute(['id' => $openId]);
            } elseif ($severity === 'critical' && $openId) {
                $pdo->prepare("UPDATE storage_alerts SET severity='critical',observation_id=:observation,threshold_percent=:threshold,updated_at=UTC_TIMESTAMP() WHERE id=:id")
                    ->execute(['observation' => $observationId, 'threshold' => $this->criticalThreshold, 'id' => $openId]);
            }
            $this->receipt($pdo, $accountId, null, null, null, $requestId, 'storage_observed', 'success', null, [
                'target_type' => $targetType,
                'target_id' => $targetId,
                'usage_bytes' => $usageBytes,
                'allowance_bytes' => $allowanceBytes,
                'utilization_percent' => $percent,
                'alert_severity' => $severity,
            ]);
            return ['observation_id' => $observationId, 'utilization_percent' => $percent, 'alert_severity' => $severity];
        });
    }

    /** @param array<string,mixed> $job @return array<string,mixed> */
    private function createAndVerify(array $job): array
    {
        $pdo = $this->database->pdo();
        $targetId = $job['target_type'] === 'pod' ? (int) $job['pod_deployment_id'] : (int) $job['homeserver_device_id'];
        $target = $this->target($pdo, (int) $job['account_id'], (string) $job['target_type'], $targetId, false);
        try {
            $pdo->prepare("UPDATE backup_jobs SET status='creating',updated_at=UTC_TIMESTAMP() WHERE id=:id")
                ->execute(['id' => $job['id']]);
            $created = $this->adapter->createBackup($target, (string) $job['job_type']);
            $reference = trim((string) ($created['reference'] ?? ''));
            $snapshotHash = strtolower(trim((string) ($created['snapshot_hash'] ?? '')));
            $size = (int) ($created['size_bytes'] ?? -1);
            if ($reference === '' || !preg_match('/^[a-f0-9]{64}$/', $snapshotHash) || $size < 0) {
                throw new RuntimeException('Backup provider returned invalid snapshot metadata.');
            }
            $context = $this->referenceContext((int) $job['account_id'], (int) $job['id'], $snapshotHash);
            $encrypted = $this->cipher->encrypt($reference, $context);
            $retentionDays = 30;
            if ($job['policy_id'] !== null) {
                $policy = $pdo->prepare('SELECT retention_days FROM backup_policies WHERE id=:id LIMIT 1');
                $policy->execute(['id' => $job['policy_id']]);
                $retentionDays = max(1, (int) $policy->fetchColumn());
            }
            $publicId = 'SNAPSHOT-' . strtoupper(bin2hex(random_bytes(12)));
            $pdo->prepare(
                'INSERT INTO backup_snapshots
                 (public_id,account_id,backup_job_id,target_type,pod_deployment_id,homeserver_device_id,status,snapshot_hash,
                  provider_reference_ciphertext,provider_reference_nonce,provider_reference_tag,encryption_key_id,size_bytes,
                  verification_status,expires_at,created_at,updated_at)
                 VALUES (:public,:account,:job,:target_type,:pod,:homeserver,\'pending_verification\',:snapshot_hash,
                         :ciphertext,:nonce,:tag,:key_id,:size,\'pending\',DATE_ADD(UTC_TIMESTAMP(),INTERVAL :retention_days DAY),
                         UTC_TIMESTAMP(),UTC_TIMESTAMP())'
            )->execute([
                'public' => $publicId,
                'account' => $job['account_id'],
                'job' => $job['id'],
                'target_type' => $job['target_type'],
                'pod' => $job['pod_deployment_id'],
                'homeserver' => $job['homeserver_device_id'],
                'snapshot_hash' => $snapshotHash,
                'ciphertext' => $encrypted['ciphertext'],
                'nonce' => $encrypted['nonce'],
                'tag' => $encrypted['tag'],
                'key_id' => $encrypted['key_id'],
                'size' => $size,
                'retention_days' => $retentionDays,
            ]);
            $snapshotId = (int) $pdo->lastInsertId();
            $pdo->prepare("UPDATE backup_jobs SET status='verifying',updated_at=UTC_TIMESTAMP() WHERE id=:id")
                ->execute(['id' => $job['id']]);
            $verified = $this->adapter->verifyBackup($target, $reference, $snapshotHash);
            $verificationHash = strtolower(trim((string) ($verified['verification_hash'] ?? '')));
            if (($verified['verified'] ?? false) !== true || !preg_match('/^[a-f0-9]{64}$/', $verificationHash)) {
                $pdo->prepare("UPDATE backup_snapshots SET status='failed',verification_status='failed',updated_at=UTC_TIMESTAMP() WHERE id=:id")
                    ->execute(['id' => $snapshotId]);
                throw new RuntimeException('Backup provider did not verify the snapshot.');
            }
            $pdo->prepare(
                'INSERT INTO backup_verifications
                 (snapshot_id,backup_job_id,result,verification_hash,checked_at,metadata_json)
                 VALUES (:snapshot,:job,\'verified\',:hash,UTC_TIMESTAMP(),:metadata)'
            )->execute([
                'snapshot' => $snapshotId,
                'job' => $job['id'],
                'hash' => $verificationHash,
                'metadata' => isset($verified['metadata']) && is_array($verified['metadata']) ? $this->json($this->safeMetadata($verified['metadata'])) : null,
            ]);
            $pdo->prepare("UPDATE backup_snapshots SET status='verified',verification_status='verified',verified_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE id=:id")
                ->execute(['id' => $snapshotId]);
            $pdo->prepare("UPDATE backup_jobs SET status='completed',completed_at=UTC_TIMESTAMP(),locked_at=NULL,locked_by=NULL,updated_at=UTC_TIMESTAMP() WHERE id=:id")
                ->execute(['id' => $job['id']]);
            $this->receipt($pdo, (int) $job['account_id'], (int) $job['id'], null, $snapshotId, (string) $job['request_id'], 'backup_verified', 'success', $verificationHash, [
                'snapshot_public_id' => $publicId,
                'snapshot_hash' => $snapshotHash,
                'size_bytes' => $size,
            ]);
            return ['job_id' => (int) $job['id'], 'snapshot_id' => $snapshotId, 'snapshot_public_id' => $publicId, 'status' => 'completed'];
        } catch (Throwable $exception) {
            $status = (int) $job['attempts'] < (int) $job['max_attempts'] ? 'queued' : 'failed';
            $pdo->prepare(
                "UPDATE backup_jobs SET status=:status,available_at=DATE_ADD(UTC_TIMESTAMP(),INTERVAL 60 SECOND),
                 locked_at=NULL,locked_by=NULL,last_error_code=:code,last_error_message=:message,updated_at=UTC_TIMESTAMP() WHERE id=:id"
            )->execute([
                'status' => $status,
                'code' => substr($exception::class, 0, 100),
                'message' => substr($exception->getMessage(), 0, 1000),
                'id' => $job['id'],
            ]);
            $this->receipt($pdo, (int) $job['account_id'], (int) $job['id'], null, null, (string) $job['request_id'], 'backup_failed', 'failure', null, ['error' => substr($exception->getMessage(), 0, 500)]);
            return ['job_id' => (int) $job['id'], 'status' => $status, 'error' => $exception->getMessage()];
        }
    }

    /** @param array<string,mixed> $job @return array<string,mixed> */
    private function deleteSnapshot(array $job): array
    {
        $pdo = $this->database->pdo();
        try {
            if ($job['snapshot_id'] === null) {
                throw new RuntimeException('Retention deletion job has no snapshot.');
            }
            $snapshot = $this->snapshot($pdo, (int) $job['account_id'], (int) $job['snapshot_id'], true);
            if ($snapshot['status'] === 'deleted') {
                $pdo->prepare("UPDATE backup_jobs SET status='completed',completed_at=UTC_TIMESTAMP(),locked_at=NULL,locked_by=NULL,updated_at=UTC_TIMESTAMP() WHERE id=:id")
                    ->execute(['id' => $job['id']]);
                return ['job_id' => (int) $job['id'], 'snapshot_id' => (int) $snapshot['id'], 'status' => 'completed', 'replayed' => true];
            }
            if ($snapshot['status'] !== 'expired') {
                throw new RuntimeException('Only an expired snapshot can be deleted by retention.');
            }
            $targetId = $snapshot['target_type'] === 'pod' ? (int) $snapshot['pod_deployment_id'] : (int) $snapshot['homeserver_device_id'];
            $target = $this->target($pdo, (int) $job['account_id'], (string) $snapshot['target_type'], $targetId, false);
            $reference = $this->decryptReference($snapshot);
            $result = $this->adapter->deleteBackup($target, $reference, (string) $snapshot['snapshot_hash']);
            $receiptHash = strtolower(trim((string) ($result['receipt_hash'] ?? '')));
            if (($result['deleted'] ?? false) !== true || !preg_match('/^[a-f0-9]{64}$/', $receiptHash)) {
                throw new RuntimeException('Provider did not verify snapshot deletion.');
            }
            $pdo->prepare("UPDATE backup_snapshots SET status='deleted',deleted_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE id=:id")
                ->execute(['id' => $snapshot['id']]);
            $pdo->prepare("UPDATE backup_jobs SET status='completed',completed_at=UTC_TIMESTAMP(),locked_at=NULL,locked_by=NULL,updated_at=UTC_TIMESTAMP() WHERE id=:id")
                ->execute(['id' => $job['id']]);
            $this->receipt($pdo, (int) $job['account_id'], (int) $job['id'], null, (int) $snapshot['id'], (string) $job['request_id'], 'retention_deleted', 'success', $receiptHash, null);
            return ['job_id' => (int) $job['id'], 'snapshot_id' => (int) $snapshot['id'], 'status' => 'completed'];
        } catch (Throwable $exception) {
            $pdo->prepare(
                "UPDATE backup_jobs SET status='failed',locked_at=NULL,locked_by=NULL,last_error_code=:code,
                 last_error_message=:message,updated_at=UTC_TIMESTAMP() WHERE id=:id"
            )->execute(['code' => substr($exception::class, 0, 100), 'message' => substr($exception->getMessage(), 0, 1000), 'id' => $job['id']]);
            return ['job_id' => (int) $job['id'], 'status' => 'failed', 'error' => $exception->getMessage()];
        }
    }

    /** @return array<string,mixed> */
    private function target(PDO $pdo, int $accountId, string $targetType, int $targetId, bool $lock): array
    {
        if ($targetType === 'pod') {
            $query = $pdo->prepare(
                "SELECT id,public_id,account_id,status,installed_version,storage_usage_bytes,storage_allowance_bytes
                 FROM pod_deployments WHERE id=:id AND account_id=:account AND status IN ('active','degraded','suspended') LIMIT 1" . ($lock ? ' FOR UPDATE' : '')
            );
        } else {
            $query = $pdo->prepare(
                "SELECT id,public_id,account_id,status,software_version FROM homeserver_devices
                 WHERE id=:id AND account_id=:account AND status IN ('paired','online','degraded','offline','suspended') LIMIT 1" . ($lock ? ' FOR UPDATE' : '')
            );
        }
        $query->execute(['id' => $targetId, 'account' => $accountId]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('Backup target was not found for this account.');
        }
        $row['target_type'] = $targetType;
        return $row;
    }

    /** @return array<string,mixed> */
    private function snapshot(PDO $pdo, int $accountId, int $snapshotId, bool $lock): array
    {
        $query = $pdo->prepare('SELECT * FROM backup_snapshots WHERE id=:id AND account_id=:account LIMIT 1' . ($lock ? ' FOR UPDATE' : ''));
        $query->execute(['id' => $snapshotId, 'account' => $accountId]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('Backup snapshot was not found for this account.');
        }
        return $row;
    }

    /** @param array<string,mixed> $snapshot */
    private function decryptReference(array $snapshot): string
    {
        return $this->cipher->decrypt(
            (string) $snapshot['provider_reference_ciphertext'],
            (string) $snapshot['provider_reference_nonce'],
            (string) $snapshot['provider_reference_tag'],
            $this->referenceContext((int) $snapshot['account_id'], (int) $snapshot['backup_job_id'], (string) $snapshot['snapshot_hash'])
        );
    }

    private function referenceContext(int $accountId, int $jobId, string $snapshotHash): string
    {
        return 'vp3-backup-reference|' . $accountId . '|' . $jobId . '|' . $snapshotHash;
    }

    private function requiredAccountTarget(int $accountId, string $targetType, int $targetId): void
    {
        if ($accountId < 1 || $targetId < 1 || !in_array($targetType, ['pod', 'homeserver'], true)) {
            throw new RuntimeException('A valid account-owned POD or HomeServer target is required.');
        }
    }

    /** @param array<string,mixed>|null $metadata */
    private function receipt(
        PDO $pdo,
        int $accountId,
        ?int $backupJobId,
        ?int $restoreJobId,
        ?int $snapshotId,
        string $requestId,
        string $operation,
        string $result,
        ?string $hash,
        ?array $metadata
    ): void {
        $pdo->prepare(
            'INSERT INTO backup_receipts
             (public_id,account_id,backup_job_id,restore_job_id,snapshot_id,request_id,operation,result,receipt_hash,metadata_json,created_at)
             VALUES (:public,:account,:backup_job,:restore_job,:snapshot,:request,:operation,:result,:hash,:metadata,UTC_TIMESTAMP())'
        )->execute([
            'public' => 'BACKUP-RCP-' . strtoupper(bin2hex(random_bytes(12))),
            'account' => $accountId,
            'backup_job' => $backupJobId,
            'restore_job' => $restoreJobId,
            'snapshot' => $snapshotId,
            'request' => $requestId,
            'operation' => substr($operation, 0, 100),
            'result' => $result,
            'hash' => $hash,
            'metadata' => $metadata === null ? null : $this->json($metadata),
        ]);
    }

    /** @param array<string,mixed> $metadata @return array<string,mixed> */
    private function safeMetadata(array $metadata): array
    {
        return array_intersect_key($metadata, array_flip([
            'provider_request_id', 'region', 'storage_class', 'verified', 'restored', 'deleted',
            'verification_hash', 'receipt_hash', 'size_bytes',
        ]));
    }

    private function json(mixed $value): string
    {
        $normalize = static function (mixed $item) use (&$normalize): mixed {
            if (!is_array($item)) {
                return $item;
            }
            if (array_is_list($item)) {
                return array_map($normalize, $item);
            }
            ksort($item);
            foreach ($item as $key => $child) {
                $item[$key] = $normalize($child);
            }
            return $item;
        };
        return json_encode($normalize($value), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
}
