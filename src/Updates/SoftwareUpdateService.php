<?php

declare(strict_types=1);

namespace Vp3\Updates;

use PDO;
use RuntimeException;
use Throwable;
use Vp3\Database;
use Vp3\Queue\QueueLease;
use Vp3\Queue\QueueLeaseLostException;

final class SoftwareUpdateService
{
    private readonly QueueLease $queueLease;

    /** @var list<string> */
    public const STAGES = ['validating', 'backing_up', 'downloading', 'installing', 'migrating', 'verifying', 'completed'];

    public function __construct(
        private readonly Database $database,
        private readonly SoftwareUpdateAdapter $adapter,
        int $leaseSeconds = 900
    ) {
        $this->queueLease = new QueueLease($leaseSeconds);
    }

    /** @return array{job_id:int,job_public_id:string,replayed:bool} */
    public function enqueue(
        int $accountId,
        string $targetType,
        int $targetId,
        int $releaseId,
        string $requestId,
        string $idempotencyKey
    ): array {
        if ($accountId < 1 || !in_array($targetType, ['pod', 'homeserver'], true)
            || $targetId < 1 || $releaseId < 1 || trim($requestId) === '' || trim($idempotencyKey) === '') {
            throw new RuntimeException('Account, target, release, request ID, and idempotency key are required.');
        }
        return $this->database->transaction(function (PDO $pdo) use (
            $accountId, $targetType, $targetId, $releaseId, $requestId, $idempotencyKey
        ): array {
            $existing = $pdo->prepare('SELECT id,public_id,target_type,pod_deployment_id,homeserver_device_id,release_id FROM update_jobs WHERE account_id=:account AND idempotency_key=:key LIMIT 1 FOR UPDATE');
            $existing->execute(['account' => $accountId, 'key' => $idempotencyKey]);
            $job = $existing->fetch(PDO::FETCH_ASSOC);
            if (is_array($job)) {
                $existingTarget = $job['target_type'] === 'pod' ? (int) $job['pod_deployment_id'] : (int) $job['homeserver_device_id'];
                if ($job['target_type'] !== $targetType || $existingTarget !== $targetId || (int) $job['release_id'] !== $releaseId) {
                    throw new RuntimeException('Update idempotency key was reused for another target or release.');
                }
                return ['job_id' => (int) $job['id'], 'job_public_id' => (string) $job['public_id'], 'replayed' => true];
            }
            $release = $this->release($pdo, $releaseId, true);
            $target = $this->target($pdo, $accountId, $targetType, $targetId, true);
            $this->assertEligible($release, $target);
            if (version_compare((string) $target['current_version'], (string) $release['version'], '>=')) {
                throw new RuntimeException('Target is already at or above this release version.');
            }
            $publicId = 'UPDATE-' . strtoupper(bin2hex(random_bytes(12)));
            $pdo->prepare(
                'INSERT INTO update_jobs
                 (public_id,account_id,target_type,pod_deployment_id,homeserver_device_id,release_id,status,
                  previous_version,target_version,idempotency_key,request_id,available_at,created_at,updated_at)
                 VALUES (:public,:account,:target_type,:pod,:homeserver,:release,\'queued\',:previous,:target,:key,:request,UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())'
            )->execute([
                'public' => $publicId,
                'account' => $accountId,
                'target_type' => $targetType,
                'pod' => $targetType === 'pod' ? $targetId : null,
                'homeserver' => $targetType === 'homeserver' ? $targetId : null,
                'release' => $releaseId,
                'previous' => $target['current_version'],
                'target' => $release['version'],
                'key' => $idempotencyKey,
                'request' => $requestId,
            ]);
            $jobId = (int) $pdo->lastInsertId();
            $insert = $pdo->prepare(
                'INSERT INTO update_steps (job_id,stage,sequence_no,status,created_at,updated_at)
                 VALUES (:job,:stage,:sequence,\'pending\',UTC_TIMESTAMP(),UTC_TIMESTAMP())'
            );
            foreach (self::STAGES as $index => $stage) {
                $insert->execute(['job' => $jobId, 'stage' => $stage, 'sequence' => $index + 1]);
            }
            $this->receipt($pdo, $accountId, $jobId, null, $requestId, 'update_queued', 'success', null, [
                'target_type' => $targetType,
                'target_id' => $targetId,
                'release_id' => $releaseId,
                'previous_version' => $target['current_version'],
                'target_version' => $release['version'],
            ]);
            return ['job_id' => $jobId, 'job_public_id' => $publicId, 'replayed' => false];
        });
    }

    /** @return array<string,mixed>|null */
    public function processNext(string $workerId): ?array
    {
        if (trim($workerId) === '') {
            throw new RuntimeException('Update worker ID is required.');
        }
        $job = $this->database->transaction(function (PDO $pdo) use ($workerId): ?array {
            $row = $pdo->query(
                "SELECT * FROM update_jobs WHERE
                 (status='queued' OR (status IN ('running','validating','backing_up','downloading','installing','migrating','verifying','rolling_back')
                  AND (locked_until IS NULL OR locked_until<UTC_TIMESTAMP())))
                 AND available_at<=UTC_TIMESTAMP() ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED"
            )->fetch(PDO::FETCH_ASSOC);
            if (!is_array($row)) {
                return null;
            }
            $token = $this->queueLease->token();
            $seconds = $this->queueLease->seconds();
            $pdo->prepare(
                "UPDATE update_jobs SET status='running',attempts=attempts+1,locked_by=:worker,locked_at=UTC_TIMESTAMP(),
                 locked_until=DATE_ADD(UTC_TIMESTAMP(),INTERVAL {$seconds} SECOND),lease_token=:token,
                 started_at=COALESCE(started_at,UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=:id"
            )->execute(['worker' => substr($workerId, 0, 128), 'token' => $token, 'id' => $row['id']]);
            $row['attempts'] = (int) $row['attempts'] + 1;
            $row['lease_token'] = $token;
            return $row;
        });
        if ($job === null) {
            return null;
        }
        return $this->run($job);
    }

    public function pause(int $accountId, int $jobId, string $requestId): void
    {
        $this->transition($accountId, $jobId, $requestId, ['queued', 'running'], 'paused');
    }

    public function resume(int $accountId, int $jobId, string $requestId): void
    {
        $this->transition($accountId, $jobId, $requestId, ['paused', 'failed'], 'queued');
    }

    /** @param array<string,mixed> $job @return array<string,mixed> */
    private function run(array $job): array
    {
        $pdo = $this->database->pdo();
        $targetId = $job['target_type'] === 'pod' ? (int) $job['pod_deployment_id'] : (int) $job['homeserver_device_id'];
        $target = $this->target($pdo, (int) $job['account_id'], (string) $job['target_type'], $targetId, false);
        $release = $this->release($pdo, (int) $job['release_id'], false);
        $steps = $pdo->prepare('SELECT * FROM update_steps WHERE job_id=:job ORDER BY sequence_no');
        $steps->execute(['job' => $job['id']]);
        foreach ($steps->fetchAll(PDO::FETCH_ASSOC) as $step) {
            if ($step['status'] === 'completed') {
                continue;
            }
            $status = $pdo->prepare('SELECT status FROM update_jobs WHERE id=:id');
            $status->execute(['id' => $job['id']]);
            if ($status->fetchColumn() === 'paused') {
                return ['job_id' => (int) $job['id'], 'status' => 'paused'];
            }
            $stage = (string) $step['stage'];
            try {
                $this->queueLease->renew($pdo, 'update_jobs', (int) $job['id'], (string) $job['lease_token']);
                $this->ownedTransaction($job, function (PDO $owned) use ($job, $step, $stage): void {
                    $owned->prepare("UPDATE update_jobs SET status='running',current_stage=:stage,updated_at=UTC_TIMESTAMP() WHERE id=:id AND lease_token=:token")
                        ->execute(['stage' => $stage, 'id' => $job['id'], 'token' => $job['lease_token']]);
                    $owned->prepare("UPDATE update_steps SET status='running',attempts=attempts+1,started_at=COALESCE(started_at,UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=:id")
                        ->execute(['id' => $step['id']]);
                });
                if ($stage === 'validating') {
                    $this->assertEligible($release, $target);
                    $result = ['eligible' => true];
                } elseif ($stage === 'backing_up') {
                    $result = $this->adapter->createPreUpdateBackup($target, $release);
                    $this->queueLease->renew($pdo, 'update_jobs', (int) $job['id'], (string) $job['lease_token']);
                    $reference = trim((string) ($result['reference'] ?? ''));
                    $hash = strtolower(trim((string) ($result['hash'] ?? '')));
                    if ($reference === '' || !preg_match('/^[a-f0-9]{64}$/', $hash) || ($result['verified'] ?? false) !== true) {
                        throw new RuntimeException('Pre-update backup must be created and verified before installation.');
                    }
                    $job['pre_update_backup_reference'] = $reference;
                    $job['pre_update_backup_hash'] = $hash;
                    $job['pre_update_backup_verified'] = 1;
                } elseif ($stage === 'completed') {
                    $result = ['completed' => true];
                } else {
                    if (in_array($stage, ['installing', 'migrating', 'verifying'], true) && (int) ($job['pre_update_backup_verified'] ?? 0) !== 1) {
                        throw new RuntimeException('Verified pre-update backup is required before installation.');
                    }
                    $result = $this->adapter->executeStage($stage, $target, $release, $job);
                    $this->queueLease->renew($pdo, 'update_jobs', (int) $job['id'], (string) $job['lease_token']);
                    if ($stage === 'verifying' && ($result['verified'] ?? false) !== true) {
                        throw new RuntimeException('Post-update verification failed.');
                    }
                }
                $this->queueLease->renew($pdo, 'update_jobs', (int) $job['id'], (string) $job['lease_token']);
                $hash = hash('sha256', $this->json($result));
                $this->ownedTransaction($job, function (PDO $owned) use ($job, $step, $stage, $result, $hash, $release): void {
                    if ($stage === 'backing_up') {
                        $owned->prepare(
                            'UPDATE update_jobs SET pre_update_backup_reference=:reference,pre_update_backup_hash=:hash,
                             pre_update_backup_verified=1,updated_at=UTC_TIMESTAMP() WHERE id=:id AND lease_token=:token'
                        )->execute([
                            'reference' => substr((string) $job['pre_update_backup_reference'], 0, 512),
                            'hash' => (string) $job['pre_update_backup_hash'],
                            'id' => $job['id'],
                            'token' => $job['lease_token'],
                        ]);
                    }
                    if ($stage === 'completed') {
                        $this->updateVersion($owned, $job, (string) $release['version']);
                    }
                    $owned->prepare(
                        "UPDATE update_steps SET status='completed',receipt_hash=:hash,completed_at=UTC_TIMESTAMP(),
                         last_error_code=NULL,last_error_message=NULL,updated_at=UTC_TIMESTAMP() WHERE id=:id"
                    )->execute(['hash' => $hash, 'id' => $step['id']]);
                    $this->receipt($owned, (int) $job['account_id'], (int) $job['id'], (int) $step['id'], (string) $job['request_id'], $stage, 'success', $hash, $this->metadata($result));
                });
            } catch (QueueLeaseLostException) {
                return ['job_id' => (int) $job['id'], 'status' => 'lease_lost'];
            } catch (Throwable $exception) {
                try {
                    $this->queueLease->renew($pdo, 'update_jobs', (int) $job['id'], (string) $job['lease_token']);
                    $this->ownedTransaction($job, function (PDO $owned) use ($job, $step, $stage, $exception): void {
                        $owned->prepare(
                            "UPDATE update_steps SET status='failed',last_error_code=:code,last_error_message=:message,updated_at=UTC_TIMESTAMP() WHERE id=:id"
                        )->execute([
                            'code' => substr($exception::class, 0, 100),
                            'message' => substr($exception->getMessage(), 0, 1000),
                            'id' => $step['id'],
                        ]);
                        $this->receipt($owned, (int) $job['account_id'], (int) $job['id'], (int) $step['id'], (string) $job['request_id'], $stage, 'failure', null, ['error' => substr($exception->getMessage(), 0, 500)]);
                    });
                } catch (QueueLeaseLostException) {
                    return ['job_id' => (int) $job['id'], 'status' => 'lease_lost'];
                }
                return $this->failOrRollback($job, $target, $release, $exception);
            }
        }
        $this->queueLease->renew($pdo, 'update_jobs', (int) $job['id'], (string) $job['lease_token']);
        $statement = $pdo->prepare(
            "UPDATE update_jobs SET status='completed',current_stage='completed',completed_at=UTC_TIMESTAMP(),locked_at=NULL,locked_by=NULL,
             locked_until=NULL,lease_token=NULL,updated_at=UTC_TIMESTAMP() WHERE id=:id AND lease_token=:token"
        );
        $statement->execute(['id' => $job['id'], 'token' => $job['lease_token']]);
        if ($statement->rowCount() !== 1) {
            return ['job_id' => (int) $job['id'], 'status' => 'lease_lost'];
        }
        return ['job_id' => (int) $job['id'], 'status' => 'completed', 'version' => $release['version']];
    }

    /** @param array<string,mixed> $job @param array<string,mixed> $target @param array<string,mixed> $release @return array<string,mixed> */
    private function failOrRollback(array $job, array $target, array $release, Throwable $exception): array
    {
        $pdo = $this->database->pdo();
        if ((int) ($job['pre_update_backup_verified'] ?? 0) === 1) {
            try {
                $this->queueLease->renew($pdo, 'update_jobs', (int) $job['id'], (string) $job['lease_token']);
                $pdo->prepare("UPDATE update_jobs SET status='running',current_stage='rolling_back',updated_at=UTC_TIMESTAMP() WHERE id=:id AND lease_token=:token")
                    ->execute(['id' => $job['id'], 'token' => $job['lease_token']]);
                $result = $this->adapter->rollback($target, $release, $job);
                $this->queueLease->renew($pdo, 'update_jobs', (int) $job['id'], (string) $job['lease_token']);
                if (($result['restored'] ?? false) !== true) {
                    throw new RuntimeException('Update rollback did not verify restoration.');
                }
                $this->updateVersion($pdo, $job, (string) $job['previous_version']);
                $statement = $pdo->prepare(
                    "UPDATE update_jobs SET status='rolled_back',current_stage='rolled_back',completed_at=UTC_TIMESTAMP(),
                     locked_at=NULL,locked_by=NULL,locked_until=NULL,lease_token=NULL,last_error_code=:code,last_error_message=:message,updated_at=UTC_TIMESTAMP() WHERE id=:id AND lease_token=:token"
                );
                $statement->execute([
                    'code' => substr($exception::class, 0, 100),
                    'message' => substr($exception->getMessage(), 0, 1000),
                    'id' => $job['id'],
                    'token' => $job['lease_token'],
                ]);
                $this->queueLease->assertUpdated($statement);
                $this->receipt($pdo, (int) $job['account_id'], (int) $job['id'], null, (string) $job['request_id'], 'rollback', 'success', hash('sha256', $this->json($result)), $this->metadata($result));
                return ['job_id' => (int) $job['id'], 'status' => 'rolled_back', 'error' => $exception->getMessage()];
            } catch (QueueLeaseLostException) {
                return ['job_id' => (int) $job['id'], 'status' => 'lease_lost'];
            } catch (Throwable $rollbackException) {
                $exception = $rollbackException;
            }
        }
        $statement = $pdo->prepare(
            "UPDATE update_jobs SET status='failed',locked_at=NULL,locked_by=NULL,locked_until=NULL,lease_token=NULL,last_error_code=:code,
             last_error_message=:message,updated_at=UTC_TIMESTAMP() WHERE id=:id AND lease_token=:token"
        );
        $statement->execute([
            'code' => substr($exception::class, 0, 100),
            'message' => substr($exception->getMessage(), 0, 1000),
            'id' => $job['id'],
            'token' => $job['lease_token'],
        ]);
        if ($statement->rowCount() !== 1) {
            return ['job_id' => (int) $job['id'], 'status' => 'lease_lost'];
        }
        return ['job_id' => (int) $job['id'], 'status' => 'failed', 'error' => $exception->getMessage()];
    }

    /** @template T @param array<string,mixed> $job @param callable(PDO):T $callback @return T */
    private function ownedTransaction(array $job, callable $callback): mixed
    {
        return $this->database->transaction(function (PDO $pdo) use ($job, $callback): mixed {
            $this->queueLease->assertOwned($pdo, 'update_jobs', (int) $job['id'], (string) $job['lease_token']);
            return $callback($pdo);
        });
    }

    /** @return array<string,mixed> */
    private function release(PDO $pdo, int $releaseId, bool $lock): array
    {
        $query = $pdo->prepare(
            'SELECT r.*,p.target_type,p.code product_code,rr.status rollout_status,rr.percentage,rr.cohort_seed,rr.starts_at,rr.ends_at,
             c.minimum_current_version,c.maximum_current_version,c.minimum_php_version,c.database_family,c.minimum_database_version
             FROM software_releases r JOIN software_products p ON p.id=r.product_id
             JOIN release_rollouts rr ON rr.release_id=r.id
             JOIN release_compatibility_rules c ON c.release_id=r.id
             WHERE r.id=:id LIMIT 1' . ($lock ? ' FOR UPDATE' : '')
        );
        $query->execute(['id' => $releaseId]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('Software release was not found.');
        }
        return $row;
    }

    /** @return array<string,mixed> */
    private function target(PDO $pdo, int $accountId, string $targetType, int $targetId, bool $lock): array
    {
        if ($targetType === 'pod') {
            $query = $pdo->prepare(
                "SELECT id,public_id,account_id,status,installed_version current_version,update_channel
                 FROM pod_deployments WHERE id=:id AND account_id=:account AND status IN ('active','degraded') LIMIT 1" . ($lock ? ' FOR UPDATE' : '')
            );
        } else {
            $query = $pdo->prepare(
                "SELECT id,public_id,account_id,status,software_version current_version,update_channel
                 FROM homeserver_devices WHERE id=:id AND account_id=:account AND status IN ('paired','online','degraded','offline') LIMIT 1" . ($lock ? ' FOR UPDATE' : '')
            );
        }
        $query->execute(['id' => $targetId, 'account' => $accountId]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row) || !is_string($row['current_version']) || trim($row['current_version']) === '') {
            throw new RuntimeException('Update target was not found or has no installed version.');
        }
        $row['target_type'] = $targetType;
        return $row;
    }

    /** @param array<string,mixed> $release @param array<string,mixed> $target */
    private function assertEligible(array $release, array $target): void
    {
        if ($release['status'] !== 'published' || $release['rollout_status'] !== 'active'
            || !is_string($release['manifest_hash']) || !is_string($release['manifest_signature'])) {
            throw new RuntimeException('Release is not published, signed, and active.');
        }
        if ($release['target_type'] !== $target['target_type']) {
            throw new RuntimeException('Release target type does not match the update target.');
        }
        if ($release['starts_at'] !== null && strtotime((string) $release['starts_at']) > time()) {
            throw new RuntimeException('Release rollout has not started.');
        }
        if ($release['ends_at'] !== null && strtotime((string) $release['ends_at']) < time()) {
            throw new RuntimeException('Release rollout has ended.');
        }
        $channel = (string) $target['update_channel'];
        if ($release['channel'] === 'beta' && $channel !== 'beta') {
            throw new RuntimeException('Stable targets cannot receive beta releases.');
        }
        $current = (string) $target['current_version'];
        if (is_string($release['minimum_current_version']) && $release['minimum_current_version'] !== ''
            && version_compare($current, $release['minimum_current_version'], '<')) {
            throw new RuntimeException('Current version is below the release compatibility floor.');
        }
        if (is_string($release['maximum_current_version']) && $release['maximum_current_version'] !== ''
            && version_compare($current, $release['maximum_current_version'], '>')) {
            throw new RuntimeException('Current version is above the release compatibility ceiling.');
        }
        $emergency = $release['channel'] === 'security' && (int) $release['emergency_override'] === 1;
        if (!$emergency) {
            $bucket = hexdec(substr(hash('sha256', $release['cohort_seed'] . '|' . $target['public_id']), 0, 8)) % 100;
            if ($bucket >= (int) $release['percentage']) {
                throw new RuntimeException('Target is outside the active staged rollout cohort.');
            }
        }
    }

    /** @param array<string,mixed> $job */
    private function updateVersion(PDO $pdo, array $job, string $version): void
    {
        if ($job['target_type'] === 'pod') {
            $pdo->prepare('UPDATE pod_deployments SET installed_version=:version,updated_at=UTC_TIMESTAMP() WHERE id=:id AND account_id=:account')
                ->execute(['version' => $version, 'id' => $job['pod_deployment_id'], 'account' => $job['account_id']]);
        } else {
            $pdo->prepare('UPDATE homeserver_devices SET software_version=:version,updated_at=UTC_TIMESTAMP() WHERE id=:id AND account_id=:account')
                ->execute(['version' => $version, 'id' => $job['homeserver_device_id'], 'account' => $job['account_id']]);
        }
    }

    /** @param list<string> $allowed */
    private function transition(int $accountId, int $jobId, string $requestId, array $allowed, string $next): void
    {
        if ($accountId < 1 || trim($requestId) === '') {
            throw new RuntimeException('Account and request ID are required.');
        }
        $marks = implode(',', array_fill(0, count($allowed), '?'));
        $statement = $this->database->pdo()->prepare(
            "UPDATE update_jobs SET status=?,request_id=?,available_at=UTC_TIMESTAMP(),locked_at=NULL,locked_by=NULL,locked_until=NULL,lease_token=NULL,updated_at=UTC_TIMESTAMP()
             WHERE id=? AND account_id=? AND status IN ({$marks})"
        );
        $statement->execute(array_merge([$next, $requestId, $jobId, $accountId], $allowed));
        if ($statement->rowCount() !== 1) {
            throw new RuntimeException('Update job cannot transition to ' . $next . '.');
        }
    }

    /** @param array<string,mixed>|null $metadata */
    private function receipt(PDO $pdo, int $accountId, int $jobId, ?int $stepId, string $requestId, string $operation, string $result, ?string $hash, ?array $metadata): void
    {
        $pdo->prepare(
            'INSERT INTO update_receipts
             (public_id,account_id,job_id,step_id,request_id,operation,result,receipt_hash,metadata_json,created_at)
             VALUES (:public,:account,:job,:step,:request,:operation,:result,:hash,:metadata,UTC_TIMESTAMP())'
        )->execute([
            'public' => 'UPDATE-RCP-' . strtoupper(bin2hex(random_bytes(12))),
            'account' => $accountId,
            'job' => $jobId,
            'step' => $stepId,
            'request' => $requestId,
            'operation' => substr($operation, 0, 100),
            'result' => $result,
            'hash' => $hash,
            'metadata' => $metadata === null ? null : $this->json($metadata),
        ]);
    }

    /** @param array<string,mixed> $result @return array<string,mixed> */
    private function metadata(array $result): array
    {
        return array_intersect_key($result, array_flip([
            'reference', 'hash', 'verified', 'restored', 'provider_request_id', 'artifact_sha256', 'migration_count',
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
