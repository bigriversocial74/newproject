<?php

declare(strict_types=1);

namespace Vp3\Provisioning;

use PDO;
use RuntimeException;
use Throwable;
use Vp3\Database;

final class PodProvisioningService
{
    /** @var list<string> */
    public const STAGES = [
        'payment_confirmed', 'domain_registered', 'hosting_allocated', 'database_created',
        'pod_installed', 'configuration_written', 'owner_account_created', 'license_injected',
        'ssl_requested', 'installation_verified', 'deployment_active',
    ];

    /** @param list<string> $protectedConfigurationPaths */
    public function __construct(
        private readonly Database $database,
        private readonly PodProvisioningAdapter $adapter,
        private readonly ProtectedConfigurationMerger $merger,
        private readonly array $protectedConfigurationPaths = ['database.password', 'app.key', 'customer']
    ) {
    }

    public function reconcileBillingOutbox(int $limit = 20): int
    {
        $count = 0;
        while ($count < max(1, $limit)) {
            $row = $this->database->transaction(function (PDO $pdo): ?array {
                $record = $pdo->query(
                    "SELECT * FROM billing_outbox WHERE job_type='provisioning' AND status='pending'
                     AND available_at<=UTC_TIMESTAMP() ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED"
                )->fetch(PDO::FETCH_ASSOC);
                if (!is_array($record)) {
                    return null;
                }
                $pdo->prepare("UPDATE billing_outbox SET status='processing', attempts=attempts+1, locked_at=UTC_TIMESTAMP(), updated_at=UTC_TIMESTAMP() WHERE id=:id")
                    ->execute(['id' => $record['id']]);
                return $record;
            });
            if ($row === null) {
                break;
            }
            try {
                $targets = $this->targets((int) $row['account_id'], (int) $row['subscription_id']);
                if ($targets === []) {
                    throw new RuntimeException('No eligible licensed Domain is available for POD provisioning.');
                }
                foreach ($targets as $target) {
                    $this->enqueue(
                        (int) $row['account_id'],
                        (int) $target['domain_id'],
                        (int) $target['license_id'],
                        'BILLING-' . $row['id'],
                        'billing-outbox:' . $row['id'] . ':domain:' . $target['domain_id']
                    );
                }
                $this->database->pdo()->prepare("UPDATE billing_outbox SET status='completed', completed_at=UTC_TIMESTAMP(), locked_at=NULL, last_error=NULL, updated_at=UTC_TIMESTAMP() WHERE id=:id")
                    ->execute(['id' => $row['id']]);
                $count++;
            } catch (Throwable $exception) {
                $this->database->pdo()->prepare("UPDATE billing_outbox SET status='failed', locked_at=NULL, last_error=:error, updated_at=UTC_TIMESTAMP() WHERE id=:id")
                    ->execute(['id' => $row['id'], 'error' => substr($exception->getMessage(), 0, 1000)]);
            }
        }
        return $count;
    }

    /** @return array{deployment_id:int,deployment_public_id:string,job_id:int,job_public_id:string,replayed:bool} */
    public function enqueue(int $accountId, int $domainId, int $licenseId, string $requestId, string $idempotencyKey): array
    {
        $this->required($accountId, $requestId, $idempotencyKey);
        return $this->database->transaction(function (PDO $pdo) use ($accountId, $domainId, $licenseId, $requestId, $idempotencyKey): array {
            $target = $this->target($pdo, $accountId, $domainId, $licenseId);
            $find = $pdo->prepare('SELECT id, public_id FROM pod_deployments WHERE domain_registration_id=:domain OR license_id=:license LIMIT 1 FOR UPDATE');
            $find->execute(['domain' => $domainId, 'license' => $licenseId]);
            $deployment = $find->fetch(PDO::FETCH_ASSOC);
            if (!is_array($deployment)) {
                $publicId = 'POD-' . strtoupper(bin2hex(random_bytes(12)));
                $fingerprint = hash('sha256', $publicId . '|' . random_bytes(32));
                $pdo->prepare(
                    'INSERT INTO pod_deployments
                     (public_id,account_id,subscription_id,domain_registration_id,license_id,status,installation_fingerprint,
                      update_channel,storage_allowance_bytes,license_status,created_at,updated_at)
                     VALUES (:public,:account,:subscription,:domain,:license,\'pending\',:fingerprint,:channel,:storage,:license_status,UTC_TIMESTAMP(),UTC_TIMESTAMP())'
                )->execute([
                    'public' => $publicId, 'account' => $accountId, 'subscription' => $target['subscription_id'],
                    'domain' => $domainId, 'license' => $licenseId, 'fingerprint' => $fingerprint,
                    'channel' => $target['update_channel'], 'storage' => $target['storage_allowance'],
                    'license_status' => $target['license_status'],
                ]);
                $deployment = ['id' => (int) $pdo->lastInsertId(), 'public_id' => $publicId];
                $this->event($pdo, (int) $deployment['id'], $accountId, $requestId, 'deployment_created', 'success', null, 'pending');
            }

            $existing = $pdo->prepare('SELECT id,public_id,deployment_id FROM pod_provisioning_jobs WHERE account_id=:account AND idempotency_key=:key LIMIT 1 FOR UPDATE');
            $existing->execute(['account' => $accountId, 'key' => $idempotencyKey]);
            $job = $existing->fetch(PDO::FETCH_ASSOC);
            if (is_array($job)) {
                if ((int) $job['deployment_id'] !== (int) $deployment['id']) {
                    throw new RuntimeException('Provisioning idempotency key was reused for another deployment.');
                }
                return [
                    'deployment_id' => (int) $deployment['id'], 'deployment_public_id' => (string) $deployment['public_id'],
                    'job_id' => (int) $job['id'], 'job_public_id' => (string) $job['public_id'], 'replayed' => true,
                ];
            }

            $jobPublicId = 'JOB-' . strtoupper(bin2hex(random_bytes(12)));
            $pdo->prepare(
                'INSERT INTO pod_provisioning_jobs
                 (public_id,deployment_id,account_id,job_type,status,idempotency_key,request_id,available_at,created_at,updated_at)
                 VALUES (:public,:deployment,:account,\'provision\',\'queued\',:key,:request,UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())'
            )->execute([
                'public' => $jobPublicId, 'deployment' => $deployment['id'], 'account' => $accountId,
                'key' => $idempotencyKey, 'request' => $requestId,
            ]);
            $jobId = (int) $pdo->lastInsertId();
            $insertStep = $pdo->prepare(
                'INSERT INTO pod_provisioning_steps
                 (job_id,deployment_id,stage,sequence_no,status,created_at,updated_at)
                 VALUES (:job,:deployment,:stage,:sequence,\'pending\',UTC_TIMESTAMP(),UTC_TIMESTAMP())'
            );
            foreach (self::STAGES as $index => $stage) {
                $insertStep->execute(['job' => $jobId, 'deployment' => $deployment['id'], 'stage' => $stage, 'sequence' => $index + 1]);
            }
            $pdo->prepare("UPDATE pod_deployments SET status='provisioning',updated_at=UTC_TIMESTAMP() WHERE id=:id")
                ->execute(['id' => $deployment['id']]);
            $this->event($pdo, (int) $deployment['id'], $accountId, $requestId, 'provisioning_queued', 'success', 'pending', 'provisioning');
            return [
                'deployment_id' => (int) $deployment['id'], 'deployment_public_id' => (string) $deployment['public_id'],
                'job_id' => $jobId, 'job_public_id' => $jobPublicId, 'replayed' => false,
            ];
        });
    }

    /** @return array<string,mixed>|null */
    public function processNext(string $workerId): ?array
    {
        if (trim($workerId) === '') {
            throw new RuntimeException('Worker ID is required.');
        }
        $job = $this->claim($workerId);
        if ($job === null) {
            return null;
        }
        return $job['job_type'] === 'rollback' ? $this->rollback($job) : $this->provision($job);
    }

    public function pause(int $accountId, int $jobId, string $requestId): void
    {
        $this->transition($accountId, $jobId, $requestId, ['queued', 'running', 'retrying', 'waiting'], 'paused');
    }

    public function resume(int $accountId, int $jobId, string $requestId): void
    {
        $this->transition($accountId, $jobId, $requestId, ['paused', 'failed'], 'retrying');
    }

    public function retry(int $accountId, int $jobId, string $requestId): void
    {
        $this->transition($accountId, $jobId, $requestId, ['failed', 'retrying'], 'retrying');
    }

    /** @return array{job_id:int,job_public_id:string,replayed:bool} */
    public function enqueueRollback(int $accountId, int $deploymentId, string $requestId, string $idempotencyKey): array
    {
        $this->required($accountId, $requestId, $idempotencyKey);
        return $this->database->transaction(function (PDO $pdo) use ($accountId, $deploymentId, $requestId, $idempotencyKey): array {
            $owned = $pdo->prepare('SELECT id FROM pod_deployments WHERE id=:id AND account_id=:account LIMIT 1 FOR UPDATE');
            $owned->execute(['id' => $deploymentId, 'account' => $accountId]);
            if (!$owned->fetchColumn()) {
                throw new RuntimeException('Deployment was not found for this account.');
            }
            $existing = $pdo->prepare('SELECT id,public_id FROM pod_provisioning_jobs WHERE account_id=:account AND idempotency_key=:key LIMIT 1');
            $existing->execute(['account' => $accountId, 'key' => $idempotencyKey]);
            $row = $existing->fetch(PDO::FETCH_ASSOC);
            if (is_array($row)) {
                return ['job_id' => (int) $row['id'], 'job_public_id' => (string) $row['public_id'], 'replayed' => true];
            }
            $publicId = 'JOB-' . strtoupper(bin2hex(random_bytes(12)));
            $pdo->prepare(
                'INSERT INTO pod_provisioning_jobs
                 (public_id,deployment_id,account_id,job_type,status,idempotency_key,request_id,available_at,created_at,updated_at)
                 VALUES (:public,:deployment,:account,\'rollback\',\'queued\',:key,:request,UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())'
            )->execute([
                'public' => $publicId, 'deployment' => $deploymentId, 'account' => $accountId,
                'key' => $idempotencyKey, 'request' => $requestId,
            ]);
            return ['job_id' => (int) $pdo->lastInsertId(), 'job_public_id' => $publicId, 'replayed' => false];
        });
    }

    /** @return array<string,mixed>|null */
    private function claim(string $workerId): ?array
    {
        return $this->database->transaction(function (PDO $pdo) use ($workerId): ?array {
            $job = $pdo->query(
                "SELECT * FROM pod_provisioning_jobs WHERE status IN ('queued','retrying')
                 AND available_at<=UTC_TIMESTAMP() ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED"
            )->fetch(PDO::FETCH_ASSOC);
            if (!is_array($job)) {
                return null;
            }
            $pdo->prepare(
                "UPDATE pod_provisioning_jobs SET status='running',attempts=attempts+1,locked_by=:worker,
                 locked_at=UTC_TIMESTAMP(),started_at=COALESCE(started_at,UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=:id"
            )->execute(['worker' => $workerId, 'id' => $job['id']]);
            $job['attempts'] = (int) $job['attempts'] + 1;
            return $job;
        });
    }

    /** @param array<string,mixed> $job @return array<string,mixed> */
    private function provision(array $job): array
    {
        $pdo = $this->database->pdo();
        $deployment = $this->deployment((int) $job['deployment_id']);
        $query = $pdo->prepare('SELECT * FROM pod_provisioning_steps WHERE job_id=:job ORDER BY sequence_no');
        $query->execute(['job' => $job['id']]);
        foreach ($query->fetchAll(PDO::FETCH_ASSOC) as $step) {
            if ($step['status'] === 'completed') {
                continue;
            }
            $status = $pdo->prepare('SELECT status FROM pod_provisioning_jobs WHERE id=:id');
            $status->execute(['id' => $job['id']]);
            if ($status->fetchColumn() === 'paused') {
                return ['job_id' => (int) $job['id'], 'status' => 'paused'];
            }
            try {
                $pdo->prepare("UPDATE pod_provisioning_steps SET status='running',attempts=attempts+1,started_at=COALESCE(started_at,UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=:id")
                    ->execute(['id' => $step['id']]);
                $pdo->prepare('UPDATE pod_provisioning_jobs SET current_stage=:stage,updated_at=UTC_TIMESTAMP() WHERE id=:id')
                    ->execute(['stage' => $step['stage'], 'id' => $job['id']]);
                $result = $step['stage'] === 'configuration_written'
                    ? $this->configuration($deployment, (int) $job['id'])
                    : $this->adapter->executeStage((string) $step['stage'], $deployment);
                $this->apply($deployment, (string) $step['stage'], $result);
                $hash = hash('sha256', $this->json($result));
                $pdo->prepare("UPDATE pod_provisioning_steps SET status='completed',provider_receipt_hash=:hash,completed_at=UTC_TIMESTAMP(),last_error_code=NULL,last_error_message=NULL,updated_at=UTC_TIMESTAMP() WHERE id=:id")
                    ->execute(['hash' => $hash, 'id' => $step['id']]);
                $this->receipt($pdo, $job, $step, (string) $step['stage'], 'success', $hash, $this->metadata($result));
                $deployment = $this->deployment((int) $job['deployment_id']);
            } catch (Throwable $exception) {
                $pdo->prepare("UPDATE pod_provisioning_steps SET status='failed',last_error_code=:code,last_error_message=:message,updated_at=UTC_TIMESTAMP() WHERE id=:id")
                    ->execute(['code' => substr($exception::class, 0, 100), 'message' => substr($exception->getMessage(), 0, 1000), 'id' => $step['id']]);
                $this->receipt($pdo, $job, $step, (string) $step['stage'], 'failure', null, ['error' => substr($exception->getMessage(), 0, 500)]);
                return $this->fail($job, $exception);
            }
        }
        $pdo->prepare("UPDATE pod_provisioning_jobs SET status='completed',current_stage='deployment_active',completed_at=UTC_TIMESTAMP(),locked_at=NULL,locked_by=NULL,updated_at=UTC_TIMESTAMP() WHERE id=:id")
            ->execute(['id' => $job['id']]);
        return ['job_id' => (int) $job['id'], 'deployment_id' => (int) $job['deployment_id'], 'status' => 'completed'];
    }

    /** @param array<string,mixed> $job @return array<string,mixed> */
    private function rollback(array $job): array
    {
        $pdo = $this->database->pdo();
        $deployment = $this->deployment((int) $job['deployment_id']);
        $query = $pdo->prepare(
            "SELECT s.* FROM pod_provisioning_steps s JOIN pod_provisioning_jobs j ON j.id=s.job_id
             WHERE s.deployment_id=:deployment AND j.job_type='provision' AND s.status='completed' ORDER BY s.sequence_no DESC"
        );
        $query->execute(['deployment' => $job['deployment_id']]);
        try {
            foreach ($query->fetchAll(PDO::FETCH_ASSOC) as $step) {
                $result = $this->adapter->rollbackStage((string) $step['stage'], $deployment);
                $pdo->prepare("UPDATE pod_provisioning_steps SET status='rolled_back',rolled_back_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE id=:id")
                    ->execute(['id' => $step['id']]);
                $this->receipt($pdo, $job, $step, 'rollback:' . $step['stage'], 'success', hash('sha256', $this->json($result)), $this->metadata($result));
            }
            $pdo->prepare("UPDATE pod_deployments SET status='archived',routing_status='disabled',ssl_status='disabled',archived_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE id=:id")
                ->execute(['id' => $job['deployment_id']]);
            $pdo->prepare("UPDATE pod_provisioning_jobs SET status='completed',completed_at=UTC_TIMESTAMP(),locked_at=NULL,locked_by=NULL,updated_at=UTC_TIMESTAMP() WHERE id=:id")
                ->execute(['id' => $job['id']]);
            $this->event($pdo, (int) $job['deployment_id'], (int) $job['account_id'], (string) $job['request_id'], 'deployment_rolled_back', 'success', (string) $deployment['status'], 'archived');
            return ['job_id' => (int) $job['id'], 'deployment_id' => (int) $job['deployment_id'], 'status' => 'completed'];
        } catch (Throwable $exception) {
            return $this->fail($job, $exception);
        }
    }

    /** @param array<string,mixed> $deployment @return array<string,mixed> */
    private function configuration(array $deployment, int $jobId): array
    {
        $merged = $this->merger->merge(
            $this->adapter->readConfiguration($deployment),
            $this->adapter->buildConfiguration($deployment),
            $this->protectedConfigurationPaths
        );
        $result = $this->adapter->writeConfiguration($deployment, $merged);
        $hash = hash('sha256', $this->json($merged));
        $this->database->pdo()->prepare(
            'INSERT INTO pod_configuration_receipts
             (deployment_id,job_id,configuration_hash,protected_roots_hash,merge_strategy,created_at)
             VALUES (:deployment,:job,:hash,:protected,\'preserve-existing-protected-paths\',UTC_TIMESTAMP())'
        )->execute([
            'deployment' => $deployment['id'], 'job' => $jobId, 'hash' => $hash,
            'protected' => hash('sha256', $this->json($this->protectedConfigurationPaths)),
        ]);
        return $result + ['configuration_hash' => $hash];
    }

    /** @param array<string,mixed> $deployment @param array<string,mixed> $result */
    private function apply(array $deployment, string $stage, array $result): void
    {
        $pdo = $this->database->pdo();
        $columns = [
            'hosting_allocated' => ['hosting_reference'], 'database_created' => ['database_reference'],
            'pod_installed' => ['installed_version'], 'license_injected' => ['license_status'],
            'ssl_requested' => ['ssl_status'], 'installation_verified' => ['installation_fingerprint', 'backup_status'],
        ];
        $sets = [];
        $parameters = ['id' => $deployment['id']];
        foreach ($columns[$stage] ?? [] as $column) {
            if (isset($result[$column]) && is_scalar($result[$column])) {
                $sets[] = $column . '=:' . $column;
                $parameters[$column] = (string) $result[$column];
            }
        }
        if ($stage === 'domain_registered') {
            $pdo->prepare("UPDATE domain_registrations SET status='active',registered_at=COALESCE(registered_at,UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=:id AND account_id=:account")
                ->execute(['id' => $deployment['domain_registration_id'], 'account' => $deployment['account_id']]);
        }
        if ($stage === 'deployment_active') {
            $sets = array_merge($sets, ["status='active'", "routing_status='active'", "ssl_status=IF(ssl_status='pending','active',ssl_status)", "license_status=IF(license_status='pending','active',license_status)", 'activated_at=COALESCE(activated_at,UTC_TIMESTAMP())']);
            $pdo->prepare("UPDATE domain_registrations SET status='active',routing_status='active',ssl_status=IF(ssl_status='pending','active',ssl_status),updated_at=UTC_TIMESTAMP() WHERE id=:id AND account_id=:account")
                ->execute(['id' => $deployment['domain_registration_id'], 'account' => $deployment['account_id']]);
        }
        if ($sets !== []) {
            $pdo->prepare('UPDATE pod_deployments SET ' . implode(',', $sets) . ',updated_at=UTC_TIMESTAMP() WHERE id=:id')->execute($parameters);
        }
    }

    /** @param array<string,mixed> $job @return array<string,mixed> */
    private function fail(array $job, Throwable $exception): array
    {
        $status = (int) $job['attempts'] < (int) $job['max_attempts'] ? 'retrying' : 'failed';
        $this->database->pdo()->prepare(
            "UPDATE pod_provisioning_jobs SET status=:status,available_at=DATE_ADD(UTC_TIMESTAMP(),INTERVAL 60 SECOND),
             locked_at=NULL,locked_by=NULL,last_error_code=:code,last_error_message=:message,updated_at=UTC_TIMESTAMP() WHERE id=:id"
        )->execute([
            'status' => $status, 'code' => substr($exception::class, 0, 100),
            'message' => substr($exception->getMessage(), 0, 1000), 'id' => $job['id'],
        ]);
        $this->database->pdo()->prepare("UPDATE pod_deployments SET status='failed',updated_at=UTC_TIMESTAMP() WHERE id=:id")
            ->execute(['id' => $job['deployment_id']]);
        return ['job_id' => (int) $job['id'], 'deployment_id' => (int) $job['deployment_id'], 'status' => $status, 'error' => $exception->getMessage()];
    }

    /** @return list<array{domain_id:int,license_id:int}> */
    private function targets(int $accountId, int $subscriptionId): array
    {
        $query = $this->database->pdo()->prepare(
            "SELECT d.id domain_id,l.id license_id FROM domain_registrations d
             JOIN subscriptions s ON s.id=d.subscription_id AND s.account_id=d.account_id
             JOIN licenses l ON l.domain_registration_id=d.id AND l.account_id=d.account_id AND l.product_type='pod'
             LEFT JOIN pod_deployments p ON p.domain_registration_id=d.id
             WHERE d.account_id=:account AND d.subscription_id=:subscription
             AND s.status IN ('active','trialing','grace') AND d.status IN ('reserved','pending','active','grace')
             AND l.status IN ('active','grace') AND p.id IS NULL ORDER BY d.id"
        );
        $query->execute(['account' => $accountId, 'subscription' => $subscriptionId]);
        return $query->fetchAll(PDO::FETCH_ASSOC);
    }

    /** @return array{subscription_id:int,update_channel:string,storage_allowance:int,license_status:string} */
    private function target(PDO $pdo, int $accountId, int $domainId, int $licenseId): array
    {
        $query = $pdo->prepare(
            "SELECT d.subscription_id,l.status license_status,
             COALESCE(JSON_UNQUOTE(channel_entitlement.value_json),'stable') update_channel,
             COALESCE(CAST(JSON_UNQUOTE(storage_entitlement.value_json) AS UNSIGNED),0) storage_allowance
             FROM domain_registrations d JOIN subscriptions s ON s.id=d.subscription_id AND s.account_id=d.account_id
             JOIN licenses l ON l.id=:license AND l.domain_registration_id=d.id AND l.account_id=d.account_id AND l.product_type='pod'
             LEFT JOIN license_entitlements channel_entitlement ON channel_entitlement.license_id=l.id AND channel_entitlement.entitlement_key='update_channel'
             LEFT JOIN license_entitlements storage_entitlement ON storage_entitlement.license_id=l.id AND storage_entitlement.entitlement_key='storage_bytes'
             WHERE d.id=:domain AND d.account_id=:account AND s.status IN ('active','trialing','grace')
             AND d.status IN ('reserved','pending','active','grace') AND l.status IN ('active','grace') LIMIT 1 FOR UPDATE"
        );
        $query->execute(['license' => $licenseId, 'domain' => $domainId, 'account' => $accountId]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('The Domain and POD license are not eligible for provisioning.');
        }
        return [
            'subscription_id' => (int) $row['subscription_id'],
            'update_channel' => trim((string) $row['update_channel'], '"') ?: 'stable',
            'storage_allowance' => max(0, (int) $row['storage_allowance']),
            'license_status' => (string) $row['license_status'],
        ];
    }

    /** @return array<string,mixed> */
    private function deployment(int $id): array
    {
        $query = $this->database->pdo()->prepare('SELECT * FROM pod_deployments WHERE id=:id LIMIT 1');
        $query->execute(['id' => $id]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('POD deployment was not found.');
        }
        return $row;
    }

    /** @param list<string> $allowed */
    private function transition(int $accountId, int $jobId, string $requestId, array $allowed, string $next): void
    {
        if ($accountId < 1 || trim($requestId) === '') {
            throw new RuntimeException('Account and request ID are required.');
        }
        $marks = implode(',', array_fill(0, count($allowed), '?'));
        $statement = $this->database->pdo()->prepare(
            "UPDATE pod_provisioning_jobs SET status=?,request_id=?,available_at=UTC_TIMESTAMP(),locked_at=NULL,locked_by=NULL,
             last_error_code=NULL,last_error_message=NULL,updated_at=UTC_TIMESTAMP() WHERE id=? AND account_id=? AND status IN ({$marks})"
        );
        $statement->execute(array_merge([$next, $requestId, $jobId, $accountId], $allowed));
        if ($statement->rowCount() !== 1) {
            throw new RuntimeException('Provisioning job cannot transition to ' . $next . '.');
        }
    }

    private function required(int $accountId, string $requestId, string $idempotencyKey): void
    {
        if ($accountId < 1 || trim($requestId) === '' || trim($idempotencyKey) === '') {
            throw new RuntimeException('Account, request ID, and idempotency key are required.');
        }
    }

    /** @param array<string,mixed> $job @param array<string,mixed> $step @param array<string,mixed> $metadata */
    private function receipt(PDO $pdo, array $job, array $step, string $operation, string $result, ?string $hash, array $metadata): void
    {
        $pdo->prepare(
            'INSERT INTO pod_provisioning_receipts
             (public_id,account_id,deployment_id,job_id,step_id,request_id,operation,result,external_reference_hash,metadata_json,created_at)
             VALUES (:public,:account,:deployment,:job,:step,:request,:operation,:result,:hash,:metadata,UTC_TIMESTAMP())'
        )->execute([
            'public' => 'RCP-' . strtoupper(bin2hex(random_bytes(12))), 'account' => $job['account_id'],
            'deployment' => $job['deployment_id'], 'job' => $job['id'], 'step' => $step['id'] ?? null,
            'request' => $job['request_id'], 'operation' => substr($operation, 0, 100), 'result' => $result,
            'hash' => $hash, 'metadata' => $metadata === [] ? null : $this->json($metadata),
        ]);
    }

    private function event(PDO $pdo, int $deployment, int $account, string $request, string $type, string $result, ?string $from, ?string $to): void
    {
        $pdo->prepare(
            'INSERT INTO pod_deployment_events
             (deployment_id,account_id,request_id,event_type,result,from_status,to_status,created_at)
             VALUES (:deployment,:account,:request,:type,:result,:from_status,:to_status,UTC_TIMESTAMP())'
        )->execute([
            'deployment' => $deployment, 'account' => $account, 'request' => $request,
            'type' => $type, 'result' => $result, 'from_status' => $from, 'to_status' => $to,
        ]);
    }

    /** @param array<string,mixed> $value @return array<string,mixed> */
    private function metadata(array $value): array
    {
        return array_intersect_key($value, array_flip([
            'hosting_reference', 'database_reference', 'installed_version', 'license_status',
            'ssl_status', 'backup_status', 'configuration_hash', 'provider_request_id',
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
