<?php

declare(strict_types=1);

namespace Vp3\Lifecycle;

use PDO;
use Vp3\Auth\AuthPublicException;
use Vp3\Database;
use Vp3\Provisioning\PodProvisioningService;

final class PodRollbackLifecycleService
{
    private const ROLES = ['customer_owner', 'customer_admin'];
    private const ACTIVE_JOB_STATUSES = ['queued', 'running', 'waiting', 'retrying', 'paused'];

    public function __construct(
        private readonly Database $database,
        private readonly PodProvisioningService $pods
    ) {
    }

    /** @return array{job_public_id:string,status:string,replayed:bool,replaced_failed_jobs:int} */
    public function enqueue(
        int $accountId,
        int $actorId,
        string $role,
        string $deploymentPublicId,
        string $confirmation,
        string $requestId,
        string $idempotencyKey
    ): array {
        if (!preg_match('/^[A-Za-z0-9._:-]{3,190}$/', trim($deploymentPublicId))) {
            throw new AuthPublicException('lifecycle_public_id_invalid', 'A valid POD deployment identity is required.', 422);
        }
        if ($confirmation !== 'ROLLBACK') {
            throw new AuthPublicException(
                'lifecycle_rollback_confirmation_required',
                'POD rollback requires the exact confirmation ROLLBACK.',
                422
            );
        }

        try {
            return $this->database->transaction(function (PDO $pdo) use (
                $accountId,
                $actorId,
                $role,
                $deploymentPublicId,
                $requestId,
                $idempotencyKey
            ): array {
                $this->authorize($pdo, $accountId, $actorId, $role);

                $deployment = $pdo->prepare(
                    'SELECT id
                     FROM pod_deployments
                     WHERE public_id=:public AND account_id=:account
                     LIMIT 1 FOR UPDATE'
                );
                $deployment->execute(['public' => $deploymentPublicId, 'account' => $accountId]);
                $deploymentId = (int) $deployment->fetchColumn();
                if ($deploymentId < 1) {
                    throw new AuthPublicException('lifecycle_pod_not_found', 'The account-owned POD deployment was not found.', 404);
                }

                $replay = $pdo->prepare(
                    'SELECT public_id,deployment_id,job_type,status
                     FROM pod_provisioning_jobs
                     WHERE account_id=:account AND idempotency_key=:idempotency
                     LIMIT 1 FOR UPDATE'
                );
                $replay->execute(['account' => $accountId, 'idempotency' => $idempotencyKey]);
                $existing = $replay->fetch(PDO::FETCH_ASSOC);
                if (is_array($existing)) {
                    if ((int) $existing['deployment_id'] !== $deploymentId
                        || (string) $existing['job_type'] !== 'rollback') {
                        throw new AuthPublicException(
                            'lifecycle_idempotency_conflict',
                            'The idempotency key was already used for another lifecycle request.',
                            409
                        );
                    }
                    return [
                        'job_public_id' => (string) $existing['public_id'],
                        'status' => (string) $existing['status'],
                        'replayed' => true,
                        'replaced_failed_jobs' => 0,
                    ];
                }

                $marks = implode(',', array_fill(0, count(self::ACTIVE_JOB_STATUSES), '?'));
                $open = $pdo->prepare(
                    "SELECT public_id
                     FROM pod_provisioning_jobs
                     WHERE deployment_id=? AND account_id=? AND status IN ({$marks})
                     ORDER BY id DESC
                     LIMIT 1 FOR UPDATE"
                );
                $open->execute([$deploymentId, $accountId, ...self::ACTIVE_JOB_STATUSES]);
                if ($open->fetchColumn()) {
                    throw new AuthPublicException(
                        'lifecycle_pod_job_open',
                        'Another active POD lifecycle job is already open for this deployment.',
                        409
                    );
                }

                $failed = $pdo->prepare(
                    "UPDATE pod_provisioning_jobs
                     SET status='canceled',completed_at=COALESCE(completed_at,UTC_TIMESTAMP()),
                         locked_at=NULL,locked_by=NULL,locked_until=NULL,lease_token=NULL,
                         updated_at=UTC_TIMESTAMP()
                     WHERE deployment_id=:deployment AND account_id=:account AND status='failed'"
                );
                $failed->execute(['deployment' => $deploymentId, 'account' => $accountId]);
                $replaced = $failed->rowCount();

                $result = $this->pods->enqueueRollback(
                    $accountId,
                    $deploymentId,
                    $requestId,
                    $idempotencyKey
                );
                $public = [
                    'job_public_id' => (string) $result['job_public_id'],
                    'status' => 'queued',
                    'replayed' => (bool) $result['replayed'],
                    'replaced_failed_jobs' => $replaced,
                ];
                $this->audit(
                    $pdo,
                    $accountId,
                    $actorId,
                    'lifecycle.pod_rollback_queued',
                    'success',
                    'pod_deployment',
                    $deploymentPublicId,
                    $requestId
                );
                return $public;
            });
        } catch (AuthPublicException $exception) {
            if ($exception->publicCode() === 'lifecycle_permission_denied') {
                $this->database->transaction(function (PDO $pdo) use (
                    $accountId,
                    $actorId,
                    $deploymentPublicId,
                    $requestId
                ): void {
                    $this->audit(
                        $pdo,
                        $accountId,
                        $actorId,
                        'lifecycle.pod_rollback',
                        'denied',
                        'pod_deployment',
                        $deploymentPublicId,
                        $requestId
                    );
                });
            }
            throw $exception;
        }
    }

    private function authorize(PDO $pdo, int $accountId, int $actorId, string $role): void
    {
        $statement = $pdo->prepare(
            "SELECT role
             FROM account_users
             WHERE account_id=:account AND user_id=:actor AND status='active'
             LIMIT 1 FOR UPDATE"
        );
        $statement->execute(['account' => $accountId, 'actor' => $actorId]);
        $storedRole = $statement->fetchColumn();
        if (!is_string($storedRole)
            || !hash_equals($storedRole, $role)
            || !in_array($storedRole, self::ROLES, true)) {
            throw new AuthPublicException(
                'lifecycle_permission_denied',
                'An active customer owner or administrator membership is required for POD rollback.',
                403
            );
        }
    }

    private function audit(
        PDO $pdo,
        int $accountId,
        int $actorId,
        string $eventType,
        string $result,
        string $resourceType,
        string $resourcePublicId,
        string $requestId
    ): void {
        $pdo->prepare(
            "INSERT INTO audit_events
             (request_id,actor_type,actor_id,account_id,event_type,resource_type,
              resource_public_id,result,created_at)
             VALUES
             (:request,'user',:actor,:account,:event,:resource_type,:resource_public_id,
              :result,UTC_TIMESTAMP())"
        )->execute([
            'request' => substr($requestId, 0, 64),
            'actor' => $actorId,
            'account' => $accountId,
            'event' => substr($eventType, 0, 100),
            'resource_type' => substr($resourceType, 0, 80),
            'resource_public_id' => substr($resourcePublicId, 0, 190),
            'result' => $result,
        ]);
    }
}
