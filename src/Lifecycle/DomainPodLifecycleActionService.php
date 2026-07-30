<?php

declare(strict_types=1);

namespace Vp3\Lifecycle;

use PDO;
use Vp3\Auth\AuthPublicException;
use Vp3\Database;
use Vp3\DomainCodes\DomainRegistryService;
use Vp3\Provisioning\PodProvisioningService;

final class DomainPodLifecycleActionService
{
    private const ROLES = ['customer_owner', 'customer_admin'];
    private const OPEN_JOB_STATUSES = ['queued', 'running', 'waiting', 'retrying', 'paused', 'failed'];

    public function __construct(
        private readonly Database $database,
        private readonly DomainRegistryService $domains,
        private readonly PodProvisioningService $pods
    ) {
    }

    /** @return array{label:string,hostname:string,available:bool} */
    public function availability(int $accountId, int $actorId, string $role, string $label): array
    {
        return $this->database->transaction(function (PDO $pdo) use ($accountId, $actorId, $role, $label): array {
            $this->authorize($pdo, $accountId, $actorId, $role);
            return $this->domains->availability($label);
        });
    }

    /** @return array<string,mixed> */
    public function registerDomain(
        int $accountId,
        int $actorId,
        string $role,
        string $subscriptionPublicId,
        string $label,
        string $requestId,
        string $idempotencyKey
    ): array {
        $this->publicId($subscriptionPublicId, 'subscription');
        return $this->run(
            $accountId,
            $actorId,
            $role,
            'domain_register',
            $subscriptionPublicId,
            $requestId,
            function (PDO $pdo) use (
                $accountId,
                $actorId,
                $subscriptionPublicId,
                $label,
                $requestId,
                $idempotencyKey
            ): array {
                $statement = $pdo->prepare(
                    "SELECT id
                     FROM subscriptions
                     WHERE public_id=:public AND account_id=:account
                       AND status IN ('active','trialing')
                     LIMIT 1 FOR UPDATE"
                );
                $statement->execute(['public' => $subscriptionPublicId, 'account' => $accountId]);
                $subscriptionId = (int) $statement->fetchColumn();
                if ($subscriptionId < 1) {
                    throw new AuthPublicException(
                        'lifecycle_subscription_not_found',
                        'An eligible account-owned subscription was not found.',
                        404
                    );
                }

                $result = $this->domains->registerAndActivate(
                    $accountId,
                    $subscriptionId,
                    $label,
                    $requestId,
                    $idempotencyKey
                );
                $public = [
                    'domain_public_id' => (string) $result['domain_public_id'],
                    'hostname' => (string) $result['hostname'],
                    'status' => 'active',
                    'entitlement_bundle_public_id' => (string) $result['entitlement_bundle_public_id'],
                    'pod_license_public_id' => (string) $result['pod_license_public_id'],
                    'homeserver_license_public_id' => (string) $result['homeserver_license_public_id'],
                ];
                $this->audit(
                    $pdo,
                    $accountId,
                    $actorId,
                    'lifecycle.domain_registered',
                    'success',
                    'domain_registration',
                    $public['domain_public_id'],
                    $requestId
                );
                return $public;
            }
        );
    }

    /** @return array<string,mixed> */
    public function activateReservedDomain(
        int $accountId,
        int $actorId,
        string $role,
        string $domainPublicId,
        string $requestId,
        string $idempotencyKey
    ): array {
        $this->publicId($domainPublicId, 'Domain');
        return $this->run(
            $accountId,
            $actorId,
            $role,
            'domain_activate_reserved',
            $domainPublicId,
            $requestId,
            function (PDO $pdo) use ($accountId, $actorId, $domainPublicId, $requestId, $idempotencyKey): array {
                $this->ownedDomain($pdo, $accountId, $domainPublicId);
                $result = $this->domains->activateReservedDomain(
                    $accountId,
                    $domainPublicId,
                    $requestId,
                    $idempotencyKey
                );
                $public = [
                    'domain_public_id' => (string) $result['domain_public_id'],
                    'hostname' => (string) $result['hostname'],
                    'status' => 'active',
                    'entitlement_bundle_public_id' => (string) $result['entitlement_bundle_public_id'],
                    'pod_license_public_id' => (string) $result['pod_license_public_id'],
                    'homeserver_license_public_id' => (string) $result['homeserver_license_public_id'],
                ];
                $this->audit($pdo, $accountId, $actorId, 'lifecycle.domain_reservation_activated', 'success', 'domain_registration', $domainPublicId, $requestId);
                return $public;
            }
        );
    }

    /** @return array{domain_public_id:string,status:string} */
    public function suspendDomain(
        int $accountId,
        int $actorId,
        string $role,
        string $domainPublicId,
        string $reason,
        string $requestId,
        string $idempotencyKey
    ): array {
        $this->publicId($domainPublicId, 'Domain');
        return $this->run(
            $accountId,
            $actorId,
            $role,
            'domain_suspend',
            $domainPublicId,
            $requestId,
            function (PDO $pdo) use ($accountId, $actorId, $domainPublicId, $reason, $requestId, $idempotencyKey): array {
                $this->ownedDomain($pdo, $accountId, $domainPublicId);
                $result = $this->domains->suspendDomain(
                    $accountId,
                    $domainPublicId,
                    $requestId,
                    $idempotencyKey,
                    $reason
                );
                $this->audit($pdo, $accountId, $actorId, 'lifecycle.domain_suspended', 'success', 'domain_registration', $domainPublicId, $requestId);
                return [
                    'domain_public_id' => (string) $result['domain_public_id'],
                    'status' => (string) $result['status'],
                ];
            }
        );
    }

    /** @return array{domain_public_id:string,status:string} */
    public function releaseDomain(
        int $accountId,
        int $actorId,
        string $role,
        string $domainPublicId,
        string $confirmation,
        string $requestId,
        string $idempotencyKey
    ): array {
        $this->publicId($domainPublicId, 'Domain');
        if ($confirmation !== 'RELEASE') {
            throw new AuthPublicException(
                'lifecycle_release_confirmation_required',
                'Domain release requires the exact confirmation RELEASE.',
                422
            );
        }
        return $this->run(
            $accountId,
            $actorId,
            $role,
            'domain_release',
            $domainPublicId,
            $requestId,
            function (PDO $pdo) use ($accountId, $actorId, $domainPublicId, $requestId, $idempotencyKey): array {
                $this->ownedDomain($pdo, $accountId, $domainPublicId);
                $result = $this->domains->releaseDomain(
                    $accountId,
                    $domainPublicId,
                    $requestId,
                    $idempotencyKey
                );
                $this->audit($pdo, $accountId, $actorId, 'lifecycle.domain_released', 'success', 'domain_registration', $domainPublicId, $requestId);
                return [
                    'domain_public_id' => (string) $result['domain_public_id'],
                    'status' => (string) $result['status'],
                ];
            }
        );
    }

    /** @return array{deployment_public_id:string,job_public_id:string,status:string,replayed:bool} */
    public function provisionPod(
        int $accountId,
        int $actorId,
        string $role,
        string $domainPublicId,
        string $requestId,
        string $idempotencyKey
    ): array {
        $this->publicId($domainPublicId, 'Domain');
        return $this->run(
            $accountId,
            $actorId,
            $role,
            'pod_provision',
            $domainPublicId,
            $requestId,
            function (PDO $pdo) use ($accountId, $actorId, $domainPublicId, $requestId, $idempotencyKey): array {
                $target = $pdo->prepare(
                    "SELECT d.id domain_id,l.id license_id
                     FROM domain_registrations d
                     JOIN licenses l
                       ON l.domain_registration_id=d.id
                      AND l.account_id=d.account_id
                      AND l.product_type='pod'
                     WHERE d.public_id=:public AND d.account_id=:account
                       AND d.status IN ('active','grace')
                       AND l.status IN ('active','grace')
                     LIMIT 1 FOR UPDATE"
                );
                $target->execute(['public' => $domainPublicId, 'account' => $accountId]);
                $row = $target->fetch(PDO::FETCH_ASSOC);
                if (!is_array($row)) {
                    throw new AuthPublicException(
                        'lifecycle_pod_target_not_found',
                        'An eligible account-owned Domain and POD license were not found.',
                        404
                    );
                }

                $replay = $pdo->prepare(
                    "SELECT j.public_id job_public_id,p.public_id deployment_public_id,j.job_type,j.status,p.domain_registration_id
                     FROM pod_provisioning_jobs j
                     JOIN pod_deployments p ON p.id=j.deployment_id AND p.account_id=j.account_id
                     WHERE j.account_id=:account AND j.idempotency_key=:idempotency
                     LIMIT 1 FOR UPDATE"
                );
                $replay->execute(['account' => $accountId, 'idempotency' => $idempotencyKey]);
                $existing = $replay->fetch(PDO::FETCH_ASSOC);
                if (is_array($existing)) {
                    if ((string) $existing['job_type'] !== 'provision'
                        || (int) $existing['domain_registration_id'] !== (int) $row['domain_id']) {
                        throw new AuthPublicException(
                            'lifecycle_idempotency_conflict',
                            'The idempotency key was already used for another lifecycle request.',
                            409
                        );
                    }
                    return [
                        'deployment_public_id' => (string) $existing['deployment_public_id'],
                        'job_public_id' => (string) $existing['job_public_id'],
                        'status' => (string) $existing['status'],
                        'replayed' => true,
                    ];
                }

                $deployment = $pdo->prepare(
                    'SELECT public_id FROM pod_deployments
                     WHERE domain_registration_id=:domain OR license_id=:license
                     LIMIT 1 FOR UPDATE'
                );
                $deployment->execute(['domain' => $row['domain_id'], 'license' => $row['license_id']]);
                if ($deployment->fetchColumn()) {
                    throw new AuthPublicException(
                        'lifecycle_pod_already_exists',
                        'This Domain already has a POD deployment. Use the existing job controls instead.',
                        409
                    );
                }

                $result = $this->pods->enqueue(
                    $accountId,
                    (int) $row['domain_id'],
                    (int) $row['license_id'],
                    $requestId,
                    $idempotencyKey
                );
                $public = [
                    'deployment_public_id' => (string) $result['deployment_public_id'],
                    'job_public_id' => (string) $result['job_public_id'],
                    'status' => 'queued',
                    'replayed' => (bool) $result['replayed'],
                ];
                $this->audit($pdo, $accountId, $actorId, 'lifecycle.pod_provision_queued', 'success', 'pod_deployment', $public['deployment_public_id'], $requestId);
                return $public;
            }
        );
    }

    /** @return array{job_public_id:string,status:string,current_stage:?string,attempts:int} */
    public function transitionPodJob(
        int $accountId,
        int $actorId,
        string $role,
        string $jobPublicId,
        string $action,
        string $requestId
    ): array {
        $this->publicId($jobPublicId, 'POD job');
        $action = strtolower(trim($action));
        if (!in_array($action, ['pause', 'resume', 'retry'], true)) {
            throw new AuthPublicException('lifecycle_pod_action_invalid', 'The POD job action is invalid.', 422);
        }

        return $this->run(
            $accountId,
            $actorId,
            $role,
            'pod_' . $action,
            $jobPublicId,
            $requestId,
            function (PDO $pdo) use ($accountId, $actorId, $jobPublicId, $action, $requestId): array {
                $statement = $pdo->prepare(
                    'SELECT id,public_id
                     FROM pod_provisioning_jobs
                     WHERE public_id=:public AND account_id=:account
                     LIMIT 1 FOR UPDATE'
                );
                $statement->execute(['public' => $jobPublicId, 'account' => $accountId]);
                $job = $statement->fetch(PDO::FETCH_ASSOC);
                if (!is_array($job)) {
                    throw new AuthPublicException('lifecycle_pod_job_not_found', 'The account-owned POD job was not found.', 404);
                }

                match ($action) {
                    'pause' => $this->pods->pause($accountId, (int) $job['id'], $requestId),
                    'resume' => $this->pods->resume($accountId, (int) $job['id'], $requestId),
                    'retry' => $this->pods->retry($accountId, (int) $job['id'], $requestId),
                };
                $status = $pdo->prepare(
                    'SELECT status,current_stage,attempts
                     FROM pod_provisioning_jobs
                     WHERE id=:id AND account_id=:account'
                );
                $status->execute(['id' => $job['id'], 'account' => $accountId]);
                $row = $status->fetch(PDO::FETCH_ASSOC);
                if (!is_array($row)) {
                    throw new AuthPublicException('lifecycle_pod_job_not_found', 'The POD job status was not found.', 404);
                }
                $this->audit($pdo, $accountId, $actorId, 'lifecycle.pod_job_' . $action, 'success', 'pod_provisioning_job', $jobPublicId, $requestId);
                return [
                    'job_public_id' => $jobPublicId,
                    'status' => (string) $row['status'],
                    'current_stage' => $row['current_stage'] === null ? null : (string) $row['current_stage'],
                    'attempts' => (int) $row['attempts'],
                ];
            }
        );
    }

    /** @return array{job_public_id:string,status:string,replayed:bool} */
    public function rollbackPod(
        int $accountId,
        int $actorId,
        string $role,
        string $deploymentPublicId,
        string $confirmation,
        string $requestId,
        string $idempotencyKey
    ): array {
        $this->publicId($deploymentPublicId, 'POD deployment');
        if ($confirmation !== 'ROLLBACK') {
            throw new AuthPublicException(
                'lifecycle_rollback_confirmation_required',
                'POD rollback requires the exact confirmation ROLLBACK.',
                422
            );
        }

        return $this->run(
            $accountId,
            $actorId,
            $role,
            'pod_rollback',
            $deploymentPublicId,
            $requestId,
            function (PDO $pdo) use ($accountId, $actorId, $deploymentPublicId, $requestId, $idempotencyKey): array {
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
                    ];
                }

                $marks = implode(',', array_fill(0, count(self::OPEN_JOB_STATUSES), '?'));
                $open = $pdo->prepare(
                    "SELECT public_id
                     FROM pod_provisioning_jobs
                     WHERE deployment_id=? AND account_id=? AND status IN ({$marks})
                     ORDER BY id DESC
                     LIMIT 1 FOR UPDATE"
                );
                $open->execute([$deploymentId, $accountId, ...self::OPEN_JOB_STATUSES]);
                if ($open->fetchColumn()) {
                    throw new AuthPublicException(
                        'lifecycle_pod_job_open',
                        'Another POD lifecycle job is already open for this deployment.',
                        409
                    );
                }

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
                ];
                $this->audit($pdo, $accountId, $actorId, 'lifecycle.pod_rollback_queued', 'success', 'pod_deployment', $deploymentPublicId, $requestId);
                return $public;
            }
        );
    }

    /** @template T @param callable(PDO):T $work @return T */
    private function run(
        int $accountId,
        int $actorId,
        string $role,
        string $operation,
        string $resourcePublicId,
        string $requestId,
        callable $work
    ): mixed {
        try {
            return $this->database->transaction(function (PDO $pdo) use ($accountId, $actorId, $role, $work): mixed {
                $this->authorize($pdo, $accountId, $actorId, $role);
                return $work($pdo);
            });
        } catch (AuthPublicException $exception) {
            if ($exception->publicCode() === 'lifecycle_permission_denied') {
                $this->database->transaction(function (PDO $pdo) use (
                    $accountId,
                    $actorId,
                    $operation,
                    $resourcePublicId,
                    $requestId
                ): void {
                    $this->audit(
                        $pdo,
                        $accountId,
                        $actorId,
                        'lifecycle.' . $operation,
                        'denied',
                        'lifecycle_resource',
                        $resourcePublicId,
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
                'An active customer owner or administrator membership is required for Domain and POD lifecycle actions.',
                403
            );
        }
    }

    private function ownedDomain(PDO $pdo, int $accountId, string $domainPublicId): int
    {
        $statement = $pdo->prepare(
            'SELECT id
             FROM domain_registrations
             WHERE public_id=:public AND account_id=:account
             LIMIT 1 FOR UPDATE'
        );
        $statement->execute(['public' => $domainPublicId, 'account' => $accountId]);
        $domainId = (int) $statement->fetchColumn();
        if ($domainId < 1) {
            throw new AuthPublicException('lifecycle_domain_not_found', 'The account-owned Domain was not found.', 404);
        }
        return $domainId;
    }

    private function publicId(string $publicId, string $label): void
    {
        if (!preg_match('/^[A-Za-z0-9._:-]{3,190}$/', trim($publicId))) {
            throw new AuthPublicException('lifecycle_public_id_invalid', 'A valid ' . $label . ' identity is required.', 422);
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
