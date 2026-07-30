<?php

declare(strict_types=1);

namespace Vp3\Infrastructure;

use PDO;
use Vp3\Auth\AuthPublicException;
use Vp3\Database;

final class InfrastructureControlCenterQueueService
{
    private const ROLES = ['customer_owner', 'customer_admin'];

    /** @var array<string,list<string>> */
    private const STAGES = [
        'reconcile' => ['hosting_verify', 'dns_verify', 'certificate_verify', 'active'],
        'teardown' => ['certificate_revoke', 'dns_remove', 'hosting_release', 'disabled'],
    ];

    public function __construct(private readonly Database $database)
    {
    }

    /** @return array{public_id:string,binding_public_id:string,status:string,replayed:bool} */
    public function enqueue(
        int $accountId,
        int $actorId,
        string $role,
        string $bindingPublicId,
        string $operationType,
        string $confirmation,
        string $requestId,
        string $idempotencyKey
    ): array {
        $bindingPublicId = trim($bindingPublicId);
        $operationType = strtolower(trim($operationType));
        if (!preg_match('/^[A-Za-z0-9._:-]{3,190}$/', $bindingPublicId)) {
            throw new AuthPublicException('infrastructure_binding_invalid', 'A valid infrastructure binding identity is required.', 422);
        }
        if (!array_key_exists($operationType, self::STAGES)) {
            throw new AuthPublicException('infrastructure_operation_invalid', 'The infrastructure operation is invalid.', 422);
        }
        if ($operationType === 'teardown' && $confirmation !== 'TEARDOWN') {
            throw new AuthPublicException(
                'infrastructure_teardown_confirmation_required',
                'Infrastructure teardown requires the exact confirmation TEARDOWN.',
                422
            );
        }
        if (!preg_match('/^[A-Za-z0-9._:-]{8,64}$/', $requestId)) {
            throw new AuthPublicException('infrastructure_request_id_invalid', 'A valid request ID is required.', 400);
        }
        if (!preg_match('/^[A-Za-z0-9._:-]{8,128}$/', $idempotencyKey)) {
            throw new AuthPublicException('infrastructure_idempotency_invalid', 'A valid idempotency key is required.', 400);
        }

        try {
            return $this->database->transaction(function (PDO $pdo) use (
                $accountId,
                $actorId,
                $role,
                $bindingPublicId,
                $operationType,
                $requestId,
                $idempotencyKey
            ): array {
                $this->authorize($pdo, $accountId, $actorId, $role);

                $bindingStatement = $pdo->prepare(
                    'SELECT id,status
                     FROM infrastructure_bindings
                     WHERE public_id=:public AND account_id=:account
                     LIMIT 1 FOR UPDATE'
                );
                $bindingStatement->execute(['public' => $bindingPublicId, 'account' => $accountId]);
                $binding = $bindingStatement->fetch(PDO::FETCH_ASSOC);
                if (!is_array($binding)) {
                    throw new AuthPublicException(
                        'infrastructure_binding_not_found',
                        'The account-owned infrastructure binding was not found.',
                        404
                    );
                }

                $replayStatement = $pdo->prepare(
                    'SELECT public_id,binding_id,operation_type,status
                     FROM provider_operations
                     WHERE account_id=:account AND idempotency_key=:idempotency
                     LIMIT 1 FOR UPDATE'
                );
                $replayStatement->execute([
                    'account' => $accountId,
                    'idempotency' => $idempotencyKey,
                ]);
                $replay = $replayStatement->fetch(PDO::FETCH_ASSOC);
                if (is_array($replay)) {
                    if ((int) $replay['binding_id'] !== (int) $binding['id']
                        || (string) $replay['operation_type'] !== $operationType) {
                        throw new AuthPublicException(
                            'infrastructure_idempotency_conflict',
                            'The idempotency key was already used for another infrastructure request.',
                            409
                        );
                    }
                    return [
                        'public_id' => (string) $replay['public_id'],
                        'binding_public_id' => $bindingPublicId,
                        'status' => (string) $replay['status'],
                        'replayed' => true,
                    ];
                }

                $openStatement = $pdo->prepare(
                    "SELECT public_id,status
                     FROM provider_operations
                     WHERE binding_id=:binding
                       AND account_id=:account
                       AND status NOT IN ('completed','canceled')
                     ORDER BY id DESC
                     LIMIT 1 FOR UPDATE"
                );
                $openStatement->execute([
                    'binding' => $binding['id'],
                    'account' => $accountId,
                ]);
                $open = $openStatement->fetch(PDO::FETCH_ASSOC);
                if (is_array($open)) {
                    throw new AuthPublicException(
                        'infrastructure_operation_open',
                        'Another infrastructure operation is already open for this binding.',
                        409
                    );
                }

                if ($operationType === 'reconcile'
                    && in_array((string) $binding['status'], ['disabled', 'tearing_down'], true)) {
                    throw new AuthPublicException(
                        'infrastructure_reconcile_unavailable',
                        'Disabled or tearing-down infrastructure cannot be reconciled.',
                        409
                    );
                }
                if ($operationType === 'teardown' && (string) $binding['status'] === 'disabled') {
                    throw new AuthPublicException(
                        'infrastructure_teardown_unavailable',
                        'The infrastructure binding is already disabled.',
                        409
                    );
                }

                $publicId = 'PROVIDER-OP-' . strtoupper(bin2hex(random_bytes(12)));
                $pdo->prepare(
                    "INSERT INTO provider_operations
                     (public_id,account_id,binding_id,operation_type,status,current_stage,
                      idempotency_key,request_id,available_at,created_at,updated_at)
                     VALUES
                     (:public,:account,:binding,:type,'queued',NULL,:idempotency,:request,
                      UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())"
                )->execute([
                    'public' => $publicId,
                    'account' => $accountId,
                    'binding' => $binding['id'],
                    'type' => $operationType,
                    'idempotency' => $idempotencyKey,
                    'request' => $requestId,
                ]);
                $operationId = (int) $pdo->lastInsertId();

                $step = $pdo->prepare(
                    "INSERT INTO provider_operation_steps
                     (operation_id,stage,sequence_no,status,created_at,updated_at)
                     VALUES (:operation,:stage,:sequence,'pending',UTC_TIMESTAMP(),UTC_TIMESTAMP())"
                );
                foreach (self::STAGES[$operationType] as $index => $stage) {
                    $step->execute([
                        'operation' => $operationId,
                        'stage' => $stage,
                        'sequence' => $index + 1,
                    ]);
                }

                $hash = hash('sha256', implode('|', [
                    $accountId,
                    $operationId,
                    $binding['id'],
                    $operationType,
                    $requestId,
                ]));
                $this->receipt(
                    $pdo,
                    $accountId,
                    $operationId,
                    (int) $binding['id'],
                    $requestId,
                    'provider_' . $operationType . '_queued',
                    'success',
                    $hash
                );
                $this->audit(
                    $pdo,
                    $accountId,
                    $actorId,
                    'infrastructure.' . $operationType . '_queued',
                    'success',
                    'infrastructure_binding',
                    $bindingPublicId,
                    $requestId
                );

                return [
                    'public_id' => $publicId,
                    'binding_public_id' => $bindingPublicId,
                    'status' => 'queued',
                    'replayed' => false,
                ];
            });
        } catch (AuthPublicException $exception) {
            if ($exception->publicCode() === 'infrastructure_permission_denied') {
                $this->database->transaction(function (PDO $pdo) use (
                    $accountId,
                    $actorId,
                    $bindingPublicId,
                    $operationType,
                    $requestId
                ): void {
                    $hash = hash('sha256', implode('|', [
                        $accountId,
                        $actorId,
                        $bindingPublicId,
                        $operationType,
                        $requestId,
                        'denied',
                    ]));
                    $this->receipt($pdo, $accountId, null, null, $requestId, $operationType . '_enqueue', 'denied', $hash);
                    $this->audit(
                        $pdo,
                        $accountId,
                        $actorId,
                        'infrastructure.' . $operationType . '_enqueue',
                        'denied',
                        'infrastructure_binding',
                        $bindingPublicId,
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
                'infrastructure_permission_denied',
                'An active customer owner or administrator membership is required for infrastructure actions.',
                403
            );
        }
    }

    private function receipt(
        PDO $pdo,
        int $accountId,
        ?int $operationId,
        ?int $bindingId,
        string $requestId,
        string $operation,
        string $result,
        string $hash
    ): void {
        $pdo->prepare(
            'INSERT INTO provider_receipts
             (public_id,account_id,operation_id,binding_id,request_id,operation,result,receipt_hash,created_at)
             VALUES
             (:public,:account,:operation_id,:binding,:request,:operation,:result,:hash,UTC_TIMESTAMP())'
        )->execute([
            'public' => 'PROVIDER-RCP-' . strtoupper(bin2hex(random_bytes(12))),
            'account' => $accountId,
            'operation_id' => $operationId,
            'binding' => $bindingId,
            'request' => substr($requestId, 0, 64),
            'operation' => substr($operation, 0, 100),
            'result' => $result,
            'hash' => $hash,
        ]);
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
