<?php

declare(strict_types=1);

namespace Vp3\Infrastructure;

use JsonException;
use PDO;
use Vp3\Auth\AuthPublicException;
use Vp3\Database;

final class InfrastructureControlCenterActionService
{
    private const ROLES = ['customer_owner', 'customer_admin'];

    /** @var array<string,list<string>> */
    private const STAGES = [
        'provision' => ['hosting_allocate', 'dns_bind', 'certificate_request', 'verify', 'active'],
        'reconcile' => ['hosting_verify', 'dns_verify', 'certificate_verify', 'active'],
        'teardown' => ['certificate_revoke', 'dns_remove', 'hosting_release', 'disabled'],
    ];

    public function __construct(
        private readonly Database $database,
        private readonly ProviderSecretCipher $cipher
    ) {
    }

    /** @param array<string,mixed> $authContext @return array{public_id:string,status:string,credential_version:int,rotated:bool} */
    public function saveConnection(
        int $accountId,
        int $actorId,
        string $role,
        string $providerType,
        string $providerCode,
        string $displayName,
        array $authContext,
        string $requestId
    ): array {
        $providerType = strtolower(trim($providerType));
        $providerCode = strtolower(trim($providerCode));
        $displayName = trim($displayName);
        if (!in_array($providerType, ['hosting', 'dns', 'certificate'], true)) {
            throw new AuthPublicException('infrastructure_provider_type_invalid', 'The provider type is invalid.', 422);
        }
        if (!preg_match('/^[a-z0-9][a-z0-9._-]{1,78}[a-z0-9]$/', $providerCode)) {
            throw new AuthPublicException('infrastructure_provider_code_invalid', 'The provider code must be 3–80 lowercase letters, numbers, dots, underscores, or hyphens.', 422);
        }
        if ($displayName === '' || mb_strlen($displayName) > 190) {
            throw new AuthPublicException('infrastructure_provider_name_invalid', 'The provider display name is required and must be 190 characters or fewer.', 422);
        }
        if ($authContext === [] || count($authContext) > 64) {
            throw new AuthPublicException('infrastructure_provider_credentials_invalid', 'A bounded provider authentication object is required.', 422);
        }
        try {
            $plaintext = json_encode($authContext, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (JsonException) {
            throw new AuthPublicException('infrastructure_provider_credentials_invalid', 'The provider authentication object is invalid.', 422);
        }
        if (!is_string($plaintext) || strlen($plaintext) > 16384) {
            throw new AuthPublicException('infrastructure_provider_credentials_invalid', 'The provider authentication object is too large.', 422);
        }
        $this->request($requestId);

        return $this->run(
            $accountId,
            $actorId,
            $role,
            'connection_save',
            $providerCode,
            $requestId,
            function (PDO $pdo) use (
                $accountId,
                $actorId,
                $providerType,
                $providerCode,
                $displayName,
                $plaintext,
                $requestId
            ): array {
                $statement = $pdo->prepare(
                    'SELECT id,public_id,credential_version
                     FROM provider_connections
                     WHERE account_id=:account AND provider_type=:type AND provider_code=:code
                     LIMIT 1 FOR UPDATE'
                );
                $statement->execute([
                    'account' => $accountId,
                    'type' => $providerType,
                    'code' => $providerCode,
                ]);
                $existing = $statement->fetch(PDO::FETCH_ASSOC);
                $rotated = is_array($existing);
                $version = $rotated ? (int) $existing['credential_version'] + 1 : 1;
                $encrypted = $this->cipher->encrypt(
                    $plaintext,
                    $this->connectionContext($accountId, $providerType, $providerCode, $version)
                );

                if ($rotated) {
                    $publicId = (string) $existing['public_id'];
                    $connectionId = (int) $existing['id'];
                    $pdo->prepare(
                        "UPDATE provider_connections
                         SET display_name=:name,status='active',credentials_ciphertext=:ciphertext,
                             credentials_nonce=:nonce,credentials_tag=:tag,encryption_key_id=:key_id,
                             credential_version=:version,revoked_at=NULL,updated_at=UTC_TIMESTAMP()
                         WHERE id=:id AND account_id=:account"
                    )->execute([
                        'name' => $displayName,
                        'ciphertext' => $encrypted['ciphertext'],
                        'nonce' => $encrypted['nonce'],
                        'tag' => $encrypted['tag'],
                        'key_id' => $encrypted['key_id'],
                        'version' => $version,
                        'id' => $connectionId,
                        'account' => $accountId,
                    ]);
                } else {
                    $publicId = 'PROVIDER-' . strtoupper(bin2hex(random_bytes(12)));
                    $pdo->prepare(
                        "INSERT INTO provider_connections
                         (public_id,account_id,provider_type,provider_code,display_name,status,
                          credentials_ciphertext,credentials_nonce,credentials_tag,encryption_key_id,
                          credential_version,created_at,updated_at)
                         VALUES
                         (:public,:account,:type,:code,:name,'active',:ciphertext,:nonce,:tag,:key_id,
                          :version,UTC_TIMESTAMP(),UTC_TIMESTAMP())"
                    )->execute([
                        'public' => $publicId,
                        'account' => $accountId,
                        'type' => $providerType,
                        'code' => $providerCode,
                        'name' => $displayName,
                        'ciphertext' => $encrypted['ciphertext'],
                        'nonce' => $encrypted['nonce'],
                        'tag' => $encrypted['tag'],
                        'key_id' => $encrypted['key_id'],
                        'version' => $version,
                    ]);
                    $connectionId = (int) $pdo->lastInsertId();
                }

                $hash = hash('sha256', implode('|', [$accountId, $connectionId, $providerType, $providerCode, $version, $requestId]));
                $this->receipt($pdo, $accountId, null, null, $requestId, 'provider_connection_saved', 'success', $hash);
                $this->audit($pdo, $accountId, $actorId, 'infrastructure.provider_connection_saved', 'success', 'provider_connection', $publicId, $requestId);

                return [
                    'public_id' => $publicId,
                    'status' => 'active',
                    'credential_version' => $version,
                    'rotated' => $rotated,
                ];
            }
        );
    }

    /** @return array{public_id:string,status:string} */
    public function revokeConnection(
        int $accountId,
        int $actorId,
        string $role,
        string $connectionPublicId,
        string $requestId
    ): array {
        $connectionPublicId = trim($connectionPublicId);
        $this->publicId($connectionPublicId, 'provider connection');
        $this->request($requestId);

        return $this->run(
            $accountId,
            $actorId,
            $role,
            'connection_revoke',
            $connectionPublicId,
            $requestId,
            function (PDO $pdo) use ($accountId, $actorId, $connectionPublicId, $requestId): array {
                $connection = $this->connectionByPublicId($pdo, $accountId, $connectionPublicId, null);
                $usage = $pdo->prepare(
                    "SELECT COUNT(*)
                     FROM infrastructure_bindings
                     WHERE account_id=:account
                       AND status<>'disabled'
                       AND (
                         hosting_connection_id=:hosting
                         OR dns_connection_id=:dns
                         OR certificate_connection_id=:certificate
                       )"
                );
                $usage->execute([
                    'account' => $accountId,
                    'hosting' => $connection['id'],
                    'dns' => $connection['id'],
                    'certificate' => $connection['id'],
                ]);
                if ((int) $usage->fetchColumn() > 0) {
                    throw new AuthPublicException(
                        'infrastructure_connection_in_use',
                        'The provider connection cannot be revoked while an active infrastructure binding uses it.',
                        409
                    );
                }

                $version = (int) $connection['credential_version'] + 1;
                $sealed = json_encode(
                    ['revoked' => true, 'evidence' => hash('sha256', random_bytes(32))],
                    JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES
                );
                $encrypted = $this->cipher->encrypt(
                    $sealed,
                    $this->connectionContext(
                        $accountId,
                        (string) $connection['provider_type'],
                        (string) $connection['provider_code'],
                        $version
                    )
                );
                $pdo->prepare(
                    "UPDATE provider_connections
                     SET status='revoked',credentials_ciphertext=:ciphertext,credentials_nonce=:nonce,
                         credentials_tag=:tag,encryption_key_id=:key_id,credential_version=:version,
                         revoked_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP()
                     WHERE id=:id AND account_id=:account"
                )->execute([
                    'ciphertext' => $encrypted['ciphertext'],
                    'nonce' => $encrypted['nonce'],
                    'tag' => $encrypted['tag'],
                    'key_id' => $encrypted['key_id'],
                    'version' => $version,
                    'id' => $connection['id'],
                    'account' => $accountId,
                ]);

                $hash = hash('sha256', implode('|', [$accountId, $connection['id'], $version, $requestId]));
                $this->receipt($pdo, $accountId, null, null, $requestId, 'provider_connection_revoked', 'success', $hash);
                $this->audit($pdo, $accountId, $actorId, 'infrastructure.provider_connection_revoked', 'success', 'provider_connection', $connectionPublicId, $requestId);
                return ['public_id' => $connectionPublicId, 'status' => 'revoked'];
            }
        );
    }

    /** @return array{public_id:string,binding_public_id:string,status:string,replayed:bool} */
    public function enqueueProvision(
        int $accountId,
        int $actorId,
        string $role,
        string $podPublicId,
        string $hostingConnectionPublicId,
        string $dnsConnectionPublicId,
        string $certificateConnectionPublicId,
        string $requestId,
        string $idempotencyKey
    ): array {
        foreach ([
            $podPublicId => 'POD',
            $hostingConnectionPublicId => 'hosting connection',
            $dnsConnectionPublicId => 'DNS connection',
            $certificateConnectionPublicId => 'certificate connection',
        ] as $publicId => $label) {
            $this->publicId(trim($publicId), $label);
        }
        $this->request($requestId);
        $this->idempotency($idempotencyKey);

        return $this->run(
            $accountId,
            $actorId,
            $role,
            'provision_enqueue',
            $podPublicId,
            $requestId,
            function (PDO $pdo) use (
                $accountId,
                $actorId,
                $podPublicId,
                $hostingConnectionPublicId,
                $dnsConnectionPublicId,
                $certificateConnectionPublicId,
                $requestId,
                $idempotencyKey
            ): array {
                $pod = $this->pod($pdo, $accountId, $podPublicId);
                $hosting = $this->connectionByPublicId($pdo, $accountId, $hostingConnectionPublicId, 'hosting');
                $dns = $this->connectionByPublicId($pdo, $accountId, $dnsConnectionPublicId, 'dns');
                $certificate = $this->connectionByPublicId($pdo, $accountId, $certificateConnectionPublicId, 'certificate');

                $existing = $this->operationReplay($pdo, $accountId, $idempotencyKey);
                if (is_array($existing)) {
                    $same = $existing['operation_type'] === 'provision'
                        && (int) $existing['deployment_id'] === (int) $pod['id']
                        && (int) $existing['hosting_connection_id'] === (int) $hosting['id']
                        && (int) $existing['dns_connection_id'] === (int) $dns['id']
                        && (int) $existing['certificate_connection_id'] === (int) $certificate['id'];
                    if (!$same) {
                        $this->idempotencyConflict();
                    }
                    return [
                        'public_id' => (string) $existing['public_id'],
                        'binding_public_id' => (string) $existing['binding_public_id'],
                        'status' => (string) $existing['status'],
                        'replayed' => true,
                    ];
                }

                $bindingCheck = $pdo->prepare(
                    'SELECT public_id,status
                     FROM infrastructure_bindings
                     WHERE deployment_id=:deployment
                     LIMIT 1 FOR UPDATE'
                );
                $bindingCheck->execute(['deployment' => $pod['id']]);
                $priorBinding = $bindingCheck->fetch(PDO::FETCH_ASSOC);
                if (is_array($priorBinding)) {
                    throw new AuthPublicException(
                        'infrastructure_binding_exists',
                        'This POD already has an infrastructure binding. Use reconcile or teardown controls for the existing binding.',
                        409
                    );
                }

                $bindingPublicId = 'INFRA-' . strtoupper(bin2hex(random_bytes(12)));
                $pdo->prepare(
                    "INSERT INTO infrastructure_bindings
                     (public_id,account_id,deployment_id,hosting_connection_id,dns_connection_id,
                      certificate_connection_id,hostname,status,created_at,updated_at)
                     VALUES
                     (:public,:account,:deployment,:hosting,:dns,:certificate,:hostname,'pending',
                      UTC_TIMESTAMP(),UTC_TIMESTAMP())"
                )->execute([
                    'public' => $bindingPublicId,
                    'account' => $accountId,
                    'deployment' => $pod['id'],
                    'hosting' => $hosting['id'],
                    'dns' => $dns['id'],
                    'certificate' => $certificate['id'],
                    'hostname' => $pod['hostname'],
                ]);
                $bindingId = (int) $pdo->lastInsertId();

                $operation = $this->enqueueOperation(
                    $pdo,
                    $accountId,
                    $bindingId,
                    $bindingPublicId,
                    'provision',
                    $requestId,
                    $idempotencyKey
                );
                $this->audit($pdo, $accountId, $actorId, 'infrastructure.provision_queued', 'success', 'infrastructure_binding', $bindingPublicId, $requestId);
                return $operation;
            }
        );
    }

    /** @return array{public_id:string,binding_public_id:string,status:string,replayed:bool} */
    public function enqueueBindingOperation(
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
        $this->publicId($bindingPublicId, 'infrastructure binding');
        if (!in_array($operationType, ['reconcile', 'teardown'], true)) {
            throw new AuthPublicException('infrastructure_operation_invalid', 'The infrastructure operation is invalid.', 422);
        }
        if ($operationType === 'teardown' && $confirmation !== 'TEARDOWN') {
            throw new AuthPublicException(
                'infrastructure_teardown_confirmation_required',
                'Infrastructure teardown requires the exact confirmation TEARDOWN.',
                422
            );
        }
        $this->request($requestId);
        $this->idempotency($idempotencyKey);

        return $this->run(
            $accountId,
            $actorId,
            $role,
            $operationType . '_enqueue',
            $bindingPublicId,
            $requestId,
            function (PDO $pdo) use (
                $accountId,
                $actorId,
                $bindingPublicId,
                $operationType,
                $requestId,
                $idempotencyKey
            ): array {
                $binding = $this->binding($pdo, $accountId, $bindingPublicId);
                $existing = $this->operationReplay($pdo, $accountId, $idempotencyKey);
                if (is_array($existing)) {
                    if ($existing['operation_type'] !== $operationType
                        || (int) $existing['binding_id'] !== (int) $binding['id']) {
                        $this->idempotencyConflict();
                    }
                    return [
                        'public_id' => (string) $existing['public_id'],
                        'binding_public_id' => (string) $existing['binding_public_id'],
                        'status' => (string) $existing['status'],
                        'replayed' => true,
                    ];
                }

                if ($operationType === 'reconcile' && in_array($binding['status'], ['disabled', 'tearing_down'], true)) {
                    throw new AuthPublicException(
                        'infrastructure_reconcile_unavailable',
                        'Disabled or tearing-down infrastructure cannot be reconciled.',
                        409
                    );
                }
                if ($operationType === 'teardown' && $binding['status'] === 'disabled') {
                    throw new AuthPublicException(
                        'infrastructure_teardown_unavailable',
                        'The infrastructure binding is already disabled.',
                        409
                    );
                }

                $operation = $this->enqueueOperation(
                    $pdo,
                    $accountId,
                    (int) $binding['id'],
                    $bindingPublicId,
                    $operationType,
                    $requestId,
                    $idempotencyKey
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
                return $operation;
            }
        );
    }

    /** @return array{public_id:string,status:string} */
    public function transitionOperation(
        int $accountId,
        int $actorId,
        string $role,
        string $operationPublicId,
        string $action,
        string $requestId
    ): array {
        $operationPublicId = trim($operationPublicId);
        $action = strtolower(trim($action));
        $this->publicId($operationPublicId, 'infrastructure operation');
        $this->request($requestId);
        $rule = match ($action) {
            'pause' => [['queued', 'running', 'hosting', 'dns', 'certificate', 'verifying'], 'paused'],
            'resume' => [['paused', 'failed'], 'queued'],
            default => throw new AuthPublicException('infrastructure_transition_invalid', 'The infrastructure transition is invalid.', 422),
        };

        return $this->run(
            $accountId,
            $actorId,
            $role,
            $action . '_operation',
            $operationPublicId,
            $requestId,
            function (PDO $pdo) use ($accountId, $actorId, $operationPublicId, $action, $requestId, $rule): array {
                $statement = $pdo->prepare(
                    'SELECT id,binding_id,status
                     FROM provider_operations
                     WHERE public_id=:public AND account_id=:account
                     LIMIT 1 FOR UPDATE'
                );
                $statement->execute(['public' => $operationPublicId, 'account' => $accountId]);
                $operation = $statement->fetch(PDO::FETCH_ASSOC);
                if (!is_array($operation)) {
                    throw new AuthPublicException('infrastructure_operation_not_found', 'The infrastructure operation was not found.', 404);
                }
                if (!in_array((string) $operation['status'], $rule[0], true)) {
                    throw new AuthPublicException(
                        'infrastructure_transition_unavailable',
                        'The infrastructure operation cannot make that transition.',
                        409
                    );
                }

                $pdo->prepare(
                    'UPDATE provider_operations
                     SET status=:status,request_id=:request,available_at=UTC_TIMESTAMP(),
                         locked_at=NULL,locked_by=NULL,locked_until=NULL,lease_token=NULL,
                         updated_at=UTC_TIMESTAMP()
                     WHERE id=:id AND account_id=:account'
                )->execute([
                    'status' => $rule[1],
                    'request' => $requestId,
                    'id' => $operation['id'],
                    'account' => $accountId,
                ]);

                $hash = hash('sha256', implode('|', [$accountId, $operation['id'], $rule[1], $requestId]));
                $this->receipt(
                    $pdo,
                    $accountId,
                    (int) $operation['id'],
                    (int) $operation['binding_id'],
                    $requestId,
                    'provider_operation_' . $action,
                    'success',
                    $hash
                );
                $this->audit(
                    $pdo,
                    $accountId,
                    $actorId,
                    'infrastructure.operation_' . $action,
                    'success',
                    'provider_operation',
                    $operationPublicId,
                    $requestId
                );
                return ['public_id' => $operationPublicId, 'status' => (string) $rule[1]];
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
            if ($exception->publicCode() === 'infrastructure_permission_denied') {
                $this->database->transaction(function (PDO $pdo) use (
                    $accountId,
                    $actorId,
                    $operation,
                    $resourcePublicId,
                    $requestId
                ): void {
                    $hash = hash('sha256', implode('|', [$accountId, $actorId, $operation, $resourcePublicId, $requestId, 'denied']));
                    $this->receipt($pdo, $accountId, null, null, $requestId, $operation, 'denied', $hash);
                    $this->audit(
                        $pdo,
                        $accountId,
                        $actorId,
                        'infrastructure.' . $operation,
                        'denied',
                        'infrastructure_resource',
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
                'infrastructure_permission_denied',
                'An active customer owner or administrator membership is required for infrastructure actions.',
                403
            );
        }
    }

    /** @return array<string,mixed> */
    private function pod(PDO $pdo, int $accountId, string $publicId): array
    {
        $statement = $pdo->prepare(
            "SELECT p.id,p.public_id,p.status,d.hostname
             FROM pod_deployments p
             JOIN domain_registrations d
               ON d.id=p.domain_registration_id
              AND d.account_id=p.account_id
             WHERE p.public_id=:public
               AND p.account_id=:account
               AND p.status IN ('pending','provisioning','active','degraded','failed')
             LIMIT 1 FOR UPDATE"
        );
        $statement->execute(['public' => trim($publicId), 'account' => $accountId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new AuthPublicException('infrastructure_pod_not_found', 'An eligible account-owned POD was not found.', 404);
        }
        return $row;
    }

    /** @return array<string,mixed> */
    private function connectionByPublicId(PDO $pdo, int $accountId, string $publicId, ?string $type): array
    {
        $sql = "SELECT id,public_id,provider_type,provider_code,credential_version,status
                FROM provider_connections
                WHERE public_id=:public AND account_id=:account AND status='active'";
        $params = ['public' => trim($publicId), 'account' => $accountId];
        if ($type !== null) {
            $sql .= ' AND provider_type=:type';
            $params['type'] = $type;
        }
        $sql .= ' LIMIT 1 FOR UPDATE';
        $statement = $pdo->prepare($sql);
        $statement->execute($params);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new AuthPublicException(
                'infrastructure_connection_not_found',
                $type === null
                    ? 'The active account-owned provider connection was not found.'
                    : 'The active account-owned ' . $type . ' provider connection was not found.',
                404
            );
        }
        return $row;
    }

    /** @return array<string,mixed> */
    private function binding(PDO $pdo, int $accountId, string $publicId): array
    {
        $statement = $pdo->prepare(
            'SELECT id,public_id,deployment_id,status
             FROM infrastructure_bindings
             WHERE public_id=:public AND account_id=:account
             LIMIT 1 FOR UPDATE'
        );
        $statement->execute(['public' => $publicId, 'account' => $accountId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new AuthPublicException('infrastructure_binding_not_found', 'The account-owned infrastructure binding was not found.', 404);
        }
        return $row;
    }

    /** @return array<string,mixed>|null */
    private function operationReplay(PDO $pdo, int $accountId, string $idempotencyKey): ?array
    {
        $statement = $pdo->prepare(
            'SELECT o.id,o.public_id,o.binding_id,o.operation_type,o.status,
                    b.public_id binding_public_id,b.deployment_id,
                    b.hosting_connection_id,b.dns_connection_id,b.certificate_connection_id
             FROM provider_operations o
             JOIN infrastructure_bindings b
               ON b.id=o.binding_id
              AND b.account_id=o.account_id
             WHERE o.account_id=:account AND o.idempotency_key=:idempotency
             LIMIT 1 FOR UPDATE'
        );
        $statement->execute(['account' => $accountId, 'idempotency' => $idempotencyKey]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $row : null;
    }

    /** @return array{public_id:string,binding_public_id:string,status:string,replayed:bool} */
    private function enqueueOperation(
        PDO $pdo,
        int $accountId,
        int $bindingId,
        string $bindingPublicId,
        string $operationType,
        string $requestId,
        string $idempotencyKey
    ): array {
        $publicId = 'PROVIDER-OP-' . strtoupper(bin2hex(random_bytes(12)));
        $pdo->prepare(
            "INSERT INTO provider_operations
             (public_id,account_id,binding_id,operation_type,status,current_stage,idempotency_key,
              request_id,available_at,created_at,updated_at)
             VALUES
             (:public,:account,:binding,:type,'queued',NULL,:idempotency,:request,
              UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())"
        )->execute([
            'public' => $publicId,
            'account' => $accountId,
            'binding' => $bindingId,
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

        $hash = hash('sha256', implode('|', [$accountId, $operationId, $bindingId, $operationType, $requestId]));
        $this->receipt(
            $pdo,
            $accountId,
            $operationId,
            $bindingId,
            $requestId,
            'provider_' . $operationType . '_queued',
            'success',
            $hash
        );
        return [
            'public_id' => $publicId,
            'binding_public_id' => $bindingPublicId,
            'status' => 'queued',
            'replayed' => false,
        ];
    }

    private function connectionContext(int $accountId, string $type, string $code, int $version): string
    {
        return 'provider-connection|' . $accountId . '|' . $type . '|' . $code . '|' . $version;
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

    private function request(string $requestId): void
    {
        if (!preg_match('/^[A-Za-z0-9._:-]{8,64}$/', $requestId)) {
            throw new AuthPublicException('infrastructure_request_id_invalid', 'A valid request ID is required.', 400);
        }
    }

    private function idempotency(string $idempotencyKey): void
    {
        if (!preg_match('/^[A-Za-z0-9._:-]{8,128}$/', $idempotencyKey)) {
            throw new AuthPublicException('infrastructure_idempotency_invalid', 'A valid idempotency key is required.', 400);
        }
    }

    private function publicId(string $publicId, string $label): void
    {
        if (!preg_match('/^[A-Za-z0-9._:-]{3,190}$/', $publicId)) {
            throw new AuthPublicException('infrastructure_public_id_invalid', 'A valid ' . $label . ' identity is required.', 422);
        }
    }

    private function idempotencyConflict(): never
    {
        throw new AuthPublicException(
            'infrastructure_idempotency_conflict',
            'The idempotency key was already used for another infrastructure request.',
            409
        );
    }
}
