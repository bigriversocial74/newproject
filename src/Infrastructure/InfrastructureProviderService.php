<?php

declare(strict_types=1);

namespace Vp3\Infrastructure;

use PDO;
use RuntimeException;
use Throwable;
use Vp3\Database;

final class InfrastructureProviderService
{
    /** @var array<string,list<string>> */
    private const STAGES = [
        'provision' => ['hosting_allocate', 'dns_bind', 'certificate_request', 'verify', 'active'],
        'reconcile' => ['hosting_verify', 'dns_verify', 'certificate_verify', 'active'],
        'teardown' => ['certificate_revoke', 'dns_remove', 'hosting_release', 'disabled'],
    ];

    public function __construct(
        private readonly Database $database,
        private readonly ProviderSecretCipher $cipher,
        private readonly HostingProviderAdapter $hosting,
        private readonly DnsProviderAdapter $dns,
        private readonly CertificateProviderAdapter $certificates
    ) {
    }

    /** @param array<string,mixed> $authContext @return array{connection_id:int,connection_public_id:string,credential_version:int} */
    public function saveConnection(
        int $accountId,
        string $providerType,
        string $providerCode,
        string $displayName,
        array $authContext,
        string $requestId
    ): array {
        $providerType = strtolower(trim($providerType));
        $providerCode = strtolower(trim($providerCode));
        if ($accountId < 1 || !in_array($providerType, ['hosting', 'dns', 'certificate'], true)
            || $providerCode === '' || trim($displayName) === '' || $authContext === [] || trim($requestId) === '') {
            throw new RuntimeException('A valid provider connection and request ID are required.');
        }
        return $this->database->transaction(function (PDO $pdo) use (
            $accountId, $providerType, $providerCode, $displayName, $authContext, $requestId
        ): array {
            $find = $pdo->prepare(
                'SELECT * FROM provider_connections WHERE account_id=:account AND provider_type=:type AND provider_code=:code LIMIT 1 FOR UPDATE'
            );
            $find->execute(['account' => $accountId, 'type' => $providerType, 'code' => $providerCode]);
            $existing = $find->fetch(PDO::FETCH_ASSOC);
            $version = is_array($existing) ? (int) $existing['credential_version'] + 1 : 1;
            $context = $this->connectionContext($accountId, $providerType, $providerCode, $version);
            $encrypted = $this->cipher->encrypt($this->json($authContext), $context);
            if (!is_array($existing)) {
                $publicId = 'PROVIDER-' . strtoupper(bin2hex(random_bytes(12)));
                $pdo->prepare(
                    'INSERT INTO provider_connections
                     (public_id,account_id,provider_type,provider_code,display_name,status,credentials_ciphertext,
                      credentials_nonce,credentials_tag,encryption_key_id,credential_version,created_at,updated_at)
                     VALUES (:public,:account,:type,:code,:name,\'active\',:ciphertext,:nonce,:tag,:key_id,:version,UTC_TIMESTAMP(),UTC_TIMESTAMP())'
                )->execute([
                    'public' => $publicId,
                    'account' => $accountId,
                    'type' => $providerType,
                    'code' => $providerCode,
                    'name' => substr(trim($displayName), 0, 190),
                    'ciphertext' => $encrypted['ciphertext'],
                    'nonce' => $encrypted['nonce'],
                    'tag' => $encrypted['tag'],
                    'key_id' => $encrypted['key_id'],
                    'version' => $version,
                ]);
                $connectionId = (int) $pdo->lastInsertId();
            } else {
                $publicId = (string) $existing['public_id'];
                $connectionId = (int) $existing['id'];
                $pdo->prepare(
                    "UPDATE provider_connections SET display_name=:name,status='active',credentials_ciphertext=:ciphertext,
                     credentials_nonce=:nonce,credentials_tag=:tag,encryption_key_id=:key_id,credential_version=:version,
                     revoked_at=NULL,updated_at=UTC_TIMESTAMP() WHERE id=:id AND account_id=:account"
                )->execute([
                    'name' => substr(trim($displayName), 0, 190),
                    'ciphertext' => $encrypted['ciphertext'],
                    'nonce' => $encrypted['nonce'],
                    'tag' => $encrypted['tag'],
                    'key_id' => $encrypted['key_id'],
                    'version' => $version,
                    'id' => $connectionId,
                    'account' => $accountId,
                ]);
            }
            $this->receipt($pdo, $accountId, null, null, $requestId, 'provider_connection_saved', 'success', null, [
                'connection_id' => $connectionId,
                'provider_type' => $providerType,
                'provider_code' => $providerCode,
                'credential_version' => $version,
            ]);
            return ['connection_id' => $connectionId, 'connection_public_id' => $publicId, 'credential_version' => $version];
        });
    }

    /** @return array{operation_id:int,operation_public_id:string,binding_id:int,binding_public_id:string,replayed:bool} */
    public function enqueueProvision(
        int $accountId,
        int $deploymentId,
        int $hostingConnectionId,
        int $dnsConnectionId,
        int $certificateConnectionId,
        string $hostname,
        string $requestId,
        string $idempotencyKey
    ): array {
        if ($accountId < 1 || $deploymentId < 1 || $hostingConnectionId < 1 || $dnsConnectionId < 1
            || $certificateConnectionId < 1 || !$this->validHostname($hostname)
            || trim($requestId) === '' || trim($idempotencyKey) === '') {
            throw new RuntimeException('Valid account-owned infrastructure targets and request identifiers are required.');
        }
        return $this->database->transaction(function (PDO $pdo) use (
            $accountId, $deploymentId, $hostingConnectionId, $dnsConnectionId, $certificateConnectionId,
            $hostname, $requestId, $idempotencyKey
        ): array {
            $deployment = $pdo->prepare(
                "SELECT id,public_id,domain_registration_id,status FROM pod_deployments
                 WHERE id=:id AND account_id=:account AND status IN ('pending','provisioning','active','degraded','failed') LIMIT 1 FOR UPDATE"
            );
            $deployment->execute(['id' => $deploymentId, 'account' => $accountId]);
            if (!is_array($deployment->fetch(PDO::FETCH_ASSOC))) {
                throw new RuntimeException('POD deployment was not found for this account.');
            }
            $this->connection($pdo, $accountId, $hostingConnectionId, 'hosting', true);
            $this->connection($pdo, $accountId, $dnsConnectionId, 'dns', true);
            $this->connection($pdo, $accountId, $certificateConnectionId, 'certificate', true);
            $find = $pdo->prepare('SELECT id,public_id FROM infrastructure_bindings WHERE deployment_id=:deployment LIMIT 1 FOR UPDATE');
            $find->execute(['deployment' => $deploymentId]);
            $binding = $find->fetch(PDO::FETCH_ASSOC);
            if (!is_array($binding)) {
                $bindingPublicId = 'INFRA-' . strtoupper(bin2hex(random_bytes(12)));
                $pdo->prepare(
                    'INSERT INTO infrastructure_bindings
                     (public_id,account_id,deployment_id,hosting_connection_id,dns_connection_id,certificate_connection_id,
                      hostname,status,created_at,updated_at)
                     VALUES (:public,:account,:deployment,:hosting,:dns,:certificate,:hostname,\'pending\',UTC_TIMESTAMP(),UTC_TIMESTAMP())'
                )->execute([
                    'public' => $bindingPublicId,
                    'account' => $accountId,
                    'deployment' => $deploymentId,
                    'hosting' => $hostingConnectionId,
                    'dns' => $dnsConnectionId,
                    'certificate' => $certificateConnectionId,
                    'hostname' => strtolower(trim($hostname)),
                ]);
                $binding = ['id' => (int) $pdo->lastInsertId(), 'public_id' => $bindingPublicId];
            } else {
                $pdo->prepare(
                    "UPDATE infrastructure_bindings SET hosting_connection_id=:hosting,dns_connection_id=:dns,
                     certificate_connection_id=:certificate,hostname=:hostname,status=IF(status='active','active','pending'),updated_at=UTC_TIMESTAMP()
                     WHERE id=:id AND account_id=:account"
                )->execute([
                    'hosting' => $hostingConnectionId,
                    'dns' => $dnsConnectionId,
                    'certificate' => $certificateConnectionId,
                    'hostname' => strtolower(trim($hostname)),
                    'id' => $binding['id'],
                    'account' => $accountId,
                ]);
            }
            return $this->enqueueOperation($pdo, $accountId, (int) $binding['id'], (string) $binding['public_id'], 'provision', $requestId, $idempotencyKey);
        });
    }

    /** @return array{operation_id:int,operation_public_id:string,binding_id:int,binding_public_id:string,replayed:bool} */
    public function enqueueReconcile(int $accountId, int $bindingId, string $requestId, string $idempotencyKey): array
    {
        return $this->enqueueForBinding($accountId, $bindingId, 'reconcile', $requestId, $idempotencyKey);
    }

    /** @return array{operation_id:int,operation_public_id:string,binding_id:int,binding_public_id:string,replayed:bool} */
    public function enqueueTeardown(int $accountId, int $bindingId, string $requestId, string $idempotencyKey): array
    {
        return $this->enqueueForBinding($accountId, $bindingId, 'teardown', $requestId, $idempotencyKey);
    }

    /** @return array<string,mixed>|null */
    public function processNext(string $workerId): ?array
    {
        if (trim($workerId) === '') {
            throw new RuntimeException('Infrastructure worker ID is required.');
        }
        $operation = $this->database->transaction(function (PDO $pdo) use ($workerId): ?array {
            $row = $pdo->query(
                "SELECT * FROM provider_operations WHERE status='queued' AND available_at<=UTC_TIMESTAMP()
                 ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED"
            )->fetch(PDO::FETCH_ASSOC);
            if (!is_array($row)) {
                return null;
            }
            $pdo->prepare(
                "UPDATE provider_operations SET status='running',attempts=attempts+1,locked_at=UTC_TIMESTAMP(),locked_by=:worker,
                 started_at=COALESCE(started_at,UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=:id"
            )->execute(['worker' => $workerId, 'id' => $row['id']]);
            $row['attempts'] = (int) $row['attempts'] + 1;
            return $row;
        });
        if ($operation === null) {
            return null;
        }
        return $this->run($operation);
    }

    public function pause(int $accountId, int $operationId, string $requestId): void
    {
        $this->transition($accountId, $operationId, $requestId, ['queued', 'running', 'hosting', 'dns', 'certificate', 'verifying'], 'paused');
    }

    public function resume(int $accountId, int $operationId, string $requestId): void
    {
        $this->transition($accountId, $operationId, $requestId, ['paused', 'failed'], 'queued');
    }

    public function revokeConnection(int $accountId, int $connectionId, string $requestId): void
    {
        if ($accountId < 1 || $connectionId < 1 || trim($requestId) === '') {
            throw new RuntimeException('Account, connection, and request ID are required.');
        }
        $this->database->transaction(function (PDO $pdo) use ($accountId, $connectionId, $requestId): void {
            $connection = $this->connection($pdo, $accountId, $connectionId, null, true);
            $inUse = $pdo->prepare(
                "SELECT COUNT(*) FROM infrastructure_bindings WHERE status NOT IN ('disabled')
                 AND (hosting_connection_id=:hosting OR dns_connection_id=:dns OR certificate_connection_id=:certificate)"
            );
            $inUse->execute(['hosting' => $connectionId, 'dns' => $connectionId, 'certificate' => $connectionId]);
            if ((int) $inUse->fetchColumn() > 0) {
                throw new RuntimeException('Provider connection cannot be revoked while active infrastructure bindings use it.');
            }
            $pdo->prepare(
                "UPDATE provider_connections SET status='revoked',credentials_ciphertext=:ciphertext,
                 credentials_nonce=:nonce,credentials_tag=:tag,revoked_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP()
                 WHERE id=:id AND account_id=:account"
            )->execute([
                'ciphertext' => base64_encode(random_bytes(48)),
                'nonce' => base64_encode(random_bytes(12)),
                'tag' => base64_encode(random_bytes(16)),
                'id' => $connectionId,
                'account' => $accountId,
            ]);
            $this->receipt($pdo, $accountId, null, null, $requestId, 'provider_connection_revoked', 'success', null, [
                'connection_id' => $connectionId,
                'provider_type' => $connection['provider_type'],
            ]);
        });
    }

    /** @return array{operation_id:int,operation_public_id:string,binding_id:int,binding_public_id:string,replayed:bool} */
    private function enqueueForBinding(int $accountId, int $bindingId, string $type, string $requestId, string $idempotencyKey): array
    {
        if ($accountId < 1 || $bindingId < 1 || trim($requestId) === '' || trim($idempotencyKey) === '') {
            throw new RuntimeException('Account, binding, request ID, and idempotency key are required.');
        }
        return $this->database->transaction(function (PDO $pdo) use ($accountId, $bindingId, $type, $requestId, $idempotencyKey): array {
            $binding = $this->binding($pdo, $accountId, $bindingId, true);
            return $this->enqueueOperation($pdo, $accountId, $bindingId, (string) $binding['public_id'], $type, $requestId, $idempotencyKey);
        });
    }

    /** @return array{operation_id:int,operation_public_id:string,binding_id:int,binding_public_id:string,replayed:bool} */
    private function enqueueOperation(PDO $pdo, int $accountId, int $bindingId, string $bindingPublicId, string $type, string $requestId, string $idempotencyKey): array
    {
        $existing = $pdo->prepare('SELECT id,public_id,binding_id,operation_type FROM provider_operations WHERE account_id=:account AND idempotency_key=:key LIMIT 1 FOR UPDATE');
        $existing->execute(['account' => $accountId, 'key' => $idempotencyKey]);
        $row = $existing->fetch(PDO::FETCH_ASSOC);
        if (is_array($row)) {
            if ((int) $row['binding_id'] !== $bindingId || $row['operation_type'] !== $type) {
                throw new RuntimeException('Infrastructure idempotency key was reused for another operation.');
            }
            return [
                'operation_id' => (int) $row['id'],
                'operation_public_id' => (string) $row['public_id'],
                'binding_id' => $bindingId,
                'binding_public_id' => $bindingPublicId,
                'replayed' => true,
            ];
        }
        $publicId = 'PROVIDER-OP-' . strtoupper(bin2hex(random_bytes(12)));
        $pdo->prepare(
            'INSERT INTO provider_operations
             (public_id,account_id,binding_id,operation_type,status,idempotency_key,request_id,available_at,created_at,updated_at)
             VALUES (:public,:account,:binding,:type,\'queued\',:key,:request,UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())'
        )->execute([
            'public' => $publicId,
            'account' => $accountId,
            'binding' => $bindingId,
            'type' => $type,
            'key' => $idempotencyKey,
            'request' => $requestId,
        ]);
        $operationId = (int) $pdo->lastInsertId();
        $insert = $pdo->prepare(
            'INSERT INTO provider_operation_steps
             (operation_id,stage,sequence_no,status,created_at,updated_at)
             VALUES (:operation,:stage,:sequence,\'pending\',UTC_TIMESTAMP(),UTC_TIMESTAMP())'
        );
        foreach (self::STAGES[$type] as $index => $stage) {
            $insert->execute(['operation' => $operationId, 'stage' => $stage, 'sequence' => $index + 1]);
        }
        $this->receipt($pdo, $accountId, $operationId, $bindingId, $requestId, 'infrastructure_' . $type . '_queued', 'success', null, null);
        return [
            'operation_id' => $operationId,
            'operation_public_id' => $publicId,
            'binding_id' => $bindingId,
            'binding_public_id' => $bindingPublicId,
            'replayed' => false,
        ];
    }

    /** @param array<string,mixed> $operation @return array<string,mixed> */
    private function run(array $operation): array
    {
        $pdo = $this->database->pdo();
        $binding = $this->binding($pdo, (int) $operation['account_id'], (int) $operation['binding_id'], false);
        $deployment = $pdo->prepare('SELECT * FROM pod_deployments WHERE id=:id AND account_id=:account LIMIT 1');
        $deployment->execute(['id' => $binding['deployment_id'], 'account' => $operation['account_id']]);
        $deploymentRow = $deployment->fetch(PDO::FETCH_ASSOC);
        if (!is_array($deploymentRow)) {
            return $this->fail($operation, new RuntimeException('Infrastructure deployment was not found.'));
        }
        $connections = [
            'hosting' => $this->connection($pdo, (int) $operation['account_id'], (int) $binding['hosting_connection_id'], 'hosting', false),
            'dns' => $this->connection($pdo, (int) $operation['account_id'], (int) $binding['dns_connection_id'], 'dns', false),
            'certificate' => $this->connection($pdo, (int) $operation['account_id'], (int) $binding['certificate_connection_id'], 'certificate', false),
        ];
        $auth = [
            'hosting' => $this->decryptConnection($connections['hosting']),
            'dns' => $this->decryptConnection($connections['dns']),
            'certificate' => $this->decryptConnection($connections['certificate']),
        ];
        $steps = $pdo->prepare('SELECT * FROM provider_operation_steps WHERE operation_id=:operation ORDER BY sequence_no');
        $steps->execute(['operation' => $operation['id']]);
        foreach ($steps->fetchAll(PDO::FETCH_ASSOC) as $step) {
            if ($step['status'] === 'completed') {
                continue;
            }
            $check = $pdo->prepare('SELECT status FROM provider_operations WHERE id=:id');
            $check->execute(['id' => $operation['id']]);
            if ($check->fetchColumn() === 'paused') {
                return ['operation_id' => (int) $operation['id'], 'status' => 'paused'];
            }
            $stage = (string) $step['stage'];
            try {
                $status = str_starts_with($stage, 'hosting') ? 'hosting'
                    : (str_starts_with($stage, 'dns') ? 'dns'
                    : (str_starts_with($stage, 'certificate') ? 'certificate'
                    : ($stage === 'verify' ? 'verifying' : 'running')));
                $pdo->prepare('UPDATE provider_operations SET status=:status,current_stage=:stage,updated_at=UTC_TIMESTAMP() WHERE id=:id')
                    ->execute(['status' => $status, 'stage' => $stage, 'id' => $operation['id']]);
                $pdo->prepare("UPDATE provider_operation_steps SET status='running',attempts=attempts+1,started_at=COALESCE(started_at,UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=:id")
                    ->execute(['id' => $step['id']]);
                $result = $this->executeStage($pdo, $stage, $binding, $deploymentRow, $auth);
                if (in_array($stage, ['hosting_verify', 'dns_verify', 'certificate_verify'], true)
                    && ($result['verified'] ?? false) !== true) {
                    throw new RuntimeException('Infrastructure provider verification failed for stage: ' . $stage);
                }
                $hash = hash('sha256', $this->json($result));
                $pdo->prepare("UPDATE provider_operation_steps SET status='completed',receipt_hash=:hash,completed_at=UTC_TIMESTAMP(),last_error_code=NULL,last_error_message=NULL,updated_at=UTC_TIMESTAMP() WHERE id=:id")
                    ->execute(['hash' => $hash, 'id' => $step['id']]);
                $this->receipt($pdo, (int) $operation['account_id'], (int) $operation['id'], (int) $binding['id'], (string) $operation['request_id'], $stage, 'success', $hash, $this->safeMetadata($result));
                $binding = $this->binding($pdo, (int) $operation['account_id'], (int) $operation['binding_id'], false);
            } catch (Throwable $exception) {
                $pdo->prepare("UPDATE provider_operation_steps SET status='failed',last_error_code=:code,last_error_message=:message,updated_at=UTC_TIMESTAMP() WHERE id=:id")
                    ->execute(['code' => substr($exception::class, 0, 100), 'message' => substr($exception->getMessage(), 0, 1000), 'id' => $step['id']]);
                $this->receipt($pdo, (int) $operation['account_id'], (int) $operation['id'], (int) $binding['id'], (string) $operation['request_id'], $stage, 'failure', null, ['error' => substr($exception->getMessage(), 0, 500)]);
                return $this->fail($operation, $exception);
            }
        }
        $pdo->prepare("UPDATE provider_operations SET status='completed',completed_at=UTC_TIMESTAMP(),locked_at=NULL,locked_by=NULL,updated_at=UTC_TIMESTAMP() WHERE id=:id")
            ->execute(['id' => $operation['id']]);
        return ['operation_id' => (int) $operation['id'], 'binding_id' => (int) $binding['id'], 'status' => 'completed', 'operation_type' => $operation['operation_type']];
    }

    /** @param array<string,mixed> $binding @param array<string,mixed> $deployment @param array<string,array<string,mixed>> $auth @return array<string,mixed> */
    private function executeStage(PDO $pdo, string $stage, array $binding, array $deployment, array $auth): array
    {
        return match ($stage) {
            'hosting_allocate' => $this->hostingAllocate($pdo, $binding, $deployment, $auth['hosting']),
            'dns_bind' => $this->dnsBind($pdo, $binding, $auth['dns']),
            'certificate_request' => $this->certificateRequest($pdo, $binding, $auth['certificate']),
            'verify' => $this->verifyAll($pdo, $binding, $auth),
            'hosting_verify' => $this->verifyHosting($pdo, $binding, $auth['hosting']),
            'dns_verify' => $this->verifyDns($pdo, $binding, $auth['dns']),
            'certificate_verify' => $this->verifyCertificate($pdo, $binding, $auth['certificate']),
            'certificate_revoke' => $this->certificateRevoke($pdo, $binding, $auth['certificate']),
            'dns_remove' => $this->dnsRemove($pdo, $binding, $auth['dns']),
            'hosting_release' => $this->hostingRelease($pdo, $binding, $auth['hosting']),
            'active' => $this->activate($pdo, $binding),
            'disabled' => $this->disable($pdo, $binding),
            default => throw new RuntimeException('Unknown infrastructure stage: ' . $stage),
        };
    }

    /** @param array<string,mixed> $binding @param array<string,mixed> $deployment @param array<string,mixed> $authContext @return array<string,mixed> */
    private function hostingAllocate(PDO $pdo, array $binding, array $deployment, array $authContext): array
    {
        $result = $this->hosting->allocateHosting($authContext, $deployment);
        $reference = trim((string) ($result['provider_reference'] ?? ''));
        $endpoint = trim((string) ($result['endpoint'] ?? ''));
        if ($reference === '' || $endpoint === '') {
            throw new RuntimeException('Hosting provider did not return an allocation reference and endpoint.');
        }
        $envelope = $this->cipher->encrypt($this->json(['reference' => $reference, 'endpoint' => $endpoint]), 'hosting-allocation|' . $binding['id']);
        $pdo->prepare(
            'INSERT INTO hosting_allocations
             (binding_id,account_id,provider_reference_ciphertext,provider_reference_nonce,provider_reference_tag,
              encryption_key_id,region,service_plan_hash,endpoint_hash,status,created_at,updated_at)
             VALUES (:binding,:account,:ciphertext,:nonce,:tag,:key_id,:region,:plan_hash,:endpoint_hash,\'active\',UTC_TIMESTAMP(),UTC_TIMESTAMP())
             ON DUPLICATE KEY UPDATE provider_reference_ciphertext=VALUES(provider_reference_ciphertext),
              provider_reference_nonce=VALUES(provider_reference_nonce),provider_reference_tag=VALUES(provider_reference_tag),
              encryption_key_id=VALUES(encryption_key_id),region=VALUES(region),service_plan_hash=VALUES(service_plan_hash),
              endpoint_hash=VALUES(endpoint_hash),status=\'active\',released_at=NULL,updated_at=UTC_TIMESTAMP()'
        )->execute([
            'binding' => $binding['id'],
            'account' => $binding['account_id'],
            'ciphertext' => $envelope['ciphertext'],
            'nonce' => $envelope['nonce'],
            'tag' => $envelope['tag'],
            'key_id' => $envelope['key_id'],
            'region' => isset($result['region']) ? substr((string) $result['region'], 0, 80) : null,
            'plan_hash' => isset($result['service_plan']) ? hash('sha256', (string) $result['service_plan']) : null,
            'endpoint_hash' => hash('sha256', $endpoint),
        ]);
        $pdo->prepare("UPDATE infrastructure_bindings SET status='provisioning',updated_at=UTC_TIMESTAMP() WHERE id=:id")
            ->execute(['id' => $binding['id']]);
        $pdo->prepare('UPDATE pod_deployments SET hosting_reference=:reference,status=\'provisioning\',updated_at=UTC_TIMESTAMP() WHERE id=:id AND account_id=:account')
            ->execute(['reference' => 'sha256:' . hash('sha256', $reference), 'id' => $binding['deployment_id'], 'account' => $binding['account_id']]);
        return ['provider_reference_hash' => hash('sha256', $reference), 'endpoint_hash' => hash('sha256', $endpoint), 'region' => $result['region'] ?? null];
    }

    /** @param array<string,mixed> $binding @param array<string,mixed> $authContext @return array<string,mixed> */
    private function dnsBind(PDO $pdo, array $binding, array $authContext): array
    {
        $hosting = $this->hostingAllocation($pdo, (int) $binding['id'], true);
        $envelope = $this->decryptEnvelope($hosting, 'hosting-allocation|' . $binding['id']);
        $endpoint = (string) ($envelope['endpoint'] ?? '');
        $type = str_contains($endpoint, ':') ? 'AAAA' : (filter_var($endpoint, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 'A' : 'CNAME');
        $result = $this->dns->upsertRecord($authContext, (string) $binding['hostname'], $type, $endpoint);
        $reference = trim((string) ($result['provider_reference'] ?? ''));
        if ($reference === '') {
            throw new RuntimeException('DNS provider did not return a record reference.');
        }
        $encrypted = $this->cipher->encrypt($reference, 'dns-binding|' . $binding['id'] . '|' . $binding['hostname'] . '|' . $type);
        $pdo->prepare(
            'INSERT INTO dns_bindings
             (binding_id,account_id,record_name,record_type,record_value_hash,provider_reference_ciphertext,
              provider_reference_nonce,provider_reference_tag,encryption_key_id,status,last_verified_at,created_at,updated_at)
             VALUES (:binding,:account,:name,:type,:value_hash,:ciphertext,:nonce,:tag,:key_id,\'active\',UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())
             ON DUPLICATE KEY UPDATE record_value_hash=VALUES(record_value_hash),provider_reference_ciphertext=VALUES(provider_reference_ciphertext),
              provider_reference_nonce=VALUES(provider_reference_nonce),provider_reference_tag=VALUES(provider_reference_tag),
              encryption_key_id=VALUES(encryption_key_id),status=\'active\',last_verified_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP()'
        )->execute([
            'binding' => $binding['id'],
            'account' => $binding['account_id'],
            'name' => $binding['hostname'],
            'type' => $type,
            'value_hash' => hash('sha256', $endpoint),
            'ciphertext' => $encrypted['ciphertext'],
            'nonce' => $encrypted['nonce'],
            'tag' => $encrypted['tag'],
            'key_id' => $encrypted['key_id'],
        ]);
        return ['provider_reference_hash' => hash('sha256', $reference), 'record_value_hash' => hash('sha256', $endpoint), 'record_type' => $type];
    }

    /** @param array<string,mixed> $binding @param array<string,mixed> $authContext @return array<string,mixed> */
    private function certificateRequest(PDO $pdo, array $binding, array $authContext): array
    {
        $result = $this->certificates->requestCertificate($authContext, (string) $binding['hostname']);
        $reference = trim((string) ($result['provider_reference'] ?? ''));
        if ($reference === '') {
            throw new RuntimeException('Certificate provider did not return an order reference.');
        }
        $encrypted = $this->cipher->encrypt($reference, 'certificate-order|' . $binding['id']);
        $pdo->prepare(
            'INSERT INTO certificate_orders
             (binding_id,account_id,domains_hash,provider_reference_ciphertext,provider_reference_nonce,
              provider_reference_tag,encryption_key_id,status,issued_at,expires_at,last_verified_at,created_at,updated_at)
             VALUES (:binding,:account,:domains_hash,:ciphertext,:nonce,:tag,:key_id,\'active\',UTC_TIMESTAMP(),:expires,UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())
             ON DUPLICATE KEY UPDATE domains_hash=VALUES(domains_hash),provider_reference_ciphertext=VALUES(provider_reference_ciphertext),
              provider_reference_nonce=VALUES(provider_reference_nonce),provider_reference_tag=VALUES(provider_reference_tag),
              encryption_key_id=VALUES(encryption_key_id),status=\'active\',issued_at=UTC_TIMESTAMP(),expires_at=VALUES(expires_at),
              last_verified_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP()'
        )->execute([
            'binding' => $binding['id'],
            'account' => $binding['account_id'],
            'domains_hash' => hash('sha256', strtolower((string) $binding['hostname'])),
            'ciphertext' => $encrypted['ciphertext'],
            'nonce' => $encrypted['nonce'],
            'tag' => $encrypted['tag'],
            'key_id' => $encrypted['key_id'],
            'expires' => isset($result['expires_at']) ? (string) $result['expires_at'] : gmdate('Y-m-d H:i:s', time() + 7776000),
        ]);
        return ['provider_reference_hash' => hash('sha256', $reference), 'expires_at' => $result['expires_at'] ?? null];
    }

    /** @param array<string,mixed> $binding @param array<string,array<string,mixed>> $auth @return array<string,mixed> */
    private function verifyAll(PDO $pdo, array $binding, array $auth): array
    {
        $hosting = $this->verifyHosting($pdo, $binding, $auth['hosting']);
        $dns = $this->verifyDns($pdo, $binding, $auth['dns']);
        $certificate = $this->verifyCertificate($pdo, $binding, $auth['certificate']);
        if (($hosting['verified'] ?? false) !== true || ($dns['verified'] ?? false) !== true || ($certificate['verified'] ?? false) !== true) {
            throw new RuntimeException('Infrastructure provider verification failed.');
        }
        return ['verified' => true, 'hosting' => true, 'dns' => true, 'certificate' => true];
    }

    /** @param array<string,mixed> $binding @param array<string,mixed> $authContext @return array<string,mixed> */
    private function verifyHosting(PDO $pdo, array $binding, array $authContext): array
    {
        $allocation = $this->hostingAllocation($pdo, (int) $binding['id'], true);
        $envelope = $this->decryptEnvelope($allocation, 'hosting-allocation|' . $binding['id']);
        $result = $this->hosting->verifyHosting($authContext, (string) $envelope['reference']);
        $verified = ($result['verified'] ?? false) === true;
        $pdo->prepare('UPDATE hosting_allocations SET status=:status,updated_at=UTC_TIMESTAMP() WHERE id=:id')
            ->execute(['status' => $verified ? 'active' : 'degraded', 'id' => $allocation['id']]);
        return ['verified' => $verified, 'provider_reference_hash' => hash('sha256', (string) $envelope['reference'])];
    }

    /** @param array<string,mixed> $binding @param array<string,mixed> $authContext @return array<string,mixed> */
    private function verifyDns(PDO $pdo, array $binding, array $authContext): array
    {
        $record = $this->dnsBinding($pdo, (int) $binding['id'], true);
        $hosting = $this->hostingAllocation($pdo, (int) $binding['id'], false);
        $hostingEnvelope = $this->decryptEnvelope($hosting, 'hosting-allocation|' . $binding['id']);
        $reference = $this->cipher->decrypt((string) $record['provider_reference_ciphertext'], (string) $record['provider_reference_nonce'], (string) $record['provider_reference_tag'], 'dns-binding|' . $binding['id'] . '|' . $record['record_name'] . '|' . $record['record_type']);
        $result = $this->dns->verifyRecord($authContext, $reference, (string) $record['record_name'], (string) $record['record_type'], (string) $hostingEnvelope['endpoint']);
        $verified = ($result['verified'] ?? false) === true;
        $pdo->prepare('UPDATE dns_bindings SET status=:status,last_verified_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE id=:id')
            ->execute(['status' => $verified ? 'active' : 'degraded', 'id' => $record['id']]);
        return ['verified' => $verified, 'provider_reference_hash' => hash('sha256', $reference)];
    }

    /** @param array<string,mixed> $binding @param array<string,mixed> $authContext @return array<string,mixed> */
    private function verifyCertificate(PDO $pdo, array $binding, array $authContext): array
    {
        $order = $this->certificateOrder($pdo, (int) $binding['id'], true);
        $reference = $this->cipher->decrypt((string) $order['provider_reference_ciphertext'], (string) $order['provider_reference_nonce'], (string) $order['provider_reference_tag'], 'certificate-order|' . $binding['id']);
        $result = $this->certificates->verifyCertificate($authContext, $reference, (string) $binding['hostname']);
        $verified = ($result['verified'] ?? false) === true;
        $pdo->prepare('UPDATE certificate_orders SET status=:status,last_verified_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE id=:id')
            ->execute(['status' => $verified ? 'active' : 'degraded', 'id' => $order['id']]);
        return ['verified' => $verified, 'provider_reference_hash' => hash('sha256', $reference)];
    }

    /** @param array<string,mixed> $binding @param array<string,mixed> $authContext @return array<string,mixed> */
    private function certificateRevoke(PDO $pdo, array $binding, array $authContext): array
    {
        $order = $this->certificateOrder($pdo, (int) $binding['id'], true);
        $reference = $this->cipher->decrypt((string) $order['provider_reference_ciphertext'], (string) $order['provider_reference_nonce'], (string) $order['provider_reference_tag'], 'certificate-order|' . $binding['id']);
        $result = $this->certificates->revokeCertificate($authContext, $reference);
        if (($result['revoked'] ?? false) !== true) {
            throw new RuntimeException('Certificate provider did not verify revocation.');
        }
        $pdo->prepare("UPDATE certificate_orders SET status='revoked',updated_at=UTC_TIMESTAMP() WHERE id=:id")
            ->execute(['id' => $order['id']]);
        return ['revoked' => true, 'provider_reference_hash' => hash('sha256', $reference)];
    }

    /** @param array<string,mixed> $binding @param array<string,mixed> $authContext @return array<string,mixed> */
    private function dnsRemove(PDO $pdo, array $binding, array $authContext): array
    {
        $record = $this->dnsBinding($pdo, (int) $binding['id'], true);
        $reference = $this->cipher->decrypt((string) $record['provider_reference_ciphertext'], (string) $record['provider_reference_nonce'], (string) $record['provider_reference_tag'], 'dns-binding|' . $binding['id'] . '|' . $record['record_name'] . '|' . $record['record_type']);
        $result = $this->dns->removeRecord($authContext, $reference);
        if (($result['removed'] ?? false) !== true) {
            throw new RuntimeException('DNS provider did not verify record removal.');
        }
        $pdo->prepare("UPDATE dns_bindings SET status='removed',updated_at=UTC_TIMESTAMP() WHERE id=:id")
            ->execute(['id' => $record['id']]);
        return ['removed' => true, 'provider_reference_hash' => hash('sha256', $reference)];
    }

    /** @param array<string,mixed> $binding @param array<string,mixed> $authContext @return array<string,mixed> */
    private function hostingRelease(PDO $pdo, array $binding, array $authContext): array
    {
        $allocation = $this->hostingAllocation($pdo, (int) $binding['id'], true);
        $envelope = $this->decryptEnvelope($allocation, 'hosting-allocation|' . $binding['id']);
        $result = $this->hosting->releaseHosting($authContext, (string) $envelope['reference']);
        if (($result['released'] ?? false) !== true) {
            throw new RuntimeException('Hosting provider did not verify allocation release.');
        }
        $pdo->prepare("UPDATE hosting_allocations SET status='released',released_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE id=:id")
            ->execute(['id' => $allocation['id']]);
        return ['released' => true, 'provider_reference_hash' => hash('sha256', (string) $envelope['reference'])];
    }

    /** @param array<string,mixed> $binding @return array<string,mixed> */
    private function activate(PDO $pdo, array $binding): array
    {
        $pdo->prepare("UPDATE infrastructure_bindings SET status='active',activated_at=COALESCE(activated_at,UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=:id")
            ->execute(['id' => $binding['id']]);
        $pdo->prepare("UPDATE pod_deployments SET status='active',routing_status='active',ssl_status='active',updated_at=UTC_TIMESTAMP() WHERE id=:id AND account_id=:account")
            ->execute(['id' => $binding['deployment_id'], 'account' => $binding['account_id']]);
        $pdo->prepare("UPDATE domain_registrations d JOIN pod_deployments p ON p.domain_registration_id=d.id SET d.status='active',d.routing_status='active',d.ssl_status='active',d.updated_at=UTC_TIMESTAMP() WHERE p.id=:deployment AND p.account_id=:account")
            ->execute(['deployment' => $binding['deployment_id'], 'account' => $binding['account_id']]);
        return ['active' => true];
    }

    /** @param array<string,mixed> $binding @return array<string,mixed> */
    private function disable(PDO $pdo, array $binding): array
    {
        $pdo->prepare("UPDATE infrastructure_bindings SET status='disabled',disabled_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE id=:id")
            ->execute(['id' => $binding['id']]);
        $pdo->prepare("UPDATE pod_deployments SET routing_status='disabled',ssl_status='disabled',updated_at=UTC_TIMESTAMP() WHERE id=:id AND account_id=:account")
            ->execute(['id' => $binding['deployment_id'], 'account' => $binding['account_id']]);
        $pdo->prepare("UPDATE domain_registrations d JOIN pod_deployments p ON p.domain_registration_id=d.id SET d.routing_status='disabled',d.ssl_status='disabled',d.updated_at=UTC_TIMESTAMP() WHERE p.id=:deployment AND p.account_id=:account")
            ->execute(['deployment' => $binding['deployment_id'], 'account' => $binding['account_id']]);
        return ['disabled' => true];
    }

    /** @param array<string,mixed> $operation @return array<string,mixed> */
    private function fail(array $operation, Throwable $exception): array
    {
        $status = (int) $operation['attempts'] < (int) $operation['max_attempts'] ? 'queued' : 'failed';
        $this->database->pdo()->prepare(
            "UPDATE provider_operations SET status=:status,available_at=DATE_ADD(UTC_TIMESTAMP(),INTERVAL 60 SECOND),
             locked_at=NULL,locked_by=NULL,last_error_code=:code,last_error_message=:message,updated_at=UTC_TIMESTAMP() WHERE id=:id"
        )->execute([
            'status' => $status,
            'code' => substr($exception::class, 0, 100),
            'message' => substr($exception->getMessage(), 0, 1000),
            'id' => $operation['id'],
        ]);
        $this->database->pdo()->prepare("UPDATE infrastructure_bindings SET status='failed',updated_at=UTC_TIMESTAMP() WHERE id=:id")
            ->execute(['id' => $operation['binding_id']]);
        return ['operation_id' => (int) $operation['id'], 'status' => $status, 'error' => $exception->getMessage()];
    }

    /** @return array<string,mixed> */
    private function connection(PDO $pdo, int $accountId, int $connectionId, ?string $type, bool $lock): array
    {
        $sql = "SELECT * FROM provider_connections WHERE id=:id AND account_id=:account AND status='active'";
        $params = ['id' => $connectionId, 'account' => $accountId];
        if ($type !== null) {
            $sql .= ' AND provider_type=:type';
            $params['type'] = $type;
        }
        $sql .= ' LIMIT 1' . ($lock ? ' FOR UPDATE' : '');
        $query = $pdo->prepare($sql);
        $query->execute($params);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('Active provider connection was not found for this account.');
        }
        return $row;
    }

    /** @param array<string,mixed> $connection @return array<string,mixed> */
    private function decryptConnection(array $connection): array
    {
        $plaintext = $this->cipher->decrypt(
            (string) $connection['credentials_ciphertext'],
            (string) $connection['credentials_nonce'],
            (string) $connection['credentials_tag'],
            $this->connectionContext((int) $connection['account_id'], (string) $connection['provider_type'], (string) $connection['provider_code'], (int) $connection['credential_version'])
        );
        $decoded = json_decode($plaintext, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new RuntimeException('Provider authentication context is invalid.');
        }
        return $decoded;
    }

    private function connectionContext(int $accountId, string $type, string $code, int $version): string
    {
        return 'provider-connection|' . $accountId . '|' . $type . '|' . $code . '|' . $version;
    }

    /** @return array<string,mixed> */
    private function binding(PDO $pdo, int $accountId, int $bindingId, bool $lock): array
    {
        $query = $pdo->prepare('SELECT * FROM infrastructure_bindings WHERE id=:id AND account_id=:account LIMIT 1' . ($lock ? ' FOR UPDATE' : ''));
        $query->execute(['id' => $bindingId, 'account' => $accountId]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('Infrastructure binding was not found for this account.');
        }
        return $row;
    }

    /** @return array<string,mixed> */
    private function hostingAllocation(PDO $pdo, int $bindingId, bool $lock): array
    {
        $query = $pdo->prepare('SELECT * FROM hosting_allocations WHERE binding_id=:binding LIMIT 1' . ($lock ? ' FOR UPDATE' : ''));
        $query->execute(['binding' => $bindingId]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('Hosting allocation was not found.');
        }
        return $row;
    }

    /** @return array<string,mixed> */
    private function dnsBinding(PDO $pdo, int $bindingId, bool $lock): array
    {
        $query = $pdo->prepare('SELECT * FROM dns_bindings WHERE binding_id=:binding AND status NOT IN (\'removed\') LIMIT 1' . ($lock ? ' FOR UPDATE' : ''));
        $query->execute(['binding' => $bindingId]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('DNS binding was not found.');
        }
        return $row;
    }

    /** @return array<string,mixed> */
    private function certificateOrder(PDO $pdo, int $bindingId, bool $lock): array
    {
        $query = $pdo->prepare('SELECT * FROM certificate_orders WHERE binding_id=:binding AND status NOT IN (\'revoked\') LIMIT 1' . ($lock ? ' FOR UPDATE' : ''));
        $query->execute(['binding' => $bindingId]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('Certificate order was not found.');
        }
        return $row;
    }

    /** @param array<string,mixed> $row @return array<string,mixed> */
    private function decryptEnvelope(array $row, string $context): array
    {
        $plaintext = $this->cipher->decrypt(
            (string) $row['provider_reference_ciphertext'],
            (string) $row['provider_reference_nonce'],
            (string) $row['provider_reference_tag'],
            $context
        );
        $decoded = json_decode($plaintext, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new RuntimeException('Encrypted provider reference envelope is invalid.');
        }
        return $decoded;
    }

    /** @param list<string> $allowed */
    private function transition(int $accountId, int $operationId, string $requestId, array $allowed, string $next): void
    {
        if ($accountId < 1 || trim($requestId) === '') {
            throw new RuntimeException('Account and request ID are required.');
        }
        $marks = implode(',', array_fill(0, count($allowed), '?'));
        $statement = $this->database->pdo()->prepare(
            "UPDATE provider_operations SET status=?,request_id=?,available_at=UTC_TIMESTAMP(),locked_at=NULL,locked_by=NULL,updated_at=UTC_TIMESTAMP()
             WHERE id=? AND account_id=? AND status IN ({$marks})"
        );
        $statement->execute(array_merge([$next, $requestId, $operationId, $accountId], $allowed));
        if ($statement->rowCount() !== 1) {
            throw new RuntimeException('Infrastructure operation cannot transition to ' . $next . '.');
        }
    }

    /** @param array<string,mixed>|null $metadata */
    private function receipt(PDO $pdo, int $accountId, ?int $operationId, ?int $bindingId, string $requestId, string $operation, string $result, ?string $hash, ?array $metadata): void
    {
        $pdo->prepare(
            'INSERT INTO provider_receipts
             (public_id,account_id,operation_id,binding_id,request_id,operation,result,receipt_hash,metadata_json,created_at)
             VALUES (:public,:account,:operation_id,:binding,:request,:operation,:result,:hash,:metadata,UTC_TIMESTAMP())'
        )->execute([
            'public' => 'PROVIDER-RCP-' . strtoupper(bin2hex(random_bytes(12))),
            'account' => $accountId,
            'operation_id' => $operationId,
            'binding' => $bindingId,
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
            'provider_reference_hash', 'endpoint_hash', 'record_value_hash', 'record_type', 'region',
            'expires_at', 'verified', 'active', 'disabled', 'released', 'removed', 'revoked',
        ]));
    }

    private function validHostname(string $hostname): bool
    {
        $hostname = strtolower(trim($hostname));
        return strlen($hostname) <= 253
            && (bool) preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$/', $hostname);
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
