<?php

declare(strict_types=1);

namespace Vp3\HomeServers;

use PDO;
use RuntimeException;
use Vp3\Database;

final class HomeServerRegistryService
{
    public function __construct(
        private readonly Database $database,
        private readonly HomeServerLeaseSigner $leaseSigner,
        private readonly int $pairingTtlSeconds = 900,
        private readonly int $leaseTtlSeconds = 3600
    ) {
    }

    /** @return array{device_id:int,device_public_id:string,credential:?string,enrollment_code:?string,replayed:bool} */
    public function registerDevice(
        int $accountId,
        int $licenseId,
        string $deviceFingerprint,
        string $requestId,
        string $idempotencyKey
    ): array {
        $this->required($accountId, $requestId, $idempotencyKey);
        $fingerprint = strtolower(trim($deviceFingerprint));
        if (!preg_match('/^[a-f0-9]{64}$/', $fingerprint)) {
            throw new RuntimeException('HomeServer device fingerprint must be a SHA-256 value.');
        }
        $requestHash = hash('sha256', $this->json([$licenseId, $fingerprint]));
        return $this->database->transaction(function (PDO $pdo) use (
            $accountId, $licenseId, $fingerprint, $requestId, $idempotencyKey, $requestHash
        ): array {
            $replay = $this->receiptReplay($pdo, $accountId, 'register_device', $idempotencyKey, $requestHash);
            if ($replay !== null) {
                return [
                    'device_id' => (int) $replay['device_id'],
                    'device_public_id' => (string) $replay['device_public_id'],
                    'credential' => null,
                    'enrollment_code' => null,
                    'replayed' => true,
                ];
            }
            $target = $this->licensedTarget($pdo, $accountId, $licenseId);
            $existing = $pdo->prepare('SELECT id,public_id FROM homeserver_devices WHERE license_id=:license OR device_fingerprint=:fingerprint LIMIT 1 FOR UPDATE');
            $existing->execute(['license' => $licenseId, 'fingerprint' => $fingerprint]);
            $device = $existing->fetch(PDO::FETCH_ASSOC);
            if (is_array($device)) {
                throw new RuntimeException('The HomeServer license or device fingerprint is already registered.');
            }

            $credential = $this->secret(32);
            $publicId = 'HS-' . strtoupper(bin2hex(random_bytes(12)));
            $pdo->prepare(
                'INSERT INTO homeserver_devices
                 (public_id,account_id,subscription_id,domain_registration_id,license_id,device_fingerprint,
                  credential_hash,credential_version,status,pairing_status,update_channel,frontend_limit,
                  created_at,updated_at)
                 VALUES (:public,:account,:subscription,:domain,:license,:fingerprint,:credential_hash,1,
                         \'pending_pairing\',\'code_issued\',:channel,:frontend_limit,UTC_TIMESTAMP(),UTC_TIMESTAMP())'
            )->execute([
                'public' => $publicId,
                'account' => $accountId,
                'subscription' => $target['subscription_id'],
                'domain' => $target['domain_registration_id'],
                'license' => $licenseId,
                'fingerprint' => $fingerprint,
                'credential_hash' => hash('sha256', $credential),
                'channel' => $target['update_channel'],
                'frontend_limit' => $target['frontend_limit'],
            ]);
            $deviceId = (int) $pdo->lastInsertId();
            $code = $this->pairingCode($pdo, $deviceId, $accountId, 'device_enrollment');
            $safe = ['device_id' => $deviceId, 'device_public_id' => $publicId];
            $this->completeReceipt($pdo, $accountId, $deviceId, 'register_device', $idempotencyKey, $requestId, $requestHash, $safe);
            $this->event($pdo, $deviceId, $accountId, $requestId, 'device_registered', 'success', [
                'license_id' => $licenseId,
                'credential_version' => 1,
                'frontend_limit' => $target['frontend_limit'],
            ]);
            return $safe + ['credential' => $credential, 'enrollment_code' => $code, 'replayed' => false];
        });
    }

    public function activateDevice(
        int $accountId,
        string $devicePublicId,
        string $credential,
        string $enrollmentCode,
        string $requestId
    ): void {
        $this->database->transaction(function (PDO $pdo) use ($accountId, $devicePublicId, $credential, $enrollmentCode, $requestId): void {
            $device = $this->device($pdo, $accountId, $devicePublicId, true);
            $this->authenticate($device, $credential);
            $this->consumeCode($pdo, (int) $device['id'], $accountId, $enrollmentCode, 'device_enrollment');
            $pdo->prepare(
                "UPDATE homeserver_devices SET status='paired',pairing_status='paired',paired_at=COALESCE(paired_at,UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=:id"
            )->execute(['id' => $device['id']]);
            $this->event($pdo, (int) $device['id'], $accountId, $requestId, 'device_activated', 'success', null);
        });
    }

    public function issueFrontendPairingCode(
        int $accountId,
        string $devicePublicId,
        string $credential,
        string $requestId
    ): string {
        return $this->database->transaction(function (PDO $pdo) use ($accountId, $devicePublicId, $credential, $requestId): string {
            $device = $this->device($pdo, $accountId, $devicePublicId, true);
            $this->authenticate($device, $credential);
            $this->assertUsable($device);
            $pdo->prepare(
                "UPDATE homeserver_pairing_codes SET status='revoked',revoked_at=UTC_TIMESTAMP()
                 WHERE device_id=:device AND purpose='frontend_pairing' AND status='active'"
            )->execute(['device' => $device['id']]);
            $code = $this->pairingCode($pdo, (int) $device['id'], $accountId, 'frontend_pairing');
            $this->event($pdo, (int) $device['id'], $accountId, $requestId, 'frontend_pairing_code_issued', 'success', null);
            return $code;
        });
    }

    /** @param list<string> $permissionScopes @return array{pair_id:int,pair_public_id:string,replayed:bool} */
    public function pairFrontend(
        int $accountId,
        string $devicePublicId,
        int $deploymentId,
        string $pairingCode,
        array $permissionScopes,
        string $requestId,
        string $idempotencyKey
    ): array {
        $this->required($accountId, $requestId, $idempotencyKey);
        $scopes = array_values(array_unique(array_filter(array_map('trim', $permissionScopes))));
        sort($scopes);
        $requestHash = hash('sha256', $this->json([$devicePublicId, $deploymentId, $scopes]));
        return $this->database->transaction(function (PDO $pdo) use (
            $accountId, $devicePublicId, $deploymentId, $pairingCode, $scopes, $requestId, $idempotencyKey, $requestHash
        ): array {
            $replay = $this->receiptReplay($pdo, $accountId, 'pair_frontend', $idempotencyKey, $requestHash);
            if ($replay !== null) {
                return ['pair_id' => (int) $replay['pair_id'], 'pair_public_id' => (string) $replay['pair_public_id'], 'replayed' => true];
            }
            $device = $this->device($pdo, $accountId, $devicePublicId, true);
            $this->assertUsable($device);
            $deployment = $pdo->prepare("SELECT id,status FROM pod_deployments WHERE id=:id AND account_id=:account AND status IN ('active','degraded') LIMIT 1 FOR UPDATE");
            $deployment->execute(['id' => $deploymentId, 'account' => $accountId]);
            if (!is_array($deployment->fetch(PDO::FETCH_ASSOC))) {
                throw new RuntimeException('The POD deployment is not pairable by this account.');
            }
            $this->consumeCode($pdo, (int) $device['id'], $accountId, $pairingCode, 'frontend_pairing');
            $existing = $pdo->prepare('SELECT id,public_id,status FROM homeserver_frontend_pairs WHERE device_id=:device AND deployment_id=:deployment LIMIT 1 FOR UPDATE');
            $existing->execute(['device' => $device['id'], 'deployment' => $deploymentId]);
            $pair = $existing->fetch(PDO::FETCH_ASSOC);
            if (!is_array($pair)) {
                if ((int) $device['paired_frontend_count'] >= (int) $device['frontend_limit']) {
                    throw new RuntimeException('The licensed paired-front-end limit has been reached.');
                }
                $publicId = 'PAIR-' . strtoupper(bin2hex(random_bytes(12)));
                $pdo->prepare(
                    'INSERT INTO homeserver_frontend_pairs
                     (public_id,device_id,account_id,deployment_id,wrapper_type,status,permission_scope_hash,paired_at,created_at,updated_at)
                     VALUES (:public,:device,:account,:deployment,\'pod\',\'active\',:scope_hash,UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())'
                )->execute([
                    'public' => $publicId,
                    'device' => $device['id'],
                    'account' => $accountId,
                    'deployment' => $deploymentId,
                    'scope_hash' => hash('sha256', $this->json($scopes)),
                ]);
                $pair = ['id' => (int) $pdo->lastInsertId(), 'public_id' => $publicId];
            } else {
                $pdo->prepare(
                    "UPDATE homeserver_frontend_pairs SET status='active',permission_scope_hash=:scope_hash,paired_at=UTC_TIMESTAMP(),revoked_at=NULL,updated_at=UTC_TIMESTAMP() WHERE id=:id"
                )->execute(['scope_hash' => hash('sha256', $this->json($scopes)), 'id' => $pair['id']]);
            }
            $this->syncPairCount($pdo, (int) $device['id']);
            $safe = ['pair_id' => (int) $pair['id'], 'pair_public_id' => (string) $pair['public_id']];
            $this->completeReceipt($pdo, $accountId, (int) $device['id'], 'pair_frontend', $idempotencyKey, $requestId, $requestHash, $safe);
            $this->event($pdo, (int) $device['id'], $accountId, $requestId, 'frontend_paired', 'success', [
                'deployment_id' => $deploymentId,
                'scope_hash' => hash('sha256', $this->json($scopes)),
            ]);
            return $safe + ['replayed' => false];
        });
    }

    public function unpairFrontend(int $accountId, string $devicePublicId, int $deploymentId, string $requestId): void
    {
        $this->database->transaction(function (PDO $pdo) use ($accountId, $devicePublicId, $deploymentId, $requestId): void {
            $device = $this->device($pdo, $accountId, $devicePublicId, true);
            $statement = $pdo->prepare(
                "UPDATE homeserver_frontend_pairs SET status='revoked',revoked_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP()
                 WHERE device_id=:device AND account_id=:account AND deployment_id=:deployment AND status='active'"
            );
            $statement->execute(['device' => $device['id'], 'account' => $accountId, 'deployment' => $deploymentId]);
            if ($statement->rowCount() !== 1) {
                throw new RuntimeException('Active HomeServer frontend pair was not found.');
            }
            $this->syncPairCount($pdo, (int) $device['id']);
            $this->event($pdo, (int) $device['id'], $accountId, $requestId, 'frontend_unpaired', 'success', ['deployment_id' => $deploymentId]);
        });
    }

    /** @return array{credential:string,credential_version:int} */
    public function rotateCredential(
        int $accountId,
        string $devicePublicId,
        string $currentCredential,
        string $reason,
        string $requestId
    ): array {
        return $this->database->transaction(function (PDO $pdo) use ($accountId, $devicePublicId, $currentCredential, $reason, $requestId): array {
            $device = $this->device($pdo, $accountId, $devicePublicId, true);
            $this->authenticate($device, $currentCredential);
            $next = (int) $device['credential_version'] + 1;
            $credential = $this->secret(32);
            $newHash = hash('sha256', $credential);
            $pdo->prepare(
                'INSERT INTO homeserver_credential_rotations
                 (device_id,account_id,request_id,previous_version,new_version,previous_hash,new_hash,reason,rotated_at)
                 VALUES (:device,:account,:request,:previous_version,:new_version,:previous_hash,:new_hash,:reason,UTC_TIMESTAMP())'
            )->execute([
                'device' => $device['id'],
                'account' => $accountId,
                'request' => $requestId,
                'previous_version' => $device['credential_version'],
                'new_version' => $next,
                'previous_hash' => $device['credential_hash'],
                'new_hash' => $newHash,
                'reason' => substr(trim($reason) ?: 'routine_rotation', 0, 190),
            ]);
            $pdo->prepare('UPDATE homeserver_devices SET credential_hash=:hash,credential_version=:version,updated_at=UTC_TIMESTAMP() WHERE id=:id')
                ->execute(['hash' => $newHash, 'version' => $next, 'id' => $device['id']]);
            $this->event($pdo, (int) $device['id'], $accountId, $requestId, 'credential_rotated', 'success', ['credential_version' => $next]);
            return ['credential' => $credential, 'credential_version' => $next];
        });
    }

    /** @param array<string,mixed> $health @return array{device_id:int,status:string} */
    public function heartbeat(
        int $accountId,
        string $devicePublicId,
        string $deviceFingerprint,
        string $credential,
        array $health,
        string $requestId
    ): array {
        return $this->database->transaction(function (PDO $pdo) use (
            $accountId, $devicePublicId, $deviceFingerprint, $credential, $health, $requestId
        ): array {
            $device = $this->device($pdo, $accountId, $devicePublicId, true);
            if (!hash_equals((string) $device['device_fingerprint'], strtolower(trim($deviceFingerprint)))) {
                throw new RuntimeException('HomeServer heartbeat fingerprint mismatch.');
            }
            $this->authenticate($device, $credential);
            $this->assertUsable($device);
            $mcpAvailable = filter_var($health['mcp_available'] ?? true, FILTER_VALIDATE_BOOL);
            $pairingAvailable = filter_var($health['pairing_available'] ?? true, FILTER_VALIDATE_BOOL);
            $status = ($mcpAvailable && $pairingAvailable) ? 'online' : 'degraded';
            $softwareVersion = $this->version($health['software_version'] ?? $device['software_version']);
            $mcpVersion = $this->version($health['mcp_version'] ?? $device['mcp_version']);
            $pdo->prepare(
                'UPDATE homeserver_devices SET status=:status,software_version=:software,mcp_version=:mcp,
                 last_heartbeat_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE id=:id'
            )->execute([
                'status' => $status,
                'software' => $softwareVersion,
                'mcp' => $mcpVersion,
                'id' => $device['id'],
            ]);
            $this->event($pdo, (int) $device['id'], $accountId, $requestId, 'heartbeat_received', 'success', [
                'status' => $status,
                'software_version' => $softwareVersion,
                'mcp_version' => $mcpVersion,
                'mcp_available' => $mcpAvailable,
                'pairing_available' => $pairingAvailable,
            ]);
            return ['device_id' => (int) $device['id'], 'status' => $status];
        });
    }

    /** @return array{lease_public_id:string,document:string,signature:string,key_id:string,expires_at:string} */
    public function issueEntitlementLease(
        int $accountId,
        string $devicePublicId,
        string $credential,
        string $requestId
    ): array {
        return $this->database->transaction(function (PDO $pdo) use ($accountId, $devicePublicId, $credential, $requestId): array {
            $device = $this->device($pdo, $accountId, $devicePublicId, true);
            $this->authenticate($device, $credential);
            $this->assertUsable($device);
            $entitlements = $pdo->prepare(
                'SELECT entitlement_key,value_type,value_json,effective_at,expires_at
                 FROM license_entitlements WHERE license_id=:license ORDER BY entitlement_key'
            );
            $entitlements->execute(['license' => $device['license_id']]);
            $values = [];
            foreach ($entitlements->fetchAll(PDO::FETCH_ASSOC) as $row) {
                $values[(string) $row['entitlement_key']] = json_decode((string) $row['value_json'], true, 512, JSON_THROW_ON_ERROR);
            }
            $issuedAt = time();
            $expiresAt = $issuedAt + max(300, $this->leaseTtlSeconds);
            $claims = [
                'iss' => 'vp3.me',
                'sub' => (string) $device['public_id'],
                'account_id' => (int) $device['account_id'],
                'license_id' => (int) $device['license_id'],
                'domain_registration_id' => (int) $device['domain_registration_id'],
                'device_fingerprint' => (string) $device['device_fingerprint'],
                'credential_version' => (int) $device['credential_version'],
                'update_channel' => (string) $device['update_channel'],
                'frontend_limit' => (int) $device['frontend_limit'],
                'entitlements' => $values,
                'iat' => $issuedAt,
                'exp' => $expiresAt,
                'nonce' => bin2hex(random_bytes(16)),
            ];
            $signed = $this->leaseSigner->sign($claims);
            $snapshotHash = hash('sha256', $this->json($values));
            $pdo->prepare(
                "UPDATE homeserver_entitlement_leases SET status='superseded',superseded_at=UTC_TIMESTAMP()
                 WHERE device_id=:device AND status='active'"
            )->execute(['device' => $device['id']]);
            $publicId = 'LEASE-' . strtoupper(bin2hex(random_bytes(12)));
            $expires = gmdate('Y-m-d H:i:s', $expiresAt);
            $pdo->prepare(
                'INSERT INTO homeserver_entitlement_leases
                 (public_id,device_id,account_id,license_id,entitlement_snapshot_hash,document_hash,signature_hash,
                  signing_key_id,status,issued_at,expires_at,created_at)
                 VALUES (:public,:device,:account,:license,:snapshot,:document,:signature,:key_id,\'active\',UTC_TIMESTAMP(),:expires,UTC_TIMESTAMP())'
            )->execute([
                'public' => $publicId,
                'device' => $device['id'],
                'account' => $accountId,
                'license' => $device['license_id'],
                'snapshot' => $snapshotHash,
                'document' => $signed['document_hash'],
                'signature' => $signed['signature_hash'],
                'key_id' => $signed['key_id'],
                'expires' => $expires,
            ]);
            $this->event($pdo, (int) $device['id'], $accountId, $requestId, 'entitlement_lease_issued', 'success', [
                'lease_public_id' => $publicId,
                'entitlement_snapshot_hash' => $snapshotHash,
                'expires_at' => $expires,
            ]);
            return [
                'lease_public_id' => $publicId,
                'document' => $signed['document'],
                'signature' => $signed['signature'],
                'key_id' => $signed['key_id'],
                'expires_at' => $expires,
            ];
        });
    }

    public function revokeDevice(int $accountId, string $devicePublicId, string $requestId): void
    {
        $this->database->transaction(function (PDO $pdo) use ($accountId, $devicePublicId, $requestId): void {
            $device = $this->device($pdo, $accountId, $devicePublicId, true);
            $pdo->prepare(
                "UPDATE homeserver_devices SET status='revoked',pairing_status='revoked',credential_hash=:hash,
                 paired_frontend_count=0,revoked_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE id=:id"
            )->execute(['hash' => hash('sha256', random_bytes(32)), 'id' => $device['id']]);
            $pdo->prepare("UPDATE homeserver_pairing_codes SET status='revoked',revoked_at=UTC_TIMESTAMP() WHERE device_id=:device AND status='active'")
                ->execute(['device' => $device['id']]);
            $pdo->prepare("UPDATE homeserver_frontend_pairs SET status='revoked',revoked_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE device_id=:device AND status='active'")
                ->execute(['device' => $device['id']]);
            $pdo->prepare("UPDATE homeserver_entitlement_leases SET status='revoked',revoked_at=UTC_TIMESTAMP() WHERE device_id=:device AND status='active'")
                ->execute(['device' => $device['id']]);
            $this->event($pdo, (int) $device['id'], $accountId, $requestId, 'device_revoked', 'success', null);
        });
    }

    public function markOffline(int $minutes = 10): int
    {
        $statement = $this->database->pdo()->prepare(
            "UPDATE homeserver_devices SET status='offline',updated_at=UTC_TIMESTAMP()
             WHERE status IN ('online','degraded','paired')
             AND (last_heartbeat_at IS NULL OR last_heartbeat_at<DATE_SUB(UTC_TIMESTAMP(),INTERVAL :minutes MINUTE))"
        );
        $statement->bindValue('minutes', max(1, $minutes), PDO::PARAM_INT);
        $statement->execute();
        return $statement->rowCount();
    }

    /** @return array{subscription_id:int,domain_registration_id:int,update_channel:string,frontend_limit:int} */
    private function licensedTarget(PDO $pdo, int $accountId, int $licenseId): array
    {
        $query = $pdo->prepare(
            "SELECT l.subscription_id,l.domain_registration_id,
             COALESCE(JSON_UNQUOTE(channel.value_json),'stable') update_channel,
             COALESCE(CAST(JSON_UNQUOTE(client_limit.value_json) AS UNSIGNED),1) frontend_limit
             FROM licenses l JOIN subscriptions s ON s.id=l.subscription_id AND s.account_id=l.account_id
             JOIN domain_registrations d ON d.id=l.domain_registration_id AND d.account_id=l.account_id
             LEFT JOIN license_entitlements channel ON channel.license_id=l.id AND channel.entitlement_key='update_channel'
             LEFT JOIN license_entitlements client_limit ON client_limit.license_id=l.id AND client_limit.entitlement_key='mcp_client_limit'
             WHERE l.id=:license AND l.account_id=:account AND l.product_type='homeserver'
             AND l.status IN ('active','grace') AND s.status IN ('active','trialing','grace')
             AND d.status IN ('reserved','pending','active','grace') LIMIT 1 FOR UPDATE"
        );
        $query->execute(['license' => $licenseId, 'account' => $accountId]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('The HomeServer license is not eligible for device registration.');
        }
        return [
            'subscription_id' => (int) $row['subscription_id'],
            'domain_registration_id' => (int) $row['domain_registration_id'],
            'update_channel' => trim((string) $row['update_channel'], '"') ?: 'stable',
            'frontend_limit' => max(1, (int) $row['frontend_limit']),
        ];
    }

    /** @return array<string,mixed> */
    private function device(PDO $pdo, int $accountId, string $publicId, bool $lock): array
    {
        $query = $pdo->prepare(
            'SELECT * FROM homeserver_devices WHERE public_id=:public AND account_id=:account LIMIT 1' . ($lock ? ' FOR UPDATE' : '')
        );
        $query->execute(['public' => trim($publicId), 'account' => $accountId]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('HomeServer device was not found for this account.');
        }
        return $row;
    }

    /** @param array<string,mixed> $device */
    private function authenticate(array $device, string $credential): void
    {
        if ($credential === '' || !hash_equals((string) $device['credential_hash'], hash('sha256', $credential))) {
            throw new RuntimeException('HomeServer device credential is invalid.');
        }
    }

    /** @param array<string,mixed> $device */
    private function assertUsable(array $device): void
    {
        if (!in_array($device['status'], ['paired', 'online', 'degraded', 'offline'], true) || $device['pairing_status'] !== 'paired') {
            throw new RuntimeException('HomeServer device is not active for this operation.');
        }
    }

    private function pairingCode(PDO $pdo, int $deviceId, int $accountId, string $purpose): string
    {
        $code = strtoupper(substr(bin2hex(random_bytes(8)), 0, 12));
        $pdo->prepare(
            'INSERT INTO homeserver_pairing_codes
             (public_id,device_id,account_id,code_hash,purpose,status,expires_at,created_at)
             VALUES (:public,:device,:account,:hash,:purpose,\'active\',DATE_ADD(UTC_TIMESTAMP(),INTERVAL :ttl SECOND),UTC_TIMESTAMP())'
        )->execute([
            'public' => 'HSP-' . strtoupper(bin2hex(random_bytes(12))),
            'device' => $deviceId,
            'account' => $accountId,
            'hash' => hash('sha256', $code),
            'purpose' => $purpose,
            'ttl' => max(60, $this->pairingTtlSeconds),
        ]);
        return $code;
    }

    private function consumeCode(PDO $pdo, int $deviceId, int $accountId, string $code, string $purpose): void
    {
        $statement = $pdo->prepare(
            "SELECT id FROM homeserver_pairing_codes WHERE device_id=:device AND account_id=:account
             AND code_hash=:hash AND purpose=:purpose AND status='active' AND expires_at>UTC_TIMESTAMP()
             LIMIT 1 FOR UPDATE"
        );
        $statement->execute([
            'device' => $deviceId,
            'account' => $accountId,
            'hash' => hash('sha256', strtoupper(trim($code))),
            'purpose' => $purpose,
        ]);
        $id = $statement->fetchColumn();
        if (!$id) {
            throw new RuntimeException('HomeServer pairing code is invalid or expired.');
        }
        $pdo->prepare("UPDATE homeserver_pairing_codes SET status='consumed',consumed_at=UTC_TIMESTAMP() WHERE id=:id")
            ->execute(['id' => $id]);
    }

    private function syncPairCount(PDO $pdo, int $deviceId): void
    {
        $pdo->prepare(
            "UPDATE homeserver_devices SET paired_frontend_count=(SELECT COUNT(*) FROM homeserver_frontend_pairs WHERE device_id=:source AND status='active'),updated_at=UTC_TIMESTAMP() WHERE id=:target"
        )->execute(['source' => $deviceId, 'target' => $deviceId]);
    }

    /** @return array<string,mixed>|null */
    private function receiptReplay(PDO $pdo, int $accountId, string $operation, string $idempotencyKey, string $requestHash): ?array
    {
        $query = $pdo->prepare(
            'SELECT request_hash,status,response_json FROM homeserver_request_receipts
             WHERE account_id=:account AND operation=:operation AND idempotency_key=:key LIMIT 1 FOR UPDATE'
        );
        $query->execute(['account' => $accountId, 'operation' => $operation, 'key' => $idempotencyKey]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            return null;
        }
        if (!hash_equals((string) $row['request_hash'], $requestHash)) {
            throw new RuntimeException('HomeServer idempotency key was reused with another request.');
        }
        if ($row['status'] !== 'completed' || !is_string($row['response_json'])) {
            throw new RuntimeException('The matching HomeServer request is still processing.');
        }
        $decoded = json_decode($row['response_json'], true, 512, JSON_THROW_ON_ERROR);
        return is_array($decoded) ? $decoded : [];
    }

    /** @param array<string,mixed> $response */
    private function completeReceipt(
        PDO $pdo,
        int $accountId,
        int $deviceId,
        string $operation,
        string $idempotencyKey,
        string $requestId,
        string $requestHash,
        array $response
    ): void {
        $pdo->prepare(
            'INSERT INTO homeserver_request_receipts
             (account_id,device_id,operation,idempotency_key,request_id,request_hash,status,response_json,created_at,completed_at)
             VALUES (:account,:device,:operation,:key,:request,:hash,\'completed\',:response,UTC_TIMESTAMP(),UTC_TIMESTAMP())'
        )->execute([
            'account' => $accountId,
            'device' => $deviceId,
            'operation' => $operation,
            'key' => $idempotencyKey,
            'request' => $requestId,
            'hash' => $requestHash,
            'response' => $this->json($response),
        ]);
    }

    /** @param array<string,mixed>|null $metadata */
    private function event(PDO $pdo, int $deviceId, int $accountId, string $requestId, string $type, string $result, ?array $metadata): void
    {
        $pdo->prepare(
            'INSERT INTO homeserver_events
             (device_id,account_id,request_id,event_type,result,metadata_json,created_at)
             VALUES (:device,:account,:request,:type,:result,:metadata,UTC_TIMESTAMP())'
        )->execute([
            'device' => $deviceId,
            'account' => $accountId,
            'request' => $requestId,
            'type' => $type,
            'result' => $result,
            'metadata' => $metadata === null ? null : $this->json($metadata),
        ]);
    }

    private function required(int $accountId, string $requestId, string $idempotencyKey): void
    {
        if ($accountId < 1 || trim($requestId) === '' || trim($idempotencyKey) === '') {
            throw new RuntimeException('Account, request ID, and idempotency key are required.');
        }
    }

    private function version(mixed $value): ?string
    {
        if (!is_string($value) || trim($value) === '') {
            return null;
        }
        return substr(trim($value), 0, 80);
    }

    private function secret(int $bytes): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
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
