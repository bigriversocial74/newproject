<?php

declare(strict_types=1);

namespace Vp3\HomeServers;

use PDO;
use RuntimeException;
use Vp3\Database;

final class HomeServerControlPlaneService
{
    public function __construct(
        private readonly Database $database,
        private readonly HomeServerRegistryService $registry,
        private readonly int $installerGrantTtlSeconds = 600,
        private readonly int $transferTtlSeconds = 1800
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
        return $this->registry->registerDevice(
            $accountId,
            $licenseId,
            $deviceFingerprint,
            $requestId,
            $idempotencyKey
        );
    }

    /** @return array{device_public_id:string,status:string,lease:array<string,mixed>} */
    public function activateDevice(
        int $accountId,
        string $devicePublicId,
        string $credential,
        string $enrollmentCode,
        string $requestId
    ): array {
        $this->registry->activateDevice($accountId, $devicePublicId, $credential, $enrollmentCode, $requestId);
        $lease = $this->registry->issueEntitlementLease($accountId, $devicePublicId, $credential, $requestId . '-LEASE');
        return ['device_public_id' => $devicePublicId, 'status' => 'paired', 'lease' => $lease];
    }

    /** @param array<string,mixed> $health @return array<string,mixed> */
    public function heartbeat(
        string $devicePublicId,
        string $credential,
        string $deviceFingerprint,
        array $health,
        string $requestId
    ): array {
        $device = $this->authenticateDevice($devicePublicId, $credential, false);
        $status = $this->registry->heartbeat(
            (int) $device['account_id'],
            $devicePublicId,
            $deviceFingerprint,
            $credential,
            $health,
            $requestId
        );
        return $status + [
            'software_authority' => 'vp3',
            'license_public_id' => (string) $device['license_public_id'],
            'update_channel' => (string) $device['update_channel'],
            'lease_refresh_recommended' => true,
        ];
    }

    /** @return array<string,mixed> */
    public function refreshLease(string $devicePublicId, string $credential, string $requestId): array
    {
        $device = $this->authenticateDevice($devicePublicId, $credential, false);
        return $this->registry->issueEntitlementLease(
            (int) $device['account_id'],
            $devicePublicId,
            $credential,
            $requestId
        );
    }

    /** @return array<string,mixed> */
    public function latestRelease(
        string $devicePublicId,
        string $credential,
        string $currentVersion,
        string $platform,
        string $architecture,
        string $requestId
    ): array {
        $device = $this->authenticateDevice($devicePublicId, $credential, false);
        $currentVersion = $this->version($currentVersion);
        $platform = $this->targetPart($platform, 'platform');
        $architecture = $this->targetPart($architecture, 'architecture');
        $allowedChannels = [(string) $device['update_channel'], 'security'];
        if ($device['update_channel'] === 'beta') {
            $allowedChannels[] = 'stable';
        }
        $allowedChannels = array_values(array_unique($allowedChannels));
        $placeholders = implode(',', array_fill(0, count($allowedChannels), '?'));
        $query = $this->database->pdo()->prepare(
            "SELECT r.id release_id,r.public_id release_public_id,r.version,r.channel,r.emergency_override,
                    r.manifest_document,r.manifest_signature,r.signature_algorithm,r.signing_key_id,r.manifest_hash,
                    r.published_at,rr.percentage,rr.cohort_seed,rr.starts_at,rr.ends_at,
                    a.id artifact_id,a.storage_reference,a.sha256,a.size_bytes,
                    c.minimum_current_version,c.maximum_current_version
             FROM software_releases r
             JOIN software_products p ON p.id=r.product_id AND p.target_type='homeserver' AND p.status='active'
             JOIN release_rollouts rr ON rr.release_id=r.id AND rr.status='active'
             JOIN release_artifacts a ON a.release_id=r.id AND a.platform=? AND a.architecture=?
             LEFT JOIN release_compatibility_rules c ON c.release_id=r.id
             WHERE r.status='published' AND r.channel IN ({$placeholders})
               AND (rr.starts_at IS NULL OR rr.starts_at<=UTC_TIMESTAMP())
               AND (rr.ends_at IS NULL OR rr.ends_at>UTC_TIMESTAMP())
             ORDER BY r.emergency_override DESC,r.published_at DESC,r.id DESC"
        );
        $query->execute(array_merge([$platform, $architecture], $allowedChannels));
        $release = null;
        foreach ($query->fetchAll(PDO::FETCH_ASSOC) as $candidate) {
            if (!$this->compatible($currentVersion, $candidate)) {
                continue;
            }
            if (!(bool) $candidate['emergency_override'] && !$this->inRollout($devicePublicId, (string) $candidate['cohort_seed'], (int) $candidate['percentage'])) {
                continue;
            }
            if (version_compare((string) $candidate['version'], $currentVersion, '<=')) {
                continue;
            }
            $release = $candidate;
            break;
        }
        if (!is_array($release)) {
            $this->event((int) $device['account_id'], (int) $device['id'], $requestId, 'release_check', 'success', ['available' => false]);
            return [
                'available' => false,
                'software_authority' => 'vp3',
                'current_version' => $currentVersion,
                'update_channel' => (string) $device['update_channel'],
            ];
        }

        $grant = $this->issueInstallerGrant($device, $release);
        $this->event((int) $device['account_id'], (int) $device['id'], $requestId, 'release_authorized', 'success', [
            'release_public_id' => $release['release_public_id'],
            'version' => $release['version'],
            'channel' => $release['channel'],
        ]);
        return [
            'available' => true,
            'software_authority' => 'vp3',
            'release_public_id' => (string) $release['release_public_id'],
            'version' => (string) $release['version'],
            'channel' => (string) $release['channel'],
            'emergency_override' => (bool) $release['emergency_override'],
            'manifest' => (string) $release['manifest_document'],
            'signature' => (string) $release['manifest_signature'],
            'signature_algorithm' => (string) $release['signature_algorithm'],
            'signing_key_id' => (string) $release['signing_key_id'],
            'manifest_hash' => (string) $release['manifest_hash'],
            'artifact' => [
                'platform' => $platform,
                'architecture' => $architecture,
                'sha256' => (string) $release['sha256'],
                'size_bytes' => (int) $release['size_bytes'],
            ],
            'installer_authorization' => $grant,
        ];
    }

    /** @return array{storage_reference:string,sha256:string,size_bytes:int,file_name:string} */
    public function consumeInstallerGrant(string $token): array
    {
        $hash = hash('sha256', $this->grantToken($token));
        return $this->database->transaction(function (PDO $pdo) use ($hash): array {
            $query = $pdo->prepare(
                "SELECT g.*,a.storage_reference,a.sha256,a.size_bytes,r.version
                 FROM homeserver_installer_grants g
                 JOIN release_artifacts a ON a.id=g.artifact_id
                 JOIN software_releases r ON r.id=g.release_id
                 JOIN homeserver_devices d ON d.id=g.device_id
                 JOIN licenses l ON l.id=d.license_id
                 JOIN subscriptions s ON s.id=d.subscription_id
                 WHERE g.token_hash=:hash LIMIT 1 FOR UPDATE"
            );
            $query->execute(['hash' => $hash]);
            $grant = $query->fetch(PDO::FETCH_ASSOC);
            if (!is_array($grant)) {
                throw new RuntimeException('Installer authorization was not found.');
            }
            if ($grant['status'] !== 'active' || strtotime((string) $grant['expires_at'] . ' UTC') <= time()) {
                $pdo->prepare("UPDATE homeserver_installer_grants SET status='expired' WHERE id=:id AND status='active'")
                    ->execute(['id' => $grant['id']]);
                throw new RuntimeException('Installer authorization has expired or was revoked.');
            }
            if ((int) $grant['use_count'] >= (int) $grant['max_uses']) {
                throw new RuntimeException('Installer authorization has already been consumed.');
            }
            $nextUse = (int) $grant['use_count'] + 1;
            $nextStatus = $nextUse >= (int) $grant['max_uses'] ? 'consumed' : 'active';
            $pdo->prepare(
                'UPDATE homeserver_installer_grants SET use_count=:uses,status=:status,last_used_at=UTC_TIMESTAMP(),
                 consumed_at=IF(:status_value=\'consumed\',UTC_TIMESTAMP(),consumed_at) WHERE id=:id'
            )->execute([
                'uses' => $nextUse,
                'status' => $nextStatus,
                'status_value' => $nextStatus,
                'id' => $grant['id'],
            ]);
            return [
                'storage_reference' => (string) $grant['storage_reference'],
                'sha256' => (string) $grant['sha256'],
                'size_bytes' => (int) $grant['size_bytes'],
                'file_name' => 'VP3-HomeServer-' . preg_replace('/[^A-Za-z0-9._-]/', '-', (string) $grant['version']) . '.exe',
            ];
        });
    }

    /** @param array<string,mixed> $metadata @return array{receipt_public_id:string,replayed:bool} */
    public function recordUpdateReceipt(
        string $devicePublicId,
        string $credential,
        string $requestId,
        string $updateId,
        ?string $releasePublicId,
        string $disposition,
        ?string $failureCode,
        ?string $receiptHash,
        array $metadata
    ): array {
        $device = $this->authenticateDevice($devicePublicId, $credential, false);
        $allowed = ['downloaded', 'staged', 'installed', 'rolled_back', 'failed'];
        if (!in_array($disposition, $allowed, true)) {
            throw new RuntimeException('Update receipt disposition is invalid.');
        }
        if ($receiptHash !== null && !preg_match('/^[a-f0-9]{64}$/', strtolower($receiptHash))) {
            throw new RuntimeException('Update receipt hash is invalid.');
        }
        return $this->database->transaction(function (PDO $pdo) use (
            $device, $requestId, $updateId, $releasePublicId, $disposition, $failureCode, $receiptHash, $metadata
        ): array {
            $existing = $pdo->prepare('SELECT public_id FROM homeserver_update_receipts_v1 WHERE device_id=:device AND request_id=:request LIMIT 1');
            $existing->execute(['device' => $device['id'], 'request' => $requestId]);
            $public = $existing->fetchColumn();
            if (is_string($public) && $public !== '') {
                return ['receipt_public_id' => $public, 'replayed' => true];
            }
            $releaseId = null;
            if ($releasePublicId !== null && trim($releasePublicId) !== '') {
                $release = $pdo->prepare('SELECT id FROM software_releases WHERE public_id=:public LIMIT 1');
                $release->execute(['public' => trim($releasePublicId)]);
                $releaseId = $release->fetchColumn();
                if ($releaseId === false) {
                    throw new RuntimeException('Software release was not found.');
                }
            }
            $public = 'HSR-' . strtoupper(bin2hex(random_bytes(12)));
            $pdo->prepare(
                'INSERT INTO homeserver_update_receipts_v1
                 (public_id,account_id,device_id,release_id,request_id,update_id,disposition,failure_code,receipt_hash,metadata_hash,created_at)
                 VALUES (:public,:account,:device,:release,:request,:update_id,:disposition,:failure,:receipt,:metadata,UTC_TIMESTAMP())'
            )->execute([
                'public' => $public,
                'account' => $device['account_id'],
                'device' => $device['id'],
                'release' => $releaseId === false ? null : $releaseId,
                'request' => $requestId,
                'update_id' => substr(trim($updateId), 0, 128),
                'disposition' => $disposition,
                'failure' => $failureCode === null ? null : substr(trim($failureCode), 0, 100),
                'receipt' => $receiptHash === null ? null : strtolower($receiptHash),
                'metadata' => $metadata === [] ? null : hash('sha256', $this->canonicalJson($metadata)),
            ]);
            return ['receipt_public_id' => $public, 'replayed' => false];
        });
    }

    public function setSuspended(int $accountId, string $devicePublicId, bool $suspended, string $requestId): void
    {
        $this->database->transaction(function (PDO $pdo) use ($accountId, $devicePublicId, $suspended, $requestId): void {
            $device = $this->ownedDevice($pdo, $accountId, $devicePublicId, true);
            if ($device['status'] === 'revoked') {
                throw new RuntimeException('Revoked HomeServer devices cannot be changed.');
            }
            $status = $suspended ? 'suspended' : 'paired';
            $pdo->prepare(
                'UPDATE homeserver_devices SET status=:status,suspended_at=:suspended,updated_at=UTC_TIMESTAMP() WHERE id=:id'
            )->execute([
                'status' => $status,
                'suspended' => $suspended ? gmdate('Y-m-d H:i:s') : null,
                'id' => $device['id'],
            ]);
            if ($suspended) {
                $this->revokeSoftwareAuthority($pdo, (int) $device['id']);
            }
            $this->event($accountId, (int) $device['id'], $requestId, $suspended ? 'device_suspended' : 'device_resumed', 'success', null, $pdo);
        });
    }

    public function revokeDevice(int $accountId, string $devicePublicId, string $requestId): void
    {
        $this->registry->revokeDevice($accountId, $devicePublicId, $requestId);
        $pdo = $this->database->pdo();
        $device = $this->ownedDevice($pdo, $accountId, $devicePublicId, false);
        $pdo->prepare("UPDATE homeserver_installer_grants SET status='revoked',revoked_at=UTC_TIMESTAMP() WHERE device_id=:device AND status='active'")
            ->execute(['device' => $device['id']]);
    }

    /** @return array<string,mixed> */
    public function replaceDevice(
        int $accountId,
        string $oldDevicePublicId,
        string $newFingerprint,
        string $requestId,
        string $idempotencyKey
    ): array {
        $pdo = $this->database->pdo();
        $old = $this->ownedDevice($pdo, $accountId, $oldDevicePublicId, false);
        if ($old['status'] === 'revoked') {
            throw new RuntimeException('The previous HomeServer device is already revoked.');
        }
        $duplicate = $pdo->prepare("SELECT id FROM homeserver_devices WHERE device_fingerprint=:fingerprint AND status<>'revoked' LIMIT 1");
        $duplicate->execute(['fingerprint' => strtolower(trim($newFingerprint))]);
        if ($duplicate->fetchColumn()) {
            throw new RuntimeException('The replacement HomeServer fingerprint is already registered.');
        }
        $this->revokeDevice($accountId, $oldDevicePublicId, $requestId . '-REVOKE');
        $registered = $this->registry->registerDevice(
            $accountId,
            (int) $old['license_id'],
            $newFingerprint,
            $requestId,
            $idempotencyKey
        );
        $this->event($accountId, (int) $registered['device_id'], $requestId, 'device_replaced', 'success', ['previous_device_public_id' => $oldDevicePublicId]);
        return $registered + ['previous_device_public_id' => $oldDevicePublicId];
    }

    /** @return array{transfer_public_id:string,transfer_code:string,expires_at:string} */
    public function requestTransfer(
        int $sourceAccountId,
        string $devicePublicId,
        int $targetAccountId,
        string $requestId
    ): array {
        if ($targetAccountId < 1 || $targetAccountId === $sourceAccountId) {
            throw new RuntimeException('A different target VP3 account is required.');
        }
        return $this->database->transaction(function (PDO $pdo) use ($sourceAccountId, $devicePublicId, $targetAccountId, $requestId): array {
            $device = $this->ownedDevice($pdo, $sourceAccountId, $devicePublicId, true);
            $target = $pdo->prepare("SELECT id FROM accounts WHERE id=:id AND status='active' LIMIT 1");
            $target->execute(['id' => $targetAccountId]);
            if (!$target->fetchColumn()) {
                throw new RuntimeException('The target VP3 account was not found or is inactive.');
            }
            $pdo->prepare("UPDATE homeserver_transfer_requests SET status='canceled',canceled_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE device_id=:device AND status='pending'")
                ->execute(['device' => $device['id']]);
            $code = strtoupper(substr(bin2hex(random_bytes(16)), 0, 24));
            $public = 'HST-' . strtoupper(bin2hex(random_bytes(12)));
            $expires = gmdate('Y-m-d H:i:s', time() + max(300, $this->transferTtlSeconds));
            $pdo->prepare(
                'INSERT INTO homeserver_transfer_requests
                 (public_id,device_id,source_account_id,target_account_id,transfer_code_hash,status,expires_at,created_at,updated_at)
                 VALUES (:public,:device,:source,:target,:hash,\'pending\',:expires,UTC_TIMESTAMP(),UTC_TIMESTAMP())'
            )->execute([
                'public' => $public,
                'device' => $device['id'],
                'source' => $sourceAccountId,
                'target' => $targetAccountId,
                'hash' => hash('sha256', $code),
                'expires' => $expires,
            ]);
            $this->event($sourceAccountId, (int) $device['id'], $requestId, 'transfer_requested', 'success', ['target_account_id' => $targetAccountId], $pdo);
            return ['transfer_public_id' => $public, 'transfer_code' => $code, 'expires_at' => $expires];
        });
    }

    /** @return array{device_public_id:string,credential:string,enrollment_code:string,license_id:int} */
    public function acceptTransfer(
        int $targetAccountId,
        string $transferCode,
        int $targetLicenseId,
        string $requestId
    ): array {
        return $this->database->transaction(function (PDO $pdo) use ($targetAccountId, $transferCode, $targetLicenseId, $requestId): array {
            $transfer = $pdo->prepare(
                "SELECT t.*,d.public_id device_public_id FROM homeserver_transfer_requests t
                 JOIN homeserver_devices d ON d.id=t.device_id
                 WHERE t.target_account_id=:account AND t.transfer_code_hash=:hash AND t.status='pending'
                   AND t.expires_at>UTC_TIMESTAMP() LIMIT 1 FOR UPDATE"
            );
            $transfer->execute(['account' => $targetAccountId, 'hash' => hash('sha256', strtoupper(trim($transferCode)))]);
            $row = $transfer->fetch(PDO::FETCH_ASSOC);
            if (!is_array($row)) {
                throw new RuntimeException('The HomeServer transfer request was not found or has expired.');
            }
            $license = $pdo->prepare(
                "SELECT l.id,l.subscription_id,l.domain_registration_id FROM licenses l
                 JOIN subscriptions s ON s.id=l.subscription_id AND s.account_id=l.account_id
                 WHERE l.id=:license AND l.account_id=:account AND l.product_type='homeserver'
                   AND l.status IN ('active','grace') AND s.status IN ('active','trialing','grace') LIMIT 1 FOR UPDATE"
            );
            $license->execute(['license' => $targetLicenseId, 'account' => $targetAccountId]);
            $target = $license->fetch(PDO::FETCH_ASSOC);
            if (!is_array($target)) {
                throw new RuntimeException('The target HomeServer license is not eligible.');
            }
            $occupied = $pdo->prepare("SELECT id FROM homeserver_devices WHERE license_id=:license AND status<>'revoked' LIMIT 1 FOR UPDATE");
            $occupied->execute(['license' => $targetLicenseId]);
            if ($occupied->fetchColumn()) {
                throw new RuntimeException('The target HomeServer license already has an active device.');
            }
            $credential = $this->secret(32);
            $enrollmentCode = strtoupper(substr(bin2hex(random_bytes(8)), 0, 12));
            $this->revokeDeviceAuthority($pdo, (int) $row['device_id']);
            $pdo->prepare(
                "UPDATE homeserver_devices SET account_id=:account,subscription_id=:subscription,
                 domain_registration_id=:domain,license_id=:license,credential_hash=:credential,
                 credential_version=credential_version+1,status='pending_pairing',pairing_status='code_issued',
                 paired_frontend_count=0,paired_at=NULL,suspended_at=NULL,revoked_at=NULL,updated_at=UTC_TIMESTAMP()
                 WHERE id=:device"
            )->execute([
                'account' => $targetAccountId,
                'subscription' => $target['subscription_id'],
                'domain' => $target['domain_registration_id'],
                'license' => $targetLicenseId,
                'credential' => hash('sha256', $credential),
                'device' => $row['device_id'],
            ]);
            $pdo->prepare(
                "INSERT INTO homeserver_pairing_codes
                 (public_id,device_id,account_id,code_hash,purpose,status,expires_at,created_at)
                 VALUES (:public,:device,:account,:hash,'device_enrollment','active',DATE_ADD(UTC_TIMESTAMP(),INTERVAL 15 MINUTE),UTC_TIMESTAMP())"
            )->execute([
                'public' => 'HSP-' . strtoupper(bin2hex(random_bytes(12))),
                'device' => $row['device_id'],
                'account' => $targetAccountId,
                'hash' => hash('sha256', $enrollmentCode),
            ]);
            $pdo->prepare("UPDATE homeserver_transfer_requests SET status='accepted',accepted_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE id=:id")
                ->execute(['id' => $row['id']]);
            $this->event($targetAccountId, (int) $row['device_id'], $requestId, 'transfer_accepted', 'success', ['source_account_id' => (int) $row['source_account_id']], $pdo);
            return [
                'device_public_id' => (string) $row['device_public_id'],
                'credential' => $credential,
                'enrollment_code' => $enrollmentCode,
                'license_id' => $targetLicenseId,
            ];
        });
    }

    /** @return array<string,mixed> */
    private function authenticateDevice(string $publicId, string $credential, bool $lock): array
    {
        $query = $this->database->pdo()->prepare(
            "SELECT d.*,l.public_id license_public_id,l.status license_status,s.status subscription_status
             FROM homeserver_devices d
             JOIN licenses l ON l.id=d.license_id AND l.account_id=d.account_id
             JOIN subscriptions s ON s.id=d.subscription_id AND s.account_id=d.account_id
             WHERE d.public_id=:public LIMIT 1" . ($lock ? ' FOR UPDATE' : '')
        );
        $query->execute(['public' => trim($publicId)]);
        $device = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($device) || $credential === '' || !hash_equals((string) ($device['credential_hash'] ?? ''), hash('sha256', $credential))) {
            throw new RuntimeException('HomeServer device credential is invalid.');
        }
        if (in_array($device['status'], ['suspended', 'revoked'], true)) {
            throw new RuntimeException('HomeServer device is suspended or revoked.');
        }
        if (!in_array($device['license_status'], ['active', 'grace'], true)
            || !in_array($device['subscription_status'], ['active', 'trialing', 'grace'], true)) {
            throw new RuntimeException('HomeServer license is not eligible.');
        }
        return $device;
    }

    /** @return array<string,mixed> */
    private function ownedDevice(PDO $pdo, int $accountId, string $publicId, bool $lock): array
    {
        $query = $pdo->prepare('SELECT * FROM homeserver_devices WHERE account_id=:account AND public_id=:public LIMIT 1' . ($lock ? ' FOR UPDATE' : ''));
        $query->execute(['account' => $accountId, 'public' => trim($publicId)]);
        $device = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($device)) {
            throw new RuntimeException('HomeServer device was not found for this account.');
        }
        return $device;
    }

    /** @param array<string,mixed> $device @param array<string,mixed> $release @return array<string,mixed> */
    private function issueInstallerGrant(array $device, array $release): array
    {
        return $this->database->transaction(function (PDO $pdo) use ($device, $release): array {
            $pdo->prepare("UPDATE homeserver_installer_grants SET status='revoked',revoked_at=UTC_TIMESTAMP() WHERE device_id=:device AND release_id=:release AND status='active'")
                ->execute(['device' => $device['id'], 'release' => $release['release_id']]);
            $token = $this->secret(32);
            $public = 'HSG-' . strtoupper(bin2hex(random_bytes(12)));
            $expires = gmdate('Y-m-d H:i:s', time() + max(120, $this->installerGrantTtlSeconds));
            $pdo->prepare(
                'INSERT INTO homeserver_installer_grants
                 (public_id,account_id,device_id,release_id,artifact_id,token_hash,status,max_uses,use_count,expires_at,created_at)
                 VALUES (:public,:account,:device,:release,:artifact,:hash,\'active\',3,0,:expires,UTC_TIMESTAMP())'
            )->execute([
                'public' => $public,
                'account' => $device['account_id'],
                'device' => $device['id'],
                'release' => $release['release_id'],
                'artifact' => $release['artifact_id'],
                'hash' => hash('sha256', $token),
                'expires' => $expires,
            ]);
            return [
                'grant_public_id' => $public,
                'token' => $token,
                'expires_at' => $expires,
                'download_path' => '/api/homeserver/v1/installer-download.php?grant=' . rawurlencode($token),
            ];
        });
    }

    private function revokeSoftwareAuthority(PDO $pdo, int $deviceId): void
    {
        $pdo->prepare("UPDATE homeserver_entitlement_leases SET status='revoked',revoked_at=UTC_TIMESTAMP() WHERE device_id=:device AND status='active'")
            ->execute(['device' => $deviceId]);
        $pdo->prepare("UPDATE homeserver_installer_grants SET status='revoked',revoked_at=UTC_TIMESTAMP() WHERE device_id=:device AND status='active'")
            ->execute(['device' => $deviceId]);
    }

    private function revokeDeviceAuthority(PDO $pdo, int $deviceId): void
    {
        $pdo->prepare("UPDATE homeserver_entitlement_leases SET status='revoked',revoked_at=UTC_TIMESTAMP() WHERE device_id=:device AND status='active'")
            ->execute(['device' => $deviceId]);
        $pdo->prepare("UPDATE homeserver_installer_grants SET status='revoked',revoked_at=UTC_TIMESTAMP() WHERE device_id=:device AND status='active'")
            ->execute(['device' => $deviceId]);
        $pdo->prepare("UPDATE homeserver_frontend_pairs SET status='revoked',revoked_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE device_id=:device AND status='active'")
            ->execute(['device' => $deviceId]);
        $pdo->prepare("UPDATE homeserver_pairing_codes SET status='revoked',revoked_at=UTC_TIMESTAMP() WHERE device_id=:device AND status='active'")
            ->execute(['device' => $deviceId]);
    }

    /** @param array<string,mixed> $release */
    private function compatible(string $currentVersion, array $release): bool
    {
        $minimum = trim((string) ($release['minimum_current_version'] ?? ''));
        $maximum = trim((string) ($release['maximum_current_version'] ?? ''));
        return ($minimum === '' || version_compare($currentVersion, $minimum, '>='))
            && ($maximum === '' || version_compare($currentVersion, $maximum, '<='));
    }

    private function inRollout(string $devicePublicId, string $seed, int $percentage): bool
    {
        if ($percentage <= 0) {
            return false;
        }
        if ($percentage >= 100) {
            return true;
        }
        $bucket = hexdec(substr(hash('sha256', $seed . ':' . $devicePublicId), 0, 8)) % 100;
        return $bucket < $percentage;
    }

    private function version(string $value): string
    {
        $value = trim($value);
        if (!preg_match('/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$/', $value)) {
            throw new RuntimeException('HomeServer version is invalid.');
        }
        return $value;
    }

    private function targetPart(string $value, string $label): string
    {
        $value = strtolower(trim($value));
        if (!preg_match('/^[a-z0-9._-]{2,80}$/', $value)) {
            throw new RuntimeException('HomeServer ' . $label . ' is invalid.');
        }
        return $value;
    }

    private function grantToken(string $token): string
    {
        $token = trim($token);
        if (!preg_match('/^[A-Za-z0-9_-]{32,256}$/', $token)) {
            throw new RuntimeException('Installer authorization is invalid.');
        }
        return $token;
    }

    private function secret(int $bytes): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }

    /** @param array<string,mixed>|null $metadata */
    private function event(
        int $accountId,
        ?int $deviceId,
        string $requestId,
        string $type,
        string $result,
        ?array $metadata,
        ?PDO $pdo = null
    ): void {
        $pdo ??= $this->database->pdo();
        $pdo->prepare(
            'INSERT INTO homeserver_control_plane_events
             (account_id,device_id,request_id,event_type,result,metadata_hash,created_at)
             VALUES (:account,:device,:request,:type,:result,:metadata,UTC_TIMESTAMP())'
        )->execute([
            'account' => $accountId,
            'device' => $deviceId,
            'request' => substr(trim($requestId), 0, 64),
            'type' => substr(trim($type), 0, 100),
            'result' => $result,
            'metadata' => $metadata === null ? null : hash('sha256', $this->canonicalJson($metadata)),
        ]);
    }

    /** @param array<string,mixed> $value */
    private function canonicalJson(array $value): string
    {
        ksort($value);
        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }
}
