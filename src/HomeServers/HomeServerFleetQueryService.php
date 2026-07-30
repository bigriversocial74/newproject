<?php

declare(strict_types=1);

namespace Vp3\HomeServers;

use PDO;
use RuntimeException;
use Vp3\Database;

final class HomeServerFleetQueryService
{
    public function __construct(private readonly Database $database)
    {
    }

    /**
     * @return array{
     *   account_id:int,
     *   summary:array{total:int,active:int,online:int,attention:int,pending_pairing:int,suspended:int,revoked:int},
     *   devices:list<array<string,mixed>>
     * }
     */
    public function snapshot(int $accountId): array
    {
        if ($accountId < 1) {
            throw new RuntimeException('A valid VP3 account is required.');
        }

        $statement = $this->database->pdo()->prepare(
            "SELECT d.id,d.public_id,d.license_id,d.domain_registration_id,d.status,d.pairing_status,
                    d.software_version,d.mcp_version,d.update_channel,d.frontend_limit,d.paired_frontend_count,
                    d.last_heartbeat_at,d.paired_at,d.suspended_at,d.revoked_at,d.created_at,d.updated_at,
                    l.public_id AS license_public_id,
                    lease.public_id AS lease_public_id,lease.status AS lease_status,
                    lease.issued_at AS lease_issued_at,lease.expires_at AS lease_expires_at,
                    lease.signing_key_id AS lease_signing_key_id,
                    receipt.disposition AS last_update_disposition,
                    receipt.failure_code AS last_update_failure_code,
                    receipt.created_at AS last_update_receipt_at,
                    COALESCE(event_counts.event_count_24h,0) AS event_count_24h
             FROM homeserver_devices d
             JOIN licenses l ON l.id=d.license_id
             LEFT JOIN homeserver_entitlement_leases lease ON lease.id=(
                 SELECT el.id FROM homeserver_entitlement_leases el
                 WHERE el.device_id=d.id
                 ORDER BY el.issued_at DESC,el.id DESC LIMIT 1
             )
             LEFT JOIN homeserver_update_receipts_v1 receipt ON receipt.id=(
                 SELECT ur.id FROM homeserver_update_receipts_v1 ur
                 WHERE ur.device_id=d.id
                 ORDER BY ur.created_at DESC,ur.id DESC LIMIT 1
             )
             LEFT JOIN (
                 SELECT device_id,COUNT(*) AS event_count_24h
                 FROM homeserver_control_plane_events
                 WHERE created_at>=UTC_TIMESTAMP()-INTERVAL 24 HOUR
                 GROUP BY device_id
             ) event_counts ON event_counts.device_id=d.id
             WHERE d.account_id=:account
             ORDER BY COALESCE(d.last_heartbeat_at,d.created_at) DESC,d.id DESC"
        );
        $statement->execute(['account' => $accountId]);

        $summary = [
            'total' => 0,
            'active' => 0,
            'online' => 0,
            'attention' => 0,
            'pending_pairing' => 0,
            'suspended' => 0,
            'revoked' => 0,
        ];
        $devices = [];

        foreach ($statement->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $status = (string) $row['status'];
            $summary['total']++;
            if (!in_array($status, ['suspended', 'revoked'], true)) {
                $summary['active']++;
            }
            if (in_array($status, ['online', 'degraded'], true)) {
                $summary['online']++;
            }
            if (in_array($status, ['offline', 'degraded', 'suspended', 'revoked'], true)) {
                $summary['attention']++;
            }
            if ($status === 'pending_pairing') {
                $summary['pending_pairing']++;
            }
            if ($status === 'suspended') {
                $summary['suspended']++;
            }
            if ($status === 'revoked') {
                $summary['revoked']++;
            }

            $devices[] = [
                'device_public_id' => (string) $row['public_id'],
                'license_id' => (int) $row['license_id'],
                'license_public_id' => (string) $row['license_public_id'],
                'domain_registration_id' => (int) $row['domain_registration_id'],
                'status' => $status,
                'pairing_status' => (string) $row['pairing_status'],
                'software_version' => $row['software_version'] !== null ? (string) $row['software_version'] : null,
                'mcp_version' => $row['mcp_version'] !== null ? (string) $row['mcp_version'] : null,
                'update_channel' => (string) $row['update_channel'],
                'frontend_limit' => (int) $row['frontend_limit'],
                'paired_frontend_count' => (int) $row['paired_frontend_count'],
                'last_heartbeat_at' => $row['last_heartbeat_at'] !== null ? (string) $row['last_heartbeat_at'] : null,
                'paired_at' => $row['paired_at'] !== null ? (string) $row['paired_at'] : null,
                'suspended_at' => $row['suspended_at'] !== null ? (string) $row['suspended_at'] : null,
                'revoked_at' => $row['revoked_at'] !== null ? (string) $row['revoked_at'] : null,
                'created_at' => (string) $row['created_at'],
                'updated_at' => (string) $row['updated_at'],
                'lease' => $row['lease_public_id'] === null ? null : [
                    'public_id' => (string) $row['lease_public_id'],
                    'status' => (string) $row['lease_status'],
                    'issued_at' => (string) $row['lease_issued_at'],
                    'expires_at' => (string) $row['lease_expires_at'],
                    'signing_key_id' => (string) $row['lease_signing_key_id'],
                ],
                'last_update_receipt' => $row['last_update_disposition'] === null ? null : [
                    'disposition' => (string) $row['last_update_disposition'],
                    'failure_code' => $row['last_update_failure_code'] !== null ? (string) $row['last_update_failure_code'] : null,
                    'created_at' => (string) $row['last_update_receipt_at'],
                ],
                'event_count_24h' => (int) $row['event_count_24h'],
            ];
        }

        return [
            'account_id' => $accountId,
            'summary' => $summary,
            'devices' => $devices,
        ];
    }
}
