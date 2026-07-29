<?php

declare(strict_types=1);

namespace Vp3\Deployments;

use PDO;
use RuntimeException;
use Vp3\Database;

final class PodHealthService
{
    public function __construct(private readonly Database $database)
    {
    }

    /** @param array<string,mixed> $health @return array{deployment_id:int,status:string,last_heartbeat_at:string} */
    public function heartbeat(int $accountId, string $deploymentPublicId, string $fingerprint, array $health, string $requestId): array
    {
        if ($accountId < 1 || trim($deploymentPublicId) === '' || !preg_match('/^[a-f0-9]{64}$/', $fingerprint) || trim($requestId) === '') {
            throw new RuntimeException('Account, deployment identity, fingerprint, and request ID are required.');
        }
        return $this->database->transaction(function (PDO $pdo) use ($accountId, $deploymentPublicId, $fingerprint, $health, $requestId): array {
            $statement = $pdo->prepare(
                'SELECT id, status, storage_allowance_bytes FROM pod_deployments
                 WHERE public_id=:public_id AND account_id=:account_id AND installation_fingerprint=:fingerprint
                 LIMIT 1 FOR UPDATE'
            );
            $statement->execute([
                'public_id' => $deploymentPublicId,
                'account_id' => $accountId,
                'fingerprint' => strtolower($fingerprint),
            ]);
            $deployment = $statement->fetch(PDO::FETCH_ASSOC);
            if (!is_array($deployment)) {
                throw new RuntimeException('Heartbeat identity does not match an account-owned POD deployment.');
            }
            $usage = max(0, (int) ($health['storage_usage_bytes'] ?? 0));
            $allowance = max(0, (int) $deployment['storage_allowance_bytes']);
            $routing = $this->status($health['routing_status'] ?? 'active', ['pending', 'active', 'degraded', 'disabled'], 'routing');
            $ssl = $this->status($health['ssl_status'] ?? 'active', ['pending', 'active', 'renewing', 'failed', 'disabled'], 'SSL');
            $backup = $this->status($health['backup_status'] ?? 'unknown', ['unknown', 'pending', 'verified', 'failed', 'disabled'], 'backup');
            $license = $this->status($health['license_status'] ?? 'active', ['pending', 'active', 'grace', 'suspended', 'expired', 'terminated'], 'license');
            $status = ($routing === 'active' && in_array($ssl, ['active', 'renewing'], true) && !in_array($license, ['suspended', 'expired', 'terminated'], true))
                ? 'active'
                : 'degraded';
            if ($allowance > 0 && $usage > $allowance) {
                $status = 'degraded';
            }
            $pdo->prepare(
                'UPDATE pod_deployments SET status=:status, storage_usage_bytes=:usage, routing_status=:routing,
                 ssl_status=:ssl, backup_status=:backup, license_status=:license,
                 installed_version=COALESCE(:version, installed_version), last_heartbeat_at=UTC_TIMESTAMP(), updated_at=UTC_TIMESTAMP()
                 WHERE id=:id'
            )->execute([
                'status' => $status,
                'usage' => $usage,
                'routing' => $routing,
                'ssl' => $ssl,
                'backup' => $backup,
                'license' => $license,
                'version' => isset($health['installed_version']) && is_string($health['installed_version']) ? substr(trim($health['installed_version']), 0, 80) : null,
                'id' => $deployment['id'],
            ]);
            $pdo->prepare(
                'INSERT INTO pod_deployment_events
                 (deployment_id, account_id, request_id, event_type, result, from_status, to_status, metadata_json, created_at)
                 VALUES (:deployment_id, :account_id, :request_id, :event_type, :result, :from_status, :to_status, :metadata_json, UTC_TIMESTAMP())'
            )->execute([
                'deployment_id' => $deployment['id'],
                'account_id' => $accountId,
                'request_id' => $requestId,
                'event_type' => 'heartbeat_received',
                'result' => 'success',
                'from_status' => $deployment['status'],
                'to_status' => $status,
                'metadata_json' => json_encode([
                    'storage_usage_bytes' => $usage,
                    'routing_status' => $routing,
                    'ssl_status' => $ssl,
                    'backup_status' => $backup,
                    'license_status' => $license,
                ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            ]);
            $time = (string) $pdo->query('SELECT UTC_TIMESTAMP()')->fetchColumn();
            return ['deployment_id' => (int) $deployment['id'], 'status' => $status, 'last_heartbeat_at' => $time];
        });
    }

    /** @param list<string> $allowed */
    private function status(mixed $value, array $allowed, string $name): string
    {
        $status = is_string($value) ? strtolower(trim($value)) : '';
        if (!in_array($status, $allowed, true)) {
            throw new RuntimeException('Invalid ' . $name . ' status.');
        }
        return $status;
    }
}
