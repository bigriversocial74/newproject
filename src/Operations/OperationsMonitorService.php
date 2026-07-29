<?php

declare(strict_types=1);

namespace Vp3\Operations;

use PDO;
use RuntimeException;
use Throwable;
use Vp3\Database;

final class OperationsMonitorService
{
    public function __construct(
        private readonly Database $database,
        private readonly OperationalIncidentService $incidents,
        private readonly OperationalAuditService $audit,
        private readonly int $podOfflineAfterMinutes = 10,
        private readonly int $homeServerOfflineAfterMinutes = 10
    ) {
        if ($this->podOfflineAfterMinutes < 1 || $this->homeServerOfflineAfterMinutes < 1) {
            throw new RuntimeException('Operational heartbeat thresholds must be positive.');
        }
    }

    /** @param array<string,mixed> $evidence */
    public function recordHealthSignal(
        int $accountScope,
        string $sourceType,
        int $sourceId,
        bool $healthy,
        string $severity,
        array $evidence,
        string $requestId
    ): void {
        $sourceType = strtolower(trim($sourceType));
        $severity = strtolower(trim($severity));
        if ($accountScope < 0 || $sourceType === '' || $sourceId < 0
            || !in_array($severity, ['info', 'warning', 'critical'], true) || trim($requestId) === '') {
            throw new RuntimeException('A valid operational health signal is required.');
        }
        $this->database->transaction(function (PDO $pdo) use (
            $accountScope, $sourceType, $sourceId, $healthy, $severity, $evidence, $requestId
        ): void {
            $prior = $pdo->prepare(
                "SELECT id FROM operational_request_receipts
                 WHERE account_scope=:account AND request_id=:request AND operation='health_signal_record' LIMIT 1"
            );
            $prior->execute(['account' => $accountScope, 'request' => $requestId]);
            if ($prior->fetchColumn() !== false) {
                return;
            }
            $evidenceHash = hash('sha256', json_encode($evidence, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
            $now = gmdate('Y-m-d H:i:s');
            $pdo->prepare(
                "INSERT INTO operational_health_signals
                 (account_scope,source_type,source_id,health_status,severity,evidence_hash,observed_at,created_at,updated_at)
                 VALUES (:account,:source_type,:source_id,:health_status,:severity,:evidence,:observed,:created,:updated)
                 ON DUPLICATE KEY UPDATE health_status=VALUES(health_status),severity=VALUES(severity),
                    evidence_hash=VALUES(evidence_hash),observed_at=VALUES(observed_at),updated_at=VALUES(updated_at)"
            )->execute([
                'account' => $accountScope,
                'source_type' => $sourceType,
                'source_id' => $sourceId,
                'health_status' => $healthy ? 'healthy' : 'unhealthy',
                'severity' => $severity,
                'evidence' => $evidenceHash,
                'observed' => $now,
                'created' => $now,
                'updated' => $now,
            ]);
            $lookup = $pdo->prepare(
                'SELECT id FROM operational_health_signals
                 WHERE account_scope=:account AND source_type=:source_type AND source_id=:source_id LIMIT 1'
            );
            $lookup->execute(['account' => $accountScope, 'source_type' => $sourceType, 'source_id' => $sourceId]);
            $signalId = (int) $lookup->fetchColumn();
            $receiptHash = hash('sha256', implode('|', [
                $accountScope,
                $sourceType,
                $sourceId,
                $healthy ? 'healthy' : 'unhealthy',
                $evidenceHash,
            ]));
            $pdo->prepare(
                "INSERT INTO operational_request_receipts
                 (account_scope,request_id,operation,result,resource_type,resource_id,receipt_hash,created_at)
                 VALUES (:account,:request,'health_signal_record','success','health_signal',:resource,:receipt,UTC_TIMESTAMP())"
            )->execute([
                'account' => $accountScope,
                'request' => substr(trim($requestId), 0, 80),
                'resource' => $signalId,
                'receipt' => $receiptHash,
            ]);
            $this->audit->appendWithPdo(
                $pdo,
                'health_signal',
                $signalId,
                $healthy ? 'healthy' : 'unhealthy',
                'system',
                0,
                $receiptHash
            );
        });
    }

    /** @return array{run_id:int,public_id:string,checked:int,opened:int,resolved:int} */
    public function run(string $workerId): array
    {
        $workerId = trim($workerId);
        if ($workerId === '') {
            throw new RuntimeException('An operational monitor worker ID is required.');
        }
        $pdo = $this->database->pdo();
        $publicId = 'OPS-MON-' . strtoupper(bin2hex(random_bytes(10)));
        $pdo->prepare(
            "INSERT INTO operational_monitor_runs (public_id,worker_id,status,started_at)
             VALUES (:public,:worker,'running',UTC_TIMESTAMP())"
        )->execute(['public' => $publicId, 'worker' => substr($workerId, 0, 128)]);
        $runId = (int) $pdo->lastInsertId();
        $seen = [];
        $checked = 0;
        $opened = 0;

        try {
            foreach ($this->detections() as $detection) {
                $checked++;
                $incident = $this->incidents->open(
                    (int) $detection['account_scope'],
                    (string) $detection['source_type'],
                    (int) $detection['source_id'],
                    (string) $detection['severity'],
                    (string) $detection['title'],
                    (array) $detection['evidence'],
                    true
                );
                $seen[(string) $incident['incident_key']] = true;
                if ($incident['created']) {
                    $opened++;
                }
            }
            $resolved = $this->resolveRecovered($seen);
            $evidenceHash = hash('sha256', $checked . '|' . $opened . '|' . $resolved . '|' . implode('|', array_keys($seen)));
            $pdo->prepare(
                "UPDATE operational_monitor_runs
                 SET status='completed',checked_count=:checked,opened_count=:opened,resolved_count=:resolved,
                     evidence_hash=:evidence,completed_at=UTC_TIMESTAMP() WHERE id=:id"
            )->execute([
                'checked' => $checked,
                'opened' => $opened,
                'resolved' => $resolved,
                'evidence' => $evidenceHash,
                'id' => $runId,
            ]);
            $this->audit->append('monitor_run', $runId, 'completed', 'worker', 0, $evidenceHash);
            return ['run_id' => $runId, 'public_id' => $publicId, 'checked' => $checked, 'opened' => $opened, 'resolved' => $resolved];
        } catch (Throwable $exception) {
            $errorHash = hash('sha256', $exception::class . '|' . $exception->getMessage());
            $pdo->prepare(
                "UPDATE operational_monitor_runs
                 SET status='failed',evidence_hash=:evidence,completed_at=UTC_TIMESTAMP() WHERE id=:id"
            )->execute(['evidence' => $errorHash, 'id' => $runId]);
            $this->audit->append('monitor_run', $runId, 'failed', 'worker', 0, $errorHash);
            throw $exception;
        }
    }

    /** @return list<array{account_scope:int,source_type:string,source_id:int,severity:string,title:string,evidence:array<string,mixed>}> */
    private function detections(): array
    {
        $detections = [];
        $pdo = $this->database->pdo();
        foreach ($pdo->query("SELECT * FROM operational_health_signals WHERE health_status='unhealthy'")->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $detections[] = $this->detection(
                (int) $row['account_scope'],
                'health_signal',
                (int) $row['id'],
                (string) $row['severity'],
                'Operational health signal is unhealthy',
                [
                    'signal_source_type' => $row['source_type'],
                    'signal_source_id' => (int) $row['source_id'],
                    'evidence_hash' => $row['evidence_hash'],
                ]
            );
        }
        foreach ($pdo->query(
            "SELECT * FROM pod_deployments WHERE status IN ('active','degraded','suspended')"
        )->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $accountId = (int) $row['account_id'];
            $deploymentId = (int) $row['id'];
            if ($row['last_heartbeat_at'] === null
                || strtotime((string) $row['last_heartbeat_at']) < time() - ($this->podOfflineAfterMinutes * 60)) {
                $detections[] = $this->detection(
                    $accountId,
                    'pod_heartbeat',
                    $deploymentId,
                    'critical',
                    'POD heartbeat is stale',
                    ['last_heartbeat_at' => $row['last_heartbeat_at']]
                );
            }
            if ((string) $row['routing_status'] !== 'active') {
                $detections[] = $this->detection(
                    $accountId,
                    'pod_routing',
                    $deploymentId,
                    (string) $row['routing_status'] === 'disabled' ? 'critical' : 'warning',
                    'POD routing is not active',
                    ['routing_status' => $row['routing_status']]
                );
            }
            if ((string) $row['ssl_status'] !== 'active') {
                $detections[] = $this->detection(
                    $accountId,
                    'pod_ssl',
                    $deploymentId,
                    (string) $row['ssl_status'] === 'failed' ? 'critical' : 'warning',
                    'POD SSL is not active',
                    ['ssl_status' => $row['ssl_status']]
                );
            }
            if ((string) $row['backup_status'] !== 'verified') {
                $detections[] = $this->detection(
                    $accountId,
                    'pod_backup',
                    $deploymentId,
                    (string) $row['backup_status'] === 'failed' ? 'critical' : 'warning',
                    'POD backup is not verified',
                    ['backup_status' => $row['backup_status']]
                );
            }
            if (!in_array((string) $row['license_status'], ['active', 'grace'], true)) {
                $detections[] = $this->detection(
                    $accountId,
                    'pod_license',
                    $deploymentId,
                    'critical',
                    'POD license is not active',
                    ['license_status' => $row['license_status']]
                );
            }
        }
        foreach ($pdo->query(
            "SELECT * FROM homeserver_devices WHERE status IN ('online','degraded','offline','suspended')"
        )->fetchAll(PDO::FETCH_ASSOC) as $row) {
            if ((string) $row['status'] !== 'online' || $row['last_heartbeat_at'] === null
                || strtotime((string) $row['last_heartbeat_at']) < time() - ($this->homeServerOfflineAfterMinutes * 60)) {
                $detections[] = $this->detection(
                    (int) $row['account_id'],
                    'homeserver_heartbeat',
                    (int) $row['id'],
                    in_array((string) $row['status'], ['offline', 'suspended'], true) ? 'critical' : 'warning',
                    'HomeServer is not healthy',
                    ['status' => $row['status'], 'last_heartbeat_at' => $row['last_heartbeat_at']]
                );
            }
        }
        foreach ($pdo->query(
            "SELECT b.id,b.account_id,b.last_error_code FROM backup_jobs b
             WHERE b.status='failed' AND b.updated_at>=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 24 HOUR)"
        )->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $detections[] = $this->detection(
                (int) $row['account_id'],
                'backup_failure',
                (int) $row['id'],
                'critical',
                'Backup job failed',
                ['last_error_code' => $row['last_error_code']]
            );
        }
        foreach ($pdo->query(
            "SELECT id,account_id,severity FROM storage_alerts WHERE status IN ('open','acknowledged')"
        )->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $detections[] = $this->detection(
                (int) $row['account_id'],
                'storage_alert',
                (int) $row['id'],
                (string) $row['severity'],
                'Storage utilization alert is active',
                ['severity' => $row['severity']]
            );
        }
        foreach ($pdo->query(
            "SELECT id,account_id,status,last_error_code FROM update_jobs
             WHERE status IN ('failed','rolled_back') AND updated_at>=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 24 HOUR)"
        )->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $detections[] = $this->detection(
                (int) $row['account_id'],
                'update_failure',
                (int) $row['id'],
                (string) $row['status'] === 'failed' ? 'critical' : 'warning',
                'Software update did not complete normally',
                ['status' => $row['status'], 'last_error_code' => $row['last_error_code']]
            );
        }
        foreach ($pdo->query(
            "SELECT id,account_id,last_error_code FROM provider_operations
             WHERE status='failed' AND updated_at>=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 24 HOUR)"
        )->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $detections[] = $this->detection(
                (int) $row['account_id'],
                'provider_failure',
                (int) $row['id'],
                'critical',
                'Infrastructure provider operation failed',
                ['last_error_code' => $row['last_error_code']]
            );
        }
        return $detections;
    }

    /** @param array<string,bool> $seen */
    private function resolveRecovered(array $seen): int
    {
        $rows = $this->database->pdo()->query(
            "SELECT id,account_scope,incident_key FROM operational_incidents
             WHERE monitor_managed=1 AND status IN ('open','acknowledged')"
        )->fetchAll(PDO::FETCH_ASSOC);
        $resolved = 0;
        foreach ($rows as $row) {
            if (!isset($seen[(string) $row['incident_key']])) {
                $this->incidents->resolve(
                    (int) $row['account_scope'],
                    (int) $row['id'],
                    0,
                    'MONITOR-RECOVERY-' . (int) $row['id'] . '-' . bin2hex(random_bytes(4)),
                    ['reason' => 'health_evidence_recovered']
                );
                $resolved++;
            }
        }
        return $resolved;
    }

    /** @param array<string,mixed> $evidence @return array{account_scope:int,source_type:string,source_id:int,severity:string,title:string,evidence:array<string,mixed>} */
    private function detection(
        int $accountScope,
        string $sourceType,
        int $sourceId,
        string $severity,
        string $title,
        array $evidence
    ): array {
        return [
            'account_scope' => $accountScope,
            'source_type' => $sourceType,
            'source_id' => $sourceId,
            'severity' => $severity,
            'title' => $title,
            'evidence' => $evidence,
        ];
    }
}
