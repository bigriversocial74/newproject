<?php

declare(strict_types=1);

namespace Vp3\Operations;

use PDO;
use Vp3\Database;

final class OperationsReadinessService
{
    public function __construct(
        private readonly Database $database,
        private readonly OperationalAuditService $audit,
        private readonly OperationalNotificationService $notifications,
        private readonly OperationalIncidentService $incidents,
        private readonly OperationsMonitorService $monitor
    ) {
    }

    /** @param array<string,mixed> $destination @return array{channel_id:int,public_id:string} */
    public function saveNotificationChannel(
        int $accountScope,
        string $channelType,
        string $label,
        array $destination,
        string $severityThreshold,
        string $requestId
    ): array {
        return $this->notifications->saveChannel(
            $accountScope,
            $channelType,
            $label,
            $destination,
            $severityThreshold,
            $requestId
        );
    }

    public function setNotificationChannelStatus(
        int $accountScope,
        int $channelId,
        string $status,
        int $actorId,
        string $requestId
    ): void {
        $this->notifications->setChannelStatus($accountScope, $channelId, $status, $actorId, $requestId);
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
        $this->monitor->recordHealthSignal(
            $accountScope,
            $sourceType,
            $sourceId,
            $healthy,
            $severity,
            $evidence,
            $requestId
        );
    }

    /** @param array<string,mixed> $evidence @return array{incident_id:int,public_id:string,status:string,created:bool,incident_key:string} */
    public function openIncident(
        int $accountScope,
        string $sourceType,
        int $sourceId,
        string $severity,
        string $title,
        array $evidence,
        bool $monitorManaged = false
    ): array {
        return $this->incidents->open(
            $accountScope,
            $sourceType,
            $sourceId,
            $severity,
            $title,
            $evidence,
            $monitorManaged
        );
    }

    public function acknowledgeIncident(int $accountScope, int $incidentId, int $actorId, string $requestId): void
    {
        $this->incidents->acknowledge($accountScope, $incidentId, $actorId, $requestId);
    }

    /** @param array<string,mixed> $resolution */
    public function resolveIncident(
        int $accountScope,
        int $incidentId,
        int $actorId,
        string $requestId,
        array $resolution = []
    ): void {
        $this->incidents->resolve($accountScope, $incidentId, $actorId, $requestId, $resolution);
    }

    /** @return array{run_id:int,public_id:string,checked:int,opened:int,resolved:int} */
    public function runMonitoringPass(string $workerId): array
    {
        return $this->monitor->run($workerId);
    }

    /** @return array{notification_id:int,status:string,receipt_hash:string}|null */
    public function processNextNotification(string $workerId): ?array
    {
        return $this->notifications->processNext($workerId);
    }

    public function verifyAuditChain(): bool
    {
        return $this->audit->verify();
    }

    /** @return array{assessment_id:int,public_id:string,status:string,score:float,blockers:int,warnings:int,checks:list<array<string,mixed>>} */
    public function assessReadiness(string $assessorType = 'system', int $assessorId = 0): array
    {
        $checks = [
            $this->countCheck(
                'critical_incidents',
                "SELECT COUNT(*) FROM operational_incidents
                 WHERE status IN ('open','acknowledged') AND severity='critical'",
                'blocker'
            ),
            $this->countCheck(
                'warning_incidents',
                "SELECT COUNT(*) FROM operational_incidents
                 WHERE status IN ('open','acknowledged') AND severity='warning'",
                'warning'
            ),
            $this->countCheck(
                'recent_failed_provisioning_jobs',
                "SELECT COUNT(*) FROM pod_provisioning_jobs
                 WHERE status='failed' AND updated_at>=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 24 HOUR)",
                'blocker'
            ),
            $this->countCheck(
                'recent_failed_update_jobs',
                "SELECT COUNT(*) FROM update_jobs
                 WHERE status='failed' AND updated_at>=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 24 HOUR)",
                'blocker'
            ),
            $this->countCheck(
                'recent_failed_backup_jobs',
                "SELECT COUNT(*) FROM backup_jobs
                 WHERE status='failed' AND updated_at>=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 24 HOUR)",
                'blocker'
            ),
            $this->countCheck(
                'recent_failed_provider_operations',
                "SELECT COUNT(*) FROM provider_operations
                 WHERE status='failed' AND updated_at>=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 24 HOUR)",
                'blocker'
            ),
            $this->countCheck(
                'failed_notifications',
                "SELECT COUNT(*) FROM operational_notifications WHERE status='failed'",
                'warning'
            ),
            $this->countCheck(
                'unhealthy_pods',
                "SELECT COUNT(*) FROM pod_deployments
                 WHERE status='active'
                   AND (routing_status<>'active' OR ssl_status<>'active'
                        OR backup_status<>'verified' OR license_status NOT IN ('active','grace'))",
                'blocker'
            ),
            $this->countCheck(
                'offline_homeservers',
                "SELECT COUNT(*) FROM homeserver_devices WHERE status IN ('offline','suspended')",
                'warning'
            ),
        ];
        $auditValid = $this->audit->verify();
        $checks[] = [
            'check_code' => 'audit_chain_integrity',
            'status' => $auditValid ? 'pass' : 'fail',
            'severity' => 'blocker',
            'count' => $auditValid ? 0 : 1,
            'evidence_hash' => hash('sha256', $auditValid ? 'valid' : 'invalid'),
            'details_hash' => hash('sha256', 'operational_audit_heads|operational_audit_chain'),
        ];

        $blockers = 0;
        $warnings = 0;
        foreach ($checks as $check) {
            if ($check['status'] === 'fail' && $check['severity'] === 'blocker') {
                $blockers++;
            } elseif ($check['status'] !== 'pass') {
                $warnings++;
            }
        }
        $score = max(0.0, 100.0 - ($blockers * 15.0) - ($warnings * 4.0));
        $status = $blockers > 0 ? 'blocked' : ($warnings > 0 ? 'warning' : 'ready');
        $evidenceHash = hash('sha256', json_encode($checks, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
        $publicId = 'OPS-READY-' . strtoupper(bin2hex(random_bytes(10)));

        $assessmentId = $this->database->transaction(function (PDO $pdo) use (
            $publicId, $status, $score, $blockers, $warnings, $evidenceHash, $assessorType, $assessorId, $checks
        ): int {
            $pdo->prepare(
                'INSERT INTO operational_readiness_assessments
                 (public_id,status,score,blocker_count,warning_count,evidence_hash,assessor_type,assessor_id,created_at)
                 VALUES (:public,:status,:score,:blockers,:warnings,:evidence,:assessor_type,:assessor_id,UTC_TIMESTAMP())'
            )->execute([
                'public' => $publicId,
                'status' => $status,
                'score' => number_format($score, 2, '.', ''),
                'blockers' => $blockers,
                'warnings' => $warnings,
                'evidence' => $evidenceHash,
                'assessor_type' => substr(trim($assessorType), 0, 40),
                'assessor_id' => max(0, $assessorId),
            ]);
            $assessmentId = (int) $pdo->lastInsertId();
            $insert = $pdo->prepare(
                'INSERT INTO operational_readiness_checks
                 (assessment_id,check_code,status,severity,evidence_hash,details_hash,created_at)
                 VALUES (:assessment,:check_code,:status,:severity,:evidence,:details,UTC_TIMESTAMP())'
            );
            foreach ($checks as $check) {
                $insert->execute([
                    'assessment' => $assessmentId,
                    'check_code' => $check['check_code'],
                    'status' => $check['status'],
                    'severity' => $check['severity'],
                    'evidence' => $check['evidence_hash'],
                    'details' => $check['details_hash'],
                ]);
            }
            $this->audit->appendWithPdo(
                $pdo,
                'readiness_assessment',
                $assessmentId,
                $status,
                $assessorType,
                $assessorId,
                $evidenceHash
            );
            return $assessmentId;
        });

        return [
            'assessment_id' => $assessmentId,
            'public_id' => $publicId,
            'status' => $status,
            'score' => $score,
            'blockers' => $blockers,
            'warnings' => $warnings,
            'checks' => $checks,
        ];
    }

    /** @return array{check_code:string,status:string,severity:string,count:int,evidence_hash:string,details_hash:string} */
    private function countCheck(string $code, string $sql, string $severity): array
    {
        $count = (int) $this->database->pdo()->query($sql)->fetchColumn();
        $status = $count === 0 ? 'pass' : ($severity === 'blocker' ? 'fail' : 'warning');
        return [
            'check_code' => $code,
            'status' => $status,
            'severity' => $severity,
            'count' => $count,
            'evidence_hash' => hash('sha256', $code . '|' . $count),
            'details_hash' => hash('sha256', $sql),
        ];
    }
}
