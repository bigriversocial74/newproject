<?php

declare(strict_types=1);

namespace Vp3\Reliability;

use DateTimeImmutable;
use DateTimeZone;
use PDO;
use RuntimeException;
use Throwable;
use Vp3\Database;
use Vp3\Operations\OperationalIncidentService;

final class ReliabilityWorkerService
{
    public function __construct(
        private readonly Database $database,
        private readonly ReliabilityProbeExecutor $executor,
        private readonly OperationalIncidentService $incidents,
        private readonly int $leaseSeconds = 300
    ) {
        if ($this->leaseSeconds < 60 || $this->leaseSeconds > 3600) {
            throw new RuntimeException('Reliability worker lease must be between 60 and 3600 seconds.');
        }
    }

    /** @return array<string,mixed>|null */
    public function processNext(string $workerId): ?array
    {
        $workerId = trim($workerId);
        if (!preg_match('/^[A-Za-z0-9._:@-]{4,120}$/', $workerId)) {
            throw new RuntimeException('A valid reliability worker identity is required.');
        }

        $probe = $this->claim($workerId);
        if ($probe === null) {
            return null;
        }

        try {
            $maintenance = $this->maintenanceActive($probe);
            $observation = $maintenance
                ? [
                    'status' => 'maintenance',
                    'latency_ms' => null,
                    'value_numeric' => null,
                    'error_code' => null,
                    'evidence' => ['maintenance_window' => true],
                ]
                : $this->executor->execute($probe);
            return $this->record($probe, $observation, $workerId);
        } catch (Throwable $exception) {
            $this->releaseAfterUnexpectedFailure((int) $probe['id'], $workerId, $exception);
            throw $exception;
        }
    }

    /** @param array<string,mixed> $observation @return array<string,mixed> */
    public function recordManual(string $probePublicId, array $observation, string $workerId = 'manual-observation'): array
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT p.*,c.account_scope,c.public_id AS component_public_id,c.display_name,c.component_type,
                    c.current_status,c.environment_id,o.availability_target_bps,o.latency_target_ms,
                    o.evaluation_window_minutes,o.warning_burn_rate,o.critical_burn_rate,
                    o.consecutive_failure_threshold,o.recovery_success_threshold
             FROM reliability_probes p
             INNER JOIN reliability_components c ON c.id=p.component_id
             INNER JOIN reliability_objectives o ON o.component_id=c.id
             WHERE p.public_id=:public_id AND p.probe_type='manual' AND p.enabled=1 LIMIT 1"
        );
        $statement->execute(['public_id' => trim($probePublicId)]);
        $probe = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($probe)) {
            throw new RuntimeException('Manual reliability probe was not found.');
        }
        $normalized = [
            'status' => strtolower((string) ($observation['status'] ?? 'failure')),
            'latency_ms' => isset($observation['latency_ms']) ? max(0, (int) $observation['latency_ms']) : null,
            'value_numeric' => isset($observation['value_numeric']) ? (float) $observation['value_numeric'] : null,
            'error_code' => isset($observation['error_code']) ? substr((string) $observation['error_code'], 0, 100) : null,
            'evidence' => is_array($observation['evidence'] ?? null) ? $observation['evidence'] : [],
        ];
        if (!in_array($normalized['status'], ['success', 'failure', 'maintenance'], true)) {
            throw new RuntimeException('Manual reliability observations require success, failure, or maintenance.');
        }
        return $this->record($probe, $normalized, $workerId);
    }

    /** @return array<string,mixed>|null */
    private function claim(string $workerId): ?array
    {
        return $this->database->transaction(function (PDO $pdo) use ($workerId): ?array {
            $statement = $pdo->query(
                "SELECT p.*,c.account_scope,c.public_id AS component_public_id,c.display_name,c.component_type,
                        c.current_status,c.environment_id,o.availability_target_bps,o.latency_target_ms,
                        o.evaluation_window_minutes,o.warning_burn_rate,o.critical_burn_rate,
                        o.consecutive_failure_threshold,o.recovery_success_threshold
                 FROM reliability_probes p
                 INNER JOIN reliability_components c ON c.id=p.component_id AND c.enabled=1
                 INNER JOIN reliability_objectives o ON o.component_id=c.id
                 WHERE p.enabled=1 AND p.probe_type<>'manual' AND p.next_due_at<=UTC_TIMESTAMP(6)
                   AND (p.lock_expires_at IS NULL OR p.lock_expires_at<UTC_TIMESTAMP(6))
                 ORDER BY p.next_due_at,p.id LIMIT 1 FOR UPDATE"
            );
            $probe = $statement->fetch(PDO::FETCH_ASSOC);
            if (!is_array($probe)) {
                return null;
            }
            $now = $this->now();
            $lease = $this->timeAfter($this->leaseSeconds);
            $pdo->prepare(
                'UPDATE reliability_probes
                 SET locked_by_hash=:worker_hash,lock_expires_at=:lease,last_started_at=:started,updated_at=:updated
                 WHERE id=:id'
            )->execute([
                'worker_hash' => hash('sha256', $workerId),
                'lease' => $lease,
                'started' => $now,
                'updated' => $now,
                'id' => (int) $probe['id'],
            ]);
            $probe['locked_by_hash'] = hash('sha256', $workerId);
            return $probe;
        });
    }

    /** @param array<string,mixed> $probe */
    private function maintenanceActive(array $probe): bool
    {
        $environmentId = isset($probe['environment_id']) ? (int) $probe['environment_id'] : 0;
        if ($environmentId < 1) {
            return false;
        }
        $statement = $this->database->pdo()->prepare(
            "SELECT COUNT(*) FROM platform_maintenance_windows
             WHERE environment_id=:environment_id
               AND approved_by_user_id IS NOT NULL
               AND window_status IN ('scheduled','open')
               AND starts_at<=UTC_TIMESTAMP(6) AND ends_at>=UTC_TIMESTAMP(6)"
        );
        $statement->execute(['environment_id' => $environmentId]);
        return (int) $statement->fetchColumn() > 0;
    }

    /** @param array<string,mixed> $probe @param array<string,mixed> $observation @return array<string,mixed> */
    private function record(array $probe, array $observation, string $workerId): array
    {
        $result = $this->database->transaction(function (PDO $pdo) use ($probe, $observation, $workerId): array {
            $locked = $pdo->prepare(
                "SELECT p.id,p.component_id,p.interval_seconds,p.locked_by_hash,p.probe_type,
                        c.account_scope,c.public_id AS component_public_id,c.display_name,c.current_status,
                        c.environment_id
                 FROM reliability_probes p
                 INNER JOIN reliability_components c ON c.id=p.component_id
                 WHERE p.id=:id LIMIT 1 FOR UPDATE"
            );
            $locked->execute(['id' => (int) $probe['id']]);
            $current = $locked->fetch(PDO::FETCH_ASSOC);
            if (!is_array($current)) {
                throw new RuntimeException('Reliability probe disappeared while executing.');
            }
            $expectedWorker = hash('sha256', $workerId);
            if ((string) $current['probe_type'] !== 'manual'
                && !hash_equals((string) ($current['locked_by_hash'] ?? ''), $expectedWorker)) {
                throw new RuntimeException('Reliability probe lease ownership changed.');
            }

            $status = strtolower((string) ($observation['status'] ?? 'failure'));
            if (!in_array($status, ['success', 'failure', 'maintenance'], true)) {
                $status = 'failure';
            }
            $latency = isset($observation['latency_ms']) ? max(0, (int) $observation['latency_ms']) : null;
            $numeric = isset($observation['value_numeric']) ? (float) $observation['value_numeric'] : null;
            $errorCode = $status === 'failure'
                ? substr((string) ($observation['error_code'] ?? 'probe_failed'), 0, 100)
                : null;
            $evidence = is_array($observation['evidence'] ?? null) ? $observation['evidence'] : [];
            $evidence['status'] = $status;
            $evidence['latency_ms'] = $latency;
            $evidence['value_numeric'] = $numeric;
            $evidence['error_code'] = $errorCode;
            $evidenceHash = $this->hashValue($evidence);
            $releaseCandidateId = $this->releaseCandidateId($pdo, (int) ($current['environment_id'] ?? 0));
            $observedAt = $this->now();
            $resultPublicId = 'REL-RES-' . strtoupper(bin2hex(random_bytes(10)));
            $pdo->prepare(
                'INSERT INTO reliability_probe_results
                 (public_id,probe_id,component_id,release_candidate_id,result_status,latency_ms,value_numeric,
                  error_code,evidence_hash,observed_at)
                 VALUES (:public_id,:probe_id,:component_id,:candidate_id,:status,:latency,:numeric,
                         :error_code,:evidence,:observed_at)'
            )->execute([
                'public_id' => $resultPublicId,
                'probe_id' => (int) $current['id'],
                'component_id' => (int) $current['component_id'],
                'candidate_id' => $releaseCandidateId,
                'status' => $status,
                'latency' => $latency,
                'numeric' => $numeric,
                'error_code' => $errorCode,
                'evidence' => $evidenceHash,
                'observed_at' => $observedAt,
            ]);
            $resultId = (int) $pdo->lastInsertId();

            if ((string) $current['probe_type'] !== 'manual') {
                $pdo->prepare(
                    'UPDATE reliability_probes
                     SET next_due_at=:next_due,locked_by_hash=NULL,lock_expires_at=NULL,last_finished_at=:finished,updated_at=:updated
                     WHERE id=:id'
                )->execute([
                    'next_due' => $this->timeAfter(max(60, (int) $current['interval_seconds'])),
                    'finished' => $observedAt,
                    'updated' => $observedAt,
                    'id' => (int) $current['id'],
                ]);
            }

            $budget = $this->calculateBudget($pdo, (int) $current['component_id'], $probe);
            $budgetPublicId = 'REL-BUD-' . strtoupper(bin2hex(random_bytes(10)));
            $pdo->prepare(
                'INSERT INTO reliability_budget_snapshots
                 (public_id,component_id,window_started_at,window_ended_at,total_probes,failed_probes,
                  availability_bps,budget_consumed_bps,burn_rate,budget_status,evidence_hash,captured_at)
                 VALUES (:public_id,:component_id,:started,:ended,:total,:failed,:availability,:consumed,
                         :burn_rate,:status,:evidence,:captured)'
            )->execute([
                'public_id' => $budgetPublicId,
                'component_id' => (int) $current['component_id'],
                'started' => $budget['window_started_at'],
                'ended' => $observedAt,
                'total' => $budget['total_probes'],
                'failed' => $budget['failed_probes'],
                'availability' => $budget['availability_bps'],
                'consumed' => $budget['budget_consumed_bps'],
                'burn_rate' => $budget['burn_rate'],
                'status' => $budget['budget_status'],
                'evidence' => $budget['evidence_hash'],
                'captured' => $observedAt,
            ]);

            $newStatus = $this->determineStatus($pdo, (int) $current['component_id'], $status, $latency, $probe, $budget);
            $priorStatus = (string) $current['current_status'];
            if (!hash_equals($priorStatus, $newStatus)) {
                $pdo->prepare(
                    'UPDATE reliability_components
                     SET current_status=:status,status_since=:since,updated_at=:updated WHERE id=:id'
                )->execute([
                    'status' => $newStatus,
                    'since' => $observedAt,
                    'updated' => $observedAt,
                    'id' => (int) $current['component_id'],
                ]);
                $this->appendStatusEvent(
                    $pdo,
                    (int) $current['component_id'],
                    $priorStatus,
                    $newStatus,
                    $status === 'maintenance' ? 'approved_maintenance_window' : 'probe_evaluation',
                    hash('sha256', $evidenceHash . '|' . $budget['evidence_hash'])
                );
            }

            return [
                'result_id' => $resultId,
                'result_public_id' => $resultPublicId,
                'component_id' => (int) $current['component_id'],
                'component_public_id' => (string) $current['component_public_id'],
                'account_scope' => (int) $current['account_scope'],
                'display_name' => (string) $current['display_name'],
                'previous_status' => $priorStatus,
                'current_status' => $newStatus,
                'observation_status' => $status,
                'budget' => $budget,
            ];
        });

        $this->synchronizeIncident($result);
        return [
            'result_public_id' => $result['result_public_id'],
            'component_public_id' => $result['component_public_id'],
            'status' => $result['current_status'],
            'observation' => $result['observation_status'],
            'budget_status' => $result['budget']['budget_status'],
            'availability_bps' => $result['budget']['availability_bps'],
            'burn_rate' => $result['budget']['burn_rate'],
        ];
    }

    /** @param array<string,mixed> $result */
    private function synchronizeIncident(array $result): void
    {
        $componentId = (int) $result['component_id'];
        $accountScope = (int) $result['account_scope'];
        $currentStatus = (string) $result['current_status'];

        $link = $this->database->pdo()->prepare(
            "SELECT ril.id,ril.operational_incident_id
             FROM reliability_incident_links ril
             WHERE ril.component_id=:component_id AND ril.link_status='open' AND ril.active_marker=1 LIMIT 1"
        );
        $link->execute(['component_id' => $componentId]);
        $active = $link->fetch(PDO::FETCH_ASSOC);

        if (in_array($currentStatus, ['degraded', 'major_outage'], true)) {
            if (is_array($active)) {
                $this->incidents->open(
                    $accountScope,
                    'reliability_component',
                    $componentId,
                    $currentStatus === 'major_outage' ? 'critical' : 'warning',
                    'Reliability objective breach: ' . (string) $result['display_name'],
                    [
                        'component_public_id' => $result['component_public_id'],
                        'status' => $currentStatus,
                        'availability_bps' => $result['budget']['availability_bps'],
                        'burn_rate' => $result['budget']['burn_rate'],
                    ],
                    true
                );
                return;
            }
            $incident = $this->incidents->open(
                $accountScope,
                'reliability_component',
                $componentId,
                $currentStatus === 'major_outage' ? 'critical' : 'warning',
                'Reliability objective breach: ' . (string) $result['display_name'],
                [
                    'component_public_id' => $result['component_public_id'],
                    'status' => $currentStatus,
                    'availability_bps' => $result['budget']['availability_bps'],
                    'burn_rate' => $result['budget']['burn_rate'],
                ],
                true
            );
            $now = $this->now();
            $this->database->pdo()->prepare(
                "INSERT INTO reliability_incident_links
                 (component_id,operational_incident_id,opened_result_id,resolved_result_id,link_status,active_marker,created_at,updated_at)
                 VALUES (:component_id,:incident_id,:result_id,NULL,'open',1,:created,:updated)"
            )->execute([
                'component_id' => $componentId,
                'incident_id' => (int) $incident['incident_id'],
                'result_id' => (int) $result['result_id'],
                'created' => $now,
                'updated' => $now,
            ]);
            return;
        }

        if ($currentStatus === 'operational' && is_array($active)) {
            $requestId = 'reliability-auto-resolve-' . $componentId . '-' . (int) $result['result_id'];
            $this->incidents->resolve(
                $accountScope,
                (int) $active['operational_incident_id'],
                0,
                $requestId,
                [
                    'component_public_id' => $result['component_public_id'],
                    'result_public_id' => $result['result_public_id'],
                    'availability_bps' => $result['budget']['availability_bps'],
                ]
            );
            $now = $this->now();
            $this->database->pdo()->prepare(
                "UPDATE reliability_incident_links
                 SET link_status='resolved',active_marker=NULL,resolved_result_id=:result_id,updated_at=:updated
                 WHERE id=:id"
            )->execute([
                'result_id' => (int) $result['result_id'],
                'updated' => $now,
                'id' => (int) $active['id'],
            ]);
        }
    }

    /** @param array<string,mixed> $probe @return array<string,mixed> */
    private function calculateBudget(PDO $pdo, int $componentId, array $probe): array
    {
        $windowMinutes = max(60, min(525600, (int) ($probe['evaluation_window_minutes'] ?? 43200)));
        $started = (new DateTimeImmutable('now', new DateTimeZone('UTC')))
            ->modify('-' . $windowMinutes . ' minutes')
            ->format('Y-m-d H:i:s.u');
        $statement = $pdo->prepare(
            "SELECT COUNT(*) AS total,
                    SUM(CASE WHEN result_status='failure' THEN 1 ELSE 0 END) AS failed
             FROM reliability_probe_results
             WHERE component_id=:component_id AND observed_at>=:started
               AND result_status IN ('success','failure')"
        );
        $statement->execute(['component_id' => $componentId, 'started' => $started]);
        $row = $statement->fetch(PDO::FETCH_ASSOC) ?: [];
        $total = max(0, (int) ($row['total'] ?? 0));
        $failed = max(0, (int) ($row['failed'] ?? 0));
        $availability = $total === 0 ? 10000 : max(0, min(10000, (int) round((($total - $failed) / $total) * 10000)));
        $target = max(1, min(10000, (int) ($probe['availability_target_bps'] ?? 9990)));
        $allowedFailureBps = max(1, 10000 - $target);
        $actualFailureBps = max(0, 10000 - $availability);
        $consumed = (int) round(($actualFailureBps / $allowedFailureBps) * 10000);
        $burnRate = round($actualFailureBps / $allowedFailureBps, 4);
        $warning = max(1.0, (float) ($probe['warning_burn_rate'] ?? 2.0));
        $critical = max($warning, (float) ($probe['critical_burn_rate'] ?? 14.4));
        $status = $burnRate >= $critical ? 'exhausted' : ($burnRate >= $warning ? 'warning' : 'healthy');
        $payload = [
            'component_id' => $componentId,
            'window_started_at' => $started,
            'total_probes' => $total,
            'failed_probes' => $failed,
            'availability_bps' => $availability,
            'target_bps' => $target,
            'budget_consumed_bps' => $consumed,
            'burn_rate' => $burnRate,
            'budget_status' => $status,
        ];
        return $payload + ['evidence_hash' => $this->hashValue($payload)];
    }

    /** @param array<string,mixed> $probe @param array<string,mixed> $budget */
    private function determineStatus(
        PDO $pdo,
        int $componentId,
        string $observationStatus,
        ?int $latencyMs,
        array $probe,
        array $budget
    ): string {
        if ($observationStatus === 'maintenance') {
            return 'maintenance';
        }
        $failureThreshold = max(1, min(50, (int) ($probe['consecutive_failure_threshold'] ?? 3)));
        $recoveryThreshold = max(1, min(50, (int) ($probe['recovery_success_threshold'] ?? 2)));
        $recent = $pdo->prepare(
            'SELECT result_status,latency_ms FROM reliability_probe_results
             WHERE component_id=:component_id AND result_status<>\'maintenance\'
             ORDER BY observed_at DESC,id DESC LIMIT 50'
        );
        $recent->execute(['component_id' => $componentId]);
        $rows = $recent->fetchAll(PDO::FETCH_ASSOC);
        $consecutiveFailures = 0;
        $consecutiveSuccesses = 0;
        foreach ($rows as $index => $row) {
            $status = (string) $row['result_status'];
            if ($index === $consecutiveFailures && $status === 'failure') {
                $consecutiveFailures++;
            }
            if ($index === $consecutiveSuccesses && $status === 'success') {
                $consecutiveSuccesses++;
            }
            if ($index > max($failureThreshold, $recoveryThreshold)) {
                break;
            }
        }
        $latencyTarget = isset($probe['latency_target_ms']) ? (int) $probe['latency_target_ms'] : 0;
        $latencyBreach = $observationStatus === 'success'
            && $latencyTarget > 0
            && $latencyMs !== null
            && $latencyMs > $latencyTarget;

        if ($consecutiveFailures >= $failureThreshold) {
            return $budget['budget_status'] === 'exhausted' ? 'major_outage' : 'degraded';
        }
        if ($latencyBreach) {
            return 'degraded';
        }
        $minimumBudgetSample = max(10, $failureThreshold * 2);
        if ((int) ($budget['total_probes'] ?? 0) >= $minimumBudgetSample
            && $budget['budget_status'] !== 'healthy') {
            return $budget['budget_status'] === 'exhausted' ? 'major_outage' : 'degraded';
        }
        if ($observationStatus === 'failure') {
            return in_array((string) ($probe['current_status'] ?? 'unknown'), ['operational', 'unknown'], true)
                ? (string) ($probe['current_status'] ?? 'unknown')
                : 'degraded';
        }
        if ($consecutiveSuccesses >= $recoveryThreshold) {
            return 'operational';
        }
        return (string) ($probe['current_status'] ?? 'unknown');
    }

    private function appendStatusEvent(
        PDO $pdo,
        int $componentId,
        string $previousStatus,
        string $currentStatus,
        string $reasonCode,
        string $evidenceHash
    ): void {
        $last = $pdo->prepare(
            'SELECT event_hash FROM reliability_status_events
             WHERE component_id=:component_id ORDER BY id DESC LIMIT 1 FOR UPDATE'
        );
        $last->execute(['component_id' => $componentId]);
        $previousHash = $last->fetchColumn();
        $previousHash = is_string($previousHash) ? $previousHash : str_repeat('0', 64);
        $occurredAt = $this->now();
        $eventHash = hash('sha256', implode('|', [
            $previousHash,
            $componentId,
            $previousStatus,
            $currentStatus,
            $reasonCode,
            $evidenceHash,
            $occurredAt,
        ]));
        $pdo->prepare(
            'INSERT INTO reliability_status_events
             (component_id,previous_status,current_status,reason_code,evidence_hash,previous_hash,event_hash,occurred_at)
             VALUES (:component_id,:previous_status,:current_status,:reason_code,:evidence,:previous_hash,:event_hash,:occurred)'
        )->execute([
            'component_id' => $componentId,
            'previous_status' => $previousStatus,
            'current_status' => $currentStatus,
            'reason_code' => $reasonCode,
            'evidence' => $evidenceHash,
            'previous_hash' => $previousHash,
            'event_hash' => $eventHash,
            'occurred' => $occurredAt,
        ]);
    }

    private function releaseCandidateId(PDO $pdo, int $environmentId): ?int
    {
        if ($environmentId < 1) {
            return null;
        }
        $statement = $pdo->prepare(
            'SELECT current_candidate_id FROM platform_deployment_environments WHERE id=:id LIMIT 1'
        );
        $statement->execute(['id' => $environmentId]);
        $candidate = $statement->fetchColumn();
        return $candidate === false || $candidate === null ? null : (int) $candidate;
    }

    private function releaseAfterUnexpectedFailure(int $probeId, string $workerId, Throwable $exception): void
    {
        $now = $this->now();
        $statement = $this->database->pdo()->prepare(
            'UPDATE reliability_probes
             SET locked_by_hash=NULL,lock_expires_at=NULL,last_finished_at=:finished,
                 next_due_at=:next_due,updated_at=:updated
             WHERE id=:id AND locked_by_hash=:worker_hash'
        );
        $statement->execute([
            'finished' => $now,
            'next_due' => $this->timeAfter(60),
            'updated' => $now,
            'id' => $probeId,
            'worker_hash' => hash('sha256', $workerId),
        ]);
    }

    private function now(): string
    {
        return (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s.u');
    }

    private function timeAfter(int $seconds): string
    {
        return (new DateTimeImmutable('now', new DateTimeZone('UTC')))
            ->modify('+' . $seconds . ' seconds')
            ->format('Y-m-d H:i:s.u');
    }

    private function hashValue(mixed $value): string
    {
        return hash('sha256', json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }
}
