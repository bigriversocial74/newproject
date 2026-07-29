<?php

declare(strict_types=1);

namespace Vp3\Operations;

use PDO;
use RuntimeException;
use Vp3\Database;

final class OperationalIncidentService
{
    /** @var array<string,int> */
    private const SEVERITY_RANK = ['info' => 1, 'warning' => 2, 'critical' => 3];

    public function __construct(
        private readonly Database $database,
        private readonly OperationalAuditService $audit,
        private readonly OperationalNotificationService $notifications
    ) {
    }

    /** @param array<string,mixed> $evidence @return array{incident_id:int,public_id:string,status:string,created:bool,incident_key:string} */
    public function open(
        int $accountScope,
        string $sourceType,
        int $sourceId,
        string $severity,
        string $title,
        array $evidence,
        bool $monitorManaged = false
    ): array {
        $sourceType = strtolower(trim($sourceType));
        $severity = strtolower(trim($severity));
        $title = trim($title);
        if ($accountScope < 0 || $sourceType === '' || $sourceId < 0 || !isset(self::SEVERITY_RANK[$severity]) || $title === '') {
            throw new RuntimeException('A valid operational incident is required.');
        }
        $incidentKey = $this->key($accountScope, $sourceType, $sourceId, $title);
        $evidenceHash = $this->hashValue($evidence);
        $summaryHash = hash('sha256', $title);

        return $this->database->transaction(function (PDO $pdo) use (
            $accountScope, $sourceType, $sourceId, $severity, $title, $monitorManaged,
            $incidentKey, $evidenceHash, $summaryHash
        ): array {
            $find = $pdo->prepare(
                'SELECT * FROM operational_incidents
                 WHERE account_scope=:account AND incident_key=:incident_key AND active_marker=1 LIMIT 1 FOR UPDATE'
            );
            $find->execute(['account' => $accountScope, 'incident_key' => $incidentKey]);
            $existing = $find->fetch(PDO::FETCH_ASSOC);
            $now = gmdate('Y-m-d H:i:s');
            $created = false;
            $eventType = 'detected';
            $effectiveSeverity = $severity;

            if (is_array($existing)) {
                $incidentId = (int) $existing['id'];
                $publicId = (string) $existing['public_id'];
                $currentSeverity = (string) $existing['severity'];
                $effectiveSeverity = self::SEVERITY_RANK[$severity] > self::SEVERITY_RANK[$currentSeverity]
                    ? $severity : $currentSeverity;
                if ($effectiveSeverity !== $currentSeverity) {
                    $eventType = 'escalated';
                }
                $status = (string) $existing['status'];
                $pdo->prepare(
                    'UPDATE operational_incidents
                     SET severity=:severity,evidence_hash=:evidence,occurrence_count=occurrence_count+1,
                         last_detected_at=:detected,updated_at=:updated,
                         monitor_managed=GREATEST(monitor_managed,:monitor_managed)
                     WHERE id=:id'
                )->execute([
                    'severity' => $effectiveSeverity,
                    'evidence' => $evidenceHash,
                    'detected' => $now,
                    'updated' => $now,
                    'monitor_managed' => $monitorManaged ? 1 : 0,
                    'id' => $incidentId,
                ]);
            } else {
                $created = true;
                $eventType = 'opened';
                $status = 'open';
                $publicId = 'OPS-INC-' . strtoupper(bin2hex(random_bytes(10)));
                $pdo->prepare(
                    "INSERT INTO operational_incidents
                     (public_id,account_scope,incident_key,source_type,source_id,severity,status,active_marker,
                      monitor_managed,title,summary_hash,evidence_hash,occurrence_count,first_detected_at,last_detected_at,created_at,updated_at)
                     VALUES (:public,:account,:incident_key,:source_type,:source_id,:severity,'open',1,:monitor_managed,
                             :title,:summary_hash,:evidence_hash,1,:first_detected,:last_detected,:created,:updated)"
                )->execute([
                    'public' => $publicId,
                    'account' => $accountScope,
                    'incident_key' => $incidentKey,
                    'source_type' => $sourceType,
                    'source_id' => $sourceId,
                    'severity' => $effectiveSeverity,
                    'monitor_managed' => $monitorManaged ? 1 : 0,
                    'title' => substr($title, 0, 190),
                    'summary_hash' => $summaryHash,
                    'evidence_hash' => $evidenceHash,
                    'first_detected' => $now,
                    'last_detected' => $now,
                    'created' => $now,
                    'updated' => $now,
                ]);
                $incidentId = (int) $pdo->lastInsertId();
            }

            $payloadHash = hash('sha256', $publicId . '|' . $eventType . '|' . $status . '|' . $effectiveSeverity . '|' . $evidenceHash);
            $eventId = $this->appendEvent(
                $pdo,
                $incidentId,
                $eventType,
                $status,
                $effectiveSeverity,
                'system',
                0,
                $payloadHash
            );
            $this->audit->appendWithPdo($pdo, 'incident', $incidentId, $eventType, 'system', 0, $payloadHash);
            if (in_array($eventType, ['opened', 'escalated'], true)) {
                $this->notifications->queueWithPdo(
                    $pdo, $incidentId, $eventId, $eventType, $status, $effectiveSeverity, $payloadHash
                );
            }
            return [
                'incident_id' => $incidentId,
                'public_id' => $publicId,
                'status' => $status,
                'created' => $created,
                'incident_key' => $incidentKey,
            ];
        });
    }

    public function acknowledge(int $accountScope, int $incidentId, int $actorId, string $requestId): void
    {
        $this->changeState($accountScope, $incidentId, 'acknowledged', $actorId, $requestId, null);
    }

    /** @param array<string,mixed> $resolution */
    public function resolve(int $accountScope, int $incidentId, int $actorId, string $requestId, array $resolution = []): void
    {
        $this->changeState($accountScope, $incidentId, 'resolved', $actorId, $requestId, $resolution);
    }

    public function incidentKey(int $accountScope, string $sourceType, int $sourceId, string $title): string
    {
        return $this->key($accountScope, $sourceType, $sourceId, $title);
    }

    /** @param array<string,mixed>|null $resolution */
    private function changeState(
        int $accountScope,
        int $incidentId,
        string $newStatus,
        int $actorId,
        string $requestId,
        ?array $resolution
    ): void {
        if ($accountScope < 0 || $incidentId < 1 || !in_array($newStatus, ['acknowledged', 'resolved'], true)
            || $actorId < 0 || trim($requestId) === '') {
            throw new RuntimeException('A valid incident state change is required.');
        }
        $outcome = $this->database->transaction(function (PDO $pdo) use (
            $accountScope, $incidentId, $newStatus, $actorId, $requestId, $resolution
        ): string {
            $operation = 'incident_' . $newStatus;
            $prior = $this->requestReceipt($pdo, $accountScope, $requestId, $operation);
            if ($prior !== null) {
                return (string) $prior['result'];
            }
            $find = $pdo->prepare('SELECT * FROM operational_incidents WHERE id=:id LIMIT 1 FOR UPDATE');
            $find->execute(['id' => $incidentId]);
            $incident = $find->fetch(PDO::FETCH_ASSOC);
            if (!is_array($incident) || (int) $incident['account_scope'] !== $accountScope) {
                $receiptHash = hash('sha256', $accountScope . '|' . $incidentId . '|' . $requestId . '|denied');
                $this->insertRequestReceipt($pdo, $accountScope, $requestId, $operation, 'denied', $incidentId, $receiptHash);
                $this->audit->appendWithPdo($pdo, 'incident', $incidentId, 'access_denied', 'account_user', $actorId, $receiptHash);
                return 'denied';
            }
            if ((string) $incident['status'] === 'resolved') {
                $receiptHash = hash('sha256', $accountScope . '|' . $incidentId . '|' . $requestId . '|ignored');
                $this->insertRequestReceipt($pdo, $accountScope, $requestId, $operation, 'ignored', $incidentId, $receiptHash);
                return 'ignored';
            }
            $now = gmdate('Y-m-d H:i:s');
            $resolutionHash = $resolution === null ? null : $this->hashValue($resolution);
            if ($newStatus === 'acknowledged') {
                $pdo->prepare(
                    "UPDATE operational_incidents
                     SET status='acknowledged',acknowledged_at=:changed,acknowledged_by=:actor,updated_at=:updated
                     WHERE id=:id"
                )->execute(['changed' => $now, 'actor' => $actorId, 'updated' => $now, 'id' => $incidentId]);
            } else {
                $pdo->prepare(
                    "UPDATE operational_incidents
                     SET status='resolved',active_marker=NULL,resolved_at=:changed,resolved_by=:actor,
                         resolution_hash=:resolution,updated_at=:updated WHERE id=:id"
                )->execute([
                    'changed' => $now,
                    'actor' => $actorId,
                    'resolution' => $resolutionHash ?? hash('sha256', 'resolved'),
                    'updated' => $now,
                    'id' => $incidentId,
                ]);
            }
            $payloadHash = hash('sha256', $incident['public_id'] . '|' . $newStatus . '|' . $incident['severity'] . '|' . ($resolutionHash ?? ''));
            $eventId = $this->appendEvent(
                $pdo,
                $incidentId,
                $newStatus,
                $newStatus,
                (string) $incident['severity'],
                'account_user',
                $actorId,
                $payloadHash
            );
            $this->audit->appendWithPdo($pdo, 'incident', $incidentId, $newStatus, 'account_user', $actorId, $payloadHash);
            $this->notifications->queueWithPdo(
                $pdo,
                $incidentId,
                $eventId,
                $newStatus,
                $newStatus,
                (string) $incident['severity'],
                $payloadHash
            );
            $receiptHash = hash('sha256', $accountScope . '|' . $incidentId . '|' . $requestId . '|' . $newStatus . '|' . $payloadHash);
            $this->insertRequestReceipt($pdo, $accountScope, $requestId, $operation, 'success', $incidentId, $receiptHash);
            return 'success';
        });
        if ($outcome === 'denied') {
            throw new RuntimeException('Operational incident does not belong to this account.');
        }
    }

    private function appendEvent(
        PDO $pdo,
        int $incidentId,
        string $eventType,
        string $eventStatus,
        string $severity,
        string $actorType,
        int $actorId,
        string $payloadHash
    ): int {
        $last = $pdo->prepare(
            'SELECT chain_hash FROM operational_incident_events WHERE incident_id=:incident ORDER BY id DESC LIMIT 1 FOR UPDATE'
        );
        $last->execute(['incident' => $incidentId]);
        $previous = $last->fetchColumn();
        $previous = is_string($previous) ? $previous : str_repeat('0', 64);
        $occurredAt = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s.u');
        $chainHash = hash('sha256', implode('|', [
            $previous,
            $incidentId,
            $eventType,
            $eventStatus,
            $severity,
            $actorType,
            $actorId,
            $payloadHash,
            $occurredAt,
        ]));
        $pdo->prepare(
            'INSERT INTO operational_incident_events
             (incident_id,event_type,event_status,severity,actor_type,actor_id,payload_hash,previous_chain_hash,chain_hash,occurred_at)
             VALUES (:incident,:event_type,:event_status,:severity,:actor_type,:actor_id,:payload,:previous_chain,:chain,:occurred)'
        )->execute([
            'incident' => $incidentId,
            'event_type' => $eventType,
            'event_status' => $eventStatus,
            'severity' => $severity,
            'actor_type' => $actorType,
            'actor_id' => max(0, $actorId),
            'payload' => $payloadHash,
            'previous_chain' => $previous,
            'chain' => $chainHash,
            'occurred' => $occurredAt,
        ]);
        return (int) $pdo->lastInsertId();
    }

    /** @return array<string,mixed>|null */
    private function requestReceipt(PDO $pdo, int $accountScope, string $requestId, string $operation): ?array
    {
        $statement = $pdo->prepare(
            'SELECT * FROM operational_request_receipts
             WHERE account_scope=:account AND request_id=:request_id AND operation=:operation LIMIT 1'
        );
        $statement->execute(['account' => $accountScope, 'request_id' => $requestId, 'operation' => $operation]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $row : null;
    }

    private function insertRequestReceipt(
        PDO $pdo,
        int $accountScope,
        string $requestId,
        string $operation,
        string $result,
        int $resourceId,
        string $receiptHash
    ): void {
        $pdo->prepare(
            "INSERT INTO operational_request_receipts
             (account_scope,request_id,operation,result,resource_type,resource_id,receipt_hash,created_at)
             VALUES (:account,:request_id,:operation,:result,'incident',:resource_id,:receipt,UTC_TIMESTAMP())"
        )->execute([
            'account' => $accountScope,
            'request_id' => substr(trim($requestId), 0, 80),
            'operation' => substr(trim($operation), 0, 100),
            'result' => $result,
            'resource_id' => $resourceId,
            'receipt' => $receiptHash,
        ]);
    }

    private function key(int $accountScope, string $sourceType, int $sourceId, string $title): string
    {
        return hash('sha256', $accountScope . '|' . strtolower(trim($sourceType)) . '|' . $sourceId . '|' . trim($title));
    }

    private function hashValue(mixed $value): string
    {
        return hash('sha256', json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }
}
