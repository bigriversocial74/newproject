<?php

declare(strict_types=1);

namespace Vp3\Security;

use PDO;
use Throwable;
use Vp3\Database;
use Vp3\Operations\OperationalIncidentService;

final class SecurityIncidentAutomationService
{
    /** @var array<string,int> */
    private const RISK_RANK = ['info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];

    public function __construct(
        private readonly Database $database,
        private readonly OperationalIncidentService $incidents,
        private readonly SecurityAlertPreferenceService $preferences,
        private readonly SecurityAuditService $audit
    ) {
    }

    /** @return array{worker_id:string,examined:int,promoted:int,ignored:int,failed:int} */
    public function runPass(string $workerId, int $limit = 50): array
    {
        $workerId = trim($workerId);
        if ($workerId === '') {
            throw new \InvalidArgumentException('A security incident automation worker ID is required.');
        }
        $limit = max(1, min(200, $limit));
        $candidates = $this->database->pdo()->query(
            "SELECT e.id
             FROM security_audit_events e
             INNER JOIN security_alert_preferences p ON p.account_scope=e.account_scope
             LEFT JOIN security_incident_cases c ON c.source_audit_event_id=e.id
             WHERE c.id IS NULL
               AND (
                 (CASE e.risk_level WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)
                   >= (CASE p.minimum_risk WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END)
                 OR (p.include_integrity_failures=1 AND e.category='integrity')
               )
             ORDER BY e.id ASC
             LIMIT {$limit}"
        )->fetchAll(PDO::FETCH_COLUMN);

        $result = [
            'worker_id' => substr($workerId, 0, 128),
            'examined' => count($candidates),
            'promoted' => 0,
            'ignored' => 0,
            'failed' => 0,
        ];

        foreach ($candidates as $eventId) {
            try {
                $outcome = $this->promoteOne((int) $eventId, $result['worker_id']);
                $result[$outcome]++;
            } catch (Throwable $exception) {
                $result['failed']++;
                $this->audit->record(
                    'security.incident.automatic_promotion_failed',
                    'platform',
                    'high',
                    'failure',
                    null,
                    'worker',
                    null,
                    null,
                    'security_audit_event',
                    null,
                    [
                        'event_id_hash' => hash('sha256', (string) $eventId),
                        'error_class' => $exception::class,
                        'error_hash' => hash('sha256', $exception->getMessage()),
                        'worker_id_hash' => hash('sha256', $result['worker_id']),
                    ],
                    'AUTO-P32-FAIL-' . $eventId
                );
            }
        }

        return $result;
    }

    /** @return 'promoted'|'ignored' */
    private function promoteOne(int $eventId, string $workerId): string
    {
        $promotion = $this->database->transaction(function (PDO $pdo) use ($eventId, $workerId): array {
            $eventStatement = $pdo->prepare(
                'SELECT * FROM security_audit_events WHERE id=:id LIMIT 1 FOR UPDATE'
            );
            $eventStatement->execute(['id' => $eventId]);
            $event = $eventStatement->fetch(PDO::FETCH_ASSOC);
            if (!is_array($event)) {
                return ['outcome' => 'ignored'];
            }

            $existing = $pdo->prepare(
                'SELECT id,public_id FROM security_incident_cases WHERE source_audit_event_id=:event LIMIT 1'
            );
            $existing->execute(['event' => $eventId]);
            if (is_array($existing->fetch(PDO::FETCH_ASSOC))) {
                return ['outcome' => 'ignored'];
            }

            $preference = $pdo->prepare(
                'SELECT minimum_risk,include_integrity_failures,notify_on_promotion
                 FROM security_alert_preferences WHERE account_scope=:account LIMIT 1 FOR UPDATE'
            );
            $preference->execute(['account' => (int) $event['account_scope']]);
            $policy = $preference->fetch(PDO::FETCH_ASSOC);
            if (!is_array($policy) || !$this->qualifies($event, $policy)) {
                return ['outcome' => 'ignored'];
            }

            $manager = $pdo->prepare(
                "SELECT au.user_id,u.public_id,au.role
                 FROM account_users au INNER JOIN users u ON u.id=au.user_id
                 WHERE au.account_id=:account AND au.status='active' AND u.status='active'
                   AND au.role IN ('customer_owner','customer_admin')
                 ORDER BY CASE au.role WHEN 'customer_owner' THEN 0 ELSE 1 END,au.id ASC
                 LIMIT 1 FOR UPDATE"
            );
            $manager->execute(['account' => (int) $event['account_scope']]);
            $managerRow = $manager->fetch(PDO::FETCH_ASSOC);
            if (!is_array($managerRow)) {
                throw new \RuntimeException('Automatic security promotion requires an active account owner or administrator.');
            }

            $incident = $this->incidents->open(
                (int) $event['account_scope'],
                'security_audit',
                $eventId,
                $this->incidentSeverity((string) $event['risk_level']),
                mb_substr('Security incident: ' . (string) $event['event_type'], 0, 190),
                [
                    'audit_event_public_id' => (string) $event['public_id'],
                    'event_type' => (string) $event['event_type'],
                    'category' => (string) $event['category'],
                    'risk_level' => (string) $event['risk_level'],
                    'result' => (string) $event['result'],
                    'chain_hash' => (string) $event['chain_hash'],
                    'promotion_source' => 'policy',
                    'worker_id_hash' => hash('sha256', $workerId),
                ],
                false
            );

            if (!(bool) $policy['notify_on_promotion']) {
                $this->preferences->suppressPromotionNotifications((int) $incident['incident_id']);
            }

            $casePublicId = 'SEC-CASE-' . strtoupper(bin2hex(random_bytes(10)));
            $now = $this->now();
            $pdo->prepare(
                "INSERT INTO security_incident_cases
                 (public_id,account_scope,operational_incident_id,source_audit_event_id,case_status,
                  assigned_user_id,created_by_user_id,last_action_at,created_at,updated_at)
                 VALUES (:public_id,:account,:incident,:event,'triage',NULL,:creator,:last_action,:created,:updated)"
            )->execute([
                'public_id' => $casePublicId,
                'account' => (int) $event['account_scope'],
                'incident' => (int) $incident['incident_id'],
                'event' => $eventId,
                'creator' => (int) $managerRow['user_id'],
                'last_action' => $now,
                'created' => $now,
                'updated' => $now,
            ]);
            $caseId = (int) $pdo->lastInsertId();
            $requestId = 'AUTO-P32-EVENT-' . $eventId;
            $evidenceHash = hash('sha256', implode('|', [
                (string) $event['public_id'],
                $casePublicId,
                (string) $incident['public_id'],
                $requestId,
                hash('sha256', $workerId),
            ]));
            $pdo->prepare(
                "INSERT INTO security_response_actions
                 (public_id,account_scope,case_id,actor_user_id,target_user_id,request_id,
                  action_type,result,evidence_hash,created_at)
                 VALUES (:public_id,:account,:case_id,:actor,NULL,:request_id,
                         'automatic_promote_event','success',:evidence_hash,:created_at)"
            )->execute([
                'public_id' => 'SEC-ACTION-' . strtoupper(bin2hex(random_bytes(10))),
                'account' => (int) $event['account_scope'],
                'case_id' => $caseId,
                'actor' => (int) $managerRow['user_id'],
                'request_id' => $requestId,
                'evidence_hash' => $evidenceHash,
                'created_at' => $now,
            ]);

            return [
                'outcome' => 'promoted',
                'account_id' => (int) $event['account_scope'],
                'event_public_id' => (string) $event['public_id'],
                'case_public_id' => $casePublicId,
                'incident_public_id' => (string) $incident['public_id'],
                'request_id' => $requestId,
            ];
        });

        if (($promotion['outcome'] ?? '') !== 'promoted') {
            return 'ignored';
        }

        $this->audit->record(
            'security.incident.automatically_promoted',
            'platform',
            'high',
            'success',
            (int) $promotion['account_id'],
            'worker',
            null,
            null,
            'security_incident_case',
            (string) $promotion['case_public_id'],
            [
                'source_event_public_id' => (string) $promotion['event_public_id'],
                'incident_public_id' => (string) $promotion['incident_public_id'],
                'worker_id_hash' => hash('sha256', $workerId),
            ],
            (string) $promotion['request_id']
        );
        return 'promoted';
    }

    /** @param array<string,mixed> $event @param array<string,mixed> $policy */
    private function qualifies(array $event, array $policy): bool
    {
        $risk = self::RISK_RANK[(string) $event['risk_level']] ?? 0;
        $minimum = self::RISK_RANK[(string) $policy['minimum_risk']] ?? self::RISK_RANK['high'];
        return $risk >= $minimum
            || ((bool) $policy['include_integrity_failures'] && (string) $event['category'] === 'integrity');
    }

    private function incidentSeverity(string $risk): string
    {
        return match ($risk) {
            'critical' => 'critical',
            'high', 'medium' => 'warning',
            default => 'info',
        };
    }

    private function now(): string
    {
        return (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s.u');
    }
}
