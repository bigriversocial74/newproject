<?php

declare(strict_types=1);

namespace Vp3\Security;

use PDO;
use Throwable;
use Vp3\Auth\AuthPublicException;
use Vp3\Database;
use Vp3\Operations\OperationsControlCenterQueryService;
use Vp3\Operations\OperationsSecretCipher;

final class SecurityCenterQueryService
{
    private const ALLOWED_ROLES = ['customer_owner', 'customer_admin'];

    public function __construct(
        private readonly Database $database,
        private readonly OperationsSecretCipher $cipher
    ) {
    }

    /**
     * @param array<string,scalar|null> $filters
     * @return array<string,mixed>
     */
    public function snapshot(
        int $accountId,
        int $userId,
        string $role,
        array $filters = [],
        int $limit = 100
    ): array {
        if ($accountId < 1 || $userId < 1 || !in_array($role, self::ALLOWED_ROLES, true)) {
            throw new AuthPublicException(
                'security_center_access_denied',
                'An active account owner or administrator membership is required.',
                403
            );
        }

        $this->assertCurrentMembership($accountId, $userId, $role);

        $audit = (new SecurityAuditQueryService($this->database))->snapshot(
            $accountId,
            $userId,
            $role,
            $filters,
            $limit
        );
        $operations = (new OperationsControlCenterQueryService($this->database))->snapshot(
            $accountId,
            $userId,
            $role
        );
        $sessions = $this->activeSessionSummary($accountId);
        $cases = $this->securityCases($accountId);
        $responders = $this->responders($accountId);
        $riskScore = $this->riskScore($audit, $operations, $sessions, $cases);

        return [
            'permissions' => [
                'can_view' => true,
                'can_export' => true,
                'can_manage_incidents' => true,
                'can_manage_sessions' => true,
                'can_manage_alert_preferences' => true,
                'can_resolve_cases' => true,
            ],
            'posture' => [
                'score' => $riskScore,
                'status' => $this->postureStatus($riskScore, (bool) $audit['chain_valid']),
                'chain_valid' => (bool) $audit['chain_valid'],
                'evaluated_at' => gmdate('Y-m-d H:i:s'),
            ],
            'metrics' => [
                'audit_events' => (int) $audit['summary']['total'],
                'high_or_critical' => (int) $audit['summary']['high_or_critical'],
                'denied_or_failed' => (int) $audit['summary']['denied_or_failed'],
                'integrity_events' => (int) $audit['summary']['integrity_events'],
                'active_sessions' => $sessions['active'],
                'account_users_with_sessions' => $sessions['users'],
                'incidents_open' => (int) $operations['metrics']['incidents_open'],
                'incidents_acknowledged' => (int) $operations['metrics']['incidents_acknowledged'],
                'active_critical_incidents' => (int) $operations['metrics']['active_critical'],
                'security_cases_active' => count(array_filter(
                    $cases,
                    static fn (array $case): bool => (string) $case['case_status'] !== 'resolved'
                )),
                'security_cases_unassigned' => count(array_filter(
                    $cases,
                    static fn (array $case): bool => (string) $case['case_status'] !== 'resolved'
                        && $case['assigned_user_public_id'] === null
                )),
            ],
            'audit_events' => $audit['events'],
            'incidents' => array_values(array_filter(
                $operations['incidents'],
                static fn (array $incident): bool => (string) $incident['status'] !== 'resolved'
            )),
            'recent_incident_events' => array_slice($operations['incident_events'], 0, 50),
            'security_cases' => $cases,
            'responders' => $responders,
            'session_targets' => array_values(array_filter(
                $responders,
                static fn (array $responder): bool => (int) $responder['active_sessions'] > 0
            )),
            'alert_preferences' => $this->alertPreferences($accountId),
            'recent_response_actions' => $this->recentResponseActions($accountId),
        ];
    }

    /** @return list<array<string,mixed>> */
    private function securityCases(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT c.id,c.public_id,c.case_status,c.last_action_at,c.created_at,c.updated_at,
                    i.public_id AS incident_public_id,i.title,i.severity,i.status AS incident_status,
                    e.public_id AS source_event_public_id,e.event_type,e.category,e.risk_level,e.result,e.occurred_at,
                    assignee.public_id AS assigned_user_public_id,assignee.display_name AS assigned_user_name,
                    creator.public_id AS created_by_user_public_id,creator.display_name AS created_by_user_name
             FROM security_incident_cases c
             INNER JOIN operational_incidents i ON i.id=c.operational_incident_id
             INNER JOIN security_audit_events e ON e.id=c.source_audit_event_id
             LEFT JOIN users assignee ON assignee.id=c.assigned_user_id
             INNER JOIN users creator ON creator.id=c.created_by_user_id
             WHERE c.account_scope=:account
             ORDER BY CASE c.case_status WHEN 'triage' THEN 0 WHEN 'investigating' THEN 1 WHEN 'contained' THEN 2 ELSE 3 END,
                      c.updated_at DESC,c.id DESC
             LIMIT 200"
        );
        $statement->execute(['account' => $accountId]);
        $cases = $statement->fetchAll(PDO::FETCH_ASSOC);
        if ($cases === []) {
            return [];
        }

        $caseIds = array_map(static fn (array $case): int => (int) $case['id'], $cases);
        $placeholders = implode(',', array_fill(0, count($caseIds), '?'));
        $notesStatement = $this->database->pdo()->prepare(
            "SELECT n.*,u.public_id AS author_user_public_id,u.display_name AS author_user_name,c.public_id AS case_public_id
             FROM security_incident_notes n
             INNER JOIN security_incident_cases c ON c.id=n.case_id
             INNER JOIN users u ON u.id=n.author_user_id
             WHERE n.case_id IN ({$placeholders})
             ORDER BY n.created_at ASC,n.id ASC"
        );
        foreach ($caseIds as $index => $caseId) {
            $notesStatement->bindValue($index + 1, $caseId, PDO::PARAM_INT);
        }
        $notesStatement->execute();
        $notesByCase = [];
        foreach ($notesStatement->fetchAll(PDO::FETCH_ASSOC) as $note) {
            $content = null;
            $available = true;
            try {
                $content = $this->cipher->decrypt(
                    (string) $note['note_ciphertext'],
                    (string) $note['note_nonce'],
                    (string) $note['note_tag'],
                    implode('|', [
                        'security-incident-note',
                        $accountId,
                        (string) $note['case_public_id'],
                        (string) $note['public_id'],
                    ])
                );
            } catch (Throwable) {
                $available = false;
            }
            $notesByCase[(int) $note['case_id']][] = [
                'public_id' => (string) $note['public_id'],
                'author_user_public_id' => (string) $note['author_user_public_id'],
                'author_user_name' => (string) $note['author_user_name'],
                'content' => $content,
                'content_available' => $available,
                'note_hash' => (string) $note['note_hash'],
                'created_at' => (string) $note['created_at'],
            ];
        }

        return array_map(static function (array $case) use ($notesByCase): array {
            $id = (int) $case['id'];
            unset($case['id']);
            $case['notes'] = $notesByCase[$id] ?? [];
            return $case;
        }, $cases);
    }

    /** @return list<array<string,mixed>> */
    private function responders(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT u.public_id,u.display_name,u.email,au.role,
                    COUNT(DISTINCT CASE WHEN s.revoked_at IS NULL
                      AND s.inactivity_expires_at>UTC_TIMESTAMP()
                      AND s.absolute_expires_at>UTC_TIMESTAMP() THEN s.id END) AS active_sessions
             FROM account_users au
             INNER JOIN users u ON u.id=au.user_id
             LEFT JOIN auth_sessions s ON s.user_id=u.id
             WHERE au.account_id=:account AND au.status='active' AND u.status='active'
               AND au.role IN ('customer_owner','customer_admin','support_member')
             GROUP BY u.id,u.public_id,u.display_name,u.email,au.role
             ORDER BY CASE au.role WHEN 'customer_owner' THEN 0 WHEN 'customer_admin' THEN 1 ELSE 2 END,
                      u.display_name ASC,u.id ASC"
        );
        $statement->execute(['account' => $accountId]);
        return array_map(static fn (array $row): array => [
            'user_public_id' => (string) $row['public_id'],
            'display_name' => (string) $row['display_name'],
            'email' => (string) $row['email'],
            'role' => (string) $row['role'],
            'active_sessions' => (int) $row['active_sessions'],
        ], $statement->fetchAll(PDO::FETCH_ASSOC));
    }

    /** @return array{automatic_promotion_enabled:bool,minimum_risk:string,include_integrity_failures:bool,notify_on_promotion:bool,notify_on_emergency_action:bool,updated_at:?string} */
    private function alertPreferences(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            'SELECT minimum_risk,include_integrity_failures,notify_on_promotion,
                    notify_on_emergency_action,updated_at
             FROM security_alert_preferences WHERE account_scope=:account LIMIT 1'
        );
        $statement->execute(['account' => $accountId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            return [
                'automatic_promotion_enabled' => false,
                'minimum_risk' => 'high',
                'include_integrity_failures' => true,
                'notify_on_promotion' => true,
                'notify_on_emergency_action' => true,
                'updated_at' => null,
            ];
        }
        return [
            'automatic_promotion_enabled' => true,
            'minimum_risk' => (string) $row['minimum_risk'],
            'include_integrity_failures' => (bool) $row['include_integrity_failures'],
            'notify_on_promotion' => (bool) $row['notify_on_promotion'],
            'notify_on_emergency_action' => (bool) $row['notify_on_emergency_action'],
            'updated_at' => $row['updated_at'] === null ? null : (string) $row['updated_at'],
        ];
    }

    /** @return list<array<string,mixed>> */
    private function recentResponseActions(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            'SELECT a.public_id,a.request_id,a.action_type,a.result,a.evidence_hash,a.created_at,
                    c.public_id AS case_public_id,actor.public_id AS actor_user_public_id,
                    actor.display_name AS actor_user_name,target.public_id AS target_user_public_id,
                    target.display_name AS target_user_name
             FROM security_response_actions a
             LEFT JOIN security_incident_cases c ON c.id=a.case_id
             INNER JOIN users actor ON actor.id=a.actor_user_id
             LEFT JOIN users target ON target.id=a.target_user_id
             WHERE a.account_scope=:account
             ORDER BY a.created_at DESC,a.id DESC LIMIT 100'
        );
        $statement->execute(['account' => $accountId]);
        return $statement->fetchAll(PDO::FETCH_ASSOC);
    }

    /** @return array{active:int,users:int} */
    private function activeSessionSummary(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT COUNT(*) AS active_sessions, COUNT(DISTINCT s.user_id) AS active_users
             FROM auth_sessions s
             INNER JOIN account_users au ON au.user_id=s.user_id
             INNER JOIN users u ON u.id=s.user_id
             WHERE au.account_id=:account
               AND au.status='active'
               AND u.status='active'
               AND s.revoked_at IS NULL
               AND s.inactivity_expires_at>UTC_TIMESTAMP()
               AND s.absolute_expires_at>UTC_TIMESTAMP()"
        );
        $statement->execute(['account' => $accountId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC) ?: [];

        return [
            'active' => (int) ($row['active_sessions'] ?? 0),
            'users' => (int) ($row['active_users'] ?? 0),
        ];
    }

    /** @param array<string,mixed> $audit @param array<string,mixed> $operations @param array{active:int,users:int} $sessions @param list<array<string,mixed>> $cases */
    private function riskScore(array $audit, array $operations, array $sessions, array $cases): int
    {
        if (!(bool) $audit['chain_valid']) {
            return 100;
        }

        $activeCases = count(array_filter(
            $cases,
            static fn (array $case): bool => (string) $case['case_status'] !== 'resolved'
        ));
        $uncontainedCases = count(array_filter(
            $cases,
            static fn (array $case): bool => in_array((string) $case['case_status'], ['triage', 'investigating'], true)
        ));

        $score = 0;
        $score += min(40, (int) $audit['summary']['high_or_critical'] * 10);
        $score += min(24, (int) $audit['summary']['denied_or_failed'] * 3);
        $score += min(16, (int) $audit['summary']['integrity_events'] * 4);
        $score += min(20, (int) $operations['metrics']['active_critical'] * 10);
        $score += min(12, (int) $operations['metrics']['incidents_open'] * 3);
        $score += min(12, $activeCases * 3);
        $score += min(12, $uncontainedCases * 4);
        $score += min(8, max(0, $sessions['active'] - $sessions['users']) * 2);

        return min(100, $score);
    }

    private function postureStatus(int $score, bool $chainValid): string
    {
        if (!$chainValid || $score >= 75) {
            return 'critical';
        }
        if ($score >= 45) {
            return 'elevated';
        }
        if ($score >= 20) {
            return 'guarded';
        }
        return 'healthy';
    }

    private function assertCurrentMembership(int $accountId, int $userId, string $role): void
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT role FROM account_users
             WHERE account_id=:account AND user_id=:user AND status='active' LIMIT 1"
        );
        $statement->execute(['account' => $accountId, 'user' => $userId]);
        $storedRole = $statement->fetchColumn();

        if (!is_string($storedRole)
            || !hash_equals($storedRole, $role)
            || !in_array($storedRole, self::ALLOWED_ROLES, true)) {
            throw new AuthPublicException(
                'security_center_access_denied',
                'An active account owner or administrator membership is required.',
                403
            );
        }
    }
}
