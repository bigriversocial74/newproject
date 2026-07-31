<?php

declare(strict_types=1);

namespace Vp3\Security;

use PDO;
use Vp3\Auth\AuthPublicException;
use Vp3\Database;
use Vp3\Operations\OperationsControlCenterQueryService;

final class SecurityCenterQueryService
{
    private const ALLOWED_ROLES = ['customer_owner', 'customer_admin'];

    public function __construct(private readonly Database $database)
    {
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
        $riskScore = $this->riskScore($audit, $operations, $sessions);

        return [
            'permissions' => [
                'can_view' => true,
                'can_export' => true,
                'can_manage_incidents' => true,
                'can_manage_sessions' => true,
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
            ],
            'audit_events' => $audit['events'],
            'incidents' => array_values(array_filter(
                $operations['incidents'],
                static fn (array $incident): bool => (string) $incident['status'] !== 'resolved'
            )),
            'recent_incident_events' => array_slice($operations['incident_events'], 0, 50),
        ];
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

    /** @param array<string,mixed> $audit @param array<string,mixed> $operations @param array{active:int,users:int} $sessions */
    private function riskScore(array $audit, array $operations, array $sessions): int
    {
        if (!(bool) $audit['chain_valid']) {
            return 100;
        }

        $score = 0;
        $score += min(40, (int) $audit['summary']['high_or_critical'] * 10);
        $score += min(24, (int) $audit['summary']['denied_or_failed'] * 3);
        $score += min(16, (int) $audit['summary']['integrity_events'] * 4);
        $score += min(20, (int) $operations['metrics']['active_critical'] * 10);
        $score += min(12, (int) $operations['metrics']['incidents_open'] * 3);
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
