<?php

declare(strict_types=1);

namespace Vp3\Security;

use PDO;
use Vp3\Auth\AuthPublicException;
use Vp3\Database;
use Vp3\Operations\OperationalIncidentService;

final class SecurityAlertPreferenceService
{
    private const MANAGER_ROLES = ['customer_owner', 'customer_admin'];
    private const RISK_LEVELS = ['low', 'medium', 'high', 'critical'];

    public function __construct(
        private readonly Database $database,
        private readonly OperationalIncidentService $incidents,
        private readonly SecurityAuditService $audit
    ) {
    }

    /** @return array{automatic_promotion_enabled:bool,minimum_risk:string,include_integrity_failures:bool,notify_on_promotion:bool,notify_on_emergency_action:bool,updated_at:?string} */
    public function snapshot(int $accountId, int $userId, string $role): array
    {
        $this->assertManager($this->database->pdo(), $accountId, $userId, $role, false);
        return $this->policyForAccount($accountId);
    }

    /** @return array{automatic_promotion_enabled:bool,minimum_risk:string,include_integrity_failures:bool,notify_on_promotion:bool,notify_on_emergency_action:bool,updated_at:?string} */
    public function save(
        int $accountId,
        int $userId,
        string $role,
        bool $enabled,
        string $minimumRisk,
        bool $includeIntegrityFailures,
        bool $notifyOnPromotion,
        bool $notifyOnEmergencyAction,
        string $requestId
    ): array {
        $minimumRisk = strtolower(trim($minimumRisk));
        $requestId = trim($requestId);
        if (!in_array($minimumRisk, self::RISK_LEVELS, true) || !preg_match('/^[A-Za-z0-9._:-]{8,80}$/', $requestId)) {
            throw new \InvalidArgumentException('Valid security alert preferences and a request ID are required.');
        }

        $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $userId,
            $role,
            $enabled,
            $minimumRisk,
            $includeIntegrityFailures,
            $notifyOnPromotion,
            $notifyOnEmergencyAction
        ): void {
            $this->assertManager($pdo, $accountId, $userId, $role, true);
            $now = $this->now();
            $pdo->prepare(
                'INSERT INTO security_alert_preferences
                 (account_scope,automatic_promotion_enabled,minimum_risk,include_integrity_failures,
                  notify_on_promotion,notify_on_emergency_action,updated_by_user_id,created_at,updated_at)
                 VALUES (:account,:automatic_enabled,:minimum_risk,:include_integrity,
                         :notify_promotion,:notify_emergency,:user,:created,:updated)
                 ON DUPLICATE KEY UPDATE automatic_promotion_enabled=VALUES(automatic_promotion_enabled),
                   minimum_risk=VALUES(minimum_risk),include_integrity_failures=VALUES(include_integrity_failures),
                   notify_on_promotion=VALUES(notify_on_promotion),
                   notify_on_emergency_action=VALUES(notify_on_emergency_action),
                   updated_by_user_id=VALUES(updated_by_user_id),updated_at=VALUES(updated_at)'
            )->execute([
                'account' => $accountId,
                'automatic_enabled' => $enabled ? 1 : 0,
                'minimum_risk' => $minimumRisk,
                'include_integrity' => $includeIntegrityFailures ? 1 : 0,
                'notify_promotion' => $notifyOnPromotion ? 1 : 0,
                'notify_emergency' => $notifyOnEmergencyAction ? 1 : 0,
                'user' => $userId,
                'created' => $now,
                'updated' => $now,
            ]);
        });

        $saved = $this->policyForAccount($accountId);
        $this->audit->record(
            'security.alert_preferences.updated',
            'platform',
            'medium',
            'success',
            $accountId,
            'account_user',
            $userId,
            null,
            'security_alert_preferences',
            null,
            [
                'automatic_promotion_enabled' => $saved['automatic_promotion_enabled'],
                'minimum_risk' => $saved['minimum_risk'],
                'include_integrity_failures' => $saved['include_integrity_failures'],
                'notify_on_promotion' => $saved['notify_on_promotion'],
                'notify_on_emergency_action' => $saved['notify_on_emergency_action'],
            ],
            $requestId
        );
        return $saved;
    }

    /** @return array{automatic_promotion_enabled:bool,minimum_risk:string,include_integrity_failures:bool,notify_on_promotion:bool,notify_on_emergency_action:bool,updated_at:?string} */
    public function policyForAccount(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            'SELECT automatic_promotion_enabled,minimum_risk,include_integrity_failures,
                    notify_on_promotion,notify_on_emergency_action,updated_at
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
            'automatic_promotion_enabled' => (bool) $row['automatic_promotion_enabled'],
            'minimum_risk' => (string) $row['minimum_risk'],
            'include_integrity_failures' => (bool) $row['include_integrity_failures'],
            'notify_on_promotion' => (bool) $row['notify_on_promotion'],
            'notify_on_emergency_action' => (bool) $row['notify_on_emergency_action'],
            'updated_at' => $row['updated_at'] === null ? null : (string) $row['updated_at'],
        ];
    }

    public function suppressPromotionNotifications(int $incidentId): void
    {
        if ($incidentId < 1) {
            return;
        }
        $this->database->pdo()->prepare(
            "DELETE FROM operational_notifications
             WHERE incident_id=:incident AND status='queued' AND event_type IN ('opened','escalated')"
        )->execute(['incident' => $incidentId]);
    }

    public function routeEmergencyAction(int $accountId, int $actorUserId, string $requestId): void
    {
        $policy = $this->policyForAccount($accountId);
        if (!$policy['notify_on_emergency_action']) {
            return;
        }

        $statement = $this->database->pdo()->prepare(
            "SELECT id,public_id,case_id,target_user_id,evidence_hash,created_at
             FROM security_response_actions
             WHERE account_scope=:account AND request_id=:request_id
               AND action_type='emergency_revoke_sessions' AND result='success' LIMIT 1"
        );
        $statement->execute(['account' => $accountId, 'request_id' => trim($requestId)]);
        $action = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($action)) {
            return;
        }

        $this->incidents->open(
            $accountId,
            'security_response_action',
            (int) $action['id'],
            'critical',
            'Emergency security response performed',
            [
                'response_action_public_id' => (string) $action['public_id'],
                'case_id' => $action['case_id'] === null ? null : (int) $action['case_id'],
                'target_user_id_hash' => hash('sha256', (string) ($action['target_user_id'] ?? '')),
                'evidence_hash' => (string) $action['evidence_hash'],
                'actor_user_id_hash' => hash('sha256', (string) $actorUserId),
            ],
            false
        );
    }

    /** @param list<string> $allowedRoles */
    private function assertManager(PDO $pdo, int $accountId, int $userId, string $role, bool $lock): void
    {
        if ($accountId < 1 || $userId < 1 || !in_array($role, self::MANAGER_ROLES, true)) {
            throw new AuthPublicException('security_alert_access_denied', 'An active account owner or administrator is required.', 403);
        }
        $statement = $pdo->prepare(
            "SELECT role FROM account_users
             WHERE account_id=:account AND user_id=:user AND status='active' LIMIT 1" . ($lock ? ' FOR UPDATE' : '')
        );
        $statement->execute(['account' => $accountId, 'user' => $userId]);
        $storedRole = $statement->fetchColumn();
        if (!is_string($storedRole) || !hash_equals($storedRole, $role) || !in_array($storedRole, self::MANAGER_ROLES, true)) {
            throw new AuthPublicException('security_alert_access_denied', 'An active account owner or administrator is required.', 403);
        }
    }

    private function now(): string
    {
        return (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s.u');
    }
}
