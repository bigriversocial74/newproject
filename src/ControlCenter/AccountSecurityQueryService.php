<?php

declare(strict_types=1);

namespace Vp3\ControlCenter;

use PDO;
use RuntimeException;
use Vp3\Auth\MfaService;
use Vp3\Database;

final class AccountSecurityQueryService
{
    public function __construct(
        private readonly Database $database,
        private readonly MfaService $mfa
    ) {
    }

    /** @return array<string,mixed> */
    public function snapshot(int $accountId, int $userId, string $role, string $currentSessionPublicId): array
    {
        $canManageTeam = in_array($role, ['customer_owner', 'customer_admin'], true);
        $account = $this->database->pdo()->prepare('SELECT public_id,display_name,status FROM accounts WHERE id=:account LIMIT 1');
        $account->execute(['account' => $accountId]);
        $accountRow = $account->fetch(PDO::FETCH_ASSOC);
        if (!is_array($accountRow)) throw new RuntimeException('The account was not found.');

        $memberSql = "SELECT au.user_id,u.public_id,u.email,u.display_name,u.status AS user_status,au.role,au.status,au.created_at,au.updated_at,
                             (SELECT COUNT(*) FROM auth_sessions s WHERE s.user_id=u.id AND s.revoked_at IS NULL
                              AND s.inactivity_expires_at>UTC_TIMESTAMP() AND s.absolute_expires_at>UTC_TIMESTAMP()) AS active_sessions
                      FROM account_users au JOIN users u ON u.id=au.user_id
                      WHERE au.account_id=:account AND au.status<>'removed'";
        $memberParams = ['account' => $accountId];
        if (!$canManageTeam) {
            $memberSql .= ' AND au.user_id=:current_user';
            $memberParams['current_user'] = $userId;
        }
        $memberSql .= " ORDER BY FIELD(au.role,'customer_owner','customer_admin','billing_manager','support_member'),u.display_name,u.id";
        $members = $this->database->pdo()->prepare($memberSql);
        $members->execute($memberParams);
        $memberRows = array_map(static fn (array $row): array => [
            'public_id' => (string) $row['public_id'],
            'email' => (string) $row['email'],
            'display_name' => (string) $row['display_name'],
            'user_status' => (string) $row['user_status'],
            'role' => (string) $row['role'],
            'status' => (string) $row['status'],
            'active_sessions' => (int) $row['active_sessions'],
            'current_user' => (int) $row['user_id'] === $userId,
            'created_at' => (string) $row['created_at'],
            'updated_at' => (string) $row['updated_at'],
        ], $members->fetchAll(PDO::FETCH_ASSOC));

        $inviteRows = [];
        if ($canManageTeam) {
            $invitations = $this->database->pdo()->prepare(
                "SELECT public_id,invited_email,role,CASE WHEN status='pending' AND expires_at<=UTC_TIMESTAMP() THEN 'expired' ELSE status END AS status,expires_at,created_at,updated_at
                 FROM account_invitations WHERE account_id=:account
                 ORDER BY FIELD(status,'pending','accepted','revoked','expired'),created_at DESC,id DESC LIMIT 100"
            );
            $invitations->execute(['account' => $accountId]);
            $inviteRows = array_map(static fn (array $row): array => [
                'public_id' => (string) $row['public_id'],
                'email' => (string) $row['invited_email'],
                'role' => (string) $row['role'],
                'status' => (string) $row['status'],
                'expires_at' => (string) $row['expires_at'],
                'created_at' => (string) $row['created_at'],
                'updated_at' => (string) $row['updated_at'],
            ], $invitations->fetchAll(PDO::FETCH_ASSOC));
        }

        $sessions = $this->database->pdo()->prepare(
            "SELECT session_public_id,last_seen_at,inactivity_expires_at,absolute_expires_at,created_at
             FROM auth_sessions WHERE user_id=:user AND revoked_at IS NULL
               AND inactivity_expires_at>UTC_TIMESTAMP() AND absolute_expires_at>UTC_TIMESTAMP()
             ORDER BY last_seen_at DESC,id DESC"
        );
        $sessions->execute(['user' => $userId]);
        $sessionRows = array_map(static fn (array $row): array => [
            'public_id' => (string) $row['session_public_id'],
            'last_seen_at' => (string) $row['last_seen_at'],
            'inactivity_expires_at' => (string) $row['inactivity_expires_at'],
            'absolute_expires_at' => (string) $row['absolute_expires_at'],
            'created_at' => (string) $row['created_at'],
            'current' => hash_equals($currentSessionPublicId, (string) $row['session_public_id']),
        ], $sessions->fetchAll(PDO::FETCH_ASSOC));

        $eventSql = "SELECT event_type,result,resource_type,resource_public_id,created_at
                     FROM audit_events WHERE ";
        $eventParams = [];
        if ($canManageTeam) {
            $eventSql .= '(account_id=:account OR (account_id IS NULL AND actor_id=:user))';
            $eventParams = ['account' => $accountId, 'user' => $userId];
        } else {
            $eventSql .= 'actor_id=:user';
            $eventParams = ['user' => $userId];
        }
        $eventSql .= " AND (event_type LIKE 'auth.%' OR event_type LIKE 'account.%' OR event_type LIKE 'team.%')
                       ORDER BY created_at DESC,id DESC LIMIT 100";
        $events = $this->database->pdo()->prepare($eventSql);
        $events->execute($eventParams);
        $eventRows = array_map(static fn (array $row): array => [
            'event_type' => (string) $row['event_type'],
            'result' => (string) $row['result'],
            'resource_type' => $row['resource_type'] === null ? null : (string) $row['resource_type'],
            'resource_public_id' => $row['resource_public_id'] === null ? null : (string) $row['resource_public_id'],
            'created_at' => (string) $row['created_at'],
        ], $events->fetchAll(PDO::FETCH_ASSOC));

        return [
            'account' => ['id' => $accountId, 'public_id' => (string) $accountRow['public_id'], 'display_name' => (string) $accountRow['display_name'], 'status' => (string) $accountRow['status']],
            'current_role' => $role,
            'can_manage_team' => $canManageTeam,
            'members' => $memberRows,
            'invitations' => $inviteRows,
            'sessions' => $sessionRows,
            'security_events' => $eventRows,
            'mfa' => $this->mfa->status($userId),
            'roles' => $canManageTeam ? ['customer_owner', 'customer_admin', 'billing_manager', 'support_member'] : [],
        ];
    }
}
