<?php

declare(strict_types=1);
namespace Vp3\Auth;

use DateTimeImmutable;
use PDO;
use RuntimeException;
use Throwable;
use Vp3\Auth\Mail\MailAdapter;
use Vp3\Database;

final class TeamSecurityService
{
    private const CUSTOMER_ROLES = ['customer_owner', 'customer_admin', 'billing_manager', 'support_member'];

    public function __construct(
        private readonly Database $database,
        private readonly MailAdapter $mail,
        private readonly AuthAuditService $audit,
        private readonly string $baseUrl,
        private readonly int $invitationTtlSeconds = 604800
    ) {
    }

    /** @return array<string,mixed> */
    public function overview(int $accountId, int $currentUserId, string $currentSessionPublicId): array
    {
        $account = $this->database->pdo()->prepare(
            'SELECT public_id,display_name,status FROM accounts WHERE id=:account LIMIT 1'
        );
        $account->execute(['account' => $accountId]);
        $accountRow = $account->fetch(PDO::FETCH_ASSOC);
        if (!is_array($accountRow)) {
            throw new RuntimeException('The account was not found.');
        }

        $members = $this->database->pdo()->prepare(
            "SELECT au.user_id,u.public_id,u.email,u.display_name,u.status AS user_status,au.role,au.status,au.created_at,au.updated_at,
                    (SELECT COUNT(*) FROM auth_sessions s WHERE s.user_id=u.id AND s.revoked_at IS NULL
                     AND s.inactivity_expires_at>UTC_TIMESTAMP() AND s.absolute_expires_at>UTC_TIMESTAMP()) AS active_sessions
             FROM account_users au JOIN users u ON u.id=au.user_id
             WHERE au.account_id=:account AND au.status<>'removed'
             ORDER BY FIELD(au.role,'customer_owner','customer_admin','billing_manager','support_member'),u.display_name,u.id"
        );
        $members->execute(['account' => $accountId]);
        $memberRows = array_map(static fn (array $row): array => [
            'user_id' => (int) $row['user_id'],
            'public_id' => (string) $row['public_id'],
            'email' => (string) $row['email'],
            'display_name' => (string) $row['display_name'],
            'user_status' => (string) $row['user_status'],
            'role' => (string) $row['role'],
            'status' => (string) $row['status'],
            'active_sessions' => (int) $row['active_sessions'],
            'current_user' => (int) $row['user_id'] === $currentUserId,
            'created_at' => (string) $row['created_at'],
            'updated_at' => (string) $row['updated_at'],
        ], $members->fetchAll(PDO::FETCH_ASSOC));

        $invitations = $this->database->pdo()->prepare(
            "SELECT public_id,invited_email,role,
                    CASE WHEN status='pending' AND expires_at<=UTC_TIMESTAMP() THEN 'expired' ELSE status END AS status,
                    expires_at,created_at,updated_at
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

        $sessions = $this->database->pdo()->prepare(
            "SELECT session_public_id,last_seen_at,inactivity_expires_at,absolute_expires_at,created_at
             FROM auth_sessions WHERE user_id=:user AND revoked_at IS NULL
               AND inactivity_expires_at>UTC_TIMESTAMP() AND absolute_expires_at>UTC_TIMESTAMP()
             ORDER BY last_seen_at DESC,id DESC"
        );
        $sessions->execute(['user' => $currentUserId]);
        $sessionRows = array_map(static fn (array $row): array => [
            'public_id' => (string) $row['session_public_id'],
            'last_seen_at' => (string) $row['last_seen_at'],
            'inactivity_expires_at' => (string) $row['inactivity_expires_at'],
            'absolute_expires_at' => (string) $row['absolute_expires_at'],
            'created_at' => (string) $row['created_at'],
            'current' => hash_equals($currentSessionPublicId, (string) $row['session_public_id']),
        ], $sessions->fetchAll(PDO::FETCH_ASSOC));

        $events = $this->database->pdo()->prepare(
            "SELECT event_type,result,resource_type,resource_public_id,created_at
             FROM audit_events WHERE (account_id=:account OR (account_id IS NULL AND actor_id=:user))
               AND (event_type LIKE 'auth.%' OR event_type LIKE 'account.%' OR event_type LIKE 'team.%')
             ORDER BY created_at DESC,id DESC LIMIT 100"
        );
        $events->execute(['account' => $accountId, 'user' => $currentUserId]);
        $eventRows = array_map(static fn (array $row): array => [
            'event_type' => (string) $row['event_type'],
            'result' => (string) $row['result'],
            'resource_type' => $row['resource_type'] === null ? null : (string) $row['resource_type'],
            'resource_public_id' => $row['resource_public_id'] === null ? null : (string) $row['resource_public_id'],
            'created_at' => (string) $row['created_at'],
        ], $events->fetchAll(PDO::FETCH_ASSOC));

        $currentMembership = array_values(array_filter(
            $memberRows,
            static fn (array $row): bool => $row['current_user']
        ));
        return [
            'account' => [
                'id' => $accountId,
                'public_id' => (string) $accountRow['public_id'],
                'display_name' => (string) $accountRow['display_name'],
                'status' => (string) $accountRow['status'],
            ],
            'current_role' => $currentMembership[0]['role'] ?? null,
            'members' => $memberRows,
            'invitations' => $inviteRows,
            'sessions' => $sessionRows,
            'security_events' => $eventRows,
            'roles' => self::CUSTOMER_ROLES,
        ];
    }

    /** @return array{public_id:string,status:string,expires_at:string} */
    public function invite(int $accountId, int $actorUserId, string $actorRole, string $email, string $role, string $requestId): array
    {
        $email = strtolower(trim($email));
        $role = trim($role);
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || !in_array($role, self::CUSTOMER_ROLES, true)) {
            throw new AuthPublicException('team_invitation_invalid', 'A valid email address and account role are required.', 422);
        }
        $this->assertRoleAssignment($actorRole, $role);

        $token = self::token(32);
        $publicId = 'INV-' . strtoupper(bin2hex(random_bytes(10)));
        $now = new DateTimeImmutable('now');
        $nowText = $now->format('Y-m-d H:i:s');
        $expires = $now->modify('+' . max(3600, $this->invitationTtlSeconds) . ' seconds');
        $accountName = '';

        $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $actorUserId,
            $actorRole,
            $email,
            $role,
            $requestId,
            $token,
            $publicId,
            $nowText,
            $expires,
            &$accountName
        ): void {
            $this->assertActor($pdo, $accountId, $actorUserId, $actorRole);
            $account = $pdo->prepare(
                "SELECT display_name FROM accounts WHERE id=:account AND status='active' LIMIT 1 FOR UPDATE"
            );
            $account->execute(['account' => $accountId]);
            $accountName = (string) $account->fetchColumn();
            if ($accountName === '') {
                throw new RuntimeException('The active account was not found.');
            }

            $existing = $pdo->prepare(
                "SELECT 1 FROM account_users au JOIN users u ON u.id=au.user_id
                 WHERE au.account_id=:account AND u.email_normalized=:email
                   AND au.status IN ('active','invited','suspended') LIMIT 1"
            );
            $existing->execute(['account' => $accountId, 'email' => $email]);
            if ($existing->fetchColumn()) {
                throw new AuthPublicException('team_member_exists', 'This email already belongs to the account team.', 409);
            }

            $pdo->prepare(
                "UPDATE account_invitations
                 SET status='revoked',revoked_at=:revoked_at,updated_at=:updated_at
                 WHERE account_id=:account AND invited_email_normalized=:email AND status='pending'"
            )->execute([
                'revoked_at' => $nowText,
                'updated_at' => $nowText,
                'account' => $accountId,
                'email' => $email,
            ]);
            $pdo->prepare(
                "INSERT INTO account_invitations
                 (public_id,account_id,invited_email,invited_email_normalized,role,token_hash,status,invited_by_user_id,accepted_by_user_id,
                  request_id,expires_at,accepted_at,revoked_at,created_at,updated_at)
                 VALUES (:public,:account,:email,:normalized,:role,:hash,'pending',:actor,NULL,:request,:expires,NULL,NULL,:created_at,:updated_at)"
            )->execute([
                'public' => $publicId,
                'account' => $accountId,
                'email' => $email,
                'normalized' => $email,
                'role' => $role,
                'hash' => hash('sha256', $token),
                'actor' => $actorUserId,
                'request' => $requestId,
                'expires' => $expires->format('Y-m-d H:i:s'),
                'created_at' => $nowText,
                'updated_at' => $nowText,
            ]);
            $metadata = [
                'invitation_public_id' => $publicId,
                'role' => $role,
                'email_hash' => hash('sha256', $email),
            ];
            $this->receipt($pdo, $accountId, $actorUserId, null, 'team.invited', 'success', $requestId, $metadata);
            $this->audit->record('team.invited', 'success', $actorUserId, $accountId, 'account_invitation', $publicId, $metadata, $requestId);
        });

        $url = rtrim($this->baseUrl, '/') . '/team-invite.php?token=' . rawurlencode($token);
        try {
            $this->mail->send(
                $email,
                'You were invited to a VP3 account',
                "You were invited to {$accountName} on VP3.me. Sign in with this email address and accept the invitation:\n{$url}\n\nThis invitation expires at {$expires->format(DATE_ATOM)}.",
                '<p>You were invited to <strong>' . htmlspecialchars($accountName, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
                . '</strong> on VP3.me.</p><p><a href="' . htmlspecialchars($url, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
                . '">Accept invitation</a></p><p>This invitation expires at '
                . htmlspecialchars($expires->format(DATE_ATOM), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '.</p>'
            );
        } catch (Throwable) {
            throw new AuthPublicException(
                'team_invitation_delivery_failed',
                'The invitation was created, but email delivery failed. Revoke it and try again.',
                503
            );
        }
        return ['public_id' => $publicId, 'status' => 'pending', 'expires_at' => $expires->format(DATE_ATOM)];
    }

    public function acceptInvitation(int $userId, string $userEmail, string $token, string $requestId): int
    {
        $result = $this->database->transaction(function (PDO $pdo) use ($userId, $userEmail, $token, $requestId): array {
            $now = new DateTimeImmutable('now');
            $nowText = $now->format('Y-m-d H:i:s');

            $user = $pdo->prepare(
                "SELECT email_normalized,status FROM users WHERE id=:user LIMIT 1 FOR UPDATE"
            );
            $user->execute(['user' => $userId]);
            $userRow = $user->fetch(PDO::FETCH_ASSOC);
            if (!is_array($userRow) || (string) $userRow['status'] !== 'active') {
                return ['denied' => 'user_inactive'];
            }
            $canonicalEmail = strtolower(trim((string) $userRow['email_normalized']));
            if (!hash_equals($canonicalEmail, strtolower(trim($userEmail)))) {
                return ['denied' => 'email_mismatch'];
            }

            $statement = $pdo->prepare(
                'SELECT * FROM account_invitations WHERE token_hash=:hash LIMIT 1 FOR UPDATE'
            );
            $statement->execute(['hash' => hash('sha256', trim($token))]);
            $invite = $statement->fetch(PDO::FETCH_ASSOC);
            if (!is_array($invite) || (string) $invite['status'] !== 'pending') {
                return ['denied' => 'invalid'];
            }
            if ($now >= new DateTimeImmutable((string) $invite['expires_at'])) {
                $pdo->prepare(
                    "UPDATE account_invitations SET status='expired',updated_at=:updated_at
                     WHERE id=:id AND status='pending'"
                )->execute(['updated_at' => $nowText, 'id' => $invite['id']]);
                $this->receipt(
                    $pdo,
                    (int) $invite['account_id'],
                    $userId,
                    $userId,
                    'team.invitation_accepted',
                    'denied',
                    $requestId,
                    ['reason' => 'expired']
                );
                return ['denied' => 'expired'];
            }
            if (!hash_equals((string) $invite['invited_email_normalized'], $canonicalEmail)) {
                $this->receipt(
                    $pdo,
                    (int) $invite['account_id'],
                    $userId,
                    $userId,
                    'team.invitation_accepted',
                    'denied',
                    $requestId,
                    ['reason' => 'email_mismatch']
                );
                return ['denied' => 'email_mismatch'];
            }

            $pdo->prepare(
                "INSERT INTO account_users (account_id,user_id,role,status,created_at,updated_at)
                 VALUES (:account,:user,:role,'active',:created_at,:updated_at)
                 ON DUPLICATE KEY UPDATE role=VALUES(role),status='active',updated_at=VALUES(updated_at)"
            )->execute([
                'account' => $invite['account_id'],
                'user' => $userId,
                'role' => $invite['role'],
                'created_at' => $nowText,
                'updated_at' => $nowText,
            ]);
            $accepted = $pdo->prepare(
                "UPDATE account_invitations
                 SET status='accepted',accepted_by_user_id=:user,accepted_at=:accepted_at,updated_at=:updated_at
                 WHERE id=:id AND status='pending'"
            );
            $accepted->execute([
                'user' => $userId,
                'accepted_at' => $nowText,
                'updated_at' => $nowText,
                'id' => $invite['id'],
            ]);
            if ($accepted->rowCount() !== 1) {
                return ['denied' => 'invalid'];
            }
            $metadata = [
                'invitation_public_id' => (string) $invite['public_id'],
                'role' => (string) $invite['role'],
            ];
            $this->receipt(
                $pdo,
                (int) $invite['account_id'],
                $userId,
                $userId,
                'team.invitation_accepted',
                'success',
                $requestId,
                $metadata
            );
            $this->audit->record(
                'team.invitation_accepted',
                'success',
                $userId,
                (int) $invite['account_id'],
                'account_invitation',
                (string) $invite['public_id'],
                $metadata,
                $requestId
            );
            return ['account_id' => (int) $invite['account_id']];
        });

        $denied = $result['denied'] ?? null;
        if ($denied === 'email_mismatch') {
            throw new AuthPublicException(
                'team_invitation_email_mismatch',
                'Sign in using the email address that received this invitation.',
                403
            );
        }
        if ($denied === 'user_inactive') {
            throw new AuthPublicException('team_invitation_user_inactive', 'A verified active user is required.', 403);
        }
        if ($denied !== null) {
            throw new AuthPublicException('team_invitation_invalid', 'The invitation is invalid or expired.', 404);
        }
        return (int) $result['account_id'];
    }

    public function revokeInvitation(int $accountId, int $actorUserId, string $publicId, string $requestId): void
    {
        $this->database->transaction(function (PDO $pdo) use ($accountId, $actorUserId, $publicId, $requestId): void {
            $nowText = (new DateTimeImmutable('now'))->format('Y-m-d H:i:s');
            $statement = $pdo->prepare(
                "UPDATE account_invitations
                 SET status='revoked',revoked_at=:revoked_at,updated_at=:updated_at
                 WHERE public_id=:public AND account_id=:account AND status='pending'"
            );
            $statement->execute([
                'revoked_at' => $nowText,
                'updated_at' => $nowText,
                'public' => $publicId,
                'account' => $accountId,
            ]);
            if ($statement->rowCount() !== 1) {
                throw new RuntimeException('The pending invitation was not found.');
            }
            $this->receipt(
                $pdo,
                $accountId,
                $actorUserId,
                null,
                'team.invitation_revoked',
                'success',
                $requestId,
                ['invitation_public_id' => $publicId]
            );
            $this->audit->record(
                'team.invitation_revoked',
                'success',
                $actorUserId,
                $accountId,
                'account_invitation',
                $publicId,
                [],
                $requestId
            );
        });
    }

    public function changeRole(
        int $accountId,
        int $actorUserId,
        string $actorRole,
        string $targetPublicId,
        string $role,
        string $requestId
    ): void {
        $this->assertRoleAssignment($actorRole, $role);
        $this->mutateMembership(
            $accountId,
            $actorUserId,
            $actorRole,
            $targetPublicId,
            $requestId,
            'role_changed',
            function (PDO $pdo, array $target) use ($role): void {
                if ((string) $target['role'] === 'customer_owner' && $role !== 'customer_owner') {
                    $this->assertAnotherOwner($pdo, (int) $target['account_id'], (int) $target['user_id']);
                }
                $pdo->prepare(
                    'UPDATE account_users SET role=:role,updated_at=UTC_TIMESTAMP() WHERE id=:id'
                )->execute(['role' => $role, 'id' => $target['membership_id']]);
            },
            ['role' => $role]
        );
    }

    public function setMembershipStatus(
        int $accountId,
        int $actorUserId,
        string $actorRole,
        string $targetPublicId,
        string $status,
        string $requestId
    ): void {
        if (!in_array($status, ['active', 'suspended', 'removed'], true)) {
            throw new AuthPublicException('team_status_invalid', 'The requested membership status is invalid.', 422);
        }
        $this->mutateMembership(
            $accountId,
            $actorUserId,
            $actorRole,
            $targetPublicId,
            $requestId,
            'status_changed',
            function (PDO $pdo, array $target) use ($status, $actorUserId): void {
                if ((int) $target['user_id'] === $actorUserId && $status !== 'active') {
                    throw new AuthPublicException(
                        'team_self_removal_denied',
                        'Use another active owner to remove or suspend your membership.',
                        409
                    );
                }
                if ((string) $target['role'] === 'customer_owner' && $status !== 'active') {
                    $this->assertAnotherOwner($pdo, (int) $target['account_id'], (int) $target['user_id']);
                }
                $pdo->prepare(
                    'UPDATE account_users SET status=:status,updated_at=UTC_TIMESTAMP() WHERE id=:id'
                )->execute(['status' => $status, 'id' => $target['membership_id']]);
                if ($status !== 'active') {
                    $pdo->prepare(
                        "UPDATE auth_sessions
                         SET revoked_at=UTC_TIMESTAMP(),revocation_reason=:reason,
                             revoked_by_user_id=:actor,updated_at=UTC_TIMESTAMP()
                         WHERE user_id=:user AND revoked_at IS NULL"
                    )->execute([
                        'reason' => 'membership_' . $status,
                        'actor' => $actorUserId,
                        'user' => $target['user_id'],
                    ]);
                }
            },
            ['status' => $status]
        );
    }

    /** @param callable(PDO,array<string,mixed>):void $mutation @param array<string,mixed> $metadata */
    private function mutateMembership(
        int $accountId,
        int $actorUserId,
        string $actorRole,
        string $targetPublicId,
        string $requestId,
        string $action,
        callable $mutation,
        array $metadata
    ): void {
        $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $actorUserId,
            $actorRole,
            $targetPublicId,
            $requestId,
            $action,
            $mutation,
            $metadata
        ): void {
            $this->assertActor($pdo, $accountId, $actorUserId, $actorRole);
            $statement = $pdo->prepare(
                'SELECT au.id AS membership_id,au.account_id,au.user_id,au.role,au.status,u.public_id
                 FROM account_users au JOIN users u ON u.id=au.user_id
                 WHERE au.account_id=:account AND u.public_id=:public LIMIT 1 FOR UPDATE'
            );
            $statement->execute(['account' => $accountId, 'public' => $targetPublicId]);
            $target = $statement->fetch(PDO::FETCH_ASSOC);
            if (!is_array($target)) {
                throw new RuntimeException('The account member was not found.');
            }
            if ($actorRole !== 'customer_owner' && (string) $target['role'] === 'customer_owner') {
                throw new AuthPublicException(
                    'team_owner_change_denied',
                    'Only an account owner can modify another owner.',
                    403
                );
            }
            $mutation($pdo, $target);
            $event = 'team.' . $action;
            $evidence = array_merge($metadata, ['target_public_id' => $targetPublicId]);
            $this->receipt(
                $pdo,
                $accountId,
                $actorUserId,
                (int) $target['user_id'],
                $event,
                'success',
                $requestId,
                $evidence
            );
            $this->audit->record(
                $event,
                'success',
                $actorUserId,
                $accountId,
                'account_member',
                $targetPublicId,
                $evidence,
                $requestId
            );
        });
    }

    private function assertActor(PDO $pdo, int $accountId, int $actorUserId, string $actorRole): void
    {
        if (!in_array($actorRole, ['customer_owner', 'customer_admin'], true)) {
            throw new AuthPublicException(
                'team_permission_denied',
                'The current account role cannot manage team members.',
                403
            );
        }
        $actor = $pdo->prepare(
            "SELECT role FROM account_users
             WHERE account_id=:account AND user_id=:user AND status='active' LIMIT 1 FOR UPDATE"
        );
        $actor->execute(['account' => $accountId, 'user' => $actorUserId]);
        $storedRole = $actor->fetchColumn();
        if (!is_string($storedRole) || !hash_equals($storedRole, $actorRole)) {
            throw new AuthPublicException(
                'team_permission_denied',
                'The current account role cannot manage team members.',
                403
            );
        }
    }

    private function assertRoleAssignment(string $actorRole, string $role): void
    {
        if (!in_array($role, self::CUSTOMER_ROLES, true)) {
            throw new AuthPublicException('team_role_invalid', 'The requested account role is invalid.', 422);
        }
        if ($role === 'customer_owner' && $actorRole !== 'customer_owner') {
            throw new AuthPublicException(
                'team_owner_assignment_denied',
                'Only an account owner can assign the owner role.',
                403
            );
        }
        if (!in_array($actorRole, ['customer_owner', 'customer_admin'], true)) {
            throw new AuthPublicException(
                'team_permission_denied',
                'The current account role cannot manage team members.',
                403
            );
        }
    }

    private function assertAnotherOwner(PDO $pdo, int $accountId, int $excludedUserId): void
    {
        $statement = $pdo->prepare(
            "SELECT COUNT(*) FROM account_users
             WHERE account_id=:account AND user_id<>:excluded AND role='customer_owner' AND status='active'"
        );
        $statement->execute(['account' => $accountId, 'excluded' => $excludedUserId]);
        if ((int) $statement->fetchColumn() < 1) {
            throw new AuthPublicException(
                'team_final_owner_required',
                'The account must retain at least one other active owner.',
                409
            );
        }
    }

    /** @param array<string,mixed> $metadata */
    private function receipt(
        PDO $pdo,
        ?int $accountId,
        ?int $actorUserId,
        ?int $targetUserId,
        string $action,
        string $result,
        string $requestId,
        array $metadata
    ): void {
        $evidence = [
            'action' => $action,
            'result' => $result,
            'account_id' => $accountId,
            'actor_user_id' => $actorUserId,
            'target_user_id' => $targetUserId,
            'metadata' => $metadata,
        ];
        $pdo->prepare(
            'INSERT INTO account_security_receipts
             (public_id,account_id,actor_user_id,target_user_id,action,result,request_id,evidence_hash,created_at)
             VALUES (:public,:account,:actor,:target,:action,:result,:request,:hash,UTC_TIMESTAMP())'
        )->execute([
            'public' => 'SEC-' . strtoupper(bin2hex(random_bytes(10))),
            'account' => $accountId,
            'actor' => $actorUserId,
            'target' => $targetUserId,
            'action' => $action,
            'result' => $result,
            'request' => $requestId,
            'hash' => hash('sha256', json_encode($evidence, JSON_THROW_ON_ERROR)),
        ]);
    }

    private static function token(int $bytes): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }
}
