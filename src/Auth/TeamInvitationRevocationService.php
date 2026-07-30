<?php

declare(strict_types=1);

namespace Vp3\Auth;

use PDO;
use Vp3\Database;

final class TeamInvitationRevocationService
{
    private const MANAGER_ROLES = ['customer_owner', 'customer_admin'];

    public function __construct(
        private readonly Database $database,
        private readonly AuthAuditService $audit
    ) {
    }

    public function revoke(
        int $accountId,
        int $actorUserId,
        string $actorRole,
        string $invitationPublicId,
        string $requestId
    ): void {
        if ($accountId < 1 || $actorUserId < 1 || !in_array($actorRole, self::MANAGER_ROLES, true)) {
            throw new AuthPublicException(
                'team_permission_denied',
                'The current account role cannot manage team invitations.',
                403
            );
        }
        if (!preg_match('/^INV-[A-F0-9]{20}$/', trim($invitationPublicId))) {
            throw new AuthPublicException('team_invitation_invalid', 'The invitation was not found.', 404);
        }

        $result = $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $actorUserId,
            $actorRole,
            $invitationPublicId,
            $requestId
        ): string {
            $existingReceipt = $pdo->prepare(
                "SELECT result FROM account_security_receipts
                 WHERE account_id=:account AND action='team.invitation_revoked' AND request_id=:request
                 LIMIT 1 FOR UPDATE"
            );
            $existingReceipt->execute(['account' => $accountId, 'request' => $requestId]);
            $existingResult = $existingReceipt->fetchColumn();
            if ($existingResult === 'success') {
                return 'success';
            }
            if (is_string($existingResult)) {
                return 'denied_replay';
            }

            $actor = $pdo->prepare(
                "SELECT role FROM account_users
                 WHERE account_id=:account AND user_id=:actor AND status='active'
                 LIMIT 1 FOR UPDATE"
            );
            $actor->execute(['account' => $accountId, 'actor' => $actorUserId]);
            $storedRole = $actor->fetchColumn();
            if (!is_string($storedRole)
                || !hash_equals($storedRole, $actorRole)
                || !in_array($storedRole, self::MANAGER_ROLES, true)) {
                $metadata = ['reason' => 'actor_membership_changed'];
                $this->receipt(
                    $pdo,
                    $accountId,
                    $actorUserId,
                    'team.invitation_revoked',
                    'denied',
                    $requestId,
                    $metadata
                );
                $this->audit->record(
                    'team.invitation_revoked',
                    'denied',
                    $actorUserId,
                    $accountId,
                    'account_invitation',
                    $invitationPublicId,
                    $metadata,
                    $requestId
                );
                return 'permission_denied';
            }

            $statement = $pdo->prepare(
                "UPDATE account_invitations
                 SET status='revoked',revoked_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP()
                 WHERE public_id=:public AND account_id=:account AND status='pending'
                   AND expires_at>UTC_TIMESTAMP()"
            );
            $statement->execute(['public' => $invitationPublicId, 'account' => $accountId]);
            if ($statement->rowCount() !== 1) {
                $metadata = ['reason' => 'not_pending_or_not_found'];
                $this->receipt(
                    $pdo,
                    $accountId,
                    $actorUserId,
                    'team.invitation_revoked',
                    'denied',
                    $requestId,
                    $metadata
                );
                $this->audit->record(
                    'team.invitation_revoked',
                    'denied',
                    $actorUserId,
                    $accountId,
                    'account_invitation',
                    $invitationPublicId,
                    $metadata,
                    $requestId
                );
                return 'not_found';
            }

            $metadata = ['invitation_public_id' => $invitationPublicId];
            $this->receipt(
                $pdo,
                $accountId,
                $actorUserId,
                'team.invitation_revoked',
                'success',
                $requestId,
                $metadata
            );
            $this->audit->record(
                'team.invitation_revoked',
                'success',
                $actorUserId,
                $accountId,
                'account_invitation',
                $invitationPublicId,
                $metadata,
                $requestId
            );
            return 'success';
        });

        if ($result === 'permission_denied') {
            throw new AuthPublicException(
                'team_permission_denied',
                'The current account role cannot manage team invitations.',
                403
            );
        }
        if ($result === 'denied_replay') {
            throw new AuthPublicException(
                'team_request_replayed_denied',
                'This invitation request was already denied.',
                409
            );
        }
        if ($result !== 'success') {
            throw new AuthPublicException('team_invitation_invalid', 'The invitation was not found.', 404);
        }
    }

    /** @param array<string,mixed> $metadata */
    private function receipt(
        PDO $pdo,
        int $accountId,
        int $actorUserId,
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
            'metadata' => $metadata,
        ];
        $pdo->prepare(
            'INSERT INTO account_security_receipts
             (public_id,account_id,actor_user_id,target_user_id,action,result,request_id,evidence_hash,created_at)
             VALUES (:public,:account,:actor,NULL,:action,:result,:request,:hash,UTC_TIMESTAMP())'
        )->execute([
            'public' => 'SEC-' . strtoupper(bin2hex(random_bytes(10))),
            'account' => $accountId,
            'actor' => $actorUserId,
            'action' => $action,
            'result' => $result,
            'request' => $requestId,
            'hash' => hash('sha256', json_encode($evidence, JSON_THROW_ON_ERROR)),
        ]);
    }
}
