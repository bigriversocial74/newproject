<?php

declare(strict_types=1);

namespace Vp3\Deployment;

use PDO;
use RuntimeException;
use Vp3\Database;

final class PlatformOperatorGrantService
{
    public function __construct(private readonly Database $database)
    {
    }

    /** @return array<string,mixed> */
    public function grant(string $accountPublicId, string $ownerUserPublicId, string $requestId): array
    {
        return $this->change($accountPublicId, $ownerUserPublicId, $requestId, 'grant');
    }

    /** @return array<string,mixed> */
    public function revoke(string $accountPublicId, string $ownerUserPublicId, string $requestId): array
    {
        return $this->change($accountPublicId, $ownerUserPublicId, $requestId, 'revoke');
    }

    /** @return array<string,mixed> */
    private function change(
        string $accountPublicId,
        string $ownerUserPublicId,
        string $requestId,
        string $action
    ): array {
        $accountPublicId = trim($accountPublicId);
        $ownerUserPublicId = trim($ownerUserPublicId);
        $requestId = trim($requestId);
        if (!in_array($action, ['grant', 'revoke'], true)
            || !preg_match('/^[A-Za-z0-9._:-]{8,80}$/', $requestId)) {
            throw new RuntimeException('A valid platform operator access request is required.');
        }

        return $this->database->transaction(function (PDO $pdo) use (
            $accountPublicId,
            $ownerUserPublicId,
            $requestId,
            $action
        ): array {
            $identity = $this->resolveOwner($pdo, $accountPublicId, $ownerUserPublicId);
            $actionType = $action . '_platform_operator';
            $evidence = hash('sha256', implode('|', [
                (string) $identity['account_public_id'],
                (string) $identity['user_public_id'],
                $action,
            ]));
            $prior = $pdo->prepare(
                'SELECT evidence_hash FROM platform_release_control_receipts
                 WHERE account_scope=:account_scope AND request_id=:request_id
                   AND action_type=:action_type LIMIT 1 FOR UPDATE'
            );
            $prior->execute([
                'account_scope' => (int) $identity['account_id'],
                'request_id' => $requestId,
                'action_type' => $actionType,
            ]);
            $priorHash = $prior->fetchColumn();
            if (is_string($priorHash)) {
                if (!hash_equals($priorHash, $evidence)) {
                    throw new RuntimeException('The platform operator access request ID has conflicting evidence.');
                }
                return $this->publicGrant($pdo, (int) $identity['account_id']);
            }

            $now = gmdate('Y-m-d H:i:s') . '.000000';
            $existing = $pdo->prepare(
                'SELECT id FROM platform_operator_accounts WHERE account_scope=:account_scope LIMIT 1 FOR UPDATE'
            );
            $existing->execute(['account_scope' => (int) $identity['account_id']]);
            $id = $existing->fetchColumn();
            if ($action === 'grant') {
                if ($id === false) {
                    $pdo->prepare(
                        "INSERT INTO platform_operator_accounts
                         (public_id,account_scope,operator_status,granted_by_user_id,granted_at,revoked_at,created_at,updated_at)
                         VALUES (:public_id,:account_scope,'active',:user_id,:granted_at,NULL,:created_at,:updated_at)"
                    )->execute([
                        'public_id' => 'POA-' . strtoupper(bin2hex(random_bytes(10))),
                        'account_scope' => (int) $identity['account_id'],
                        'user_id' => (int) $identity['user_id'],
                        'granted_at' => $now,
                        'created_at' => $now,
                        'updated_at' => $now,
                    ]);
                } else {
                    $pdo->prepare(
                        "UPDATE platform_operator_accounts
                         SET operator_status='active',granted_by_user_id=:user_id,granted_at=:granted_at,
                             revoked_at=NULL,updated_at=:updated_at WHERE id=:id"
                    )->execute([
                        'user_id' => (int) $identity['user_id'],
                        'granted_at' => $now,
                        'updated_at' => $now,
                        'id' => (int) $id,
                    ]);
                }
            } else {
                if ($id === false) {
                    throw new RuntimeException('The platform operator account is not currently registered.');
                }
                $pdo->prepare(
                    "UPDATE platform_operator_accounts
                     SET operator_status='revoked',revoked_at=:revoked_at,updated_at=:updated_at WHERE id=:id"
                )->execute(['revoked_at' => $now, 'updated_at' => $now, 'id' => (int) $id]);
            }

            $pdo->prepare(
                'INSERT INTO platform_release_control_receipts
                 (public_id,account_scope,promotion_id,request_id,action_type,result,evidence_hash,created_at)
                 VALUES (:public_id,:account_scope,NULL,:request_id,:action_type,\'success\',:evidence_hash,:created_at)'
            )->execute([
                'public_id' => 'PRR-' . strtoupper(bin2hex(random_bytes(10))),
                'account_scope' => (int) $identity['account_id'],
                'request_id' => $requestId,
                'action_type' => $actionType,
                'evidence_hash' => $evidence,
                'created_at' => $now,
            ]);
            return $this->publicGrant($pdo, (int) $identity['account_id']);
        });
    }

    /** @return array<string,mixed> */
    private function resolveOwner(PDO $pdo, string $accountPublicId, string $ownerUserPublicId): array
    {
        $resolve = $pdo->prepare(
            "SELECT a.id AS account_id,a.public_id AS account_public_id,a.display_name,
                    u.id AS user_id,u.public_id AS user_public_id,au.role
             FROM accounts a
             INNER JOIN account_users au ON au.account_id=a.id
             INNER JOIN users u ON u.id=au.user_id
             WHERE a.public_id=:account_public_id AND a.status='active'
               AND u.public_id=:user_public_id AND u.status='active'
               AND au.status='active' AND au.role='customer_owner' LIMIT 1"
        );
        $resolve->execute([
            'account_public_id' => $accountPublicId,
            'user_public_id' => $ownerUserPublicId,
        ]);
        $identity = $resolve->fetch(PDO::FETCH_ASSOC);
        if (!is_array($identity)) {
            throw new RuntimeException('The platform operator account and active owner identity were not found.');
        }
        return $identity;
    }

    /** @return array<string,mixed> */
    private function publicGrant(PDO $pdo, int $accountId): array
    {
        $statement = $pdo->prepare(
            "SELECT po.public_id,po.operator_status,po.granted_at,po.revoked_at,
                    a.public_id AS account_public_id,a.display_name AS account_name,
                    u.public_id AS granted_by_user_public_id
             FROM platform_operator_accounts po
             INNER JOIN accounts a ON a.id=po.account_scope
             INNER JOIN users u ON u.id=po.granted_by_user_id
             WHERE po.account_scope=:account_scope LIMIT 1"
        );
        $statement->execute(['account_scope' => $accountId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('The platform operator grant could not be loaded.');
        }
        return $row;
    }
}
