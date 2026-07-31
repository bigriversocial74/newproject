<?php

declare(strict_types=1);

namespace Vp3\Deployment;

use PDO;
use Vp3\Auth\AuthPublicException;
use Vp3\Database;

final class PlatformOperatorAuthorizer
{
    public function __construct(private readonly Database $database)
    {
    }

    public function assertOperator(int $accountId, int $userId, string $role, bool $ownerOnly = false): void
    {
        if ($accountId <= 0 || $userId <= 0) {
            throw new AuthPublicException('platform_operator_context_invalid', 'A valid platform operator context is required.', 403);
        }

        $allowed = $ownerOnly ? ['customer_owner'] : ['customer_owner', 'customer_admin'];
        if (!in_array($role, $allowed, true)) {
            throw new AuthPublicException(
                'platform_operator_role_denied',
                $ownerOnly ? 'A platform owner membership is required.' : 'A platform owner or administrator membership is required.',
                403
            );
        }

        $statement = $this->database->pdo()->prepare(
            "SELECT au.role
             FROM platform_operator_accounts po
             INNER JOIN accounts a ON a.id=po.account_scope AND a.status='active'
             INNER JOIN account_users au ON au.account_id=po.account_scope
             WHERE po.account_scope=:account_id AND po.operator_status='active'
               AND au.user_id=:user_id AND au.status='active' LIMIT 1"
        );
        $statement->execute(['account_id' => $accountId, 'user_id' => $userId]);
        $storedRole = $statement->fetchColumn();
        if (!is_string($storedRole) || !hash_equals($storedRole, $role) || !in_array($storedRole, $allowed, true)) {
            throw new AuthPublicException(
                'platform_operator_access_denied',
                'This account is not authorized to manage VP3 platform releases.',
                403
            );
        }
    }

    /** @return array{account_id:int,account_public_id:string,account_name:string,role:string} */
    public function resolveByPublicAccount(string $accountPublicId, int $userId): array
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT a.id AS account_id,a.public_id AS account_public_id,a.display_name AS account_name,au.role
             FROM platform_operator_accounts po
             INNER JOIN accounts a ON a.id=po.account_scope
             INNER JOIN account_users au ON au.account_id=a.id
             WHERE a.public_id=:public_id AND a.status='active' AND po.operator_status='active'
               AND au.user_id=:user_id AND au.status='active'
               AND au.role IN ('customer_owner','customer_admin') LIMIT 1"
        );
        $statement->execute(['public_id' => trim($accountPublicId), 'user_id' => $userId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new AuthPublicException(
                'platform_operator_access_denied',
                'This account is not authorized to manage VP3 platform releases.',
                403
            );
        }
        return [
            'account_id' => (int) $row['account_id'],
            'account_public_id' => (string) $row['account_public_id'],
            'account_name' => (string) $row['account_name'],
            'role' => (string) $row['role'],
        ];
    }
}
