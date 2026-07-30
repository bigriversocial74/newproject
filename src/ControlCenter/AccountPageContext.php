<?php

declare(strict_types=1);

namespace Vp3\ControlCenter;

use PDO;
use Vp3\Auth\AuthPublicException;
use Vp3\Http\AuthEndpoint;

final class AccountPageContext
{
    /**
     * @param array<string,mixed> $container
     * @return array{current:array<string,mixed>,accounts:list<array<string,mixed>>,selected:array<string,mixed>,csrf_token:string}
     */
    public static function resolve(array $container): array
    {
        $current = $container['authentication_context']->requireCurrent(
            AuthEndpoint::ip(),
            AuthEndpoint::userAgent()
        );
        $statement = $container['database']->pdo()->prepare(
            "SELECT a.id,a.public_id,a.display_name,a.status,au.role
             FROM account_users au
             JOIN accounts a ON a.id=au.account_id
             WHERE au.user_id=:user AND au.status='active'
               AND au.role IN ('owner','administrator')
               AND a.status='active'
             ORDER BY a.display_name,a.id"
        );
        $statement->execute(['user' => (int) $current['user']['id']]);
        $accounts = $statement->fetchAll(PDO::FETCH_ASSOC);
        if ($accounts === []) {
            throw new AuthPublicException(
                'account_membership_required',
                'An active VP3 owner or administrator account is required.',
                403
            );
        }

        $requested = max(0, (int) ($_GET['account_id'] ?? 0));
        $selected = null;
        foreach ($accounts as $account) {
            if ($requested === 0 || (int) $account['id'] === $requested) {
                $selected = $account;
                break;
            }
        }
        if (!is_array($selected)) {
            $selected = $accounts[0];
        }

        return [
            'current' => $current,
            'accounts' => array_values($accounts),
            'selected' => $selected,
            'csrf_token' => $container['session']->csrfToken(),
        ];
    }
}
