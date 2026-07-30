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
        return self::resolveForRoles($container, ['customer_owner', 'customer_admin']);
    }

    /**
     * @param array<string,mixed> $container
     * @param list<string> $allowedRoles
     * @return array{current:array<string,mixed>,accounts:list<array<string,mixed>>,selected:array<string,mixed>,csrf_token:string}
     */
    public static function resolveForRoles(array $container, array $allowedRoles): array
    {
        $roles = self::roles($allowedRoles);
        $current = $container['authentication_context']->requireCurrent(
            AuthEndpoint::ip(),
            AuthEndpoint::userAgent()
        );
        $placeholders = implode(',', array_fill(0, count($roles), '?'));
        $statement = $container['database']->pdo()->prepare(
            "SELECT a.id,a.public_id,a.display_name,a.status,au.role
             FROM account_users au
             JOIN accounts a ON a.id=au.account_id
             WHERE au.user_id=? AND au.status='active'
               AND au.role IN ({$placeholders})
               AND a.status='active'
             ORDER BY a.display_name,a.id"
        );
        $statement->execute([(int) $current['user']['id'], ...$roles]);
        $accounts = $statement->fetchAll(PDO::FETCH_ASSOC);
        if ($accounts === []) {
            throw new AuthPublicException(
                'account_membership_required',
                'An active VP3 membership with permission for this page is required.',
                403
            );
        }

        $requested = trim((string) ($_GET['account'] ?? $_GET['account_public_id'] ?? ''));
        if ($requested !== '' && !preg_match('/^[A-Za-z0-9._:-]{3,64}$/', $requested)) {
            throw new AuthPublicException(
                'account_identity_invalid',
                'The selected VP3 account identity is invalid.',
                400
            );
        }
        $selected = null;
        foreach ($accounts as $account) {
            if ($requested === '' || hash_equals((string) $account['public_id'], $requested)) {
                $selected = $account;
                break;
            }
        }
        if (!is_array($selected)) {
            throw new AuthPublicException(
                'account_membership_required',
                'The selected VP3 account is not available to this membership.',
                403
            );
        }

        return [
            'current' => $current,
            'accounts' => array_values($accounts),
            'selected' => $selected,
            'csrf_token' => $container['session']->csrfToken(),
        ];
    }

    /** @param list<string> $roles @return list<string> */
    private static function roles(array $roles): array
    {
        $allowed = ['customer_owner', 'customer_admin', 'billing_manager', 'support_member'];
        $normalized = array_values(array_unique(array_filter(
            array_map(static fn (mixed $role): string => trim((string) $role), $roles),
            static fn (string $role): bool => in_array($role, $allowed, true)
        )));
        if ($normalized === []) {
            throw new AuthPublicException('account_role_invalid', 'The account role policy is invalid.', 500);
        }
        return $normalized;
    }
}
