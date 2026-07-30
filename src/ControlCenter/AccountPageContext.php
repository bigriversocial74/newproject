<?php

declare(strict_types=1);

namespace Vp3\ControlCenter;

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
        $current = $container['authentication_context']->requireCurrent(
            AuthEndpoint::ip(),
            AuthEndpoint::userAgent()
        );
        $resolver = new PublicAccountIdentityResolver($container['database']);
        $accounts = $resolver->memberships((int) $current['user']['id'], $allowedRoles);
        if ($accounts === []) {
            throw new AuthPublicException(
                'account_membership_required',
                'An active VP3 membership with permission for this page is required.',
                403
            );
        }
        $requested = $resolver->publicId((string) ($_GET['account'] ?? $_GET['account_public_id'] ?? ''));
        $resolved = $resolver->resolve((int) $current['user']['id'], $requested, $allowedRoles);
        $selected = null;
        foreach ($accounts as $account) {
            if (hash_equals((string) $account['public_id'], $resolved['account_public_id'])) {
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
            'accounts' => $accounts,
            'selected' => $selected,
            'csrf_token' => $container['session']->csrfToken(),
        ];
    }
}
