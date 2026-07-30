<?php

declare(strict_types=1);

namespace Vp3\ControlCenter;

use PDO;
use Vp3\Auth\AuthPublicException;
use Vp3\Database;

final class PublicAccountIdentityResolver
{
    private const ALLOWED_ROLES = ['customer_owner', 'customer_admin', 'billing_manager', 'support_member'];

    public function __construct(private readonly Database $database)
    {
    }

    /** @param list<string> $allowedRoles @return list<array<string,mixed>> */
    public function memberships(int $userId, array $allowedRoles): array
    {
        $roles = $this->roles($allowedRoles);
        $placeholders = implode(',', array_fill(0, count($roles), '?'));
        $statement = $this->database->pdo()->prepare(
            "SELECT a.id,a.public_id,a.display_name,a.status,au.role
             FROM account_users au
             JOIN accounts a ON a.id=au.account_id
             WHERE au.user_id=? AND au.status='active'
               AND au.role IN ({$placeholders})
               AND a.status='active'
             ORDER BY a.display_name,a.id"
        );
        $statement->execute([$userId, ...$roles]);
        return array_values($statement->fetchAll(PDO::FETCH_ASSOC));
    }

    /** @param list<string> $allowedRoles @return array{account_id:int,account_public_id:string,display_name:string,role:string} */
    public function resolve(int $userId, ?string $requestedPublicId, array $allowedRoles): array
    {
        $memberships = $this->memberships($userId, $allowedRoles);
        if ($memberships === []) {
            throw new AuthPublicException(
                'account_membership_required',
                'An active VP3 membership with permission for this account is required.',
                403
            );
        }
        $requestedPublicId = $this->publicId($requestedPublicId);
        $selected = null;
        foreach ($memberships as $membership) {
            if ($requestedPublicId === null || hash_equals((string) $membership['public_id'], $requestedPublicId)) {
                $selected = $membership;
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
            'account_id' => (int) $selected['id'],
            'account_public_id' => (string) $selected['public_id'],
            'display_name' => (string) $selected['display_name'],
            'role' => (string) $selected['role'],
        ];
    }

    public function publicId(?string $value): ?string
    {
        $value = trim((string) $value);
        if ($value === '') {
            return null;
        }
        if (!preg_match('/^[A-Za-z0-9._:-]{3,64}$/', $value)) {
            throw new AuthPublicException(
                'account_identity_invalid',
                'The VP3 account identity is invalid.',
                400
            );
        }
        return $value;
    }

    /** @param list<string> $roles @return list<string> */
    private function roles(array $roles): array
    {
        $normalized = array_values(array_unique(array_filter(
            array_map(static fn (mixed $role): string => trim((string) $role), $roles),
            static fn (string $role): bool => in_array($role, self::ALLOWED_ROLES, true)
        )));
        if ($normalized === []) {
            throw new AuthPublicException('account_role_invalid', 'The account role policy is invalid.', 500);
        }
        return $normalized;
    }
}
