<?php

declare(strict_types=1);

namespace Vp3\Deployment;

use Vp3\Database;

final class WebInitialSetupService
{
    public function __construct(
        private readonly Database $database,
        private readonly InitialOwnerBootstrapService $owners,
        private readonly PlatformOperatorGrantService $operators
    ) {
    }

    /** @return array<string,mixed> */
    public function createFirstAdministrator(
        string $email,
        string $displayName,
        string $accountName,
        string $password,
        string $requestId,
        bool $grantPlatformOperator
    ): array {
        return $this->database->transaction(function () use (
            $email,
            $displayName,
            $accountName,
            $password,
            $requestId,
            $grantPlatformOperator
        ): array {
            $owner = $this->owners->bootstrap(
                $email,
                $displayName,
                $accountName,
                $password,
                $requestId
            );

            $operator = null;
            if ($grantPlatformOperator) {
                $operator = $this->operators->grant(
                    (string) $owner['account_public_id'],
                    (string) $owner['user_public_id'],
                    substr($requestId . '-operator', 0, 80)
                );
            }

            return [
                'account_public_id' => (string) $owner['account_public_id'],
                'user_public_id' => (string) $owner['user_public_id'],
                'email' => (string) $owner['email'],
                'platform_operator' => is_array($operator)
                    && ($operator['operator_status'] ?? null) === 'active',
                'replayed' => (bool) ($owner['replayed'] ?? false),
            ];
        });
    }
}
