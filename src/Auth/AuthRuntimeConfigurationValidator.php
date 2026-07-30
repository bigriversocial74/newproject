<?php

declare(strict_types=1);

namespace Vp3\Auth;

use RuntimeException;

final class AuthRuntimeConfigurationValidator
{
    /** @param array<string,mixed> $config */
    public function validate(array $config, bool $usingExampleConfig): void
    {
        $auth = (array) ($config['auth'] ?? []);
        $challengeTtl = (int) ($auth['mfa_challenge_ttl_seconds'] ?? 0);
        $recoveryCount = (int) ($auth['mfa_recovery_code_count'] ?? 0);
        $invitationTtl = (int) ($auth['team_invitation_ttl_seconds'] ?? 0);
        if ($challengeTtl < 60 || $challengeTtl > 900) {
            throw new RuntimeException('AUTH_MFA_CHALLENGE_TTL_SECONDS must be between 60 and 900.');
        }
        if ($recoveryCount < 6 || $recoveryCount > 20) {
            throw new RuntimeException('AUTH_MFA_RECOVERY_CODE_COUNT must be between 6 and 20.');
        }
        if ($invitationTtl < 3600 || $invitationTtl > 2592000) {
            throw new RuntimeException('AUTH_TEAM_INVITATION_TTL_SECONDS must be between 3600 and 2592000.');
        }
        $environment = strtolower((string) ($config['app']['env'] ?? 'development'));
        if ($environment !== 'production') {
            return;
        }
        if ($usingExampleConfig) {
            throw new RuntimeException('Production authentication cannot start from config-example.php.');
        }
        $encoded = trim((string) ($auth['secret_encryption_key_base64'] ?? ''));
        $decoded = base64_decode($encoded, true);
        if (!is_string($decoded) || strlen($decoded) !== 32) {
            throw new RuntimeException('AUTH_SECRET_ENCRYPTION_KEY_B64 must contain exactly 32 bytes in production.');
        }
        if (trim((string) ($auth['secret_encryption_key_id'] ?? '')) === '') {
            throw new RuntimeException('AUTH_SECRET_ENCRYPTION_KEY_ID is required in production.');
        }
    }
}
