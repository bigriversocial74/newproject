<?php

declare(strict_types=1);

namespace Vp3\Security;

use PDO;
use Vp3\Auth\AuthPublicException;
use Vp3\Auth\MfaService;
use Vp3\Database;

final class SecurityReauthenticationProofService
{
    public function __construct(
        private readonly Database $database,
        private readonly MfaService $mfa,
        private readonly SecurityReauthenticationService $reauthentication,
        private readonly SecurityAuditService $audit
    ) {
    }

    /**
     * @param array<string,mixed> $context
     * @return array{reauthentication_public_id:string,challenge:string,expires_at:string,mfa_required:bool,mfa_challenge_token:?string,mfa_challenge_public_id:?string}
     */
    public function begin(
        int $accountId,
        int $userId,
        string $role,
        string $actionType,
        array $context,
        string $ipAddress,
        string $userAgent
    ): array {
        $this->assertManager($accountId, $userId, $role);
        $challenge = $this->reauthentication->issue($accountId, $userId, $actionType, $context, 300);
        $mfaRequired = $this->mfa->requiresMfa($userId);
        $mfaChallenge = $mfaRequired ? $this->mfa->createChallenge($userId, $ipAddress, $userAgent) : null;

        return [
            'reauthentication_public_id' => $challenge['public_id'],
            'challenge' => $challenge['challenge'],
            'expires_at' => $challenge['expires_at'],
            'mfa_required' => $mfaRequired,
            'mfa_challenge_token' => $mfaChallenge['challenge_token'] ?? null,
            'mfa_challenge_public_id' => $mfaChallenge['challenge_public_id'] ?? null,
        ];
    }

    /** @param array<string,mixed> $context */
    public function complete(
        int $accountId,
        int $userId,
        string $role,
        string $actionType,
        array $context,
        string $reauthenticationPublicId,
        string $challenge,
        string $currentPassword,
        ?string $mfaChallengeToken,
        ?string $mfaCode,
        string $ipAddress,
        string $userAgent,
        string $requestId
    ): void {
        $this->assertManager($accountId, $userId, $role);
        $password = $this->database->pdo()->prepare(
            "SELECT password_hash FROM users WHERE id=:user_id AND status='active' LIMIT 1"
        );
        $password->execute(['user_id' => $userId]);
        $hash = $password->fetchColumn();
        if (!is_string($hash) || !password_verify($currentPassword, $hash)) {
            $this->audit->record(
                'security.reauthentication.denied',
                'authentication',
                'high',
                'denied',
                $accountId,
                'account_user',
                $userId,
                null,
                'security_reauthentication',
                $reauthenticationPublicId,
                ['reason' => 'password_invalid', 'action_type' => $actionType],
                $requestId,
                null,
                $ipAddress,
                $userAgent
            );
            throw new AuthPublicException('password_invalid', 'The current password is incorrect.', 403);
        }

        if ($this->mfa->requiresMfa($userId)) {
            if ($mfaChallengeToken === null || trim($mfaChallengeToken) === '' || $mfaCode === null || trim($mfaCode) === '') {
                throw new AuthPublicException('mfa_code_required', 'A current MFA code is required.', 422);
            }
            $verified = $this->mfa->completeChallenge(
                trim($mfaChallengeToken),
                trim($mfaCode),
                $ipAddress,
                $userAgent,
                $requestId
            );
            if ((int) $verified['id'] !== $userId) {
                throw new AuthPublicException('mfa_challenge_invalid', 'The MFA challenge is invalid or expired.', 403);
            }
        }

        if (!$this->reauthentication->satisfy(
            trim($reauthenticationPublicId),
            trim($challenge),
            $accountId,
            $userId,
            $actionType,
            $context
        )) {
            throw new AuthPublicException(
                'security_reauthentication_invalid',
                'Sensitive-action reauthentication is invalid or expired.',
                403
            );
        }

        $this->audit->record(
            'security.reauthentication.satisfied',
            'authentication',
            'high',
            'success',
            $accountId,
            'account_user',
            $userId,
            null,
            'security_reauthentication',
            $reauthenticationPublicId,
            ['action_type' => $actionType, 'mfa_required' => $this->mfa->requiresMfa($userId)],
            $requestId,
            null,
            $ipAddress,
            $userAgent
        );
    }

    private function assertManager(int $accountId, int $userId, string $role): void
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT role FROM account_users
             WHERE account_id=:account_id AND user_id=:user_id AND status='active' LIMIT 1"
        );
        $statement->execute(['account_id' => $accountId, 'user_id' => $userId]);
        $storedRole = $statement->fetchColumn();
        if (!is_string($storedRole) || !hash_equals($storedRole, $role)
            || !in_array($storedRole, ['customer_owner', 'customer_admin'], true)) {
            throw new AuthPublicException(
                'security_reauthentication_access_denied',
                'An owner or administrator membership is required.',
                403
            );
        }
    }
}
