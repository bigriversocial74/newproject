<?php

declare(strict_types=1);

namespace Vp3\Auth;

use DateTimeImmutable;
use PDO;
use RuntimeException;
use Vp3\Database;

final class PasswordChangeService
{
    public function __construct(
        private readonly Database $database,
        private readonly PasswordPolicy $passwordPolicy,
        private readonly AuthAuditService $audit
    ) {
    }

    /** @return array{revoked_sessions:int} */
    public function change(
        int $userId,
        string $currentPassword,
        string $newPassword,
        string $currentSessionPublicId,
        string $ip,
        string $userAgent
    ): array {
        $this->passwordPolicy->assertValid($newPassword);
        $newHash = password_hash($newPassword, PASSWORD_DEFAULT);
        if (!is_string($newHash)) {
            throw new RuntimeException('Credential hashing failed.');
        }

        try {
            return $this->database->transaction(function (PDO $pdo) use (
                $userId,
                $currentPassword,
                $newPassword,
                $newHash,
                $currentSessionPublicId,
                $ip,
                $userAgent
            ): array {
                $userStatement = $pdo->prepare(
                    'SELECT public_id, password_hash, status FROM users WHERE id = :id LIMIT 1 FOR UPDATE'
                );
                $userStatement->execute(['id' => $userId]);
                $user = $userStatement->fetch();
                if (!$user || (string) $user['status'] !== 'active'
                    || !password_verify($currentPassword, (string) $user['password_hash'])) {
                    throw new AuthPublicException('current_password_invalid', 'The current password is incorrect.', 403);
                }
                if (password_verify($newPassword, (string) $user['password_hash'])) {
                    throw new AuthPublicException('password_reuse_rejected', 'Choose a password that is different from the current password.', 422);
                }

                $currentSession = $pdo->prepare(
                    'SELECT id FROM auth_sessions
                     WHERE user_id = :user_id AND session_public_id = :session_public_id AND revoked_at IS NULL
                     LIMIT 1 FOR UPDATE'
                );
                $currentSession->execute([
                    'user_id' => $userId,
                    'session_public_id' => $currentSessionPublicId,
                ]);
                if (!$currentSession->fetch()) {
                    throw new AuthPublicException('invalid_session', 'The session is invalid or expired.', 401);
                }

                $otherSessions = $pdo->prepare(
                    'SELECT session_public_id FROM auth_sessions
                     WHERE user_id = :user_id AND session_public_id <> :current_public_id AND revoked_at IS NULL
                     FOR UPDATE'
                );
                $otherSessions->execute([
                    'user_id' => $userId,
                    'current_public_id' => $currentSessionPublicId,
                ]);
                $otherPublicIds = array_map(
                    static fn (array $row): string => (string) $row['session_public_id'],
                    $otherSessions->fetchAll()
                );

                $now = new DateTimeImmutable('now');
                $pdo->prepare(
                    'UPDATE users SET password_hash = :password_hash, updated_at = :updated_at WHERE id = :id'
                )->execute([
                    'password_hash' => $newHash,
                    'updated_at' => $now->format('Y-m-d H:i:s'),
                    'id' => $userId,
                ]);
                $pdo->prepare(
                    'UPDATE auth_sessions
                     SET revoked_at = :revoked_at, revocation_reason = :reason,
                         revoked_by_user_id = :actor_user_id, updated_at = :updated_at
                     WHERE user_id = :target_user_id AND session_public_id <> :current_public_id AND revoked_at IS NULL'
                )->execute([
                    'revoked_at' => $now->format('Y-m-d H:i:s'),
                    'reason' => 'password_change',
                    'actor_user_id' => $userId,
                    'target_user_id' => $userId,
                    'updated_at' => $now->format('Y-m-d H:i:s'),
                    'current_public_id' => $currentSessionPublicId,
                ]);

                foreach ($otherPublicIds as $publicId) {
                    $requestId = $this->audit->sessionEvent(
                        'revoked',
                        $publicId,
                        $userId,
                        $ip,
                        $userAgent,
                        ['reason' => 'password_change']
                    );
                    $this->audit->record(
                        'auth.session.revoked',
                        'success',
                        $userId,
                        null,
                        'auth_session',
                        $publicId,
                        ['reason' => 'password_change'],
                        $requestId
                    );
                }
                $this->audit->record(
                    'auth.password_changed',
                    'success',
                    $userId,
                    null,
                    'user',
                    (string) $user['public_id'],
                    ['revoked_sessions' => count($otherPublicIds)]
                );

                return ['revoked_sessions' => count($otherPublicIds)];
            });
        } catch (AuthPublicException $exception) {
            $this->audit->record(
                'auth.password_change.denied',
                'denied',
                $userId,
                null,
                'user',
                null,
                ['reason' => $exception->publicCode()]
            );
            throw $exception;
        }
    }
}
