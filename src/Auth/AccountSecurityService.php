<?php

declare(strict_types=1);

namespace Vp3\Auth;

use DateTimeImmutable;
use PDO;
use RuntimeException;
use Vp3\Database;

final class AccountSecurityService
{
    public function __construct(private readonly Database $database, private readonly PasswordPolicy $passwordPolicy)
    {
    }

    public function verifyEmail(string $token): bool
    {
        $hash = hash('sha256', trim($token));
        $now = new DateTimeImmutable('now');

        return $this->database->transaction(function (PDO $pdo) use ($hash, $now): bool {
            $statement = $pdo->prepare(
                'SELECT evt.id, evt.user_id FROM email_verification_tokens evt
                 WHERE evt.token_hash = :token_hash AND evt.consumed_at IS NULL AND evt.expires_at > :now
                 LIMIT 1 FOR UPDATE'
            );
            $statement->execute(['token_hash' => $hash, 'now' => $now->format('Y-m-d H:i:s')]);
            $record = $statement->fetch();
            if (!$record) {
                return false;
            }

            $pdo->prepare('UPDATE users SET status = :status, email_verified_at = :verified_at, updated_at = :updated_at WHERE id = :id')
                ->execute([
                    'status' => 'active',
                    'verified_at' => $now->format('Y-m-d H:i:s'),
                    'updated_at' => $now->format('Y-m-d H:i:s'),
                    'id' => $record['user_id'],
                ]);
            $pdo->prepare(
                'UPDATE accounts a JOIN account_users au ON au.account_id = a.id
                 SET a.status = :status, a.updated_at = :updated_at
                 WHERE au.user_id = :user_id AND au.role = :role'
            )->execute([
                'status' => 'active',
                'updated_at' => $now->format('Y-m-d H:i:s'),
                'user_id' => $record['user_id'],
                'role' => 'customer_owner',
            ]);
            $pdo->prepare('UPDATE email_verification_tokens SET consumed_at = :consumed_at WHERE id = :id')
                ->execute(['consumed_at' => $now->format('Y-m-d H:i:s'), 'id' => $record['id']]);

            return true;
        });
    }

    public function createPasswordReset(string $email): ?string
    {
        $email = strtolower(trim($email));
        $pdo = $this->database->pdo();
        $statement = $pdo->prepare('SELECT id FROM users WHERE email_normalized = :email AND status IN (\'active\',\'pending_verification\') LIMIT 1');
        $statement->execute(['email' => $email]);
        $user = $statement->fetch();
        if (!$user) {
            return null;
        }

        $token = bin2hex(random_bytes(32));
        $now = new DateTimeImmutable('now');
        $pdo->prepare('UPDATE password_reset_tokens SET consumed_at = :now WHERE user_id = :user_id AND consumed_at IS NULL')
            ->execute(['now' => $now->format('Y-m-d H:i:s'), 'user_id' => $user['id']]);
        $pdo->prepare(
            'INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, created_at)
             VALUES (:user_id, :token_hash, :expires_at, :created_at)'
        )->execute([
            'user_id' => $user['id'],
            'token_hash' => hash('sha256', $token),
            'expires_at' => $now->modify('+60 minutes')->format('Y-m-d H:i:s'),
            'created_at' => $now->format('Y-m-d H:i:s'),
        ]);

        return $token;
    }

    public function resetPassword(string $token, string $password): bool
    {
        $this->passwordPolicy->assertValid($password);
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);
        if (!is_string($passwordHash)) {
            throw new RuntimeException('Password hashing failed.');
        }
        $tokenHash = hash('sha256', trim($token));
        $now = new DateTimeImmutable('now');

        return $this->database->transaction(function (PDO $pdo) use ($tokenHash, $passwordHash, $now): bool {
            $statement = $pdo->prepare(
                'SELECT id, user_id FROM password_reset_tokens
                 WHERE token_hash = :token_hash AND consumed_at IS NULL AND expires_at > :now
                 LIMIT 1 FOR UPDATE'
            );
            $statement->execute(['token_hash' => $tokenHash, 'now' => $now->format('Y-m-d H:i:s')]);
            $record = $statement->fetch();
            if (!$record) {
                return false;
            }

            $pdo->prepare('UPDATE users SET password_hash = :password_hash, updated_at = :updated_at WHERE id = :id')
                ->execute([
                    'password_hash' => $passwordHash,
                    'updated_at' => $now->format('Y-m-d H:i:s'),
                    'id' => $record['user_id'],
                ]);
            $pdo->prepare('UPDATE password_reset_tokens SET consumed_at = :consumed_at WHERE id = :id')
                ->execute(['consumed_at' => $now->format('Y-m-d H:i:s'), 'id' => $record['id']]);
            $pdo->prepare('UPDATE auth_sessions SET revoked_at = :revoked_at WHERE user_id = :user_id AND revoked_at IS NULL')
                ->execute(['revoked_at' => $now->format('Y-m-d H:i:s'), 'user_id' => $record['user_id']]);

            return true;
        });
    }
}
