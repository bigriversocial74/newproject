<?php

declare(strict_types=1);

namespace Vp3\Auth;

use DateTimeImmutable;
use PDO;
use RuntimeException;
use Vp3\Database;

final class AuthService
{
    public function __construct(
        private readonly Database $database,
        private readonly PasswordPolicy $passwordPolicy
    ) {
    }

    /** @return array{account_id:int,user_id:int,verification_token:string} */
    public function register(string $email, string $password, string $displayName): array
    {
        $email = strtolower(trim($email));
        $displayName = trim($displayName);

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new RuntimeException('A valid email address is required.');
        }
        if ($displayName === '') {
            throw new RuntimeException('Display name is required.');
        }

        $this->passwordPolicy->assertValid($password);
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);
        if (!is_string($passwordHash)) {
            throw new RuntimeException('Password hashing failed.');
        }

        return $this->database->transaction(function (PDO $pdo) use ($email, $passwordHash, $displayName): array {
            $check = $pdo->prepare('SELECT id FROM users WHERE email_normalized = :email LIMIT 1');
            $check->execute(['email' => $email]);
            if ($check->fetch()) {
                throw new RuntimeException('An account already exists for this email address.');
            }

            $accountPublicId = 'VP3-' . strtoupper(bin2hex(random_bytes(6)));
            $userPublicId = 'USR-' . strtoupper(bin2hex(random_bytes(6)));
            $verificationToken = bin2hex(random_bytes(32));
            $now = new DateTimeImmutable('now');

            $pdo->prepare(
                'INSERT INTO accounts (public_id, account_type, status, display_name, created_at, updated_at)
                 VALUES (:public_id, :account_type, :status, :display_name, :created_at, :updated_at)'
            )->execute([
                'public_id' => $accountPublicId,
                'account_type' => 'individual',
                'status' => 'pending_verification',
                'display_name' => $displayName,
                'created_at' => $now->format('Y-m-d H:i:s'),
                'updated_at' => $now->format('Y-m-d H:i:s'),
            ]);
            $accountId = (int) $pdo->lastInsertId();

            $pdo->prepare(
                'INSERT INTO users (public_id, email, email_normalized, password_hash, display_name, status, created_at, updated_at)
                 VALUES (:public_id, :email, :email_normalized, :password_hash, :display_name, :status, :created_at, :updated_at)'
            )->execute([
                'public_id' => $userPublicId,
                'email' => $email,
                'email_normalized' => $email,
                'password_hash' => $passwordHash,
                'display_name' => $displayName,
                'status' => 'pending_verification',
                'created_at' => $now->format('Y-m-d H:i:s'),
                'updated_at' => $now->format('Y-m-d H:i:s'),
            ]);
            $userId = (int) $pdo->lastInsertId();

            $pdo->prepare(
                'INSERT INTO account_users (account_id, user_id, role, status, created_at, updated_at)
                 VALUES (:account_id, :user_id, :role, :status, :created_at, :updated_at)'
            )->execute([
                'account_id' => $accountId,
                'user_id' => $userId,
                'role' => 'customer_owner',
                'status' => 'active',
                'created_at' => $now->format('Y-m-d H:i:s'),
                'updated_at' => $now->format('Y-m-d H:i:s'),
            ]);

            $pdo->prepare(
                'INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, created_at)
                 VALUES (:user_id, :token_hash, :expires_at, :created_at)'
            )->execute([
                'user_id' => $userId,
                'token_hash' => hash('sha256', $verificationToken),
                'expires_at' => $now->modify('+24 hours')->format('Y-m-d H:i:s'),
                'created_at' => $now->format('Y-m-d H:i:s'),
            ]);

            return ['account_id' => $accountId, 'user_id' => $userId, 'verification_token' => $verificationToken];
        });
    }

    /** @return array{id:int,public_id:string,email:string,display_name:string}|null */
    public function authenticate(string $email, string $password, string $ip = '', string $userAgent = ''): ?array
    {
        $email = strtolower(trim($email));
        $pdo = $this->database->pdo();
        $emailHash = hash('sha256', $email);
        $ipHash = hash('sha256', $ip);
        $window = (new DateTimeImmutable('now'))->modify('-15 minutes')->format('Y-m-d H:i:s');

        $attempts = $pdo->prepare(
            'SELECT COUNT(*) FROM auth_login_attempts
             WHERE succeeded = 0 AND attempted_at >= :window AND (email_hash = :email_hash OR ip_hash = :ip_hash)'
        );
        $attempts->execute(['window' => $window, 'email_hash' => $emailHash, 'ip_hash' => $ipHash]);
        if ((int) $attempts->fetchColumn() >= 10) {
            throw new RuntimeException('Too many sign-in attempts. Try again later.');
        }

        $statement = $pdo->prepare(
            'SELECT id, public_id, email, display_name, password_hash, status
             FROM users WHERE email_normalized = :email LIMIT 1'
        );
        $statement->execute(['email' => $email]);
        $user = $statement->fetch();
        $success = $user && password_verify($password, (string) $user['password_hash'])
            && in_array($user['status'], ['active', 'pending_verification'], true);

        $now = new DateTimeImmutable('now');
        $pdo->prepare(
            'INSERT INTO auth_login_attempts (email_hash, ip_hash, succeeded, attempted_at)
             VALUES (:email_hash, :ip_hash, :succeeded, :attempted_at)'
        )->execute([
            'email_hash' => $emailHash,
            'ip_hash' => $ipHash,
            'succeeded' => $success ? 1 : 0,
            'attempted_at' => $now->format('Y-m-d H:i:s'),
        ]);

        if (!$success) {
            return null;
        }

        if (password_needs_rehash((string) $user['password_hash'], PASSWORD_DEFAULT)) {
            $rehash = password_hash($password, PASSWORD_DEFAULT);
            if (is_string($rehash)) {
                $pdo->prepare('UPDATE users SET password_hash = :hash, updated_at = :updated_at WHERE id = :id')
                    ->execute(['hash' => $rehash, 'updated_at' => $now->format('Y-m-d H:i:s'), 'id' => $user['id']]);
            }
        }
        $pdo->prepare('UPDATE users SET last_login_at = :last_login_at, updated_at = :updated_at WHERE id = :id')
            ->execute(['last_login_at' => $now->format('Y-m-d H:i:s'), 'updated_at' => $now->format('Y-m-d H:i:s'), 'id' => $user['id']]);

        return [
            'id' => (int) $user['id'],
            'public_id' => (string) $user['public_id'],
            'email' => (string) $user['email'],
            'display_name' => (string) $user['display_name'],
        ];
    }
}
