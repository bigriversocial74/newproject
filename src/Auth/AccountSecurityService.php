<?php

declare(strict_types=1);

namespace Vp3\Auth;

use DateTimeImmutable;
use PDO;
use RuntimeException;
use Throwable;
use Vp3\Auth\Mail\MailAdapter;
use Vp3\Auth\Mail\NullMailAdapter;
use Vp3\Database;

final class AccountSecurityService
{
    private readonly MailAdapter $mail;
    private readonly AuthAuditService $audit;
    /** @var array<string,mixed> */
    private readonly array $config;

    /** @param array<string,mixed> $config */
    public function __construct(
        private readonly Database $database,
        private readonly PasswordPolicy $passwordPolicy,
        ?MailAdapter $mail = null,
        array $config = [],
        ?AuthAuditService $audit = null
    ) {
        $this->mail = $mail ?? new NullMailAdapter();
        $this->audit = $audit ?? new AuthAuditService($database);
        $this->config = array_merge([
            'verification_ttl_seconds' => 86400,
            'password_reset_ttl_seconds' => 3600,
            'base_url' => 'https://vp3.me',
        ], $config);
    }

    public function verifyEmail(string $token): bool
    {
        $hash = hash('sha256', trim($token));
        $now = new DateTimeImmutable('now');
        $verified = $this->database->transaction(function (PDO $pdo) use ($hash, $now): bool {
            $statement = $pdo->prepare(
                'SELECT evt.id, evt.user_id, u.public_id AS user_public_id, au.account_id
                 FROM email_verification_tokens evt
                 JOIN users u ON u.id = evt.user_id
                 LEFT JOIN account_users au ON au.user_id = u.id AND au.role = :owner_role
                 WHERE evt.token_hash = :token_hash AND evt.consumed_at IS NULL AND evt.invalidated_at IS NULL
                   AND evt.expires_at > :now
                 LIMIT 1 FOR UPDATE'
            );
            $statement->execute([
                'owner_role' => 'customer_owner',
                'token_hash' => $hash,
                'now' => $now->format('Y-m-d H:i:s'),
            ]);
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
            $pdo->prepare(
                'UPDATE email_verification_tokens SET invalidated_at = :invalidated_at
                 WHERE user_id = :user_id AND id <> :id AND consumed_at IS NULL AND invalidated_at IS NULL'
            )->execute([
                'invalidated_at' => $now->format('Y-m-d H:i:s'),
                'user_id' => $record['user_id'],
                'id' => $record['id'],
            ]);
            $this->audit->record(
                'auth.email_verified',
                'success',
                (int) $record['user_id'],
                $record['account_id'] === null ? null : (int) $record['account_id'],
                'user',
                (string) $record['user_public_id']
            );
            return true;
        });

        if (!$verified) {
            $this->audit->record('auth.email_verified', 'denied', null, null, 'email_verification', null, ['reason' => 'invalid_expired_or_replayed']);
        }
        return $verified;
    }

    public function resendVerification(string $email): ?string
    {
        $email = strtolower(trim($email));
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->audit->record('auth.verification.requested', 'success', null, null, 'user', null, ['delivered' => false]);
            return null;
        }
        $pdo = $this->database->pdo();
        $statement = $pdo->prepare(
            'SELECT u.id, u.email, u.display_name, u.public_id, au.account_id
             FROM users u
             LEFT JOIN account_users au ON au.user_id = u.id AND au.role = :owner_role
             WHERE u.email_normalized = :email AND u.status = :status LIMIT 1'
        );
        $statement->execute(['owner_role' => 'customer_owner', 'email' => $email, 'status' => 'pending_verification']);
        $user = $statement->fetch();
        if (!$user) {
            $this->audit->record('auth.verification.requested', 'success', null, null, 'user', null, ['delivered' => false]);
            return null;
        }

        $token = $this->newToken();
        $requestId = $this->audit->requestId();
        $now = new DateTimeImmutable('now');
        $this->database->transaction(function (PDO $transaction) use ($user, $token, $requestId, $now): void {
            $transaction->prepare(
                'UPDATE email_verification_tokens SET invalidated_at = :invalidated_at
                 WHERE user_id = :user_id AND consumed_at IS NULL AND invalidated_at IS NULL'
            )->execute(['invalidated_at' => $now->format('Y-m-d H:i:s'), 'user_id' => $user['id']]);
            $transaction->prepare(
                'INSERT INTO email_verification_tokens (user_id, request_id, token_hash, expires_at, created_at)
                 VALUES (:user_id, :request_id, :token_hash, :expires_at, :created_at)'
            )->execute([
                'user_id' => $user['id'],
                'request_id' => $requestId,
                'token_hash' => hash('sha256', $token),
                'expires_at' => $now->modify('+' . max(60, (int) $this->config['verification_ttl_seconds']) . ' seconds')->format('Y-m-d H:i:s'),
                'created_at' => $now->format('Y-m-d H:i:s'),
            ]);
        });
        try {
            $this->sendVerificationEmail((string) $user['email'], (string) $user['display_name'], $token);
            $this->audit->record(
                'auth.verification.requested',
                'success',
                (int) $user['id'],
                $user['account_id'] === null ? null : (int) $user['account_id'],
                'user',
                (string) $user['public_id'],
                ['delivered' => true],
                $requestId
            );
            return $token;
        } catch (Throwable) {
            $this->audit->record(
                'auth.verification.requested',
                'failure',
                (int) $user['id'],
                $user['account_id'] === null ? null : (int) $user['account_id'],
                'user',
                (string) $user['public_id'],
                ['delivered' => false, 'reason' => 'mail_delivery_failed'],
                $requestId
            );
            return null;
        }
    }

    public function createPasswordReset(string $email): ?string
    {
        return $this->requestPasswordReset($email);
    }

    public function requestPasswordReset(string $email): ?string
    {
        $email = strtolower(trim($email));
        $pdo = $this->database->pdo();
        $statement = $pdo->prepare(
            'SELECT id, public_id, email, display_name FROM users
             WHERE email_normalized = :email AND status = :status LIMIT 1'
        );
        $statement->execute(['email' => $email, 'status' => 'active']);
        $user = $statement->fetch();
        if (!$user) {
            $this->audit->record('auth.password_reset.requested', 'success', null, null, 'user', null, ['delivered' => false]);
            return null;
        }

        $token = $this->newToken();
        $requestId = $this->audit->requestId();
        $now = new DateTimeImmutable('now');
        $this->database->transaction(function (PDO $transaction) use ($user, $token, $requestId, $now): void {
            $transaction->prepare(
                'UPDATE password_reset_tokens SET invalidated_at = :invalidated_at
                 WHERE user_id = :user_id AND consumed_at IS NULL AND invalidated_at IS NULL'
            )->execute(['invalidated_at' => $now->format('Y-m-d H:i:s'), 'user_id' => $user['id']]);
            $transaction->prepare(
                'INSERT INTO password_reset_tokens (user_id, request_id, token_hash, expires_at, created_at)
                 VALUES (:user_id, :request_id, :token_hash, :expires_at, :created_at)'
            )->execute([
                'user_id' => $user['id'],
                'request_id' => $requestId,
                'token_hash' => hash('sha256', $token),
                'expires_at' => $now->modify('+' . max(60, (int) $this->config['password_reset_ttl_seconds']) . ' seconds')->format('Y-m-d H:i:s'),
                'created_at' => $now->format('Y-m-d H:i:s'),
            ]);
        });
        try {
            $this->sendPasswordResetEmail((string) $user['email'], (string) $user['display_name'], $token);
            $this->audit->record(
                'auth.password_reset.requested',
                'success',
                (int) $user['id'],
                null,
                'user',
                (string) $user['public_id'],
                ['delivered' => true],
                $requestId
            );
            return $token;
        } catch (Throwable) {
            $this->audit->record(
                'auth.password_reset.requested',
                'failure',
                (int) $user['id'],
                null,
                'user',
                (string) $user['public_id'],
                ['delivered' => false, 'reason' => 'mail_delivery_failed'],
                $requestId
            );
            return null;
        }
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

        $result = $this->database->transaction(function (PDO $pdo) use ($tokenHash, $passwordHash, $now): bool {
            $statement = $pdo->prepare(
                'SELECT prt.id, prt.user_id, u.public_id AS user_public_id
                 FROM password_reset_tokens prt
                 JOIN users u ON u.id = prt.user_id
                 WHERE prt.token_hash = :token_hash AND prt.consumed_at IS NULL AND prt.invalidated_at IS NULL
                   AND prt.expires_at > :now
                 LIMIT 1 FOR UPDATE'
            );
            $statement->execute(['token_hash' => $tokenHash, 'now' => $now->format('Y-m-d H:i:s')]);
            $record = $statement->fetch();
            if (!$record) {
                return false;
            }

            $sessions = $pdo->prepare('SELECT session_public_id FROM auth_sessions WHERE user_id = :user_id AND revoked_at IS NULL FOR UPDATE');
            $sessions->execute(['user_id' => $record['user_id']]);
            $sessionPublicIds = array_map(static fn (array $row): string => (string) $row['session_public_id'], $sessions->fetchAll());

            $pdo->prepare('UPDATE users SET password_hash = :password_hash, updated_at = :updated_at WHERE id = :id')
                ->execute([
                    'password_hash' => $passwordHash,
                    'updated_at' => $now->format('Y-m-d H:i:s'),
                    'id' => $record['user_id'],
                ]);
            $pdo->prepare('UPDATE password_reset_tokens SET consumed_at = :consumed_at WHERE id = :id')
                ->execute(['consumed_at' => $now->format('Y-m-d H:i:s'), 'id' => $record['id']]);
            $pdo->prepare(
                'UPDATE password_reset_tokens SET invalidated_at = :invalidated_at
                 WHERE user_id = :user_id AND id <> :id AND consumed_at IS NULL AND invalidated_at IS NULL'
            )->execute([
                'invalidated_at' => $now->format('Y-m-d H:i:s'),
                'user_id' => $record['user_id'],
                'id' => $record['id'],
            ]);
            $pdo->prepare(
                'UPDATE auth_sessions
                 SET revoked_at = :revoked_at, revocation_reason = :reason, updated_at = :updated_at
                 WHERE user_id = :user_id AND revoked_at IS NULL'
            )->execute([
                'revoked_at' => $now->format('Y-m-d H:i:s'),
                'reason' => 'password_reset',
                'updated_at' => $now->format('Y-m-d H:i:s'),
                'user_id' => $record['user_id'],
            ]);
            foreach ($sessionPublicIds as $sessionPublicId) {
                $requestId = $this->audit->sessionEvent(
                    'revoked',
                    $sessionPublicId,
                    (int) $record['user_id'],
                    '',
                    '',
                    ['reason' => 'password_reset']
                );
                $this->audit->record(
                    'auth.session.revoked',
                    'success',
                    (int) $record['user_id'],
                    null,
                    'auth_session',
                    $sessionPublicId,
                    ['reason' => 'password_reset'],
                    $requestId
                );
            }
            $this->audit->record(
                'auth.password_reset.completed',
                'success',
                (int) $record['user_id'],
                null,
                'user',
                (string) $record['user_public_id'],
                ['revoked_sessions' => count($sessionPublicIds)]
            );
            return true;
        });

        if (!$result) {
            $this->audit->record('auth.password_reset.completed', 'denied', null, null, 'password_reset', null, ['reason' => 'invalid_expired_or_replayed']);
        }
        return $result;
    }

    private function sendVerificationEmail(string $email, string $displayName, string $token): void
    {
        $url = rtrim((string) $this->config['base_url'], '/') . '/verify-email?token=' . rawurlencode($token);
        $subject = 'Verify your VP3.me email address';
        $text = "Hello {$displayName},\n\nVerify your email address:\n{$url}\n\nIf you did not request this, ignore this message.";
        $html = '<p>Hello ' . htmlspecialchars($displayName, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . ',</p>'
            . '<p><a href="' . htmlspecialchars($url, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '">Verify email address</a></p>';
        $this->mail->send($email, $subject, $text, $html);
    }

    private function sendPasswordResetEmail(string $email, string $displayName, string $token): void
    {
        $url = rtrim((string) $this->config['base_url'], '/') . '/reset-password?token=' . rawurlencode($token);
        $subject = 'Reset your VP3.me password';
        $text = "Hello {$displayName},\n\nUse this link to reset your password:\n{$url}\n\nIf you did not request this, ignore this message.";
        $html = '<p>Hello ' . htmlspecialchars($displayName, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . ',</p>'
            . '<p><a href="' . htmlspecialchars($url, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '">Reset password</a></p>';
        $this->mail->send($email, $subject, $text, $html);
    }

    private function newToken(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }
}
