<?php

declare(strict_types=1);

namespace Vp3\Auth;

use DateTimeImmutable;
use PDO;
use PDOException;
use RuntimeException;
use Throwable;
use Vp3\Auth\Mail\MailAdapter;
use Vp3\Auth\Mail\NullMailAdapter;
use Vp3\Database;

final class AuthService
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
            'login_attempt_limit' => 8,
            'login_attempt_window_seconds' => 900,
            'base_url' => 'https://vp3.me',
        ], $config);
    }

    /** @return array{account_id:int,user_id:int,verification_token:string} */
    public function register(string $email, string $password, string $displayName, string $ip = '', string $userAgent = ''): array
    {
        $email = strtolower(trim($email));
        $displayName = trim($displayName);
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new AuthPublicException('invalid_registration', 'Valid registration information is required.', 422);
        }
        if ($displayName === '' || mb_strlen($displayName) > 190) {
            throw new AuthPublicException('invalid_registration', 'Valid registration information is required.', 422);
        }
        $this->passwordPolicy->assertValid($password);
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);
        if (!is_string($passwordHash)) {
            throw new RuntimeException('Password hashing failed.');
        }

        $verificationToken = $this->newToken();
        $requestId = $this->audit->requestId();
        try {
            $result = $this->database->transaction(function (PDO $pdo) use ($email, $passwordHash, $displayName, $verificationToken, $requestId): array {
                $now = new DateTimeImmutable('now');
                $accountPublicId = 'VP3-' . strtoupper(bin2hex(random_bytes(6)));
                $userPublicId = 'USR-' . strtoupper(bin2hex(random_bytes(6)));

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
                    'INSERT INTO email_verification_tokens (user_id, request_id, token_hash, expires_at, created_at)
                     VALUES (:user_id, :request_id, :token_hash, :expires_at, :created_at)'
                )->execute([
                    'user_id' => $userId,
                    'request_id' => $requestId,
                    'token_hash' => hash('sha256', $verificationToken),
                    'expires_at' => $now->modify('+' . max(60, (int) $this->config['verification_ttl_seconds']) . ' seconds')->format('Y-m-d H:i:s'),
                    'created_at' => $now->format('Y-m-d H:i:s'),
                ]);
                $this->audit->record('auth.registration', 'success', $userId, $accountId, 'user', $userPublicId, [], $requestId);
                return ['account_id' => $accountId, 'user_id' => $userId, 'verification_token' => $verificationToken];
            });
        } catch (PDOException $exception) {
            if ((string) $exception->getCode() === '23000') {
                $this->audit->record('auth.registration', 'denied', null, null, 'user', null, ['reason' => 'duplicate_email'], $requestId);
                throw new AuthPublicException('registration_unavailable', 'Unable to create the account with the supplied information.', 409);
            }
            throw $exception;
        }

        try {
            $this->sendVerificationEmail($email, $displayName, $verificationToken);
            $this->audit->record('auth.verification.requested', 'success', $result['user_id'], $result['account_id'], 'user', null, ['delivered' => true], $requestId);
        } catch (Throwable) {
            $this->audit->record('auth.verification.requested', 'failure', $result['user_id'], $result['account_id'], 'user', null, ['delivered' => false, 'reason' => 'mail_delivery_failed'], $requestId);
            throw new AuthPublicException('verification_delivery_failed', 'The account was created, but the verification email could not be sent. Request a new verification email.', 503);
        }
        return $result;
    }

    /** @return array{id:int,public_id:string,email:string,display_name:string}|null */
    public function authenticate(
        string $email,
        string $password,
        string $ip = '',
        string $userAgent = '',
        bool $deferCompletion = false
    ): ?array {
        $email = strtolower(trim($email));
        $pdo = $this->database->pdo();
        $emailHash = hash('sha256', $email);
        $ipHash = hash('sha256', $ip);
        $windowSeconds = max(60, (int) $this->config['login_attempt_window_seconds']);
        $limit = max(1, (int) $this->config['login_attempt_limit']);
        $window = (new DateTimeImmutable('now'))->modify('-' . $windowSeconds . ' seconds')->format('Y-m-d H:i:s');

        $attempts = $pdo->prepare(
            'SELECT COUNT(*) FROM auth_login_attempts
             WHERE succeeded = 0 AND attempted_at >= :window AND (email_hash = :email_hash OR ip_hash = :ip_hash)'
        );
        $attempts->execute(['window' => $window, 'email_hash' => $emailHash, 'ip_hash' => $ipHash]);
        if ((int) $attempts->fetchColumn() >= $limit) {
            $this->audit->record('auth.login.throttled', 'denied', null, null, 'user', null, ['window_seconds' => $windowSeconds, 'limit' => $limit]);
            throw new AuthPublicException('login_throttled', 'Too many sign-in attempts. Try again later.', 429);
        }

        $statement = $pdo->prepare(
            'SELECT id, public_id, email, display_name, password_hash, status
             FROM users WHERE email_normalized = :email LIMIT 1'
        );
        $statement->execute(['email' => $email]);
        $user = $statement->fetch();
        $passwordValid = $user && password_verify($password, (string) $user['password_hash']);
        $active = $passwordValid && (string) $user['status'] === 'active';
        $now = new DateTimeImmutable('now');

        $pdo->prepare(
            'INSERT INTO auth_login_attempts (email_hash, ip_hash, succeeded, attempted_at)
             VALUES (:email_hash, :ip_hash, :succeeded, :attempted_at)'
        )->execute(['email_hash' => $emailHash, 'ip_hash' => $ipHash, 'succeeded' => $active ? 1 : 0, 'attempted_at' => $now->format('Y-m-d H:i:s')]);

        if ($passwordValid && (string) $user['status'] === 'pending_verification') {
            $this->audit->record('auth.login.failure', 'denied', (int) $user['id'], null, 'user', (string) $user['public_id'], ['reason' => 'email_unverified']);
            throw new AuthPublicException('email_verification_required', 'Verify your email address before signing in.', 403);
        }
        if (!$active) {
            $this->audit->record('auth.login.failure', 'denied', $user ? (int) $user['id'] : null, null, 'user', $user ? (string) $user['public_id'] : null, ['reason' => 'invalid_credentials']);
            return null;
        }

        if (password_needs_rehash((string) $user['password_hash'], PASSWORD_DEFAULT)) {
            $rehash = password_hash($password, PASSWORD_DEFAULT);
            if (is_string($rehash)) {
                $pdo->prepare('UPDATE users SET password_hash = :hash, updated_at = :updated_at WHERE id = :id')
                    ->execute(['hash' => $rehash, 'updated_at' => $now->format('Y-m-d H:i:s'), 'id' => $user['id']]);
            }
        }

        $result = ['id' => (int) $user['id'], 'public_id' => (string) $user['public_id'], 'email' => (string) $user['email'], 'display_name' => (string) $user['display_name']];
        if (!$deferCompletion) {
            $this->completeLogin($result['id'], $result['public_id']);
        } else {
            $this->audit->record('auth.login.password_verified', 'success', $result['id'], null, 'user', $result['public_id']);
        }
        return $result;
    }

    public function completeLogin(int $userId, string $userPublicId, ?string $requestId = null): void
    {
        $now = (new DateTimeImmutable('now'))->format('Y-m-d H:i:s');
        $this->database->pdo()->prepare('UPDATE users SET last_login_at=:now,updated_at=:now WHERE id=:id AND status=\'active\'')
            ->execute(['now' => $now, 'id' => $userId]);
        $this->audit->record('auth.login.success', 'success', $userId, null, 'user', $userPublicId, [], $requestId);
    }

    private function sendVerificationEmail(string $email, string $displayName, string $token): void
    {
        $url = rtrim((string) $this->config['base_url'], '/') . '/verify-email?token=' . rawurlencode($token);
        $subject = 'Verify your VP3.me email address';
        $text = "Hello {$displayName},\n\nVerify your email address to activate your VP3.me account:\n{$url}\n\nIf you did not create this account, ignore this message.";
        $html = '<p>Hello ' . htmlspecialchars($displayName, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . ',</p>'
            . '<p>Verify your email address to activate your VP3.me account:</p>'
            . '<p><a href="' . htmlspecialchars($url, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '">Verify email address</a></p>'
            . '<p>If you did not create this account, ignore this message.</p>';
        $this->mail->send($email, $subject, $text, $html);
    }

    private function newToken(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }
}
