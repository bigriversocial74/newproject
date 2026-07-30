<?php

declare(strict_types=1);

namespace Vp3\Auth;

use DateTimeImmutable;
use PDO;
use RuntimeException;
use Vp3\Database;

final class MfaService
{
    public function __construct(
        private readonly Database $database,
        private readonly AuthSecretCipher $cipher,
        private readonly AuthAuditService $audit,
        private readonly int $challengeTtlSeconds = 300,
        private readonly int $recoveryCodeCount = 10
    ) {
    }

    /** @return array{enabled:bool,status:string,recovery_codes_remaining:int,activated_at:?string} */
    public function status(int $userId): array
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT status,activated_at FROM auth_mfa_methods WHERE user_id=:user AND method_type='totp' LIMIT 1"
        );
        $statement->execute(['user' => $userId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        $remaining = $this->database->pdo()->prepare(
            'SELECT COUNT(*) FROM auth_mfa_recovery_codes WHERE user_id=:user AND used_at IS NULL'
        );
        $remaining->execute(['user' => $userId]);
        return [
            'enabled' => is_array($row) && (string) $row['status'] === 'active',
            'status' => is_array($row) ? (string) $row['status'] : 'not_configured',
            'recovery_codes_remaining' => (int) $remaining->fetchColumn(),
            'activated_at' => is_array($row) && $row['activated_at'] !== null ? (string) $row['activated_at'] : null,
        ];
    }

    /** @return array{secret:string,otpauth_uri:string,issuer:string,account:string} */
    public function beginEnrollment(int $userId, string $email, string $displayName, string $requestId): array
    {
        $secret = self::base32Encode(random_bytes(20));
        $context = $this->context($userId);
        $encrypted = $this->cipher->encrypt($secret, $context);
        $now = new DateTimeImmutable('now');
        $label = trim($displayName) !== '' ? trim($displayName) : strtolower(trim($email));
        $this->database->transaction(function (PDO $pdo) use ($userId, $encrypted, $label, $now, $requestId): void {
            $pdo->prepare('DELETE FROM auth_mfa_recovery_codes WHERE user_id=:user')->execute(['user' => $userId]);
            $pdo->prepare(
                "INSERT INTO auth_mfa_methods
                 (user_id,method_type,status,secret_ciphertext,secret_nonce,secret_tag,secret_key_id,label,last_used_counter,
                  activated_at,disabled_at,created_at,updated_at)
                 VALUES (:user,'totp','pending',:ciphertext,:nonce,:tag,:key_id,:label,NULL,NULL,NULL,:now,:now)
                 ON DUPLICATE KEY UPDATE status='pending',secret_ciphertext=VALUES(secret_ciphertext),secret_nonce=VALUES(secret_nonce),
                   secret_tag=VALUES(secret_tag),secret_key_id=VALUES(secret_key_id),label=VALUES(label),last_used_counter=NULL,
                   activated_at=NULL,disabled_at=NULL,updated_at=VALUES(updated_at)"
            )->execute([
                'user' => $userId,
                'ciphertext' => $encrypted['ciphertext'],
                'nonce' => $encrypted['nonce'],
                'tag' => $encrypted['tag'],
                'key_id' => $encrypted['key_id'],
                'label' => mb_substr($label, 0, 190),
                'now' => $now->format('Y-m-d H:i:s'),
            ]);
            $this->receipt($pdo, null, $userId, $userId, 'mfa.enrollment_started', 'success', $requestId, ['method' => 'totp']);
        });
        $issuer = 'VP3.me';
        $account = strtolower(trim($email));
        $uri = 'otpauth://totp/' . rawurlencode($issuer . ':' . $account)
            . '?secret=' . rawurlencode($secret)
            . '&issuer=' . rawurlencode($issuer)
            . '&algorithm=SHA1&digits=6&period=30';
        return ['secret' => $secret, 'otpauth_uri' => $uri, 'issuer' => $issuer, 'account' => $account];
    }

    /** @return array{recovery_codes:list<string>,enabled:bool} */
    public function confirmEnrollment(int $userId, string $code, string $requestId): array
    {
        $result = $this->database->transaction(function (PDO $pdo) use ($userId, $code, $requestId): array {
            $method = $this->method($pdo, $userId, true);
            if ($method === null || (string) $method['status'] !== 'pending') {
                throw new AuthPublicException('mfa_enrollment_missing', 'Start MFA enrollment before confirming a code.', 409);
            }
            $secret = $this->decryptMethod($method, $userId);
            $counter = $this->matchingCounter($secret, $code, null);
            if ($counter === null) {
                $this->receipt($pdo, null, $userId, $userId, 'mfa.enrollment_confirmed', 'denied', $requestId, ['reason' => 'invalid_code']);
                return ['denied' => 'invalid_code'];
            }
            $now = new DateTimeImmutable('now');
            $pdo->prepare(
                "UPDATE auth_mfa_methods SET status='active',last_used_counter=:counter,activated_at=:now,disabled_at=NULL,updated_at=:now
                 WHERE id=:id AND status='pending'"
            )->execute(['counter' => $counter, 'now' => $now->format('Y-m-d H:i:s'), 'id' => $method['id']]);
            $pdo->prepare('DELETE FROM auth_mfa_recovery_codes WHERE user_id=:user')->execute(['user' => $userId]);
            $codes = $this->newRecoveryCodes();
            $insert = $pdo->prepare(
                'INSERT INTO auth_mfa_recovery_codes (user_id,code_hash,used_at,created_at) VALUES (:user,:hash,NULL,:now)'
            );
            foreach ($codes as $recoveryCode) {
                $insert->execute(['user' => $userId, 'hash' => hash('sha256', $this->normalizeRecoveryCode($recoveryCode)), 'now' => $now->format('Y-m-d H:i:s')]);
            }
            $this->receipt($pdo, null, $userId, $userId, 'mfa.enrollment_confirmed', 'success', $requestId, ['recovery_code_count' => count($codes)]);
            $this->audit->record('auth.mfa.enabled', 'success', $userId, null, 'user', null, ['method' => 'totp'], $requestId);
            return ['recovery_codes' => $codes, 'enabled' => true];
        });
        if (($result['denied'] ?? null) === 'invalid_code') {
            throw new AuthPublicException('mfa_code_invalid', 'The verification code is invalid or expired.', 422);
        }
        return $result;
    }

    public function disable(int $userId, string $password, string $requestId): void
    {
        $this->database->transaction(function (PDO $pdo) use ($userId, $password, $requestId): void {
            $user = $pdo->prepare('SELECT password_hash FROM users WHERE id=:user AND status=\'active\' LIMIT 1 FOR UPDATE');
            $user->execute(['user' => $userId]);
            $hash = $user->fetchColumn();
            if (!is_string($hash) || !password_verify($password, $hash)) {
                $this->receipt($pdo, null, $userId, $userId, 'mfa.disabled', 'denied', $requestId, ['reason' => 'password_invalid']);
                throw new AuthPublicException('password_invalid', 'The current password is incorrect.', 403);
            }
            $now = (new DateTimeImmutable('now'))->format('Y-m-d H:i:s');
            $pdo->prepare(
                "UPDATE auth_mfa_methods SET status='disabled',secret_ciphertext='',secret_nonce='',secret_tag='',
                 last_used_counter=NULL,disabled_at=:now,updated_at=:now WHERE user_id=:user AND method_type='totp'"
            )->execute(['now' => $now, 'user' => $userId]);
            $pdo->prepare('DELETE FROM auth_mfa_recovery_codes WHERE user_id=:user')->execute(['user' => $userId]);
            $pdo->prepare('UPDATE auth_mfa_challenges SET consumed_at=:now WHERE user_id=:user AND consumed_at IS NULL')
                ->execute(['now' => $now, 'user' => $userId]);
            $this->receipt($pdo, null, $userId, $userId, 'mfa.disabled', 'success', $requestId, []);
            $this->audit->record('auth.mfa.disabled', 'success', $userId, null, 'user', null, [], $requestId);
        });
    }

    public function requiresMfa(int $userId): bool
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT 1 FROM auth_mfa_methods WHERE user_id=:user AND method_type='totp' AND status='active' LIMIT 1"
        );
        $statement->execute(['user' => $userId]);
        return (bool) $statement->fetchColumn();
    }

    /** @return array{challenge_token:string,challenge_public_id:string,expires_at:string} */
    public function createChallenge(int $userId, string $ip, string $userAgent): array
    {
        if (!$this->requiresMfa($userId)) {
            throw new AuthPublicException('mfa_not_enabled', 'MFA is not enabled for this account.', 409);
        }
        $token = self::token(32);
        $publicId = 'MFA-' . strtoupper(bin2hex(random_bytes(10)));
        $now = new DateTimeImmutable('now');
        $expires = $now->modify('+' . max(60, $this->challengeTtlSeconds) . ' seconds');
        $this->database->transaction(function (PDO $pdo) use ($userId, $ip, $userAgent, $token, $publicId, $now, $expires): void {
            $pdo->prepare('UPDATE auth_mfa_challenges SET consumed_at=:now WHERE user_id=:user AND consumed_at IS NULL')
                ->execute(['now' => $now->format('Y-m-d H:i:s'), 'user' => $userId]);
            $pdo->prepare(
                'INSERT INTO auth_mfa_challenges
                 (public_id,user_id,token_hash,ip_hash,user_agent_hash,expires_at,consumed_at,created_at)
                 VALUES (:public,:user,:token_hash,:ip_hash,:ua_hash,:expires,NULL,:now)'
            )->execute([
                'public' => $publicId,
                'user' => $userId,
                'token_hash' => hash('sha256', $token),
                'ip_hash' => hash('sha256', $ip),
                'ua_hash' => hash('sha256', $userAgent),
                'expires' => $expires->format('Y-m-d H:i:s'),
                'now' => $now->format('Y-m-d H:i:s'),
            ]);
        });
        return ['challenge_token' => $token, 'challenge_public_id' => $publicId, 'expires_at' => $expires->format(DATE_ATOM)];
    }

    /** @return array{id:int,public_id:string,email:string,display_name:string} */
    public function completeChallenge(string $token, string $code, string $ip, string $userAgent, string $requestId): array
    {
        $result = $this->database->transaction(function (PDO $pdo) use ($token, $code, $ip, $userAgent, $requestId): array {
            $challenge = $pdo->prepare(
                "SELECT c.*,u.public_id AS user_public_id,u.email,u.display_name,u.status AS user_status
                 FROM auth_mfa_challenges c JOIN users u ON u.id=c.user_id
                 WHERE c.token_hash=:token_hash LIMIT 1 FOR UPDATE"
            );
            $challenge->execute(['token_hash' => hash('sha256', trim($token))]);
            $row = $challenge->fetch(PDO::FETCH_ASSOC);
            $now = new DateTimeImmutable('now');
            if (!is_array($row) || $row['consumed_at'] !== null || $now >= new DateTimeImmutable((string) $row['expires_at'])
                || !hash_equals((string) $row['ip_hash'], hash('sha256', $ip))
                || !hash_equals((string) $row['user_agent_hash'], hash('sha256', $userAgent))
                || (string) $row['user_status'] !== 'active') {
                throw new AuthPublicException('mfa_challenge_invalid', 'The MFA challenge is invalid or expired.', 401);
            }
            $userId = (int) $row['user_id'];
            $method = $this->method($pdo, $userId, true);
            if ($method === null || (string) $method['status'] !== 'active') {
                throw new AuthPublicException('mfa_challenge_invalid', 'The MFA challenge is invalid or expired.', 401);
            }
            $verified = false;
            $normalizedRecovery = $this->normalizeRecoveryCode($code);
            if (preg_match('/^[A-Z0-9]{12}$/', $normalizedRecovery)) {
                $recovery = $pdo->prepare(
                    'SELECT id FROM auth_mfa_recovery_codes WHERE user_id=:user AND code_hash=:hash AND used_at IS NULL LIMIT 1 FOR UPDATE'
                );
                $recovery->execute(['user' => $userId, 'hash' => hash('sha256', $normalizedRecovery)]);
                $recoveryId = (int) $recovery->fetchColumn();
                if ($recoveryId > 0) {
                    $pdo->prepare('UPDATE auth_mfa_recovery_codes SET used_at=:now WHERE id=:id AND used_at IS NULL')
                        ->execute(['now' => $now->format('Y-m-d H:i:s'), 'id' => $recoveryId]);
                    $verified = true;
                }
            } else {
                $secret = $this->decryptMethod($method, $userId);
                $lastCounter = $method['last_used_counter'] === null ? null : (int) $method['last_used_counter'];
                $counter = $this->matchingCounter($secret, $code, $lastCounter);
                if ($counter !== null) {
                    $pdo->prepare('UPDATE auth_mfa_methods SET last_used_counter=:counter,updated_at=:now WHERE id=:id')
                        ->execute(['counter' => $counter, 'now' => $now->format('Y-m-d H:i:s'), 'id' => $method['id']]);
                    $verified = true;
                }
            }
            if (!$verified) {
                $this->receipt($pdo, null, $userId, $userId, 'mfa.challenge_completed', 'denied', $requestId, ['reason' => 'code_invalid']);
                return ['denied' => 'invalid_code'];
            }
            $pdo->prepare('UPDATE auth_mfa_challenges SET consumed_at=:now WHERE id=:id AND consumed_at IS NULL')
                ->execute(['now' => $now->format('Y-m-d H:i:s'), 'id' => $row['id']]);
            $this->receipt($pdo, null, $userId, $userId, 'mfa.challenge_completed', 'success', $requestId, []);
            $this->audit->record('auth.mfa.challenge_completed', 'success', $userId, null, 'user', (string) $row['user_public_id'], [], $requestId);
            return ['user' => ['id' => $userId, 'public_id' => (string) $row['user_public_id'], 'email' => (string) $row['email'], 'display_name' => (string) $row['display_name']]];
        });
        if (($result['denied'] ?? null) === 'invalid_code') {
            throw new AuthPublicException('mfa_code_invalid', 'The verification code is invalid or already used.', 401);
        }
        return $result['user'];
    }

    /** @return array<string,mixed>|null */
    private function method(PDO $pdo, int $userId, bool $lock): ?array
    {
        $sql = "SELECT * FROM auth_mfa_methods WHERE user_id=:user AND method_type='totp' LIMIT 1" . ($lock ? ' FOR UPDATE' : '');
        $statement = $pdo->prepare($sql);
        $statement->execute(['user' => $userId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $row : null;
    }

    /** @param array<string,mixed> $method */
    private function decryptMethod(array $method, int $userId): string
    {
        return $this->cipher->decrypt(
            (string) $method['secret_ciphertext'],
            (string) $method['secret_nonce'],
            (string) $method['secret_tag'],
            $this->context($userId)
        );
    }

    private function matchingCounter(string $secret, string $code, ?int $minimumExclusive): ?int
    {
        $normalized = preg_replace('/\D+/', '', trim($code));
        if (!is_string($normalized) || strlen($normalized) !== 6) {
            return null;
        }
        $current = intdiv(time(), 30);
        foreach ([$current - 1, $current, $current + 1] as $counter) {
            if ($minimumExclusive !== null && $counter <= $minimumExclusive) {
                continue;
            }
            if (hash_equals($this->hotp($secret, $counter), $normalized)) {
                return $counter;
            }
        }
        return null;
    }

    private function hotp(string $base32Secret, int $counter): string
    {
        $secret = self::base32Decode($base32Secret);
        $binaryCounter = pack('N2', ($counter >> 32) & 0xFFFFFFFF, $counter & 0xFFFFFFFF);
        $hash = hash_hmac('sha1', $binaryCounter, $secret, true);
        $offset = ord($hash[19]) & 0x0F;
        $value = ((ord($hash[$offset]) & 0x7F) << 24)
            | ((ord($hash[$offset + 1]) & 0xFF) << 16)
            | ((ord($hash[$offset + 2]) & 0xFF) << 8)
            | (ord($hash[$offset + 3]) & 0xFF);
        return str_pad((string) ($value % 1000000), 6, '0', STR_PAD_LEFT);
    }

    /** @return list<string> */
    private function newRecoveryCodes(): array
    {
        $codes = [];
        for ($i = 0; $i < max(6, $this->recoveryCodeCount); $i++) {
            $raw = strtoupper(bin2hex(random_bytes(6)));
            $codes[] = substr($raw, 0, 4) . '-' . substr($raw, 4, 4) . '-' . substr($raw, 8, 4);
        }
        return $codes;
    }

    private function normalizeRecoveryCode(string $code): string
    {
        return strtoupper((string) preg_replace('/[^A-Z0-9]/i', '', trim($code)));
    }

    /** @param array<string,mixed> $metadata */
    private function receipt(PDO $pdo, ?int $accountId, ?int $actorUserId, ?int $targetUserId, string $action, string $result, string $requestId, array $metadata): void
    {
        $evidence = ['action' => $action, 'result' => $result, 'account_id' => $accountId, 'actor_user_id' => $actorUserId, 'target_user_id' => $targetUserId, 'metadata' => $metadata];
        $pdo->prepare(
            'INSERT INTO account_security_receipts
             (public_id,account_id,actor_user_id,target_user_id,action,result,request_id,evidence_hash,created_at)
             VALUES (:public,:account,:actor,:target,:action,:result,:request,:hash,:now)'
        )->execute([
            'public' => 'SEC-' . strtoupper(bin2hex(random_bytes(10))),
            'account' => $accountId,
            'actor' => $actorUserId,
            'target' => $targetUserId,
            'action' => $action,
            'result' => $result,
            'request' => $requestId,
            'hash' => hash('sha256', json_encode($evidence, JSON_THROW_ON_ERROR)),
            'now' => (new DateTimeImmutable('now'))->format('Y-m-d H:i:s'),
        ]);
    }

    private function context(int $userId): string
    {
        return 'vp3:auth:mfa:user:' . $userId . ':totp:v1';
    }

    private static function token(int $bytes): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }

    private static function base32Encode(string $bytes): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bits = '';
        foreach (str_split($bytes) as $byte) {
            $bits .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
        }
        $output = '';
        foreach (str_split($bits, 5) as $chunk) {
            $output .= $alphabet[bindec(str_pad($chunk, 5, '0', STR_PAD_RIGHT))];
        }
        return $output;
    }

    private static function base32Decode(string $value): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $clean = strtoupper((string) preg_replace('/[^A-Z2-7]/i', '', $value));
        $bits = '';
        foreach (str_split($clean) as $character) {
            $position = strpos($alphabet, $character);
            if ($position === false) {
                throw new RuntimeException('The MFA secret is invalid.');
            }
            $bits .= str_pad(decbin($position), 5, '0', STR_PAD_LEFT);
        }
        $output = '';
        foreach (str_split($bits, 8) as $chunk) {
            if (strlen($chunk) === 8) {
                $output .= chr(bindec($chunk));
            }
        }
        return $output;
    }
}
