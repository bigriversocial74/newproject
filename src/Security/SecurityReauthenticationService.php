<?php

declare(strict_types=1);

namespace Vp3\Security;

use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;
use PDO;
use RuntimeException;
use Vp3\Database;

final class SecurityReauthenticationService
{
    public function __construct(private readonly Database $database)
    {
    }

    /**
     * @param array<string,mixed> $context
     * @return array{public_id:string,challenge:string,expires_at:string}
     */
    public function issue(
        int $accountId,
        int $userId,
        string $actionType,
        array $context = [],
        int $ttlSeconds = 300
    ): array {
        if ($accountId <= 0 || $userId <= 0) {
            throw new InvalidArgumentException('A valid account and user are required.');
        }
        $actionType = trim($actionType);
        if ($actionType === '') {
            throw new InvalidArgumentException('A sensitive action type is required.');
        }

        $ttlSeconds = max(60, min($ttlSeconds, 900));
        $challenge = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $publicId = 'SRC-' . strtoupper(bin2hex(random_bytes(16)));
        $challengeHash = hash('sha256', $challenge);
        $contextHash = hash('sha256', $this->canonicalJson($context));
        $now = $this->now();
        $expiresAt = (new DateTimeImmutable('+' . $ttlSeconds . ' seconds', new DateTimeZone('UTC')))
            ->format('Y-m-d H:i:s');

        $statement = $this->database->pdo()->prepare(
            'INSERT INTO security_reauthentication_challenges
             (public_id,account_scope,user_id,action_type,challenge_hash,context_hash,status,
              expires_at,satisfied_at,consumed_at,revoked_at,created_at)
             VALUES (:public_id,:account_scope,:user_id,:action_type,:challenge_hash,:context_hash,\'pending\',
                     :expires_at,NULL,NULL,NULL,:created_at)'
        );
        $statement->execute([
            'public_id' => $publicId,
            'account_scope' => $accountId,
            'user_id' => $userId,
            'action_type' => mb_substr($actionType, 0, 120),
            'challenge_hash' => $challengeHash,
            'context_hash' => $contextHash,
            'expires_at' => $expiresAt,
            'created_at' => $now,
        ]);

        return [
            'public_id' => $publicId,
            'challenge' => $challenge,
            'expires_at' => $expiresAt,
        ];
    }

    /** @param array<string,mixed> $context */
    public function satisfy(
        string $publicId,
        string $challenge,
        int $accountId,
        int $userId,
        string $actionType,
        array $context = []
    ): bool {
        $challengeHash = hash('sha256', $challenge);
        $contextHash = hash('sha256', $this->canonicalJson($context));
        $now = $this->now();

        $statement = $this->database->pdo()->prepare(
            'UPDATE security_reauthentication_challenges
             SET status=\'satisfied\',satisfied_at=:satisfied_at
             WHERE public_id=:public_id AND account_scope=:account_scope AND user_id=:user_id
               AND action_type=:action_type AND challenge_hash=:challenge_hash AND context_hash=:context_hash
               AND status=\'pending\' AND expires_at>:current_time'
        );
        $statement->execute([
            'satisfied_at' => $now,
            'public_id' => $publicId,
            'account_scope' => $accountId,
            'user_id' => $userId,
            'action_type' => mb_substr(trim($actionType), 0, 120),
            'challenge_hash' => $challengeHash,
            'context_hash' => $contextHash,
            'current_time' => $now,
        ]);

        return $statement->rowCount() === 1;
    }

    /** @param array<string,mixed> $context */
    public function consume(
        string $publicId,
        int $accountId,
        int $userId,
        string $actionType,
        array $context = []
    ): void {
        $contextHash = hash('sha256', $this->canonicalJson($context));
        $now = $this->now();

        $statement = $this->database->pdo()->prepare(
            'UPDATE security_reauthentication_challenges
             SET status=\'consumed\',consumed_at=:consumed_at
             WHERE public_id=:public_id AND account_scope=:account_scope AND user_id=:user_id
               AND action_type=:action_type AND context_hash=:context_hash
               AND status=\'satisfied\' AND expires_at>:current_time'
        );
        $statement->execute([
            'consumed_at' => $now,
            'public_id' => $publicId,
            'account_scope' => $accountId,
            'user_id' => $userId,
            'action_type' => mb_substr(trim($actionType), 0, 120),
            'context_hash' => $contextHash,
            'current_time' => $now,
        ]);

        if ($statement->rowCount() !== 1) {
            throw new RuntimeException('Sensitive-action reauthentication is missing, expired, or already used.');
        }
    }

    public function expireOutstanding(): int
    {
        $statement = $this->database->pdo()->prepare(
            'UPDATE security_reauthentication_challenges
             SET status=\'expired\'
             WHERE status IN (\'pending\',\'satisfied\') AND expires_at<=:current_time'
        );
        $statement->execute(['current_time' => $this->now()]);
        return $statement->rowCount();
    }

    private function canonicalJson(mixed $value): string
    {
        return json_encode(
            $this->canonicalize($value),
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION
        );
    }

    private function canonicalize(mixed $value): mixed
    {
        if (!is_array($value)) {
            return $value;
        }
        if (array_is_list($value)) {
            return array_map(fn (mixed $item): mixed => $this->canonicalize($item), $value);
        }
        ksort($value, SORT_STRING);
        foreach ($value as $key => $item) {
            $value[$key] = $this->canonicalize($item);
        }
        return $value;
    }

    private function now(): string
    {
        return (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s');
    }
}
