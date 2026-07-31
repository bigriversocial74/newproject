<?php

declare(strict_types=1);

namespace Vp3\Security;

use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;
use PDO;
use Vp3\Database;

final class SecurityRateLimitService
{
    public function __construct(private readonly Database $database)
    {
    }

    /** @return array{allowed:bool,retry_after:int,attempt_count:int,blocked_until:?string,bucket_hash:string} */
    public function registerAttempt(
        string $scopeType,
        string $scopeKey,
        string $actionType,
        int $maxAttempts,
        int $windowSeconds,
        int $blockSeconds,
        ?string $requestId = null
    ): array {
        $scopeType = trim($scopeType);
        $scopeKey = trim($scopeKey);
        $actionType = trim($actionType);
        if ($scopeType === '' || $scopeKey === '' || $actionType === '') {
            throw new InvalidArgumentException('Rate-limit scope and action values are required.');
        }
        if ($maxAttempts < 1 || $windowSeconds < 1 || $blockSeconds < 1) {
            throw new InvalidArgumentException('Rate-limit thresholds must be positive.');
        }

        $scopeType = mb_substr($scopeType, 0, 40);
        $actionType = mb_substr($actionType, 0, 120);
        $requestId = $requestId === null || trim($requestId) === ''
            ? null
            : mb_substr(trim($requestId), 0, 80);
        $bucketHash = hash('sha256', $scopeType . '|' . $actionType . '|' . $scopeKey);

        return $this->database->transaction(function (PDO $pdo) use (
            $scopeType,
            $actionType,
            $requestId,
            $bucketHash,
            $maxAttempts,
            $windowSeconds,
            $blockSeconds
        ): array {
            $select = $pdo->prepare(
                'SELECT window_started_at,attempt_count,denied_count,blocked_until
                 FROM security_rate_limit_buckets WHERE bucket_hash=:bucket_hash FOR UPDATE'
            );
            $select->execute(['bucket_hash' => $bucketHash]);
            $row = $select->fetch(PDO::FETCH_ASSOC);
            $now = new DateTimeImmutable('now', new DateTimeZone('UTC'));
            $nowString = $now->format('Y-m-d H:i:s.u');

            if (!is_array($row)) {
                $insert = $pdo->prepare(
                    'INSERT INTO security_rate_limit_buckets
                     (bucket_hash,scope_type,action_type,window_started_at,attempt_count,denied_count,
                      blocked_until,last_request_id,created_at,updated_at)
                     VALUES (:bucket_hash,:scope_type,:action_type,:window_started_at,1,0,NULL,
                             :last_request_id,:created_at,:updated_at)'
                );
                $insert->execute([
                    'bucket_hash' => $bucketHash,
                    'scope_type' => $scopeType,
                    'action_type' => $actionType,
                    'window_started_at' => $nowString,
                    'last_request_id' => $requestId,
                    'created_at' => $nowString,
                    'updated_at' => $nowString,
                ]);

                return [
                    'allowed' => true,
                    'retry_after' => 0,
                    'attempt_count' => 1,
                    'blocked_until' => null,
                    'bucket_hash' => $bucketHash,
                ];
            }

            $blockedUntil = $row['blocked_until'] === null
                ? null
                : new DateTimeImmutable((string) $row['blocked_until'], new DateTimeZone('UTC'));
            if ($blockedUntil !== null && $blockedUntil > $now) {
                $denied = $pdo->prepare(
                    'UPDATE security_rate_limit_buckets
                     SET denied_count=denied_count+1,last_request_id=:request_id,updated_at=:updated_at
                     WHERE bucket_hash=:bucket_hash'
                );
                $denied->execute([
                    'request_id' => $requestId,
                    'updated_at' => $nowString,
                    'bucket_hash' => $bucketHash,
                ]);

                return [
                    'allowed' => false,
                    'retry_after' => max(1, $blockedUntil->getTimestamp() - $now->getTimestamp()),
                    'attempt_count' => (int) $row['attempt_count'],
                    'blocked_until' => $blockedUntil->format('Y-m-d H:i:s.u'),
                    'bucket_hash' => $bucketHash,
                ];
            }

            $windowStarted = new DateTimeImmutable((string) $row['window_started_at'], new DateTimeZone('UTC'));
            $windowExpired = ($now->getTimestamp() - $windowStarted->getTimestamp()) >= $windowSeconds;
            $attemptCount = $windowExpired ? 1 : ((int) $row['attempt_count']) + 1;
            $newWindow = $windowExpired ? $nowString : $windowStarted->format('Y-m-d H:i:s.u');
            $allowed = $attemptCount <= $maxAttempts;
            $newBlockedUntil = null;
            if (!$allowed) {
                $newBlockedUntil = $now->modify('+' . $blockSeconds . ' seconds');
            }

            $update = $pdo->prepare(
                'UPDATE security_rate_limit_buckets
                 SET window_started_at=:window_started_at,attempt_count=:attempt_count,
                     denied_count=denied_count+:denied_increment,blocked_until=:blocked_until,
                     last_request_id=:last_request_id,updated_at=:updated_at
                 WHERE bucket_hash=:bucket_hash'
            );
            $update->execute([
                'window_started_at' => $newWindow,
                'attempt_count' => $attemptCount,
                'denied_increment' => $allowed ? 0 : 1,
                'blocked_until' => $newBlockedUntil?->format('Y-m-d H:i:s.u'),
                'last_request_id' => $requestId,
                'updated_at' => $nowString,
                'bucket_hash' => $bucketHash,
            ]);

            return [
                'allowed' => $allowed,
                'retry_after' => $allowed ? 0 : $blockSeconds,
                'attempt_count' => $attemptCount,
                'blocked_until' => $newBlockedUntil?->format('Y-m-d H:i:s.u'),
                'bucket_hash' => $bucketHash,
            ];
        });
    }

    public function clear(string $scopeType, string $scopeKey, string $actionType): void
    {
        $bucketHash = hash('sha256', trim($scopeType) . '|' . trim($actionType) . '|' . trim($scopeKey));
        $statement = $this->database->pdo()->prepare(
            'DELETE FROM security_rate_limit_buckets WHERE bucket_hash=:bucket_hash'
        );
        $statement->execute(['bucket_hash' => $bucketHash]);
    }
}
