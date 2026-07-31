<?php

declare(strict_types=1);

namespace Vp3\Security;

use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;
use PDO;
use RuntimeException;
use Vp3\Database;

final class SecurityAuditService
{
    private const CATEGORIES = [
        'authentication', 'session', 'mfa', 'team', 'billing', 'domain',
        'pod', 'homeserver', 'settings', 'integrity', 'platform',
    ];

    private const RISK_LEVELS = ['info', 'low', 'medium', 'high', 'critical'];
    private const RESULTS = ['success', 'failure', 'denied', 'ignored'];

    /** @var list<string> */
    private const BLOCKED_METADATA_KEYS = [
        'password', 'passphrase', 'token', 'secret', 'authorization', 'cookie',
        'csrf', 'credential', 'private_key', 'recovery_code', 'ciphertext',
        'raw_payload', 'request_body', 'response_body', 'email_body', 'smtp_password',
    ];

    public function __construct(private readonly Database $database)
    {
    }

    /**
     * @param array<string,mixed> $metadata
     * @return array{public_id:string,request_id:string,sequence_number:int,chain_hash:string}
     */
    public function record(
        string $eventType,
        string $category,
        string $riskLevel,
        string $result,
        ?int $accountId = null,
        string $actorType = 'system',
        ?int $actorId = null,
        ?string $actorPublicId = null,
        ?string $resourceType = null,
        ?string $resourcePublicId = null,
        array $metadata = [],
        ?string $requestId = null,
        ?string $correlationId = null,
        string $ipAddress = '',
        string $userAgent = ''
    ): array {
        $eventType = $this->boundedRequired($eventType, 120, 'event type');
        $category = $this->enum($category, self::CATEGORIES, 'category');
        $riskLevel = $this->enum($riskLevel, self::RISK_LEVELS, 'risk level');
        $result = $this->enum($result, self::RESULTS, 'result');
        $actorType = $this->boundedRequired($actorType, 40, 'actor type');
        $accountScope = max(0, $accountId ?? 0);
        $requestId = $requestId === null || trim($requestId) === ''
            ? $this->requestId()
            : $this->boundedRequired($requestId, 80, 'request id');
        $correlationId = $this->boundedNullable($correlationId, 80);
        $actorPublicId = $this->boundedNullable($actorPublicId, 64);
        $resourceType = $this->boundedNullable($resourceType, 80);
        $resourcePublicId = $this->boundedNullable($resourcePublicId, 128);
        $safeMetadata = $this->sanitizeMetadata($metadata);
        $metadataJson = $this->canonicalJson($safeMetadata);
        $metadataHash = hash('sha256', $metadataJson);
        $ipHash = $this->hashClientValue($ipAddress);
        $userAgentHash = $this->hashClientValue($userAgent);

        return $this->database->transaction(function (PDO $pdo) use (
            $eventType,
            $category,
            $riskLevel,
            $result,
            $accountScope,
            $actorType,
            $actorId,
            $actorPublicId,
            $resourceType,
            $resourcePublicId,
            $requestId,
            $correlationId,
            $safeMetadata,
            $metadataJson,
            $metadataHash,
            $ipHash,
            $userAgentHash
        ): array {
            $pdo->prepare(
                'INSERT IGNORE INTO security_audit_heads
                 (account_scope,last_sequence,last_chain_hash,updated_at)
                 VALUES (:scope,0,:zero_hash,:updated_at)'
            )->execute([
                'scope' => $accountScope,
                'zero_hash' => str_repeat('0', 64),
                'updated_at' => $this->nowMicroseconds(),
            ]);

            $head = $pdo->prepare(
                'SELECT last_sequence,last_chain_hash
                 FROM security_audit_heads WHERE account_scope=:scope FOR UPDATE'
            );
            $head->execute(['scope' => $accountScope]);
            $headRow = $head->fetch(PDO::FETCH_ASSOC);
            if (!is_array($headRow)) {
                throw new RuntimeException('The security audit chain head could not be loaded.');
            }

            $previousHash = (string) $headRow['last_chain_hash'];
            $sequence = ((int) $headRow['last_sequence']) + 1;
            $occurredAt = $this->nowMicroseconds();
            $publicId = 'SAE-' . strtoupper(bin2hex(random_bytes(16)));
            $chainHash = $this->chainHash([
                'previous_chain_hash' => $previousHash,
                'account_scope' => $accountScope,
                'sequence_number' => $sequence,
                'public_id' => $publicId,
                'request_id' => $requestId,
                'correlation_id' => $correlationId,
                'event_type' => $eventType,
                'category' => $category,
                'risk_level' => $riskLevel,
                'result' => $result,
                'actor_type' => $actorType,
                'actor_id' => $actorId,
                'actor_public_id' => $actorPublicId,
                'resource_type' => $resourceType,
                'resource_public_id' => $resourcePublicId,
                'ip_hash' => $ipHash,
                'user_agent_hash' => $userAgentHash,
                'metadata_hash' => $metadataHash,
                'occurred_at' => $occurredAt,
            ]);

            $insert = $pdo->prepare(
                'INSERT INTO security_audit_events
                 (public_id,account_scope,sequence_number,request_id,correlation_id,event_type,category,
                  risk_level,result,actor_type,actor_id,actor_public_id,resource_type,resource_public_id,
                  ip_hash,user_agent_hash,metadata_json,metadata_hash,previous_chain_hash,chain_hash,
                  occurred_at,created_at)
                 VALUES
                 (:public_id,:account_scope,:sequence_number,:request_id,:correlation_id,:event_type,:category,
                  :risk_level,:result,:actor_type,:actor_id,:actor_public_id,:resource_type,:resource_public_id,
                  :ip_hash,:user_agent_hash,:metadata_json,:metadata_hash,:previous_chain_hash,:chain_hash,
                  :occurred_at,:created_at)'
            );
            $insert->execute([
                'public_id' => $publicId,
                'account_scope' => $accountScope,
                'sequence_number' => $sequence,
                'request_id' => $requestId,
                'correlation_id' => $correlationId,
                'event_type' => $eventType,
                'category' => $category,
                'risk_level' => $riskLevel,
                'result' => $result,
                'actor_type' => $actorType,
                'actor_id' => $actorId,
                'actor_public_id' => $actorPublicId,
                'resource_type' => $resourceType,
                'resource_public_id' => $resourcePublicId,
                'ip_hash' => $ipHash,
                'user_agent_hash' => $userAgentHash,
                'metadata_json' => $safeMetadata === [] ? null : $metadataJson,
                'metadata_hash' => $metadataHash,
                'previous_chain_hash' => $previousHash,
                'chain_hash' => $chainHash,
                'occurred_at' => $occurredAt,
                'created_at' => $occurredAt,
            ]);

            $update = $pdo->prepare(
                'UPDATE security_audit_heads
                 SET last_sequence=:sequence,last_chain_hash=:chain_hash,updated_at=:updated_at
                 WHERE account_scope=:scope AND last_sequence=:previous_sequence
                   AND last_chain_hash=:previous_hash'
            );
            $update->execute([
                'sequence' => $sequence,
                'chain_hash' => $chainHash,
                'updated_at' => $occurredAt,
                'scope' => $accountScope,
                'previous_sequence' => $sequence - 1,
                'previous_hash' => $previousHash,
            ]);
            if ($update->rowCount() !== 1) {
                throw new RuntimeException('The security audit chain head changed unexpectedly.');
            }

            return [
                'public_id' => $publicId,
                'request_id' => $requestId,
                'sequence_number' => $sequence,
                'chain_hash' => $chainHash,
            ];
        });
    }

    public function verifyScope(?int $accountId = null): bool
    {
        $accountScope = max(0, $accountId ?? 0);
        $statement = $this->database->pdo()->prepare(
            'SELECT public_id,account_scope,sequence_number,request_id,correlation_id,event_type,category,
                    risk_level,result,actor_type,actor_id,actor_public_id,resource_type,resource_public_id,
                    ip_hash,user_agent_hash,metadata_hash,previous_chain_hash,chain_hash,occurred_at
             FROM security_audit_events WHERE account_scope=:scope ORDER BY sequence_number ASC'
        );
        $statement->execute(['scope' => $accountScope]);

        $previousHash = str_repeat('0', 64);
        $expectedSequence = 1;
        while (($row = $statement->fetch(PDO::FETCH_ASSOC)) !== false) {
            if ((int) $row['sequence_number'] !== $expectedSequence) {
                return false;
            }
            if (!hash_equals($previousHash, (string) $row['previous_chain_hash'])) {
                return false;
            }
            $expectedHash = $this->chainHash([
                'previous_chain_hash' => $previousHash,
                'account_scope' => (int) $row['account_scope'],
                'sequence_number' => (int) $row['sequence_number'],
                'public_id' => (string) $row['public_id'],
                'request_id' => (string) $row['request_id'],
                'correlation_id' => $row['correlation_id'] === null ? null : (string) $row['correlation_id'],
                'event_type' => (string) $row['event_type'],
                'category' => (string) $row['category'],
                'risk_level' => (string) $row['risk_level'],
                'result' => (string) $row['result'],
                'actor_type' => (string) $row['actor_type'],
                'actor_id' => $row['actor_id'] === null ? null : (int) $row['actor_id'],
                'actor_public_id' => $row['actor_public_id'] === null ? null : (string) $row['actor_public_id'],
                'resource_type' => $row['resource_type'] === null ? null : (string) $row['resource_type'],
                'resource_public_id' => $row['resource_public_id'] === null ? null : (string) $row['resource_public_id'],
                'ip_hash' => $row['ip_hash'] === null ? null : (string) $row['ip_hash'],
                'user_agent_hash' => $row['user_agent_hash'] === null ? null : (string) $row['user_agent_hash'],
                'metadata_hash' => (string) $row['metadata_hash'],
                'occurred_at' => (string) $row['occurred_at'],
            ]);
            if (!hash_equals($expectedHash, (string) $row['chain_hash'])) {
                return false;
            }
            $previousHash = (string) $row['chain_hash'];
            ++$expectedSequence;
        }

        $head = $this->database->pdo()->prepare(
            'SELECT last_sequence,last_chain_hash FROM security_audit_heads WHERE account_scope=:scope'
        );
        $head->execute(['scope' => $accountScope]);
        $headRow = $head->fetch(PDO::FETCH_ASSOC);
        if (!is_array($headRow)) {
            return $expectedSequence === 1;
        }

        return (int) $headRow['last_sequence'] === $expectedSequence - 1
            && hash_equals($previousHash, (string) $headRow['last_chain_hash']);
    }

    public function requestId(): string
    {
        return 'REQ-' . strtoupper(bin2hex(random_bytes(12)));
    }

    public static function categoryForEventType(string $eventType): string
    {
        $prefix = strtolower((string) strtok($eventType, '.'));
        return match ($prefix) {
            'auth' => 'authentication',
            'session' => 'session',
            'mfa' => 'mfa',
            'account', 'team' => 'team',
            'billing', 'stripe' => 'billing',
            'domain' => 'domain',
            'pod' => 'pod',
            'homeserver' => 'homeserver',
            'settings' => 'settings',
            'integrity', 'request_integrity' => 'integrity',
            default => 'platform',
        };
    }

    public static function riskFor(string $eventType, string $result): string
    {
        $normalized = strtolower($eventType . ' ' . $result);
        if (str_contains($normalized, 'critical') || str_contains($normalized, 'compromise')) {
            return 'critical';
        }
        if ($result === 'denied' || str_contains($normalized, 'revoke') || str_contains($normalized, 'reset')) {
            return 'high';
        }
        if ($result === 'failure' || str_contains($normalized, 'login') || str_contains($normalized, 'mfa')) {
            return 'medium';
        }
        return 'info';
    }

    /** @param array<string,mixed> $metadata @return array<string,mixed> */
    private function sanitizeMetadata(array $metadata): array
    {
        $value = $this->sanitizeValue($metadata, 0);
        return is_array($value) ? $value : [];
    }

    private function sanitizeValue(mixed $value, int $depth): mixed
    {
        if ($depth > 6) {
            return '[depth-limit]';
        }
        if ($value === null || is_bool($value) || is_int($value) || is_float($value)) {
            return $value;
        }
        if (is_string($value)) {
            return mb_substr($value, 0, 2048);
        }
        if (!is_array($value)) {
            return null;
        }

        $safe = [];
        $count = 0;
        foreach ($value as $key => $item) {
            if (++$count > 100) {
                $safe['_truncated'] = true;
                break;
            }
            $stringKey = (string) $key;
            if ($this->blockedMetadataKey($stringKey)) {
                continue;
            }
            $safe[$stringKey] = $this->sanitizeValue($item, $depth + 1);
        }
        return $safe;
    }

    private function blockedMetadataKey(string $key): bool
    {
        $normalized = strtolower(str_replace(['-', ' '], '_', $key));
        foreach (self::BLOCKED_METADATA_KEYS as $blocked) {
            if (str_contains($normalized, $blocked)) {
                return true;
            }
        }
        return false;
    }

    /** @param array<string,mixed> $payload */
    private function chainHash(array $payload): string
    {
        return hash('sha256', $this->canonicalJson($payload));
    }

    private function canonicalJson(mixed $value): string
    {
        $canonical = $this->canonicalize($value);
        return json_encode(
            $canonical,
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

    private function hashClientValue(string $value): ?string
    {
        $value = trim($value);
        return $value === '' ? null : hash('sha256', $value);
    }

    /** @param list<string> $allowed */
    private function enum(string $value, array $allowed, string $label): string
    {
        if (!in_array($value, $allowed, true)) {
            throw new InvalidArgumentException('Invalid security audit ' . $label . '.');
        }
        return $value;
    }

    private function boundedRequired(string $value, int $length, string $label): string
    {
        $value = trim($value);
        if ($value === '') {
            throw new InvalidArgumentException('Security audit ' . $label . ' is required.');
        }
        return mb_substr($value, 0, $length);
    }

    private function boundedNullable(?string $value, int $length): ?string
    {
        if ($value === null || trim($value) === '') {
            return null;
        }
        return mb_substr(trim($value), 0, $length);
    }

    private function nowMicroseconds(): string
    {
        return (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s.u');
    }
}
