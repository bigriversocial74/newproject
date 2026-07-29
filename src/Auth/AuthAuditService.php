<?php

declare(strict_types=1);

namespace Vp3\Auth;

use DateTimeImmutable;
use Vp3\Database;

final class AuthAuditService
{
    public function __construct(private readonly Database $database)
    {
    }

    /** @param array<string,scalar|null> $metadata */
    public function record(
        string $eventType,
        string $result,
        ?int $actorId = null,
        ?int $accountId = null,
        ?string $resourceType = null,
        ?string $resourcePublicId = null,
        array $metadata = [],
        ?string $requestId = null
    ): string {
        $requestId ??= $this->requestId();
        $safeMetadata = $this->sanitize($metadata);
        $statement = $this->database->pdo()->prepare(
            'INSERT INTO audit_events
             (request_id, actor_type, actor_id, account_id, event_type, resource_type, resource_public_id, result, metadata_json, created_at)
             VALUES (:request_id, :actor_type, :actor_id, :account_id, :event_type, :resource_type, :resource_public_id, :result, :metadata_json, :created_at)'
        );
        $statement->execute([
            'request_id' => $requestId,
            'actor_type' => $actorId === null ? 'system' : 'user',
            'actor_id' => $actorId,
            'account_id' => $accountId,
            'event_type' => $eventType,
            'resource_type' => $resourceType,
            'resource_public_id' => $resourcePublicId,
            'result' => in_array($result, ['success', 'failure', 'denied'], true) ? $result : 'failure',
            'metadata_json' => $safeMetadata === [] ? null : json_encode($safeMetadata, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            'created_at' => (new DateTimeImmutable('now'))->format('Y-m-d H:i:s'),
        ]);
        return $requestId;
    }

    /** @param array<string,scalar|null> $metadata */
    public function sessionEvent(
        string $eventType,
        ?string $sessionPublicId,
        ?int $userId,
        string $ip,
        string $userAgent,
        array $metadata = [],
        ?string $requestId = null
    ): string {
        $requestId ??= $this->requestId();
        $safeMetadata = $this->sanitize($metadata);
        $statement = $this->database->pdo()->prepare(
            'INSERT INTO auth_session_events
             (session_public_id, user_id, request_id, event_type, ip_hash, user_agent_hash, metadata_json, created_at)
             VALUES (:session_public_id, :user_id, :request_id, :event_type, :ip_hash, :user_agent_hash, :metadata_json, :created_at)'
        );
        $statement->execute([
            'session_public_id' => $sessionPublicId,
            'user_id' => $userId,
            'request_id' => $requestId,
            'event_type' => $eventType,
            'ip_hash' => $ip === '' ? null : hash('sha256', $ip),
            'user_agent_hash' => $userAgent === '' ? null : hash('sha256', $userAgent),
            'metadata_json' => $safeMetadata === [] ? null : json_encode($safeMetadata, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            'created_at' => (new DateTimeImmutable('now'))->format('Y-m-d H:i:s'),
        ]);
        return $requestId;
    }

    public function requestId(): string
    {
        return 'REQ-' . strtoupper(bin2hex(random_bytes(12)));
    }

    /** @param array<string,scalar|null> $metadata @return array<string,scalar|null> */
    private function sanitize(array $metadata): array
    {
        $blocked = ['password', 'token', 'secret', 'authorization', 'cookie', 'email_body', 'smtp_password'];
        $safe = [];
        foreach ($metadata as $key => $value) {
            $normalized = strtolower((string) $key);
            foreach ($blocked as $needle) {
                if (str_contains($normalized, $needle)) {
                    continue 2;
                }
            }
            if (is_scalar($value) || $value === null) {
                $safe[(string) $key] = $value;
            }
        }
        return $safe;
    }
}
