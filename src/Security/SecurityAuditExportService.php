<?php

declare(strict_types=1);

namespace Vp3\Security;

use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;
use PDO;
use RuntimeException;
use Vp3\Database;

final class SecurityAuditExportService
{
    public function __construct(
        private readonly Database $database,
        private readonly SecurityAuditQueryService $query
    ) {
    }

    /**
     * @param array<string,scalar|null> $filters
     * @return array{public_id:string,format:string,row_count:int,content_hash:string,expires_at:string,content:string}
     */
    public function build(
        int $accountId,
        int $userId,
        string $role,
        string $format,
        array $filters = []
    ): array {
        if (!$this->query->canExport($role)) {
            throw new RuntimeException('The current role cannot export security audit events.');
        }
        if (!in_array($format, ['csv', 'jsonl'], true)) {
            throw new InvalidArgumentException('Unsupported security audit export format.');
        }

        $filterJson = $this->canonicalJson($filters);
        $filterHash = hash('sha256', $filterJson);
        $publicId = 'SAX-' . strtoupper(bin2hex(random_bytes(16)));
        $createdAt = $this->now();
        $expiresAt = (new DateTimeImmutable('+15 minutes', new DateTimeZone('UTC')))->format('Y-m-d H:i:s');

        $insert = $this->database->pdo()->prepare(
            'INSERT INTO security_audit_exports
             (public_id,account_scope,requested_by,format,status,filter_hash,row_count,content_hash,
              failure_hash,expires_at,created_at,completed_at)
             VALUES (:public_id,:account_scope,:requested_by,:format,\'building\',:filter_hash,0,NULL,
                     NULL,:expires_at,:created_at,NULL)'
        );
        $insert->execute([
            'public_id' => $publicId,
            'account_scope' => $accountId,
            'requested_by' => $userId,
            'format' => $format,
            'filter_hash' => $filterHash,
            'expires_at' => $expiresAt,
            'created_at' => $createdAt,
        ]);

        try {
            $snapshot = $this->query->snapshot($accountId, $userId, $role, $filters, 500);
            $content = $format === 'csv'
                ? $this->csv($snapshot['events'])
                : $this->jsonLines($snapshot['events']);
            $contentHash = hash('sha256', $content);
            $rowCount = count($snapshot['events']);

            $update = $this->database->pdo()->prepare(
                'UPDATE security_audit_exports
                 SET status=\'ready\',row_count=:row_count,content_hash=:content_hash,completed_at=:completed_at
                 WHERE public_id=:public_id AND account_scope=:account_scope AND requested_by=:requested_by'
            );
            $update->execute([
                'row_count' => $rowCount,
                'content_hash' => $contentHash,
                'completed_at' => $this->now(),
                'public_id' => $publicId,
                'account_scope' => $accountId,
                'requested_by' => $userId,
            ]);

            (new SecurityAuditService($this->database))->record(
                eventType: 'security.audit.exported',
                category: 'platform',
                riskLevel: 'medium',
                result: 'success',
                accountId: $accountId,
                actorType: 'user',
                actorId: $userId,
                resourceType: 'security_audit_export',
                resourcePublicId: $publicId,
                metadata: [
                    'format' => $format,
                    'row_count' => $rowCount,
                    'filter_hash' => $filterHash,
                    'content_hash' => $contentHash,
                ]
            );

            return [
                'public_id' => $publicId,
                'format' => $format,
                'row_count' => $rowCount,
                'content_hash' => $contentHash,
                'expires_at' => $expiresAt,
                'content' => $content,
            ];
        } catch (\Throwable $exception) {
            $failureHash = hash('sha256', $exception::class . '|' . $exception->getMessage());
            $failure = $this->database->pdo()->prepare(
                'UPDATE security_audit_exports
                 SET status=\'failed\',failure_hash=:failure_hash,completed_at=:completed_at
                 WHERE public_id=:public_id'
            );
            $failure->execute([
                'failure_hash' => $failureHash,
                'completed_at' => $this->now(),
                'public_id' => $publicId,
            ]);
            throw $exception;
        }
    }

    /** @param list<array<string,mixed>> $events */
    private function csv(array $events): string
    {
        $stream = fopen('php://temp', 'w+b');
        if ($stream === false) {
            throw new RuntimeException('Unable to create the security audit export.');
        }

        fputcsv($stream, [
            'public_id', 'sequence_number', 'request_id', 'correlation_id', 'event_type',
            'category', 'risk_level', 'result', 'actor_type', 'actor_public_id',
            'resource_type', 'resource_public_id', 'occurred_at', 'metadata_json', 'chain_hash',
        ]);
        foreach ($events as $event) {
            fputcsv($stream, [
                $event['public_id'],
                $event['sequence_number'],
                $event['request_id'],
                $event['correlation_id'],
                $event['event_type'],
                $event['category'],
                $event['risk_level'],
                $event['result'],
                $event['actor_type'],
                $event['actor_public_id'],
                $event['resource_type'],
                $event['resource_public_id'],
                $event['occurred_at'],
                $event['metadata'] === null ? null : $this->canonicalJson($event['metadata']),
                $event['chain_hash'],
            ]);
        }

        rewind($stream);
        $content = stream_get_contents($stream);
        fclose($stream);
        if (!is_string($content)) {
            throw new RuntimeException('Unable to read the security audit export.');
        }
        return $content;
    }

    /** @param list<array<string,mixed>> $events */
    private function jsonLines(array $events): string
    {
        $lines = array_map(fn (array $event): string => $this->canonicalJson($event), $events);
        return $lines === [] ? '' : implode("\n", $lines) . "\n";
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
