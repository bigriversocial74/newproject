<?php

declare(strict_types=1);

namespace Vp3\Operations;

use PDO;
use Vp3\Database;

final class OperationalAuditService
{
    public function __construct(private readonly Database $database)
    {
    }

    public function append(
        string $scopeType,
        int $scopeId,
        string $eventType,
        string $actorType,
        int $actorId,
        string $payloadHash
    ): string {
        return $this->database->transaction(fn (PDO $pdo): string => $this->appendWithPdo(
            $pdo, $scopeType, $scopeId, $eventType, $actorType, $actorId, $payloadHash
        ));
    }

    public function appendWithPdo(
        PDO $pdo,
        string $scopeType,
        int $scopeId,
        string $eventType,
        string $actorType,
        int $actorId,
        string $payloadHash
    ): string {
        $head = $pdo->query('SELECT last_chain_hash FROM operational_audit_heads WHERE id=1 FOR UPDATE');
        $previous = $head->fetchColumn();
        $previous = is_string($previous) ? $previous : str_repeat('0', 64);
        $occurredAt = $this->nowMicroseconds();
        $chainHash = $this->hash(
            $previous,
            substr(trim($scopeType), 0, 80),
            max(0, $scopeId),
            substr(trim($eventType), 0, 100),
            substr(trim($actorType), 0, 40),
            max(0, $actorId),
            $payloadHash,
            $occurredAt
        );
        $pdo->prepare(
            'INSERT INTO operational_audit_chain
             (scope_type,scope_id,event_type,actor_type,actor_id,payload_hash,previous_chain_hash,chain_hash,occurred_at)
             VALUES (:scope_type,:scope_id,:event_type,:actor_type,:actor_id,:payload,:previous_chain,:chain,:occurred)'
        )->execute([
            'scope_type' => substr(trim($scopeType), 0, 80),
            'scope_id' => max(0, $scopeId),
            'event_type' => substr(trim($eventType), 0, 100),
            'actor_type' => substr(trim($actorType), 0, 40),
            'actor_id' => max(0, $actorId),
            'payload' => $payloadHash,
            'previous_chain' => $previous,
            'chain' => $chainHash,
            'occurred' => $occurredAt,
        ]);
        $pdo->prepare(
            'UPDATE operational_audit_heads SET last_chain_hash=:chain,updated_at=:updated WHERE id=1'
        )->execute(['chain' => $chainHash, 'updated' => $occurredAt]);
        return $chainHash;
    }

    public function verify(): bool
    {
        $rows = $this->database->pdo()->query(
            'SELECT * FROM operational_audit_chain ORDER BY id ASC'
        )->fetchAll(PDO::FETCH_ASSOC);
        $previous = str_repeat('0', 64);
        foreach ($rows as $row) {
            if ((string) $row['previous_chain_hash'] !== $previous) {
                return false;
            }
            $expected = $this->hash(
                $previous,
                (string) $row['scope_type'],
                (int) $row['scope_id'],
                (string) $row['event_type'],
                (string) $row['actor_type'],
                (int) $row['actor_id'],
                (string) $row['payload_hash'],
                (string) $row['occurred_at']
            );
            if (!hash_equals($expected, (string) $row['chain_hash'])) {
                return false;
            }
            $previous = (string) $row['chain_hash'];
        }
        $head = $this->database->pdo()->query(
            'SELECT last_chain_hash FROM operational_audit_heads WHERE id=1'
        )->fetchColumn();
        return is_string($head) && hash_equals($previous, $head);
    }

    private function hash(
        string $previous,
        string $scopeType,
        int $scopeId,
        string $eventType,
        string $actorType,
        int $actorId,
        string $payloadHash,
        string $occurredAt
    ): string {
        return hash('sha256', implode('|', [
            $previous,
            $scopeType,
            $scopeId,
            $eventType,
            $actorType,
            $actorId,
            $payloadHash,
            $occurredAt,
        ]));
    }

    private function nowMicroseconds(): string
    {
        return (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s.u');
    }
}
