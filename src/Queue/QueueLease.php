<?php

declare(strict_types=1);

namespace Vp3\Queue;

use PDO;
use RuntimeException;

final class QueueLease
{
    /** @var array<string,true> */
    private const TABLES = [
        'billing_outbox' => true,
        'pod_provisioning_jobs' => true,
        'update_jobs' => true,
        'backup_jobs' => true,
        'restore_jobs' => true,
        'provider_operations' => true,
        'operational_notifications' => true,
    ];

    public function __construct(private readonly int $leaseSeconds = 900)
    {
        if ($leaseSeconds < 30 || $leaseSeconds > 3600) {
            throw new RuntimeException('Queue lease duration must be between 30 and 3600 seconds.');
        }
    }

    public function token(): string
    {
        return bin2hex(random_bytes(32));
    }

    public function seconds(): int
    {
        return $this->leaseSeconds;
    }

    /** @param list<string> $statuses */
    public function renew(PDO $pdo, string $table, int $id, string $token, array $statuses = ['running']): void
    {
        $this->assertTable($table);
        if ($id < 1 || !preg_match('/^[a-f0-9]{64}$/', $token) || $statuses === []) {
            throw new RuntimeException('A valid queue lease identity is required.');
        }
        foreach ($statuses as $status) {
            if (!preg_match('/^[a-z_]+$/', $status)) {
                throw new RuntimeException('Queue lease status is invalid.');
            }
        }
        $marks = implode(',', array_fill(0, count($statuses), '?'));
        $statement = $pdo->prepare(
            "UPDATE {$table} SET locked_until=DATE_ADD(IF(locked_until>UTC_TIMESTAMP(),locked_until,UTC_TIMESTAMP()),INTERVAL {$this->leaseSeconds} SECOND),updated_at=UTC_TIMESTAMP()
             WHERE id=? AND lease_token=? AND status IN ({$marks})"
        );
        $statement->execute(array_merge([$id, $token], $statuses));
        if ($statement->rowCount() !== 1) {
            throw new QueueLeaseLostException('Queue lease was lost before the operation completed.');
        }
    }

    public function assertUpdated(\PDOStatement $statement): void
    {
        if ($statement->rowCount() !== 1) {
            throw new QueueLeaseLostException('Queue lease was lost before the state change completed.');
        }
    }

    /** @param list<string> $statuses */
    public function assertOwned(PDO $pdo, string $table, int $id, string $token, array $statuses = ['running']): void
    {
        $this->assertTable($table);
        $marks = implode(',', array_fill(0, count($statuses), '?'));
        $statement = $pdo->prepare(
            "SELECT id FROM {$table} WHERE id=? AND lease_token=? AND locked_until>=UTC_TIMESTAMP() AND status IN ({$marks}) LIMIT 1"
        );
        $statement->execute(array_merge([$id, $token], $statuses));
        if (!$statement->fetchColumn()) {
            throw new QueueLeaseLostException('Queue lease is no longer owned by this worker.');
        }
    }

    private function assertTable(string $table): void
    {
        if (!isset(self::TABLES[$table])) {
            throw new RuntimeException('Queue lease table is not allowed.');
        }
    }
}
