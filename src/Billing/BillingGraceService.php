<?php

declare(strict_types=1);

namespace Vp3\Billing;

use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;
use PDO;
use Vp3\Database;

final class BillingGraceService
{
    public function __construct(private readonly Database $database)
    {
    }

    /** @return array{expired_subscriptions:int,expired_licenses:int} */
    public function expireDueGracePeriods(string $requestId, ?DateTimeImmutable $at = null): array
    {
        if (trim($requestId) === '') {
            throw new InvalidArgumentException('A request ID is required.');
        }
        $clock = ($at ?? new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s');

        return $this->database->transaction(function (PDO $pdo) use ($requestId, $clock): array {
            $select = $pdo->prepare(
                'SELECT id, account_id FROM subscriptions
                 WHERE status = :status AND grace_ends_at IS NOT NULL AND grace_ends_at <= :clock FOR UPDATE'
            );
            $select->execute(['status' => 'grace', 'clock' => $clock]);
            $rows = $select->fetchAll(PDO::FETCH_ASSOC);
            $expiredLicenses = 0;
            foreach ($rows as $row) {
                $subscriptionId = (int) $row['id'];
                $accountId = (int) $row['account_id'];
                $pdo->prepare(
                    'UPDATE subscriptions SET status = :status, updated_at = :updated_at WHERE id = :id'
                )->execute(['status' => 'expired', 'updated_at' => $clock, 'id' => $subscriptionId]);
                $licenses = $pdo->prepare(
                    'UPDATE licenses SET status = :status, grace_ends_at = NULL, updated_at = :updated_at
                     WHERE subscription_id = :subscription_id'
                );
                $licenses->execute(['status' => 'expired', 'updated_at' => $clock, 'subscription_id' => $subscriptionId]);
                $expiredLicenses += $licenses->rowCount();
                $pdo->prepare(
                    'INSERT INTO subscription_events
                     (subscription_id, account_id, request_id, event_type, from_status, to_status, metadata_json, created_at)
                     VALUES (:subscription_id, :account_id, :request_id, :event_type, :from_status, :to_status, :metadata_json, :created_at)'
                )->execute([
                    'subscription_id' => $subscriptionId,
                    'account_id' => $accountId,
                    'request_id' => substr(trim($requestId), 0, 64),
                    'event_type' => 'billing_grace_expired',
                    'from_status' => 'grace',
                    'to_status' => 'expired',
                    'metadata_json' => json_encode(['expired_at' => $clock], JSON_THROW_ON_ERROR),
                    'created_at' => $clock,
                ]);
                $pdo->prepare(
                    'INSERT IGNORE INTO billing_outbox
                     (job_type, dedupe_key, account_id, subscription_id, payload_json, status, attempts, available_at, created_at, updated_at)
                     VALUES (:job_type, :dedupe_key, :account_id, :subscription_id, :payload_json, :status, 0, :available_at, :created_at, :updated_at)'
                )->execute([
                    'job_type' => 'license_sync',
                    'dedupe_key' => 'grace-expired:' . $subscriptionId . ':' . hash('sha256', $clock),
                    'account_id' => $accountId,
                    'subscription_id' => $subscriptionId,
                    'payload_json' => json_encode(['subscription_status' => 'expired', 'license_status' => 'expired'], JSON_THROW_ON_ERROR),
                    'status' => 'pending',
                    'available_at' => $clock,
                    'created_at' => $clock,
                    'updated_at' => $clock,
                ]);
            }
            return ['expired_subscriptions' => count($rows), 'expired_licenses' => $expiredLicenses];
        });
    }
}
