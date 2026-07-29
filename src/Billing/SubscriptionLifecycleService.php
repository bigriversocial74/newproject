<?php

declare(strict_types=1);

namespace Vp3\Billing;

use DateTimeImmutable;
use InvalidArgumentException;
use PDO;
use RuntimeException;
use Vp3\Database;

final class SubscriptionLifecycleService
{
    /** @var array<string,list<string>> */
    private const ALLOWED_TRANSITIONS = [
        'trialing' => ['active', 'canceled', 'expired'],
        'active' => ['past_due', 'canceled', 'expired'],
        'past_due' => ['active', 'grace', 'canceled', 'expired'],
        'grace' => ['active', 'canceled', 'expired'],
        'canceled' => ['active', 'expired'],
        'expired' => [],
    ];

    public function __construct(private readonly Database $database)
    {
    }

    /** @return array{id:int,public_id:string,account_id:int,plan_id:int,status:string} */
    public function create(
        int $accountId,
        int $planId,
        string $status,
        string $requestId,
        ?DateTimeImmutable $periodStart = null,
        ?DateTimeImmutable $periodEnd = null
    ): array {
        $this->assertIdentity($accountId, $planId, $requestId);
        if (!array_key_exists($status, self::ALLOWED_TRANSITIONS)) {
            throw new InvalidArgumentException('The subscription status is invalid.');
        }

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $planId,
            $status,
            $requestId,
            $periodStart,
            $periodEnd
        ): array {
            $account = $pdo->prepare('SELECT id FROM accounts WHERE id = :id AND status = :status LIMIT 1 FOR UPDATE');
            $account->execute(['id' => $accountId, 'status' => 'active']);
            if (!$account->fetchColumn()) {
                throw new RuntimeException('An active account is required.');
            }

            $plan = $pdo->prepare('SELECT id FROM plans WHERE id = :id AND status = :status LIMIT 1');
            $plan->execute(['id' => $planId, 'status' => 'active']);
            if (!$plan->fetchColumn()) {
                throw new RuntimeException('An active plan is required.');
            }

            $now = new DateTimeImmutable('now');
            $start = $periodStart ?? $now;
            $publicId = 'SUB-' . strtoupper(bin2hex(random_bytes(8)));
            $statement = $pdo->prepare(
                'INSERT INTO subscriptions
                 (public_id, account_id, plan_id, status, starts_at, current_period_starts_at, current_period_ends_at, created_at, updated_at)
                 VALUES
                 (:public_id, :account_id, :plan_id, :status, :starts_at, :period_start, :period_end, :created_at, :updated_at)'
            );
            $statement->execute([
                'public_id' => $publicId,
                'account_id' => $accountId,
                'plan_id' => $planId,
                'status' => $status,
                'starts_at' => $now->format('Y-m-d H:i:s'),
                'period_start' => $start->format('Y-m-d H:i:s'),
                'period_end' => $periodEnd?->format('Y-m-d H:i:s'),
                'created_at' => $now->format('Y-m-d H:i:s'),
                'updated_at' => $now->format('Y-m-d H:i:s'),
            ]);
            $id = (int) $pdo->lastInsertId();
            $this->recordEvent($pdo, $id, $accountId, $requestId, 'subscription_created', null, $status, []);

            return [
                'id' => $id,
                'public_id' => $publicId,
                'account_id' => $accountId,
                'plan_id' => $planId,
                'status' => $status,
            ];
        });
    }

    /** @return array{id:int,public_id:string,account_id:int,plan_id:int,status:string} */
    public function transition(
        int $accountId,
        int $subscriptionId,
        string $toStatus,
        string $requestId,
        ?DateTimeImmutable $graceEndsAt = null
    ): array {
        if ($accountId < 1 || $subscriptionId < 1 || trim($requestId) === '') {
            throw new InvalidArgumentException('The subscription transition identity is invalid.');
        }
        if (!array_key_exists($toStatus, self::ALLOWED_TRANSITIONS)) {
            throw new InvalidArgumentException('The target subscription status is invalid.');
        }

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $subscriptionId,
            $toStatus,
            $requestId,
            $graceEndsAt
        ): array {
            $statement = $pdo->prepare(
                'SELECT id, public_id, account_id, plan_id, status
                 FROM subscriptions
                 WHERE id = :id AND account_id = :account_id
                 LIMIT 1 FOR UPDATE'
            );
            $statement->execute(['id' => $subscriptionId, 'account_id' => $accountId]);
            $subscription = $statement->fetch(PDO::FETCH_ASSOC);
            if (!is_array($subscription)) {
                throw new RuntimeException('The subscription was not found for this account.');
            }

            $fromStatus = (string) $subscription['status'];
            if ($fromStatus === $toStatus) {
                return $this->normalize($subscription);
            }
            if (!in_array($toStatus, self::ALLOWED_TRANSITIONS[$fromStatus] ?? [], true)) {
                throw new RuntimeException('The subscription transition is not allowed.');
            }
            if ($toStatus === 'grace' && $graceEndsAt === null) {
                throw new InvalidArgumentException('A grace end time is required.');
            }

            $now = new DateTimeImmutable('now');
            $update = $pdo->prepare(
                'UPDATE subscriptions
                 SET status = :status,
                     grace_ends_at = :grace_ends_at,
                     canceled_at = :canceled_at,
                     updated_at = :updated_at
                 WHERE id = :id'
            );
            $update->execute([
                'status' => $toStatus,
                'grace_ends_at' => $toStatus === 'grace' ? $graceEndsAt?->format('Y-m-d H:i:s') : null,
                'canceled_at' => $toStatus === 'canceled' ? $now->format('Y-m-d H:i:s') : null,
                'updated_at' => $now->format('Y-m-d H:i:s'),
                'id' => $subscriptionId,
            ]);
            $this->recordEvent(
                $pdo,
                $subscriptionId,
                $accountId,
                trim($requestId),
                'subscription_status_changed',
                $fromStatus,
                $toStatus,
                ['grace_ends_at' => $graceEndsAt?->format(DATE_ATOM)]
            );

            $subscription['status'] = $toStatus;
            return $this->normalize($subscription);
        });
    }

    private function assertIdentity(int $accountId, int $planId, string $requestId): void
    {
        if ($accountId < 1 || $planId < 1 || trim($requestId) === '') {
            throw new InvalidArgumentException('The subscription identity is invalid.');
        }
    }

    /** @param array<string,mixed> $metadata */
    private function recordEvent(
        PDO $pdo,
        int $subscriptionId,
        int $accountId,
        string $requestId,
        string $eventType,
        ?string $fromStatus,
        ?string $toStatus,
        array $metadata
    ): void {
        $statement = $pdo->prepare(
            'INSERT INTO subscription_events
             (subscription_id, account_id, request_id, event_type, from_status, to_status, metadata_json, created_at)
             VALUES
             (:subscription_id, :account_id, :request_id, :event_type, :from_status, :to_status, :metadata_json, :created_at)'
        );
        $statement->execute([
            'subscription_id' => $subscriptionId,
            'account_id' => $accountId,
            'request_id' => $requestId,
            'event_type' => $eventType,
            'from_status' => $fromStatus,
            'to_status' => $toStatus,
            'metadata_json' => json_encode($metadata, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            'created_at' => (new DateTimeImmutable('now'))->format('Y-m-d H:i:s'),
        ]);
    }

    /** @param array<string,mixed> $row @return array{id:int,public_id:string,account_id:int,plan_id:int,status:string} */
    private function normalize(array $row): array
    {
        return [
            'id' => (int) $row['id'],
            'public_id' => (string) $row['public_id'],
            'account_id' => (int) $row['account_id'],
            'plan_id' => (int) $row['plan_id'],
            'status' => (string) $row['status'],
        ];
    }
}
