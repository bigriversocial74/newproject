<?php

declare(strict_types=1);

namespace Vp3\Catalog;

use DateTimeImmutable;
use InvalidArgumentException;
use PDO;
use RuntimeException;
use Vp3\Database;

final class PlanCatalogService
{
    /** @var list<string> */
    public const REQUIRED_ENTITLEMENTS = [
        'storage_bytes',
        'pod_installation_limit',
        'homeserver_limit',
        'mcp_client_limit',
        'update_channel',
        'automatic_updates',
        'managed_security',
        'backup_retention_days',
        'support_tier',
        'custom_domain_alias_limit',
        'pod_user_limit',
        'api_access',
        'security_update_access',
    ];

    public function __construct(private readonly Database $database)
    {
    }

    /**
     * @return array{id:int,public_id:string,code:string,name:string,status:string,billing_interval:string,currency:string,price_minor:int}
     */
    public function createPlan(
        string $code,
        string $name,
        string $billingInterval,
        string $currency,
        int $priceMinor,
        string $status = 'draft'
    ): array {
        $code = strtolower(trim($code));
        $name = trim($name);
        $currency = strtoupper(trim($currency));

        if (!preg_match('/^[a-z0-9][a-z0-9_-]{1,63}$/', $code)) {
            throw new InvalidArgumentException('The plan code is invalid.');
        }
        if ($name === '' || mb_strlen($name) > 190) {
            throw new InvalidArgumentException('The plan name is invalid.');
        }
        if (!in_array($billingInterval, ['monthly', 'annual', 'custom'], true)) {
            throw new InvalidArgumentException('The billing interval is invalid.');
        }
        if (!preg_match('/^[A-Z]{3}$/', $currency)) {
            throw new InvalidArgumentException('The plan currency is invalid.');
        }
        if ($priceMinor < 0) {
            throw new InvalidArgumentException('The plan price cannot be negative.');
        }
        if (!in_array($status, ['draft', 'active', 'retired'], true)) {
            throw new InvalidArgumentException('The plan status is invalid.');
        }

        $now = new DateTimeImmutable('now');
        $publicId = 'PLAN-' . strtoupper(bin2hex(random_bytes(8)));
        $statement = $this->database->pdo()->prepare(
            'INSERT INTO plans
             (public_id, code, name, status, billing_interval, currency, price_minor, created_at, updated_at)
             VALUES
             (:public_id, :code, :name, :status, :billing_interval, :currency, :price_minor, :created_at, :updated_at)'
        );
        $statement->execute([
            'public_id' => $publicId,
            'code' => $code,
            'name' => $name,
            'status' => $status,
            'billing_interval' => $billingInterval,
            'currency' => $currency,
            'price_minor' => $priceMinor,
            'created_at' => $now->format('Y-m-d H:i:s'),
            'updated_at' => $now->format('Y-m-d H:i:s'),
        ]);

        return [
            'id' => (int) $this->database->pdo()->lastInsertId(),
            'public_id' => $publicId,
            'code' => $code,
            'name' => $name,
            'status' => $status,
            'billing_interval' => $billingInterval,
            'currency' => $currency,
            'price_minor' => $priceMinor,
        ];
    }

    public function upsertEntitlement(int $planId, string $key, string $valueType, mixed $value): void
    {
        $key = trim($key);
        if ($planId < 1 || !preg_match('/^[a-z][a-z0-9_]{1,99}$/', $key)) {
            throw new InvalidArgumentException('The entitlement identity is invalid.');
        }
        if (!in_array($valueType, ['boolean', 'integer', 'string', 'json'], true)) {
            throw new InvalidArgumentException('The entitlement value type is invalid.');
        }
        $this->assertValueMatchesType($valueType, $value);

        $encoded = json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $now = (new DateTimeImmutable('now'))->format('Y-m-d H:i:s');
        $statement = $this->database->pdo()->prepare(
            'INSERT INTO plan_entitlements
             (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
             VALUES (:plan_id, :entitlement_key, :value_type, :value_json, :created_at, :updated_at)
             ON DUPLICATE KEY UPDATE
             value_type = VALUES(value_type), value_json = VALUES(value_json), updated_at = VALUES(updated_at)'
        );
        $statement->execute([
            'plan_id' => $planId,
            'entitlement_key' => $key,
            'value_type' => $valueType,
            'value_json' => $encoded,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
    }

    /** @return array<string,mixed> */
    public function entitlementsForPlan(int $planId): array
    {
        $statement = $this->database->pdo()->prepare(
            'SELECT entitlement_key, value_json FROM plan_entitlements WHERE plan_id = :plan_id ORDER BY entitlement_key'
        );
        $statement->execute(['plan_id' => $planId]);

        $entitlements = [];
        foreach ($statement->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $entitlements[(string) $row['entitlement_key']] = json_decode(
                (string) $row['value_json'],
                true,
                32,
                JSON_THROW_ON_ERROR
            );
        }

        return $entitlements;
    }

    public function assertRequiredEntitlements(int $planId): void
    {
        $entitlements = $this->entitlementsForPlan($planId);
        $missing = array_values(array_diff(self::REQUIRED_ENTITLEMENTS, array_keys($entitlements)));
        if ($missing !== []) {
            throw new RuntimeException('The plan is missing required entitlements: ' . implode(', ', $missing));
        }
    }

    /** @return array{id:int,account_id:int,plan_id:int,status:string}|null */
    public function activePlanForSubscription(int $subscriptionId, int $accountId): ?array
    {
        $statement = $this->database->pdo()->prepare(
            'SELECT s.id, s.account_id, s.plan_id, s.status
             FROM subscriptions s
             JOIN plans p ON p.id = s.plan_id
             WHERE s.id = :subscription_id
               AND s.account_id = :account_id
               AND s.status = :subscription_status
               AND p.status = :plan_status
             LIMIT 1'
        );
        $statement->execute([
            'subscription_id' => $subscriptionId,
            'account_id' => $accountId,
            'subscription_status' => 'active',
            'plan_status' => 'active',
        ]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            return null;
        }

        return [
            'id' => (int) $row['id'],
            'account_id' => (int) $row['account_id'],
            'plan_id' => (int) $row['plan_id'],
            'status' => (string) $row['status'],
        ];
    }

    private function assertValueMatchesType(string $valueType, mixed $value): void
    {
        $valid = match ($valueType) {
            'boolean' => is_bool($value),
            'integer' => is_int($value),
            'string' => is_string($value),
            'json' => is_array($value) || is_object($value),
            default => false,
        };

        if (!$valid) {
            throw new InvalidArgumentException('The entitlement value does not match its declared type.');
        }
    }
}
