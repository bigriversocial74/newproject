<?php

declare(strict_types=1);

namespace Vp3\Billing;

use DateTimeImmutable;
use InvalidArgumentException;
use PDO;
use RuntimeException;
use Vp3\Database;

final class StripeCatalogService
{
    public function __construct(private readonly Database $database)
    {
    }

    /** @return array{id:int,plan_id:int,stripe_product_id:string,active:bool} */
    public function mapProduct(int $planId, string $stripeProductId, bool $active = true): array
    {
        $this->assertExternalId($stripeProductId, 'prod_');
        if ($planId < 1) {
            throw new InvalidArgumentException('Plan ID is required.');
        }

        return $this->database->transaction(function (PDO $pdo) use ($planId, $stripeProductId, $active): array {
            $plan = $pdo->prepare('SELECT id FROM plans WHERE id = :id LIMIT 1 FOR UPDATE');
            $plan->execute(['id' => $planId]);
            if (!$plan->fetchColumn()) {
                throw new RuntimeException('The plan was not found.');
            }
            $now = (new DateTimeImmutable('now'))->format('Y-m-d H:i:s');
            $statement = $pdo->prepare(
                'INSERT INTO stripe_product_mappings
                 (plan_id, stripe_product_id, active, created_at, updated_at)
                 VALUES (:plan_id, :stripe_product_id, :active, :created_at, :updated_at)
                 ON DUPLICATE KEY UPDATE
                   stripe_product_id = VALUES(stripe_product_id), active = VALUES(active), updated_at = VALUES(updated_at)'
            );
            $statement->execute([
                'plan_id' => $planId,
                'stripe_product_id' => trim($stripeProductId),
                'active' => $active ? 1 : 0,
                'created_at' => $now,
                'updated_at' => $now,
            ]);
            $row = $pdo->prepare('SELECT id, plan_id, stripe_product_id, active FROM stripe_product_mappings WHERE plan_id = :plan_id');
            $row->execute(['plan_id' => $planId]);
            $result = $row->fetch(PDO::FETCH_ASSOC);
            if (!is_array($result)) {
                throw new RuntimeException('Stripe product mapping could not be loaded.');
            }
            return [
                'id' => (int) $result['id'],
                'plan_id' => (int) $result['plan_id'],
                'stripe_product_id' => (string) $result['stripe_product_id'],
                'active' => (bool) $result['active'],
            ];
        });
    }

    /** @return array{id:int,plan_id:int,stripe_price_id:string,unit_amount:int,currency:string,active:bool} */
    public function mapPrice(
        int $planId,
        string $stripePriceId,
        string $billingInterval,
        string $currency,
        int $unitAmount,
        ?string $lookupKey = null,
        bool $active = true
    ): array {
        $this->assertExternalId($stripePriceId, 'price_');
        if (!in_array($billingInterval, ['monthly', 'annual', 'custom'], true)) {
            throw new InvalidArgumentException('Billing interval is invalid.');
        }
        $currency = strtoupper(trim($currency));
        if (preg_match('/^[A-Z]{3}$/', $currency) !== 1 || $unitAmount < 0) {
            throw new InvalidArgumentException('Stripe price currency or amount is invalid.');
        }

        return $this->database->transaction(function (PDO $pdo) use (
            $planId,
            $stripePriceId,
            $billingInterval,
            $currency,
            $unitAmount,
            $lookupKey,
            $active
        ): array {
            $product = $pdo->prepare('SELECT id FROM stripe_product_mappings WHERE plan_id = :plan_id AND active = 1 LIMIT 1 FOR UPDATE');
            $product->execute(['plan_id' => $planId]);
            $productId = (int) $product->fetchColumn();
            if ($productId < 1) {
                throw new RuntimeException('An active Stripe product mapping is required.');
            }
            $now = (new DateTimeImmutable('now'))->format('Y-m-d H:i:s');
            $statement = $pdo->prepare(
                'INSERT INTO stripe_price_mappings
                 (plan_id, stripe_product_mapping_id, stripe_price_id, lookup_key, billing_interval, currency, unit_amount, active, created_at, updated_at)
                 VALUES
                 (:plan_id, :product_id, :stripe_price_id, :lookup_key, :billing_interval, :currency, :unit_amount, :active, :created_at, :updated_at)
                 ON DUPLICATE KEY UPDATE
                   plan_id = VALUES(plan_id), stripe_product_mapping_id = VALUES(stripe_product_mapping_id),
                   lookup_key = VALUES(lookup_key), billing_interval = VALUES(billing_interval),
                   currency = VALUES(currency), unit_amount = VALUES(unit_amount), active = VALUES(active), updated_at = VALUES(updated_at)'
            );
            $statement->execute([
                'plan_id' => $planId,
                'product_id' => $productId,
                'stripe_price_id' => trim($stripePriceId),
                'lookup_key' => $lookupKey === null ? null : trim($lookupKey),
                'billing_interval' => $billingInterval,
                'currency' => $currency,
                'unit_amount' => $unitAmount,
                'active' => $active ? 1 : 0,
                'created_at' => $now,
                'updated_at' => $now,
            ]);
            $row = $pdo->prepare(
                'SELECT id, plan_id, stripe_price_id, unit_amount, currency, active
                 FROM stripe_price_mappings WHERE stripe_price_id = :stripe_price_id LIMIT 1'
            );
            $row->execute(['stripe_price_id' => trim($stripePriceId)]);
            $result = $row->fetch(PDO::FETCH_ASSOC);
            if (!is_array($result)) {
                throw new RuntimeException('Stripe price mapping could not be loaded.');
            }
            return [
                'id' => (int) $result['id'],
                'plan_id' => (int) $result['plan_id'],
                'stripe_price_id' => (string) $result['stripe_price_id'],
                'unit_amount' => (int) $result['unit_amount'],
                'currency' => (string) $result['currency'],
                'active' => (bool) $result['active'],
            ];
        });
    }

    private function assertExternalId(string $value, string $prefix): void
    {
        $value = trim($value);
        if (!str_starts_with($value, $prefix) || preg_match('/^[A-Za-z0-9_]+$/', $value) !== 1) {
            throw new InvalidArgumentException('Stripe external ID is invalid.');
        }
    }
}
