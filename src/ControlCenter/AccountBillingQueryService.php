<?php

declare(strict_types=1);

namespace Vp3\ControlCenter;

use PDO;
use RuntimeException;
use Vp3\Database;

final class AccountBillingQueryService
{
    public function __construct(private readonly Database $database)
    {
    }

    /** @return array<string,mixed> */
    public function snapshot(int $accountId): array
    {
        if ($accountId < 1) {
            throw new RuntimeException('A valid account is required.');
        }

        $account = $this->account($accountId);
        $plans = $this->plans();
        $subscriptions = $this->subscriptions($accountId);
        $invoices = $this->invoices($accountId);
        $payments = $this->payments($accountId);
        $refunds = $this->refunds($accountId);
        $attention = $this->attention($subscriptions, $invoices, $payments);

        $amountDue = 0;
        $amountPaid = 0;
        foreach ($invoices as $invoice) {
            $amountDue += (int) $invoice['amount_due'];
            $amountPaid += (int) $invoice['amount_paid'];
        }

        return [
            'account' => $account,
            'metrics' => [
                'active_subscriptions' => $this->countStatuses($subscriptions, ['active', 'trialing']),
                'billing_attention' => count($attention),
                'open_invoices' => $this->countStatuses($invoices, ['open', 'draft', 'uncollectible']),
                'failed_payments' => $this->countStatuses($payments, ['requires_payment_method', 'requires_action', 'canceled', 'failed']),
                'amount_due' => $amountDue,
                'amount_paid' => $amountPaid,
                'currency' => $this->dominantCurrency($invoices, $plans),
            ],
            'plans' => $plans,
            'subscriptions' => $subscriptions,
            'invoices' => $invoices,
            'payments' => $payments,
            'refunds' => $refunds,
            'attention' => $attention,
            'portal_available' => $this->portalAvailable($accountId),
        ];
    }

    /** @return array{id:int,public_id:string,display_name:string,status:string} */
    private function account(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            'SELECT id,public_id,display_name,status FROM accounts WHERE id=:account AND status=\'active\' LIMIT 1'
        );
        $statement->execute(['account' => $accountId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('The active account was not found.');
        }
        return [
            'id' => (int) $row['id'],
            'public_id' => (string) $row['public_id'],
            'display_name' => (string) $row['display_name'],
            'status' => (string) $row['status'],
        ];
    }

    /** @return list<array<string,mixed>> */
    private function plans(): array
    {
        $statement = $this->database->pdo()->query(
            "SELECT p.public_id,p.code,p.name,p.billing_interval,p.currency,p.price_minor,
                    sp.billing_interval AS checkout_interval,sp.currency AS checkout_currency,
                    sp.unit_amount AS checkout_amount,
                    (SELECT COUNT(*) FROM plan_entitlements pe WHERE pe.plan_id=p.id) AS entitlement_count
             FROM plans p
             LEFT JOIN stripe_price_mappings sp
               ON sp.id=(SELECT MAX(sp2.id) FROM stripe_price_mappings sp2 WHERE sp2.plan_id=p.id AND sp2.active=1)
             WHERE p.status='active'
             ORDER BY COALESCE(sp.unit_amount,p.price_minor),p.name,p.id"
        );
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        return array_map(static fn (array $row): array => [
            'public_id' => (string) $row['public_id'],
            'code' => (string) $row['code'],
            'name' => (string) $row['name'],
            'billing_interval' => (string) ($row['checkout_interval'] ?: $row['billing_interval']),
            'currency' => strtoupper((string) ($row['checkout_currency'] ?: $row['currency'])),
            'amount' => (int) ($row['checkout_amount'] ?? $row['price_minor']),
            'entitlement_count' => (int) $row['entitlement_count'],
            'available_for_checkout' => $row['checkout_amount'] !== null,
        ], $rows);
    }

    /** @return list<array<string,mixed>> */
    private function subscriptions(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT s.public_id,s.status,s.provider_status,s.starts_at,s.current_period_starts_at,
                    s.current_period_ends_at,s.grace_ends_at,s.canceled_at,s.updated_at,
                    p.public_id AS plan_public_id,p.code AS plan_code,p.name AS plan_name,
                    p.billing_interval,p.currency,p.price_minor,
                    (SELECT COUNT(*) FROM domain_registrations d WHERE d.subscription_id=s.id AND d.status NOT IN ('released','transferred')) AS domain_count,
                    (SELECT COUNT(*) FROM licenses l WHERE l.subscription_id=s.id AND l.status NOT IN ('expired','terminated')) AS license_count
             FROM subscriptions s
             JOIN plans p ON p.id=s.plan_id
             WHERE s.account_id=:account
             ORDER BY FIELD(s.status,'past_due','grace','trialing','active','canceled','expired'),s.updated_at DESC,s.id DESC"
        );
        $statement->execute(['account' => $accountId]);
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        return array_map(static fn (array $row): array => [
            'public_id' => (string) $row['public_id'],
            'status' => (string) $row['status'],
            'provider_status' => $row['provider_status'] === null ? null : (string) $row['provider_status'],
            'plan' => [
                'public_id' => (string) $row['plan_public_id'],
                'code' => (string) $row['plan_code'],
                'name' => (string) $row['plan_name'],
                'billing_interval' => (string) $row['billing_interval'],
                'currency' => strtoupper((string) $row['currency']),
                'amount' => (int) $row['price_minor'],
            ],
            'starts_at' => $row['starts_at'],
            'period_starts_at' => $row['current_period_starts_at'],
            'period_ends_at' => $row['current_period_ends_at'],
            'grace_ends_at' => $row['grace_ends_at'],
            'canceled_at' => $row['canceled_at'],
            'domain_count' => (int) $row['domain_count'],
            'license_count' => (int) $row['license_count'],
            'updated_at' => $row['updated_at'],
        ], $rows);
    }

    /** @return list<array<string,mixed>> */
    private function invoices(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT status,billing_reason,currency,amount_due,amount_paid,amount_remaining,
                    hosted_invoice_url,invoice_pdf_url,period_start,period_end,due_at,paid_at,created_at,updated_at
             FROM billing_invoices
             WHERE account_id=:account
             ORDER BY created_at DESC,id DESC LIMIT 50"
        );
        $statement->execute(['account' => $accountId]);
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        return array_map(fn (array $row): array => [
            'status' => (string) $row['status'],
            'billing_reason' => $row['billing_reason'] === null ? null : (string) $row['billing_reason'],
            'currency' => strtoupper((string) $row['currency']),
            'amount_due' => (int) $row['amount_due'],
            'amount_paid' => (int) $row['amount_paid'],
            'amount_remaining' => (int) $row['amount_remaining'],
            'hosted_url' => $this->trustedStripeUrl($row['hosted_invoice_url']),
            'pdf_url' => $this->trustedStripeUrl($row['invoice_pdf_url']),
            'period_start' => $row['period_start'],
            'period_end' => $row['period_end'],
            'due_at' => $row['due_at'],
            'paid_at' => $row['paid_at'],
            'created_at' => $row['created_at'],
            'updated_at' => $row['updated_at'],
        ], $rows);
    }

    /** @return list<array<string,mixed>> */
    private function payments(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT status,currency,amount,amount_received,payment_method_type,failure_code,failure_message,created_at,updated_at
             FROM billing_payment_intents
             WHERE account_id=:account
             ORDER BY created_at DESC,id DESC LIMIT 30"
        );
        $statement->execute(['account' => $accountId]);
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        return array_map(static fn (array $row): array => [
            'status' => (string) $row['status'],
            'currency' => strtoupper((string) $row['currency']),
            'amount' => (int) $row['amount'],
            'amount_received' => (int) $row['amount_received'],
            'payment_method_type' => $row['payment_method_type'] === null ? null : (string) $row['payment_method_type'],
            'failure_code' => $row['failure_code'] === null ? null : (string) $row['failure_code'],
            'failure_message' => $row['failure_message'] === null ? null : mb_substr((string) $row['failure_message'], 0, 300),
            'created_at' => $row['created_at'],
            'updated_at' => $row['updated_at'],
        ], $rows);
    }

    /** @return list<array<string,mixed>> */
    private function refunds(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT status,currency,amount,reason,failure_reason,created_at,updated_at
             FROM billing_refunds
             WHERE account_id=:account
             ORDER BY created_at DESC,id DESC LIMIT 30"
        );
        $statement->execute(['account' => $accountId]);
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        return array_map(static fn (array $row): array => [
            'status' => (string) $row['status'],
            'currency' => strtoupper((string) $row['currency']),
            'amount' => (int) $row['amount'],
            'reason' => $row['reason'] === null ? null : (string) $row['reason'],
            'failure_reason' => $row['failure_reason'] === null ? null : (string) $row['failure_reason'],
            'created_at' => $row['created_at'],
            'updated_at' => $row['updated_at'],
        ], $rows);
    }

    /** @param list<array<string,mixed>> $subscriptions @param list<array<string,mixed>> $invoices @param list<array<string,mixed>> $payments @return list<array<string,string>> */
    private function attention(array $subscriptions, array $invoices, array $payments): array
    {
        $items = [];
        foreach ($subscriptions as $subscription) {
            if (!in_array($subscription['status'], ['past_due', 'grace'], true)) {
                continue;
            }
            $items[] = [
                'severity' => $subscription['status'] === 'past_due' ? 'critical' : 'warning',
                'title' => $subscription['status'] === 'past_due' ? 'Subscription payment is past due' : 'Subscription is in a billing grace period',
                'detail' => (string) $subscription['plan']['name'] . ($subscription['grace_ends_at'] ? ' · Grace ends ' . $subscription['grace_ends_at'] : ''),
                'action' => 'portal',
            ];
        }
        foreach ($invoices as $invoice) {
            if ((int) $invoice['amount_remaining'] < 1 || in_array($invoice['status'], ['paid', 'void'], true)) {
                continue;
            }
            $items[] = [
                'severity' => in_array($invoice['status'], ['uncollectible', 'open'], true) ? 'critical' : 'warning',
                'title' => 'Invoice requires attention',
                'detail' => strtoupper((string) $invoice['currency']) . ' ' . number_format(((int) $invoice['amount_remaining']) / 100, 2),
                'action' => 'portal',
            ];
        }
        foreach ($payments as $payment) {
            if (!in_array($payment['status'], ['requires_payment_method', 'requires_action', 'canceled', 'failed'], true)) {
                continue;
            }
            $items[] = [
                'severity' => 'critical',
                'title' => 'Payment attempt failed',
                'detail' => $payment['failure_message'] ?: 'Update the payment method in the secure billing portal.',
                'action' => 'portal',
            ];
        }
        return array_slice($items, 0, 20);
    }

    /** @param list<array<string,mixed>> $rows @param list<string> $statuses */
    private function countStatuses(array $rows, array $statuses): int
    {
        $count = 0;
        foreach ($rows as $row) {
            if (in_array($row['status'] ?? null, $statuses, true)) {
                $count++;
            }
        }
        return $count;
    }

    /** @param list<array<string,mixed>> $invoices @param list<array<string,mixed>> $plans */
    private function dominantCurrency(array $invoices, array $plans): string
    {
        if ($invoices !== []) {
            return strtoupper((string) $invoices[0]['currency']);
        }
        if ($plans !== []) {
            return strtoupper((string) $plans[0]['currency']);
        }
        return 'USD';
    }

    private function portalAvailable(int $accountId): bool
    {
        $statement = $this->database->pdo()->prepare('SELECT 1 FROM stripe_customers WHERE account_id=:account LIMIT 1');
        $statement->execute(['account' => $accountId]);
        return (bool) $statement->fetchColumn();
    }

    private function trustedStripeUrl(mixed $value): ?string
    {
        if (!is_string($value) || trim($value) === '') {
            return null;
        }
        $url = trim($value);
        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        $host = strtolower((string) parse_url($url, PHP_URL_HOST));
        if ($scheme !== 'https' || ($host !== 'stripe.com' && !str_ends_with($host, '.stripe.com'))) {
            return null;
        }
        return $url;
    }
}
