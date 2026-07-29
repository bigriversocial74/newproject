<?php

declare(strict_types=1);

namespace Vp3\Billing;

use DateTimeImmutable;
use DateTimeZone;
use PDO;
use RuntimeException;
use Throwable;
use Vp3\Database;

final class StripeWebhookService
{
    /** @var list<string> */
    private const SUPPORTED_EVENTS = [
        'checkout.session.completed',
        'customer.subscription.created',
        'customer.subscription.updated',
        'customer.subscription.deleted',
        'invoice.paid',
        'invoice.payment_failed',
        'payment_intent.succeeded',
        'payment_intent.payment_failed',
        'refund.created',
        'refund.updated',
    ];

    public function __construct(
        private readonly Database $database,
        private readonly StripeSignatureVerifier $signatureVerifier,
        private readonly int $graceDays = 7
    ) {
    }

    /** @return array{event_id:string,event_type:string,status:string,replayed:bool} */
    public function handle(string $payload, string $signatureHeader, string $requestId): array
    {
        if (trim($requestId) === '') {
            throw new RuntimeException('A request ID is required for Stripe webhook processing.');
        }
        $event = $this->signatureVerifier->verifyAndDecode($payload, $signatureHeader);
        $eventId = (string) $event['id'];
        $eventType = (string) $event['type'];
        $object = $event['data']['object'] ?? null;
        if (!is_array($object)) {
            throw new RuntimeException('Stripe webhook object is missing.');
        }

        $insert = $this->database->pdo()->prepare(
            'INSERT IGNORE INTO stripe_webhook_events
             (stripe_event_id, event_type, api_version, livemode, payload_hash, payload_json, status, attempts, received_at)
             VALUES (:event_id, :event_type, :api_version, :livemode, :payload_hash, :payload_json, :status, 1, :received_at)'
        );
        $insert->execute([
            'event_id' => $eventId,
            'event_type' => $eventType,
            'api_version' => is_string($event['api_version'] ?? null) ? $event['api_version'] : null,
            'livemode' => !empty($event['livemode']) ? 1 : 0,
            'payload_hash' => hash('sha256', $payload),
            'payload_json' => $payload,
            'status' => 'processing',
            'received_at' => $this->now(),
        ]);
        if ($insert->rowCount() === 0) {
            $existing = $this->database->pdo()->prepare(
                'SELECT event_type, status FROM stripe_webhook_events WHERE stripe_event_id = :event_id LIMIT 1'
            );
            $existing->execute(['event_id' => $eventId]);
            $row = $existing->fetch(PDO::FETCH_ASSOC);
            return [
                'event_id' => $eventId,
                'event_type' => is_array($row) ? (string) $row['event_type'] : $eventType,
                'status' => is_array($row) ? (string) $row['status'] : 'processing',
                'replayed' => true,
            ];
        }

        try {
            $status = $this->database->transaction(function (PDO $pdo) use ($eventId, $eventType, $object, $requestId, $event): string {
                if (!in_array($eventType, self::SUPPORTED_EVENTS, true)) {
                    $this->completeEvent($pdo, $eventId, 'ignored');
                    return 'ignored';
                }

                match ($eventType) {
                    'checkout.session.completed' => $this->processCheckout($pdo, $object, $requestId, $eventId, !empty($event['livemode'])),
                    'customer.subscription.created',
                    'customer.subscription.updated',
                    'customer.subscription.deleted' => $this->processSubscription($pdo, $object, $requestId, $eventId, $eventType),
                    'invoice.paid', 'invoice.payment_failed' => $this->processInvoice($pdo, $object, $requestId, $eventId, $eventType),
                    'payment_intent.succeeded', 'payment_intent.payment_failed' => $this->processPaymentIntent($pdo, $object, $requestId, $eventId),
                    'refund.created', 'refund.updated' => $this->processRefund($pdo, $object, $requestId, $eventId),
                    default => null,
                };
                $this->completeEvent($pdo, $eventId, 'completed');
                return 'completed';
            });
        } catch (Throwable $exception) {
            $failure = $this->database->pdo()->prepare(
                'UPDATE stripe_webhook_events
                 SET status = :status, attempts = attempts + 1, error_code = :error_code,
                     error_message = :error_message, processed_at = :processed_at
                 WHERE stripe_event_id = :event_id'
            );
            $failure->execute([
                'status' => 'failed',
                'error_code' => substr(get_class($exception), 0, 100),
                'error_message' => substr($exception->getMessage(), 0, 1000),
                'processed_at' => $this->now(),
                'event_id' => $eventId,
            ]);
            throw $exception;
        }

        return ['event_id' => $eventId, 'event_type' => $eventType, 'status' => $status, 'replayed' => false];
    }

    /** @param array<string,mixed> $object */
    private function processCheckout(PDO $pdo, array $object, string $requestId, string $eventId, bool $livemode): void
    {
        $sessionId = $this->requiredString($object, 'id');
        $accountId = $this->positiveInt($object['metadata']['vp3_account_id'] ?? $object['client_reference_id'] ?? null);
        $planId = $this->positiveInt($object['metadata']['vp3_plan_id'] ?? null);
        $customerId = $this->nullableString($object['customer'] ?? null);
        $subscriptionExternalId = $this->nullableString($object['subscription'] ?? null);
        if ($accountId < 1 || $planId < 1) {
            throw new RuntimeException('Checkout metadata does not identify the VP3 account and plan.');
        }
        $this->assertAccountAndPlan($pdo, $accountId, $planId);
        if ($customerId !== null) {
            $this->upsertCustomer($pdo, $accountId, $customerId, $livemode, $object);
        }

        $status = ($object['status'] ?? null) === 'expired' ? 'expired' : 'complete';
        $update = $pdo->prepare(
            'UPDATE stripe_checkout_sessions
             SET stripe_customer_id = :customer_id, stripe_subscription_id = :subscription_id,
                 status = :status, completed_at = :completed_at, updated_at = :updated_at
             WHERE stripe_session_id = :session_id AND account_id = :account_id'
        );
        $update->execute([
            'customer_id' => $customerId,
            'subscription_id' => $subscriptionExternalId,
            'status' => $status,
            'completed_at' => $status === 'complete' ? $this->now() : null,
            'updated_at' => $this->now(),
            'session_id' => $sessionId,
            'account_id' => $accountId,
        ]);

        $paymentStatus = (string) ($object['payment_status'] ?? 'unpaid');
        if ($subscriptionExternalId !== null && in_array($paymentStatus, ['paid', 'no_payment_required'], true)) {
            $localStatus = $paymentStatus === 'paid' ? 'active' : 'trialing';
            $subscriptionId = $this->upsertSubscription(
                $pdo,
                $accountId,
                $planId,
                $customerId,
                $subscriptionExternalId,
                $localStatus,
                $localStatus,
                null,
                null,
                $requestId,
                'checkout_subscription_confirmed'
            );
            $this->syncLicenses($pdo, $subscriptionId, $localStatus, $requestId);
            $this->enqueue($pdo, 'provisioning', 'provisioning:' . $subscriptionExternalId, $accountId, $subscriptionId, [
                'source' => 'checkout.session.completed',
                'stripe_event_id' => $eventId,
                'stripe_session_id' => $sessionId,
            ]);
            $this->receipt($pdo, $requestId, $accountId, $subscriptionId, 'checkout_completed', $eventId, 'success', [
                'payment_status' => $paymentStatus,
            ]);
        }
    }

    /** @param array<string,mixed> $object */
    private function processSubscription(
        PDO $pdo,
        array $object,
        string $requestId,
        string $eventId,
        string $eventType
    ): void {
        $externalId = $this->requiredString($object, 'id');
        $customerId = $this->requiredString($object, 'customer');
        $accountId = $this->accountForCustomer($pdo, $customerId, $object);
        $priceId = $this->subscriptionPriceId($object);
        $plan = $this->planForPrice($pdo, $priceId);
        $providerStatus = (string) ($object['status'] ?? 'incomplete');
        $internalStatus = $eventType === 'customer.subscription.deleted'
            ? 'canceled'
            : $this->internalSubscriptionStatus($providerStatus);
        $periodStart = $this->dateFromTimestamp($object['current_period_start'] ?? null);
        $periodEnd = $this->dateFromTimestamp($object['current_period_end'] ?? null);

        $before = $pdo->prepare(
            'SELECT id, plan_id, status FROM subscriptions WHERE provider = :provider AND provider_subscription_id = :external_id LIMIT 1 FOR UPDATE'
        );
        $before->execute(['provider' => 'stripe', 'external_id' => $externalId]);
        $old = $before->fetch(PDO::FETCH_ASSOC);
        $subscriptionId = $this->upsertSubscription(
            $pdo,
            $accountId,
            $plan['plan_id'],
            $customerId,
            $externalId,
            $internalStatus,
            $providerStatus,
            $periodStart,
            $periodEnd,
            $requestId,
            'stripe_subscription_synced'
        );
        $item = $object['items']['data'][0] ?? [];
        $this->upsertSubscriptionItem(
            $pdo,
            $subscriptionId,
            $plan['plan_id'],
            is_array($item) ? $this->nullableString($item['id'] ?? null) : null,
            $priceId,
            is_array($item) ? max(1, $this->positiveInt($item['quantity'] ?? 1)) : 1
        );
        if (is_array($old) && (int) $old['plan_id'] !== $plan['plan_id']) {
            $this->syncEntitlementsForSubscription($pdo, $subscriptionId, $plan['plan_id']);
        }
        $this->syncLicenses($pdo, $subscriptionId, $internalStatus, $requestId);

        if ($internalStatus === 'active' || $internalStatus === 'trialing') {
            if (!is_array($old)) {
                $this->enqueue($pdo, 'provisioning', 'provisioning:' . $externalId, $accountId, $subscriptionId, [
                    'source' => $eventType,
                    'stripe_event_id' => $eventId,
                ]);
            } else {
                $this->enqueue($pdo, 'license_sync', 'license-sync:' . $eventId, $accountId, $subscriptionId, [
                    'status' => $internalStatus,
                    'plan_id' => $plan['plan_id'],
                ]);
            }
        }

        $metadata = ['provider_status' => $providerStatus, 'internal_status' => $internalStatus, 'price_id' => $priceId];
        if (is_array($old) && (int) $old['plan_id'] !== $plan['plan_id']) {
            $oldAmount = $this->planAmount($pdo, (int) $old['plan_id']);
            $metadata['plan_change'] = $plan['unit_amount'] >= $oldAmount ? 'upgrade' : 'downgrade';
            $metadata['old_plan_id'] = (int) $old['plan_id'];
            $metadata['new_plan_id'] = $plan['plan_id'];
        }
        $this->receipt($pdo, $requestId, $accountId, $subscriptionId, $eventType, $eventId, 'success', $metadata);
    }

    /** @param array<string,mixed> $object */
    private function processInvoice(PDO $pdo, array $object, string $requestId, string $eventId, string $eventType): void
    {
        $invoiceExternalId = $this->requiredString($object, 'id');
        $customerId = $this->requiredString($object, 'customer');
        $accountId = $this->accountForCustomer($pdo, $customerId, $object);
        $subscriptionExternalId = $this->nullableString($object['subscription'] ?? null);
        $subscriptionId = $this->localSubscriptionId($pdo, $accountId, $subscriptionExternalId);
        $currency = strtoupper((string) ($object['currency'] ?? 'USD'));
        $now = $this->now();
        $statement = $pdo->prepare(
            'INSERT INTO billing_invoices
             (account_id, subscription_id, stripe_invoice_id, stripe_subscription_id, stripe_customer_id,
              status, billing_reason, currency, amount_due, amount_paid, amount_remaining,
              hosted_invoice_url, invoice_pdf_url, period_start, period_end, due_at, paid_at, created_at, updated_at)
             VALUES
             (:account_id, :subscription_id, :invoice_id, :stripe_subscription_id, :customer_id,
              :status, :billing_reason, :currency, :amount_due, :amount_paid, :amount_remaining,
              :hosted_url, :pdf_url, :period_start, :period_end, :due_at, :paid_at, :created_at, :updated_at)
             ON DUPLICATE KEY UPDATE
              subscription_id = VALUES(subscription_id), status = VALUES(status), amount_due = VALUES(amount_due),
              amount_paid = VALUES(amount_paid), amount_remaining = VALUES(amount_remaining),
              hosted_invoice_url = VALUES(hosted_invoice_url), invoice_pdf_url = VALUES(invoice_pdf_url),
              paid_at = VALUES(paid_at), updated_at = VALUES(updated_at)'
        );
        $statement->execute([
            'account_id' => $accountId,
            'subscription_id' => $subscriptionId > 0 ? $subscriptionId : null,
            'invoice_id' => $invoiceExternalId,
            'stripe_subscription_id' => $subscriptionExternalId,
            'customer_id' => $customerId,
            'status' => (string) ($object['status'] ?? ($eventType === 'invoice.paid' ? 'paid' : 'open')),
            'billing_reason' => $this->nullableString($object['billing_reason'] ?? null),
            'currency' => $currency,
            'amount_due' => max(0, (int) ($object['amount_due'] ?? 0)),
            'amount_paid' => max(0, (int) ($object['amount_paid'] ?? 0)),
            'amount_remaining' => max(0, (int) ($object['amount_remaining'] ?? 0)),
            'hosted_url' => $this->nullableString($object['hosted_invoice_url'] ?? null),
            'pdf_url' => $this->nullableString($object['invoice_pdf'] ?? null),
            'period_start' => $this->dateFromTimestamp($object['period_start'] ?? null),
            'period_end' => $this->dateFromTimestamp($object['period_end'] ?? null),
            'due_at' => $this->dateFromTimestamp($object['due_date'] ?? null),
            'paid_at' => $eventType === 'invoice.paid' ? $this->dateFromTimestamp($object['status_transitions']['paid_at'] ?? time()) : null,
            'created_at' => $now,
            'updated_at' => $now,
        ]);

        if ($subscriptionId > 0) {
            if ($eventType === 'invoice.paid') {
                $this->setSubscriptionState($pdo, $subscriptionId, 'active', 'active', null, $requestId, 'invoice_payment_recovered');
                $this->syncLicenses($pdo, $subscriptionId, 'active', $requestId);
                $this->enqueue($pdo, 'license_sync', 'license-sync:' . $eventId, $accountId, $subscriptionId, ['status' => 'active']);
            } else {
                $graceEndsAt = (new DateTimeImmutable('now'))->modify('+' . max(1, $this->graceDays) . ' days')->format('Y-m-d H:i:s');
                $this->setSubscriptionState($pdo, $subscriptionId, 'grace', 'past_due', $graceEndsAt, $requestId, 'invoice_payment_failed');
                $this->syncLicenses($pdo, $subscriptionId, 'grace', $requestId);
                $this->enqueue($pdo, 'license_sync', 'license-sync:' . $eventId, $accountId, $subscriptionId, [
                    'status' => 'grace',
                    'grace_ends_at' => $graceEndsAt,
                ]);
            }
        }
        $this->receipt($pdo, $requestId, $accountId, $subscriptionId > 0 ? $subscriptionId : null, $eventType, $eventId, 'success', [
            'invoice_id' => $invoiceExternalId,
        ]);
    }

    /** @param array<string,mixed> $object */
    private function processPaymentIntent(PDO $pdo, array $object, string $requestId, string $eventId): void
    {
        $externalId = $this->requiredString($object, 'id');
        $customerId = $this->nullableString($object['customer'] ?? null);
        $invoiceExternalId = $this->nullableString($object['invoice'] ?? null);
        $accountId = $customerId !== null ? $this->accountForCustomer($pdo, $customerId, $object) : $this->positiveInt($object['metadata']['vp3_account_id'] ?? null);
        if ($accountId < 1) {
            throw new RuntimeException('Payment intent cannot be linked to a VP3 account.');
        }
        $invoiceId = null;
        $subscriptionId = null;
        if ($invoiceExternalId !== null) {
            $invoice = $pdo->prepare('SELECT id, subscription_id FROM billing_invoices WHERE stripe_invoice_id = :id LIMIT 1');
            $invoice->execute(['id' => $invoiceExternalId]);
            $row = $invoice->fetch(PDO::FETCH_ASSOC);
            if (is_array($row)) {
                $invoiceId = (int) $row['id'];
                $subscriptionId = $row['subscription_id'] === null ? null : (int) $row['subscription_id'];
            }
        }
        $methodType = $object['payment_method_types'][0] ?? null;
        $lastError = is_array($object['last_payment_error'] ?? null) ? $object['last_payment_error'] : [];
        $now = $this->now();
        $pdo->prepare(
            'INSERT INTO billing_payment_intents
             (account_id, subscription_id, billing_invoice_id, stripe_payment_intent_id, status, currency,
              amount, amount_received, payment_method_type, failure_code, failure_message, created_at, updated_at)
             VALUES
             (:account_id, :subscription_id, :invoice_id, :external_id, :status, :currency,
              :amount, :amount_received, :method_type, :failure_code, :failure_message, :created_at, :updated_at)
             ON DUPLICATE KEY UPDATE
              status = VALUES(status), amount = VALUES(amount), amount_received = VALUES(amount_received),
              payment_method_type = VALUES(payment_method_type), failure_code = VALUES(failure_code),
              failure_message = VALUES(failure_message), updated_at = VALUES(updated_at)'
        )->execute([
            'account_id' => $accountId,
            'subscription_id' => $subscriptionId,
            'invoice_id' => $invoiceId,
            'external_id' => $externalId,
            'status' => (string) ($object['status'] ?? 'unknown'),
            'currency' => strtoupper((string) ($object['currency'] ?? 'USD')),
            'amount' => max(0, (int) ($object['amount'] ?? 0)),
            'amount_received' => max(0, (int) ($object['amount_received'] ?? 0)),
            'method_type' => is_string($methodType) ? $methodType : null,
            'failure_code' => $this->nullableString($lastError['code'] ?? null),
            'failure_message' => $this->nullableString($lastError['message'] ?? null),
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        $this->receipt($pdo, $requestId, $accountId, $subscriptionId, 'payment_intent_recorded', $eventId, 'success', [
            'payment_intent_id' => $externalId,
            'status' => $object['status'] ?? 'unknown',
        ]);
    }

    /** @param array<string,mixed> $object */
    private function processRefund(PDO $pdo, array $object, string $requestId, string $eventId): void
    {
        $refundId = $this->requiredString($object, 'id');
        $paymentIntentExternalId = $this->nullableString($object['payment_intent'] ?? null);
        $paymentId = null;
        $accountId = 0;
        $subscriptionId = null;
        if ($paymentIntentExternalId !== null) {
            $payment = $pdo->prepare(
                'SELECT id, account_id, subscription_id FROM billing_payment_intents WHERE stripe_payment_intent_id = :id LIMIT 1'
            );
            $payment->execute(['id' => $paymentIntentExternalId]);
            $row = $payment->fetch(PDO::FETCH_ASSOC);
            if (is_array($row)) {
                $paymentId = (int) $row['id'];
                $accountId = (int) $row['account_id'];
                $subscriptionId = $row['subscription_id'] === null ? null : (int) $row['subscription_id'];
            }
        }
        if ($accountId < 1) {
            $accountId = $this->positiveInt($object['metadata']['vp3_account_id'] ?? null);
        }
        if ($accountId < 1) {
            throw new RuntimeException('Refund cannot be linked to a VP3 account.');
        }
        $now = $this->now();
        $pdo->prepare(
            'INSERT INTO billing_refunds
             (account_id, subscription_id, billing_payment_intent_id, stripe_refund_id, stripe_payment_intent_id,
              status, currency, amount, reason, failure_reason, created_at, updated_at)
             VALUES
             (:account_id, :subscription_id, :payment_id, :refund_id, :payment_intent_id,
              :status, :currency, :amount, :reason, :failure_reason, :created_at, :updated_at)
             ON DUPLICATE KEY UPDATE
              status = VALUES(status), amount = VALUES(amount), reason = VALUES(reason),
              failure_reason = VALUES(failure_reason), updated_at = VALUES(updated_at)'
        )->execute([
            'account_id' => $accountId,
            'subscription_id' => $subscriptionId,
            'payment_id' => $paymentId,
            'refund_id' => $refundId,
            'payment_intent_id' => $paymentIntentExternalId,
            'status' => (string) ($object['status'] ?? 'pending'),
            'currency' => strtoupper((string) ($object['currency'] ?? 'USD')),
            'amount' => max(0, (int) ($object['amount'] ?? 0)),
            'reason' => $this->nullableString($object['reason'] ?? null),
            'failure_reason' => $this->nullableString($object['failure_reason'] ?? null),
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        $this->receipt($pdo, $requestId, $accountId, $subscriptionId, 'refund_recorded', $eventId, 'success', [
            'stripe_refund_id' => $refundId,
            'amount' => max(0, (int) ($object['amount'] ?? 0)),
        ]);
    }

    /** @param array<string,mixed> $object */
    private function upsertCustomer(PDO $pdo, int $accountId, string $customerId, bool $livemode, array $object): void
    {
        $email = $this->nullableString($object['customer_details']['email'] ?? $object['customer_email'] ?? null);
        $now = $this->now();
        $pdo->prepare(
            'INSERT INTO stripe_customers
             (account_id, stripe_customer_id, email, livemode, metadata_json, created_at, updated_at)
             VALUES (:account_id, :customer_id, :email, :livemode, :metadata_json, :created_at, :updated_at)
             ON DUPLICATE KEY UPDATE
              stripe_customer_id = VALUES(stripe_customer_id), email = COALESCE(VALUES(email), email),
              livemode = VALUES(livemode), metadata_json = VALUES(metadata_json), updated_at = VALUES(updated_at)'
        )->execute([
            'account_id' => $accountId,
            'customer_id' => $customerId,
            'email' => $email,
            'livemode' => $livemode ? 1 : 0,
            'metadata_json' => json_encode(['source' => 'stripe_webhook'], JSON_THROW_ON_ERROR),
            'created_at' => $now,
            'updated_at' => $now,
        ]);
    }

    /** @param array<string,mixed> $object */
    private function accountForCustomer(PDO $pdo, string $customerId, array $object): int
    {
        $statement = $pdo->prepare('SELECT account_id FROM stripe_customers WHERE stripe_customer_id = :id LIMIT 1');
        $statement->execute(['id' => $customerId]);
        $accountId = (int) $statement->fetchColumn();
        if ($accountId > 0) {
            return $accountId;
        }
        $accountId = $this->positiveInt($object['metadata']['vp3_account_id'] ?? null);
        if ($accountId < 1) {
            throw new RuntimeException('Stripe customer is not linked to a VP3 account.');
        }
        $this->upsertCustomer($pdo, $accountId, $customerId, false, $object);
        return $accountId;
    }

    private function assertAccountAndPlan(PDO $pdo, int $accountId, int $planId): void
    {
        $statement = $pdo->prepare(
            'SELECT COUNT(*) FROM accounts a JOIN plans p ON p.id = :plan_id AND p.status = :plan_status
             WHERE a.id = :account_id AND a.status = :account_status'
        );
        $statement->execute([
            'plan_id' => $planId,
            'plan_status' => 'active',
            'account_id' => $accountId,
            'account_status' => 'active',
        ]);
        if ((int) $statement->fetchColumn() !== 1) {
            throw new RuntimeException('Stripe billing references an invalid VP3 account or plan.');
        }
    }

    /** @return array{plan_id:int,unit_amount:int} */
    private function planForPrice(PDO $pdo, string $priceId): array
    {
        $statement = $pdo->prepare(
            'SELECT plan_id, unit_amount FROM stripe_price_mappings WHERE stripe_price_id = :price_id AND active = 1 LIMIT 1'
        );
        $statement->execute(['price_id' => $priceId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('Stripe price is not mapped to an active VP3 plan.');
        }
        return ['plan_id' => (int) $row['plan_id'], 'unit_amount' => (int) $row['unit_amount']];
    }

    /** @param array<string,mixed> $object */
    private function subscriptionPriceId(array $object): string
    {
        $priceId = $object['items']['data'][0]['price']['id'] ?? null;
        if (!is_string($priceId) || $priceId === '') {
            throw new RuntimeException('Stripe subscription price is missing.');
        }
        return $priceId;
    }

    private function upsertSubscription(
        PDO $pdo,
        int $accountId,
        int $planId,
        ?string $customerId,
        string $externalId,
        string $status,
        string $providerStatus,
        ?string $periodStart,
        ?string $periodEnd,
        string $requestId,
        string $eventType
    ): int {
        $existing = $pdo->prepare(
            'SELECT id, status FROM subscriptions WHERE provider = :provider AND provider_subscription_id = :external_id LIMIT 1 FOR UPDATE'
        );
        $existing->execute(['provider' => 'stripe', 'external_id' => $externalId]);
        $row = $existing->fetch(PDO::FETCH_ASSOC);
        $now = $this->now();
        if (is_array($row)) {
            $pdo->prepare(
                'UPDATE subscriptions SET account_id = :account_id, plan_id = :plan_id, status = :status,
                 provider_status = :provider_status, provider_customer_id = :customer_id,
                 current_period_starts_at = :period_start, current_period_ends_at = :period_end,
                 grace_ends_at = :grace_ends_at, canceled_at = :canceled_at, updated_at = :updated_at
                 WHERE id = :id'
            )->execute([
                'account_id' => $accountId,
                'plan_id' => $planId,
                'status' => $status,
                'provider_status' => $providerStatus,
                'customer_id' => $customerId,
                'period_start' => $periodStart,
                'period_end' => $periodEnd,
                'grace_ends_at' => $status === 'grace' ? (new DateTimeImmutable('now'))->modify('+' . max(1, $this->graceDays) . ' days')->format('Y-m-d H:i:s') : null,
                'canceled_at' => $status === 'canceled' ? $now : null,
                'updated_at' => $now,
                'id' => $row['id'],
            ]);
            $subscriptionId = (int) $row['id'];
            $fromStatus = (string) $row['status'];
        } else {
            $publicId = 'SUB-' . strtoupper(bin2hex(random_bytes(8)));
            $pdo->prepare(
                'INSERT INTO subscriptions
                 (public_id, account_id, plan_id, status, provider_status, provider, provider_customer_id,
                  provider_subscription_id, starts_at, current_period_starts_at, current_period_ends_at,
                  grace_ends_at, canceled_at, created_at, updated_at)
                 VALUES
                 (:public_id, :account_id, :plan_id, :status, :provider_status, :provider, :customer_id,
                  :external_id, :starts_at, :period_start, :period_end, :grace_ends_at, :canceled_at, :created_at, :updated_at)'
            )->execute([
                'public_id' => $publicId,
                'account_id' => $accountId,
                'plan_id' => $planId,
                'status' => $status,
                'provider_status' => $providerStatus,
                'provider' => 'stripe',
                'customer_id' => $customerId,
                'external_id' => $externalId,
                'starts_at' => $now,
                'period_start' => $periodStart ?? $now,
                'period_end' => $periodEnd,
                'grace_ends_at' => $status === 'grace' ? (new DateTimeImmutable('now'))->modify('+' . max(1, $this->graceDays) . ' days')->format('Y-m-d H:i:s') : null,
                'canceled_at' => $status === 'canceled' ? $now : null,
                'created_at' => $now,
                'updated_at' => $now,
            ]);
            $subscriptionId = (int) $pdo->lastInsertId();
            $fromStatus = null;
        }
        $this->subscriptionEvent($pdo, $subscriptionId, $accountId, $requestId, $eventType, $fromStatus, $status, [
            'provider' => 'stripe',
            'provider_status' => $providerStatus,
            'provider_subscription_id' => $externalId,
        ]);
        return $subscriptionId;
    }

    private function setSubscriptionState(
        PDO $pdo,
        int $subscriptionId,
        string $status,
        string $providerStatus,
        ?string $graceEndsAt,
        string $requestId,
        string $eventType
    ): void {
        $select = $pdo->prepare('SELECT account_id, status FROM subscriptions WHERE id = :id LIMIT 1 FOR UPDATE');
        $select->execute(['id' => $subscriptionId]);
        $row = $select->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            return;
        }
        $pdo->prepare(
            'UPDATE subscriptions SET status = :status, provider_status = :provider_status,
             grace_ends_at = :grace_ends_at, canceled_at = :canceled_at, updated_at = :updated_at WHERE id = :id'
        )->execute([
            'status' => $status,
            'provider_status' => $providerStatus,
            'grace_ends_at' => $graceEndsAt,
            'canceled_at' => $status === 'canceled' ? $this->now() : null,
            'updated_at' => $this->now(),
            'id' => $subscriptionId,
        ]);
        $this->subscriptionEvent($pdo, $subscriptionId, (int) $row['account_id'], $requestId, $eventType, (string) $row['status'], $status, []);
    }

    private function syncEntitlementsForSubscription(PDO $pdo, int $subscriptionId, int $planId): void
    {
        $entitlements = $pdo->prepare(
            'SELECT entitlement_key, value_type, value_json FROM plan_entitlements WHERE plan_id = :plan_id ORDER BY entitlement_key'
        );
        $entitlements->execute(['plan_id' => $planId]);
        $rows = $entitlements->fetchAll(PDO::FETCH_ASSOC);
        if ($rows === []) {
            throw new RuntimeException('The upgraded plan has no entitlements.');
        }
        $snapshot = [];
        foreach ($rows as $row) {
            $snapshot[(string) $row['entitlement_key']] = json_decode((string) $row['value_json'], true, 512, JSON_THROW_ON_ERROR);
        }
        $snapshotHash = hash('sha256', json_encode($snapshot, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
        $licenses = $pdo->prepare(
            'SELECT id, entitlement_bundle_id FROM licenses WHERE subscription_id = :subscription_id FOR UPDATE'
        );
        $licenses->execute(['subscription_id' => $subscriptionId]);
        $licenseRows = $licenses->fetchAll(PDO::FETCH_ASSOC);
        $now = $this->now();
        $bundleIds = [];
        foreach ($licenseRows as $license) {
            $licenseId = (int) $license['id'];
            $bundleIds[(int) $license['entitlement_bundle_id']] = true;
            $pdo->prepare('DELETE FROM license_entitlements WHERE license_id = :license_id')->execute(['license_id' => $licenseId]);
            $insert = $pdo->prepare(
                'INSERT INTO license_entitlements
                 (license_id, entitlement_key, value_type, value_json, source_plan_id, effective_at, expires_at, created_at, updated_at)
                 VALUES (:license_id, :entitlement_key, :value_type, :value_json, :plan_id, :effective_at, NULL, :created_at, :updated_at)'
            );
            foreach ($rows as $row) {
                $insert->execute([
                    'license_id' => $licenseId,
                    'entitlement_key' => $row['entitlement_key'],
                    'value_type' => $row['value_type'],
                    'value_json' => $row['value_json'],
                    'plan_id' => $planId,
                    'effective_at' => $now,
                    'created_at' => $now,
                    'updated_at' => $now,
                ]);
            }
        }
        foreach (array_keys($bundleIds) as $bundleId) {
            $pdo->prepare(
                'UPDATE entitlement_bundles SET plan_id = :plan_id, snapshot_hash = :snapshot_hash, updated_at = :updated_at WHERE id = :id'
            )->execute(['plan_id' => $planId, 'snapshot_hash' => $snapshotHash, 'updated_at' => $now, 'id' => $bundleId]);
        }
    }

    private function syncLicenses(PDO $pdo, int $subscriptionId, string $subscriptionStatus, string $requestId): void
    {
        $licenseStatus = match ($subscriptionStatus) {
            'trialing', 'active' => 'active',
            'past_due', 'grace' => 'grace',
            'expired' => 'expired',
            'canceled' => 'suspended',
            default => 'suspended',
        };
        $now = $this->now();
        $pdo->prepare(
            'UPDATE licenses SET status = :status,
             grace_ends_at = CASE WHEN :status_for_grace = :grace THEN (SELECT grace_ends_at FROM subscriptions WHERE id = :subscription_lookup) ELSE NULL END,
             suspended_at = CASE WHEN :status_for_suspend = :suspended THEN :now_for_suspend ELSE NULL END,
             updated_at = :updated_at WHERE subscription_id = :subscription_id'
        )->execute([
            'status' => $licenseStatus,
            'status_for_grace' => $licenseStatus,
            'grace' => 'grace',
            'subscription_lookup' => $subscriptionId,
            'status_for_suspend' => $licenseStatus,
            'suspended' => 'suspended',
            'now_for_suspend' => $now,
            'updated_at' => $now,
            'subscription_id' => $subscriptionId,
        ]);
        $this->enqueue($pdo, 'license_sync', 'license-state:' . $subscriptionId . ':' . $subscriptionStatus . ':' . hash('sha256', $requestId),  $this->subscriptionAccountId($pdo, $subscriptionId), $subscriptionId, [
            'subscription_status' => $subscriptionStatus,
            'license_status' => $licenseStatus,
        ]);
    }

    private function upsertSubscriptionItem(PDO $pdo, int $subscriptionId, int $planId, ?string $itemId, string $priceId, int $quantity): void
    {
        $now = $this->now();
        $pdo->prepare(
            'INSERT INTO billing_subscription_items
             (subscription_id, plan_id, stripe_subscription_item_id, stripe_price_id, quantity, created_at, updated_at)
             VALUES (:subscription_id, :plan_id, :item_id, :price_id, :quantity, :created_at, :updated_at)
             ON DUPLICATE KEY UPDATE plan_id = VALUES(plan_id), stripe_subscription_item_id = VALUES(stripe_subscription_item_id),
              stripe_price_id = VALUES(stripe_price_id), quantity = VALUES(quantity), updated_at = VALUES(updated_at)'
        )->execute([
            'subscription_id' => $subscriptionId,
            'plan_id' => $planId,
            'item_id' => $itemId,
            'price_id' => $priceId,
            'quantity' => $quantity,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
    }

    /** @param array<string,mixed> $payload */
    private function enqueue(PDO $pdo, string $jobType, string $dedupeKey, int $accountId, ?int $subscriptionId, array $payload): void
    {
        $now = $this->now();
        $pdo->prepare(
            'INSERT IGNORE INTO billing_outbox
             (job_type, dedupe_key, account_id, subscription_id, payload_json, status, attempts, available_at, created_at, updated_at)
             VALUES (:job_type, :dedupe_key, :account_id, :subscription_id, :payload_json, :status, 0, :available_at, :created_at, :updated_at)'
        )->execute([
            'job_type' => $jobType,
            'dedupe_key' => substr($dedupeKey, 0, 190),
            'account_id' => $accountId,
            'subscription_id' => $subscriptionId,
            'payload_json' => json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            'status' => 'pending',
            'available_at' => $now,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
    }

    /** @param array<string,mixed> $metadata */
    private function receipt(
        PDO $pdo,
        string $requestId,
        int $accountId,
        ?int $subscriptionId,
        string $eventType,
        ?string $externalRequestId,
        string $result,
        array $metadata
    ): void {
        $pdo->prepare(
            'INSERT INTO billing_receipts
             (public_id, request_id, account_id, subscription_id, event_type, external_request_id, result, metadata_json, created_at)
             VALUES (:public_id, :request_id, :account_id, :subscription_id, :event_type, :external_request_id, :result, :metadata_json, :created_at)'
        )->execute([
            'public_id' => 'BR-' . strtoupper(bin2hex(random_bytes(10))),
            'request_id' => substr($requestId, 0, 64),
            'account_id' => $accountId,
            'subscription_id' => $subscriptionId,
            'event_type' => $eventType,
            'external_request_id' => $externalRequestId,
            'result' => $result,
            'metadata_json' => json_encode($metadata, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            'created_at' => $this->now(),
        ]);
    }

    /** @param array<string,mixed> $metadata */
    private function subscriptionEvent(
        PDO $pdo,
        int $subscriptionId,
        int $accountId,
        string $requestId,
        string $eventType,
        ?string $fromStatus,
        ?string $toStatus,
        array $metadata
    ): void {
        $pdo->prepare(
            'INSERT INTO subscription_events
             (subscription_id, account_id, request_id, event_type, from_status, to_status, metadata_json, created_at)
             VALUES (:subscription_id, :account_id, :request_id, :event_type, :from_status, :to_status, :metadata_json, :created_at)'
        )->execute([
            'subscription_id' => $subscriptionId,
            'account_id' => $accountId,
            'request_id' => substr($requestId, 0, 64),
            'event_type' => $eventType,
            'from_status' => $fromStatus,
            'to_status' => $toStatus,
            'metadata_json' => json_encode($metadata, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            'created_at' => $this->now(),
        ]);
    }

    private function completeEvent(PDO $pdo, string $eventId, string $status): void
    {
        $pdo->prepare(
            'UPDATE stripe_webhook_events SET status = :status, error_code = NULL, error_message = NULL,
             processed_at = :processed_at WHERE stripe_event_id = :event_id'
        )->execute(['status' => $status, 'processed_at' => $this->now(), 'event_id' => $eventId]);
    }

    private function localSubscriptionId(PDO $pdo, int $accountId, ?string $externalId): int
    {
        if ($externalId === null) {
            return 0;
        }
        $statement = $pdo->prepare(
            'SELECT id FROM subscriptions WHERE account_id = :account_id AND provider = :provider AND provider_subscription_id = :external_id LIMIT 1'
        );
        $statement->execute(['account_id' => $accountId, 'provider' => 'stripe', 'external_id' => $externalId]);
        return (int) $statement->fetchColumn();
    }

    private function subscriptionAccountId(PDO $pdo, int $subscriptionId): int
    {
        $statement = $pdo->prepare('SELECT account_id FROM subscriptions WHERE id = :id LIMIT 1');
        $statement->execute(['id' => $subscriptionId]);
        return (int) $statement->fetchColumn();
    }

    private function planAmount(PDO $pdo, int $planId): int
    {
        $statement = $pdo->prepare('SELECT MAX(unit_amount) FROM stripe_price_mappings WHERE plan_id = :plan_id AND active = 1');
        $statement->execute(['plan_id' => $planId]);
        return (int) $statement->fetchColumn();
    }

    private function internalSubscriptionStatus(string $providerStatus): string
    {
        return match ($providerStatus) {
            'trialing' => 'trialing',
            'active' => 'active',
            'past_due', 'unpaid', 'paused' => 'grace',
            'canceled' => 'canceled',
            'incomplete_expired' => 'expired',
            default => 'past_due',
        };
    }

    /** @param array<string,mixed> $source */
    private function requiredString(array $source, string $key): string
    {
        $value = $source[$key] ?? null;
        if (!is_string($value) || trim($value) === '') {
            throw new RuntimeException('Stripe object is missing required field: ' . $key);
        }
        return trim($value);
    }

    private function nullableString(mixed $value): ?string
    {
        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    private function positiveInt(mixed $value): int
    {
        if (is_int($value)) {
            return max(0, $value);
        }
        return is_string($value) && ctype_digit($value) ? (int) $value : 0;
    }

    private function dateFromTimestamp(mixed $value): ?string
    {
        $timestamp = is_int($value) ? $value : (is_string($value) && ctype_digit($value) ? (int) $value : 0);
        if ($timestamp < 1) {
            return null;
        }
        return (new DateTimeImmutable('@' . $timestamp))->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s');
    }

    private function now(): string
    {
        return (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s');
    }
}
