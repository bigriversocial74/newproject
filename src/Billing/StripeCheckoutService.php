<?php

declare(strict_types=1);

namespace Vp3\Billing;

use DateTimeImmutable;
use InvalidArgumentException;
use PDO;
use RuntimeException;
use Vp3\Database;

final class StripeCheckoutService
{
    public function __construct(
        private readonly Database $database,
        private readonly StripeGateway $gateway
    ) {
    }

    /** @return array{public_id:string,stripe_session_id:string,url:?string,status:string,replayed:bool} */
    public function createCheckoutSession(
        int $accountId,
        int $planId,
        string $successUrl,
        string $cancelUrl,
        string $requestId,
        string $idempotencyKey
    ): array {
        $this->assertRequest($accountId, $requestId, $idempotencyKey);
        $this->assertUrl($successUrl);
        $this->assertUrl($cancelUrl);
        if ($planId < 1) {
            throw new InvalidArgumentException('Plan ID is required.');
        }

        $requestHash = hash('sha256', json_encode([
            'plan_id' => $planId,
            'success_url' => $successUrl,
            'cancel_url' => $cancelUrl,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
        $existing = $this->checkoutByIdempotency($accountId, $idempotencyKey);
        if ($existing !== null) {
            if (!hash_equals((string) $existing['request_hash'], $requestHash)) {
                throw new RuntimeException('The checkout idempotency key was reused with a different payload.');
            }
            return $this->normalizeCheckout($existing, true);
        }

        $context = $this->loadCheckoutContext($accountId, $planId);
        $parameters = [
            'mode' => 'subscription',
            'line_items' => [['price' => $context['stripe_price_id'], 'quantity' => 1]],
            'success_url' => $successUrl,
            'cancel_url' => $cancelUrl,
            'client_reference_id' => (string) $accountId,
            'metadata' => ['vp3_account_id' => (string) $accountId, 'vp3_plan_id' => (string) $planId],
            'subscription_data' => ['metadata' => ['vp3_account_id' => (string) $accountId, 'vp3_plan_id' => (string) $planId]],
        ];
        if ($context['stripe_customer_id'] !== null) {
            $parameters['customer'] = $context['stripe_customer_id'];
        }
        $session = $this->gateway->createCheckoutSession($parameters, $idempotencyKey);
        $sessionId = $this->requiredString($session, 'id', 'Stripe checkout session ID');
        $status = in_array($session['status'] ?? null, ['open', 'complete', 'expired'], true) ? (string) $session['status'] : 'open';
        $publicId = 'CHK-' . strtoupper(bin2hex(random_bytes(10)));
        $now = new DateTimeImmutable('now');

        $this->database->transaction(function (PDO $pdo) use (
            $publicId,
            $accountId,
            $planId,
            $context,
            $idempotencyKey,
            $requestHash,
            $session,
            $sessionId,
            $status,
            $successUrl,
            $cancelUrl,
            $now
        ): void {
            $statement = $pdo->prepare(
                'INSERT INTO stripe_checkout_sessions
                 (public_id, account_id, plan_id, stripe_price_mapping_id, idempotency_key, request_hash,
                  stripe_session_id, stripe_customer_id, stripe_subscription_id, status, session_url,
                  success_url, cancel_url, expires_at, completed_at, created_at, updated_at)
                 VALUES
                 (:public_id, :account_id, :plan_id, :price_id, :idempotency_key, :request_hash,
                  :session_id, :customer_id, :subscription_id, :status, :session_url,
                  :success_url, :cancel_url, :expires_at, :completed_at, :created_at, :updated_at)'
            );
            $statement->execute([
                'public_id' => $publicId,
                'account_id' => $accountId,
                'plan_id' => $planId,
                'price_id' => $context['price_mapping_id'],
                'idempotency_key' => $idempotencyKey,
                'request_hash' => $requestHash,
                'session_id' => $sessionId,
                'customer_id' => is_string($session['customer'] ?? null) ? $session['customer'] : $context['stripe_customer_id'],
                'subscription_id' => is_string($session['subscription'] ?? null) ? $session['subscription'] : null,
                'status' => $status,
                'session_url' => is_string($session['url'] ?? null) ? $session['url'] : null,
                'success_url' => $successUrl,
                'cancel_url' => $cancelUrl,
                'expires_at' => isset($session['expires_at']) ? $this->timestamp((int) $session['expires_at']) : null,
                'completed_at' => $status === 'complete' ? $now->format('Y-m-d H:i:s') : null,
                'created_at' => $now->format('Y-m-d H:i:s'),
                'updated_at' => $now->format('Y-m-d H:i:s'),
            ]);
        });

        return [
            'public_id' => $publicId,
            'stripe_session_id' => $sessionId,
            'url' => is_string($session['url'] ?? null) ? $session['url'] : null,
            'status' => $status,
            'replayed' => false,
        ];
    }

    /** @return array{public_id:string,stripe_session_id:string,url:string,replayed:bool} */
    public function createPortalSession(
        int $accountId,
        string $returnUrl,
        string $requestId,
        string $idempotencyKey
    ): array {
        $this->assertRequest($accountId, $requestId, $idempotencyKey);
        $this->assertUrl($returnUrl);
        $requestHash = hash('sha256', $returnUrl);
        $existing = $this->database->pdo()->prepare(
            'SELECT public_id, stripe_session_id, session_url, request_hash FROM stripe_portal_sessions
             WHERE account_id = :account_id AND idempotency_key = :idempotency_key LIMIT 1'
        );
        $existing->execute(['account_id' => $accountId, 'idempotency_key' => $idempotencyKey]);
        $row = $existing->fetch(PDO::FETCH_ASSOC);
        if (is_array($row)) {
            if (!hash_equals((string) $row['request_hash'], $requestHash)) {
                throw new RuntimeException('The portal idempotency key was reused with a different payload.');
            }
            return [
                'public_id' => (string) $row['public_id'],
                'stripe_session_id' => (string) $row['stripe_session_id'],
                'url' => (string) $row['session_url'],
                'replayed' => true,
            ];
        }

        $customer = $this->database->pdo()->prepare(
            'SELECT stripe_customer_id FROM stripe_customers WHERE account_id = :account_id LIMIT 1'
        );
        $customer->execute(['account_id' => $accountId]);
        $customerId = $customer->fetchColumn();
        if (!is_string($customerId) || $customerId === '') {
            throw new RuntimeException('A Stripe customer is required for the billing portal.');
        }
        $session = $this->gateway->createPortalSession(['customer' => $customerId, 'return_url' => $returnUrl], $idempotencyKey);
        $sessionId = $this->requiredString($session, 'id', 'Stripe portal session ID');
        $url = $this->requiredString($session, 'url', 'Stripe portal session URL');
        $publicId = 'BPS-' . strtoupper(bin2hex(random_bytes(10)));
        $this->database->pdo()->prepare(
            'INSERT INTO stripe_portal_sessions
             (public_id, account_id, idempotency_key, request_hash, stripe_session_id, session_url, return_url, created_at)
             VALUES (:public_id, :account_id, :idempotency_key, :request_hash, :session_id, :session_url, :return_url, :created_at)'
        )->execute([
            'public_id' => $publicId,
            'account_id' => $accountId,
            'idempotency_key' => $idempotencyKey,
            'request_hash' => $requestHash,
            'session_id' => $sessionId,
            'session_url' => $url,
            'return_url' => $returnUrl,
            'created_at' => (new DateTimeImmutable('now'))->format('Y-m-d H:i:s'),
        ]);
        return ['public_id' => $publicId, 'stripe_session_id' => $sessionId, 'url' => $url, 'replayed' => false];
    }

    /** @return array<string,mixed>|null */
    private function checkoutByIdempotency(int $accountId, string $idempotencyKey): ?array
    {
        $statement = $this->database->pdo()->prepare(
            'SELECT public_id, stripe_session_id, session_url, status, request_hash
             FROM stripe_checkout_sessions WHERE account_id = :account_id AND idempotency_key = :idempotency_key LIMIT 1'
        );
        $statement->execute(['account_id' => $accountId, 'idempotency_key' => $idempotencyKey]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $row : null;
    }

    /** @return array{price_mapping_id:int,stripe_price_id:string,stripe_customer_id:?string} */
    private function loadCheckoutContext(int $accountId, int $planId): array
    {
        $statement = $this->database->pdo()->prepare(
            'SELECT a.id AS account_id, p.id AS plan_id, sp.id AS price_mapping_id, sp.stripe_price_id,
                    sc.stripe_customer_id
             FROM accounts a
             JOIN plans p ON p.id = :plan_id AND p.status = :plan_status
             JOIN stripe_price_mappings sp ON sp.plan_id = p.id AND sp.active = 1
             LEFT JOIN stripe_customers sc ON sc.account_id = a.id
             WHERE a.id = :account_id AND a.status = :account_status
             ORDER BY sp.id DESC LIMIT 1'
        );
        $statement->execute([
            'plan_id' => $planId,
            'plan_status' => 'active',
            'account_id' => $accountId,
            'account_status' => 'active',
        ]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('An active account, plan, and Stripe price mapping are required.');
        }
        return [
            'price_mapping_id' => (int) $row['price_mapping_id'],
            'stripe_price_id' => (string) $row['stripe_price_id'],
            'stripe_customer_id' => is_string($row['stripe_customer_id']) ? $row['stripe_customer_id'] : null,
        ];
    }

    /** @param array<string,mixed> $row @return array{public_id:string,stripe_session_id:string,url:?string,status:string,replayed:bool} */
    private function normalizeCheckout(array $row, bool $replayed): array
    {
        return [
            'public_id' => (string) $row['public_id'],
            'stripe_session_id' => (string) $row['stripe_session_id'],
            'url' => is_string($row['session_url'] ?? null) ? $row['session_url'] : null,
            'status' => (string) $row['status'],
            'replayed' => $replayed,
        ];
    }

    private function assertRequest(int $accountId, string $requestId, string $idempotencyKey): void
    {
        if ($accountId < 1 || trim($requestId) === '' || trim($idempotencyKey) === '') {
            throw new InvalidArgumentException('Billing request identity is invalid.');
        }
        if (strlen($idempotencyKey) > 128) {
            throw new InvalidArgumentException('Billing idempotency key is too long.');
        }
    }

    private function assertUrl(string $url): void
    {
        if (filter_var($url, FILTER_VALIDATE_URL) === false || !in_array(parse_url($url, PHP_URL_SCHEME), ['https'], true)) {
            throw new InvalidArgumentException('Billing redirect URL must be HTTPS.');
        }
    }

    /** @param array<string,mixed> $source */
    private function requiredString(array $source, string $key, string $label): string
    {
        $value = $source[$key] ?? null;
        if (!is_string($value) || trim($value) === '') {
            throw new RuntimeException($label . ' is missing.');
        }
        return trim($value);
    }

    private function timestamp(int $timestamp): string
    {
        return (new DateTimeImmutable('@' . $timestamp))->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s');
    }
}
