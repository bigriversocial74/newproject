<?php

declare(strict_types=1);

use Vp3\Billing\BillingGraceService;
use Vp3\Billing\StripeCatalogService;
use Vp3\Billing\StripeCheckoutService;
use Vp3\Billing\StripeGateway;
use Vp3\Billing\StripeSignatureVerifier;
use Vp3\Billing\StripeWebhookService;
use Vp3\Database;
use Vp3\Licensing\DomainLicenseBundleService;

$root = dirname(__DIR__);
$autoload = $root . '/vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
} else {
    spl_autoload_register(static function (string $class) use ($root): void {
        $prefix = 'Vp3\\';
        if (!str_starts_with($class, $prefix)) {
            return;
        }
        $path = $root . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($path)) {
            require $path;
        }
    });
}

final class Phase4FakeStripeGateway implements StripeGateway
{
    public int $checkoutCalls = 0;
    public int $portalCalls = 0;

    public function createCheckoutSession(array $parameters, string $idempotencyKey): array
    {
        $this->checkoutCalls++;
        return [
            'id' => 'cs_test_' . substr(hash('sha256', $idempotencyKey), 0, 16),
            'status' => 'open',
            'url' => 'https://checkout.stripe.test/' . rawurlencode($idempotencyKey),
            'expires_at' => time() + 1800,
            'customer' => $parameters['customer'] ?? null,
            'subscription' => null,
        ];
    }

    public function createPortalSession(array $parameters, string $idempotencyKey): array
    {
        $this->portalCalls++;
        return [
            'id' => 'bps_test_' . substr(hash('sha256', $idempotencyKey), 0, 16),
            'url' => 'https://billing.stripe.test/' . rawurlencode((string) $parameters['customer']),
        ];
    }
}

$dsn = getenv('VP3_TEST_DSN') ?: '';
if ($dsn === '') {
    fwrite(STDERR, "VP3_TEST_DSN is required.\n");
    exit(1);
}
$database = new Database([
    'dsn' => $dsn,
    'username' => getenv('VP3_TEST_DB_USER') ?: 'root',
    'password' => getenv('VP3_TEST_DB_PASSWORD') ?: '',
    'options' => [
        \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
        \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
        \PDO::ATTR_EMULATE_PREPARES => false,
    ],
]);
$pdo = $database->pdo();
$gateway = new Phase4FakeStripeGateway();
$catalog = new StripeCatalogService($database);
$checkout = new StripeCheckoutService($database, $gateway);
$secret = 'whsec_phase4_database';
$webhooks = new StripeWebhookService($database, new StripeSignatureVerifier($secret, 300), 7);
$grace = new BillingGraceService($database);
$bundles = new DomainLicenseBundleService($database);
$failures = [];

$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};
$send = static function (StripeWebhookService $service, string $secret, string $eventId, string $type, array $object): array {
    $payload = json_encode([
        'id' => $eventId,
        'type' => $type,
        'api_version' => '2024-06-20',
        'livemode' => false,
        'data' => ['object' => $object],
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $timestamp = time();
    $signature = hash_hmac('sha256', $timestamp . '.' . $payload, $secret);
    return $service->handle($payload, 't=' . $timestamp . ',v1=' . $signature, 'REQ-' . strtoupper(substr(hash('sha256', $eventId), 0, 20)));
};

try {
    $now = new \DateTimeImmutable('now');
    $token = strtolower(bin2hex(random_bytes(5)));
    $pdo->prepare(
        'INSERT INTO accounts (public_id, account_type, status, display_name, created_at, updated_at)
         VALUES (:public_id, :type, :status, :display_name, :created_at, :updated_at)'
    )->execute([
        'public_id' => 'VP3-P4-' . strtoupper($token),
        'type' => 'individual',
        'status' => 'active',
        'display_name' => 'Phase Four Account',
        'created_at' => $now->format('Y-m-d H:i:s'),
        'updated_at' => $now->format('Y-m-d H:i:s'),
    ]);
    $accountId = (int) $pdo->lastInsertId();
    $standardPlanId = (int) $pdo->query("SELECT id FROM plans WHERE code='standard' LIMIT 1")->fetchColumn();
    $pdo->prepare('UPDATE plans SET price_minor = :price WHERE id = :id')->execute(['price' => 2500, 'id' => $standardPlanId]);

    $premiumCode = 'premium-' . $token;
    $pdo->prepare(
        'INSERT INTO plans (public_id, code, name, status, billing_interval, currency, price_minor, created_at, updated_at)
         VALUES (:public_id, :code, :name, :status, :interval, :currency, :price, :created_at, :updated_at)'
    )->execute([
        'public_id' => 'PLAN-P4-' . strtoupper($token),
        'code' => $premiumCode,
        'name' => 'Phase Four Premium',
        'status' => 'active',
        'interval' => 'monthly',
        'currency' => 'USD',
        'price' => 5000,
        'created_at' => $now->format('Y-m-d H:i:s'),
        'updated_at' => $now->format('Y-m-d H:i:s'),
    ]);
    $premiumPlanId = (int) $pdo->lastInsertId();
    $pdo->prepare(
        'INSERT INTO plan_entitlements (plan_id, entitlement_key, value_type, value_json, created_at, updated_at)
         SELECT :premium_plan_id, entitlement_key, value_type, value_json, :created_at, :updated_at
         FROM plan_entitlements WHERE plan_id = :standard_plan_id'
    )->execute([
        'premium_plan_id' => $premiumPlanId,
        'created_at' => $now->format('Y-m-d H:i:s'),
        'updated_at' => $now->format('Y-m-d H:i:s'),
        'standard_plan_id' => $standardPlanId,
    ]);

    $catalog->mapProduct($standardPlanId, 'prod_standard_' . $token);
    $catalog->mapPrice($standardPlanId, 'price_standard_' . $token, 'monthly', 'USD', 2500, 'standard-' . $token);
    $catalog->mapProduct($premiumPlanId, 'prod_premium_' . $token);
    $catalog->mapPrice($premiumPlanId, 'price_premium_' . $token, 'monthly', 'USD', 5000, 'premium-' . $token);

    $idempotencyKey = 'checkout-' . $token;
    $checkoutResult = $checkout->createCheckoutSession(
        $accountId,
        $standardPlanId,
        'https://vp3.test/success',
        'https://vp3.test/cancel',
        'REQ-CHECKOUT-' . strtoupper($token),
        $idempotencyKey
    );
    $checkoutReplay = $checkout->createCheckoutSession(
        $accountId,
        $standardPlanId,
        'https://vp3.test/success',
        'https://vp3.test/cancel',
        'REQ-CHECKOUT-REPLAY-' . strtoupper($token),
        $idempotencyKey
    );
    $assert($checkoutReplay['replayed'] === true && $gateway->checkoutCalls === 1, 'Checkout idempotency replay called Stripe twice.');
    $assert((int) $pdo->query("SELECT COUNT(*) FROM billing_outbox WHERE job_type='provisioning'")->fetchColumn() === 0, 'Checkout request provisioned directly before payment confirmation.');
    $mismatchRejected = false;
    try {
        $checkout->createCheckoutSession($accountId, $premiumPlanId, 'https://vp3.test/success', 'https://vp3.test/cancel', 'REQ-MISMATCH', $idempotencyKey);
    } catch (Throwable) {
        $mismatchRejected = true;
    }
    $assert($mismatchRejected, 'Checkout idempotency payload mismatch was accepted.');

    $customerId = 'cus_' . $token;
    $subscriptionExternalId = 'sub_' . $token;
    $checkoutEventId = 'evt_checkout_' . $token;
    $checkoutEvent = $send($webhooks, $secret, $checkoutEventId, 'checkout.session.completed', [
        'id' => $checkoutResult['stripe_session_id'],
        'status' => 'complete',
        'payment_status' => 'paid',
        'customer' => $customerId,
        'subscription' => $subscriptionExternalId,
        'client_reference_id' => (string) $accountId,
        'metadata' => ['vp3_account_id' => (string) $accountId, 'vp3_plan_id' => (string) $standardPlanId],
    ]);
    $assert($checkoutEvent['status'] === 'completed', 'Checkout completion webhook did not complete.');
    $replay = $send($webhooks, $secret, $checkoutEventId, 'checkout.session.completed', [
        'id' => $checkoutResult['stripe_session_id'], 'status' => 'complete', 'payment_status' => 'paid',
        'customer' => $customerId, 'subscription' => $subscriptionExternalId,
        'client_reference_id' => (string) $accountId,
        'metadata' => ['vp3_account_id' => (string) $accountId, 'vp3_plan_id' => (string) $standardPlanId],
    ]);
    $assert($replay['replayed'] === true, 'Duplicate Stripe webhook was not deduplicated.');
    $subscriptionId = (int) $pdo->query("SELECT id FROM subscriptions WHERE provider_subscription_id=" . $pdo->quote($subscriptionExternalId))->fetchColumn();
    $assert($subscriptionId > 0, 'Checkout completion did not create the local subscription.');
    $assert((int) $pdo->query("SELECT COUNT(*) FROM billing_outbox WHERE job_type='provisioning'")->fetchColumn() === 1, 'Payment confirmation did not enqueue exactly one provisioning request.');

    $portal = $checkout->createPortalSession($accountId, 'https://vp3.test/account', 'REQ-PORTAL-' . strtoupper($token), 'portal-' . $token);
    $portalReplay = $checkout->createPortalSession($accountId, 'https://vp3.test/account', 'REQ-PORTAL-R-' . strtoupper($token), 'portal-' . $token);
    $assert($portalReplay['replayed'] === true && $gateway->portalCalls === 1 && $portal['url'] !== '', 'Billing portal idempotency failed.');

    $bundle = $bundles->activateDomainBundle(
        $accountId,
        $subscriptionId,
        'phase4-' . $token,
        'REQ-BUNDLE-' . strtoupper($token),
        'IDEM-BUNDLE-' . strtoupper($token)
    );
    $licenseStatus = $pdo->prepare('SELECT DISTINCT status FROM licenses WHERE domain_registration_id = :domain_id');
    $licenseStatus->execute(['domain_id' => $bundle['domain_id']]);
    $assert($licenseStatus->fetchColumn() === 'active', 'Newly purchased Domain licenses were not active.');

    $invoiceId = 'in_' . $token;
    $send($webhooks, $secret, 'evt_failed_' . $token, 'invoice.payment_failed', [
        'id' => $invoiceId, 'customer' => $customerId, 'subscription' => $subscriptionExternalId,
        'status' => 'open', 'billing_reason' => 'subscription_cycle', 'currency' => 'usd',
        'amount_due' => 2500, 'amount_paid' => 0, 'amount_remaining' => 2500,
        'period_start' => time(), 'period_end' => time() + 2592000,
    ]);
    $state = $pdo->query('SELECT status, provider_status, grace_ends_at FROM subscriptions WHERE id=' . $subscriptionId)->fetch(\PDO::FETCH_ASSOC);
    $assert(is_array($state) && $state['status'] === 'grace' && $state['provider_status'] === 'past_due' && $state['grace_ends_at'] !== null, 'Payment failure did not create a non-destructive grace period.');
    $assert((int) $pdo->query("SELECT COUNT(*) FROM licenses WHERE subscription_id={$subscriptionId} AND status='grace'")->fetchColumn() === 2, 'Payment failure did not propagate grace to both licenses.');

    $send($webhooks, $secret, 'evt_paid_' . $token, 'invoice.paid', [
        'id' => $invoiceId, 'customer' => $customerId, 'subscription' => $subscriptionExternalId,
        'status' => 'paid', 'billing_reason' => 'subscription_cycle', 'currency' => 'usd',
        'amount_due' => 2500, 'amount_paid' => 2500, 'amount_remaining' => 0,
        'period_start' => time(), 'period_end' => time() + 2592000,
        'status_transitions' => ['paid_at' => time()],
    ]);
    $assert($pdo->query('SELECT status FROM subscriptions WHERE id=' . $subscriptionId)->fetchColumn() === 'active', 'Payment recovery did not reactivate the subscription.');
    $assert((int) $pdo->query("SELECT COUNT(*) FROM licenses WHERE subscription_id={$subscriptionId} AND status='active'")->fetchColumn() === 2, 'Payment recovery did not reactivate both licenses.');

    $subscriptionObject = static function (string $priceId, string $status = 'active') use ($subscriptionExternalId, $customerId, $accountId): array {
        return [
            'id' => $subscriptionExternalId,
            'customer' => $customerId,
            'status' => $status,
            'current_period_start' => time(),
            'current_period_end' => time() + 2592000,
            'metadata' => ['vp3_account_id' => (string) $accountId],
            'items' => ['data' => [[
                'id' => 'si_' . substr(hash('sha256', $priceId), 0, 12),
                'quantity' => 1,
                'price' => ['id' => $priceId],
            ]]],
        ];
    };
    $send($webhooks, $secret, 'evt_upgrade_' . $token, 'customer.subscription.updated', $subscriptionObject('price_premium_' . $token));
    $assert((int) $pdo->query('SELECT plan_id FROM subscriptions WHERE id=' . $subscriptionId)->fetchColumn() === $premiumPlanId, 'Plan upgrade did not update the subscription plan.');
    $assert((int) $pdo->query("SELECT COUNT(*) FROM license_entitlements le JOIN licenses l ON l.id=le.license_id WHERE l.subscription_id={$subscriptionId} AND le.source_plan_id={$premiumPlanId}")->fetchColumn() >= 26, 'Plan upgrade did not refresh both license entitlement snapshots.');
    $send($webhooks, $secret, 'evt_downgrade_' . $token, 'customer.subscription.updated', $subscriptionObject('price_standard_' . $token));
    $assert((int) $pdo->query('SELECT plan_id FROM subscriptions WHERE id=' . $subscriptionId)->fetchColumn() === $standardPlanId, 'Plan downgrade did not update the subscription plan.');

    $send($webhooks, $secret, 'evt_cancel_' . $token, 'customer.subscription.deleted', $subscriptionObject('price_standard_' . $token, 'canceled'));
    $assert($pdo->query('SELECT status FROM subscriptions WHERE id=' . $subscriptionId)->fetchColumn() === 'canceled', 'Cancellation did not update the subscription.');
    $assert((int) $pdo->query("SELECT COUNT(*) FROM licenses WHERE subscription_id={$subscriptionId} AND status='suspended'")->fetchColumn() === 2, 'Cancellation did not suspend both licenses non-destructively.');
    $send($webhooks, $secret, 'evt_reactivate_' . $token, 'customer.subscription.updated', $subscriptionObject('price_standard_' . $token, 'active'));
    $assert((int) $pdo->query("SELECT COUNT(*) FROM licenses WHERE subscription_id={$subscriptionId} AND status='active'")->fetchColumn() === 2, 'Reactivation did not restore both licenses.');

    $paymentIntentId = 'pi_' . $token;
    $send($webhooks, $secret, 'evt_pi_' . $token, 'payment_intent.succeeded', [
        'id' => $paymentIntentId, 'customer' => $customerId, 'invoice' => $invoiceId, 'status' => 'succeeded',
        'currency' => 'usd', 'amount' => 2500, 'amount_received' => 2500, 'payment_method_types' => ['card'],
    ]);
    $send($webhooks, $secret, 'evt_refund_' . $token, 'refund.created', [
        'id' => 're_' . $token, 'payment_intent' => $paymentIntentId, 'status' => 'succeeded',
        'currency' => 'usd', 'amount' => 500, 'reason' => 'requested_by_customer',
    ]);
    $assert((int) $pdo->query("SELECT COUNT(*) FROM billing_refunds WHERE stripe_refund_id='re_{$token}'")->fetchColumn() === 1, 'Refund receipt was not persisted.');

    $send($webhooks, $secret, 'evt_failed_expire_' . $token, 'invoice.payment_failed', [
        'id' => 'in_expire_' . $token, 'customer' => $customerId, 'subscription' => $subscriptionExternalId,
        'status' => 'open', 'currency' => 'usd', 'amount_due' => 2500, 'amount_paid' => 0, 'amount_remaining' => 2500,
    ]);
    $pdo->prepare('UPDATE subscriptions SET grace_ends_at = :past WHERE id = :id')->execute([
        'past' => $now->modify('-1 minute')->format('Y-m-d H:i:s'), 'id' => $subscriptionId,
    ]);
    $expired = $grace->expireDueGracePeriods('REQ-GRACE-' . strtoupper($token), $now);
    $assert($expired['expired_subscriptions'] === 1 && $expired['expired_licenses'] === 2, 'Grace expiration did not expire the subscription and paired licenses.');

    $invalidRejected = false;
    try {
        $payload = json_encode(['id' => 'evt_invalid_' . $token, 'type' => 'invoice.paid', 'data' => ['object' => []]], JSON_THROW_ON_ERROR);
        $webhooks->handle($payload, 't=' . time() . ',v1=' . str_repeat('0', 64), 'REQ-INVALID');
    } catch (Throwable) {
        $invalidRejected = true;
    }
    $assert($invalidRejected, 'Invalid webhook signature was accepted.');

    $assert((int) $pdo->query("SELECT COUNT(*) FROM stripe_webhook_events WHERE status='completed'")->fetchColumn() >= 10, 'Stripe webhook audit history is incomplete.');
    $assert((int) $pdo->query('SELECT COUNT(*) FROM billing_receipts WHERE account_id=' . $accountId)->fetchColumn() >= 9, 'Billing audit receipts are incomplete.');
} catch (\Throwable $exception) {
    $failures[] = get_class($exception) . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}
echo "Phase 4 Stripe billing and subscription lifecycle certification passed.\n";
