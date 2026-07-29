<?php

declare(strict_types=1);

use Vp3\Billing\StripeSignatureVerifier;

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

$failures = [];
$requiredFiles = [
    'src/Billing/StripeGateway.php',
    'src/Billing/StripeApiClient.php',
    'src/Billing/StripeSignatureVerifier.php',
    'src/Billing/StripeCatalogService.php',
    'src/Billing/StripeCheckoutService.php',
    'src/Billing/StripeWebhookService.php',
    'src/Billing/BillingGraceService.php',
    'public/webhooks/stripe.php',
    'database/migrations/20260729_phase4_stripe_billing.sql',
];
foreach ($requiredFiles as $file) {
    if (!is_file($root . '/' . $file)) {
        $failures[] = 'Missing Phase 4 file: ' . $file;
    }
}

$sql = (string) @file_get_contents($root . '/database/migrations/20260729_phase4_stripe_billing.sql');
foreach ([
    'stripe_customers', 'stripe_product_mappings', 'stripe_price_mappings', 'stripe_checkout_sessions',
    'stripe_portal_sessions', 'stripe_webhook_events', 'billing_subscription_items', 'billing_invoices',
    'billing_payment_intents', 'billing_refunds', 'billing_outbox', 'billing_receipts',
] as $table) {
    if (!str_contains($sql, 'CREATE TABLE IF NOT EXISTS ' . $table)) {
        $failures[] = 'Missing Phase 4 table: ' . $table;
    }
}
$checkoutSource = (string) @file_get_contents($root . '/src/Billing/StripeCheckoutService.php');
if (str_contains($checkoutSource, 'billing_outbox')) {
    $failures[] = 'Checkout request code must not enqueue provisioning directly.';
}
$webhookSource = (string) @file_get_contents($root . '/src/Billing/StripeWebhookService.php');
foreach (['invoice.payment_failed', 'invoice.paid', 'customer.subscription.updated', 'refund.created', 'provisioning'] as $needle) {
    if (!str_contains($webhookSource, $needle)) {
        $failures[] = 'Webhook processor is missing contract: ' . $needle;
    }
}

$secret = 'whsec_phase4_contract';
$payload = json_encode(['id' => 'evt_contract', 'type' => 'test.event', 'data' => ['object' => ['id' => 'obj_1']]], JSON_THROW_ON_ERROR);
$timestamp = time();
$signature = hash_hmac('sha256', $timestamp . '.' . $payload, $secret);
$verifier = new StripeSignatureVerifier($secret, 300);
$event = $verifier->verifyAndDecode($payload, 't=' . $timestamp . ',v1=' . $signature, $timestamp);
if (($event['id'] ?? null) !== 'evt_contract') {
    $failures[] = 'Valid Stripe signature did not verify.';
}
$invalidRejected = false;
try {
    $verifier->verifyAndDecode($payload, 't=' . $timestamp . ',v1=' . str_repeat('0', 64), $timestamp);
} catch (Throwable) {
    $invalidRejected = true;
}
if (!$invalidRejected) {
    $failures[] = 'Invalid Stripe signature was accepted.';
}
$staleRejected = false;
try {
    $verifier->verifyAndDecode($payload, 't=' . ($timestamp - 1000) . ',v1=' . hash_hmac('sha256', ($timestamp - 1000) . '.' . $payload, $secret), $timestamp);
} catch (Throwable) {
    $staleRejected = true;
}
if (!$staleRejected) {
    $failures[] = 'Stale Stripe signature was accepted.';
}

if ($failures !== []) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}
echo "Phase 4 Stripe static contract certification passed.\n";
