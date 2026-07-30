<?php

declare(strict_types=1);

use Vp3\ControlCenter\AccountBillingQueryService;
use Vp3\Database;

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
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => true,
    ],
]);
$pdo = $database->pdo();
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};
$accountIds = [];
$subscriptionIds = [];
$planId = 0;

try {
    $token = strtolower(bin2hex(random_bytes(6)));
    $upper = strtoupper($token);
    $now = gmdate('Y-m-d H:i:s');
    $periodEnd = gmdate('Y-m-d H:i:s', time() + 2592000);
    $graceEnd = gmdate('Y-m-d H:i:s', time() + 259200);

    $pdo->prepare(
        "INSERT INTO plans (public_id,code,name,status,billing_interval,currency,price_minor,created_at,updated_at)
         VALUES (:public,:code,'Phase 16 Billing Plan','active','monthly','USD',4900,:now,:now)"
    )->execute(['public' => 'PLAN-P16-' . $upper, 'code' => 'phase16-' . $token, 'now' => $now]);
    $planId = (int) $pdo->lastInsertId();
    $pdo->prepare(
        "INSERT INTO stripe_product_mappings (plan_id,stripe_product_id,active,created_at,updated_at)
         VALUES (:plan,:external,1,:now,:now)"
    )->execute(['plan' => $planId, 'external' => 'prod_p16_' . $token, 'now' => $now]);
    $productId = (int) $pdo->lastInsertId();
    $pdo->prepare(
        "INSERT INTO stripe_price_mappings
         (plan_id,stripe_product_mapping_id,stripe_price_id,lookup_key,billing_interval,currency,unit_amount,active,created_at,updated_at)
         VALUES (:plan,:product,:external,:lookup,'monthly','USD',4900,1,:now,:now)"
    )->execute([
        'plan' => $planId,
        'product' => $productId,
        'external' => 'price_p16_' . $token,
        'lookup' => 'phase16-' . $token,
        'now' => $now,
    ]);

    $createAccount = static function (string $suffix, string $status) use ($pdo, $token, $upper, $now, $periodEnd, $graceEnd, $planId, &$accountIds, &$subscriptionIds): array {
        $pdo->prepare(
            "INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at)
             VALUES (:public,'individual','active',:name,:now,:now)"
        )->execute([
            'public' => 'VP3-P16-' . $upper . '-' . strtoupper($suffix),
            'name' => 'Phase 16 ' . ucfirst($suffix),
            'now' => $now,
        ]);
        $accountId = (int) $pdo->lastInsertId();
        $accountIds[] = $accountId;
        $pdo->prepare(
            "INSERT INTO subscriptions
             (public_id,account_id,plan_id,status,provider,provider_status,provider_customer_id,provider_subscription_id,
              starts_at,current_period_starts_at,current_period_ends_at,grace_ends_at,created_at,updated_at)
             VALUES (:public,:account,:plan,:status,'stripe',:provider_status,:customer,:subscription,:now,:now,:ends,:grace,:now,:now)"
        )->execute([
            'public' => 'SUB-P16-' . $upper . '-' . strtoupper($suffix),
            'account' => $accountId,
            'plan' => $planId,
            'status' => $status,
            'provider_status' => $status === 'past_due' ? 'past_due' : 'active',
            'customer' => 'cus_p16_' . $token . '_' . $suffix,
            'subscription' => 'sub_p16_' . $token . '_' . $suffix,
            'now' => $now,
            'ends' => $periodEnd,
            'grace' => $status === 'grace' ? $graceEnd : null,
        ]);
        $subscriptionId = (int) $pdo->lastInsertId();
        $subscriptionIds[] = $subscriptionId;
        return ['account' => $accountId, 'subscription' => $subscriptionId];
    };

    $owned = $createAccount('owned', 'past_due');
    $other = $createAccount('other', 'active');

    $ownedExternal = [
        'customer' => 'cus_p16_' . $token . '_owned',
        'invoice' => 'in_p16_' . $token . '_owned',
        'payment' => 'pi_p16_' . $token . '_owned',
        'refund' => 're_p16_' . $token . '_owned',
    ];
    $otherExternal = [
        'invoice' => 'in_p16_' . $token . '_other',
        'payment' => 'pi_p16_' . $token . '_other',
    ];

    $pdo->prepare(
        "INSERT INTO stripe_customers (account_id,stripe_customer_id,email,livemode,created_at,updated_at)
         VALUES (:account,:customer,'billing@example.test',0,:now,:now)"
    )->execute(['account' => $owned['account'], 'customer' => $ownedExternal['customer'], 'now' => $now]);

    $insertInvoice = $pdo->prepare(
        "INSERT INTO billing_invoices
         (account_id,subscription_id,stripe_invoice_id,stripe_subscription_id,stripe_customer_id,status,billing_reason,currency,
          amount_due,amount_paid,amount_remaining,hosted_invoice_url,invoice_pdf_url,period_start,period_end,due_at,created_at,updated_at)
         VALUES (:account,:subscription,:invoice,:stripe_subscription,:customer,:status,'subscription_cycle','USD',4900,:paid,:remaining,
                 :hosted,:pdf,:now,:ends,:due,:now,:now)"
    );
    $insertInvoice->execute([
        'account' => $owned['account'], 'subscription' => $owned['subscription'], 'invoice' => $ownedExternal['invoice'],
        'stripe_subscription' => 'sub_p16_' . $token . '_owned', 'customer' => $ownedExternal['customer'], 'status' => 'open',
        'paid' => 0, 'remaining' => 4900, 'hosted' => 'https://invoice.stripe.com/i/' . $token,
        'pdf' => 'https://pay.stripe.com/invoice/' . $token . '/pdf', 'now' => $now, 'ends' => $periodEnd, 'due' => $graceEnd,
    ]);
    $ownedInvoiceId = (int) $pdo->lastInsertId();
    $insertInvoice->execute([
        'account' => $other['account'], 'subscription' => $other['subscription'], 'invoice' => $otherExternal['invoice'],
        'stripe_subscription' => 'sub_p16_' . $token . '_other', 'customer' => 'cus_p16_' . $token . '_other', 'status' => 'paid',
        'paid' => 4900, 'remaining' => 0, 'hosted' => 'https://invoice.stripe.com/i/' . $token . '-other',
        'pdf' => 'https://pay.stripe.com/invoice/' . $token . '-other/pdf', 'now' => $now, 'ends' => $periodEnd, 'due' => $graceEnd,
    ]);

    $insertPayment = $pdo->prepare(
        "INSERT INTO billing_payment_intents
         (account_id,subscription_id,billing_invoice_id,stripe_payment_intent_id,status,currency,amount,amount_received,
          payment_method_type,failure_code,failure_message,created_at,updated_at)
         VALUES (:account,:subscription,:invoice,:external,:status,'USD',4900,:received,'card',:failure_code,:failure_message,:now,:now)"
    );
    $insertPayment->execute([
        'account' => $owned['account'], 'subscription' => $owned['subscription'], 'invoice' => $ownedInvoiceId,
        'external' => $ownedExternal['payment'], 'status' => 'requires_payment_method', 'received' => 0,
        'failure_code' => 'card_declined', 'failure_message' => 'The payment method was declined.', 'now' => $now,
    ]);
    $ownedPaymentId = (int) $pdo->lastInsertId();
    $insertPayment->execute([
        'account' => $other['account'], 'subscription' => $other['subscription'], 'invoice' => null,
        'external' => $otherExternal['payment'], 'status' => 'succeeded', 'received' => 4900,
        'failure_code' => null, 'failure_message' => null, 'now' => $now,
    ]);

    $pdo->prepare(
        "INSERT INTO billing_refunds
         (account_id,subscription_id,billing_payment_intent_id,stripe_refund_id,stripe_payment_intent_id,status,currency,amount,reason,created_at,updated_at)
         VALUES (:account,:subscription,:payment,:refund,:payment_external,'succeeded','USD',1200,'requested_by_customer',:now,:now)"
    )->execute([
        'account' => $owned['account'], 'subscription' => $owned['subscription'], 'payment' => $ownedPaymentId,
        'refund' => $ownedExternal['refund'], 'payment_external' => $ownedExternal['payment'], 'now' => $now,
    ]);

    $query = new AccountBillingQueryService($database);
    $snapshot = $query->snapshot($owned['account']);
    $assert($snapshot['account']['id'] === $owned['account'], 'Billing snapshot returned the wrong account.');
    $assert($snapshot['metrics']['billing_attention'] >= 2, 'Billing attention metrics did not detect past-due payment state.');
    $assert($snapshot['metrics']['open_invoices'] === 1, 'Open invoice metric is incorrect.');
    $assert($snapshot['metrics']['failed_payments'] === 1, 'Failed payment metric is incorrect.');
    $assert($snapshot['portal_available'] === true, 'Stripe portal eligibility was not detected.');
    $assert(count($snapshot['subscriptions']) === 1 && $snapshot['subscriptions'][0]['status'] === 'past_due', 'Subscription status is incorrect.');
    $assert(count($snapshot['invoices']) === 1 && $snapshot['invoices'][0]['amount_remaining'] === 4900, 'Invoice data is incorrect.');
    $assert($snapshot['invoices'][0]['hosted_url'] === 'https://invoice.stripe.com/i/' . $token, 'Trusted hosted invoice URL was not retained.');
    $assert(count($snapshot['payments']) === 1 && $snapshot['payments'][0]['status'] === 'requires_payment_method', 'Payment failure data is incorrect.');
    $assert(count($snapshot['refunds']) === 1 && $snapshot['refunds'][0]['amount'] === 1200, 'Refund data is incorrect.');
    $planMatches = array_values(array_filter($snapshot['plans'], static fn (array $plan): bool => $plan['public_id'] === 'PLAN-P16-' . $upper));
    $assert(count($planMatches) === 1 && $planMatches[0]['available_for_checkout'] === true, 'Checkout-ready plan was not returned.');

    $encoded = json_encode($snapshot, JSON_THROW_ON_ERROR);
    foreach (array_values($ownedExternal) as $externalId) {
        $assert(!str_contains($encoded, $externalId), 'Billing snapshot leaked external Stripe identifier ' . $externalId . '.');
    }
    foreach (['stripe_customer_id','stripe_subscription_id','stripe_invoice_id','stripe_payment_intent_id','stripe_refund_id'] as $forbiddenKey) {
        $assert(!str_contains($encoded, $forbiddenKey), 'Billing snapshot exposed forbidden key ' . $forbiddenKey . '.');
    }

    $otherSnapshot = $query->snapshot($other['account']);
    $otherJson = json_encode($otherSnapshot, JSON_THROW_ON_ERROR);
    $assert(count($otherSnapshot['subscriptions']) === 1 && $otherSnapshot['subscriptions'][0]['status'] === 'active', 'Second account subscription is incorrect.');
    $assert($otherSnapshot['portal_available'] === false, 'Second account incorrectly received portal eligibility.');
    $assert(!str_contains($otherJson, 'The payment method was declined.'), 'Payment failure leaked across accounts.');
    $assert(!str_contains($otherJson, 'https://invoice.stripe.com/i/' . $token . '"'), 'Invoice URL leaked across accounts.');
} catch (Throwable $exception) {
    $failures[] = $exception::class . ': ' . $exception->getMessage();
} finally {
    if ($accountIds !== []) {
        $placeholders = implode(',', array_fill(0, count($accountIds), '?'));
        foreach (['billing_refunds','billing_payment_intents','billing_invoices','stripe_customers'] as $table) {
            $pdo->prepare("DELETE FROM {$table} WHERE account_id IN ({$placeholders})")->execute($accountIds);
        }
    }
    if ($subscriptionIds !== []) {
        $placeholders = implode(',', array_fill(0, count($subscriptionIds), '?'));
        $pdo->prepare("DELETE FROM subscriptions WHERE id IN ({$placeholders})")->execute($subscriptionIds);
    }
    if ($accountIds !== []) {
        $placeholders = implode(',', array_fill(0, count($accountIds), '?'));
        $pdo->prepare("DELETE FROM accounts WHERE id IN ({$placeholders})")->execute($accountIds);
    }
    if ($planId > 0) {
        $pdo->prepare('DELETE FROM stripe_price_mappings WHERE plan_id=?')->execute([$planId]);
        $pdo->prepare('DELETE FROM stripe_product_mappings WHERE plan_id=?')->execute([$planId]);
        $pdo->prepare('DELETE FROM plans WHERE id=?')->execute([$planId]);
    }
}

if ($failures !== []) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}

echo "Phase 16 billing account isolation and privacy integration passed.\n";
