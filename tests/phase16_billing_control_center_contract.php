<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$required = [
    'src/ControlCenter/AccountBillingQueryService.php',
    'public/billing.php',
    'public/api/control-center/v1/billing-overview.php',
    'public/api/control-center/v1/billing-action.php',
    'public/assets/billing-control-center.js',
    'public/assets/billing-control-center.css',
];
foreach ($required as $path) {
    if (!is_file($root . '/' . $path)) $failures[] = 'Missing Phase 16 file: ' . $path;
}
$page = (string) @file_get_contents($root . '/public/billing.php');
$shell = (string) @file_get_contents($root . '/src/ControlCenter/ControlCenterPage.php');
$client = (string) @file_get_contents($root . '/public/assets/billing-control-center.js');
$action = (string) @file_get_contents($root . '/public/api/control-center/v1/billing-action.php');
$query = (string) @file_get_contents($root . '/src/ControlCenter/AccountBillingQueryService.php');
foreach (['Billing & Plans', '/billing.php', "'billing' =>"] as $needle) if (!str_contains($shell . $page, $needle)) $failures[] = 'Billing shell contract is missing: ' . $needle;
foreach (['billing-overview.php', 'billing-action.php', 'checkout.stripe.com', 'billing.stripe.com'] as $needle) if (!str_contains($client . $action, $needle)) $failures[] = 'Billing action contract is missing: ' . $needle;
foreach (['accountContext', 'requestId', 'idempotencyKey', 'base_url', 'trustedStripeRedirect'] as $needle) if (!str_contains($action, $needle)) $failures[] = 'Billing endpoint boundary is missing: ' . $needle;
foreach (['localStorage', 'sessionStorage', 'document.cookie', '.innerHTML', 'eval('] as $forbidden) if (str_contains($client, $forbidden)) $failures[] = 'Billing client contains forbidden browser behavior: ' . $forbidden;
foreach (['success_url', 'cancel_url', 'return_url'] as $callerRedirect) if (str_contains($action, "\$payload['" . $callerRedirect . "']")) $failures[] = 'Billing endpoint accepts caller-controlled redirect: ' . $callerRedirect;
foreach (['stripe_session_id', 'stripe_customer_id', 'stripe_subscription_id', 'stripe_invoice_id', 'stripe_payment_intent_id', 'stripe_refund_id'] as $externalId) if (str_contains($action, "'" . $externalId . "' =>")) $failures[] = 'Billing endpoint exposes external Stripe identifier: ' . $externalId;
if (!str_contains($query, 'WHERE account_id=:account') || !str_contains($query, 'WHERE s.account_id=:account')) $failures[] = 'Billing read model is missing account-scoped queries.';
foreach (['checkout_interval', 'checkout_currency', 'checkout_amount'] as $pricingField) if (!str_contains($query, $pricingField)) $failures[] = 'Subscription billing does not use the active Stripe mapping: ' . $pricingField;
if (!str_contains($client, "hasCurrentSubscription ? 'Add Another' : 'Choose Plan'")) $failures[] = 'Existing subscriptions do not retain the Add Another checkout path.';
if (str_contains($client, 'button.disabled = currentPlans.has(item.public_id)')) $failures[] = 'An existing plan still disables repeat subscription checkout.';
if (str_contains($page, '<script>') || str_contains($page, '<style') || str_contains($page, ' style=')) $failures[] = 'Billing page violates the external script/style CSP contract.';
if (!str_contains($shell, "style-src 'self'") || !str_contains($shell, 'billing-control-center.css')) $failures[] = 'Shared shell does not retain the strict Billing CSP/style contract.';
if (!str_contains($client, '{ ...payload, account_id: accountId, csrf_token: csrfToken }')) $failures[] = 'Billing client does not force account and CSRF identity after caller payload fields.';
foreach (['Secure billing checkout could not be created.', 'The secure billing portal could not be opened.', 'The billing provider returned an untrusted redirect.'] as $safeMessage) if (!str_contains($action, $safeMessage)) $failures[] = 'Billing provider error sanitization is missing: ' . $safeMessage;
if ($failures !== []) { fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL); exit(1); }
echo "Phase 16 Billing and Plans control center contract passed.\n";
