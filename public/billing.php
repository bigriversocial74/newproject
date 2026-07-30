<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\ControlCenter\AccountPageContext;
use Vp3\ControlCenter\ControlCenterPage;

$container = require dirname(__DIR__) . '/bootstrap.php';
try {
    $context = AccountPageContext::resolve(
        $container,
        ['customer_owner', 'customer_admin', 'billing_manager']
    );
} catch (AuthPublicException $exception) {
    ControlCenterPage::renderAccessFailure('VP3 Billing', $exception);
}
ControlCenterPage::renderStart(
    $context,
    'Billing & Plans',
    'billing',
    'Plans, subscriptions, invoices, payment recovery, and secure Stripe account management.'
);
$escape = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
?>
<section class="hero billing-hero">
  <div><span class="eyebrow">Account billing control</span><h2><?= $escape($context['selected']['display_name']) ?></h2><p>Review plan access, renewal state, invoices, payment outcomes, and refunds without exposing payment credentials or Stripe identifiers.</p></div>
  <div class="hero-actions"><button class="button light" id="refresh-billing" type="button">Refresh Billing</button><button class="button primary" id="open-billing-portal" type="button">Manage Payment Method</button></div>
</section>
<div id="billing-notice" aria-live="polite"></div>
<section id="billing-metrics" class="metrics" aria-label="Billing metrics"><div class="metric"><span>Status</span><strong>Loading…</strong></div></section>
<section class="grid two section-space">
  <article class="panel"><header class="panel-head"><div><h3>Billing Attention</h3><p>Payment, renewal, and grace-period issues requiring action.</p></div><span id="billing-attention-count" class="status">0</span></header><div id="billing-attention" class="attention-list"><div class="empty">Loading billing signals…</div></div></article>
  <article class="panel"><header class="panel-head"><div><h3>Current Subscriptions</h3><p>Plan state, renewal period, and attached Domain and license counts.</p></div></header><div id="billing-subscriptions" class="list"><div class="empty">Loading subscriptions…</div></div></article>
</section>
<section class="panel section-space"><header class="panel-head"><div><h3>Available Plans</h3><p>Start a secure Stripe Checkout session for an eligible VP3 plan.</p></div></header><div id="billing-plans" class="billing-plan-grid"><div class="empty">Loading plans…</div></div></section>
<section class="panel section-space"><header class="panel-head"><div><h3>Invoices</h3><p>Amounts and customer-safe Stripe-hosted invoice links.</p></div></header><div id="billing-invoices" class="billing-table-wrap"><div class="empty">Loading invoices…</div></div></section>
<section class="grid equal section-space">
  <article class="panel"><header class="panel-head"><div><h3>Payment Activity</h3><p>Recent payment status without payment credentials or provider IDs.</p></div></header><div id="billing-payments" class="list"><div class="empty">Loading payments…</div></div></article>
  <article class="panel"><header class="panel-head"><div><h3>Refunds</h3><p>Recent refund outcomes and customer-visible reasons.</p></div></header><div id="billing-refunds" class="list"><div class="empty">Loading refunds…</div></div></article>
</section>
<?php ControlCenterPage::renderEnd(['/assets/billing-control-center.js']); ?>
