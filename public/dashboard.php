<?php

declare(strict_types=1);

use Vp3\ControlCenter\AccountPageContext;
use Vp3\ControlCenter\ControlCenterPage;

$container = require dirname(__DIR__) . '/bootstrap.php';
try {
    $context = AccountPageContext::resolve($container);
} catch (Throwable) {
    ControlCenterPage::renderSignInRequired('VP3 Dashboard');
}
ControlCenterPage::renderStart(
    $context,
    'Dashboard',
    'dashboard',
    'Domains, PODs, HomeServers, subscriptions, and operational attention in one account view.'
);
$escape = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
?>
<section class="hero">
  <div><span class="eyebrow">Unified personal online deployment control</span><h2><?= $escape($context['selected']['display_name']) ?></h2><p>Manage the complete VP3 estate without crossing the privacy boundary into POD customer content or HomeServer private data.</p></div>
  <div class="hero-actions"><button class="button light" id="refresh-control-center" type="button">Refresh Dashboard</button><a class="button primary" href="/domains.php?account_id=<?= (int) $context['selected']['id'] ?>">Manage Domains</a></div>
</section>
<div id="control-center-notice" aria-live="polite"></div>
<section id="dashboard-metrics" class="metrics" aria-label="Account metrics"><div class="metric"><span>Status</span><strong>Loading…</strong></div></section>
<section class="grid two">
  <article class="panel"><header class="panel-head"><div><h3>Needs Attention</h3><p>Prioritized billing, Domain, POD, HomeServer, and incident signals.</p></div><span id="attention-count" class="status">0</span></header><div id="dashboard-attention" class="attention-list"><div class="empty">Loading attention items…</div></div></article>
  <article class="panel"><header class="panel-head"><div><h3>Estate Summary</h3><p>Deployment and authority state across the selected account.</p></div></header><div id="dashboard-estate" class="list"><div class="empty">Loading estate summary…</div></div></article>
</section>
<section class="grid equal section-space">
  <article class="panel" id="subscriptions"><header class="panel-head"><div><h3>Subscriptions</h3><p>Plans, renewal windows, and entitlement status.</p></div></header><div id="dashboard-subscriptions" class="list"><div class="empty">Loading subscriptions…</div></div></article>
  <article class="panel" id="incidents"><header class="panel-head"><div><h3>Operational Incidents</h3><p>Account-scoped operational metadata only.</p></div></header><div id="dashboard-incidents" class="list"><div class="empty">Loading incidents…</div></div></article>
</section>
<?php ControlCenterPage::renderEnd(['/assets/control-center.js']); ?>
