<?php

declare(strict_types=1);

use Vp3\ControlCenter\AccountPageContext;
use Vp3\ControlCenter\ControlCenterPage;

$container = require dirname(__DIR__) . '/bootstrap.php';
try {
    $context = AccountPageContext::resolve($container);
} catch (Throwable) {
    ControlCenterPage::renderSignInRequired('VP3 Domains');
}
ControlCenterPage::renderStart(
    $context,
    'Domains',
    'domains',
    'Register and manage VP3 subdomains, paired licenses, routing, SSL, and deployment readiness.'
);
?>
<section class="hero">
  <div><span class="eyebrow">Account-owned Domain registry</span><h2>Domain & License Control</h2><p>Each active VP3 Domain receives one POD license and one HomeServer license under the same entitlement bundle.</p></div>
  <div class="hero-actions"><button class="button light" id="refresh-control-center" type="button">Refresh Domains</button></div>
</section>
<div id="control-center-notice" aria-live="polite"></div>
<section id="domain-metrics" class="metrics" aria-label="Domain metrics"><div class="metric"><span>Status</span><strong>Loading…</strong></div></section>
<section class="grid two">
  <article class="panel"><header class="panel-head"><div><h3>Registered Domains</h3><p>Lifecycle, routing, SSL, license, POD, and HomeServer state.</p></div></header><div id="domain-list" class="list"><div class="empty">Loading Domains…</div></div></article>
  <aside class="grid">
    <article class="panel"><header class="panel-head"><div><h3>Register Domain</h3><p>Activate an available <strong>.vp3.me</strong> hostname on an eligible subscription.</p></div></header>
      <form id="domain-register-form" class="form">
        <label><span>Subscription</span><select id="domain-subscription" required><option value="">Loading subscriptions…</option></select></label>
        <label><span>Domain label</span><input id="domain-label" type="text" minlength="3" maxlength="63" pattern="[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?" autocomplete="off" placeholder="your-name" required></label>
        <p id="domain-preview" class="help">Enter a label to check availability.</p>
        <button class="button primary" type="submit">Register Domain & Licenses</button>
      </form>
    </article>
    <article class="panel"><header class="panel-head"><div><h3>Lifecycle Boundary</h3></div></header><p class="help">Suspension is non-destructive. Release requires an exact confirmation and is only offered as an explicit advanced action. Domain operations never expose POD files, configuration secrets, or HomeServer private content.</p></article>
  </aside>
</section>
<div id="control-center-modal" class="modal" hidden aria-live="assertive"></div>
<?php ControlCenterPage::renderEnd(['/assets/control-center.js']); ?>
