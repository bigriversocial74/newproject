<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\ControlCenter\AccountPageContext;
use Vp3\ControlCenter\ControlCenterPage;

$container = require dirname(__DIR__) . '/bootstrap.php';
try {
    $context = AccountPageContext::resolve($container);
} catch (AuthPublicException $exception) {
    ControlCenterPage::renderAccessFailure('VP3 PODs', $exception);
}
ControlCenterPage::renderStart(
    $context,
    'PODs',
    'pods',
    'Provision, monitor, pause, retry, and safely roll back account-owned POD deployments.'
);
?>
<section class="hero">
  <div><span class="eyebrow">Hosted personal online deployments</span><h2>POD Deployment Operations</h2><p>VP3 manages deployment metadata, health, updates, backups, and provider receipts. Customer application content and configuration secrets remain outside this interface.</p></div>
  <div class="hero-actions"><button class="button light" id="refresh-control-center" type="button">Refresh PODs</button></div>
</section>
<div id="control-center-notice" aria-live="polite"></div>
<section id="pod-metrics" class="metrics" aria-label="POD metrics"><div class="metric"><span>Status</span><strong>Loading…</strong></div></section>
<section class="grid two">
  <article class="panel"><header class="panel-head"><div><h3>Deployments</h3><p>Live deployment state, worker progress, storage, SSL, backup, and release information.</p></div></header><div id="pod-list" class="list"><div class="empty">Loading POD deployments…</div></div></article>
  <aside class="grid">
    <article class="panel"><header class="panel-head"><div><h3>Provision POD</h3><p>Queue a deployment for an active Domain with an unused POD license.</p></div></header>
      <form id="pod-provision-form" class="form">
        <label><span>Eligible Domain</span><select id="pod-domain" required><option value="">Loading eligible Domains…</option></select></label>
        <button class="button primary" type="submit">Queue POD Provisioning</button>
      </form>
    </article>
    <article class="panel"><header class="panel-head"><div><h3>Worker Safety</h3></div></header><p class="help">The web request only queues work. ZIP validation, database creation, configuration preservation, SSL, verification, updates, backups, and rollback run through durable leased workers.</p></article>
  </aside>
</section>
<div id="control-center-modal" class="modal" hidden aria-live="assertive"></div>
<?php ControlCenterPage::renderEnd(['/assets/control-center.js']); ?>
