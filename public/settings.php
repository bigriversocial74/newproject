<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\ControlCenter\AccountPageContext;
use Vp3\ControlCenter\ControlCenterPage;

$container = require dirname(__DIR__) . '/bootstrap.php';
try {
    $context = AccountPageContext::resolveForRoles($container, ['customer_owner', 'customer_admin']);
} catch (AuthPublicException $exception) {
    ControlCenterPage::renderAccessFailure('VP3 Federated Settings', $exception);
}
ControlCenterPage::renderStart(
    $context,
    'Settings & Authority',
    'settings',
    'Revisioned VP3 and HomeServer preferences with explicit authority, device scope, and signed browser snapshots.'
);
$escape = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
?>
<section class="hero settings-hero">
  <div>
    <span class="eyebrow">One catalog · explicit authority</span>
    <h2><?= $escape($context['selected']['display_name']) ?></h2>
    <p>VP3 controls cloud policy, HomeServer controls private local behavior, and shared settings synchronize only through an explicitly selected account-owned HomeServer.</p>
  </div>
  <div class="hero-actions"><button class="button light" id="refresh-settings" type="button">Refresh Settings</button></div>
</section>
<section class="settings-control" data-federated-settings>
  <div id="settings-notice" aria-live="polite"></div>
  <section class="panel settings-device-panel">
    <header class="panel-head">
      <div><h3>HomeServer scope</h3><p>Select a HomeServer to view and edit shared device-scoped preferences. VP3-owned settings remain account-scoped.</p></div>
      <label class="settings-device-picker"><span>Selected HomeServer</span><select id="settings-device"><option value="">Account settings only</option></select></label>
    </header>
    <div class="settings-device-state" id="settings-device-state">Loading account-owned HomeServers…</div>
  </section>
  <section id="settings-summary" class="metrics"><div class="metric"><span>Status</span><strong>Loading…</strong></div></section>
  <section id="settings-groups" class="settings-groups"><div class="empty">Loading federated settings…</div></section>
  <section class="panel settings-boundary">
    <header class="panel-head"><div><h3>Authority boundary</h3><p>Private files, models, credentials, tools, and local execution never enter this settings catalog.</p></div></header>
    <div class="settings-boundary-grid">
      <article><strong>VP3 authority</strong><p>Account, subscription, domain, licensing, release channel, and cloud notification policy.</p></article>
      <article><strong>HomeServer authority</strong><p>Private local schedules, credentials, files, models, tools, and execution behavior.</p></article>
      <article><strong>Shared authority</strong><p>Only explicitly cataloged non-secret preferences synchronize with revisions and conflict receipts.</p></article>
    </div>
  </section>
</section>
<?php ControlCenterPage::renderEnd(['/assets/federated-settings.js']); ?>
