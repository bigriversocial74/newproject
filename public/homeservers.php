<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\ControlCenter\AccountPageContext;
use Vp3\ControlCenter\ControlCenterPage;

$container = require dirname(__DIR__) . '/bootstrap.php';
try {
    $context = AccountPageContext::resolve($container);
} catch (AuthPublicException $exception) {
    ControlCenterPage::renderAccessFailure('VP3 HomeServers', $exception);
}
ControlCenterPage::renderStart(
    $context,
    'HomeServers',
    'homeservers',
    'Register, activate, monitor, replace, transfer, suspend, and revoke VP3 software-authority devices.'
);
$escape = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
?>
<section data-homeserver-fleet data-account-id="<?= (int) $context['selected']['id'] ?>" data-csrf-token="<?= $escape($context['csrf_token']) ?>">
  <section class="hero"><div><span class="eyebrow">VP3 software authority</span><h2>HomeServer Activation & Fleet Operations</h2><p>Register HomeServers to eligible VP3 licenses, complete secure Control Center activation, review signed leases and update evidence, and manage each device lifecycle.</p></div><div class="hero-actions"><button id="refresh-fleet" class="button light" type="button">Refresh Fleet</button></div></section>
  <section id="fleet-metrics" class="metrics" aria-label="Fleet summary"></section>
  <div id="fleet-notice" aria-live="polite"></div>
  <section class="grid two">
    <article class="panel"><header class="panel-head"><div><h3>Registered HomeServers</h3><p>Account-scoped operational status and signed authority evidence.</p></div></header><div id="fleet-devices" class="device-list"><div class="empty">Loading fleet…</div></div></article>
    <aside class="grid">
      <article class="panel"><header class="panel-head"><div><h3>Register HomeServer</h3><p>Create a one-time activation bundle for the Control Center.</p></div></header><form id="register-form" class="form"><label><span>Eligible license</span><select id="register-license" required><option value="">Loading licenses…</option></select></label><label><span>Local device fingerprint</span><input id="register-fingerprint" type="text" minlength="64" maxlength="64" pattern="[A-Fa-f0-9]{64}" autocomplete="off" placeholder="Copy from HomeServer Settings" required></label><p class="help">The fingerprint is a namespaced SHA-256 derivative of the local HomeServer installation identity. It is not a hardware serial number.</p><button class="button primary" type="submit">Create Activation Bundle</button></form></article>
      <article class="panel"><header class="panel-head"><div><h3>Activation Steps</h3></div></header><div class="list"><div class="card soft"><p>1. Open HomeServer Settings and copy the local fingerprint.</p></div><div class="card soft"><p>2. Register an eligible VP3 license.</p></div><div class="card soft"><p>3. Paste the one-time bundle into Control Center.</p></div><div class="card soft"><p>4. Verify heartbeat, lease, and release checks.</p></div></div></article>
      <article class="panel"><header class="panel-head"><div><h3>Privacy Boundary</h3></div></header><p class="help">VP3 stores licensed identity, entitlement state, versions, health timestamps, hashes, and operational receipts. Private files, prompts, conversations, models, tools, MCP content, and local credentials remain on the HomeServer.</p></article>
    </aside>
  </section>
  <div id="fleet-secret-modal" class="modal" hidden aria-live="assertive"></div>
</section>
<?php ControlCenterPage::renderEnd(['/assets/homeserver-fleet.js', '/assets/homeserver-transfer-accept.js']); ?>
