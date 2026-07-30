<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\ControlCenter\AccountPageContext;
use Vp3\ControlCenter\ControlCenterPage;

$container = require dirname(__DIR__) . '/bootstrap.php';
try {
    $context = AccountPageContext::resolveForRoles($container, ['customer_owner', 'customer_admin']);
} catch (AuthPublicException $exception) {
    ControlCenterPage::renderAccessFailure('VP3 Infrastructure', $exception);
}

ControlCenterPage::renderStart(
    $context,
    'Infrastructure',
    'infrastructure',
    'Encrypted provider connections, POD hosting, DNS, SSL, reconciliation, and protected teardown.'
);
$escape = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
?>
<section class="hero infrastructure-hero">
  <div>
    <span class="eyebrow">Provider-backed POD delivery</span>
    <h2><?= $escape($context['selected']['display_name']) ?></h2>
    <p>Connect hosting, DNS, and certificate providers without exposing credentials, then provision and reconcile account-owned POD infrastructure.</p>
  </div>
  <div class="hero-actions"><button class="button light" id="infrastructure-refresh" type="button">Refresh Infrastructure</button></div>
</section>

<div id="infrastructure-notice" aria-live="polite"></div>
<section id="infrastructure-metrics" class="metrics infrastructure-metrics" aria-label="Infrastructure metrics">
  <div class="metric"><span>Status</span><strong>Loading…</strong></div>
</section>

<section class="grid infrastructure-top-grid">
  <article class="panel">
    <header class="panel-head">
      <div><h3>Provider Connections</h3><p>Customer-safe inventory. Credentials are encrypted and never returned after submission.</p></div>
    </header>
    <div id="infrastructure-connections" class="list"><div class="empty">Loading provider connections…</div></div>
  </article>

  <article class="panel">
    <header class="panel-head">
      <div><h3>Add or Rotate Connection</h3><p>Saving the same provider type and code rotates its encrypted credential envelope.</p></div>
    </header>
    <form id="infrastructure-connection-form" class="form">
      <label><span>Provider type</span><select id="infrastructure-provider-type" required>
        <option value="hosting">Hosting</option>
        <option value="dns">DNS</option>
        <option value="certificate">Certificate / SSL</option>
      </select></label>
      <label><span>Provider code</span><input id="infrastructure-provider-code" type="text" minlength="3" maxlength="80" pattern="[a-z0-9][a-z0-9._-]{1,78}[a-z0-9]" placeholder="production-provider" autocomplete="off" required></label>
      <label><span>Display name</span><input id="infrastructure-provider-name" type="text" maxlength="190" placeholder="Production DNS" autocomplete="off" required></label>
      <label><span>Authentication JSON</span><textarea id="infrastructure-provider-auth" rows="6" maxlength="16384" spellcheck="false" autocomplete="off" placeholder='{"token":"provider-secret"}' required></textarea></label>
      <p class="help">The authentication object is sent only to VP3 over the current authenticated session and sealed with AES-256-GCM before database storage.</p>
      <button class="button primary" type="submit">Encrypt & Save Connection</button>
    </form>
  </article>
</section>

<section class="grid infrastructure-top-grid">
  <article class="panel">
    <header class="panel-head">
      <div><h3>Provision POD Infrastructure</h3><p>Bind one eligible POD to one active hosting, DNS, and certificate connection.</p></div>
    </header>
    <form id="infrastructure-provision-form" class="form">
      <label><span>POD</span><select id="infrastructure-pod" required><option value="">Loading PODs…</option></select></label>
      <label><span>Hosting connection</span><select id="infrastructure-hosting" required><option value="">Loading hosting connections…</option></select></label>
      <label><span>DNS connection</span><select id="infrastructure-dns" required><option value="">Loading DNS connections…</option></select></label>
      <label><span>Certificate connection</span><select id="infrastructure-certificate" required><option value="">Loading certificate connections…</option></select></label>
      <button class="button primary" type="submit">Queue Provisioning</button>
    </form>
  </article>

  <article class="panel">
    <header class="panel-head">
      <div><h3>Attention</h3><p>Failed, degraded, or paused infrastructure requiring an owner or administrator decision.</p></div>
    </header>
    <div id="infrastructure-attention" class="list"><div class="empty">Loading attention items…</div></div>
  </article>
</section>

<section class="panel">
  <header class="panel-head">
    <div><h3>POD Infrastructure Bindings</h3><p>Hosting, DNS, certificate, routing, and SSL status without provider secrets or private POD content.</p></div>
  </header>
  <div id="infrastructure-bindings" class="list infrastructure-binding-list"><div class="empty">Loading bindings…</div></div>
</section>

<section class="panel">
  <header class="panel-head">
    <div><h3>Infrastructure Operations</h3><p>Provision, reconcile, and teardown stages with pause and resume controls.</p></div>
  </header>
  <div id="infrastructure-operations" class="list infrastructure-operation-list"><div class="empty">Loading operations…</div></div>
</section>

<dialog id="infrastructure-confirm-dialog" class="infrastructure-dialog">
  <form method="dialog" id="infrastructure-confirm-form">
    <h3>Confirm Infrastructure Teardown</h3>
    <p>This removes certificate, DNS, and hosting resources in reverse dependency order. Type <strong>TEARDOWN</strong> to continue.</p>
    <label><span>Confirmation</span><input id="infrastructure-confirm-value" type="text" autocomplete="off" required></label>
    <div class="dialog-actions">
      <button class="button light" value="cancel" type="submit">Cancel</button>
      <button class="button danger" id="infrastructure-confirm-submit" value="confirm" type="submit">Queue Teardown</button>
    </div>
  </form>
</dialog>
<?php ControlCenterPage::renderEnd(['/assets/infrastructure-control-center.js']); ?>
