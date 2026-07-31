<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\ControlCenter\AccountPageContext;
use Vp3\ControlCenter\ControlCenterPage;
use Vp3\Deployment\PlatformOperatorAuthorizer;

$container = require dirname(__DIR__) . '/bootstrap.php';
try {
    $context = AccountPageContext::resolveForRoles($container, ['customer_owner', 'customer_admin']);
    $authorizer = new PlatformOperatorAuthorizer($container['database']);
    $authorizer->assertOperator(
        (int) $context['selected']['id'],
        (int) $context['current']['user']['id'],
        (string) $context['selected']['role']
    );
} catch (AuthPublicException $exception) {
    ControlCenterPage::renderAccessFailure('VP3 Releases & Deployments', $exception);
}

ControlCenterPage::renderStart(
    $context,
    'Releases & Deployments',
    'releases',
    'Signed release inventory, production approvals, maintenance windows, deployment health, and reauthenticated rollback.'
);
$escape = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
?>
<section class="hero release-hero">
  <div>
    <span class="eyebrow">Platform operator control plane</span>
    <h2><?= $escape($context['selected']['display_name']) ?></h2>
    <p>Promote verified releases from staging to production through owner-approved maintenance windows. Browser requests only create controlled queue records; deployment workers execute the certified Phase 33 upgrade and rollback engine.</p>
  </div>
  <div class="hero-actions"><button class="button light" id="release-refresh" type="button">Refresh</button></div>
</section>
<div id="release-notice" aria-live="polite"></div>
<section id="release-metrics" class="metrics" aria-label="Release metrics"><div class="metric"><span>Status</span><strong>Loading…</strong></div></section>

<section class="grid two section-space release-environment-grid">
  <article class="panel">
    <header class="panel-head"><div><h3>Deployment Environments</h3><p>Store only canonical HTTPS origins and SHA-256 fingerprints generated from non-secret target configuration. Secrets remain in protected server configuration.</p></div></header>
    <div id="release-environments" class="release-card-list"><div class="empty">Loading environments…</div></div>
    <form id="release-environment-form" class="release-form-grid">
      <label>Environment<select name="environment_key" required><option value="staging">Staging</option><option value="production">Production</option></select></label>
      <label>Display name<input name="display_name" maxlength="120" required placeholder="VP3 Production"></label>
      <label class="wide">Base URL<input name="base_url" type="url" maxlength="500" required placeholder="https://vp3.me"></label>
      <label class="wide">Configuration SHA-256<input name="config_fingerprint" maxlength="64" pattern="[a-fA-F0-9]{64}" required placeholder="Run tools/vp3-environment-fingerprint.php on the target host"></label>
      <div class="release-form-actions"><button class="button primary" type="submit">Save Environment</button></div>
    </form>
  </article>

  <article class="panel">
    <header class="panel-head"><div><h3>Verified Release Candidates</h3><p>Candidates are registered from detached Ed25519 artifacts by the server-side release registry tool.</p></div><span id="release-candidate-count" class="status">0 candidates</span></header>
    <div id="release-candidates" class="release-card-list"><div class="empty">Loading candidates…</div></div>
  </article>
</section>

<section class="grid two section-space">
  <article class="panel">
    <header class="panel-head"><div><h3>Maintenance Windows</h3><p>Production promotions run only inside an owner-approved UTC window of six hours or less.</p></div><span id="release-window-count" class="status">0 windows</span></header>
    <form id="release-window-form" class="release-form-grid">
      <label>Target environment<select name="environment_public_id" id="release-window-environment" required></select></label>
      <label>Starts UTC<input name="starts_at" type="datetime-local" required></label>
      <label>Ends UTC<input name="ends_at" type="datetime-local" required></label>
      <label class="wide">Reason<textarea name="reason" maxlength="500" required placeholder="Scheduled platform release and health verification"></textarea></label>
      <div class="release-form-actions"><button class="button primary" type="submit">Schedule Window</button></div>
    </form>
    <div id="release-windows" class="release-card-list"><div class="empty">Loading maintenance windows…</div></div>
  </article>

  <article class="panel">
    <header class="panel-head"><div><h3>Request Promotion</h3><p>Staging must be healthy and running the selected signed candidate. Production requires a current healthy worker and an approved window.</p></div></header>
    <form id="release-promotion-form" class="release-form-grid">
      <label>Release candidate<select name="candidate_public_id" id="release-promotion-candidate" required></select></label>
      <label>Source<select name="source_environment_public_id" id="release-promotion-source" required></select></label>
      <label>Target<select name="target_environment_public_id" id="release-promotion-target" required></select></label>
      <label>Maintenance window<select name="maintenance_window_public_id" id="release-promotion-window" required></select></label>
      <label class="wide">Scheduled UTC<input name="scheduled_for" type="datetime-local"><small>Leave blank to queue immediately when the window opens.</small></label>
      <div class="release-form-actions"><button class="button primary" type="submit">Request Promotion</button></div>
    </form>
  </article>
</section>

<section class="panel section-space">
  <header class="panel-head"><div><h3>Promotion & Deployment History</h3><p>Approval, deployment, backup, health, failure, and rollback evidence remain linked to the promotion record.</p></div><span id="release-promotion-count" class="status">0 promotions</span></header>
  <div id="release-promotions" class="release-promotion-list"><div class="empty">Loading promotions…</div></div>
</section>

<section class="panel section-space">
  <header class="panel-head"><div><h3>Latest Environment Health</h3><p>Non-secret readiness evidence from database, schema, active release, worker, and deployment checks.</p></div></header>
  <div id="release-health" class="release-card-list"><div class="empty">Loading health evidence…</div></div>
</section>

<dialog id="release-reauth-dialog" class="release-dialog">
  <form method="dialog" id="release-reauth-form">
    <header><div><span class="eyebrow">Sensitive platform action</span><h3 id="release-reauth-title">Confirm identity</h3></div><button class="button small" value="cancel" type="submit">Close</button></header>
    <p id="release-reauth-description">Enter your current password. MFA is required when enabled.</p>
    <label>Current password<input name="current_password" type="password" autocomplete="current-password" required></label>
    <label id="release-mfa-field">MFA or recovery code<input name="mfa_code" autocomplete="one-time-code"></label>
    <div class="release-dialog-actions"><button class="button primary" value="confirm" type="submit">Verify and Continue</button></div>
  </form>
</dialog>

<?php ControlCenterPage::renderEnd(['/assets/release-deployment.js']); ?>
