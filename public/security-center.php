<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\ControlCenter\AccountPageContext;
use Vp3\ControlCenter\ControlCenterPage;
use Vp3\ControlCenter\ControlCenterUrl;

$container = require dirname(__DIR__) . '/bootstrap.php';
try {
    $context = AccountPageContext::resolveForRoles(
        $container,
        ['customer_owner', 'customer_admin']
    );
} catch (AuthPublicException $exception) {
    ControlCenterPage::renderAccessFailure('VP3 Security Center', $exception);
}

ControlCenterPage::renderStart(
    $context,
    'Security Center',
    'security-center',
    'Account-wide security posture, tamper-evident evidence, sessions, and incident response.'
);
$escape = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$accountPublicId = (string) $context['selected']['public_id'];
?>
<section class="hero security-center-hero">
  <div>
    <span class="eyebrow">Security operations</span>
    <h2><?= $escape($context['selected']['display_name']) ?></h2>
    <p>Review account-wide risk, verify the audit chain, investigate denied activity, assign responders, and perform reauthenticated emergency actions without exposing private POD or HomeServer content.</p>
  </div>
  <div class="hero-actions">
    <button class="button light" id="security-center-refresh" type="button">Refresh</button>
    <button class="button primary" id="security-center-export" type="button">Export Evidence</button>
  </div>
</section>
<div id="security-center-notice" aria-live="polite"></div>
<section id="security-center-posture" class="security-posture" aria-label="Security posture">
  <div class="security-posture-score"><span>Risk score</span><strong>—</strong></div>
  <div><span class="eyebrow">Audit-chain integrity</span><h3>Loading…</h3><p>Verifying account evidence.</p></div>
</section>
<section id="security-center-metrics" class="metrics" aria-label="Security metrics"><div class="metric"><span>Status</span><strong>Loading…</strong></div></section>

<section class="panel section-space">
  <header class="panel-head">
    <div><h3>Security Alert Policy</h3><p>Opt this account into automatic policy-based case promotion and route selected alerts through the existing Operations notification channels.</p></div>
    <span id="security-policy-status" class="status">Loading…</span>
  </header>
  <form id="security-alert-preferences" class="security-policy-grid">
    <label class="security-toggle"><input type="checkbox" name="automatic_promotion_enabled"><span>Automatic incident promotion</span></label>
    <label>Minimum risk<select name="minimum_risk"><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></label>
    <label class="security-toggle"><input type="checkbox" name="include_integrity_failures"><span>Always include integrity failures</span></label>
    <label class="security-toggle"><input type="checkbox" name="notify_on_promotion"><span>Notify on automatic promotion</span></label>
    <label class="security-toggle"><input type="checkbox" name="notify_on_emergency_action"><span>Notify on emergency response</span></label>
    <div class="security-filter-action"><button class="button primary" type="submit">Save Policy</button></div>
  </form>
</section>

<section class="panel section-space">
  <header class="panel-head">
    <div><h3>Security Cases &amp; Responders</h3><p>Assign active owners, administrators, or support responders; preserve encrypted analyst notes; contain sessions; and close cases only after current-password and MFA proof.</p></div>
    <span id="security-case-count" class="status">0 cases</span>
  </header>
  <div id="security-center-cases" class="security-case-list"><div class="empty">Loading security cases…</div></div>
</section>

<section class="panel section-space">
  <header class="panel-head"><div><h3>Evidence Filters</h3><p>Filter the account ledger by category, risk, result, event type, or UTC date range.</p></div><button class="button small" id="security-filter-reset" type="button">Reset</button></header>
  <form id="security-center-filters" class="security-filter-grid">
    <label>Category<select name="category"><option value="">All categories</option><option>authentication</option><option>session</option><option>mfa</option><option>team</option><option>billing</option><option>domain</option><option>pod</option><option>homeserver</option><option>settings</option><option>integrity</option><option>platform</option></select></label>
    <label>Risk<select name="risk_level"><option value="">All risk levels</option><option>info</option><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label>
    <label>Result<select name="result"><option value="">All results</option><option>success</option><option>failure</option><option>denied</option><option>ignored</option></select></label>
    <label>Event type<input name="event_type" maxlength="120" placeholder="auth.login.failed"></label>
    <label>From<input name="from" type="datetime-local"></label>
    <label>To<input name="to" type="datetime-local"></label>
    <div class="security-filter-action"><button class="button primary" type="submit">Apply Filters</button></div>
  </form>
</section>
<section class="grid two section-space security-center-grid">
  <article class="panel">
    <header class="panel-head"><div><h3>Active Security &amp; Operational Incidents</h3><p>Open and acknowledged account incidents, including policy-promoted security events.</p></div><a class="button small" href="<?= $escape(ControlCenterUrl::relative('/operations.php', $accountPublicId)) ?>">Open Operations</a></header>
    <div id="security-center-incidents" class="list"><div class="empty">Loading incidents…</div></div>
  </article>
  <article class="panel">
    <header class="panel-head"><div><h3>Recent Response Actions</h3><p>Immutable, account-scoped case assignment, note, containment, emergency, and resolution receipts.</p></div></header>
    <div id="security-center-response-actions" class="list"><div class="empty">Loading response activity…</div></div>
  </article>
</section>
<section class="panel section-space">
  <header class="panel-head"><div><h3>Tamper-Evident Security Evidence</h3><p>Account-scoped events with privacy-hashed client evidence and recursively redacted metadata.</p></div><span id="security-center-event-count" class="status">0 events</span></header>
  <div id="security-center-events" class="security-evidence-table"><div class="empty">Loading security evidence…</div></div>
</section>

<dialog id="security-reauth-dialog" class="security-dialog">
  <form method="dialog" id="security-reauth-form">
    <header><div><span class="eyebrow">Sensitive action</span><h3 id="security-reauth-title">Confirm identity</h3></div><button class="button small" value="cancel" type="submit">Close</button></header>
    <p id="security-reauth-description">Enter your current password. MFA is also required when enabled.</p>
    <label>Current password<input name="current_password" type="password" autocomplete="current-password" required></label>
    <label id="security-mfa-field">MFA or recovery code<input name="mfa_code" inputmode="numeric" autocomplete="one-time-code"></label>
    <div class="security-dialog-actions"><button class="button primary" value="confirm" type="submit">Verify and Continue</button></div>
  </form>
</dialog>

<?php ControlCenterPage::renderEnd(['/assets/security-center.js']); ?>
