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
    ControlCenterPage::renderAccessFailure('VP3 Reliability', $exception);
}

ControlCenterPage::renderStart(
    $context,
    'Reliability & Status',
    'reliability',
    'Service objectives, synthetic probes, error budgets, capacity signals, incident automation, and public status communication.'
);
$escape = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
?>
<section class="hero reliability-hero">
  <div>
    <span class="eyebrow">Platform reliability control plane</span>
    <h2><?= $escape($context['selected']['display_name']) ?></h2>
    <p>Measure availability and latency continuously, suppress approved maintenance, correlate health with releases, and escalate sustained objective breaches into Operations incidents.</p>
  </div>
  <div class="hero-actions"><button class="button light" id="reliability-refresh" type="button">Refresh</button></div>
</section>

<div id="reliability-notice" aria-live="polite"></div>
<section id="reliability-metrics" class="metrics" aria-label="Reliability metrics">
  <div class="metric"><span>Status</span><strong>Loading…</strong></div>
</section>

<section class="grid two section-space">
  <article class="panel">
    <header class="panel-head"><div><h3>Reliability Components</h3><p>Public and private platform components with optional staging or production release correlation.</p></div><span id="reliability-component-count" class="status">0 components</span></header>
    <div id="reliability-components" class="reliability-card-list"><div class="empty">Loading components…</div></div>
    <form id="reliability-component-form" class="reliability-form-grid">
      <input type="hidden" name="component_public_id">
      <label>Component key<input name="component_key" maxlength="80" required placeholder="platform-api"></label>
      <label>Display name<input name="display_name" maxlength="160" required placeholder="VP3 Platform API"></label>
      <label>Type<select name="component_type" required>
        <option value="platform">Platform</option><option value="http">HTTP</option><option value="dns">DNS</option>
        <option value="ssl">SSL</option><option value="database">Database</option><option value="worker">Worker</option>
        <option value="queue">Queue</option><option value="storage">Storage</option><option value="provider">Provider</option>
        <option value="pod">POD</option><option value="homeserver">HomeServer</option>
      </select></label>
      <label>Visibility<select name="visibility"><option value="private">Private</option><option value="public">Public status page</option></select></label>
      <label>Environment<select name="environment_public_id" id="reliability-component-environment"><option value="">No release environment</option></select></label>
      <label>Display order<input name="display_order" type="number" min="0" max="10000" value="100"></label>
      <label class="check"><input name="enabled" type="checkbox" checked> Enabled</label>
      <div class="reliability-form-actions"><button class="button primary" type="submit">Save Component</button></div>
    </form>
  </article>

  <article class="panel">
    <header class="panel-head"><div><h3>Service-Level Objective</h3><p>Availability, latency, burn-rate, consecutive-failure, and recovery thresholds.</p></div></header>
    <form id="reliability-objective-form" class="reliability-form-grid">
      <label class="wide">Component<select name="component_public_id" id="reliability-objective-component" required></select></label>
      <label>Availability basis points<input name="availability_target_bps" type="number" min="9000" max="10000" value="9990" required><small>9990 = 99.90%</small></label>
      <label>Latency target ms<input name="latency_target_ms" type="number" min="1" max="300000" placeholder="500"></label>
      <label>Window minutes<input name="evaluation_window_minutes" type="number" min="60" max="525600" value="43200" required></label>
      <label>Warning burn rate<input name="warning_burn_rate" type="number" min="1" max="1000" step="0.01" value="2.00" required></label>
      <label>Critical burn rate<input name="critical_burn_rate" type="number" min="1" max="10000" step="0.01" value="14.40" required></label>
      <label>Failure threshold<input name="consecutive_failure_threshold" type="number" min="1" max="50" value="3" required></label>
      <label>Recovery threshold<input name="recovery_success_threshold" type="number" min="1" max="50" value="2" required></label>
      <div class="reliability-form-actions"><button class="button primary" type="submit">Save Objective</button></div>
    </form>
  </article>
</section>

<section class="grid two section-space">
  <article class="panel">
    <header class="panel-head"><div><h3>Synthetic & Internal Probes</h3><p>Targets remain server-side and are never returned in browser snapshots or the public status page.</p></div></header>
    <form id="reliability-probe-form" class="reliability-form-grid">
      <input type="hidden" name="probe_public_id">
      <label class="wide">Component<select name="component_public_id" id="reliability-probe-component" required></select></label>
      <label>Probe type<select name="probe_type" required>
        <option value="http">HTTPS</option><option value="dns">DNS</option><option value="ssl">TLS certificate</option>
        <option value="database">Primary database</option><option value="worker">Release worker</option>
        <option value="queue">Release queue</option><option value="storage">Application storage</option><option value="manual">Manual observation</option>
      </select></label>
      <label>Target<input name="target_value" maxlength="500" required placeholder="https://vp3.me/health"></label>
      <label>Interval seconds<input name="interval_seconds" type="number" min="60" max="86400" value="300" required></label>
      <label>Timeout ms<input name="timeout_ms" type="number" min="250" max="30000" value="5000" required></label>
      <label class="check"><input name="enabled" type="checkbox" checked> Enabled</label>
      <div class="reliability-form-actions"><button class="button primary" type="submit">Save Probe</button></div>
    </form>
    <p class="form-help">Protected targets: database <code>primary</code>; worker <code>staging:300</code> or <code>production:300</code>; queue numeric threshold; storage <code>application_root</code>; manual <code>manual</code>.</p>
  </article>

  <article class="panel">
    <header class="panel-head"><div><h3>Manual Observation</h3><p>Record a provider, POD, HomeServer, or external dependency signal through a configured manual probe.</p></div></header>
    <form id="reliability-manual-form" class="reliability-form-grid">
      <label class="wide">Manual probe<select name="probe_public_id" id="reliability-manual-probe" required></select></label>
      <label>Status<select name="status"><option value="success">Success</option><option value="failure">Failure</option><option value="maintenance">Maintenance</option></select></label>
      <label>Latency ms<input name="latency_ms" type="number" min="0" max="300000"></label>
      <label>Numeric value<input name="value_numeric" type="number" step="0.0001"></label>
      <label>Error code<input name="error_code" maxlength="100" placeholder="provider_unavailable"></label>
      <div class="reliability-form-actions"><button class="button primary" type="submit">Record Observation</button></div>
    </form>
  </article>
</section>

<section class="grid two section-space">
  <article class="panel">
    <header class="panel-head"><div><h3>Public Status Page</h3><p>Only explicitly public components and customer-safe communication are shown.</p></div><a id="reliability-public-link" class="button small" href="#" hidden target="_blank" rel="noopener">Open Status Page</a></header>
    <form id="reliability-status-form" class="reliability-form-grid">
      <label>Public slug<input name="public_slug" maxlength="80" required placeholder="vp3-platform"></label>
      <label>Page title<input name="page_title" maxlength="160" required placeholder="VP3 Platform Status"></label>
      <label class="wide">Description<textarea name="page_description" maxlength="500" required></textarea></label>
      <label class="check"><input name="public_enabled" type="checkbox"> Public page enabled</label>
      <label class="check"><input name="show_history" type="checkbox" checked> Show status history</label>
      <div class="reliability-form-actions"><button class="button primary" type="submit">Save Status Page</button></div>
    </form>
  </article>

  <article class="panel">
    <header class="panel-head"><div><h3>Status Communication</h3><p>Publish scheduled maintenance, active incident, and resolution messages.</p></div></header>
    <form id="reliability-message-form" class="reliability-form-grid">
      <label class="wide">Component<select name="component_public_id" id="reliability-message-component"><option value="">All components</option></select></label>
      <label class="wide">Title<input name="title" maxlength="160" required></label>
      <label class="wide">Message<textarea name="message" maxlength="1000" required></textarea></label>
      <label>Starts UTC<input name="starts_at" type="datetime-local" required></label>
      <label>Ends UTC<input name="ends_at" type="datetime-local"></label>
      <div class="reliability-form-actions"><button class="button primary" type="submit">Publish Message</button></div>
    </form>
  </article>
</section>

<section class="panel section-space">
  <header class="panel-head"><div><h3>Status Messages & Maintenance</h3><p>Phase 34 maintenance windows are synchronized into reliability evaluation and suppress false alerts.</p></div></header>
  <div id="reliability-messages" class="reliability-card-list"><div class="empty">Loading status communication…</div></div>
  <div id="reliability-windows" class="reliability-card-list compact"><div class="empty">Loading maintenance windows…</div></div>
</section>

<section class="panel section-space">
  <header class="panel-head"><div><h3>Immutable Status History</h3><p>Component transitions are chained with SHA-256 evidence and correlated with active release identity.</p></div></header>
  <div id="reliability-events" class="reliability-event-list"><div class="empty">Loading status history…</div></div>
</section>

<?php ControlCenterPage::renderEnd(['/assets/reliability.js']); ?>
