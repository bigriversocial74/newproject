<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\ControlCenter\AccountPageContext;
use Vp3\ControlCenter\ControlCenterPage;

$container = require dirname(__DIR__) . '/bootstrap.php';
try {
    $context = AccountPageContext::resolveForRoles(
        $container,
        ['customer_owner', 'customer_admin', 'support_member']
    );
} catch (AuthPublicException $exception) {
    ControlCenterPage::renderAccessFailure('VP3 Operations', $exception);
}

ControlCenterPage::renderStart(
    $context,
    'Operations',
    'operations',
    'Account health, operational incidents, notification channels, and delivery evidence.'
);
$escape = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
?>
<section class="hero operations-hero">
  <div>
    <span class="eyebrow">Account operations control</span>
    <h2><?= $escape($context['selected']['display_name']) ?></h2>
    <p>Review account-scoped health signals, acknowledge incidents, record resolutions, and manage encrypted email notification channels. Private POD and HomeServer content remains outside VP3.</p>
  </div>
  <div class="hero-actions">
    <button class="button light" id="refresh-operations" type="button">Refresh Operations</button>
    <button class="button primary" id="add-notification-channel" type="button" hidden>Add Notification Channel</button>
  </div>
</section>
<div id="operations-notice" aria-live="polite"></div>
<section id="operations-metrics" class="metrics" aria-label="Operations metrics">
  <div class="metric"><span>Status</span><strong>Loading…</strong></div>
</section>
<section class="grid two section-space">
  <article class="panel">
    <header class="panel-head"><div><h3>Account Health</h3><p>Latest customer-safe health state by operational source.</p></div></header>
    <div id="operations-health" class="operations-list"><div class="empty">Loading health signals…</div></div>
  </article>
  <article class="panel">
    <header class="panel-head"><div><h3>Notification Delivery</h3><p>Queued, delivered, and failed delivery evidence without provider responses or destination data.</p></div></header>
    <div id="operations-deliveries" class="operations-list"><div class="empty">Loading deliveries…</div></div>
  </article>
</section>
<section class="panel section-space">
  <header class="panel-head"><div><h3>Operational Incidents</h3><p>Account-isolated incident state, occurrence history, and role-aware actions.</p></div></header>
  <div id="operations-incidents" class="operations-list"><div class="empty">Loading incidents…</div></div>
</section>
<section class="grid two section-space">
  <article class="panel">
    <header class="panel-head"><div><h3>Incident Timeline</h3><p>Append-only status transitions and monitor events.</p></div></header>
    <div id="operations-events" class="operations-list"><div class="empty">Loading incident events…</div></div>
  </article>
  <article class="panel">
    <header class="panel-head"><div><h3>Notification Channels</h3><p>Email destinations remain encrypted and are never returned to the browser.</p></div></header>
    <div id="operations-channels" class="operations-list"><div class="empty">Loading channels…</div></div>
  </article>
</section>
<dialog id="operations-dialog" class="operations-dialog">
  <form method="dialog" id="operations-dialog-form">
    <header><h3 id="operations-dialog-title">Operations Action</h3><button value="cancel" class="dialog-close" aria-label="Close" type="submit">×</button></header>
    <div id="operations-dialog-body" class="operations-form"></div>
    <footer><button value="cancel" class="button light" type="submit">Cancel</button><button value="confirm" class="button primary" id="operations-dialog-confirm" type="submit">Confirm</button></footer>
  </form>
</dialog>
<?php ControlCenterPage::renderEnd(['/assets/operations-control-center.js']); ?>
