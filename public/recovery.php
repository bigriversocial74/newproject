<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\ControlCenter\AccountPageContext;
use Vp3\ControlCenter\ControlCenterPage;

$container = require dirname(__DIR__) . '/bootstrap.php';
try {
    $context = AccountPageContext::resolveForRoles($container, ['customer_owner', 'customer_admin']);
} catch (AuthPublicException $exception) {
    ControlCenterPage::renderAccessFailure('VP3 Recovery & Updates', $exception);
}
ControlCenterPage::renderStart(
    $context,
    'Recovery & Updates',
    'recovery',
    'POD storage, verified backups, restore queues, signed releases, updates, and rollback evidence.'
);
$escape = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
?>
<section class="hero recovery-hero">
  <div>
    <span class="eyebrow">Protected POD lifecycle</span>
    <h2><?= $escape($context['selected']['display_name']) ?></h2>
    <p>Schedule verified backups, restore account-owned snapshots, and install signed POD releases with mandatory pre-update recovery protection.</p>
  </div>
  <div class="hero-actions"><button class="button light" id="recovery-refresh" type="button">Refresh Recovery</button></div>
</section>
<div id="recovery-notice" aria-live="polite"></div>
<section id="recovery-metrics" class="metrics"><div class="metric"><span>Status</span><strong>Loading…</strong></div></section>
<section class="grid two recovery-layout">
  <div class="grid">
    <article class="panel"><header class="panel-head"><div><h3>POD Recovery Plans</h3><p>Storage state, scheduling, retention, backup, and eligible signed releases.</p></div></header><div id="recovery-pods" class="list"><div class="empty">Loading POD recovery state…</div></div></article>
    <article class="panel"><header class="panel-head"><div><h3>Verified Snapshots</h3><p>Only verified, account-owned snapshots can enter the restore queue.</p></div></header><div id="recovery-snapshots" class="list"><div class="empty">Loading snapshots…</div></div></article>
  </div>
  <aside class="grid">
    <article class="panel"><header class="panel-head"><div><h3>Backup & Restore Jobs</h3><p>Customer-safe queue and completion history.</p></div></header><div id="recovery-jobs" class="list"><div class="empty">Loading recovery jobs…</div></div></article>
    <article class="panel"><header class="panel-head"><div><h3>Software Updates</h3><p>Signed release progress, pre-update backup verification, stages, and rollback state.</p></div></header><div id="recovery-updates" class="list"><div class="empty">Loading updates…</div></div></article>
  </aside>
</section>
<dialog id="recovery-dialog" class="security-dialog">
  <form method="dialog" id="recovery-dialog-form">
    <header><h3 id="recovery-dialog-title">Confirm action</h3><button class="dialog-close" value="cancel" aria-label="Close">×</button></header>
    <div id="recovery-dialog-body" class="dialog-body"></div>
    <footer><button class="button light" value="cancel">Cancel</button><button class="button primary" id="recovery-dialog-confirm" value="confirm">Confirm</button></footer>
  </form>
</dialog>
<?php ControlCenterPage::renderEnd(['/assets/recovery-control-center.js']); ?>
