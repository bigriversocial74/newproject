<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\ControlCenter\AccountPageContext;
use Vp3\ControlCenter\ControlCenterPage;

$container = require dirname(__DIR__) . '/bootstrap.php';
try {
    $context = AccountPageContext::resolve(
        $container,
        ['customer_owner', 'customer_admin', 'billing_manager', 'support_member']
    );
} catch (AuthPublicException $exception) {
    ControlCenterPage::renderAccessFailure('VP3 Account Security', $exception);
}
ControlCenterPage::renderStart(
    $context,
    'Account & Security',
    'account-security',
    'Profile, password, multi-factor authentication, sessions, team access, and security history.'
);
$escape = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
?>
<section class="hero security-hero">
  <div><span class="eyebrow">Identity and access control</span><h2><?= $escape($context['selected']['display_name']) ?></h2><p>Manage your personal security and, when authorized, the account team. Invitation tokens, MFA secrets, recovery codes, and session tokens are never stored in the browser.</p></div>
  <div class="hero-actions"><button class="button light" id="refresh-security" type="button">Refresh Security</button></div>
</section>
<div id="security-notice" aria-live="polite"></div>
<section id="security-metrics" class="metrics" aria-label="Security metrics"><div class="metric"><span>Status</span><strong>Loading…</strong></div></section>
<section class="grid two section-space">
  <article class="panel"><header class="panel-head"><div><h3>Profile</h3><p>Your verified email is read-only. Display-name changes require your current password.</p></div></header><div id="profile-summary" class="security-summary"></div><form id="profile-form" class="security-form"><label>Display name<input name="display_name" maxlength="190" required></label><label>Current password<input name="current_password" type="password" autocomplete="current-password" required></label><button class="button primary" type="submit">Save Profile</button></form></article>
  <article class="panel"><header class="panel-head"><div><h3>Password</h3><p>Changing your password revokes other active sessions.</p></div></header><form id="password-form" class="security-form"><label>Current password<input name="current_password" type="password" autocomplete="current-password" required></label><label>New password<input name="new_password" type="password" autocomplete="new-password" minlength="12" required></label><button class="button primary" type="submit">Change Password</button></form></article>
</section>
<section class="grid two section-space">
  <article class="panel"><header class="panel-head"><div><h3>Multi-Factor Authentication</h3><p>Use a TOTP authenticator and one-time recovery codes.</p></div><span id="mfa-status" class="status">Loading</span></header><div id="mfa-content" class="security-stack"></div></article>
  <article class="panel"><header class="panel-head"><div><h3>Active Sessions</h3><p>Only timestamps and public session references are displayed.</p></div><button class="button small" id="logout-others" type="button">Revoke Other Sessions</button></header><div id="security-sessions" class="list"><div class="empty">Loading sessions…</div></div></article>
</section>
<section id="team-section" class="panel section-space"><header class="panel-head"><div><h3>Account Team</h3><p>Owners and administrators can invite members and manage account roles.</p></div><button class="button primary" id="invite-member" type="button">Invite Member</button></header><div id="team-members" class="list"><div class="empty">Loading team…</div></div><div class="section-divider"></div><h4>Invitations</h4><div id="team-invitations" class="list"><div class="empty">Loading invitations…</div></div></section>
<section class="panel section-space"><header class="panel-head"><div><h3>Security History</h3><p>Append-only customer-safe authentication and team events.</p></div></header><div id="security-events" class="list"><div class="empty">Loading security history…</div></div></section>
<dialog id="security-dialog" class="security-dialog"><form method="dialog" id="security-dialog-form"><header><h3 id="security-dialog-title">Action</h3><button value="cancel" class="dialog-close" aria-label="Close" type="submit">×</button></header><div id="security-dialog-body" class="security-form"></div><footer><button value="cancel" class="button light" type="submit">Cancel</button><button value="confirm" class="button primary" id="security-dialog-confirm" type="submit">Confirm</button></footer></form></dialog>
<?php ControlCenterPage::renderEnd(['/assets/account-security.js']); ?>
