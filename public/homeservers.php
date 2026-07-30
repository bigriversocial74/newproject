<?php

declare(strict_types=1);

use Vp3\Http\AuthEndpoint;

$container = require dirname(__DIR__) . '/bootstrap.php';

try {
    $current = $container['authentication_context']->requireCurrent(AuthEndpoint::ip(), AuthEndpoint::userAgent());
    $memberships = $container['database']->pdo()->prepare(
        "SELECT a.id,a.public_id,a.display_name,au.role
         FROM account_users au
         JOIN accounts a ON a.id=au.account_id
         WHERE au.user_id=:user AND au.status='active'
           AND au.role IN ('owner','administrator')
           AND a.status='active'
         ORDER BY a.display_name,a.id"
    );
    $memberships->execute(['user' => (int) $current['user']['id']]);
    $accounts = $memberships->fetchAll(PDO::FETCH_ASSOC);
    if ($accounts === []) {
        throw new RuntimeException('Account membership is unavailable.');
    }
    $selectedAccountId = max(0, (int) ($_GET['account_id'] ?? 0));
    $selected = null;
    foreach ($accounts as $account) {
        if ($selectedAccountId === 0 || (int) $account['id'] === $selectedAccountId) {
            $selected = $account;
            break;
        }
    }
    if (!is_array($selected)) {
        $selected = $accounts[0];
    }
    $csrfToken = $container['session']->csrfToken();
} catch (Throwable) {
    http_response_code(401);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    ?><!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VP3 HomeServers</title><style>body{font-family:system-ui;margin:0;background:#f5f6f8;color:#171b24;display:grid;place-items:center;min-height:100vh}.card{max-width:560px;background:#fff;border:1px solid #e2e6ec;border-radius:16px;padding:28px}p{color:#687286;line-height:1.55}</style></head><body><main class="card"><h1>Sign in required</h1><p>Sign in to an active VP3 owner or administrator account to manage HomeServers.</p></main></body></html><?php
    exit;
}

$escape = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('X-Frame-Options: DENY');
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>HomeServer Fleet · VP3</title>
  <link rel="stylesheet" href="/assets/homeserver-fleet.css">
</head>
<body>
<header class="topbar">
  <div class="brand"><div class="brand-mark">V3</div><div><strong>VP3</strong><span>HomeServer Fleet</span></div></div>
  <div class="account-select"><label for="fleet-account">Account</label><select id="fleet-account"><?php foreach ($accounts as $account): ?><option value="<?= (int) $account['id'] ?>" <?= (int) $account['id'] === (int) $selected['id'] ? 'selected' : '' ?>><?= $escape($account['display_name']) ?> · <?= $escape($account['role']) ?></option><?php endforeach; ?></select></div>
</header>
<main class="layout" data-homeserver-fleet data-account-id="<?= (int) $selected['id'] ?>" data-csrf-token="<?= $escape($csrfToken) ?>">
  <section class="hero"><div><span class="eyebrow">Personal online deployment infrastructure</span><h1>HomeServer Activation & Fleet Operations</h1><p>Register HomeServers to eligible VP3 licenses, complete secure Control Center activation, review signed leases and update evidence, and manage each device lifecycle.</p></div><div class="hero-actions"><button id="refresh-fleet" class="button light" type="button">Refresh Fleet</button></div></section>
  <section id="fleet-metrics" class="metrics" aria-label="Fleet summary"></section>
  <div id="fleet-notice" aria-live="polite"></div>
  <section class="workspace">
    <article class="panel"><header class="panel-head"><div><h2>Registered HomeServers</h2><p>Account-scoped operational status and signed authority evidence.</p></div></header><div id="fleet-devices" class="device-list"><div class="empty">Loading fleet…</div></div></article>
    <aside class="stack">
      <article class="panel"><header class="panel-head"><div><h2>Register HomeServer</h2><p>Create a one-time activation bundle for the Control Center.</p></div></header><form id="register-form" class="form"><label><span>Eligible license</span><select id="register-license" required><option value="">Loading licenses…</option></select></label><label><span>Local device fingerprint</span><input id="register-fingerprint" type="text" minlength="64" maxlength="64" pattern="[A-Fa-f0-9]{64}" autocomplete="off" placeholder="Copy from HomeServer Settings" required></label><p class="help">The fingerprint is a namespaced SHA-256 derivative of the local HomeServer installation identity. It is not a hardware serial number.</p><button class="button primary" type="submit">Create Activation Bundle</button></form></article>
      <article class="panel"><header class="panel-head"><div><h2>Activation Steps</h2></div></header><dl class="detail-list"><div><dt>1</dt><dd>Open HomeServer Settings</dd></div><div><dt>2</dt><dd>Copy local fingerprint</dd></div><div><dt>3</dt><dd>Register eligible VP3 license</dd></div><div><dt>4</dt><dd>Paste one-time bundle into Control Center</dd></div><div><dt>5</dt><dd>Verify heartbeat, lease, and release checks</dd></div></dl></article>
      <article class="panel"><header class="panel-head"><div><h2>Privacy Boundary</h2></div></header><p class="help">VP3 stores licensed identity, entitlement state, versions, health timestamps, hashes, and operational receipts. Private files, prompts, conversations, models, tools, MCP content, and local credentials remain on the HomeServer.</p></article>
    </aside>
  </section>
</main>
<div id="fleet-secret-modal" class="modal" hidden aria-live="assertive"></div>
<script src="/assets/homeserver-fleet.js" defer></script>
<script src="/assets/homeserver-transfer-accept.js" defer></script>
</body>
</html>
