<?php

declare(strict_types=1);

use Vp3\Http\AuthEndpoint;

$container = require dirname(__DIR__) . '/bootstrap.php';

try {
    $current = $container['authentication_context']->requireCurrent(AuthEndpoint::ip(), AuthEndpoint::userAgent());
    $memberships = $container['database']->pdo()->prepare(
        "SELECT a.id,a.public_id,a.display_name,au.role FROM account_users au JOIN accounts a ON a.id=au.account_id WHERE au.user_id=:user AND au.status='active' AND au.role IN ('owner','administrator') AND a.status='active' ORDER BY a.display_name,a.id"
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
    ?><!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VP3 Settings</title><style>body{font-family:system-ui;margin:0;background:#f5f6f8;color:#171b24;display:grid;place-items:center;min-height:100vh}.card{max-width:560px;background:#fff;border:1px solid #e2e6ec;border-radius:16px;padding:28px}p{color:#687286;line-height:1.55}</style></head><body><main class="card"><h1>Sign in required</h1><p>Sign in to an active VP3 owner or administrator account to manage shared settings.</p></main></body></html><?php
    exit;
}

$escape = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Shared Settings · VP3</title>
  <link rel="stylesheet" href="/assets/federated-settings.css">
</head>
<body>
<header class="topbar">
  <a class="brand" href="/"><span class="brand-mark">V3</span><span><strong>VP3</strong><small>Shared Control Center</small></span></a>
  <nav><a href="/homeservers.php">HomeServers</a><a class="active" href="/settings.php">Settings</a></nav>
  <label class="account-select"><span>Account</span><select id="settings-account"><?php foreach ($accounts as $account): ?><option value="<?= (int) $account['id'] ?>" <?= (int) $account['id'] === (int) $selected['id'] ? 'selected' : '' ?>><?= $escape($account['display_name']) ?> · <?= $escape($account['role']) ?></option><?php endforeach; ?></select></label>
</header>
<main class="layout" data-federated-settings data-account-id="<?= (int) $selected['id'] ?>" data-csrf-token="<?= $escape($csrfToken) ?>">
  <section class="hero">
    <div><span class="eyebrow">One configuration model · two control surfaces</span><h1>VP3 & HomeServer Settings</h1><p>VP3 controls cloud, licensing, and account policy. HomeServer controls private local behavior. Shared preferences synchronize with revisions and conflict receipts instead of overwriting each other.</p></div>
    <div class="hero-actions"><button id="refresh-settings" type="button" class="button secondary">Refresh</button><button id="sync-settings" type="button" class="button primary">Request HomeServer Sync</button></div>
  </section>
  <section class="summary" id="settings-summary" aria-label="Settings synchronization summary"></section>
  <div id="settings-notice" aria-live="polite"></div>
  <section id="settings-groups" class="settings-groups"><div class="loading">Loading shared settings…</div></section>
  <section class="boundary"><h2>Authority boundary</h2><div class="boundary-grid"><article><strong>VP3</strong><p>Account, subscription, domain, license, release channel, and cloud notification policy.</p></article><article><strong>HomeServer</strong><p>Private files, models, tools, credentials, local schedules, local execution, and desktop behavior.</p></article><article><strong>Shared</strong><p>Only explicitly cataloged, non-secret preferences synchronize through revisioned snapshots.</p></article></div></section>
</main>
<script src="/assets/federated-settings.js" defer></script>
</body>
</html>
