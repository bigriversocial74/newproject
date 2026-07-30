<?php

declare(strict_types=1);

namespace Vp3\ControlCenter;

use Vp3\Auth\AuthPublicException;

final class ControlCenterPage
{
    /** @param array<string,mixed> $context */
    public static function renderStart(array $context, string $title, string $active, string $description): void
    {
        self::securityHeaders();
        $accounts = $context['accounts'];
        $selected = $context['selected'];
        $escape = static fn (mixed $value): string => htmlspecialchars(
            (string) $value,
            ENT_QUOTES | ENT_SUBSTITUTE,
            'UTF-8'
        );
        $nav = [
            'dashboard' => ['/dashboard.php', 'Dashboard'],
            'domains' => ['/domains.php', 'Domains'],
            'pods' => ['/pods.php', 'PODs'],
            'homeservers' => ['/homeservers.php', 'HomeServers'],
        ];
        ?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title><?= $escape($title) ?> · VP3</title>
  <link rel="stylesheet" href="/assets/control-center.css">
  <link rel="stylesheet" href="/assets/homeserver-control-center-compat.css">
</head>
<body>
<div class="app-shell">
  <aside class="sidebar">
    <a class="brand" href="/dashboard.php?account_id=<?= (int) $selected['id'] ?>" aria-label="VP3 Dashboard">
      <span class="brand-mark">V3</span>
      <span><strong>VP3</strong><small>Personal Online Deployment</small></span>
    </a>
    <nav class="nav" aria-label="VP3 Control Center">
      <?php foreach ($nav as $key => [$href, $label]): ?>
        <a class="nav-link<?= $active === $key ? ' active' : '' ?>" href="<?= $escape($href) ?>?account_id=<?= (int) $selected['id'] ?>">
          <span class="nav-dot" aria-hidden="true"></span><?= $escape($label) ?>
        </a>
      <?php endforeach; ?>
    </nav>
    <div class="sidebar-foot">
      <span>Account-scoped control plane</span>
      <small>Private POD and HomeServer content stays outside VP3.</small>
    </div>
  </aside>
  <div class="app-main">
    <header class="topbar">
      <div><h1><?= $escape($title) ?></h1><p><?= $escape($description) ?></p></div>
      <label class="account-picker"><span>Account</span><select id="control-center-account">
        <?php foreach ($accounts as $account): ?>
          <option value="<?= (int) $account['id'] ?>" <?= (int) $account['id'] === (int) $selected['id'] ? 'selected' : '' ?>><?= $escape($account['display_name']) ?> · <?= $escape($account['role']) ?></option>
        <?php endforeach; ?>
      </select></label>
    </header>
    <main class="content" data-control-center data-account-id="<?= (int) $selected['id'] ?>" data-csrf-token="<?= $escape($context['csrf_token']) ?>" data-page="<?= $escape($active) ?>">
<?php
    }

    /** @param list<string> $scripts */
    public static function renderEnd(array $scripts = []): void
    {
        ?>
    </main>
  </div>
</div>
<script src="/assets/control-center-shell.js" defer></script>
<?php foreach ($scripts as $script): ?><script src="<?= htmlspecialchars($script, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>" defer></script><?php endforeach; ?>
</body>
</html>
<?php
    }

    public static function renderAccessFailure(string $title, AuthPublicException $exception): never
    {
        self::securityHeaders();
        http_response_code($exception->httpStatus());
        $heading = $exception->httpStatus() === 401 ? 'Sign in required' : 'Account access required';
        ?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title><?= htmlspecialchars($title, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></title><link rel="stylesheet" href="/assets/control-center.css"></head><body class="auth-required"><main class="auth-card"><span class="brand-mark">V3</span><h1><?= htmlspecialchars($heading, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></h1><p><?= htmlspecialchars($exception->publicMessage(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></p></main></body></html>
<?php
        exit;
    }

    public static function securityHeaders(): void
    {
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: same-origin');
        header('X-Frame-Options: DENY');
        header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
    }
}
