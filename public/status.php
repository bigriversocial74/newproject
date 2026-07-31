<?php

declare(strict_types=1);

use Vp3\Deployment\PlatformOperatorAuthorizer;
use Vp3\Reliability\ReliabilityControlCenterQueryService;

$container = require dirname(__DIR__) . '/bootstrap.php';
$slug = strtolower(trim((string) ($_GET['status'] ?? '')));
$service = new ReliabilityControlCenterQueryService(
    $container['database'],
    new PlatformOperatorAuthorizer($container['database'])
);

try {
    $status = $service->publicStatus($slug);
} catch (Throwable) {
    http_response_code(404);
    $status = null;
}

header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: public, max-age=30, stale-while-revalidate=60');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
$escape = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
if ($status === null):
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Status page unavailable</title><link rel="stylesheet" href="/assets/reliability.css"></head><body class="status-page"><main class="status-shell"><section class="status-hero"><span class="status-brand">VP3</span><h1>Status page unavailable</h1><p>The requested status page is not published.</p></section></main></body></html>
<?php exit; endif;
$page = $status['page'];
$overall = (string) $status['overall_status'];
$labels = ['operational' => 'All systems operational', 'degraded' => 'Degraded performance', 'major_outage' => 'Major service outage', 'maintenance' => 'Scheduled maintenance', 'unknown' => 'Status unavailable'];
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title><?= $escape($page['page_title']) ?></title>
  <link rel="stylesheet" href="/assets/reliability.css">
</head>
<body class="status-page">
<main class="status-shell">
  <section class="status-hero status-<?= $escape($overall) ?>">
    <span class="status-brand">VP3</span>
    <h1><?= $escape($page['page_title']) ?></h1>
    <p><?= $escape($page['page_description']) ?></p>
    <div class="overall-state"><span aria-hidden="true"></span><strong><?= $escape($labels[$overall] ?? $labels['unknown']) ?></strong></div>
  </section>

  <?php if ($status['messages'] !== []): ?>
  <section class="public-status-section"><h2>Updates</h2>
    <?php foreach ($status['messages'] as $message): ?>
      <article class="public-message"><div><strong><?= $escape($message['title']) ?></strong><span><?= $escape($message['message_status']) ?></span></div><p><?= $escape($message['message']) ?></p><small><?= $escape($message['starts_at']) ?> UTC<?= $message['component_name'] ? ' · ' . $escape($message['component_name']) : '' ?></small></article>
    <?php endforeach; ?>
  </section>
  <?php endif; ?>

  <section class="public-status-section"><h2>Components</h2>
    <div class="public-component-list">
      <?php foreach ($status['components'] as $component): ?>
        <article class="public-component">
          <div><strong><?= $escape($component['display_name']) ?></strong><small><?= $escape($component['component_type']) ?></small></div>
          <span class="component-state state-<?= $escape($component['current_status']) ?>"><?= $escape(str_replace('_', ' ', $component['current_status'])) ?></span>
        </article>
      <?php endforeach; ?>
      <?php if ($status['components'] === []): ?><div class="empty">No public components are configured.</div><?php endif; ?>
    </div>
  </section>

  <?php if ($page['show_history'] && $status['history'] !== []): ?>
  <section class="public-status-section"><h2>Recent history</h2>
    <div class="public-history">
      <?php foreach ($status['history'] as $event): ?>
        <article><span class="history-dot state-<?= $escape($event['current_status']) ?>"></span><div><strong><?= $escape($event['display_name']) ?></strong><p><?= $escape(str_replace('_', ' ', $event['previous_status'])) ?> → <?= $escape(str_replace('_', ' ', $event['current_status'])) ?></p><small><?= $escape($event['occurred_at']) ?> UTC</small></div></article>
      <?php endforeach; ?>
    </div>
  </section>
  <?php endif; ?>

  <footer>Last refreshed <?= $escape($status['generated_at']) ?> · Customer-safe platform status only.</footer>
</main>
</body>
</html>
