<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\ControlCenter\ControlCenterUrl;
use Vp3\Http\AuthEndpoint;

$container = require dirname(__DIR__) . '/bootstrap.php';
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
$token = trim((string) ($_POST['token'] ?? $_GET['token'] ?? ''));
$message = '';
$error = '';
try {
    $current = $container['authentication_context']->requireCurrent(AuthEndpoint::ip(), AuthEndpoint::userAgent(), false);
    if (strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')) === 'POST') {
        $container['session']->assertCsrf((string) ($_POST['csrf_token'] ?? ''));
        $requestId = trim((string) ($_POST['request_id'] ?? ''));
        if (!preg_match('/^[A-Za-z0-9._:-]{8,64}$/', $requestId)) {
            $requestId = 'REQ-INV-' . strtoupper(bin2hex(random_bytes(8)));
        }
        $accountId = $container['team_security']->acceptInvitation(
            (int) $current['user']['id'],
            (string) $current['user']['email'],
            $token,
            $requestId
        );
        $statement = $container['database']->pdo()->prepare(
            "SELECT a.public_id
             FROM account_users au
             JOIN accounts a ON a.id=au.account_id
             WHERE au.account_id=? AND au.user_id=? AND au.status='active' AND a.status='active'
             LIMIT 1"
        );
        $statement->execute([$accountId, (int) $current['user']['id']]);
        $accountPublicId = (string) $statement->fetchColumn();
        if ($accountPublicId === '') {
            throw new RuntimeException('The accepted account is not available.');
        }
        header('Location: ' . ControlCenterUrl::relative('/account-security.php', $accountPublicId, ['invitation' => 'accepted']), true, 303);
        exit;
    }
    if ($token === '') {
        $error = 'The invitation token is missing.';
    }
} catch (AuthPublicException $exception) {
    http_response_code($exception->httpStatus());
    $error = $exception->publicMessage();
} catch (Throwable) {
    http_response_code(500);
    $error = 'The invitation could not be processed.';
}
$escape = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Accept VP3 invitation</title><link rel="stylesheet" href="/assets/control-center.css"></head>
<body class="auth-required"><main class="auth-card"><span class="brand-mark">V3</span><h1>Account invitation</h1>
<?php if ($error !== ''): ?><p><?= $escape($error) ?></p><?php else: ?><p>Signed in as <?= $escape($current['user']['email']) ?>. Accept this invitation only if you recognize the account administrator who sent it.</p>
<form method="post" action="/team-invite.php"><input type="hidden" name="token" value="<?= $escape($token) ?>"><input type="hidden" name="csrf_token" value="<?= $escape($container['session']->csrfToken()) ?>"><input type="hidden" name="request_id" value="REQ-INV-<?= $escape(strtoupper(bin2hex(random_bytes(8)))) ?>"><button class="button primary" type="submit">Accept Invitation</button></form><?php endif; ?>
</main></body></html>
