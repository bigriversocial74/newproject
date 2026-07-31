<?php

declare(strict_types=1);

use Vp3\Auth\PasswordPolicy;
use Vp3\Database;
use Vp3\Deployment\InitialOwnerBootstrapService;
use Vp3\Deployment\PlatformOperatorGrantService;
use Vp3\Deployment\WebInitialSetupService;

header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");

$root = dirname(__DIR__);
$configPath = $root . '/config/config.php';
$state = 'config_missing';
$message = null;
$errors = [];
$result = null;
$config = null;
$database = null;
$setupAvailable = false;
$operatorGrantEnabled = true;

$escape = static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

$autoload = $root . '/vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
} else {
    spl_autoload_register(static function (string $class) use ($root): void {
        $prefix = 'Vp3\\';
        if (!str_starts_with($class, $prefix)) {
            return;
        }
        $path = $root . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($path)) {
            require $path;
        }
    });
}

try {
    if (!is_file($configPath)) {
        $message = 'Rename config/config-example.php to config/config.php, update the marked settings, then reload this page.';
    } else {
        $config = require $configPath;
        if (!is_array($config)) {
            throw new RuntimeException('config/config.php must return a PHP array.');
        }

        $app = (array) ($config['app'] ?? []);
        $sessionName = trim((string) ($app['session_name'] ?? 'vp3_setup'));
        if ($sessionName === '' || preg_match('/^[A-Za-z0-9,-]{1,128}$/', $sessionName) !== 1) {
            $sessionName = 'vp3_setup';
        }
        session_name($sessionName . '_setup');
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'secure' => (bool) ($app['session_secure'] ?? true),
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        session_start();

        if (!isset($_SESSION['vp3_setup_csrf']) || !is_string($_SESSION['vp3_setup_csrf'])) {
            $_SESSION['vp3_setup_csrf'] = bin2hex(random_bytes(32));
        }

        $setup = (array) ($config['setup'] ?? []);
        $setupEnabled = (bool) ($setup['enabled'] ?? false);
        $setupKey = trim((string) ($setup['first_user_key'] ?? ''));
        $operatorGrantEnabled = (bool) ($setup['grant_platform_operator_to_first_owner'] ?? true);
        $authKeyEncoded = (string) (($config['auth']['secret_encryption_key_base64'] ?? ''));
        $authKey = base64_decode($authKeyEncoded, true);
        $appEnvironment = strtolower(trim((string) ($app['env'] ?? '')));
        $baseUrl = (string) ($app['base_url'] ?? '');
        $baseUrlParts = parse_url($baseUrl);
        $productionOriginValid = $appEnvironment !== 'production'
            || (is_array($baseUrlParts)
                && strtolower((string) ($baseUrlParts['scheme'] ?? '')) === 'https'
                && isset($baseUrlParts['host'])
                && !isset($baseUrlParts['user'], $baseUrlParts['pass'], $baseUrlParts['query'], $baseUrlParts['fragment']));

        if (!$setupEnabled
            || strlen($setupKey) < 20
            || str_contains(strtoupper($setupKey), 'CHANGE_THIS')
            || !is_string($authKey)
            || strlen($authKey) !== 32
            || str_contains(strtoupper($authKeyEncoded), 'CHANGE_THIS')
            || !$productionOriginValid) {
            $state = 'config_invalid';
            $message = 'Finish the marked setup values in config/config.php. Use a private setup key, a valid 32-byte base64 encryption key, and an HTTPS production URL.';
        } else {
            $database = new Database((array) ($config['database'] ?? []));
            $pdo = $database->pdo();
            $requiredTables = [
                'accounts',
                'users',
                'account_users',
                'platform_deployment_receipts',
                'platform_operator_accounts',
                'platform_release_control_receipts',
            ];
            $missingTables = [];
            $tableStatement = $pdo->prepare(
                'SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=:table_name'
            );
            foreach ($requiredTables as $table) {
                $tableStatement->execute(['table_name' => $table]);
                if ((int) $tableStatement->fetchColumn() !== 1) {
                    $missingTables[] = $table;
                }
            }

            if ($missingTables !== []) {
                $state = 'database_not_installed';
                $message = 'The database connection works, but the VP3 SQL installer has not been imported into this database.';
            } else {
                $accountCount = (int) $pdo->query('SELECT COUNT(*) FROM accounts')->fetchColumn();
                $userCount = (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
                if ($accountCount !== 0 || $userCount !== 0) {
                    $state = 'locked';
                    $message = 'Initial setup is permanently locked because a VP3 account or user already exists.';
                } else {
                    $state = 'ready';
                    $setupAvailable = true;
                }
            }
        }
    }
} catch (Throwable) {
    $state = 'error';
    $message = 'VP3 could not validate the configuration or database. Check the values in config/config.php.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $setupAvailable && is_array($config) && $database instanceof Database) {
    $now = time();
    $attemptWindow = (array) ($_SESSION['vp3_setup_attempts'] ?? ['started_at' => $now, 'count' => 0]);
    if (($now - (int) ($attemptWindow['started_at'] ?? 0)) > 900) {
        $attemptWindow = ['started_at' => $now, 'count' => 0];
    }

    try {
        if ((int) ($attemptWindow['count'] ?? 0) >= 5) {
            throw new RuntimeException('Too many setup attempts. Reload after 15 minutes.');
        }
        $csrf = (string) ($_POST['csrf_token'] ?? '');
        if (!hash_equals((string) $_SESSION['vp3_setup_csrf'], $csrf)) {
            throw new RuntimeException('The setup form expired. Reload and try again.');
        }

        $setup = (array) ($config['setup'] ?? []);
        $configuredSetupKey = (string) ($setup['first_user_key'] ?? '');
        $submittedSetupKey = trim((string) ($_POST['setup_key'] ?? ''));
        if (!hash_equals($configuredSetupKey, $submittedSetupKey)) {
            $attemptWindow['count'] = (int) ($attemptWindow['count'] ?? 0) + 1;
            $_SESSION['vp3_setup_attempts'] = $attemptWindow;
            throw new RuntimeException('The setup key is not correct.');
        }

        $email = trim((string) ($_POST['email'] ?? ''));
        $displayName = trim((string) ($_POST['display_name'] ?? ''));
        $accountName = trim((string) ($_POST['account_name'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');
        $passwordConfirmation = (string) ($_POST['password_confirmation'] ?? '');
        if (!hash_equals($password, $passwordConfirmation)) {
            throw new RuntimeException('The passwords do not match.');
        }

        $requestId = 'web-owner-' . gmdate('YmdHis') . '-' . bin2hex(random_bytes(6));
        $passwordPolicy = new PasswordPolicy((int) (($config['auth']['password_min_length'] ?? 12)));
        $setupService = new WebInitialSetupService(
            $database,
            new InitialOwnerBootstrapService($database, $passwordPolicy),
            new PlatformOperatorGrantService($database)
        );
        $result = $setupService->createFirstAdministrator(
            $email,
            $displayName,
            $accountName,
            $password,
            $requestId,
            $operatorGrantEnabled
        );
        $password = str_repeat("\0", strlen($password));
        $passwordConfirmation = str_repeat("\0", strlen($passwordConfirmation));
        $_SESSION = [];
        session_regenerate_id(true);
        $state = 'complete';
        $setupAvailable = false;
        $message = 'The first VP3 administrator was created successfully. This setup page is now locked.';
    } catch (Throwable $exception) {
        $errors[] = $exception->getMessage();
    }
}

$baseUrl = is_array($config) ? rtrim((string) (($config['app']['base_url'] ?? '/')), '/') : '/';
if ($baseUrl === '') {
    $baseUrl = '/';
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>VP3 First Administrator Setup</title>
    <style>
        :root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#141414;background:#f5f5f3}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:32px 18px}.shell{width:min(720px,100%)}.brand{font-size:14px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;margin-bottom:14px}.card{background:#fff;border:1px solid #deded8;border-radius:24px;box-shadow:0 24px 80px rgba(0,0,0,.08);padding:clamp(24px,5vw,48px)}h1{font-size:clamp(30px,5vw,48px);line-height:1.02;margin:0 0 14px;letter-spacing:-.04em}p{color:#5b5b55;line-height:1.6}.status{border-radius:14px;padding:14px 16px;background:#f3f3ef;border:1px solid #deded8;margin:20px 0}.status.complete{background:#eef8ef;border-color:#b8d9bd}.status.error{background:#fff1f1;border-color:#e4b5b5}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.field{display:grid;gap:7px;margin-bottom:16px}.field.full{grid-column:1/-1}label{font-size:13px;font-weight:750}input{width:100%;border:1px solid #cfcfc8;border-radius:12px;padding:13px 14px;font:inherit;background:#fff}input:focus{outline:3px solid rgba(20,20,20,.12);border-color:#141414}.button{width:100%;border:0;border-radius:12px;padding:14px 18px;background:#141414;color:#fff;font:inherit;font-weight:800;cursor:pointer}.button:hover{background:#2d2d2b}.steps{margin:18px 0 0;padding-left:20px;color:#5b5b55;line-height:1.8}.meta{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;overflow-wrap:anywhere;background:#f3f3ef;padding:10px 12px;border-radius:10px}.footer{font-size:12px;color:#77776f;margin-top:18px;text-align:center}@media(max-width:640px){.grid{grid-template-columns:1fr}.card{border-radius:18px}}
    </style>
</head>
<body>
<main class="shell">
    <div class="brand">VP3 Installation</div>
    <section class="card">
        <h1>Create the first administrator</h1>
        <p>This one-time page creates the first organization owner and grants platform administration when enabled in <code>config/config.php</code>.</p>

        <?php if ($message !== null): ?>
            <div class="status <?= $state === 'complete' ? 'complete' : ($state === 'error' || $errors !== [] ? 'error' : '') ?>">
                <?= $escape($message) ?>
            </div>
        <?php endif; ?>

        <?php foreach ($errors as $error): ?>
            <div class="status error"><?= $escape($error) ?></div>
        <?php endforeach; ?>

        <?php if ($state === 'config_missing'): ?>
            <ol class="steps">
                <li>Rename <code>config/config-example.php</code> to <code>config/config.php</code>.</li>
                <li>Update the marked domain, database, encryption key, and setup-key values.</li>
                <li>Import <code>database/vp3-single-install.sql</code>.</li>
                <li>Reload this page.</li>
            </ol>
        <?php elseif ($state === 'database_not_installed'): ?>
            <ol class="steps">
                <li>Open your hosting database manager or phpMyAdmin.</li>
                <li>Select the database configured in <code>config/config.php</code>.</li>
                <li>Import <code>database/vp3-single-install.sql</code>.</li>
                <li>Reload this page.</li>
            </ol>
        <?php elseif ($state === 'ready'): ?>
            <form method="post" action="" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?= $escape((string) $_SESSION['vp3_setup_csrf']) ?>">
                <div class="grid">
                    <div class="field full">
                        <label for="setup_key">Private setup key</label>
                        <input id="setup_key" name="setup_key" type="password" required autocomplete="off">
                    </div>
                    <div class="field">
                        <label for="display_name">Your name</label>
                        <input id="display_name" name="display_name" type="text" required maxlength="190" autocomplete="name">
                    </div>
                    <div class="field">
                        <label for="email">Email address</label>
                        <input id="email" name="email" type="email" required maxlength="254" autocomplete="email">
                    </div>
                    <div class="field full">
                        <label for="account_name">Organization name</label>
                        <input id="account_name" name="account_name" type="text" required maxlength="190" value="VP3" autocomplete="organization">
                    </div>
                    <div class="field">
                        <label for="password">Password</label>
                        <input id="password" name="password" type="password" required minlength="<?= (int) (($config['auth']['password_min_length'] ?? 12)) ?>" autocomplete="new-password">
                    </div>
                    <div class="field">
                        <label for="password_confirmation">Confirm password</label>
                        <input id="password_confirmation" name="password_confirmation" type="password" required minlength="<?= (int) (($config['auth']['password_min_length'] ?? 12)) ?>" autocomplete="new-password">
                    </div>
                </div>
                <button class="button" type="submit">Create first administrator</button>
            </form>
        <?php elseif ($state === 'complete' && is_array($result)): ?>
            <p>Save these public identities with your deployment records:</p>
            <p class="meta">Account: <?= $escape((string) $result['account_public_id']) ?></p>
            <p class="meta">User: <?= $escape((string) $result['user_public_id']) ?></p>
            <p class="meta">Platform operator: <?= ($result['platform_operator'] ?? false) ? 'active' : 'not granted' ?></p>
            <p><a href="<?= $escape($baseUrl) ?>">Continue to VP3</a></p>
        <?php endif; ?>
    </section>
    <div class="footer">The setup key and password are never written to the page response or deployment receipts.</div>
</main>
</body>
</html>
