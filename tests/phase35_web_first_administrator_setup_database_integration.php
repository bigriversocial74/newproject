<?php

declare(strict_types=1);

use Vp3\Auth\PasswordPolicy;
use Vp3\Database;
use Vp3\Deployment\InitialOwnerBootstrapService;
use Vp3\Deployment\PlatformOperatorGrantService;
use Vp3\Deployment\WebInitialSetupService;

$root = dirname(__DIR__);
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

$dsn = (string) (getenv('VP3_TEST_DSN') ?: '');
$username = (string) (getenv('VP3_TEST_DB_USER') ?: '');
$password = (string) (getenv('VP3_TEST_DB_PASSWORD') ?: '');
$mysqlBinary = (string) (getenv('VP3_TEST_MYSQL_BINARY') ?: '/usr/bin/mysql');
if (!str_starts_with($dsn, 'mysql:') || $username === '' || !is_file($mysqlBinary)) {
    fwrite(STDERR, "Phase 35 web setup database test requires VP3_TEST_DSN, VP3_TEST_DB_USER and VP3_TEST_MYSQL_BINARY.\n");
    exit(1);
}

$parts = [];
foreach (explode(';', substr($dsn, strlen('mysql:'))) as $part) {
    if (!str_contains($part, '=')) {
        continue;
    }
    [$key, $value] = explode('=', $part, 2);
    $parts[strtolower(trim($key))] = trim($value);
}
$host = $parts['host'] ?? '127.0.0.1';
$port = (int) ($parts['port'] ?? 3306);
$tempDatabase = 'vp3_websetup_' . strtolower(bin2hex(random_bytes(6)));
$serverDsn = 'mysql:host=' . $host . ';port=' . $port . ';charset=utf8mb4';
$admin = new PDO($serverDsn, $username, $password, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_EMULATE_PREPARES => false,
]);
$admin->exec('CREATE DATABASE `' . $tempDatabase . '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');

$run = static function (string $command, string $databasePassword): void {
    $descriptor = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $environment = array_merge($_SERVER, $_ENV, ['MYSQL_PWD' => $databasePassword]);
    $process = proc_open($command, $descriptor, $pipes, null, $environment);
    if (!is_resource($process)) {
        throw new RuntimeException('Unable to start the database client.');
    }
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exit = proc_close($process);
    if ($exit !== 0) {
        throw new RuntimeException('Database client failed: ' . trim((string) $stderr . (string) $stdout));
    }
};

try {
    $command = implode(' ', [
        escapeshellarg($mysqlBinary),
        '-h', escapeshellarg($host),
        '-P', escapeshellarg((string) $port),
        '-u', escapeshellarg($username),
        escapeshellarg($tempDatabase),
        '<', escapeshellarg($root . '/database/vp3-single-install.sql'),
    ]);
    $run($command, $password);

    $database = new Database([
        'dsn' => 'mysql:host=' . $host . ';port=' . $port . ';dbname=' . $tempDatabase . ';charset=utf8mb4',
        'username' => $username,
        'password' => $password,
        'options' => [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ],
    ]);
    $service = new WebInitialSetupService(
        $database,
        new InitialOwnerBootstrapService($database, new PasswordPolicy(12)),
        new PlatformOperatorGrantService($database)
    );

    $ownerPassword = 'Correct-Horse-Battery-Staple-35!';
    $requestId = 'web-setup-certification-35';
    $result = $service->createFirstAdministrator(
        'founder@example.test',
        'Founder',
        'VP3 Test Organization',
        $ownerPassword,
        $requestId,
        true
    );

    if (($result['platform_operator'] ?? false) !== true) {
        throw new RuntimeException('The first owner did not receive platform-operator authority.');
    }
    $pdo = $database->pdo();
    if ((int) $pdo->query('SELECT COUNT(*) FROM accounts')->fetchColumn() !== 1
        || (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn() !== 1
        || (int) $pdo->query("SELECT COUNT(*) FROM account_users WHERE role='customer_owner' AND status='active'")->fetchColumn() !== 1
        || (int) $pdo->query("SELECT COUNT(*) FROM platform_operator_accounts WHERE operator_status='active'")->fetchColumn() !== 1) {
        throw new RuntimeException('The first-administrator identities were not created exactly once.');
    }

    $hash = (string) $pdo->query("SELECT password_hash FROM users WHERE email_normalized='founder@example.test' LIMIT 1")->fetchColumn();
    if (!password_verify($ownerPassword, $hash) || str_contains($hash, $ownerPassword)) {
        throw new RuntimeException('The first administrator password was not stored safely.');
    }

    $replay = $service->createFirstAdministrator(
        'founder@example.test',
        'Founder',
        'VP3 Test Organization',
        $ownerPassword,
        $requestId,
        true
    );
    if (($replay['account_public_id'] ?? null) !== ($result['account_public_id'] ?? null)
        || ($replay['user_public_id'] ?? null) !== ($result['user_public_id'] ?? null)
        || ($replay['replayed'] ?? false) !== true) {
        throw new RuntimeException('Exact first-administrator request replay was not stable.');
    }

    $secondRejected = false;
    try {
        $service->createFirstAdministrator(
            'other@example.test',
            'Other Owner',
            'Other Organization',
            'Another-Strong-Password-35!',
            'web-setup-second-request-35',
            true
        );
    } catch (Throwable) {
        $secondRejected = true;
    }
    if (!$secondRejected) {
        throw new RuntimeException('A second first-administrator setup was not rejected.');
    }

    fwrite(STDOUT, "Phase 35 browser first-administrator database certification passed.\n");
} finally {
    $admin->exec('DROP DATABASE IF EXISTS `' . $tempDatabase . '`');
}
