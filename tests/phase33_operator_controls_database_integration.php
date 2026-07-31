<?php

declare(strict_types=1);

use Vp3\Auth\PasswordPolicy;
use Vp3\Database;
use Vp3\Deployment\DatabaseCommandService;
use Vp3\Deployment\DeploymentHealthService;
use Vp3\Deployment\DeploymentPreflightService;
use Vp3\Deployment\InitialOwnerBootstrapService;
use Vp3\Deployment\PlatformReleaseSignatureService;
use Vp3\Deployment\PlatformUpgradeService;
use Vp3\Deployment\ReleaseManifestService;

$root = dirname(__DIR__);
$autoload = $root . '/vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
} else {
    spl_autoload_register(static function (string $class) use ($root): void {
        $prefix = 'Vp3\\';
        if (!str_starts_with($class, $prefix)) return;
        $path = $root . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($path)) require $path;
    });
}

$dsn = (string) (getenv('VP3_TEST_DSN') ?: '');
$user = (string) (getenv('VP3_TEST_DB_USER') ?: '');
$password = (string) (getenv('VP3_TEST_DB_PASSWORD') ?: '');
if ($dsn === '') {
    fwrite(STDOUT, "Phase 33 operator controls database integration skipped.\n");
    exit(0);
}

$parts = [];
foreach (explode(';', substr($dsn, 6)) as $part) {
    if ($part !== '' && str_contains($part, '=')) {
        [$key, $value] = explode('=', $part, 2);
        $parts[strtolower(trim($key))] = trim($value);
    }
}
$host = (string) ($parts['host'] ?? '127.0.0.1');
$port = (int) ($parts['port'] ?? 3306);
$charset = (string) ($parts['charset'] ?? 'utf8mb4');
$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
];
$admin = new PDO("mysql:host={$host};port={$port};charset={$charset}", $user, $password, $options);
$suffix = strtolower(bin2hex(random_bytes(5)));
$databaseName = 'vp3_p33_operator_' . $suffix;
$temporaryRoot = sys_get_temp_dir() . '/vp3-p33-operator-' . $suffix;
$backupRoot = $temporaryRoot . '/backups';
$quote = static fn (string $name): string => '`' . $name . '`';
$remove = static function (string $path) use (&$remove): void {
    if (is_dir($path)) {
        foreach (scandir($path) ?: [] as $entry) {
            if ($entry !== '.' && $entry !== '..') $remove($path . '/' . $entry);
        }
        @rmdir($path);
    } elseif (is_file($path)) {
        @unlink($path);
    }
};

try {
    $admin->exec('DROP DATABASE IF EXISTS ' . $quote($databaseName));
    $admin->exec('CREATE DATABASE ' . $quote($databaseName) . ' CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
    @mkdir($backupRoot, 0700, true);
    $databaseConfig = [
        'dsn' => "mysql:host={$host};port={$port};dbname={$databaseName};charset={$charset}",
        'username' => $user,
        'password' => $password,
        'options' => $options,
    ];
    $deploymentConfig = [
        'backup_root' => $backupRoot,
        'mysqldump_binary' => (string) (getenv('VP3_TEST_MYSQLDUMP_BINARY') ?: '/usr/bin/mysqldump'),
        'mysql_binary' => (string) (getenv('VP3_TEST_MYSQL_BINARY') ?: '/usr/bin/mysql'),
        'lock_name' => 'vp3-p33-operator-' . $suffix,
        'maximum_backup_bytes' => 536870912,
    ];
    $releaseConfig = require $root . '/config/release.php';
    $database = new Database($databaseConfig);
    $manifests = new ReleaseManifestService($root, $releaseConfig);
    $preflight = new DeploymentPreflightService(
        $root,
        ['app' => ['env' => 'test', 'base_url' => 'https://vp3.test'], 'database' => $databaseConfig],
        $deploymentConfig,
        $manifests
    );
    $commands = new DatabaseCommandService(
        $databaseConfig,
        $deploymentConfig['mysqldump_binary'],
        $deploymentConfig['mysql_binary'],
        $backupRoot,
        $deploymentConfig['maximum_backup_bytes']
    );
    $upgrade = new PlatformUpgradeService(
        $root,
        $database,
        $deploymentConfig,
        $manifests,
        $preflight,
        $commands
    );
    $installed = $upgrade->install('phase33-operator-install-' . $suffix);
    if (($installed['run_status'] ?? '') !== 'completed') {
        throw new RuntimeException('Operator test installation did not complete.');
    }

    $owners = new InitialOwnerBootstrapService($database, new PasswordPolicy(12));
    $owner = $owners->bootstrap(
        'founder-' . $suffix . '@example.test',
        'VP3 Founder',
        'VP3 Test Account',
        'StrongOwnerPass123',
        'phase33-owner-' . $suffix
    );
    if (($owner['replayed'] ?? true) !== false) {
        throw new RuntimeException('Initial owner bootstrap was unexpectedly replayed.');
    }
    $replay = $owners->bootstrap(
        'founder-' . $suffix . '@example.test',
        'VP3 Founder',
        'VP3 Test Account',
        'StrongOwnerPass123',
        'phase33-owner-' . $suffix
    );
    if (($replay['replayed'] ?? false) !== true
        || !hash_equals($owner['account_public_id'], $replay['account_public_id'])) {
        throw new RuntimeException('Initial owner bootstrap replay did not return the original public identity.');
    }
    try {
        $owners->bootstrap(
            'other-' . $suffix . '@example.test',
            'Other Owner',
            'Other Account',
            'StrongOwnerPass123',
            'phase33-owner-other-' . $suffix
        );
        throw new RuntimeException('A second initial owner bootstrap was accepted.');
    } catch (RuntimeException $exception) {
        if ($exception->getMessage() === 'A second initial owner bootstrap was accepted.') throw $exception;
    }
    $storedHash = (string) $database->pdo()->query('SELECT password_hash FROM users LIMIT 1')->fetchColumn();
    if (!password_verify('StrongOwnerPass123', $storedHash) || str_contains($storedHash, 'StrongOwnerPass123')) {
        throw new RuntimeException('Initial owner password was not safely hashed.');
    }

    $keyPair = sodium_crypto_sign_keypair();
    $private = sodium_crypto_sign_secretkey($keyPair);
    $public = sodium_crypto_sign_publickey($keyPair);
    $signer = new PlatformReleaseSignatureService(
        base64_encode($private),
        base64_encode($public),
        'phase33-test-ed25519'
    );
    $manifest = $manifests->build();
    $signature = $signer->sign($manifest, $manifests);
    $signer->verify($manifest, $signature, $manifests);
    $tampered = $manifest;
    $tampered['version'] = 'tampered';
    try {
        $signer->verify($tampered, $signature, $manifests);
        throw new RuntimeException('A tampered release manifest signature was accepted.');
    } catch (RuntimeException $exception) {
        if ($exception->getMessage() === 'A tampered release manifest signature was accepted.') throw $exception;
    }

    $health = new DeploymentHealthService($root, $database, $manifests);
    $report = $health->verify('phase33-health-' . $suffix);
    if (($report['ok'] ?? false) !== true || !preg_match('/^[a-f0-9]{64}$/', (string) ($report['evidence_hash'] ?? ''))) {
        throw new RuntimeException('Deployment health verification did not produce a valid success receipt.');
    }
    $healthReplay = $health->verify('phase33-health-' . $suffix);
    if (!hash_equals((string) $report['evidence_hash'], (string) $healthReplay['evidence_hash'])) {
        throw new RuntimeException('Deployment health replay changed its evidence hash.');
    }
    $receiptCount = (int) $database->pdo()->query(
        "SELECT COUNT(*) FROM platform_deployment_receipts
         WHERE action_type IN ('bootstrap_owner','platform_health_verify')"
    )->fetchColumn();
    if ($receiptCount !== 2) {
        throw new RuntimeException('Operator controls created an unexpected number of immutable receipts.');
    }

    fwrite(STDOUT, "Phase 33 owner bootstrap, release signing and deployment health passed.\n");
} finally {
    try { $admin->exec('DROP DATABASE IF EXISTS ' . $quote($databaseName)); } catch (Throwable) {}
    $remove($temporaryRoot);
}
