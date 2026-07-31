<?php

declare(strict_types=1);

use Vp3\Database;
use Vp3\Deployment\DatabaseCommandService;
use Vp3\Deployment\DeploymentPreflightService;
use Vp3\Deployment\PlatformUpgradeService;
use Vp3\Deployment\ReleaseManifestService;

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
if ($dsn === '') {
    fwrite(STDOUT, "Phase 33 database integration skipped: VP3_TEST_DSN is not configured.\n");
    exit(0);
}

$parseDsn = static function (string $dsn): array {
    if (!str_starts_with($dsn, 'mysql:')) {
        throw new RuntimeException('The Phase 33 test requires a MySQL-compatible DSN.');
    }
    $values = [];
    foreach (explode(';', substr($dsn, 6)) as $part) {
        if ($part !== '' && str_contains($part, '=')) {
            [$key, $value] = array_map('trim', explode('=', $part, 2));
            $values[strtolower($key)] = $value;
        }
    }
    return [
        'host' => (string) ($values['host'] ?? '127.0.0.1'),
        'port' => (int) ($values['port'] ?? 3306),
        'charset' => (string) ($values['charset'] ?? 'utf8mb4'),
    ];
};
$connection = $parseDsn($dsn);
$adminDsn = sprintf(
    'mysql:host=%s;port=%d;charset=%s',
    $connection['host'],
    $connection['port'],
    $connection['charset']
);
$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
];
$admin = new PDO($adminDsn, $username, $password, $options);
$suffix = strtolower(bin2hex(random_bytes(5)));
$installDatabase = 'vp3_p33_install_' . $suffix;
$upgradeDatabase = 'vp3_p33_upgrade_' . $suffix;
$temporaryRoot = sys_get_temp_dir() . '/vp3-phase33-' . $suffix;
$backupRoot = $temporaryRoot . '/backups';
$mysqlBinary = (string) (getenv('VP3_TEST_MYSQL_BINARY') ?: '/usr/bin/mysql');
$mysqldumpBinary = (string) (getenv('VP3_TEST_MYSQLDUMP_BINARY') ?: '/usr/bin/mysqldump');

$quoteDatabase = static function (string $database): string {
    if (!preg_match('/^[a-z0-9_]+$/', $database)) {
        throw new RuntimeException('Unsafe temporary database identity.');
    }
    return '`' . $database . '`';
};
$drop = static function (PDO $admin, string $database) use ($quoteDatabase): void {
    $admin->exec('DROP DATABASE IF EXISTS ' . $quoteDatabase($database));
};
$makeConfig = static function (string $database) use ($connection, $username, $password, $options): array {
    return [
        'dsn' => sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=%s',
            $connection['host'],
            $connection['port'],
            $database,
            $connection['charset']
        ),
        'username' => $username,
        'password' => $password,
        'options' => $options,
    ];
};
$removeTree = static function (string $path) use (&$removeTree): void {
    if (!is_dir($path)) {
        if (is_file($path)) {
            @unlink($path);
        }
        return;
    }
    foreach (scandir($path) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }
        $removeTree($path . DIRECTORY_SEPARATOR . $entry);
    }
    @rmdir($path);
};

$releaseConfig = require $root . '/config/release.php';
$expectedManifest = new ReleaseManifestService($root, $releaseConfig);
$expectedMigrationCount = count($expectedManifest->migrationPaths());
$expectedReleaseVersion = (string) ($releaseConfig['version'] ?? '');
if ($expectedMigrationCount < 24 || $expectedReleaseVersion === '') {
    throw new RuntimeException('The current release identity is incomplete.');
}
$applicationConfig = static fn (array $databaseConfig): array => [
    'app' => ['env' => 'test', 'base_url' => 'https://vp3.test'],
    'database' => $databaseConfig,
];
$deploymentConfig = [
    'backup_root' => $backupRoot,
    'mysqldump_binary' => $mysqldumpBinary,
    'mysql_binary' => $mysqlBinary,
    'lock_name' => 'vp3-phase33-test-' . $suffix,
    'maximum_backup_bytes' => 536870912,
];
$serviceFor = static function (
    string $serviceRoot,
    array $databaseConfig,
    array $release,
    array $deployment
) use ($applicationConfig): array {
    $database = new Database($databaseConfig);
    $manifest = new ReleaseManifestService($serviceRoot, $release);
    $preflight = new DeploymentPreflightService(
        $serviceRoot,
        $applicationConfig($databaseConfig),
        $deployment,
        $manifest
    );
    $commands = new DatabaseCommandService(
        $databaseConfig,
        (string) $deployment['mysqldump_binary'],
        (string) $deployment['mysql_binary'],
        (string) $deployment['backup_root'],
        (int) $deployment['maximum_backup_bytes']
    );
    return [
        'database' => $database,
        'manifest' => $manifest,
        'commands' => $commands,
        'service' => new PlatformUpgradeService(
            $serviceRoot,
            $database,
            $deployment,
            $manifest,
            $preflight,
            $commands
        ),
    ];
};

try {
    @mkdir($backupRoot, 0700, true);
    foreach ([$installDatabase, $upgradeDatabase] as $database) {
        $drop($admin, $database);
        $admin->exec('CREATE DATABASE ' . $quoteDatabase($database) . ' CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
    }

    // Clean installation from the committed standalone installer.
    $installConfig = $makeConfig($installDatabase);
    $installServices = $serviceFor($root, $installConfig, $releaseConfig, $deploymentConfig);
    $installed = $installServices['service']->install('phase33-install-' . $suffix);
    if (($installed['run_status'] ?? '') !== 'completed') {
        throw new RuntimeException('Clean installation did not complete.');
    }
    $installPdo = $installServices['database']->pdo();
    $migrationCount = (int) $installPdo->query('SELECT COUNT(*) FROM platform_schema_migrations')->fetchColumn();
    if ($migrationCount !== $expectedMigrationCount) {
        throw new RuntimeException('Clean installation did not register every current migration.');
    }
    $activeRelease = (string) $installPdo->query(
        "SELECT release_version FROM platform_release_records WHERE release_status='active'"
    )->fetchColumn();
    if (!hash_equals($expectedReleaseVersion, $activeRelease)) {
        throw new RuntimeException('Clean installation did not activate the current release.');
    }
    $verifiedInstall = $installServices['service']->verify();
    if (($verifiedInstall['release']['migration_count'] ?? 0) !== $expectedMigrationCount) {
        throw new RuntimeException('Clean installation verification returned the wrong migration count.');
    }

    // Build an exact Phase 32 database without the Phase 33 migration.
    $manifestLines = file($root . '/database/single-install-manifest.txt', FILE_IGNORE_NEW_LINES);
    if (!is_array($manifestLines)) {
        throw new RuntimeException('Unable to read the migration manifest.');
    }
    $phase32Sql = "SET FOREIGN_KEY_CHECKS=0;\n";
    foreach ($manifestLines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }
        if ($line === 'migrations/20260731_phase33_production_deployment_upgrade.sql') {
            break;
        }
        $content = file_get_contents($root . '/database/' . $line);
        if (!is_string($content)) {
            throw new RuntimeException('Unable to read Phase 32 migration ' . $line . '.');
        }
        $phase32Sql .= "\n-- " . $line . "\n" . $content . "\n";
    }
    $phase32Sql .= "SET FOREIGN_KEY_CHECKS=1;\n";
    $phase32Path = $temporaryRoot . '/phase32.sql';
    @mkdir(dirname($phase32Path), 0700, true);
    file_put_contents($phase32Path, $phase32Sql, LOCK_EX);

    $upgradeConfig = $makeConfig($upgradeDatabase);
    $upgradeServices = $serviceFor($root, $upgradeConfig, $releaseConfig, $deploymentConfig);
    $upgradeServices['commands']->importSqlFile($phase32Path);
    $upgraded = $upgradeServices['service']->upgrade('phase33-upgrade-' . $suffix);
    if (($upgraded['run_status'] ?? '') !== 'completed' || ($upgraded['backup_public_id'] ?? '') === '') {
        throw new RuntimeException('Phase 32 to Phase 33 upgrade did not complete with a backup receipt.');
    }
    $upgradePdo = $upgradeServices['database']->pdo();
    if ((int) $upgradePdo->query('SELECT COUNT(*) FROM platform_schema_migrations')->fetchColumn() !== $expectedMigrationCount) {
        throw new RuntimeException('Upgrade did not reconcile all migration checksums.');
    }
    $backup = $upgradePdo->query('SELECT * FROM platform_deployment_backups LIMIT 1')->fetch();
    if (!is_array($backup) || $backup['backup_status'] !== 'verified') {
        throw new RuntimeException('Upgrade backup was not verified.');
    }
    $backupPath = $backupRoot . '/' . $backup['public_id'] . '.sql';
    if (!is_file($backupPath) || !hash_equals((string) $backup['file_sha256'], (string) hash_file('sha256', $backupPath))) {
        throw new RuntimeException('Upgrade backup file does not match its database receipt.');
    }
    $replay = $upgradeServices['service']->upgrade('phase33-upgrade-' . $suffix);
    if (($replay['public_id'] ?? '') !== ($upgraded['public_id'] ?? '')) {
        throw new RuntimeException('Exact upgrade request replay did not return the original run.');
    }

    $firstMigration = (string) $upgradePdo->query(
        'SELECT migration_path FROM platform_schema_migrations ORDER BY id ASC LIMIT 1'
    )->fetchColumn();
    $originalHash = (string) $upgradePdo->query(
        'SELECT migration_sha256 FROM platform_schema_migrations ORDER BY id ASC LIMIT 1'
    )->fetchColumn();
    $upgradePdo->prepare('UPDATE platform_schema_migrations SET migration_sha256=:sha WHERE migration_path=:path')
        ->execute(['sha' => str_repeat('0', 64), 'path' => $firstMigration]);
    try {
        $upgradeServices['service']->verify();
        throw new RuntimeException('Changed applied migration checksum was accepted.');
    } catch (RuntimeException $exception) {
        if ($exception->getMessage() !== 'platform_schema_verification_failed') {
            throw $exception;
        }
    }
    $upgradePdo->prepare('UPDATE platform_schema_migrations SET migration_sha256=:sha WHERE migration_path=:path')
        ->execute(['sha' => $originalHash, 'path' => $firstMigration]);

    // Force a partially applied invalid migration and prove automatic database restore.
    $failureRoot = $temporaryRoot . '/failure-release';
    @mkdir($failureRoot . '/database/migrations', 0700, true);
    @mkdir($failureRoot . '/workers', 0700, true);
    copy(
        $root . '/database/migrations/20260731_phase33_production_deployment_upgrade.sql',
        $failureRoot . '/database/migrations/20260731_phase33_production_deployment_upgrade.sql'
    );
    file_put_contents(
        $failureRoot . '/database/migrations/99999999_phase33_forced_failure.sql',
        "CREATE TABLE phase33_should_rollback (id INT NOT NULL);\nTHIS IS NOT VALID SQL;\n",
        LOCK_EX
    );
    copy($root . '/database/vp3-single-install.sql', $failureRoot . '/database/vp3-single-install.sql');
    file_put_contents(
        $failureRoot . '/database/single-install-manifest.txt',
        "migrations/20260731_phase33_production_deployment_upgrade.sql\n"
        . "migrations/99999999_phase33_forced_failure.sql\n",
        LOCK_EX
    );
    file_put_contents($failureRoot . '/workers/operations.php', "<?php\n", LOCK_EX);
    file_put_contents($failureRoot . '/workers/security-incidents.php', "<?php\n", LOCK_EX);
    $failureRelease = [
        'format' => 'vp3-platform-release-v1',
        'version' => '33.0.1-failure-test',
        'schema_level' => 34,
        'minimum_php' => '8.2.0',
        'supported_databases' => ['mysql' => '8.0.0', 'mariadb' => '10.11.0'],
        'migration_tail' => 'migrations/99999999_phase33_forced_failure.sql',
        'installer_path' => 'database/vp3-single-install.sql',
        'migration_manifest_path' => 'database/single-install-manifest.txt',
    ];
    $failureServices = $serviceFor($failureRoot, $upgradeConfig, $failureRelease, $deploymentConfig);
    try {
        $failureServices['service']->upgrade('phase33-failure-' . $suffix);
        throw new RuntimeException('The forced invalid migration unexpectedly succeeded.');
    } catch (RuntimeException $exception) {
        if ($exception->getMessage() === 'The forced invalid migration unexpectedly succeeded.') {
            throw $exception;
        }
    }
    $tableCheck = $upgradePdo->query(
        "SELECT COUNT(*) FROM information_schema.tables
         WHERE table_schema=DATABASE() AND table_name='phase33_should_rollback'"
    );
    if ((int) $tableCheck->fetchColumn() !== 0) {
        throw new RuntimeException('Automatic rollback left the partially created failure table behind.');
    }
    $releaseAfterRollback = (string) $upgradePdo->query(
        "SELECT release_version FROM platform_release_records WHERE release_status='active' ORDER BY id DESC LIMIT 1"
    )->fetchColumn();
    if (!hash_equals($expectedReleaseVersion, $releaseAfterRollback)) {
        throw new RuntimeException('Automatic rollback did not restore the prior active release.');
    }
    $journals = glob($backupRoot . '/PLATFORM-RUN-*.json') ?: [];
    $rolledBack = false;
    foreach ($journals as $journal) {
        $document = json_decode((string) file_get_contents($journal), true);
        if (is_array($document) && ($document['status'] ?? '') === 'rolled_back') {
            $rolledBack = true;
        }
    }
    if (!$rolledBack) {
        throw new RuntimeException('Automatic rollback did not preserve a protected rolled-back journal.');
    }

    fwrite(STDOUT, "Phase 33 production deployment database integration passed.\n");
} finally {
    foreach ([$installDatabase, $upgradeDatabase] as $database) {
        try {
            $drop($admin, $database);
        } catch (Throwable) {
        }
    }
    $removeTree($temporaryRoot);
}
