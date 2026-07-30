<?php

declare(strict_types=1);

$root = dirname(__DIR__);
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

$getEnv = static function (string $name, string $default): string {
    $value = getenv($name);
    if (!is_string($value) || trim($value) === '') {
        return $default;
    }
    return $value;
};

$dsn = $getEnv('VP3_TEST_DSN', '');
$adminUsername = $getEnv('VP3_TEST_DB_USER', 'root');
$adminPassword = $getEnv('VP3_TEST_DB_PASSWORD', '');
$databaseHost = $getEnv('VP3_TEST_DB_HOST', '127.0.0.1');
$databasePort = max(1, (int) $getEnv('VP3_TEST_DB_PORT', '3306'));
$dumpBinary = $getEnv('VP3_TEST_DUMP_BINARY', '/usr/bin/mysqldump');
$mysqlBinary = $getEnv('VP3_TEST_MYSQL_BINARY', '/usr/bin/mysql');
$mode = strtolower(trim($getEnv('VP3_PHASE11C_BACKUP_MODE', 'full')));
if ($dsn === '') {
    fwrite(STDERR, "VP3_TEST_DSN is required.\n");
    exit(1);
}
if (!in_array($mode, ['create', 'verify', 'restore', 'full'], true)) {
    fwrite(STDERR, "VP3_PHASE11C_BACKUP_MODE must be create, verify, restore, or full.\n");
    exit(1);
}

$admin = new PDO($dsn, $adminUsername, $adminPassword, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
]);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};
$removeTree = static function (string $path) use (&$removeTree): void {
    if (!file_exists($path) && !is_link($path)) {
        return;
    }
    if (is_link($path) || is_file($path)) {
        @unlink($path);
        return;
    }
    foreach (new FilesystemIterator($path, FilesystemIterator::SKIP_DOTS) as $item) {
        $removeTree($item->getPathname());
    }
    @rmdir($path);
};

$workspace = sys_get_temp_dir() . '/vp3-phase11c-backup-' . bin2hex(random_bytes(6));
$deploymentRoot = $workspace . '/pods';
$backupRoot = $workspace . '/backups';
$publicId = 'pod-backup' . bin2hex(random_bytes(4));
$deployment = $deploymentRoot . '/' . $publicId;
$release = $deployment . '/releases/1.0.0-test';
$sharedConfig = $deployment . '/shared/config/config.php';
$statePath = $deployment . '/shared/.vp3/database.json';
$tenantDatabase = 'p11cbk_' . bin2hex(random_bytes(5));
$qualifiedTenantDatabase = '`' . str_replace('`', '``', $tenantDatabase) . '`';
$tenantUser = 'p11cu_' . bin2hex(random_bytes(5));
$tenantPassword = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');

try {
    $admin->exec('CREATE DATABASE ' . $qualifiedTenantDatabase . ' CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
    $admin->exec('CREATE USER ' . $admin->quote($tenantUser) . '@' . $admin->quote('%') . ' IDENTIFIED BY ' . $admin->quote($tenantPassword));
    $admin->exec('GRANT ALL PRIVILEGES ON ' . $qualifiedTenantDatabase . '.* TO ' . $admin->quote($tenantUser) . '@' . $admin->quote('%'));
    $tenantDefiner = $admin->quote($tenantUser) . '@' . $admin->quote('%');

    $tenant = new PDO(
        sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $databaseHost, $databasePort, $tenantDatabase),
        $tenantUser,
        $tenantPassword,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]
    );
    $tenant->exec('CREATE TABLE backup_probe (id INT PRIMARY KEY, value_text VARCHAR(190) NOT NULL)');
    $tenant->exec("INSERT INTO backup_probe (id,value_text) VALUES (1,'original-database-value')");

    @mkdir($release . '/public', 0750, true);
    @mkdir($release . '/config', 0750, true);
    @mkdir(dirname($sharedConfig), 0750, true);
    @mkdir(dirname($statePath), 0700, true);
    file_put_contents($release . '/public/index.php', "<?php echo 'original-file-value';\n", LOCK_EX);
    file_put_contents($sharedConfig, "<?php return ['database' => ['password' => '" . addslashes($tenantPassword) . "']];\n", LOCK_EX);
    file_put_contents($statePath, json_encode([
        'database_name' => $tenantDatabase,
        'database_username' => $tenantUser,
        'database_password' => $tenantPassword,
        'app_key' => 'base64:' . base64_encode(random_bytes(32)),
    ], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT), LOCK_EX);
    symlink($release, $deployment . '/current');
    symlink($sharedConfig, $release . '/config/config.php');

    $adapter = new Vp3\Backups\PortableLocalPodBackupAdapter([
        'deployment_root' => $deploymentRoot,
        'backup_root' => $backupRoot,
        'encryption_key_base64' => base64_encode(random_bytes(32)),
        'configuration_path' => 'config/config.php',
        'mysqldump_binary' => $dumpBinary,
        'mysql_binary' => $mysqlBinary,
        'database_host' => $databaseHost,
        'database_port' => $databasePort,
        'maximum_backup_bytes' => 104857600,
    ]);
    $target = ['target_type' => 'pod', 'public_id' => strtoupper($publicId), 'id' => 1, 'account_id' => 1];

    $created = $adapter->createBackup($target, 'manual');
    $reference = (string) ($created['reference'] ?? '');
    $snapshotHash = (string) ($created['snapshot_hash'] ?? '');
    $encryptedPath = $backupRoot . '/' . $reference;
    $assert(is_file($encryptedPath), 'Encrypted local POD backup file was not created.');
    $assert(preg_match('/^[a-f0-9]{64}$/', $snapshotHash) === 1, 'Encrypted local POD backup hash is invalid.');
    $encryptedBytes = (string) file_get_contents($encryptedPath);
    $assert(!str_contains($encryptedBytes, 'original-database-value'), 'Database plaintext is visible in the encrypted backup.');
    $assert(!str_contains($encryptedBytes, $tenantPassword), 'Tenant database password is visible in the encrypted backup.');

    if (in_array($mode, ['verify', 'restore', 'full'], true)) {
        $verified = $adapter->verifyBackup($target, $reference, $snapshotHash);
        $assert(($verified['verified'] ?? false) === true, 'Encrypted local POD backup verification failed.');
    }

    if (in_array($mode, ['restore', 'full'], true)) {
        file_put_contents($release . '/public/index.php', "<?php echo 'modified-file-value';\n", LOCK_EX);
        $tenant->exec("UPDATE backup_probe SET value_text='modified-database-value' WHERE id=1");
        $tenant->exec('CREATE TABLE post_backup_only (id INT PRIMARY KEY, value_text VARCHAR(190) NOT NULL)');
        $tenant->exec('CREATE VIEW post_backup_view AS SELECT id,value_text FROM post_backup_only');

        // The administrator creates the objects under binary logging, but ownership remains with the tenant.
        $admin->exec(
            'CREATE DEFINER=' . $tenantDefiner . ' TRIGGER ' . $qualifiedTenantDatabase . '.`post_backup_trigger` BEFORE INSERT ON '
            . $qualifiedTenantDatabase . '.`post_backup_only` FOR EACH ROW SET NEW.value_text=UPPER(NEW.value_text)'
        );
        $admin->exec(
            'CREATE DEFINER=' . $tenantDefiner . ' PROCEDURE ' . $qualifiedTenantDatabase
            . '.`post_backup_procedure`() SELECT COUNT(*) FROM ' . $qualifiedTenantDatabase . '.`post_backup_only`'
        );
        $admin->exec(
            'CREATE DEFINER=' . $tenantDefiner . ' EVENT ' . $qualifiedTenantDatabase
            . ".`post_backup_event` ON SCHEDULE AT CURRENT_TIMESTAMP + INTERVAL 1 DAY DO INSERT INTO "
            . $qualifiedTenantDatabase . ".`post_backup_only` (id,value_text) VALUES (2,'event')"
        );
        $tenant->exec("INSERT INTO post_backup_only (id,value_text) VALUES (1,'must-disappear-after-restore')");

        $restored = $adapter->restoreBackup($target, $reference, $snapshotHash);
        $assert(($restored['restored'] ?? false) === true, 'Encrypted local POD backup restore did not report success.');
        $assert(($restored['portable_links_verified'] ?? false) === true, 'Restored POD links were not rewritten and verified.');
        $assert(($restored['database_schema_reset'] ?? false) === true, 'Restore did not report the connection-preserving schema reset.');
        $assert(str_contains((string) file_get_contents($deployment . '/current/public/index.php'), 'original-file-value'), 'POD file content was not restored.');
        $assert((string) $tenant->query('SELECT value_text FROM backup_probe WHERE id=1')->fetchColumn() === 'original-database-value', 'Tenant database content was not restored through the existing connection.');

        $objectChecks = [
            ['TABLES', 'TABLE_SCHEMA', 'TABLE_NAME', 'post_backup_only'],
            ['TABLES', 'TABLE_SCHEMA', 'TABLE_NAME', 'post_backup_view'],
            ['TRIGGERS', 'TRIGGER_SCHEMA', 'TRIGGER_NAME', 'post_backup_trigger'],
            ['ROUTINES', 'ROUTINE_SCHEMA', 'ROUTINE_NAME', 'post_backup_procedure'],
            ['EVENTS', 'EVENT_SCHEMA', 'EVENT_NAME', 'post_backup_event'],
        ];
        foreach ($objectChecks as [$table, $schemaColumn, $nameColumn, $objectName]) {
            $statement = $admin->prepare(
                'SELECT COUNT(*) FROM information_schema.' . $table
                . ' WHERE ' . $schemaColumn . '=:database AND ' . $nameColumn . '=:name'
            );
            $statement->execute(['database' => $tenantDatabase, 'name' => $objectName]);
            $assert((int) $statement->fetchColumn() === 0, 'Complete restore left a post-snapshot database object: ' . $objectName);
        }
        $assert(is_link($deployment . '/current'), 'Restored POD current release is not a symbolic link.');
        $assert(is_link($deployment . '/current/config/config.php') && is_file($deployment . '/current/config/config.php'), 'Restored POD shared configuration link is broken.');
    }

    try {
        $adapter->createBackup(['target_type' => 'homeserver', 'public_id' => 'HS-PRIVATE'], 'manual');
        $failures[] = 'Hosted backup adapter accepted private HomeServer content.';
    } catch (RuntimeException) {
    }

    $deleted = $adapter->deleteBackup($target, $reference, $snapshotHash);
    $assert(($deleted['deleted'] ?? false) === true && !file_exists($encryptedPath), 'Encrypted local POD backup deletion failed.');
} catch (Throwable $exception) {
    $failures[] = 'Phase 11C encrypted backup ' . $mode . ' drill failed: ' . $exception->getMessage();
} finally {
    $removeTree($workspace);
    try {
        $admin->exec('DROP DATABASE IF EXISTS ' . $qualifiedTenantDatabase);
    } catch (Throwable) {
    }
    try {
        $admin->exec('DROP USER IF EXISTS ' . $admin->quote($tenantUser) . '@' . $admin->quote('%'));
    } catch (Throwable) {
    }
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 11C encrypted backup failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

echo "Phase 11C encrypted POD backup " . $mode . " drill passed.\n";
