<?php

declare(strict_types=1);

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

use Vp3\Database;
use Vp3\Releases\ReleaseCatalogService;
use Vp3\Releases\ReleaseManifestSigner;
use Vp3\Updates\LocalPodSoftwareUpdateAdapter;
use Vp3\Updates\SoftwareUpdateService;

$dsn = getenv('VP3_TEST_DSN') ?: '';
$adminUsername = getenv('VP3_TEST_DB_USER') ?: 'root';
$adminPassword = getenv('VP3_TEST_DB_PASSWORD') ?: '';
$databaseHost = getenv('VP3_TEST_DB_HOST') ?: '127.0.0.1';
$databasePort = max(1, (int) (getenv('VP3_TEST_DB_PORT') ?: 3306));
$dumpBinary = getenv('VP3_TEST_DUMP_BINARY') ?: '/usr/bin/mysqldump';
$mysqlBinary = getenv('VP3_TEST_MYSQL_BINARY') ?: '/usr/bin/mysql';
if ($dsn === '') {
    fwrite(STDERR, "VP3_TEST_DSN is required.\n");
    exit(1);
}
if (!class_exists(ZipArchive::class)) {
    fwrite(STDERR, "Phase 11C update certification requires ext-zip.\n");
    exit(1);
}

$database = new Database([
    'dsn' => $dsn,
    'username' => $adminUsername,
    'password' => $adminPassword,
    'options' => [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ],
]);
$pdo = $database->pdo();
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
$makeZip = static function (string $path, string $version, bool $validEntrypoint): void {
    $zip = new ZipArchive();
    if ($zip->open($path, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        throw new RuntimeException('Unable to create the Phase 11C update ZIP fixture.');
    }
    $root = 'pod-' . str_replace('.', '-', $version) . '/';
    if ($validEntrypoint) {
        $zip->addFromString($root . 'public/index.php', "<?php echo 'release-" . $version . "';\n");
    } else {
        $zip->addFromString($root . 'public/missing-index.txt', "broken-release\n");
    }
    $zip->addFromString($root . 'config/config.php', "<?php return ['placeholder' => 'must-not-replace-shared-config'];\n");
    $zip->addFromString(
        $root . 'database/migrations/001_update_probe.sql',
        "CREATE TABLE IF NOT EXISTS update_release_probe (id INT PRIMARY KEY, value_text VARCHAR(190) NOT NULL);\n"
        . "INSERT INTO update_release_probe (id,value_text) VALUES (1,'release-" . $version . "') "
        . "ON DUPLICATE KEY UPDATE value_text=VALUES(value_text);\n"
        . "UPDATE update_content_probe SET value_text='release-" . $version . "' WHERE id=1;\n"
    );
    $zip->addFromString($root . 'vp3-update.json', json_encode([
        'migrations' => ['database/migrations/001_update_probe.sql'],
    ], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT));
    $zip->close();
};

$workspace = sys_get_temp_dir() . '/vp3-phase11c-update-' . bin2hex(random_bytes(6));
$deploymentRoot = $workspace . '/pods';
$backupRoot = $workspace . '/backups';
$artifactRoot = $workspace . '/artifacts';
@mkdir($artifactRoot, 0750, true);
$token = strtolower(bin2hex(random_bytes(6)));
$tenantDatabase = 'p11cup_' . substr($token, 0, 10);
$tenantUser = 'p11cu_' . substr($token, 0, 10);
$tenantPassword = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
$podPublicId = 'POD-UPD' . strtoupper($token);
$deploymentPath = $deploymentRoot . '/' . strtolower($podPublicId);
$baselineRelease = $deploymentPath . '/releases/11.3.0-baseline';
$sharedConfig = $deploymentPath . '/shared/config/config.php';
$databaseState = $deploymentPath . '/shared/.vp3/database.json';
$accountId = 0;
$deploymentId = 0;

try {
    $pdo->exec('CREATE DATABASE `' . $tenantDatabase . '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
    $pdo->exec('CREATE USER ' . $pdo->quote($tenantUser) . '@' . $pdo->quote('%') . ' IDENTIFIED BY ' . $pdo->quote($tenantPassword));
    $pdo->exec('GRANT ALL PRIVILEGES ON `' . $tenantDatabase . '`.* TO ' . $pdo->quote($tenantUser) . '@' . $pdo->quote('%'));
    $tenant = new PDO(
        sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $databaseHost, $databasePort, $tenantDatabase),
        $tenantUser,
        $tenantPassword,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]
    );
    $tenant->exec('CREATE TABLE update_content_probe (id INT PRIMARY KEY, value_text VARCHAR(190) NOT NULL)');
    $tenant->exec("INSERT INTO update_content_probe (id,value_text) VALUES (1,'baseline-11.3.0')");

    @mkdir($baselineRelease . '/public', 0750, true);
    @mkdir($baselineRelease . '/config', 0750, true);
    @mkdir(dirname($sharedConfig), 0750, true);
    @mkdir(dirname($databaseState), 0700, true);
    file_put_contents($baselineRelease . '/public/index.php', "<?php echo 'release-11.3.0';\n", LOCK_EX);
    file_put_contents($sharedConfig, "<?php return ['app' => ['key' => 'preserved-app-key'], 'database' => ['password' => '" . addslashes($tenantPassword) . "']];\n", LOCK_EX);
    file_put_contents($databaseState, json_encode([
        'database_name' => $tenantDatabase,
        'database_username' => $tenantUser,
        'database_password' => $tenantPassword,
        'app_key' => 'preserved-app-key',
    ], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT), LOCK_EX);
    symlink($baselineRelease, $deploymentPath . '/current');
    symlink($sharedConfig, $baselineRelease . '/config/config.php');

    $now = gmdate('Y-m-d H:i:s');
    $pdo->prepare("INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at) VALUES (:public,'individual','active',:name,:created,:updated)")
        ->execute([
            'public' => 'VP3-P11C-UPD-' . strtoupper($token),
            'name' => 'Phase 11C Update Account',
            'created' => $now,
            'updated' => $now,
        ]);
    $accountId = (int) $pdo->lastInsertId();
    $planId = (int) $pdo->query("SELECT id FROM plans WHERE code='standard' LIMIT 1")->fetchColumn();
    if ($planId < 1) {
        throw new RuntimeException('Standard plan seed is missing.');
    }
    $pdo->prepare(
        "INSERT INTO subscriptions
         (public_id,account_id,plan_id,status,provider,provider_customer_id,provider_subscription_id,starts_at,current_period_starts_at,current_period_ends_at,created_at,updated_at)
         VALUES (:public,:account,:plan,'active','stripe',:customer,:external,:starts,:period_start,:period_end,:created,:updated)"
    )->execute([
        'public' => 'SUB-P11C-UPD-' . strtoupper($token),
        'account' => $accountId,
        'plan' => $planId,
        'customer' => 'cus_p11cup_' . $token,
        'external' => 'sub_p11cup_' . $token,
        'starts' => $now,
        'period_start' => $now,
        'period_end' => gmdate('Y-m-d H:i:s', time() + 2592000),
        'created' => $now,
        'updated' => $now,
    ]);
    $subscriptionId = (int) $pdo->lastInsertId();
    $label = 'phase11c-update-' . $token;
    $pdo->prepare(
        "INSERT INTO domain_registrations
         (public_id,account_id,subscription_id,label,hostname,status,routing_status,ssl_status,registered_at,created_at,updated_at)
         VALUES (:public,:account,:subscription,:label,:hostname,'active','active','active',:registered,:created,:updated)"
    )->execute([
        'public' => 'DOM-P11C-UPD-' . strtoupper($token),
        'account' => $accountId,
        'subscription' => $subscriptionId,
        'label' => $label,
        'hostname' => $label . '.vp3.me',
        'registered' => $now,
        'created' => $now,
        'updated' => $now,
    ]);
    $domainId = (int) $pdo->lastInsertId();
    $pdo->prepare(
        'INSERT INTO entitlement_bundles
         (public_id,account_id,subscription_id,domain_registration_id,plan_id,snapshot_hash,created_at,updated_at)
         VALUES (:public,:account,:subscription,:domain,:plan,:snapshot,:created,:updated)'
    )->execute([
        'public' => 'BUNDLE-P11C-UPD-' . strtoupper($token),
        'account' => $accountId,
        'subscription' => $subscriptionId,
        'domain' => $domainId,
        'plan' => $planId,
        'snapshot' => hash('sha256', 'p11c-update-bundle-' . $token),
        'created' => $now,
        'updated' => $now,
    ]);
    $bundleId = (int) $pdo->lastInsertId();
    $pdo->prepare(
        "INSERT INTO licenses
         (public_id,account_id,subscription_id,domain_registration_id,entitlement_bundle_id,product_type,status,starts_at,created_at,updated_at)
         VALUES (:public,:account,:subscription,:domain,:bundle,'pod','active',:starts,:created,:updated)"
    )->execute([
        'public' => 'LIC-P11C-UPD-' . strtoupper($token),
        'account' => $accountId,
        'subscription' => $subscriptionId,
        'domain' => $domainId,
        'bundle' => $bundleId,
        'starts' => $now,
        'created' => $now,
        'updated' => $now,
    ]);
    $licenseId = (int) $pdo->lastInsertId();
    $pdo->prepare(
        "INSERT INTO pod_deployments
         (public_id,account_id,subscription_id,domain_registration_id,license_id,status,installation_fingerprint,installed_version,update_channel,
          storage_usage_bytes,storage_allowance_bytes,last_heartbeat_at,routing_status,ssl_status,backup_status,license_status,activated_at,created_at,updated_at)
         VALUES (:public,:account,:subscription,:domain,:license,'active',:fingerprint,'11.3.0','stable',0,1073741824,UTC_TIMESTAMP(),
                 'active','active','verified','active',UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())"
    )->execute([
        'public' => $podPublicId,
        'account' => $accountId,
        'subscription' => $subscriptionId,
        'domain' => $domainId,
        'license' => $licenseId,
        'fingerprint' => hash('sha256', 'p11c-update-pod-' . $token),
    ]);
    $deploymentId = (int) $pdo->lastInsertId();

    $keypair = sodium_crypto_sign_keypair();
    $signer = new ReleaseManifestSigner(
        base64_encode(sodium_crypto_sign_secretkey($keypair)),
        base64_encode(sodium_crypto_sign_publickey($keypair)),
        'phase11c-update-test-key'
    );
    $catalog = new ReleaseCatalogService($database, $signer);
    $productId = $catalog->ensureProduct('vp3-pod', 'VP3 POD', 'pod');

    $successZip = $artifactRoot . '/pod-11.3.1.zip';
    $makeZip($successZip, '11.3.1', true);
    $successRelease = $catalog->createDraftRelease(
        $productId,
        '11.3.1',
        'stable',
        [[
            'platform' => 'php',
            'architecture' => 'any',
            'storage_reference' => $successZip,
            'sha256' => hash_file('sha256', $successZip),
            'size_bytes' => filesize($successZip),
        ]],
        [
            'minimum_current_version' => '11.3.0',
            'maximum_current_version' => '11.3.0',
            'minimum_php_version' => '8.2.0',
            'database_family' => 'any',
        ],
        100,
        false,
        'Phase 11C successful local update',
        'REQ-P11C-UPD-RELEASE-1-' . strtoupper($token)
    );
    $catalog->publishRelease($successRelease['release_id'], 'REQ-P11C-UPD-PUBLISH-1-' . strtoupper($token));

    $adapterConfiguration = [
        'deployment_root' => $deploymentRoot,
        'backup_root' => $backupRoot,
        'encryption_key_base64' => base64_encode(random_bytes(32)),
        'configuration_path' => 'config/config.php',
        'entrypoint_path' => 'public/index.php',
        'mysqldump_binary' => $dumpBinary,
        'mysql_binary' => $mysqlBinary,
        'database_host' => $databaseHost,
        'database_port' => $databasePort,
        'maximum_backup_bytes' => 104857600,
        'maximum_archive_files' => 1000,
        'maximum_archive_bytes' => 104857600,
        'platform_database_dsn' => $dsn,
        'platform_database_username' => $adminUsername,
        'platform_database_password' => $adminPassword,
    ];
    $adapter = new LocalPodSoftwareUpdateAdapter($adapterConfiguration);
    $updates = new SoftwareUpdateService($database, $adapter, 300);

    $job = $updates->enqueue(
        $accountId,
        'pod',
        $deploymentId,
        $successRelease['release_id'],
        'REQ-P11C-UPD-JOB-1-' . strtoupper($token),
        'IDEM-P11C-UPD-JOB-1-' . $token
    );
    $result = $updates->processNext('phase11c-update-worker');
    $assert(is_array($result) && ($result['status'] ?? '') === 'completed', 'The valid local POD update did not complete.');
    $assert((string) $pdo->query('SELECT installed_version FROM pod_deployments WHERE id=' . $deploymentId)->fetchColumn() === '11.3.1', 'The successful local update did not synchronize installed_version.');
    $assert(str_contains((string) file_get_contents($deploymentPath . '/current/public/index.php'), 'release-11.3.1'), 'The successful local update did not activate the new release files.');
    $activeConfig = require $deploymentPath . '/current/config/config.php';
    $assert(is_array($activeConfig) && ($activeConfig['app']['key'] ?? '') === 'preserved-app-key', 'The successful local update replaced the shared POD configuration.');
    $assert(!isset($activeConfig['placeholder']), 'A release ZIP placeholder replaced the shared POD configuration.');
    $assert((string) $tenant->query('SELECT value_text FROM update_content_probe WHERE id=1')->fetchColumn() === 'release-11.3.1', 'The successful local update migration did not update tenant data.');
    $assert((string) $tenant->query('SELECT value_text FROM update_release_probe WHERE id=1')->fetchColumn() === 'release-11.3.1', 'The successful local update migration marker is missing.');
    $assert((int) $pdo->query('SELECT pre_update_backup_verified FROM update_jobs WHERE id=' . (int) $job['job_id'])->fetchColumn() === 1, 'The successful update did not record a verified encrypted pre-update backup.');

    $brokenZip = $artifactRoot . '/pod-11.3.2-broken.zip';
    $makeZip($brokenZip, '11.3.2', false);
    $brokenRelease = $catalog->createDraftRelease(
        $productId,
        '11.3.2',
        'stable',
        [[
            'platform' => 'php',
            'architecture' => 'any',
            'storage_reference' => $brokenZip,
            'sha256' => hash_file('sha256', $brokenZip),
            'size_bytes' => filesize($brokenZip),
        ]],
        [
            'minimum_current_version' => '11.3.1',
            'maximum_current_version' => '11.3.1',
            'minimum_php_version' => '8.2.0',
            'database_family' => 'any',
        ],
        100,
        false,
        'Phase 11C broken local update for rollback proof',
        'REQ-P11C-UPD-RELEASE-2-' . strtoupper($token)
    );
    $catalog->publishRelease($brokenRelease['release_id'], 'REQ-P11C-UPD-PUBLISH-2-' . strtoupper($token));
    $brokenJob = $updates->enqueue(
        $accountId,
        'pod',
        $deploymentId,
        $brokenRelease['release_id'],
        'REQ-P11C-UPD-JOB-2-' . strtoupper($token),
        'IDEM-P11C-UPD-JOB-2-' . $token
    );
    $brokenResult = $updates->processNext('phase11c-update-worker');
    $assert(is_array($brokenResult) && ($brokenResult['status'] ?? '') === 'rolled_back', 'The broken local POD update did not trigger automatic rollback.');
    $assert((string) $pdo->query('SELECT installed_version FROM pod_deployments WHERE id=' . $deploymentId)->fetchColumn() === '11.3.1', 'Automatic rollback did not restore the prior installed_version.');
    $assert(str_contains((string) file_get_contents($deploymentPath . '/current/public/index.php'), 'release-11.3.1'), 'Automatic rollback did not restore the prior release files.');
    $assert((string) $tenant->query('SELECT value_text FROM update_content_probe WHERE id=1')->fetchColumn() === 'release-11.3.1', 'Automatic rollback did not preserve the prior tenant database state.');
    $assert(is_link($deploymentPath . '/current/config/config.php') && is_file($deploymentPath . '/current/config/config.php'), 'Automatic rollback left the shared POD configuration link broken.');
    $assert((int) $pdo->query("SELECT COUNT(*) FROM update_receipts WHERE job_id=" . (int) $brokenJob['job_id'] . " AND operation='rollback' AND result='success'")->fetchColumn() === 1, 'Automatic rollback evidence was not recorded.');

    $receiptText = (string) $pdo->query(
        "SELECT COALESCE(GROUP_CONCAT(CONCAT_WS('|',operation,COALESCE(metadata_json,''),COALESCE(receipt_hash,'')) SEPARATOR ';'),'')
         FROM update_receipts WHERE job_id IN (" . (int) $job['job_id'] . ',' . (int) $brokenJob['job_id'] . ')'
    )->fetchColumn();
    $assert(!str_contains($receiptText, $tenantPassword), 'The tenant database password leaked into update receipts.');

    try {
        $adapter->executeStage('downloading', ['target_type' => 'homeserver', 'public_id' => 'HS-PRIVATE'], ['id' => 1], ['id' => 1, 'public_id' => 'UPDATE-PRIVATE']);
        $failures[] = 'The local POD update adapter accepted a private HomeServer update.';
    } catch (RuntimeException) {
        // Expected privacy boundary.
    }
} catch (Throwable $exception) {
    $failures[] = 'Phase 11C local update lifecycle failed: ' . $exception->getMessage();
} finally {
    $removeTree($workspace);
    try {
        $pdo->exec('DROP DATABASE IF EXISTS `' . $tenantDatabase . '`');
    } catch (Throwable) {
        // Best-effort fixture cleanup.
    }
    try {
        $pdo->exec('DROP USER IF EXISTS ' . $pdo->quote($tenantUser) . '@' . $pdo->quote('%'));
    } catch (Throwable) {
        // Best-effort fixture cleanup.
    }
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 11C local update failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

echo "Phase 11C local POD update, migration, verification, and encrypted rollback drill passed.\n";
