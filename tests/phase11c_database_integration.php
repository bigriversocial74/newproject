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
use Vp3\Provisioning\DatabaseAwareLocalPodProvisioningAdapter;
use Vp3\Provisioning\PodProvisioningService;
use Vp3\Provisioning\ProtectedConfigurationMerger;

$dsn = getenv('VP3_TEST_DSN') ?: '';
$username = getenv('VP3_TEST_DB_USER') ?: 'root';
$password = getenv('VP3_TEST_DB_PASSWORD') ?: '';
$databaseHost = getenv('VP3_TEST_DB_HOST') ?: '127.0.0.1';
$databasePort = max(1, (int) (getenv('VP3_TEST_DB_PORT') ?: 3306));
if ($dsn === '') {
    fwrite(STDERR, "VP3_TEST_DSN is required.\n");
    exit(1);
}
if (!class_exists(ZipArchive::class)) {
    fwrite(STDERR, "Phase 11C database certification requires ext-zip.\n");
    exit(1);
}

$database = new Database([
    'dsn' => $dsn,
    'username' => $username,
    'password' => $password,
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

$workspace = sys_get_temp_dir() . '/vp3-phase11c-db-' . bin2hex(random_bytes(6));
$deploymentRoot = $workspace . '/pods';
$releaseZip = $workspace . '/pod-release.zip';
@mkdir($workspace, 0750, true);
$tenantDatabaseName = null;
$tenantUsername = null;
$tenantPassword = null;

try {
    $zip = new ZipArchive();
    if ($zip->open($releaseZip, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        throw new RuntimeException('Unable to create the Phase 11C release ZIP fixture.');
    }
    $zip->addFromString('vp3-pod/public/index.php', "<?php echo 'VP3 POD';\n");
    $zip->addFromString('vp3-pod/config/config.php', "<?php return ['placeholder' => ['must_not_survive' => true]];\n");
    $zip->addFromString('vp3-pod/assets/release.txt', "phase11c\n");
    $zip->close();

    $token = strtolower(bin2hex(random_bytes(6)));
    $now = gmdate('Y-m-d H:i:s');
    $pdo->prepare(
        'INSERT INTO accounts (public_id, account_type, status, display_name, created_at, updated_at)
         VALUES (:public_id, :type, :status, :display_name, :created_at, :updated_at)'
    )->execute([
        'public_id' => 'VP3-P11C-' . strtoupper($token),
        'type' => 'individual',
        'status' => 'active',
        'display_name' => 'Phase 11C Account',
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    $accountId = (int) $pdo->lastInsertId();
    $planId = (int) $pdo->query("SELECT id FROM plans WHERE code='standard' LIMIT 1")->fetchColumn();
    if ($planId < 1) {
        throw new RuntimeException('Standard plan seed is missing.');
    }

    $pdo->prepare(
        'INSERT INTO subscriptions
         (public_id, account_id, plan_id, status, provider, provider_customer_id, provider_subscription_id,
          starts_at, current_period_starts_at, current_period_ends_at, created_at, updated_at)
         VALUES (:public_id, :account_id, :plan_id, :status, :provider, :customer, :subscription,
                 :starts_at, :period_start, :period_end, :created_at, :updated_at)'
    )->execute([
        'public_id' => 'SUB-P11C-' . strtoupper($token),
        'account_id' => $accountId,
        'plan_id' => $planId,
        'status' => 'active',
        'provider' => 'stripe',
        'customer' => 'cus_p11c_' . $token,
        'subscription' => 'sub_p11c_' . $token,
        'starts_at' => $now,
        'period_start' => $now,
        'period_end' => gmdate('Y-m-d H:i:s', time() + 2592000),
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    $subscriptionId = (int) $pdo->lastInsertId();
    $hostname = 'phase11c-' . $token . '.vp3.me';
    $pdo->prepare(
        'INSERT INTO domain_registrations
         (public_id, account_id, subscription_id, label, hostname, status, routing_status, ssl_status,
          reserved_until, created_at, updated_at)
         VALUES (:public_id, :account_id, :subscription_id, :label, :hostname, :status, :routing, :ssl,
                 :reserved_until, :created_at, :updated_at)'
    )->execute([
        'public_id' => 'DOM-P11C-' . strtoupper($token),
        'account_id' => $accountId,
        'subscription_id' => $subscriptionId,
        'label' => 'phase11c-' . $token,
        'hostname' => $hostname,
        'status' => 'reserved',
        'routing' => 'pending',
        'ssl' => 'pending',
        'reserved_until' => gmdate('Y-m-d H:i:s', time() + 3600),
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    $domainId = (int) $pdo->lastInsertId();

    $pdo->prepare(
        'INSERT INTO entitlement_bundles
         (public_id, account_id, subscription_id, domain_registration_id, plan_id, snapshot_hash, created_at, updated_at)
         VALUES (:public_id, :account_id, :subscription_id, :domain_id, :plan_id, :snapshot_hash, :created_at, :updated_at)'
    )->execute([
        'public_id' => 'BUNDLE-P11C-' . strtoupper($token),
        'account_id' => $accountId,
        'subscription_id' => $subscriptionId,
        'domain_id' => $domainId,
        'plan_id' => $planId,
        'snapshot_hash' => hash('sha256', 'phase11c-' . $token),
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    $bundleId = (int) $pdo->lastInsertId();

    $pdo->prepare(
        'INSERT INTO licenses
         (public_id, account_id, subscription_id, domain_registration_id, entitlement_bundle_id, product_type,
          status, starts_at, created_at, updated_at)
         VALUES (:public_id, :account_id, :subscription_id, :domain_id, :bundle_id, :product_type,
                 :status, :starts_at, :created_at, :updated_at)'
    )->execute([
        'public_id' => 'LIC-P11C-' . strtoupper($token),
        'account_id' => $accountId,
        'subscription_id' => $subscriptionId,
        'domain_id' => $domainId,
        'bundle_id' => $bundleId,
        'product_type' => 'pod',
        'status' => 'active',
        'starts_at' => $now,
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    $licenseId = (int) $pdo->lastInsertId();
    foreach ([
        ['update_channel', 'string', json_encode('stable', JSON_THROW_ON_ERROR)],
        ['storage_bytes', 'integer', json_encode(1073741824, JSON_THROW_ON_ERROR)],
    ] as [$key, $type, $value]) {
        $pdo->prepare(
            'INSERT INTO license_entitlements
             (license_id, entitlement_key, value_type, value_json, source_plan_id, effective_at, created_at, updated_at)
             VALUES (:license_id, :key, :type, :value, :plan_id, :effective_at, :created_at, :updated_at)'
        )->execute([
            'license_id' => $licenseId,
            'key' => $key,
            'type' => $type,
            'value' => $value,
            'plan_id' => $planId,
            'effective_at' => $now,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
    }

    $adapter = new DatabaseAwareLocalPodProvisioningAdapter([
        'deployment_root' => $deploymentRoot,
        'release_zip' => $releaseZip,
        'release_version' => '11.0.0-integration',
        'release_sha256' => hash_file('sha256', $releaseZip),
        'configuration_path' => 'config/config.php',
        'entrypoint_path' => 'public/index.php',
        'wildcard_base_domain' => 'vp3.me',
        'wildcard_tls_ready' => true,
        'database_admin_dsn' => $dsn,
        'database_admin_username' => $username,
        'database_admin_password' => $password,
        'database_host' => $databaseHost,
        'database_port' => $databasePort,
        'database_charset' => 'utf8mb4',
        'database_name_prefix' => 'p11cdb_',
        'database_user_prefix' => 'p11cu_',
        'database_user_host' => '%',
        'maximum_archive_files' => 100,
        'maximum_archive_bytes' => 10485760,
        'strip_single_root' => true,
        'platform_database_dsn' => $dsn,
        'platform_database_username' => $username,
        'platform_database_password' => $password,
    ]);
    $service = new PodProvisioningService(
        $database,
        $adapter,
        new ProtectedConfigurationMerger(),
        ['database.password', 'app.key', 'customer'],
        300
    );

    $queued = $service->enqueue(
        $accountId,
        $domainId,
        $licenseId,
        'REQ-P11C-' . strtoupper($token),
        'IDEM-P11C-' . $token
    );
    $result = $service->processNext('phase11c-worker');
    $assert(is_array($result) && ($result['status'] ?? '') === 'completed', 'Local POD provisioning did not complete.');

    $deployment = $pdo->query('SELECT * FROM pod_deployments WHERE id=' . (int) $queued['deployment_id'])->fetch(PDO::FETCH_ASSOC);
    if (!is_array($deployment)) {
        throw new RuntimeException('The provisioned POD deployment record was not found.');
    }
    $assert($deployment['status'] === 'active', 'The local POD deployment was not activated.');
    $assert($deployment['routing_status'] === 'active' && $deployment['ssl_status'] === 'active', 'Wildcard routing or TLS did not activate.');
    $assert($deployment['installed_version'] === '11.0.0-integration', 'The installed POD release version is incorrect.');

    $podRoot = $deploymentRoot . '/' . strtolower((string) $deployment['public_id']);
    $secretPath = $podRoot . '/shared/.vp3/database.json';
    $sharedConfigPath = $podRoot . '/shared/config/config.php';
    $releaseConfigPath = $podRoot . '/current/config/config.php';
    $assert(is_file($podRoot . '/current/public/index.php'), 'The POD ZIP entrypoint was not extracted.');
    $assert(is_file($podRoot . '/current/assets/release.txt'), 'The POD ZIP asset was not extracted.');
    $assert(is_file($secretPath), 'The local tenant database credential state was not created.');
    $assert(is_file($sharedConfigPath), 'The shared POD configuration was not created.');
    $assert(is_link($releaseConfigPath), 'The active release is not linked to the shared POD configuration.');

    $state = json_decode((string) file_get_contents($secretPath), true);
    if (!is_array($state)) {
        throw new RuntimeException('The local tenant database credential state is invalid.');
    }
    $tenantDatabaseName = (string) ($state['database_name'] ?? '');
    $tenantUsername = (string) ($state['database_username'] ?? '');
    $tenantPassword = (string) ($state['database_password'] ?? '');
    $assert($tenantDatabaseName !== '' && $tenantUsername !== '' && strlen($tenantPassword) >= 32, 'The tenant database identity or password is incomplete.');

    $podConfig = require $sharedConfigPath;
    $assert(is_array($podConfig), 'The generated POD configuration does not return an array.');
    $assert(($podConfig['app']['url'] ?? '') === 'https://' . $hostname, 'The generated POD URL is incorrect.');
    $assert(($podConfig['database']['name'] ?? '') === $tenantDatabaseName, 'The generated POD database name is incorrect.');
    $assert(($podConfig['database']['username'] ?? '') === $tenantUsername, 'The generated POD database username is incorrect.');
    $assert(($podConfig['database']['password'] ?? '') === $tenantPassword, 'The generated POD database password does not match local secret state.');
    $assert(!isset($podConfig['placeholder']), 'A placeholder configuration from the release ZIP survived first provisioning.');

    $tenantPdo = new PDO(
        sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $databaseHost, $databasePort, $tenantDatabaseName),
        $tenantUsername,
        $tenantPassword,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]
    );
    $assert((int) $tenantPdo->query('SELECT 1')->fetchColumn() === 1, 'Generated tenant database credentials cannot connect.');

    $receiptText = (string) $pdo->query(
        'SELECT COALESCE(GROUP_CONCAT(CONCAT_WS(\'|\',operation,COALESCE(metadata_json,\'\'),COALESCE(external_reference_hash,\'\')) SEPARATOR \';\'),\'\')
         FROM pod_provisioning_receipts WHERE deployment_id=' . (int) $queued['deployment_id']
    )->fetchColumn();
    $deploymentText = implode('|', array_map(static fn (mixed $value): string => is_scalar($value) ? (string) $value : '', $deployment));
    $assert(!str_contains($receiptText, $tenantPassword), 'The tenant database password leaked into provisioning receipts.');
    $assert(!str_contains($deploymentText, $tenantPassword), 'The tenant database password leaked into the deployment registry.');
    $assert((int) $pdo->query('SELECT COUNT(*) FROM pod_configuration_receipts WHERE deployment_id=' . (int) $queued['deployment_id'])->fetchColumn() === 1, 'The configuration hash receipt was not recorded.');

    $rollback = $service->enqueueRollback(
        $accountId,
        (int) $queued['deployment_id'],
        'REQ-P11C-ROLLBACK-' . strtoupper($token),
        'IDEM-P11C-ROLLBACK-' . $token
    );
    $rollbackResult = $service->processNext('phase11c-rollback-worker');
    $assert(is_array($rollbackResult) && ($rollbackResult['status'] ?? '') === 'completed', 'Local POD rollback did not complete.');
    $assert(!file_exists($podRoot) && !is_link($podRoot), 'Local POD rollback did not remove the deployment directory.');
    $databaseExists = $pdo->prepare('SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=:name');
    $databaseExists->execute(['name' => $tenantDatabaseName]);
    $assert((int) $databaseExists->fetchColumn() === 0, 'Local POD rollback did not drop the tenant database.');
    $assert((int) $pdo->query('SELECT COUNT(*) FROM pod_provisioning_jobs WHERE id=' . (int) $rollback['job_id'] . " AND status='completed'")->fetchColumn() === 1, 'Rollback job status was not completed.');

    try {
        new PDO(
            sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $databaseHost, $databasePort, $tenantDatabaseName),
            $tenantUsername,
            $tenantPassword,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
        );
        $failures[] = 'The generated tenant database user remained usable after rollback.';
    } catch (PDOException) {
        // Expected.
    }
} catch (Throwable $exception) {
    $failures[] = 'Phase 11C database lifecycle failed: ' . $exception->getMessage();
} finally {
    $removeTree($workspace);
    if (is_string($tenantDatabaseName) && preg_match('/^[a-z][a-z0-9_]*$/', $tenantDatabaseName)) {
        try {
            $pdo->exec('DROP DATABASE IF EXISTS `' . $tenantDatabaseName . '`');
        } catch (Throwable) {
            // Best-effort fixture cleanup.
        }
    }
    if (is_string($tenantUsername) && preg_match('/^[a-z][a-z0-9_]*$/', $tenantUsername)) {
        try {
            $pdo->exec('DROP USER IF EXISTS ' . $pdo->quote($tenantUsername) . '@' . $pdo->quote('%'));
        } catch (Throwable) {
            // Best-effort fixture cleanup.
        }
    }
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 11C database failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

echo "Phase 11C ZIP, tenant database, config, verification, and rollback certification passed.\n";
