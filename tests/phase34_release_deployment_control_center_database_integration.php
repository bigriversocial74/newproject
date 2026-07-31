<?php

declare(strict_types=1);

use Vp3\Auth\PasswordPolicy;
use Vp3\Database;
use Vp3\Deployment\DatabaseCommandService;
use Vp3\Deployment\DeploymentEnvironmentFingerprintService;
use Vp3\Deployment\DeploymentHealthService;
use Vp3\Deployment\DeploymentPreflightService;
use Vp3\Deployment\InitialOwnerBootstrapService;
use Vp3\Deployment\PlatformOperatorAuthorizer;
use Vp3\Deployment\PlatformOperatorGrantService;
use Vp3\Deployment\PlatformReleaseSignatureService;
use Vp3\Deployment\PlatformUpgradeService;
use Vp3\Deployment\ReleaseCandidateRegistryService;
use Vp3\Deployment\ReleaseDeploymentControlCenterActionService;
use Vp3\Deployment\ReleaseDeploymentControlCenterQueryService;
use Vp3\Deployment\ReleaseDeploymentWorkerService;
use Vp3\Deployment\ReleaseManifestService;
use Vp3\Operations\NullOperationalNotificationAdapter;
use Vp3\Operations\OperationalAuditService;
use Vp3\Operations\OperationalIncidentService;
use Vp3\Operations\OperationalNotificationService;
use Vp3\Operations\OperationsSecretCipher;
use Vp3\Security\SecurityReauthenticationService;

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
$client = (string) (getenv('VP3_TEST_MYSQL_BINARY') ?: '/usr/bin/mysql');
$dump = (string) (getenv('VP3_TEST_MYSQLDUMP_BINARY') ?: '/usr/bin/mysqldump');
if ($dsn === '') {
    fwrite(STDOUT, "Phase 34 release deployment database integration skipped.\n");
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
$centralName = 'vp3_p34_control_' . $suffix;
$stagingName = 'vp3_p34_stage_' . $suffix;
$productionName = 'vp3_p34_prod_' . $suffix;
$temporaryRoot = sys_get_temp_dir() . '/vp3-p34-' . $suffix;
$artifactRoot = $temporaryRoot . '/artifacts';
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
$databaseConfig = static fn (string $name): array => [
    'dsn' => "mysql:host={$host};port={$port};dbname={$name};charset={$charset}",
    'username' => $user,
    'password' => $password,
    'options' => $options,
];
$import = static function (string $databaseName, string $sqlPath) use ($client, $host, $port, $user, $password): void {
    $descriptor = [
        0 => ['file', $sqlPath, 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $prior = getenv('MYSQL_PWD');
    putenv('MYSQL_PWD=' . $password);
    try {
        $process = proc_open([
            $client, '--protocol=TCP', '-h', $host, '-P', (string) $port, '-u', $user, $databaseName,
        ], $descriptor, $pipes);
        if (!is_resource($process)) throw new RuntimeException('Unable to start native database import.');
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $status = proc_close($process);
        if ($status !== 0) {
            throw new RuntimeException('Native database import failed: ' . mb_substr(trim((string) ($stderr ?: $stdout)), 0, 500));
        }
    } finally {
        $prior === false ? putenv('MYSQL_PWD') : putenv('MYSQL_PWD=' . $prior);
    }
};
$phase33Sql = static function () use ($root, $temporaryRoot): string {
    $manifest = file($root . '/database/single-install-manifest.txt', FILE_IGNORE_NEW_LINES);
    if (!is_array($manifest)) throw new RuntimeException('Unable to read migration manifest.');
    $document = "SET NAMES utf8mb4;\nSET time_zone = '+00:00';\nSET FOREIGN_KEY_CHECKS = 0;\n";
    $found = false;
    foreach ($manifest as $entry) {
        $entry = trim($entry);
        if ($entry === '' || str_starts_with($entry, '#')) continue;
        $content = file_get_contents($root . '/database/' . $entry);
        if (!is_string($content)) throw new RuntimeException('Unable to read migration ' . $entry);
        $document .= "\n-- " . $entry . "\n" . $content . "\n";
        if ($entry === 'migrations/20260731_phase33_production_deployment_upgrade.sql') {
            $found = true;
            break;
        }
    }
    if (!$found) throw new RuntimeException('Phase 33 migration was not found in the manifest.');
    $document .= "\nSET FOREIGN_KEY_CHECKS = 1;\n";
    $path = $temporaryRoot . '/phase33-baseline.sql';
    file_put_contents($path, $document, LOCK_EX);
    return $path;
};

try {
    @mkdir($artifactRoot, 0700, true);
    foreach ([$centralName, $stagingName, $productionName] as $name) {
        $admin->exec('DROP DATABASE IF EXISTS ' . $quote($name));
        $admin->exec('CREATE DATABASE ' . $quote($name) . ' CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
    }
    $import($centralName, $root . '/database/vp3-single-install.sql');
    $baseline = $phase33Sql();
    $import($stagingName, $baseline);
    $import($productionName, $baseline);

    $releaseConfig = require $root . '/config/release.php';
    $centralConfig = $databaseConfig($centralName);
    $stagingConfig = $databaseConfig($stagingName);
    $productionConfig = $databaseConfig($productionName);
    $central = new Database($centralConfig);
    $staging = new Database($stagingConfig);
    $production = new Database($productionConfig);
    $manifests = new ReleaseManifestService($root, $releaseConfig);

    $owners = new InitialOwnerBootstrapService($central, new PasswordPolicy(12));
    $owner1 = $owners->bootstrap(
        'owner1-' . $suffix . '@example.test', 'VP3 Owner One', 'VP3 Platform Operators',
        'StrongOwnerPass123', 'phase34-owner1-' . $suffix
    );
    $pdo = $central->pdo();
    $accountId = (int) $pdo->query('SELECT id FROM accounts LIMIT 1')->fetchColumn();
    $owner1Id = (int) $pdo->query('SELECT id FROM users LIMIT 1')->fetchColumn();
    $now = gmdate('Y-m-d H:i:s');
    $owner2PublicId = 'USR-' . strtoupper(bin2hex(random_bytes(12)));
    $pdo->prepare(
        "INSERT INTO users
         (public_id,email,email_normalized,password_hash,display_name,status,email_verified_at,last_login_at,created_at,updated_at)
         VALUES (:public_id,:email,:normalized,:password_hash,'VP3 Owner Two','active',:verified,NULL,:created,:updated)"
    )->execute([
        'public_id' => $owner2PublicId,
        'email' => 'owner2-' . $suffix . '@example.test',
        'normalized' => 'owner2-' . $suffix . '@example.test',
        'password_hash' => password_hash('StrongOwnerPass456', PASSWORD_DEFAULT),
        'verified' => $now,
        'created' => $now,
        'updated' => $now,
    ]);
    $owner2Id = (int) $pdo->lastInsertId();
    $pdo->prepare(
        "INSERT INTO account_users (account_id,user_id,role,status,created_at,updated_at)
         VALUES (:account_id,:user_id,'customer_owner','active',:created,:updated)"
    )->execute(['account_id' => $accountId, 'user_id' => $owner2Id, 'created' => $now, 'updated' => $now]);

    $grants = new PlatformOperatorGrantService($central);
    $grant = $grants->grant($owner1['account_public_id'], $owner1['user_public_id'], 'phase34-grant-' . $suffix);
    if (($grant['operator_status'] ?? '') !== 'active') throw new RuntimeException('Platform operator grant did not activate.');
    $grantReplay = $grants->grant($owner1['account_public_id'], $owner1['user_public_id'], 'phase34-grant-' . $suffix);
    if (($grantReplay['operator_status'] ?? '') !== 'active') throw new RuntimeException('Platform operator grant replay failed.');

    $authorizer = new PlatformOperatorAuthorizer($central);
    $authorizer->assertOperator($accountId, $owner1Id, 'customer_owner', true);
    $reauth = new SecurityReauthenticationService($central);
    $actions = new ReleaseDeploymentControlCenterActionService($central, $authorizer, $reauth);

    $keyPair = sodium_crypto_sign_keypair();
    $private = sodium_crypto_sign_secretkey($keyPair);
    $public = sodium_crypto_sign_publickey($keyPair);
    $signer = new PlatformReleaseSignatureService(base64_encode($private), base64_encode($public), 'phase34-test-ed25519');
    $manifest = $manifests->build();
    $signature = $signer->sign($manifest, $manifests);
    $directory = $artifactRoot . '/34.0.0';
    @mkdir($directory, 0700, true);
    $manifestPath = $directory . '/platform-release-manifest.json';
    $signaturePath = $directory . '/platform-release-signature.json';
    file_put_contents($manifestPath, $manifests->canonicalJson($manifest) . "\n", LOCK_EX);
    file_put_contents($signaturePath, $manifests->canonicalJson($signature) . "\n", LOCK_EX);
    $registry = new ReleaseCandidateRegistryService(
        $central, $manifests, $artifactRoot, base64_encode($public), 'phase34-test-ed25519'
    );
    $candidate = $registry->register($manifestPath, $signaturePath, $owner1Id);
    if (($candidate['source_tree_sha256'] ?? '') !== $manifest['application_source']['tree_sha256']
        || (int) ($candidate['source_file_count'] ?? 0) !== (int) $manifest['application_source']['file_count']) {
        throw new RuntimeException('Signed source-tree identity was not retained by candidate registration.');
    }

    $applicationBase = require $root . '/config/config-example.php';
    $applicationBase['app']['env'] = 'test';
    $fingerprints = new DeploymentEnvironmentFingerprintService();
    $stagingApp = $applicationBase;
    $stagingApp['app']['base_url'] = 'https://staging.vp3.test';
    $stagingApp['database'] = $stagingConfig;
    $productionApp = $applicationBase;
    $productionApp['app']['base_url'] = 'https://production.vp3.test';
    $productionApp['database'] = $productionConfig;
    $stagingFingerprint = $fingerprints->fingerprint($stagingApp, $stagingConfig, $releaseConfig, 'staging');
    $productionFingerprint = $fingerprints->fingerprint($productionApp, $productionConfig, $releaseConfig, 'production');
    $stageEnv = $actions->saveEnvironment(
        $accountId, $owner1Id, 'customer_owner', 'staging', 'VP3 Staging', 'https://staging.vp3.test',
        $stagingFingerprint, 'phase34-stage-env-' . $suffix
    );
    $prodEnv = $actions->saveEnvironment(
        $accountId, $owner1Id, 'customer_owner', 'production', 'VP3 Production', 'https://production.vp3.test',
        $productionFingerprint, 'phase34-prod-env-' . $suffix
    );

    $operationsAudit = new OperationalAuditService($central);
    $operationsCipher = new OperationsSecretCipher(base64_encode(random_bytes(32)), 'phase34-test-operations');
    $notifications = new OperationalNotificationService(
        $central, $operationsCipher, new NullOperationalNotificationAdapter(), $operationsAudit, 60
    );
    $incidents = new OperationalIncidentService($central, $operationsAudit, $notifications);

    $workerFactory = static function (
        Database $target,
        array $targetConfig,
        array $targetApp,
        string $environmentKey,
        string $backupRoot,
        string $fingerprint
    ) use ($root, $releaseConfig, $manifests, $client, $dump, $central, $incidents): ReleaseDeploymentWorkerService {
        @mkdir($backupRoot, 0700, true);
        $deployment = [
            'backup_root' => $backupRoot,
            'mysqldump_binary' => $dump,
            'mysql_binary' => $client,
            'lock_name' => 'vp3-p34-' . $environmentKey . '-' . bin2hex(random_bytes(4)),
            'maximum_backup_bytes' => 536870912,
        ];
        $preflight = new DeploymentPreflightService($root, $targetApp, $deployment, $manifests);
        $commands = new DatabaseCommandService(
            $targetConfig, $dump, $client, $backupRoot, 536870912
        );
        $upgrade = new PlatformUpgradeService($root, $target, $deployment, $manifests, $preflight, $commands);
        $health = new DeploymentHealthService($root, $target, $manifests);
        return new ReleaseDeploymentWorkerService(
            $central, $target, $manifests, $preflight, $upgrade, $health, $incidents, $fingerprint, 300
        );
    };
    $stagingWorker = $workerFactory(
        $staging, $stagingConfig, $stagingApp, 'staging', $temporaryRoot . '/stage-backups', $stagingFingerprint
    );
    $productionWorker = $workerFactory(
        $production, $productionConfig, $productionApp, 'production', $temporaryRoot . '/prod-backups', $productionFingerprint
    );

    if ($stagingWorker->processNext('staging', 'phase34-stage-worker') !== null) {
        throw new RuntimeException('Staging worker unexpectedly claimed an empty queue.');
    }
    $stagePromotion = $actions->requestStagingDeployment(
        $accountId, $owner1Id, 'customer_owner', $candidate['public_id'], $stageEnv['public_id'],
        'phase34-stage-promote-' . $suffix
    );
    $stageResult = $stagingWorker->processNext('staging', 'phase34-stage-worker');
    if (($stageResult['status'] ?? '') !== 'completed') throw new RuntimeException('Staging deployment did not complete.');

    if ($productionWorker->processNext('production', 'phase34-prod-worker') !== null) {
        throw new RuntimeException('Production worker unexpectedly claimed an empty queue.');
    }
    $window = $actions->scheduleMaintenanceWindow(
        $accountId, $owner1Id, 'customer_owner', $prodEnv['public_id'],
        gmdate('Y-m-d H:i:s', time() - 60), gmdate('Y-m-d H:i:s', time() + 3600),
        'Phase 34 certified production promotion', 'phase34-window-' . $suffix
    );
    $promotion = $actions->requestPromotion(
        $accountId, $owner1Id, 'customer_owner', $candidate['public_id'], $stageEnv['public_id'],
        $prodEnv['public_id'], $window['public_id'], null, 'phase34-production-request-' . $suffix
    );
    try {
        $actions->approvePromotion(
            $accountId, $owner1Id, 'customer_owner', $promotion['public_id'], 'not-used',
            'phase34-self-approval-' . $suffix
        );
        throw new RuntimeException('The requesting owner approved their own production promotion.');
    } catch (RuntimeException $exception) {
        if ($exception->getMessage() === 'The requesting owner approved their own production promotion.') throw $exception;
    }
    $approvalContext = ['promotion_public_id' => $promotion['public_id']];
    $approvalChallenge = $reauth->issue(
        $accountId, $owner2Id, 'platform.approve_release_promotion', $approvalContext
    );
    if (!$reauth->satisfy(
        $approvalChallenge['public_id'], $approvalChallenge['challenge'], $accountId, $owner2Id,
        'platform.approve_release_promotion', $approvalContext
    )) throw new RuntimeException('Production approval reauthentication was not satisfied.');
    $actions->approvePromotion(
        $accountId, $owner2Id, 'customer_owner', $promotion['public_id'], $approvalChallenge['public_id'],
        'phase34-production-approve-' . $suffix
    );
    $productionResult = $productionWorker->processNext('production', 'phase34-prod-worker');
    if (($productionResult['status'] ?? '') !== 'completed') throw new RuntimeException('Production promotion did not complete.');

    $completed = $pdo->prepare(
        'SELECT deployment_run_public_id,backup_public_id,promotion_status,attempt_count,lease_expires_at
         FROM platform_release_promotions WHERE public_id=:public_id LIMIT 1'
    );
    $completed->execute(['public_id' => $promotion['public_id']]);
    $completedRow = $completed->fetch(PDO::FETCH_ASSOC);
    if (!is_array($completedRow) || $completedRow['promotion_status'] !== 'completed'
        || !is_string($completedRow['deployment_run_public_id']) || !is_string($completedRow['backup_public_id'])
        || (int) $completedRow['attempt_count'] < 1 || $completedRow['lease_expires_at'] !== null) {
        throw new RuntimeException('Completed production deployment evidence is incomplete.');
    }
    $stepCount = (int) $pdo->query('SELECT COUNT(*) FROM platform_release_promotion_steps')->fetchColumn();
    if ($stepCount < 1) throw new RuntimeException('Target deployment steps were not copied to the control plane.');

    $rollbackContext = ['promotion_public_id' => $promotion['public_id']];
    $rollbackChallenge = $reauth->issue($accountId, $owner2Id, 'platform.rollback_release', $rollbackContext);
    if (!$reauth->satisfy(
        $rollbackChallenge['public_id'], $rollbackChallenge['challenge'], $accountId, $owner2Id,
        'platform.rollback_release', $rollbackContext
    )) throw new RuntimeException('Rollback reauthentication was not satisfied.');
    $actions->queueRollback(
        $accountId, $owner2Id, 'customer_owner', $promotion['public_id'], $rollbackChallenge['public_id'],
        'phase34-rollback-' . $suffix
    );
    $rollbackResult = $productionWorker->processNext('production', 'phase34-prod-worker');
    if (($rollbackResult['status'] ?? '') !== 'rolled_back') throw new RuntimeException('Production rollback did not complete.');

    $snapshot = (new ReleaseDeploymentControlCenterQueryService($central, $authorizer))
        ->snapshot($accountId, $owner1Id, 'customer_owner');
    $matching = array_values(array_filter(
        $snapshot['promotions'],
        static fn (array $row): bool => ($row['public_id'] ?? '') === $promotion['public_id']
    ));
    if (count($matching) !== 1 || ($matching[0]['event_chain_valid'] ?? false) !== true
        || ($matching[0]['promotion_status'] ?? '') !== 'rolled_back') {
        throw new RuntimeException('The account-scoped promotion history or event chain is invalid.');
    }

    $revoked = $grants->revoke($owner1['account_public_id'], $owner1['user_public_id'], 'phase34-revoke-' . $suffix);
    if (($revoked['operator_status'] ?? '') !== 'revoked') throw new RuntimeException('Platform operator revocation failed.');
    try {
        $authorizer->assertOperator($accountId, $owner1Id, 'customer_owner');
        throw new RuntimeException('A revoked platform-operator account retained release access.');
    } catch (Throwable $exception) {
        if ($exception->getMessage() === 'A revoked platform-operator account retained release access.') throw $exception;
    }

    fwrite(STDOUT, "Phase 34 platform operator, signed candidate, staging, production, rollback, lease and evidence certification passed.\n");
} finally {
    foreach ([$centralName, $stagingName, $productionName] as $name) {
        try { $admin->exec('DROP DATABASE IF EXISTS ' . $quote($name)); } catch (Throwable) {}
    }
    $remove($temporaryRoot);
}
