<?php

declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix = 'Vp3\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $path = dirname(__DIR__) . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($path)) {
        require $path;
    }
});

use Vp3\Infrastructure\WildcardLocalInfrastructureAdapter;
use Vp3\Provisioning\LocalPodProvisioningAdapter;
use Vp3\Runtime\RuntimeConfigurationValidator;

$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};
$expectRuntime = static function (callable $callback, string $message) use (&$failures): void {
    try {
        $callback();
        $failures[] = $message;
    } catch (RuntimeException) {
        // Expected.
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

if (!class_exists(ZipArchive::class)) {
    fwrite(STDERR, "Phase 11C runtime certification requires ext-zip.\n");
    exit(1);
}

$workspace = sys_get_temp_dir() . '/vp3-phase11c-runtime-' . bin2hex(random_bytes(6));
$deploymentRoot = $workspace . '/pods';
$releaseZip = $workspace . '/pod-release.zip';
$unsafeZip = $workspace . '/unsafe-release.zip';
@mkdir($workspace, 0750, true);

try {
    $zip = new ZipArchive();
    if ($zip->open($releaseZip, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        throw new RuntimeException('Unable to create the valid runtime ZIP fixture.');
    }
    $zip->addFromString('pod-package/public/index.php', "<?php echo 'POD';\n");
    $zip->addFromString('pod-package/config/config.php', "<?php return ['placeholder' => true];\n");
    $zip->addFromString('pod-package/assets/app.txt', "asset\n");
    $zip->close();

    $configuration = [
        'deployment_root' => $deploymentRoot,
        'release_zip' => $releaseZip,
        'release_version' => '11.0.0-test',
        'release_sha256' => hash_file('sha256', $releaseZip),
        'configuration_path' => 'config/config.php',
        'entrypoint_path' => 'public/index.php',
        'wildcard_base_domain' => 'vp3.me',
        'wildcard_tls_ready' => true,
        'database_admin_dsn' => 'mysql:host=127.0.0.1;charset=utf8mb4',
        'database_admin_username' => 'runtime-only',
        'database_admin_password' => 'runtime-only',
        'maximum_archive_files' => 100,
        'maximum_archive_bytes' => 10485760,
        'strip_single_root' => true,
    ];
    $deployment = [
        'id' => 1,
        'public_id' => 'POD-RUNTIME123',
        'account_id' => 1,
        'domain_registration_id' => 1,
        'license_id' => 1,
        'installation_fingerprint' => hash('sha256', 'runtime'),
        'domain_hostname' => 'runtime.vp3.me',
        'update_channel' => 'stable',
        'storage_allowance_bytes' => 1048576,
        'license_status' => 'active',
        'license_public_id' => 'LIC-RUNTIME123',
    ];

    $adapter = new LocalPodProvisioningAdapter($configuration);
    $hosting = $adapter->executeStage('hosting_allocated', $deployment);
    $installed = $adapter->executeStage('pod_installed', $deployment);
    $podRoot = $deploymentRoot . '/pod-runtime123';
    $assert(($hosting['hosting_reference'] ?? '') === 'local:pod-runtime123', 'Local hosting reference was not generated.');
    $assert(($installed['installed_version'] ?? '') === '11.0.0-test', 'Release version was not recorded.');
    $assert(is_link($podRoot . '/current'), 'The current POD release is not an atomic symbolic link.');
    $assert(is_file($podRoot . '/current/public/index.php'), 'The valid ZIP was not extracted through its single root directory.');
    $assert(is_file($podRoot . '/current/assets/app.txt'), 'The valid ZIP asset was not extracted.');

    $adapter->writeConfiguration($deployment, [
        'app' => ['url' => 'https://runtime.vp3.me'],
        'database' => ['password' => 'runtime-secret'],
    ]);
    $written = require $podRoot . '/current/config/config.php';
    $assert(is_array($written) && ($written['app']['url'] ?? '') === 'https://runtime.vp3.me', 'Generated POD configuration was not written.');
    $assert(($adapter->executeStage('ssl_requested', $deployment)['ssl_status'] ?? '') === 'active', 'Wildcard TLS stage did not become active.');
    $expectRuntime(
        static fn () => $adapter->executeStage('domain_registered', array_replace($deployment, ['domain_hostname' => 'outside.example.test'])),
        'A hostname outside the configured wildcard domain was accepted.'
    );

    $checksumConfiguration = array_replace($configuration, ['release_sha256' => str_repeat('0', 64)]);
    $checksumAdapter = new LocalPodProvisioningAdapter($checksumConfiguration);
    $checksumDeployment = array_replace($deployment, ['public_id' => 'POD-CHECKSUM123']);
    $checksumAdapter->executeStage('hosting_allocated', $checksumDeployment);
    $expectRuntime(
        static fn () => $checksumAdapter->executeStage('pod_installed', $checksumDeployment),
        'A release ZIP with the wrong checksum was installed.'
    );

    $zip = new ZipArchive();
    if ($zip->open($unsafeZip, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        throw new RuntimeException('Unable to create the unsafe runtime ZIP fixture.');
    }
    $zip->addFromString('../escaped.php', "<?php echo 'unsafe';\n");
    $zip->addFromString('public/index.php', "<?php echo 'unsafe';\n");
    $zip->close();
    $unsafeAdapter = new LocalPodProvisioningAdapter(array_replace($configuration, [
        'release_zip' => $unsafeZip,
        'release_sha256' => hash_file('sha256', $unsafeZip),
        'strip_single_root' => false,
    ]));
    $unsafeDeployment = array_replace($deployment, ['public_id' => 'POD-UNSAFE123']);
    $unsafeAdapter->executeStage('hosting_allocated', $unsafeDeployment);
    $expectRuntime(
        static fn () => $unsafeAdapter->executeStage('pod_installed', $unsafeDeployment),
        'A ZIP traversal entry was accepted.'
    );
    $assert(!file_exists($deploymentRoot . '/escaped.php') && !file_exists($workspace . '/escaped.php'), 'A ZIP traversal entry escaped the release directory.');

    $wildcard = new WildcardLocalInfrastructureAdapter([
        'wildcard_base_domain' => 'vp3.me',
        'deployment_root' => $deploymentRoot,
        'wildcard_dns_ready' => true,
        'wildcard_tls_ready' => true,
    ]);
    $dns = $wildcard->upsertRecord([], 'runtime.vp3.me', 'A', '192.0.2.10');
    $certificate = $wildcard->requestCertificate([], 'runtime.vp3.me');
    $assert(($dns['shared'] ?? false) === true, 'Wildcard DNS resource was not marked shared.');
    $assert(($certificate['certificate_hostname'] ?? '') === '*.vp3.me', 'Wildcard certificate hostname is incorrect.');
    $assert(($wildcard->removeRecord([], (string) $dns['provider_reference'])['shared_wildcard_record_preserved'] ?? false) === true, 'Individual teardown removed the shared wildcard DNS record.');
    $assert(($wildcard->revokeCertificate([], (string) $certificate['provider_reference'])['shared_wildcard_certificate_preserved'] ?? false) === true, 'Individual teardown revoked the shared wildcard certificate.');

    $validator = new RuntimeConfigurationValidator();
    $testConfig = [
        'app' => ['env' => 'test', 'base_url' => 'https://vp3.test', 'session_secure' => true],
        'queue' => ['lease_seconds' => 900],
        'auth' => [
            'session_inactivity_ttl_seconds' => 300,
            'session_absolute_ttl_seconds' => 600,
            'login_attempt_limit' => 8,
            'login_attempt_window_seconds' => 900,
        ],
        'mail' => ['driver' => 'null'],
        'provisioning' => ['provider_driver' => 'local'],
        'infrastructure' => ['provider_driver' => 'wildcard-local'],
        'backups' => ['provider_driver' => 'null'],
        'releases' => ['update_provider_driver' => 'null'],
        'operations' => ['notification_driver' => 'null'],
    ];
    $validator->validate($testConfig, true);
    $invalidDriver = $testConfig;
    $invalidDriver['provisioning']['provider_driver'] = 'cpanel-secret';
    $expectRuntime(static fn () => $validator->validate($invalidDriver, true), 'An unsupported provisioning driver was accepted.');
} catch (Throwable $exception) {
    $failures[] = 'Phase 11C runtime fixture failed: ' . $exception->getMessage();
} finally {
    $removeTree($workspace);
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 11C runtime failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

echo "Phase 11C local ZIP and wildcard runtime certification passed.\n";
