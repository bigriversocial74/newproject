<?php

declare(strict_types=1);

namespace Vp3\Provisioning;

use FilesystemIterator;
use PDO;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use Throwable;
use ZipArchive;

final class LocalPodProvisioningAdapter implements PodProvisioningAdapter
{
    private string $deploymentRoot;
    private string $releaseZip;
    private string $releaseVersion;
    private string $releaseSha256;
    private string $configurationPath;
    private string $entrypointPath;
    private string $baseDomain;
    private bool $wildcardTlsReady;
    private string $databaseAdminDsn;
    private string $databaseAdminUsername;
    private string $databaseAdminPassword;
    private string $databaseHost;
    private int $databasePort;
    private string $databaseCharset;
    private string $databaseNamePrefix;
    private string $databaseUserPrefix;
    private string $databaseUserHost;
    private int $maximumArchiveFiles;
    private int $maximumArchiveBytes;
    private bool $stripSingleRoot;

    /** @param array<string,mixed> $configuration */
    public function __construct(array $configuration)
    {
        $this->deploymentRoot = $this->absolutePath((string) ($configuration['deployment_root'] ?? ''), 'VP3_POD_DEPLOYMENT_ROOT');
        $this->releaseZip = $this->absolutePath((string) ($configuration['release_zip'] ?? ''), 'VP3_POD_RELEASE_ZIP');
        $this->releaseVersion = $this->safeVersion((string) ($configuration['release_version'] ?? 'development'));
        $this->releaseSha256 = strtolower(trim((string) ($configuration['release_sha256'] ?? '')));
        $this->configurationPath = $this->relativePath((string) ($configuration['configuration_path'] ?? 'config/config.php'), 'VP3_POD_CONFIGURATION_PATH');
        $this->entrypointPath = $this->relativePath((string) ($configuration['entrypoint_path'] ?? 'public/index.php'), 'VP3_POD_ENTRYPOINT_PATH');
        $this->baseDomain = $this->hostname((string) ($configuration['wildcard_base_domain'] ?? 'vp3.me'));
        $this->wildcardTlsReady = (bool) ($configuration['wildcard_tls_ready'] ?? false);
        $this->databaseAdminDsn = trim((string) ($configuration['database_admin_dsn'] ?? ''));
        $this->databaseAdminUsername = trim((string) ($configuration['database_admin_username'] ?? ''));
        $this->databaseAdminPassword = (string) ($configuration['database_admin_password'] ?? '');
        $this->databaseHost = trim((string) ($configuration['database_host'] ?? '127.0.0.1'));
        $this->databasePort = max(1, min(65535, (int) ($configuration['database_port'] ?? 3306)));
        $this->databaseCharset = strtolower(trim((string) ($configuration['database_charset'] ?? 'utf8mb4')));
        $this->databaseNamePrefix = $this->identifierPrefix((string) ($configuration['database_name_prefix'] ?? 'vp3pod_'));
        $this->databaseUserPrefix = $this->identifierPrefix((string) ($configuration['database_user_prefix'] ?? 'vp3pod_'));
        $this->databaseUserHost = trim((string) ($configuration['database_user_host'] ?? 'localhost')) ?: 'localhost';
        $this->maximumArchiveFiles = max(1, (int) ($configuration['maximum_archive_files'] ?? 20000));
        $this->maximumArchiveBytes = max(1048576, (int) ($configuration['maximum_archive_bytes'] ?? 1073741824));
        $this->stripSingleRoot = (bool) ($configuration['strip_single_root'] ?? true);

        if (!class_exists(ZipArchive::class)) {
            throw new RuntimeException('The PHP zip extension is required for local POD provisioning.');
        }
        if (!is_file($this->releaseZip) || !is_readable($this->releaseZip)) {
            throw new RuntimeException('The configured POD release ZIP is not readable.');
        }
        if ($this->releaseSha256 !== '' && !preg_match('/^[a-f0-9]{64}$/', $this->releaseSha256)) {
            throw new RuntimeException('VP3_POD_RELEASE_SHA256 must be a 64-character hexadecimal SHA-256 value.');
        }
        if ($this->databaseAdminDsn === '' || $this->databaseAdminUsername === '') {
            throw new RuntimeException('A database administration DSN and username are required for local POD provisioning.');
        }
        if (!in_array($this->databaseCharset, ['utf8mb4', 'utf8'], true)) {
            throw new RuntimeException('The POD database charset must be utf8mb4 or utf8.');
        }
    }

    public function executeStage(string $stage, array $deployment): array
    {
        $this->assertDeployment($deployment);

        return match ($stage) {
            'payment_confirmed' => ['provider_request_id' => $this->requestId($deployment, $stage)],
            'domain_registered' => $this->registerDomain($deployment),
            'hosting_allocated' => $this->allocateHosting($deployment),
            'database_created' => $this->createDatabase($deployment),
            'pod_installed' => $this->installPod($deployment),
            'owner_account_created' => $this->createOwnerBootstrap($deployment),
            'license_injected' => $this->injectLicense($deployment),
            'ssl_requested' => $this->requestWildcardCertificate($deployment),
            'installation_verified' => $this->verifyInstallation($deployment),
            'deployment_active' => $this->activateDeployment($deployment),
            default => throw new RuntimeException('Unsupported local provisioning stage: ' . $stage . '.'),
        };
    }

    public function rollbackStage(string $stage, array $deployment): array
    {
        $this->assertDeployment($deployment);

        return match ($stage) {
            'deployment_active' => $this->removeFile($this->sharedVp3Path($deployment, 'active.json')),
            'installation_verified', 'ssl_requested', 'owner_account_created', 'domain_registered', 'payment_confirmed' => [
                'provider_request_id' => $this->requestId($deployment, 'rollback:' . $stage),
                'shared_resource_preserved' => true,
            ],
            'license_injected' => $this->removeFile($this->sharedVp3Path($deployment, 'license.json')),
            'configuration_written' => $this->removeGeneratedConfiguration($deployment),
            'pod_installed' => $this->rollbackRelease($deployment),
            'database_created' => $this->dropDatabase($deployment),
            'hosting_allocated' => $this->releaseHosting($deployment),
            default => throw new RuntimeException('Unsupported local rollback stage: ' . $stage . '.'),
        };
    }

    public function readConfiguration(array $deployment): array
    {
        $path = $this->configurationFile($deployment);
        if (!is_file($path)) {
            return [];
        }

        $configuration = (static function (string $configurationFile): mixed {
            return require $configurationFile;
        })($path);

        if (!is_array($configuration)) {
            throw new RuntimeException('The existing POD configuration must return an array.');
        }

        return $configuration;
    }

    public function buildConfiguration(array $deployment): array
    {
        $state = $this->readSecretState($deployment);
        $hostname = $this->deploymentHostname($deployment);

        return [
            'app' => [
                'env' => 'production',
                'url' => 'https://' . $hostname,
                'key' => (string) $state['app_key'],
                'deployment_public_id' => (string) $deployment['public_id'],
            ],
            'database' => [
                'dsn' => sprintf(
                    'mysql:host=%s;port=%d;dbname=%s;charset=%s',
                    $this->databaseHost,
                    $this->databasePort,
                    $state['database_name'],
                    $this->databaseCharset
                ),
                'host' => $this->databaseHost,
                'port' => $this->databasePort,
                'name' => (string) $state['database_name'],
                'username' => (string) $state['database_username'],
                'password' => (string) $state['database_password'],
                'charset' => $this->databaseCharset,
            ],
            'pod' => [
                'account_id' => (int) $deployment['account_id'],
                'domain_registration_id' => (int) $deployment['domain_registration_id'],
                'license_id' => (int) $deployment['license_id'],
                'hostname' => $hostname,
                'installation_fingerprint' => (string) $deployment['installation_fingerprint'],
                'update_channel' => (string) $deployment['update_channel'],
                'storage_allowance_bytes' => (int) $deployment['storage_allowance_bytes'],
            ],
        ];
    }

    public function writeConfiguration(array $deployment, array $configuration): array
    {
        $path = $this->configurationFile($deployment);
        $this->ensureDirectory(dirname($path), 0750);
        $content = "<?php\n\ndeclare(strict_types=1);\n\nreturn " . var_export($configuration, true) . ";\n";
        $this->atomicWrite($path, $content, 0640);

        return [
            'provider_request_id' => $this->requestId($deployment, 'configuration_written'),
            'configuration_path_hash' => hash('sha256', $this->relativeDeploymentPath($deployment, $path)),
        ];
    }

    /** @param array<string,mixed> $deployment @return array<string,mixed> */
    private function registerDomain(array $deployment): array
    {
        $hostname = $this->deploymentHostname($deployment);
        return [
            'provider_request_id' => $this->requestId($deployment, 'domain_registered'),
            'hostname_hash' => hash('sha256', $hostname),
            'wildcard_route' => '*.' . $this->baseDomain,
        ];
    }

    /** @param array<string,mixed> $deployment @return array<string,mixed> */
    private function allocateHosting(array $deployment): array
    {
        $root = $this->deploymentPath($deployment);
        $this->ensureDirectory($this->deploymentRoot, 0750);
        $this->ensureDirectory($root, 0750);
        $this->ensureDirectory($root . '/releases', 0750);
        $this->ensureDirectory($root . '/shared/.vp3', 0700);
        $this->atomicWrite($root . '/shared/.vp3/deployment.json', $this->json([
            'deployment_public_id' => (string) $deployment['public_id'],
            'hostname' => $this->deploymentHostname($deployment),
            'created_at' => gmdate(DATE_ATOM),
        ]), 0600);

        return [
            'hosting_reference' => 'local:' . strtolower((string) $deployment['public_id']),
            'provider_request_id' => $this->requestId($deployment, 'hosting_allocated'),
        ];
    }

    /** @param array<string,mixed> $deployment @return array<string,mixed> */
    private function createDatabase(array $deployment): array
    {
        $this->allocateHosting($deployment);
        $existing = $this->tryReadSecretState($deployment);
        $suffix = substr(hash('sha256', (string) $deployment['public_id']), 0, 16);
        $databaseName = $this->limitedIdentifier($this->databaseNamePrefix . $suffix, 64);
        $databaseUsername = $this->limitedIdentifier($this->databaseUserPrefix . $suffix, 32);
        $databasePassword = is_array($existing) && isset($existing['database_password'])
            ? (string) $existing['database_password']
            : rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $appKey = is_array($existing) && isset($existing['app_key'])
            ? (string) $existing['app_key']
            : 'base64:' . base64_encode(random_bytes(32));

        $pdo = $this->databaseAdmin();
        $database = $this->quoteIdentifier($databaseName);
        $user = $pdo->quote($databaseUsername);
        $host = $pdo->quote($this->databaseUserHost);
        $password = $pdo->quote($databasePassword);
        $pdo->exec("CREATE DATABASE IF NOT EXISTS {$database} CHARACTER SET {$this->databaseCharset} COLLATE {$this->databaseCollation()}");
        $pdo->exec("CREATE USER IF NOT EXISTS {$user}@{$host} IDENTIFIED BY {$password}");
        $pdo->exec("ALTER USER {$user}@{$host} IDENTIFIED BY {$password}");
        $pdo->exec("GRANT ALL PRIVILEGES ON {$database}.* TO {$user}@{$host}");

        $state = [
            'database_name' => $databaseName,
            'database_username' => $databaseUsername,
            'database_password' => $databasePassword,
            'app_key' => $appKey,
            'created_at' => is_array($existing) && isset($existing['created_at']) ? $existing['created_at'] : gmdate(DATE_ATOM),
        ];
        $this->atomicWrite($this->secretStatePath($deployment), $this->json($state), 0600);

        return [
            'database_reference' => 'mysql:' . $databaseName,
            'provider_request_id' => $this->requestId($deployment, 'database_created'),
        ];
    }

    /** @param array<string,mixed> $deployment @return array<string,mixed> */
    private function installPod(array $deployment): array
    {
        $this->allocateHosting($deployment);
        $archiveHash = hash_file('sha256', $this->releaseZip);
        if (!is_string($archiveHash)) {
            throw new RuntimeException('Unable to calculate the POD release checksum.');
        }
        if ($this->releaseSha256 !== '' && !hash_equals($this->releaseSha256, strtolower($archiveHash))) {
            throw new RuntimeException('The POD release ZIP checksum does not match VP3_POD_RELEASE_SHA256.');
        }

        $releaseName = $this->releaseVersion . '-' . substr($archiveHash, 0, 12);
        $releaseDirectory = $this->deploymentPath($deployment) . '/releases/' . $releaseName;
        $releaseMarker = $releaseDirectory . '/.vp3-release.json';
        if (is_file($releaseMarker)) {
            $marker = json_decode((string) file_get_contents($releaseMarker), true);
            if (is_array($marker) && hash_equals((string) ($marker['archive_sha256'] ?? ''), $archiveHash)) {
                $this->switchCurrentRelease($deployment, $releaseDirectory);
                return [
                    'installed_version' => $this->releaseVersion,
                    'provider_request_id' => $this->requestId($deployment, 'pod_installed'),
                    'archive_sha256' => $archiveHash,
                ];
            }
            throw new RuntimeException('The target release directory already exists with a different release marker.');
        }

        $temporaryDirectory = $this->deploymentPath($deployment) . '/releases/.tmp-' . bin2hex(random_bytes(8));
        $this->ensureDirectory($temporaryDirectory, 0750);
        try {
            $this->extractArchive($this->releaseZip, $temporaryDirectory);
            if (!is_file($temporaryDirectory . '/' . $this->entrypointPath)) {
                throw new RuntimeException('The POD release does not contain the configured entrypoint.');
            }
            $this->atomicWrite($temporaryDirectory . '/.vp3-release.json', $this->json([
                'version' => $this->releaseVersion,
                'archive_sha256' => $archiveHash,
                'installed_at' => gmdate(DATE_ATOM),
            ]), 0640);
            if (!rename($temporaryDirectory, $releaseDirectory)) {
                throw new RuntimeException('Unable to activate the extracted POD release directory.');
            }
        } catch (Throwable $exception) {
            $this->removeTree($temporaryDirectory);
            throw $exception;
        }

        $this->switchCurrentRelease($deployment, $releaseDirectory);
        return [
            'installed_version' => $this->releaseVersion,
            'provider_request_id' => $this->requestId($deployment, 'pod_installed'),
            'archive_sha256' => $archiveHash,
        ];
    }

    /** @param array<string,mixed> $deployment @return array<string,mixed> */
    private function createOwnerBootstrap(array $deployment): array
    {
        $path = $this->sharedVp3Path($deployment, 'owner-bootstrap.json');
        $this->atomicWrite($path, $this->json([
            'account_id' => (int) $deployment['account_id'],
            'deployment_public_id' => (string) $deployment['public_id'],
            'domain_registration_id' => (int) $deployment['domain_registration_id'],
            'created_at' => gmdate(DATE_ATOM),
        ]), 0600);

        return ['provider_request_id' => $this->requestId($deployment, 'owner_account_created')];
    }

    /** @param array<string,mixed> $deployment @return array<string,mixed> */
    private function injectLicense(array $deployment): array
    {
        $this->atomicWrite($this->sharedVp3Path($deployment, 'license.json'), $this->json([
            'deployment_public_id' => (string) $deployment['public_id'],
            'license_id' => (int) $deployment['license_id'],
            'license_public_id' => (string) ($deployment['license_public_id'] ?? ''),
            'installation_fingerprint' => (string) $deployment['installation_fingerprint'],
            'status' => (string) $deployment['license_status'],
            'issued_at' => gmdate(DATE_ATOM),
        ]), 0600);

        return [
            'license_status' => in_array((string) $deployment['license_status'], ['active', 'grace'], true)
                ? (string) $deployment['license_status']
                : 'active',
            'provider_request_id' => $this->requestId($deployment, 'license_injected'),
        ];
    }

    /** @param array<string,mixed> $deployment @return array<string,mixed> */
    private function requestWildcardCertificate(array $deployment): array
    {
        $this->deploymentHostname($deployment);
        if (!$this->wildcardTlsReady) {
            throw new RuntimeException('The wildcard TLS route is not marked ready.');
        }

        return [
            'ssl_status' => 'active',
            'provider_request_id' => $this->requestId($deployment, 'ssl_requested'),
            'certificate_reference' => 'wildcard:*.' . $this->baseDomain,
        ];
    }

    /** @param array<string,mixed> $deployment @return array<string,mixed> */
    private function verifyInstallation(array $deployment): array
    {
        $current = $this->currentReleasePath($deployment);
        if (!is_link($current)) {
            throw new RuntimeException('The POD current release link is missing.');
        }
        if (!is_file($current . '/' . $this->entrypointPath)) {
            throw new RuntimeException('The POD entrypoint is missing from the active release.');
        }
        if (!is_file($this->configurationFile($deployment))) {
            throw new RuntimeException('The POD configuration file is missing.');
        }
        if (!is_file($this->sharedVp3Path($deployment, 'license.json'))) {
            throw new RuntimeException('The POD license file is missing.');
        }

        $state = $this->readSecretState($deployment);
        $database = new PDO(
            sprintf(
                'mysql:host=%s;port=%d;dbname=%s;charset=%s',
                $this->databaseHost,
                $this->databasePort,
                $state['database_name'],
                $this->databaseCharset
            ),
            (string) $state['database_username'],
            (string) $state['database_password'],
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]
        );
        $database->query('SELECT 1')->fetchColumn();

        return [
            'installation_fingerprint' => (string) $deployment['installation_fingerprint'],
            'backup_status' => 'pending',
            'provider_request_id' => $this->requestId($deployment, 'installation_verified'),
        ];
    }

    /** @param array<string,mixed> $deployment @return array<string,mixed> */
    private function activateDeployment(array $deployment): array
    {
        $this->verifyInstallation($deployment);
        $this->atomicWrite($this->sharedVp3Path($deployment, 'active.json'), $this->json([
            'hostname' => $this->deploymentHostname($deployment),
            'deployment_public_id' => (string) $deployment['public_id'],
            'activated_at' => gmdate(DATE_ATOM),
        ]), 0640);

        return ['provider_request_id' => $this->requestId($deployment, 'deployment_active')];
    }

    /** @param array<string,mixed> $deployment @return array<string,mixed> */
    private function removeGeneratedConfiguration(array $deployment): array
    {
        return $this->removeFile($this->configurationFile($deployment));
    }

    /** @param array<string,mixed> $deployment @return array<string,mixed> */
    private function rollbackRelease(array $deployment): array
    {
        $current = $this->currentReleasePath($deployment);
        $previousPath = $this->sharedVp3Path($deployment, 'previous-release.txt');
        if (is_link($current) || file_exists($current)) {
            unlink($current);
        }
        if (is_file($previousPath)) {
            $previous = trim((string) file_get_contents($previousPath));
            if ($previous !== '' && is_dir($previous) && $this->isWithin($previous, $this->deploymentPath($deployment) . '/releases')) {
                if (!symlink($previous, $current)) {
                    throw new RuntimeException('Unable to restore the previous POD release.');
                }
            }
            unlink($previousPath);
        }

        return ['provider_request_id' => $this->requestId($deployment, 'rollback:pod_installed')];
    }

    /** @param array<string,mixed> $deployment @return array<string,mixed> */
    private function dropDatabase(array $deployment): array
    {
        $state = $this->tryReadSecretState($deployment);
        if (!is_array($state)) {
            return ['provider_request_id' => $this->requestId($deployment, 'rollback:database_created')];
        }

        $pdo = $this->databaseAdmin();
        $databaseName = (string) ($state['database_name'] ?? '');
        $databaseUsername = (string) ($state['database_username'] ?? '');
        if (!$this->validIdentifier($databaseName) || !$this->validIdentifier($databaseUsername)) {
            throw new RuntimeException('Stored POD database identifiers are invalid.');
        }
        $pdo->exec('DROP DATABASE IF EXISTS ' . $this->quoteIdentifier($databaseName));
        $pdo->exec('DROP USER IF EXISTS ' . $pdo->quote($databaseUsername) . '@' . $pdo->quote($this->databaseUserHost));
        unlink($this->secretStatePath($deployment));

        return ['provider_request_id' => $this->requestId($deployment, 'rollback:database_created')];
    }

    /** @param array<string,mixed> $deployment @return array<string,mixed> */
    private function releaseHosting(array $deployment): array
    {
        $root = $this->deploymentPath($deployment);
        $marker = $root . '/shared/.vp3/deployment.json';
        if (is_file($marker)) {
            $data = json_decode((string) file_get_contents($marker), true);
            if (!is_array($data) || !hash_equals((string) $deployment['public_id'], (string) ($data['deployment_public_id'] ?? ''))) {
                throw new RuntimeException('The local deployment marker does not match the requested POD.');
            }
        }
        $this->removeTree($root);

        return ['provider_request_id' => $this->requestId($deployment, 'rollback:hosting_allocated')];
    }

    private function extractArchive(string $archivePath, string $destination): void
    {
        $archive = new ZipArchive();
        if ($archive->open($archivePath) !== true) {
            throw new RuntimeException('Unable to open the POD release ZIP.');
        }

        try {
            if ($archive->numFiles < 1 || $archive->numFiles > $this->maximumArchiveFiles) {
                throw new RuntimeException('The POD release ZIP contains an invalid number of files.');
            }
            $entries = [];
            $totalBytes = 0;
            for ($index = 0; $index < $archive->numFiles; $index++) {
                $stat = $archive->statIndex($index);
                if (!is_array($stat) || !isset($stat['name'])) {
                    throw new RuntimeException('Unable to inspect a POD release ZIP entry.');
                }
                $name = $this->archiveEntryName((string) $stat['name']);
                $totalBytes += max(0, (int) ($stat['size'] ?? 0));
                if ($totalBytes > $this->maximumArchiveBytes) {
                    throw new RuntimeException('The POD release ZIP exceeds the allowed extracted size.');
                }
                if ($this->zipEntryIsSymlink($archive, $index)) {
                    throw new RuntimeException('Symbolic links are not allowed inside the POD release ZIP.');
                }
                $entries[] = ['index' => $index, 'name' => $name, 'directory' => str_ends_with($name, '/')];
            }

            $root = $this->stripSingleRoot ? $this->singleArchiveRoot($entries) : null;
            foreach ($entries as $entry) {
                $relative = $entry['name'];
                if ($root !== null) {
                    if ($relative === $root . '/') {
                        continue;
                    }
                    $relative = substr($relative, strlen($root) + 1);
                }
                if ($relative === '') {
                    continue;
                }
                $target = $destination . '/' . rtrim($relative, '/');
                if (!$this->isWithin($target, $destination)) {
                    throw new RuntimeException('A POD release ZIP entry escapes the release directory.');
                }
                if ($entry['directory']) {
                    $this->ensureDirectory($target, 0750);
                    continue;
                }
                $this->ensureDirectory(dirname($target), 0750);
                $source = $archive->getStream((string) $entry['name']);
                if (!is_resource($source)) {
                    throw new RuntimeException('Unable to read a POD release ZIP entry.');
                }
                $output = fopen($target, 'xb');
                if (!is_resource($output)) {
                    fclose($source);
                    throw new RuntimeException('Unable to create an extracted POD release file.');
                }
                try {
                    if (stream_copy_to_stream($source, $output) === false) {
                        throw new RuntimeException('Unable to extract a POD release file.');
                    }
                } finally {
                    fclose($source);
                    fclose($output);
                }
                chmod($target, 0640);
            }
        } finally {
            $archive->close();
        }
    }

    /** @param list<array{index:int,name:string,directory:bool}> $entries */
    private function singleArchiveRoot(array $entries): ?string
    {
        $root = null;
        foreach ($entries as $entry) {
            $trimmed = trim($entry['name'], '/');
            if ($trimmed === '') {
                continue;
            }
            $segments = explode('/', $trimmed);
            if (count($segments) < 2 && !$entry['directory']) {
                return null;
            }
            $candidate = $segments[0];
            if ($root === null) {
                $root = $candidate;
            } elseif ($root !== $candidate) {
                return null;
            }
        }
        return $root;
    }

    private function archiveEntryName(string $name): string
    {
        $name = str_replace('\\', '/', $name);
        if ($name === '' || str_contains($name, "\0") || str_starts_with($name, '/') || preg_match('/^[A-Za-z]:\//', $name)) {
            throw new RuntimeException('The POD release ZIP contains an unsafe path.');
        }
        foreach (explode('/', trim($name, '/')) as $segment) {
            if ($segment === '..' || $segment === '.') {
                throw new RuntimeException('The POD release ZIP contains a traversal path.');
            }
        }
        return $name;
    }

    private function zipEntryIsSymlink(ZipArchive $archive, int $index): bool
    {
        $operationsSystem = 0;
        $attributes = 0;
        if (!$archive->getExternalAttributesIndex($index, $operationsSystem, $attributes)) {
            return false;
        }
        $mode = ($attributes >> 16) & 0170000;
        return $mode === 0120000;
    }

    /** @param array<string,mixed> $deployment */
    private function switchCurrentRelease(array $deployment, string $releaseDirectory): void
    {
        $current = $this->currentReleasePath($deployment);
        if (is_link($current)) {
            $previous = readlink($current);
            if (is_string($previous) && $previous !== '' && $previous !== $releaseDirectory) {
                $this->atomicWrite($this->sharedVp3Path($deployment, 'previous-release.txt'), $previous . "\n", 0600);
            }
            unlink($current);
        } elseif (file_exists($current)) {
            throw new RuntimeException('The POD current path exists but is not a symbolic link.');
        }
        if (!symlink($releaseDirectory, $current)) {
            throw new RuntimeException('Unable to point the POD current release link at the extracted release.');
        }
    }

    /** @param array<string,mixed> $deployment */
    private function configurationFile(array $deployment): string
    {
        return $this->currentReleasePath($deployment) . '/' . $this->configurationPath;
    }

    /** @param array<string,mixed> $deployment */
    private function currentReleasePath(array $deployment): string
    {
        return $this->deploymentPath($deployment) . '/current';
    }

    /** @param array<string,mixed> $deployment */
    private function sharedVp3Path(array $deployment, string $file): string
    {
        $path = $this->deploymentPath($deployment) . '/shared/.vp3/' . $this->relativePath($file, 'internal file');
        $this->ensureDirectory(dirname($path), 0700);
        return $path;
    }

    /** @param array<string,mixed> $deployment */
    private function secretStatePath(array $deployment): string
    {
        return $this->sharedVp3Path($deployment, 'database.json');
    }

    /** @param array<string,mixed> $deployment @return array<string,mixed> */
    private function readSecretState(array $deployment): array
    {
        $state = $this->tryReadSecretState($deployment);
        if (!is_array($state)) {
            throw new RuntimeException('The POD database credential state has not been created.');
        }
        foreach (['database_name', 'database_username', 'database_password', 'app_key'] as $key) {
            if (!isset($state[$key]) || !is_string($state[$key]) || $state[$key] === '') {
                throw new RuntimeException('The POD database credential state is incomplete.');
            }
        }
        return $state;
    }

    /** @param array<string,mixed> $deployment @return array<string,mixed>|null */
    private function tryReadSecretState(array $deployment): ?array
    {
        $path = $this->secretStatePath($deployment);
        if (!is_file($path)) {
            return null;
        }
        $state = json_decode((string) file_get_contents($path), true);
        return is_array($state) ? $state : null;
    }

    private function databaseAdmin(): PDO
    {
        return new PDO(
            $this->databaseAdminDsn,
            $this->databaseAdminUsername,
            $this->databaseAdminPassword,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]
        );
    }

    /** @param array<string,mixed> $deployment */
    private function deploymentPath(array $deployment): string
    {
        $segment = strtolower((string) $deployment['public_id']);
        if (!preg_match('/^pod-[a-z0-9]+$/', $segment)) {
            throw new RuntimeException('The POD public ID cannot be used as a local deployment directory.');
        }
        return rtrim($this->deploymentRoot, '/') . '/' . $segment;
    }

    /** @param array<string,mixed> $deployment */
    private function deploymentHostname(array $deployment): string
    {
        $hostname = $this->hostname((string) ($deployment['domain_hostname'] ?? ''));
        if ($hostname === $this->baseDomain || !str_ends_with($hostname, '.' . $this->baseDomain)) {
            throw new RuntimeException('The POD hostname is outside the configured wildcard base domain.');
        }
        return $hostname;
    }

    /** @param array<string,mixed> $deployment */
    private function assertDeployment(array $deployment): void
    {
        foreach (['id', 'public_id', 'account_id', 'domain_registration_id', 'license_id', 'installation_fingerprint'] as $field) {
            if (!array_key_exists($field, $deployment) || $deployment[$field] === '' || $deployment[$field] === null) {
                throw new RuntimeException('The POD deployment is missing ' . $field . '.');
            }
        }
    }

    private function absolutePath(string $path, string $label): string
    {
        $path = trim($path);
        if ($path === '' || (!str_starts_with($path, '/') && !preg_match('/^[A-Za-z]:[\\\\\/]/', $path))) {
            throw new RuntimeException($label . ' must be an absolute path.');
        }
        return rtrim(str_replace('\\', '/', $path), '/');
    }

    private function relativePath(string $path, string $label): string
    {
        $path = trim(str_replace('\\', '/', $path), '/');
        if ($path === '') {
            throw new RuntimeException($label . ' cannot be empty.');
        }
        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.' || $segment === '..') {
                throw new RuntimeException($label . ' contains an unsafe path segment.');
            }
        }
        return $path;
    }

    private function hostname(string $hostname): string
    {
        $hostname = strtolower(rtrim(trim($hostname), '.'));
        if ($hostname === '' || strlen($hostname) > 253 || !preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/', $hostname)) {
            throw new RuntimeException('The configured POD hostname is invalid.');
        }
        return $hostname;
    }

    private function safeVersion(string $version): string
    {
        $version = trim($version);
        if ($version === '' || !preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/', $version)) {
            throw new RuntimeException('VP3_POD_RELEASE_VERSION contains unsupported characters.');
        }
        return $version;
    }

    private function identifierPrefix(string $prefix): string
    {
        $prefix = strtolower(trim($prefix));
        if ($prefix === '' || !preg_match('/^[a-z][a-z0-9_]*$/', $prefix)) {
            throw new RuntimeException('POD database identifier prefixes must begin with a letter and contain only lowercase letters, digits, and underscores.');
        }
        return $prefix;
    }

    private function limitedIdentifier(string $identifier, int $maximumLength): string
    {
        $identifier = substr($identifier, 0, $maximumLength);
        if (!$this->validIdentifier($identifier)) {
            throw new RuntimeException('A generated POD database identifier is invalid.');
        }
        return $identifier;
    }

    private function validIdentifier(string $identifier): bool
    {
        return $identifier !== '' && strlen($identifier) <= 64 && preg_match('/^[a-z][a-z0-9_]*$/', $identifier) === 1;
    }

    private function quoteIdentifier(string $identifier): string
    {
        if (!$this->validIdentifier($identifier)) {
            throw new RuntimeException('Unsafe database identifier.');
        }
        return '`' . $identifier . '`';
    }

    private function databaseCollation(): string
    {
        return $this->databaseCharset === 'utf8' ? 'utf8_unicode_ci' : 'utf8mb4_unicode_ci';
    }

    private function ensureDirectory(string $path, int $permissions): void
    {
        if (is_dir($path)) {
            return;
        }
        if (!mkdir($path, $permissions, true) && !is_dir($path)) {
            throw new RuntimeException('Unable to create local POD directory.');
        }
        chmod($path, $permissions);
    }

    private function atomicWrite(string $path, string $content, int $permissions): void
    {
        $this->ensureDirectory(dirname($path), 0750);
        $temporary = $path . '.tmp-' . bin2hex(random_bytes(8));
        $written = file_put_contents($temporary, $content, LOCK_EX);
        if ($written === false || $written !== strlen($content)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to write a local POD file.');
        }
        chmod($temporary, $permissions);
        if (!rename($temporary, $path)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to atomically replace a local POD file.');
        }
    }

    /** @return array<string,mixed> */
    private function removeFile(string $path): array
    {
        if ((is_file($path) || is_link($path)) && !unlink($path)) {
            throw new RuntimeException('Unable to remove a local POD file.');
        }
        return ['removed' => true];
    }

    private function removeTree(string $path): void
    {
        if (!file_exists($path) && !is_link($path)) {
            return;
        }
        if (is_link($path) || is_file($path)) {
            if (!unlink($path)) {
                throw new RuntimeException('Unable to remove a local POD path.');
            }
            return;
        }
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $item) {
            $itemPath = $item->getPathname();
            if ($item->isLink() || $item->isFile()) {
                if (!unlink($itemPath)) {
                    throw new RuntimeException('Unable to remove a local POD file during cleanup.');
                }
            } elseif (!rmdir($itemPath)) {
                throw new RuntimeException('Unable to remove a local POD directory during cleanup.');
            }
        }
        if (!rmdir($path)) {
            throw new RuntimeException('Unable to remove the local POD deployment directory.');
        }
    }

    private function isWithin(string $path, string $root): bool
    {
        $path = str_replace('\\', '/', $path);
        $root = rtrim(str_replace('\\', '/', $root), '/');
        return $path === $root || str_starts_with($path, $root . '/');
    }

    /** @param array<string,mixed> $deployment */
    private function relativeDeploymentPath(array $deployment, string $path): string
    {
        $root = $this->deploymentPath($deployment);
        if (!$this->isWithin($path, $root)) {
            throw new RuntimeException('The path is outside the POD deployment root.');
        }
        return ltrim(substr($path, strlen($root)), '/');
    }

    /** @param array<string,mixed> $deployment */
    private function requestId(array $deployment, string $operation): string
    {
        return substr(hash('sha256', (string) $deployment['public_id'] . '|' . $operation), 0, 32);
    }

    /** @param array<string,mixed> $value */
    private function json(array $value): string
    {
        return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) . "\n";
    }
}
