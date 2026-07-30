<?php

declare(strict_types=1);

namespace Vp3\Provisioning;

use PDO;
use RuntimeException;

final class DatabaseAwareLocalPodProvisioningAdapter implements PodProvisioningAdapter
{
    private LocalPodProvisioningAdapter $inner;
    private PDO $platformDatabase;
    private string $deploymentRoot;
    private string $configurationPath;

    /** @param array<string,mixed> $configuration */
    public function __construct(array $configuration)
    {
        $this->inner = new LocalPodProvisioningAdapter($configuration);
        $dsn = trim((string) ($configuration['platform_database_dsn'] ?? getenv('DB_DSN') ?: ''));
        $username = trim((string) ($configuration['platform_database_username'] ?? getenv('DB_USERNAME') ?: ''));
        $password = (string) ($configuration['platform_database_password'] ?? getenv('DB_PASSWORD') ?: '');
        if ($dsn === '' || $username === '') {
            throw new RuntimeException('The VP3 platform database connection is required for local POD hostname resolution.');
        }
        $this->platformDatabase = new PDO($dsn, $username, $password, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        $this->deploymentRoot = $this->absolutePath((string) ($configuration['deployment_root'] ?? ''));
        $this->configurationPath = $this->relativePath((string) ($configuration['configuration_path'] ?? 'config/config.php'));
    }

    public function executeStage(string $stage, array $deployment): array
    {
        return $this->inner->executeStage($stage, $this->resolve($deployment));
    }

    public function rollbackStage(string $stage, array $deployment): array
    {
        $deployment = $this->resolve($deployment);
        if ($stage === 'configuration_written') {
            $releaseConfiguration = $this->releaseConfigurationPath($deployment);
            $sharedConfiguration = $this->sharedConfigurationPath($deployment);
            if ((is_file($releaseConfiguration) || is_link($releaseConfiguration)) && !unlink($releaseConfiguration)) {
                throw new RuntimeException('Unable to remove the POD release configuration link.');
            }
            if (is_file($sharedConfiguration) && !unlink($sharedConfiguration)) {
                throw new RuntimeException('Unable to remove the shared POD configuration.');
            }
            return ['removed' => true];
        }
        return $this->inner->rollbackStage($stage, $deployment);
    }

    public function readConfiguration(array $deployment): array
    {
        $path = $this->sharedConfigurationPath($this->resolve($deployment));
        if (!is_file($path)) {
            return [];
        }
        $configuration = (static function (string $configurationFile): mixed {
            return require $configurationFile;
        })($path);
        if (!is_array($configuration)) {
            throw new RuntimeException('The shared POD configuration must return an array.');
        }
        return $configuration;
    }

    public function buildConfiguration(array $deployment): array
    {
        return $this->inner->buildConfiguration($this->resolve($deployment));
    }

    public function writeConfiguration(array $deployment, array $configuration): array
    {
        $deployment = $this->resolve($deployment);
        $result = $this->inner->writeConfiguration($deployment, $configuration);
        $releaseConfiguration = $this->releaseConfigurationPath($deployment);
        $sharedConfiguration = $this->sharedConfigurationPath($deployment);
        $content = file_get_contents($releaseConfiguration);
        if (!is_string($content)) {
            throw new RuntimeException('Unable to read the generated POD configuration.');
        }
        $this->atomicWrite($sharedConfiguration, $content, 0640);
        if ((is_file($releaseConfiguration) || is_link($releaseConfiguration)) && !unlink($releaseConfiguration)) {
            throw new RuntimeException('Unable to replace the release configuration with a shared link.');
        }
        if (!symlink($sharedConfiguration, $releaseConfiguration)) {
            throw new RuntimeException('Unable to link the active POD release to its shared configuration.');
        }
        return $result + ['shared_configuration' => true];
    }

    /** @param array<string,mixed> $deployment @return array<string,mixed> */
    private function resolve(array $deployment): array
    {
        $domainId = (int) ($deployment['domain_registration_id'] ?? 0);
        $licenseId = (int) ($deployment['license_id'] ?? 0);
        $accountId = (int) ($deployment['account_id'] ?? 0);
        if ($domainId < 1 || $licenseId < 1 || $accountId < 1) {
            throw new RuntimeException('The POD deployment is missing its account, Domain, or license identity.');
        }

        $statement = $this->platformDatabase->prepare(
            'SELECT d.hostname domain_hostname,d.label domain_label,d.public_id domain_public_id,
                    l.public_id license_public_id,a.public_id account_public_id
             FROM domain_registrations d
             JOIN licenses l ON l.id=:license AND l.domain_registration_id=d.id AND l.account_id=d.account_id
             JOIN accounts a ON a.id=d.account_id
             WHERE d.id=:domain AND d.account_id=:account LIMIT 1'
        );
        $statement->execute(['license' => $licenseId, 'domain' => $domainId, 'account' => $accountId]);
        $identity = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($identity)) {
            throw new RuntimeException('The authoritative POD Domain and license identity could not be resolved.');
        }

        return array_replace($deployment, $identity);
    }

    /** @param array<string,mixed> $deployment */
    private function deploymentPath(array $deployment): string
    {
        $publicId = strtolower(trim((string) ($deployment['public_id'] ?? '')));
        if (!preg_match('/^pod-[a-z0-9]+$/', $publicId)) {
            throw new RuntimeException('The POD public ID is invalid for shared configuration storage.');
        }
        return rtrim($this->deploymentRoot, '/') . '/' . $publicId;
    }

    /** @param array<string,mixed> $deployment */
    private function releaseConfigurationPath(array $deployment): string
    {
        return $this->deploymentPath($deployment) . '/current/' . $this->configurationPath;
    }

    /** @param array<string,mixed> $deployment */
    private function sharedConfigurationPath(array $deployment): string
    {
        return $this->deploymentPath($deployment) . '/shared/config/' . basename($this->configurationPath);
    }

    private function absolutePath(string $path): string
    {
        $path = trim($path);
        if ($path === '' || (!str_starts_with($path, '/') && !preg_match('/^[A-Za-z]:[\\\\\/]/', $path))) {
            throw new RuntimeException('The local POD deployment root must be an absolute path.');
        }
        return rtrim(str_replace('\\', '/', $path), '/');
    }

    private function relativePath(string $path): string
    {
        $path = trim(str_replace('\\', '/', $path), '/');
        if ($path === '') {
            throw new RuntimeException('The POD configuration path cannot be empty.');
        }
        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.' || $segment === '..') {
                throw new RuntimeException('The POD configuration path is unsafe.');
            }
        }
        return $path;
    }

    private function atomicWrite(string $path, string $content, int $permissions): void
    {
        $directory = dirname($path);
        if (!is_dir($directory) && !mkdir($directory, 0750, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to create the shared POD configuration directory.');
        }
        $temporary = $path . '.tmp-' . bin2hex(random_bytes(8));
        $written = file_put_contents($temporary, $content, LOCK_EX);
        if ($written === false || $written !== strlen($content)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to write the shared POD configuration.');
        }
        chmod($temporary, $permissions);
        if (!rename($temporary, $path)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to activate the shared POD configuration.');
        }
    }
}
