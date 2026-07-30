<?php

declare(strict_types=1);

namespace Vp3\Runtime;

use RuntimeException;
use Vp3\Auth\Mail\SmtpMailAdapter;
use Vp3\Backups\BackupProviderAdapter;
use Vp3\Backups\NullBackupProviderAdapter;
use Vp3\Backups\PortableLocalPodBackupAdapter;
use Vp3\Infrastructure\CertificateProviderAdapter;
use Vp3\Infrastructure\DnsProviderAdapter;
use Vp3\Infrastructure\HostingProviderAdapter;
use Vp3\Infrastructure\NullInfrastructureProviderAdapter;
use Vp3\Infrastructure\WildcardLocalInfrastructureAdapter;
use Vp3\Operations\NullOperationalNotificationAdapter;
use Vp3\Operations\OperationalNotificationAdapter;
use Vp3\Operations\SmtpOperationalNotificationAdapter;
use Vp3\Provisioning\DatabaseAwareLocalPodProvisioningAdapter;
use Vp3\Provisioning\NullPodProvisioningAdapter;
use Vp3\Provisioning\PodProvisioningAdapter;
use Vp3\Updates\LocalPodSoftwareUpdateAdapter;
use Vp3\Updates\NullSoftwareUpdateAdapter;
use Vp3\Updates\SoftwareUpdateAdapter;

final class AdapterFactory
{
    /** @param array<string,mixed> $configuration */
    public static function provisioning(string $driver, string $environment, array $configuration = []): PodProvisioningAdapter
    {
        $driver = self::driver($driver);
        if ($driver === 'local') {
            return new DatabaseAwareLocalPodProvisioningAdapter(
                $configuration === [] ? self::localProvisioningConfiguration() : $configuration
            );
        }
        self::assertNullAllowed($driver, $environment, 'POD provisioning');
        return new NullPodProvisioningAdapter();
    }

    /** @param array<string,mixed> $configuration */
    public static function updates(string $driver, string $environment, array $configuration = []): SoftwareUpdateAdapter
    {
        $driver = self::driver($driver);
        if ($driver === 'local-pod') {
            return new LocalPodSoftwareUpdateAdapter(
                $configuration === [] ? self::localUpdateConfiguration() : $configuration
            );
        }
        self::assertNullAllowed($driver, $environment, 'software update');
        return new NullSoftwareUpdateAdapter();
    }

    /** @param array<string,mixed> $configuration */
    public static function backups(string $driver, string $environment, array $configuration = []): BackupProviderAdapter
    {
        $driver = self::driver($driver);
        if ($driver === 'local-pod') {
            return new PortableLocalPodBackupAdapter(
                $configuration === [] ? self::localBackupConfiguration() : $configuration
            );
        }
        self::assertNullAllowed($driver, $environment, 'backup');
        return new NullBackupProviderAdapter();
    }

    /** @param array<string,mixed> $configuration @return array{hosting:HostingProviderAdapter,dns:DnsProviderAdapter,certificate:CertificateProviderAdapter} */
    public static function infrastructure(string $driver, string $environment, array $configuration = []): array
    {
        $driver = self::driver($driver);
        if ($driver === 'wildcard-local') {
            $adapter = new WildcardLocalInfrastructureAdapter(
                $configuration === [] ? self::wildcardInfrastructureConfiguration() : $configuration
            );
            return ['hosting' => $adapter, 'dns' => $adapter, 'certificate' => $adapter];
        }
        self::assertNullAllowed($driver, $environment, 'infrastructure');
        $adapter = new NullInfrastructureProviderAdapter();
        return ['hosting' => $adapter, 'dns' => $adapter, 'certificate' => $adapter];
    }

    public static function notifications(string $driver, string $environment): OperationalNotificationAdapter
    {
        $driver = self::driver($driver);
        if ($driver === 'smtp') {
            return new SmtpOperationalNotificationAdapter(new SmtpMailAdapter(
                (string) (getenv('SMTP_HOST') ?: ''),
                max(1, (int) (getenv('SMTP_PORT') ?: 587)),
                strtolower((string) (getenv('SMTP_ENCRYPTION') ?: 'tls')),
                (string) (getenv('SMTP_USERNAME') ?: ''),
                (string) (getenv('SMTP_PASSWORD') ?: ''),
                (string) (getenv('MAIL_SENDER_EMAIL') ?: 'no-reply@vp3.me'),
                (string) (getenv('MAIL_SENDER_NAME') ?: 'VP3.me')
            ));
        }
        self::assertNullAllowed($driver, $environment, 'operational notification');
        return new NullOperationalNotificationAdapter();
    }

    private static function assertNullAllowed(string $driver, string $environment, string $label): void
    {
        $driver = self::driver($driver);
        $environment = strtolower(trim($environment));
        if ($driver !== 'null') {
            throw new RuntimeException('Unsupported ' . $label . ' driver: ' . ($driver === '' ? '(empty)' : $driver) . '.');
        }
        if ($environment === 'production') {
            throw new RuntimeException('The null ' . $label . ' adapter is forbidden in production.');
        }
    }

    private static function driver(string $driver): string
    {
        return strtolower(trim($driver));
    }

    /** @return array<string,mixed> */
    private static function localProvisioningConfiguration(): array
    {
        return [
            'deployment_root' => getenv('VP3_POD_DEPLOYMENT_ROOT') ?: '/srv/vp3/pods',
            'release_zip' => getenv('VP3_POD_RELEASE_ZIP') ?: '/srv/vp3/releases/pod.zip',
            'release_version' => getenv('VP3_POD_RELEASE_VERSION') ?: 'development',
            'release_sha256' => getenv('VP3_POD_RELEASE_SHA256') ?: '',
            'configuration_path' => getenv('VP3_POD_CONFIGURATION_PATH') ?: 'config/config.php',
            'entrypoint_path' => getenv('VP3_POD_ENTRYPOINT_PATH') ?: 'public/index.php',
            'wildcard_base_domain' => getenv('VP3_WILDCARD_BASE_DOMAIN') ?: 'vp3.me',
            'wildcard_tls_ready' => filter_var(getenv('VP3_WILDCARD_TLS_READY') ?: '0', FILTER_VALIDATE_BOOL),
            'database_admin_dsn' => getenv('VP3_POD_DB_ADMIN_DSN') ?: 'mysql:host=127.0.0.1;charset=utf8mb4',
            'database_admin_username' => getenv('VP3_POD_DB_ADMIN_USERNAME') ?: '',
            'database_admin_password' => getenv('VP3_POD_DB_ADMIN_PASSWORD') ?: '',
            'database_host' => getenv('VP3_POD_DB_HOST') ?: '127.0.0.1',
            'database_port' => (int) (getenv('VP3_POD_DB_PORT') ?: 3306),
            'database_charset' => getenv('VP3_POD_DB_CHARSET') ?: 'utf8mb4',
            'database_name_prefix' => getenv('VP3_POD_DB_NAME_PREFIX') ?: 'vp3pod_',
            'database_user_prefix' => getenv('VP3_POD_DB_USER_PREFIX') ?: 'vp3pod_',
            'database_user_host' => getenv('VP3_POD_DB_USER_HOST') ?: 'localhost',
            'maximum_archive_files' => (int) (getenv('VP3_POD_MAX_ARCHIVE_FILES') ?: 20000),
            'maximum_archive_bytes' => (int) (getenv('VP3_POD_MAX_ARCHIVE_BYTES') ?: 1073741824),
            'strip_single_root' => filter_var(getenv('VP3_POD_STRIP_SINGLE_ROOT') ?: '1', FILTER_VALIDATE_BOOL),
            'platform_database_dsn' => getenv('DB_DSN') ?: '',
            'platform_database_username' => getenv('DB_USERNAME') ?: '',
            'platform_database_password' => getenv('DB_PASSWORD') ?: '',
        ];
    }

    /** @return array<string,mixed> */
    private static function localBackupConfiguration(): array
    {
        return [
            'deployment_root' => getenv('VP3_POD_DEPLOYMENT_ROOT') ?: '/srv/vp3/pods',
            'backup_root' => getenv('VP3_LOCAL_BACKUP_ROOT') ?: '/srv/vp3/backups',
            'encryption_key_base64' => getenv('VP3_LOCAL_BACKUP_ENCRYPTION_KEY_B64') ?: '',
            'configuration_path' => getenv('VP3_POD_CONFIGURATION_PATH') ?: 'config/config.php',
            'mysqldump_binary' => getenv('VP3_MYSQLDUMP_BINARY') ?: '/usr/bin/mysqldump',
            'mysql_binary' => getenv('VP3_MYSQL_BINARY') ?: '/usr/bin/mysql',
            'database_host' => getenv('VP3_POD_DB_HOST') ?: '127.0.0.1',
            'database_port' => (int) (getenv('VP3_POD_DB_PORT') ?: 3306),
            'maximum_backup_bytes' => (int) (getenv('VP3_LOCAL_BACKUP_MAX_BYTES') ?: 5368709120),
        ];
    }

    /** @return array<string,mixed> */
    private static function localUpdateConfiguration(): array
    {
        return array_replace(self::localBackupConfiguration(), [
            'entrypoint_path' => getenv('VP3_POD_ENTRYPOINT_PATH') ?: 'public/index.php',
            'maximum_archive_files' => (int) (getenv('VP3_POD_MAX_ARCHIVE_FILES') ?: 20000),
            'maximum_archive_bytes' => (int) (getenv('VP3_POD_MAX_ARCHIVE_BYTES') ?: 1073741824),
            'platform_database_dsn' => getenv('DB_DSN') ?: '',
            'platform_database_username' => getenv('DB_USERNAME') ?: '',
            'platform_database_password' => getenv('DB_PASSWORD') ?: '',
        ]);
    }

    /** @return array<string,mixed> */
    private static function wildcardInfrastructureConfiguration(): array
    {
        return [
            'deployment_root' => getenv('VP3_POD_DEPLOYMENT_ROOT') ?: '/srv/vp3/pods',
            'wildcard_base_domain' => getenv('VP3_WILDCARD_BASE_DOMAIN') ?: 'vp3.me',
            'wildcard_dns_ready' => filter_var(getenv('VP3_WILDCARD_DNS_READY') ?: '0', FILTER_VALIDATE_BOOL),
            'wildcard_tls_ready' => filter_var(getenv('VP3_WILDCARD_TLS_READY') ?: '0', FILTER_VALIDATE_BOOL),
        ];
    }
}
