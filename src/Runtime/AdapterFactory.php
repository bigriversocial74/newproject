<?php

declare(strict_types=1);

namespace Vp3\Runtime;

use RuntimeException;
use Vp3\Backups\BackupProviderAdapter;
use Vp3\Backups\NullBackupProviderAdapter;
use Vp3\Infrastructure\CertificateProviderAdapter;
use Vp3\Infrastructure\DnsProviderAdapter;
use Vp3\Infrastructure\HostingProviderAdapter;
use Vp3\Infrastructure\NullInfrastructureProviderAdapter;
use Vp3\Operations\NullOperationalNotificationAdapter;
use Vp3\Operations\OperationalNotificationAdapter;
use Vp3\Provisioning\NullPodProvisioningAdapter;
use Vp3\Provisioning\PodProvisioningAdapter;
use Vp3\Updates\NullSoftwareUpdateAdapter;
use Vp3\Updates\SoftwareUpdateAdapter;

final class AdapterFactory
{
    public static function provisioning(string $driver, string $environment): PodProvisioningAdapter
    {
        self::assertNullAllowed($driver, $environment, 'POD provisioning');
        return new NullPodProvisioningAdapter();
    }

    public static function updates(string $driver, string $environment): SoftwareUpdateAdapter
    {
        self::assertNullAllowed($driver, $environment, 'software update');
        return new NullSoftwareUpdateAdapter();
    }

    public static function backups(string $driver, string $environment): BackupProviderAdapter
    {
        self::assertNullAllowed($driver, $environment, 'backup');
        return new NullBackupProviderAdapter();
    }

    /** @return array{hosting:HostingProviderAdapter,dns:DnsProviderAdapter,certificate:CertificateProviderAdapter} */
    public static function infrastructure(string $driver, string $environment): array
    {
        self::assertNullAllowed($driver, $environment, 'infrastructure');
        $adapter = new NullInfrastructureProviderAdapter();
        return ['hosting' => $adapter, 'dns' => $adapter, 'certificate' => $adapter];
    }

    public static function notifications(string $driver, string $environment): OperationalNotificationAdapter
    {
        self::assertNullAllowed($driver, $environment, 'operational notification');
        return new NullOperationalNotificationAdapter();
    }

    private static function assertNullAllowed(string $driver, string $environment, string $label): void
    {
        $driver = strtolower(trim($driver));
        $environment = strtolower(trim($environment));
        if ($driver !== 'null') {
            throw new RuntimeException('Unsupported ' . $label . ' driver: ' . ($driver === '' ? '(empty)' : $driver) . '.');
        }
        if ($environment === 'production') {
            throw new RuntimeException('The null ' . $label . ' adapter is forbidden in production.');
        }
    }
}
