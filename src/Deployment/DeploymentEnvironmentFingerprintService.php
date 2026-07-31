<?php

declare(strict_types=1);

namespace Vp3\Deployment;

use RuntimeException;

final class DeploymentEnvironmentFingerprintService
{
    /**
     * @param array<string,mixed> $applicationConfig
     * @param array<string,mixed> $databaseConfig
     * @param array<string,mixed> $releaseConfig
     */
    public function fingerprint(
        array $applicationConfig,
        array $databaseConfig,
        array $releaseConfig,
        string $environmentKey
    ): string {
        $environmentKey = strtolower(trim($environmentKey));
        if (!in_array($environmentKey, ['staging', 'production'], true)) {
            throw new RuntimeException('A staging or production environment key is required.');
        }
        $databaseIdentity = $this->databaseIdentity((string) ($databaseConfig['dsn'] ?? ''));
        $app = (array) ($applicationConfig['app'] ?? []);
        $auth = (array) ($applicationConfig['auth'] ?? []);
        $mail = (array) ($applicationConfig['mail'] ?? []);
        $provisioning = (array) ($applicationConfig['provisioning'] ?? []);
        $homeserver = (array) ($applicationConfig['homeserver'] ?? []);
        $releases = (array) ($applicationConfig['releases'] ?? []);
        $backups = (array) ($applicationConfig['backups'] ?? []);
        $infrastructure = (array) ($applicationConfig['infrastructure'] ?? []);
        $operations = (array) ($applicationConfig['operations'] ?? []);
        $queue = (array) ($applicationConfig['queue'] ?? []);

        $document = [
            'format' => 'vp3-platform-environment-fingerprint-v1',
            'environment_key' => $environmentKey,
            'app' => [
                'env' => strtolower((string) ($app['env'] ?? '')),
                'base_url' => rtrim((string) ($app['base_url'] ?? ''), '/'),
                'session_name' => (string) ($app['session_name'] ?? ''),
                'session_secure' => (bool) ($app['session_secure'] ?? false),
            ],
            'database' => $databaseIdentity,
            'release' => [
                'format' => (string) ($releaseConfig['format'] ?? ''),
                'version' => (string) ($releaseConfig['version'] ?? ''),
                'schema_level' => (int) ($releaseConfig['schema_level'] ?? 0),
                'migration_tail' => (string) ($releaseConfig['migration_tail'] ?? ''),
            ],
            'auth' => [
                'password_min_length' => (int) ($auth['password_min_length'] ?? 0),
                'session_inactivity_ttl_seconds' => (int) ($auth['session_inactivity_ttl_seconds'] ?? 0),
                'session_absolute_ttl_seconds' => (int) ($auth['session_absolute_ttl_seconds'] ?? 0),
                'mfa_challenge_ttl_seconds' => (int) ($auth['mfa_challenge_ttl_seconds'] ?? 0),
            ],
            'mail' => [
                'driver' => strtolower((string) ($mail['driver'] ?? '')),
                'smtp_host' => strtolower((string) ($mail['smtp_host'] ?? '')),
                'smtp_port' => (int) ($mail['smtp_port'] ?? 0),
                'smtp_encryption' => strtolower((string) ($mail['smtp_encryption'] ?? '')),
                'sender_email' => strtolower((string) ($mail['sender_email'] ?? '')),
            ],
            'provisioning' => [
                'driver' => strtolower((string) ($provisioning['provider_driver'] ?? '')),
                'deployment_root' => (string) ($provisioning['deployment_root'] ?? ''),
                'release_version' => (string) ($provisioning['release_version'] ?? ''),
                'release_sha256' => strtolower((string) ($provisioning['release_sha256'] ?? '')),
                'configuration_path' => (string) ($provisioning['configuration_path'] ?? ''),
                'entrypoint_path' => (string) ($provisioning['entrypoint_path'] ?? ''),
                'wildcard_base_domain' => strtolower((string) ($provisioning['wildcard_base_domain'] ?? '')),
                'wildcard_tls_ready' => (bool) ($provisioning['wildcard_tls_ready'] ?? false),
            ],
            'homeserver' => [
                'pairing_ttl_seconds' => (int) ($homeserver['pairing_ttl_seconds'] ?? 0),
                'lease_ttl_seconds' => (int) ($homeserver['lease_ttl_seconds'] ?? 0),
                'offline_after_minutes' => (int) ($homeserver['offline_after_minutes'] ?? 0),
            ],
            'releases' => [
                'update_provider_driver' => strtolower((string) ($releases['update_provider_driver'] ?? '')),
                'deployment_root' => (string) ($releases['deployment_root'] ?? ''),
                'backup_root' => (string) ($releases['backup_root'] ?? ''),
                'configuration_path' => (string) ($releases['configuration_path'] ?? ''),
                'entrypoint_path' => (string) ($releases['entrypoint_path'] ?? ''),
                'mysqldump_binary' => (string) ($releases['mysqldump_binary'] ?? ''),
                'mysql_binary' => (string) ($releases['mysql_binary'] ?? ''),
            ],
            'backups' => [
                'provider_driver' => strtolower((string) ($backups['provider_driver'] ?? '')),
                'local_backup_root' => (string) ($backups['local_backup_root'] ?? ''),
                'configuration_path' => (string) ($backups['configuration_path'] ?? ''),
                'warning_threshold_percent' => (float) ($backups['warning_threshold_percent'] ?? 0),
                'critical_threshold_percent' => (float) ($backups['critical_threshold_percent'] ?? 0),
            ],
            'infrastructure' => [
                'provider_driver' => strtolower((string) ($infrastructure['provider_driver'] ?? '')),
                'deployment_root' => (string) ($infrastructure['deployment_root'] ?? ''),
                'wildcard_base_domain' => strtolower((string) ($infrastructure['wildcard_base_domain'] ?? '')),
                'wildcard_dns_ready' => (bool) ($infrastructure['wildcard_dns_ready'] ?? false),
                'wildcard_tls_ready' => (bool) ($infrastructure['wildcard_tls_ready'] ?? false),
            ],
            'operations' => [
                'notification_driver' => strtolower((string) ($operations['notification_driver'] ?? '')),
                'pod_offline_after_minutes' => (int) ($operations['pod_offline_after_minutes'] ?? 0),
                'homeserver_offline_after_minutes' => (int) ($operations['homeserver_offline_after_minutes'] ?? 0),
            ],
            'queue' => ['lease_seconds' => (int) ($queue['lease_seconds'] ?? 0)],
        ];

        return hash('sha256', $this->canonicalJson($document));
    }

    /** @return array{driver:string,host:string,port:int,dbname:string,charset:string} */
    private function databaseIdentity(string $dsn): array
    {
        if (!preg_match('/^([A-Za-z0-9_]+):(.*)$/', trim($dsn), $matches)) {
            throw new RuntimeException('The target database DSN is invalid.');
        }
        $values = [];
        foreach (explode(';', $matches[2]) as $part) {
            if ($part !== '' && str_contains($part, '=')) {
                [$key, $value] = explode('=', $part, 2);
                $values[strtolower(trim($key))] = trim($value);
            }
        }
        return [
            'driver' => strtolower($matches[1]),
            'host' => strtolower((string) ($values['host'] ?? '')),
            'port' => (int) ($values['port'] ?? 3306),
            'dbname' => (string) ($values['dbname'] ?? ''),
            'charset' => strtolower((string) ($values['charset'] ?? 'utf8mb4')),
        ];
    }

    private function canonicalJson(mixed $value): string
    {
        return json_encode(
            $this->canonicalize($value),
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION
        );
    }

    private function canonicalize(mixed $value): mixed
    {
        if (!is_array($value)) {
            return $value;
        }
        if (array_is_list($value)) {
            return array_map(fn (mixed $item): mixed => $this->canonicalize($item), $value);
        }
        ksort($value, SORT_STRING);
        foreach ($value as $key => $item) {
            $value[$key] = $this->canonicalize($item);
        }
        return $value;
    }
}
