<?php

declare(strict_types=1);

namespace Vp3\Runtime;

use RuntimeException;

final class RuntimeConfigurationValidator
{
    /** @param array<string,mixed> $config */
    public function validate(array $config, bool $usingExampleConfig): void
    {
        $environment = strtolower(trim((string) ($config['app']['env'] ?? '')));
        if (!in_array($environment, ['development', 'test', 'staging', 'production'], true)) {
            throw new RuntimeException('APP_ENV must be development, test, staging, or production.');
        }

        $leaseSeconds = (int) ($config['queue']['lease_seconds'] ?? 0);
        if ($leaseSeconds < 30 || $leaseSeconds > 3600) {
            throw new RuntimeException('VP3_QUEUE_LEASE_SECONDS must be between 30 and 3600.');
        }

        if ($environment !== 'production') {
            return;
        }
        if ($usingExampleConfig) {
            throw new RuntimeException('Production cannot start from config-example.php. Create config/config.php.');
        }
        if (($config['app']['session_secure'] ?? false) !== true) {
            throw new RuntimeException('Secure session cookies are required in production.');
        }
        $baseUrl = (string) ($config['app']['base_url'] ?? '');
        if (!str_starts_with(strtolower($baseUrl), 'https://')) {
            throw new RuntimeException('APP_BASE_URL must use HTTPS in production.');
        }

        $this->requiredString($config, ['database', 'dsn'], 'DB_DSN');
        $this->requiredString($config, ['database', 'username'], 'DB_USERNAME');
        $this->requiredString($config, ['database', 'password'], 'DB_PASSWORD');
        $this->requiredString($config, ['stripe', 'secret_key'], 'STRIPE_SECRET_KEY');
        $this->requiredString($config, ['stripe', 'webhook_secret'], 'STRIPE_WEBHOOK_SECRET');

        $leaseSigningKey = $this->requiredString($config, ['homeserver', 'lease_signing_key'], 'HOMESERVER_LEASE_SIGNING_KEY');
        if (strlen($leaseSigningKey) < 32) {
            throw new RuntimeException('HOMESERVER_LEASE_SIGNING_KEY must contain at least 32 bytes.');
        }

        $this->base64Length($this->requiredString($config, ['releases', 'signing_private_key_base64'], 'RELEASE_SIGNING_PRIVATE_KEY_B64'), 64, 'RELEASE_SIGNING_PRIVATE_KEY_B64');
        $this->base64Length($this->requiredString($config, ['releases', 'signing_public_key_base64'], 'RELEASE_SIGNING_PUBLIC_KEY_B64'), 32, 'RELEASE_SIGNING_PUBLIC_KEY_B64');
        $this->base64Length($this->requiredString($config, ['backups', 'metadata_encryption_key_base64'], 'BACKUP_METADATA_ENCRYPTION_KEY_B64'), 32, 'BACKUP_METADATA_ENCRYPTION_KEY_B64');
        $this->base64Length($this->requiredString($config, ['infrastructure', 'secret_encryption_key_base64'], 'PROVIDER_SECRET_ENCRYPTION_KEY_B64'), 32, 'PROVIDER_SECRET_ENCRYPTION_KEY_B64');
        $this->base64Length($this->requiredString($config, ['operations', 'secret_encryption_key_base64'], 'OPERATIONS_SECRET_ENCRYPTION_KEY_B64'), 32, 'OPERATIONS_SECRET_ENCRYPTION_KEY_B64');

        foreach ([
            ['provisioning', 'provider_driver', 'VP3_PROVISIONING_DRIVER'],
            ['releases', 'update_provider_driver', 'VP3_UPDATE_PROVIDER_DRIVER'],
            ['backups', 'provider_driver', 'VP3_BACKUP_PROVIDER_DRIVER'],
            ['infrastructure', 'provider_driver', 'VP3_INFRASTRUCTURE_PROVIDER_DRIVER'],
            ['operations', 'notification_driver', 'VP3_OPERATIONS_NOTIFICATION_DRIVER'],
        ] as [$section, $key, $label]) {
            $driver = strtolower($this->requiredString($config, [$section, $key], $label));
            if ($driver === 'null') {
                throw new RuntimeException($label . ' cannot use the null adapter in production.');
            }
        }
    }

    /** @param array<string,mixed> $config @param list<string> $path */
    private function requiredString(array $config, array $path, string $label): string
    {
        $value = $config;
        foreach ($path as $segment) {
            if (!is_array($value) || !array_key_exists($segment, $value)) {
                throw new RuntimeException($label . ' is required in production.');
            }
            $value = $value[$segment];
        }
        if (!is_string($value) || trim($value) === '') {
            throw new RuntimeException($label . ' is required in production.');
        }
        return $value;
    }

    private function base64Length(string $value, int $length, string $label): void
    {
        $decoded = base64_decode($value, true);
        if (!is_string($decoded) || strlen($decoded) !== $length) {
            throw new RuntimeException($label . ' must decode to exactly ' . $length . ' bytes.');
        }
    }
}
