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

        $auth = (array) ($config['auth'] ?? []);
        $inactivityTtl = (int) ($auth['session_inactivity_ttl_seconds'] ?? 0);
        $absoluteTtl = (int) ($auth['session_absolute_ttl_seconds'] ?? 0);
        if ($inactivityTtl < 300) {
            throw new RuntimeException('AUTH_SESSION_INACTIVITY_TTL_SECONDS must be at least 300.');
        }
        if ($absoluteTtl < $inactivityTtl) {
            throw new RuntimeException('AUTH_SESSION_ABSOLUTE_TTL_SECONDS must be greater than or equal to the inactivity TTL.');
        }
        if ((int) ($auth['login_attempt_limit'] ?? 0) < 1) {
            throw new RuntimeException('AUTH_LOGIN_ATTEMPT_LIMIT must be at least 1.');
        }
        if ((int) ($auth['login_attempt_window_seconds'] ?? 0) < 60) {
            throw new RuntimeException('AUTH_LOGIN_ATTEMPT_WINDOW_SECONDS must be at least 60.');
        }

        $mail = (array) ($config['mail'] ?? []);
        $mailDriver = strtolower(trim((string) ($mail['driver'] ?? '')));
        if (!in_array($mailDriver, ['null', 'smtp'], true)) {
            throw new RuntimeException('MAIL_DRIVER must be null or smtp.');
        }

        $provisioningDriver = $this->allowedDriver(
            (string) ($config['provisioning']['provider_driver'] ?? ''),
            ['null', 'local'],
            'VP3_PROVISIONING_DRIVER'
        );
        $infrastructureDriver = $this->allowedDriver(
            (string) ($config['infrastructure']['provider_driver'] ?? ''),
            ['null', 'wildcard-local'],
            'VP3_INFRASTRUCTURE_PROVIDER_DRIVER'
        );
        $backupDriver = $this->allowedDriver(
            (string) ($config['backups']['provider_driver'] ?? ''),
            ['null', 'local-pod'],
            'VP3_BACKUP_PROVIDER_DRIVER'
        );
        $updateDriver = $this->allowedDriver(
            (string) ($config['releases']['update_provider_driver'] ?? ''),
            ['null', 'local-pod'],
            'VP3_UPDATE_PROVIDER_DRIVER'
        );
        $notificationDriver = $this->allowedDriver(
            (string) ($config['operations']['notification_driver'] ?? ''),
            ['null', 'smtp'],
            'VP3_OPERATIONS_NOTIFICATION_DRIVER'
        );

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

        if ($mailDriver !== 'smtp') {
            throw new RuntimeException('MAIL_DRIVER must be smtp in production.');
        }
        $this->requiredString($config, ['mail', 'smtp_host'], 'SMTP_HOST');
        $smtpPort = (int) ($mail['smtp_port'] ?? 0);
        if ($smtpPort < 1 || $smtpPort > 65535) {
            throw new RuntimeException('SMTP_PORT must be between 1 and 65535.');
        }
        $smtpEncryption = strtolower($this->requiredString($config, ['mail', 'smtp_encryption'], 'SMTP_ENCRYPTION'));
        if (!in_array($smtpEncryption, ['tls', 'ssl'], true)) {
            throw new RuntimeException('SMTP_ENCRYPTION must be tls or ssl in production.');
        }
        $this->requiredString($config, ['mail', 'smtp_username'], 'SMTP_USERNAME');
        $this->requiredString($config, ['mail', 'smtp_password'], 'SMTP_PASSWORD');
        $senderEmail = $this->requiredString($config, ['mail', 'sender_email'], 'MAIL_SENDER_EMAIL');
        if (!filter_var($senderEmail, FILTER_VALIDATE_EMAIL)) {
            throw new RuntimeException('MAIL_SENDER_EMAIL must be a valid email address.');
        }
        $this->requiredString($config, ['mail', 'sender_name'], 'MAIL_SENDER_NAME');

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
            [$provisioningDriver, 'VP3_PROVISIONING_DRIVER'],
            [$updateDriver, 'VP3_UPDATE_PROVIDER_DRIVER'],
            [$backupDriver, 'VP3_BACKUP_PROVIDER_DRIVER'],
            [$infrastructureDriver, 'VP3_INFRASTRUCTURE_PROVIDER_DRIVER'],
            [$notificationDriver, 'VP3_OPERATIONS_NOTIFICATION_DRIVER'],
        ] as [$driver, $label]) {
            if ($driver === 'null') {
                throw new RuntimeException($label . ' cannot use the null adapter in production.');
            }
        }

        if ($provisioningDriver === 'local') {
            $this->validateLocalProvisioning($config);
        }
        if ($infrastructureDriver === 'wildcard-local') {
            $this->validateWildcardInfrastructure($config);
        }
        if ($backupDriver === 'local-pod') {
            $this->validateLocalBackup($config, 'backups');
        }
        if ($updateDriver === 'local-pod') {
            $this->validateLocalBackup($config, 'releases');
            $this->requiredString($config, ['releases', 'configuration_path'], 'VP3_POD_CONFIGURATION_PATH');
            $this->requiredString($config, ['releases', 'entrypoint_path'], 'VP3_POD_ENTRYPOINT_PATH');
            if ((int) ($config['releases']['maximum_archive_files'] ?? 0) < 1) {
                throw new RuntimeException('VP3_POD_MAX_ARCHIVE_FILES must be at least 1.');
            }
            if ((int) ($config['releases']['maximum_archive_bytes'] ?? 0) < 1048576) {
                throw new RuntimeException('VP3_POD_MAX_ARCHIVE_BYTES must be at least 1048576.');
            }
        }
        if ($provisioningDriver === 'local' && $infrastructureDriver !== 'wildcard-local') {
            throw new RuntimeException('Local POD provisioning currently requires the wildcard-local infrastructure adapter.');
        }
        if ($updateDriver === 'local-pod' && $backupDriver !== 'local-pod') {
            throw new RuntimeException('Local POD updates require the local-pod backup driver for consistent recovery operations.');
        }
        if ($notificationDriver === 'smtp' && $mailDriver !== 'smtp') {
            throw new RuntimeException('SMTP operational notifications require the production SMTP mail driver.');
        }
    }

    /** @param array<string,mixed> $config */
    private function validateLocalProvisioning(array $config): void
    {
        if (!extension_loaded('zip')) {
            throw new RuntimeException('The PHP zip extension is required for local POD provisioning.');
        }
        $deploymentRoot = $this->requiredString($config, ['provisioning', 'deployment_root'], 'VP3_POD_DEPLOYMENT_ROOT');
        $releaseZip = $this->requiredString($config, ['provisioning', 'release_zip'], 'VP3_POD_RELEASE_ZIP');
        $this->absolutePath($deploymentRoot, 'VP3_POD_DEPLOYMENT_ROOT');
        $this->absolutePath($releaseZip, 'VP3_POD_RELEASE_ZIP');
        if (!is_file($releaseZip) || !is_readable($releaseZip)) {
            throw new RuntimeException('VP3_POD_RELEASE_ZIP must point to a readable ZIP file in production.');
        }
        $checksum = strtolower($this->requiredString($config, ['provisioning', 'release_sha256'], 'VP3_POD_RELEASE_SHA256'));
        if (!preg_match('/^[a-f0-9]{64}$/', $checksum)) {
            throw new RuntimeException('VP3_POD_RELEASE_SHA256 must be a 64-character hexadecimal SHA-256 value.');
        }
        if (!hash_equals($checksum, strtolower((string) hash_file('sha256', $releaseZip)))) {
            throw new RuntimeException('VP3_POD_RELEASE_SHA256 does not match the configured release ZIP.');
        }
        $this->requiredString($config, ['provisioning', 'release_version'], 'VP3_POD_RELEASE_VERSION');
        $this->requiredString($config, ['provisioning', 'database_admin_dsn'], 'VP3_POD_DB_ADMIN_DSN');
        $this->requiredString($config, ['provisioning', 'database_admin_username'], 'VP3_POD_DB_ADMIN_USERNAME');
        $this->requiredString($config, ['provisioning', 'database_admin_password'], 'VP3_POD_DB_ADMIN_PASSWORD');
        $this->requiredString($config, ['provisioning', 'wildcard_base_domain'], 'VP3_WILDCARD_BASE_DOMAIN');
        if (($config['provisioning']['wildcard_tls_ready'] ?? false) !== true) {
            throw new RuntimeException('VP3_WILDCARD_TLS_READY must be true for local POD provisioning in production.');
        }
        $this->writableDirectoryOrParent($deploymentRoot, 'VP3_POD_DEPLOYMENT_ROOT');
    }

    /** @param array<string,mixed> $config */
    private function validateWildcardInfrastructure(array $config): void
    {
        $deploymentRoot = $this->requiredString($config, ['infrastructure', 'deployment_root'], 'VP3_POD_DEPLOYMENT_ROOT');
        $this->absolutePath($deploymentRoot, 'VP3_POD_DEPLOYMENT_ROOT');
        $this->requiredString($config, ['infrastructure', 'wildcard_base_domain'], 'VP3_WILDCARD_BASE_DOMAIN');
        if (($config['infrastructure']['wildcard_dns_ready'] ?? false) !== true) {
            throw new RuntimeException('VP3_WILDCARD_DNS_READY must be true for wildcard-local infrastructure in production.');
        }
        if (($config['infrastructure']['wildcard_tls_ready'] ?? false) !== true) {
            throw new RuntimeException('VP3_WILDCARD_TLS_READY must be true for wildcard-local infrastructure in production.');
        }
        $this->writableDirectoryOrParent($deploymentRoot, 'VP3_POD_DEPLOYMENT_ROOT');
    }

    /** @param array<string,mixed> $config */
    private function validateLocalBackup(array $config, string $section): void
    {
        if (!extension_loaded('zip') || !extension_loaded('sodium')) {
            throw new RuntimeException('The PHP zip and sodium extensions are required for encrypted local POD backup/update operations.');
        }
        $deploymentRoot = $this->requiredString($config, [$section, 'deployment_root'], 'VP3_POD_DEPLOYMENT_ROOT');
        $backupRootKey = $section === 'backups' ? 'local_backup_root' : 'backup_root';
        $backupKeyKey = $section === 'backups' ? 'local_encryption_key_base64' : 'backup_encryption_key_base64';
        $backupRoot = $this->requiredString($config, [$section, $backupRootKey], 'VP3_LOCAL_BACKUP_ROOT');
        $this->absolutePath($deploymentRoot, 'VP3_POD_DEPLOYMENT_ROOT');
        $this->absolutePath($backupRoot, 'VP3_LOCAL_BACKUP_ROOT');
        $this->writableDirectoryOrParent($deploymentRoot, 'VP3_POD_DEPLOYMENT_ROOT');
        $this->writableDirectoryOrParent($backupRoot, 'VP3_LOCAL_BACKUP_ROOT');
        $this->base64Length(
            $this->requiredString($config, [$section, $backupKeyKey], 'VP3_LOCAL_BACKUP_ENCRYPTION_KEY_B64'),
            32,
            'VP3_LOCAL_BACKUP_ENCRYPTION_KEY_B64'
        );
        $this->executable($this->requiredString($config, [$section, 'mysqldump_binary'], 'VP3_MYSQLDUMP_BINARY'), 'VP3_MYSQLDUMP_BINARY');
        $this->executable($this->requiredString($config, [$section, 'mysql_binary'], 'VP3_MYSQL_BINARY'), 'VP3_MYSQL_BINARY');
        if ((int) ($config[$section]['database_port'] ?? 0) < 1 || (int) ($config[$section]['database_port'] ?? 0) > 65535) {
            throw new RuntimeException('VP3_POD_DB_PORT must be between 1 and 65535.');
        }
        $this->requiredString($config, [$section, 'database_host'], 'VP3_POD_DB_HOST');
        if ((int) ($config[$section]['maximum_backup_bytes'] ?? 0) < 1048576) {
            throw new RuntimeException('VP3_LOCAL_BACKUP_MAX_BYTES must be at least 1048576.');
        }
    }

    private function allowedDriver(string $driver, array $allowed, string $label): string
    {
        $driver = strtolower(trim($driver));
        if (!in_array($driver, $allowed, true)) {
            throw new RuntimeException($label . ' must be one of: ' . implode(', ', $allowed) . '.');
        }
        return $driver;
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

    private function executable(string $path, string $label): void
    {
        $this->absolutePath($path, $label);
        if (!is_file($path) || !is_executable($path)) {
            throw new RuntimeException($label . ' must point to an executable file.');
        }
    }

    private function absolutePath(string $path, string $label): void
    {
        if (!str_starts_with($path, '/') && !preg_match('/^[A-Za-z]:[\\\\\/]/', $path)) {
            throw new RuntimeException($label . ' must be an absolute path.');
        }
    }

    private function writableDirectoryOrParent(string $path, string $label): void
    {
        $candidate = $path;
        while (!file_exists($candidate)) {
            $parent = dirname($candidate);
            if ($parent === $candidate) {
                break;
            }
            $candidate = $parent;
        }
        if (!is_dir($candidate) || !is_writable($candidate)) {
            throw new RuntimeException($label . ' or its nearest existing parent must be writable.');
        }
    }
}
