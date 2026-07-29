<?php

declare(strict_types=1);

namespace Vp3\Auth\Mail;

use RuntimeException;

final class MailAdapterFactory
{
    /** @param array<string,mixed> $config */
    public static function create(array $config, string $environment): MailAdapter
    {
        $driver = strtolower(trim((string) ($config['driver'] ?? 'null')));
        if ($driver === 'null') {
            if ($environment === 'production') {
                throw new RuntimeException('Null mail adapter is not permitted in production.');
            }
            return new NullMailAdapter();
        }
        if ($driver !== 'smtp') {
            throw new RuntimeException('Unsupported mail driver.');
        }
        return new SmtpMailAdapter(
            (string) ($config['smtp_host'] ?? ''),
            (int) ($config['smtp_port'] ?? 0),
            strtolower((string) ($config['smtp_encryption'] ?? '')),
            (string) ($config['smtp_username'] ?? ''),
            (string) ($config['smtp_password'] ?? ''),
            (string) ($config['sender_email'] ?? ''),
            (string) ($config['sender_name'] ?? '')
        );
    }
}
