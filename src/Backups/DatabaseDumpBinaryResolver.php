<?php

declare(strict_types=1);

namespace Vp3\Backups;

use RuntimeException;

final class DatabaseDumpBinaryResolver
{
    public static function resolve(string $configuredBinary, string $backupRoot): string
    {
        $configuredBinary = self::absoluteExecutable($configuredBinary, 'VP3_MYSQLDUMP_BINARY');
        $backupRoot = self::absolutePath($backupRoot, 'VP3_LOCAL_BACKUP_ROOT');

        if (!is_dir($backupRoot) && !mkdir($backupRoot, 0700, true) && !is_dir($backupRoot)) {
            throw new RuntimeException('Unable to create the local backup root for database tooling.');
        }
        chmod($backupRoot, 0700);

        $toolDirectory = $backupRoot . '/.vp3-tools';
        if (!is_dir($toolDirectory) && !mkdir($toolDirectory, 0700, true) && !is_dir($toolDirectory)) {
            throw new RuntimeException('Unable to create the protected database tooling directory.');
        }
        chmod($toolDirectory, 0700);

        $options = ['--add-drop-table'];
        if (strtolower(basename($configuredBinary)) === 'mysqldump') {
            array_unshift($options, '--no-tablespaces');
        }

        $wrapper = $toolDirectory . '/database-dump-schema';
        $content = "#!/bin/sh\nset -eu\nexec "
            . escapeshellarg($configuredBinary)
            . ' ' . implode(' ', array_map('escapeshellarg', $options))
            . " \"\$@\"\n";
        $existing = is_file($wrapper) ? file_get_contents($wrapper) : false;
        if (!is_string($existing) || !hash_equals(hash('sha256', $content), hash('sha256', $existing))) {
            $temporary = $wrapper . '.tmp-' . bin2hex(random_bytes(8));
            $written = file_put_contents($temporary, $content, LOCK_EX);
            if ($written === false || $written !== strlen($content)) {
                @unlink($temporary);
                throw new RuntimeException('Unable to write the protected database dump wrapper.');
            }
            chmod($temporary, 0700);
            if (!rename($temporary, $wrapper)) {
                @unlink($temporary);
                throw new RuntimeException('Unable to activate the protected database dump wrapper.');
            }
        }
        chmod($wrapper, 0700);

        if (!is_executable($wrapper)) {
            throw new RuntimeException('The protected database dump wrapper is not executable.');
        }
        return $wrapper;
    }

    private static function absoluteExecutable(string $path, string $label): string
    {
        $path = self::absolutePath($path, $label);
        if (!is_file($path) || !is_executable($path)) {
            throw new RuntimeException($label . ' must point to an executable file.');
        }
        return $path;
    }

    private static function absolutePath(string $path, string $label): string
    {
        $path = trim($path);
        if ($path === '' || (!str_starts_with($path, '/') && !preg_match('/^[A-Za-z]:[\\\\\/]/', $path))) {
            throw new RuntimeException($label . ' must be an absolute path.');
        }
        return rtrim(str_replace('\\', '/', $path), '/');
    }
}
