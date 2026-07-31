<?php

declare(strict_types=1);

namespace Vp3\Deployment;

use PDO;
use RuntimeException;

final class DatabaseCommandService
{
    /** @param array{dsn:string,username:string,password:string} $databaseConfig */
    public function __construct(
        private readonly array $databaseConfig,
        private readonly string $mysqldumpBinary,
        private readonly string $mysqlBinary,
        private readonly string $backupRoot,
        private readonly int $maximumBackupBytes = 5368709120
    ) {
    }

    /** @return array{path:string,path_hash:string,sha256:string,bytes:int,engine:string,version:string} */
    public function createBackup(PDO $pdo, string $backupPublicId): array
    {
        $connection = $this->connection();
        $this->assertBinary($this->mysqldumpBinary, 'mysqldump');
        $this->ensureBackupRoot();
        if (!preg_match('/^PLATFORM-BACKUP-[A-F0-9]{20}$/', $backupPublicId)) {
            throw new RuntimeException('A valid platform backup identity is required.');
        }

        $path = rtrim($this->backupRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $backupPublicId . '.sql';
        $temporary = $path . '.partial-' . bin2hex(random_bytes(5));
        $handle = fopen($temporary, 'xb');
        if ($handle === false) {
            throw new RuntimeException('Unable to create the temporary database backup file.');
        }
        @chmod($temporary, 0600);

        try {
            $command = [
                $this->mysqldumpBinary,
                '--host=' . $connection['host'],
                '--port=' . (string) $connection['port'],
                '--user=' . $this->databaseConfig['username'],
                '--default-character-set=' . $connection['charset'],
                '--single-transaction',
                '--quick',
                '--skip-lock-tables',
                '--routines',
                '--triggers',
                '--events',
                '--hex-blob',
                '--add-drop-table',
                '--skip-comments',
                $connection['database'],
            ];
            $this->run($command, null, $handle);
            fflush($handle);
            if (function_exists('fsync')) {
                fsync($handle);
            }
        } finally {
            fclose($handle);
        }

        $bytes = filesize($temporary);
        if (!is_int($bytes) || $bytes < 1 || $bytes > $this->maximumBackupBytes) {
            @unlink($temporary);
            throw new RuntimeException('The database backup size is outside the configured safety boundary.');
        }
        $sha256 = hash_file('sha256', $temporary);
        if (!is_string($sha256) || !preg_match('/^[a-f0-9]{64}$/', $sha256)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to verify the database backup checksum.');
        }
        if (!rename($temporary, $path)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to publish the verified database backup atomically.');
        }
        @chmod($path, 0600);

        $version = (string) $pdo->query('SELECT VERSION()')->fetchColumn();
        return [
            'path' => $path,
            'path_hash' => hash('sha256', $path),
            'sha256' => $sha256,
            'bytes' => $bytes,
            'engine' => stripos($version, 'mariadb') !== false ? 'mariadb' : 'mysql',
            'version' => mb_substr($version, 0, 80),
        ];
    }

    public function importSqlFile(string $path): void
    {
        if (!is_file($path) || !is_readable($path)) {
            throw new RuntimeException('The SQL import file is missing or unreadable.');
        }
        $connection = $this->connection();
        $this->assertBinary($this->mysqlBinary, 'mysql');
        $input = fopen($path, 'rb');
        if ($input === false) {
            throw new RuntimeException('Unable to open the SQL import file.');
        }
        try {
            $this->run([
                $this->mysqlBinary,
                '--host=' . $connection['host'],
                '--port=' . (string) $connection['port'],
                '--user=' . $this->databaseConfig['username'],
                '--default-character-set=' . $connection['charset'],
                '--database=' . $connection['database'],
                '--binary-mode',
            ], $input, null);
        } finally {
            fclose($input);
        }
    }

    public function restoreBackup(PDO $pdo, string $path, string $expectedSha256): void
    {
        if (!preg_match('/^[a-f0-9]{64}$/', strtolower($expectedSha256))) {
            throw new RuntimeException('A valid backup checksum is required for restore.');
        }
        $actual = is_file($path) ? hash_file('sha256', $path) : false;
        if (!is_string($actual) || !hash_equals(strtolower($expectedSha256), strtolower($actual))) {
            throw new RuntimeException('The database backup checksum does not match the restore receipt.');
        }

        $tables = $pdo->query(
            "SELECT table_name FROM information_schema.tables
             WHERE table_schema=DATABASE() AND table_type='BASE TABLE'"
        )->fetchAll(PDO::FETCH_COLUMN);
        $pdo->exec('SET FOREIGN_KEY_CHECKS=0');
        try {
            foreach ($tables as $table) {
                if (!is_string($table) || !preg_match('/^[A-Za-z0-9_]+$/', $table)) {
                    throw new RuntimeException('Unsafe database table identity encountered during restore.');
                }
                $pdo->exec('DROP TABLE IF EXISTS `' . $table . '`');
            }
        } finally {
            $pdo->exec('SET FOREIGN_KEY_CHECKS=1');
        }
        $this->importSqlFile($path);
    }

    /** @return array{host:string,port:int,database:string,charset:string} */
    public function connection(): array
    {
        $dsn = trim((string) ($this->databaseConfig['dsn'] ?? ''));
        if (!str_starts_with(strtolower($dsn), 'mysql:')) {
            throw new RuntimeException('Phase 33 deployment supports MySQL-compatible PDO DSNs only.');
        }
        $values = [];
        foreach (explode(';', substr($dsn, 6)) as $part) {
            if ($part === '' || !str_contains($part, '=')) {
                continue;
            }
            [$key, $value] = array_map('trim', explode('=', $part, 2));
            $values[strtolower($key)] = $value;
        }
        $host = (string) ($values['host'] ?? '127.0.0.1');
        $database = (string) ($values['dbname'] ?? '');
        $charset = strtolower((string) ($values['charset'] ?? 'utf8mb4'));
        $port = (int) ($values['port'] ?? 3306);
        if ($host === '' || $database === '' || $port < 1 || $port > 65535) {
            throw new RuntimeException('The database DSN must include a valid host, port, and database name.');
        }
        if (!preg_match('/^[A-Za-z0-9_$-]+$/', $database)) {
            throw new RuntimeException('The database name contains unsupported characters.');
        }
        if (!in_array($charset, ['utf8mb4', 'utf8'], true)) {
            throw new RuntimeException('The database charset must be utf8mb4 or utf8.');
        }
        return ['host' => $host, 'port' => $port, 'database' => $database, 'charset' => $charset];
    }

    private function ensureBackupRoot(): void
    {
        if (!str_starts_with($this->backupRoot, DIRECTORY_SEPARATOR)) {
            throw new RuntimeException('VP3_PLATFORM_BACKUP_ROOT must be an absolute path.');
        }
        if (!is_dir($this->backupRoot) && !mkdir($this->backupRoot, 0700, true) && !is_dir($this->backupRoot)) {
            throw new RuntimeException('Unable to create the platform backup directory.');
        }
        @chmod($this->backupRoot, 0700);
        if (!is_writable($this->backupRoot)) {
            throw new RuntimeException('The platform backup directory is not writable.');
        }
    }

    private function assertBinary(string $path, string $label): void
    {
        if (!str_starts_with($path, DIRECTORY_SEPARATOR) || !is_file($path) || !is_executable($path)) {
            throw new RuntimeException('The configured ' . $label . ' binary is unavailable or not executable.');
        }
    }

    /** @param list<string> $command @param resource|null $stdin @param resource|null $stdout */
    private function run(array $command, mixed $stdin, mixed $stdout): void
    {
        $descriptors = [
            0 => $stdin === null ? ['pipe', 'r'] : $stdin,
            1 => $stdout === null ? ['pipe', 'w'] : $stdout,
            2 => ['pipe', 'w'],
        ];
        $environment = array_merge($_ENV, ['MYSQL_PWD' => (string) ($this->databaseConfig['password'] ?? '')]);
        $process = proc_open($command, $descriptors, $pipes, null, $environment);
        if (!is_resource($process)) {
            throw new RuntimeException('Unable to start the database command.');
        }
        if ($stdin === null && isset($pipes[0]) && is_resource($pipes[0])) {
            fclose($pipes[0]);
        }
        $capturedStdout = '';
        if ($stdout === null && isset($pipes[1]) && is_resource($pipes[1])) {
            $capturedStdout = (string) stream_get_contents($pipes[1], 8192);
            fclose($pipes[1]);
        }
        $stderr = '';
        if (isset($pipes[2]) && is_resource($pipes[2])) {
            $stderr = (string) stream_get_contents($pipes[2], 8192);
            fclose($pipes[2]);
        }
        $status = proc_close($process);
        if ($status !== 0) {
            throw new RuntimeException(
                'Database command failed with exit code ' . $status . ': ' .
                mb_substr(trim($stderr !== '' ? $stderr : $capturedStdout), 0, 500)
            );
        }
    }
}
