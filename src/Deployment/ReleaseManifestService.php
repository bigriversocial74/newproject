<?php

declare(strict_types=1);

namespace Vp3\Deployment;

use RuntimeException;

final class ReleaseManifestService
{
    /** @param array<string,mixed> $release */
    public function __construct(
        private readonly string $root,
        private readonly array $release
    ) {
    }

    /** @return array<string,mixed> */
    public function build(?string $commitSha = null): array
    {
        $commitSha = $this->commitSha($commitSha);
        $installerPath = $this->absolute((string) ($this->release['installer_path'] ?? ''));
        $manifestPath = $this->absolute((string) ($this->release['migration_manifest_path'] ?? ''));
        $migrations = $this->migrationEntries($manifestPath);

        $migrationDocuments = [];
        foreach ($migrations as $path) {
            $absolute = $this->absolute('database/' . $path);
            $migrationDocuments[] = [
                'path' => $path,
                'sha256' => $this->fileSha256($absolute),
                'bytes' => $this->fileBytes($absolute),
            ];
        }

        $manifest = [
            'format' => (string) ($this->release['format'] ?? ''),
            'version' => (string) ($this->release['version'] ?? ''),
            'commit_sha' => $commitSha,
            'schema_level' => (int) ($this->release['schema_level'] ?? 0),
            'minimum_php' => (string) ($this->release['minimum_php'] ?? ''),
            'supported_databases' => (array) ($this->release['supported_databases'] ?? []),
            'migration_tail' => (string) ($this->release['migration_tail'] ?? ''),
            'migration_count' => count($migrationDocuments),
            'migrations' => $migrationDocuments,
            'installer' => [
                'path' => $this->relative($installerPath),
                'sha256' => $this->fileSha256($installerPath),
                'bytes' => $this->fileBytes($installerPath),
            ],
            'migration_manifest' => [
                'path' => $this->relative($manifestPath),
                'sha256' => $this->fileSha256($manifestPath),
                'bytes' => $this->fileBytes($manifestPath),
            ],
        ];
        $manifest['manifest_sha256'] = hash('sha256', $this->canonicalJson($manifest));
        return $manifest;
    }

    /** @param array<string,mixed> $manifest */
    public function verify(array $manifest): void
    {
        $expected = $this->build((string) ($manifest['commit_sha'] ?? ''));
        if (!hash_equals(
            (string) ($expected['manifest_sha256'] ?? ''),
            (string) ($manifest['manifest_sha256'] ?? '')
        )) {
            throw new RuntimeException('The platform release manifest does not match the current release files.');
        }
        if ($this->canonicalJson($expected) !== $this->canonicalJson($manifest)) {
            throw new RuntimeException('The platform release manifest content is not canonical or current.');
        }
    }

    /** @param array<string,mixed> $manifest */
    public function write(array $manifest, string $path): void
    {
        $this->verify($manifest);
        $directory = dirname($path);
        if (!is_dir($directory) && !mkdir($directory, 0750, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to create the release manifest directory.');
        }
        $temporary = $path . '.tmp-' . bin2hex(random_bytes(6));
        $bytes = file_put_contents($temporary, $this->canonicalJson($manifest) . "\n", LOCK_EX);
        if (!is_int($bytes) || $bytes < 1) {
            @unlink($temporary);
            throw new RuntimeException('Unable to write the platform release manifest.');
        }
        @chmod($temporary, 0640);
        if (!rename($temporary, $path)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to publish the platform release manifest atomically.');
        }
    }

    /** @return list<string> */
    public function migrationPaths(): array
    {
        return $this->migrationEntries($this->absolute((string) $this->release['migration_manifest_path']));
    }

    public function migrationSha256(string $path): string
    {
        return $this->fileSha256($this->absolute('database/' . $path));
    }

    /** @param mixed $value */
    public function canonicalJson(mixed $value): string
    {
        return json_encode(
            $this->canonicalize($value),
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );
    }

    /** @param mixed $value @return mixed */
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

    private function commitSha(?string $commitSha): string
    {
        $candidate = trim((string) ($commitSha ?: getenv('VP3_RELEASE_COMMIT') ?: ''));
        if ($candidate === '') {
            $candidate = $this->gitCommit();
        }
        if (!preg_match('/^[a-f0-9]{40,64}$/', strtolower($candidate))) {
            throw new RuntimeException('VP3_RELEASE_COMMIT must be a 40 to 64 character hexadecimal commit identity.');
        }
        return strtolower($candidate);
    }

    private function gitCommit(): string
    {
        $descriptor = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = proc_open(['git', '-C', $this->root, 'rev-parse', 'HEAD'], $descriptor, $pipes);
        if (!is_resource($process)) {
            throw new RuntimeException('Unable to resolve the current Git commit.');
        }
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $status = proc_close($process);
        if ($status !== 0 || !is_string($stdout)) {
            throw new RuntimeException('Unable to resolve the current Git commit: ' . mb_substr(trim((string) $stderr), 0, 200));
        }
        return trim($stdout);
    }

    /** @return list<string> */
    private function migrationEntries(string $path): array
    {
        $lines = file($path, FILE_IGNORE_NEW_LINES);
        if (!is_array($lines)) {
            throw new RuntimeException('Unable to read the migration manifest.');
        }
        $entries = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            if (!preg_match('#^migrations/[A-Za-z0-9._-]+\.sql$#', $line)) {
                throw new RuntimeException('Unsafe migration manifest path: ' . $line);
            }
            $entries[] = $line;
        }
        if ($entries === []) {
            throw new RuntimeException('The migration manifest is empty.');
        }
        if (count($entries) !== count(array_unique($entries))) {
            throw new RuntimeException('The migration manifest contains duplicate paths.');
        }
        $tail = (string) ($this->release['migration_tail'] ?? '');
        if (end($entries) !== $tail) {
            throw new RuntimeException('The release migration tail does not match the migration manifest.');
        }
        return array_values($entries);
    }

    private function absolute(string $relative): string
    {
        $relative = ltrim(str_replace('\\', '/', trim($relative)), '/');
        if ($relative === '' || str_contains($relative, '../')) {
            throw new RuntimeException('An unsafe release path was configured.');
        }
        $path = $this->root . '/' . $relative;
        if (!is_file($path) || !is_readable($path)) {
            throw new RuntimeException('A required release file is missing or unreadable: ' . $relative);
        }
        return $path;
    }

    private function relative(string $absolute): string
    {
        $prefix = rtrim($this->root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if (!str_starts_with($absolute, $prefix)) {
            throw new RuntimeException('A release file is outside the repository root.');
        }
        return str_replace(DIRECTORY_SEPARATOR, '/', substr($absolute, strlen($prefix)));
    }

    private function fileSha256(string $path): string
    {
        $hash = hash_file('sha256', $path);
        if (!is_string($hash)) {
            throw new RuntimeException('Unable to hash release file: ' . $this->relative($path));
        }
        return strtolower($hash);
    }

    private function fileBytes(string $path): int
    {
        $bytes = filesize($path);
        if (!is_int($bytes) || $bytes < 1) {
            throw new RuntimeException('A release file is empty or unreadable: ' . $this->relative($path));
        }
        return $bytes;
    }
}
