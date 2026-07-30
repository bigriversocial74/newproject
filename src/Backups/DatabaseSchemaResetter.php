<?php

declare(strict_types=1);

namespace Vp3\Backups;

use PDO;
use RuntimeException;
use Throwable;

final class DatabaseSchemaResetter
{
    public function __construct(
        private readonly string $databaseHost,
        private readonly int $databasePort
    ) {
        if (trim($this->databaseHost) === '') {
            throw new RuntimeException('The POD database host is required for schema restoration.');
        }
        if ($this->databasePort < 1 || $this->databasePort > 65535) {
            throw new RuntimeException('The POD database port is invalid for schema restoration.');
        }
    }

    /** @param array<string,mixed> $state */
    public function reset(array $state): void
    {
        $databaseName = trim((string) ($state['database_name'] ?? ''));
        $databaseUsername = trim((string) ($state['database_username'] ?? ''));
        $databasePassword = (string) ($state['database_password'] ?? '');
        if (!preg_match('/^[A-Za-z0-9_]{1,64}$/', $databaseName)
            || $databaseUsername === ''
            || $databasePassword === '') {
            throw new RuntimeException('The POD database state is incomplete for schema restoration.');
        }

        $pdo = new PDO(
            sprintf(
                'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
                $this->databaseHost,
                $this->databasePort,
                $databaseName
            ),
            $databaseUsername,
            $databasePassword,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]
        );

        $pdo->exec('SET FOREIGN_KEY_CHECKS=0');
        try {
            $this->dropEvents($pdo, $databaseName);
            $this->dropRoutines($pdo, $databaseName);
            $this->dropTriggers($pdo, $databaseName);
            $this->dropViews($pdo, $databaseName);
            $this->dropTables($pdo, $databaseName);
        } catch (Throwable $exception) {
            throw new RuntimeException('Unable to reset the tenant database schema before restore.', 0, $exception);
        } finally {
            $pdo->exec('SET FOREIGN_KEY_CHECKS=1');
        }
    }

    private function dropEvents(PDO $pdo, string $databaseName): void
    {
        $query = $pdo->prepare(
            'SELECT EVENT_NAME FROM information_schema.EVENTS WHERE EVENT_SCHEMA=:schema ORDER BY EVENT_NAME'
        );
        $query->execute(['schema' => $databaseName]);
        foreach ($query->fetchAll(PDO::FETCH_COLUMN) as $name) {
            $pdo->exec('DROP EVENT IF EXISTS ' . $this->qualified($databaseName, (string) $name));
        }
    }

    private function dropRoutines(PDO $pdo, string $databaseName): void
    {
        $query = $pdo->prepare(
            'SELECT ROUTINE_NAME,ROUTINE_TYPE FROM information_schema.ROUTINES '
            . 'WHERE ROUTINE_SCHEMA=:schema ORDER BY ROUTINE_TYPE,ROUTINE_NAME'
        );
        $query->execute(['schema' => $databaseName]);
        foreach ($query->fetchAll(PDO::FETCH_ASSOC) as $routine) {
            $name = $this->qualified($databaseName, (string) ($routine['ROUTINE_NAME'] ?? ''));
            $type = strtoupper((string) ($routine['ROUTINE_TYPE'] ?? ''));
            if ($type === 'PROCEDURE') {
                $pdo->exec('DROP PROCEDURE IF EXISTS ' . $name);
            } elseif ($type === 'FUNCTION') {
                $pdo->exec('DROP FUNCTION IF EXISTS ' . $name);
            } else {
                throw new RuntimeException('The tenant database contains an unsupported routine type.');
            }
        }
    }

    private function dropTriggers(PDO $pdo, string $databaseName): void
    {
        $query = $pdo->prepare(
            'SELECT TRIGGER_NAME FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=:schema ORDER BY TRIGGER_NAME'
        );
        $query->execute(['schema' => $databaseName]);
        foreach ($query->fetchAll(PDO::FETCH_COLUMN) as $name) {
            $pdo->exec('DROP TRIGGER IF EXISTS ' . $this->qualified($databaseName, (string) $name));
        }
    }

    private function dropViews(PDO $pdo, string $databaseName): void
    {
        $query = $pdo->prepare(
            "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=:schema AND TABLE_TYPE='VIEW' ORDER BY TABLE_NAME"
        );
        $query->execute(['schema' => $databaseName]);
        $names = $query->fetchAll(PDO::FETCH_COLUMN);
        if ($names !== []) {
            $pdo->exec('DROP VIEW IF EXISTS ' . implode(',', array_map(
                fn (mixed $name): string => $this->qualified($databaseName, (string) $name),
                $names
            )));
        }
    }

    private function dropTables(PDO $pdo, string $databaseName): void
    {
        $query = $pdo->prepare(
            "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=:schema AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME"
        );
        $query->execute(['schema' => $databaseName]);
        $names = $query->fetchAll(PDO::FETCH_COLUMN);
        if ($names !== []) {
            $pdo->exec('DROP TABLE IF EXISTS ' . implode(',', array_map(
                fn (mixed $name): string => $this->qualified($databaseName, (string) $name),
                $names
            )));
        }
    }

    private function qualified(string $databaseName, string $objectName): string
    {
        if ($objectName === '') {
            throw new RuntimeException('A tenant database object name is empty.');
        }
        return $this->identifier($databaseName) . '.' . $this->identifier($objectName);
    }

    private function identifier(string $value): string
    {
        return '`' . str_replace('`', '``', $value) . '`';
    }
}
