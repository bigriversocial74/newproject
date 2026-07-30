<?php

declare(strict_types=1);

namespace Vp3;

use PDO;
use RuntimeException;

final class Database
{
    private PDO $pdo;
    private int $savepointCounter = 0;

    /** @param array{dsn:string,username:string,password:string,options?:array<int,mixed>} $config */
    public function __construct(array $config)
    {
        if ($config['dsn'] === '') {
            throw new RuntimeException('Database DSN is required.');
        }

        $this->pdo = new PDO(
            $config['dsn'],
            $config['username'],
            $config['password'],
            $config['options'] ?? []
        );
    }

    public function pdo(): PDO
    {
        return $this->pdo;
    }

    /** @template T @param callable(PDO):T $callback @return T */
    public function transaction(callable $callback): mixed
    {
        if (!$this->pdo->inTransaction()) {
            $this->pdo->beginTransaction();

            try {
                $result = $callback($this->pdo);
                $this->pdo->commit();
                return $result;
            } catch (\Throwable $exception) {
                if ($this->pdo->inTransaction()) {
                    $this->pdo->rollBack();
                }
                throw $exception;
            }
        }

        $savepoint = 'vp3_nested_' . (++$this->savepointCounter);
        $this->pdo->exec('SAVEPOINT ' . $savepoint);

        try {
            $result = $callback($this->pdo);
            $this->pdo->exec('RELEASE SAVEPOINT ' . $savepoint);
            return $result;
        } catch (\Throwable $exception) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->exec('ROLLBACK TO SAVEPOINT ' . $savepoint);
                $this->pdo->exec('RELEASE SAVEPOINT ' . $savepoint);
            }
            throw $exception;
        }
    }
}
