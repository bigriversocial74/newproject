<?php

declare(strict_types=1);

use Vp3\Database;

$root = dirname(__DIR__);
$autoload = $root . '/vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
} else {
    spl_autoload_register(static function (string $class) use ($root): void {
        $prefix = 'Vp3\\';
        if (!str_starts_with($class, $prefix)) {
            return;
        }
        $path = $root . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($path)) {
            require $path;
        }
    });
}

$dsn = getenv('VP3_TEST_DSN') ?: '';
if ($dsn === '') {
    fwrite(STDERR, "VP3_TEST_DSN is required.\n");
    exit(1);
}
$database = new Database([
    'dsn' => $dsn,
    'username' => getenv('VP3_TEST_DB_USER') ?: 'root',
    'password' => getenv('VP3_TEST_DB_PASSWORD') ?: '',
    'options' => [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ],
]);
$pdo = $database->pdo();
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};
$exists = static function (string $publicId) use ($pdo): bool {
    $statement = $pdo->prepare('SELECT COUNT(*) FROM accounts WHERE public_id=:public');
    $statement->execute(['public' => $publicId]);
    return (int) $statement->fetchColumn() === 1;
};

try {
    $suffix = strtoupper(bin2hex(random_bytes(6)));
    $now = gmdate('Y-m-d H:i:s');
    $outerKept = 'VP3-P21-NEST-KEEP-' . $suffix;
    $innerRolledBack = 'VP3-P21-NEST-INNER-' . $suffix;
    $outerRolledBack = 'VP3-P21-NEST-OUTER-' . $suffix;
    $innerRolledBackWithOuter = 'VP3-P21-NEST-OUTER-INNER-' . $suffix;
    $successOuter = 'VP3-P21-NEST-SUCCESS-' . $suffix;
    $successInner = 'VP3-P21-NEST-SUCCESS-INNER-' . $suffix;

    $insert = static function (PDO $connection, string $publicId, string $now): void {
        $connection->prepare(
            "INSERT INTO accounts
             (public_id,account_type,status,display_name,created_at,updated_at)
             VALUES (:public,'organization','active',:name,:created,:updated)"
        )->execute([
            'public' => $publicId,
            'name' => $publicId,
            'created' => $now,
            'updated' => $now,
        ]);
    };

    $database->transaction(function (PDO $connection) use (
        $database,
        $insert,
        $outerKept,
        $innerRolledBack,
        $now
    ): void {
        $insert($connection, $outerKept, $now);
        try {
            $database->transaction(function (PDO $nested) use ($insert, $innerRolledBack, $now): void {
                $insert($nested, $innerRolledBack, $now);
                throw new RuntimeException('Expected nested savepoint rollback.');
            });
        } catch (RuntimeException $exception) {
            if ($exception->getMessage() !== 'Expected nested savepoint rollback.') {
                throw $exception;
            }
        }
    });
    $assert($exists($outerKept), 'Outer transaction did not commit after a caught nested rollback.');
    $assert(!$exists($innerRolledBack), 'Nested savepoint failure leaked writes into the outer commit.');

    try {
        $database->transaction(function (PDO $connection) use (
            $database,
            $insert,
            $outerRolledBack,
            $innerRolledBackWithOuter,
            $now
        ): void {
            $insert($connection, $outerRolledBack, $now);
            $database->transaction(function (PDO $nested) use ($insert, $innerRolledBackWithOuter, $now): void {
                $insert($nested, $innerRolledBackWithOuter, $now);
            });
            throw new RuntimeException('Expected outer rollback.');
        });
    } catch (RuntimeException $exception) {
        if ($exception->getMessage() !== 'Expected outer rollback.') {
            throw $exception;
        }
    }
    $assert(!$exists($outerRolledBack), 'Outer rollback leaked its own write.');
    $assert(!$exists($innerRolledBackWithOuter), 'Outer rollback did not include successful nested work.');

    $database->transaction(function (PDO $connection) use (
        $database,
        $insert,
        $successOuter,
        $successInner,
        $now
    ): void {
        $insert($connection, $successOuter, $now);
        $database->transaction(function (PDO $nested) use ($insert, $successInner, $now): void {
            $insert($nested, $successInner, $now);
        });
    });
    $assert($exists($successOuter) && $exists($successInner), 'Successful nested transaction did not commit atomically.');

    $cleanup = $pdo->prepare('DELETE FROM accounts WHERE public_id IN (?,?,?,?,?,?)');
    $cleanup->execute([
        $outerKept,
        $innerRolledBack,
        $outerRolledBack,
        $innerRolledBackWithOuter,
        $successOuter,
        $successInner,
    ]);
} catch (Throwable $exception) {
    $failures[] = 'Unhandled nested transaction exception: ' . $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 21 nested transaction failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 21 nested transaction certification passed.\n");
