<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\Database;
use Vp3\Infrastructure\InfrastructureControlCenterQueueService;

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
$expectCode = static function (callable $operation, string $code, string $message) use (&$failures): void {
    try {
        $operation();
        $failures[] = $message . ' No exception was raised.';
    } catch (AuthPublicException $exception) {
        if ($exception->publicCode() !== $code) {
            $failures[] = $message . ' Received ' . $exception->publicCode() . '.';
        }
    }
};

try {
    $account = $pdo->query(
        "SELECT id
         FROM accounts
         WHERE public_id LIKE 'VP3-P20-%-ALPHA'
         ORDER BY id DESC
         LIMIT 1"
    )->fetchColumn();
    $accountId = (int) $account;
    if ($accountId < 1) {
        throw new RuntimeException('The Phase 20 primary database fixture must run before serialization proof.');
    }

    $membership = $pdo->prepare(
        "SELECT au.user_id,au.role
         FROM account_users au
         WHERE au.account_id=:account
           AND au.status='active'
           AND au.role='customer_owner'
         ORDER BY au.user_id
         LIMIT 1"
    );
    $membership->execute(['account' => $accountId]);
    $actor = $membership->fetch(PDO::FETCH_ASSOC);
    if (!is_array($actor)) {
        throw new RuntimeException('The Phase 20 owner fixture was not found.');
    }

    $bindingStatement = $pdo->prepare(
        'SELECT id,public_id
         FROM infrastructure_bindings
         WHERE account_id=:account
         ORDER BY id DESC
         LIMIT 1'
    );
    $bindingStatement->execute(['account' => $accountId]);
    $binding = $bindingStatement->fetch(PDO::FETCH_ASSOC);
    if (!is_array($binding)) {
        throw new RuntimeException('The Phase 20 infrastructure binding fixture was not found.');
    }

    $service = new InfrastructureControlCenterQueueService($database);
    $suffix = strtoupper(bin2hex(random_bytes(6)));

    $expectCode(
        fn () => $service->enqueue(
            $accountId,
            (int) $actor['user_id'],
            (string) $actor['role'],
            (string) $binding['public_id'],
            'reconcile',
            '',
            'REQ-P20-SERIAL-BLOCK-' . $suffix,
            'IDEM-P20-SERIAL-BLOCK-' . $suffix
        ),
        'infrastructure_operation_open',
        'A second binding operation was queued while an operation remained open.'
    );

    $pdo->prepare(
        "UPDATE provider_operations
         SET status='completed',current_stage='completed',completed_at=COALESCE(completed_at,UTC_TIMESTAMP()),
             locked_at=NULL,locked_by=NULL,locked_until=NULL,lease_token=NULL,updated_at=UTC_TIMESTAMP()
         WHERE account_id=:account AND binding_id=:binding AND status NOT IN ('completed','canceled')"
    )->execute([
        'account' => $accountId,
        'binding' => $binding['id'],
    ]);

    $queued = $service->enqueue(
        $accountId,
        (int) $actor['user_id'],
        (string) $actor['role'],
        (string) $binding['public_id'],
        'reconcile',
        '',
        'REQ-P20-SERIAL-QUEUE-' . $suffix,
        'IDEM-P20-SERIAL-QUEUE-' . $suffix
    );
    $replay = $service->enqueue(
        $accountId,
        (int) $actor['user_id'],
        (string) $actor['role'],
        (string) $binding['public_id'],
        'reconcile',
        '',
        'REQ-P20-SERIAL-REPLAY-' . $suffix,
        'IDEM-P20-SERIAL-QUEUE-' . $suffix
    );
    $assert($queued['replayed'] === false && $replay['replayed'] === true,
        'Serialized infrastructure queue replay is incorrect.');
    $assert($queued['public_id'] === $replay['public_id'],
        'Serialized infrastructure replay changed operation identity.');

    $operationIdStatement = $pdo->prepare(
        'SELECT id FROM provider_operations WHERE public_id=:public AND account_id=:account'
    );
    $operationIdStatement->execute(['public' => $queued['public_id'], 'account' => $accountId]);
    $operationId = (int) $operationIdStatement->fetchColumn();
    $stepCount = $pdo->prepare(
        'SELECT COUNT(*) FROM provider_operation_steps WHERE operation_id=:operation'
    );
    $stepCount->execute(['operation' => $operationId]);
    $assert((int) $stepCount->fetchColumn() === 4,
        'Serialized reconcile queue omitted the certified four-stage pipeline.');

    $expectCode(
        fn () => $service->enqueue(
            $accountId,
            (int) $actor['user_id'],
            (string) $actor['role'],
            (string) $binding['public_id'],
            'teardown',
            'TEARDOWN',
            'REQ-P20-SERIAL-TEARDOWN-' . $suffix,
            'IDEM-P20-SERIAL-TEARDOWN-' . $suffix
        ),
        'infrastructure_operation_open',
        'Teardown was queued while reconciliation remained open.'
    );

    $openCount = $pdo->prepare(
        "SELECT COUNT(*)
         FROM provider_operations
         WHERE account_id=:account AND binding_id=:binding
           AND status NOT IN ('completed','canceled')"
    );
    $openCount->execute(['account' => $accountId, 'binding' => $binding['id']]);
    $assert((int) $openCount->fetchColumn() === 1,
        'More than one infrastructure operation remained open for the binding.');
} catch (Throwable $exception) {
    $failures[] = 'Unhandled Phase 20 serialization exception: ' . $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 20 operation serialization failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 20 operation serialization certification passed.\n");
