<?php

declare(strict_types=1);

use Vp3\Database;
use Vp3\Security\SecurityAuditService;

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
$audit = new SecurityAuditService($database);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

$scope = random_int(700000000, 799999999);
$otherScope = $scope + 100000000;

try {
    $pdo->beginTransaction();

    $first = $audit->record(
        eventType: 'auth.login.denied',
        category: 'authentication',
        riskLevel: 'high',
        result: 'denied',
        accountId: $scope,
        actorType: 'user',
        actorPublicId: 'USR-PHASE30-PROBE',
        resourceType: 'account',
        resourcePublicId: 'ACC-PHASE30-PROBE',
        metadata: [
            'reason' => 'invalid_credentials',
            'password' => 'must-not-persist',
            'nested' => [
                'token' => 'must-not-persist',
                'safe_marker' => 'retained',
            ],
        ],
        requestId: 'REQ-PHASE30-ONE',
        correlationId: 'CORR-PHASE30',
        ipAddress: '203.0.113.10',
        userAgent: 'Phase30-Test-Agent/1.0'
    );

    $second = $audit->record(
        eventType: 'session.revoked',
        category: 'session',
        riskLevel: 'high',
        result: 'success',
        accountId: $scope,
        actorType: 'user',
        actorPublicId: 'USR-PHASE30-PROBE',
        resourceType: 'session',
        resourcePublicId: 'SES-PHASE30-PROBE',
        metadata: ['reason' => 'user_requested'],
        requestId: 'REQ-PHASE30-TWO',
        correlationId: 'CORR-PHASE30',
        ipAddress: '203.0.113.10',
        userAgent: 'Phase30-Test-Agent/1.0'
    );

    $other = $audit->record(
        eventType: 'settings.updated',
        category: 'settings',
        riskLevel: 'info',
        result: 'success',
        accountId: $otherScope,
        actorType: 'system',
        metadata: ['setting' => 'timezone'],
        requestId: 'REQ-PHASE30-OTHER'
    );

    $rows = $pdo->prepare(
        'SELECT * FROM security_audit_events WHERE account_scope=:scope ORDER BY sequence_number ASC'
    );
    $rows->execute(['scope' => $scope]);
    $events = $rows->fetchAll(PDO::FETCH_ASSOC);

    $assert(count($events) === 2, 'The account security audit chain did not retain both events.');
    $assert(($events[0]['sequence_number'] ?? null) === 1 || (int) ($events[0]['sequence_number'] ?? 0) === 1, 'The first account audit sequence is not one.');
    $assert((int) ($events[1]['sequence_number'] ?? 0) === 2, 'The second account audit sequence is not two.');
    $assert((string) ($events[0]['previous_chain_hash'] ?? '') === str_repeat('0', 64), 'The first audit event does not start at the zero hash.');
    $assert(hash_equals((string) ($events[0]['chain_hash'] ?? ''), (string) ($events[1]['previous_chain_hash'] ?? '')), 'The account audit chain is not linked.');
    $assert((string) ($first['chain_hash'] ?? '') === (string) ($events[0]['chain_hash'] ?? ''), 'The first append receipt does not match the stored chain hash.');
    $assert((int) ($second['sequence_number'] ?? 0) === 2, 'The second append receipt lost its sequence number.');
    $assert((int) ($other['sequence_number'] ?? 0) === 1, 'A separate account scope did not start an independent chain.');

    $metadata = json_decode((string) ($events[0]['metadata_json'] ?? '{}'), true, 512, JSON_THROW_ON_ERROR);
    $assert(($metadata['reason'] ?? null) === 'invalid_credentials', 'Safe audit metadata was removed.');
    $assert(($metadata['nested']['safe_marker'] ?? null) === 'retained', 'Nested safe audit metadata was removed.');
    $assert(!array_key_exists('password', $metadata), 'Password metadata reached the audit ledger.');
    $assert(!array_key_exists('token', $metadata['nested'] ?? []), 'Nested token metadata reached the audit ledger.');
    $assert((string) ($events[0]['ip_hash'] ?? '') === hash('sha256', '203.0.113.10'), 'The audit ledger did not privacy-hash the client IP.');
    $assert((string) ($events[0]['user_agent_hash'] ?? '') === hash('sha256', 'Phase30-Test-Agent/1.0'), 'The audit ledger did not privacy-hash the user agent.');
    $assert($audit->verifyScope($scope), 'The intact account audit chain failed verification.');
    $assert($audit->verifyScope($otherScope), 'The intact secondary audit chain failed verification.');

    $originalMetadataHash = (string) $events[1]['metadata_hash'];
    $tamper = $pdo->prepare(
        'UPDATE security_audit_events SET metadata_hash=:tampered WHERE public_id=:public_id'
    );
    $tamper->execute([
        'tampered' => str_repeat('f', 64),
        'public_id' => (string) $events[1]['public_id'],
    ]);
    $assert(!$audit->verifyScope($scope), 'Tampered audit metadata was not detected.');

    $restore = $pdo->prepare(
        'UPDATE security_audit_events SET metadata_hash=:metadata_hash WHERE public_id=:public_id'
    );
    $restore->execute([
        'metadata_hash' => $originalMetadataHash,
        'public_id' => (string) $events[1]['public_id'],
    ]);
    $assert($audit->verifyScope($scope), 'The restored audit chain did not verify.');

    $native = $pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES);
    $assert($native === false || $native === 0, 'Phase 30 database proof did not use native PDO prepares.');

    $pdo->rollBack();
} catch (Throwable $exception) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    $failures[] = $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 30 security audit hardening database failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 30 security audit hardening database certification passed.\n");
require __DIR__ . '/phase30_security_runtime_database_integration.php';
