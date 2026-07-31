<?php

declare(strict_types=1);

use Vp3\Database;
use Vp3\Security\SecurityAuditExportService;
use Vp3\Security\SecurityAuditQueryService;
use Vp3\Security\SecurityAuditService;
use Vp3\Security\SecurityRateLimitService;
use Vp3\Security\SecurityReauthenticationService;

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
$query = new SecurityAuditQueryService($database);
$export = new SecurityAuditExportService($database, $query);
$reauth = new SecurityReauthenticationService($database);
$rateLimit = new SecurityRateLimitService($database);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

$scope = random_int(810000000, 819999999);
$ownerId = random_int(820000000, 829999999);
$limitedId = $ownerId + 1;

try {
    $pdo->beginTransaction();

    $audit->record(
        eventType: 'billing.plan.changed',
        category: 'billing',
        riskLevel: 'medium',
        result: 'success',
        accountId: $scope,
        actorType: 'user',
        actorId: $ownerId,
        actorPublicId: 'USR-P30-OWNER',
        resourceType: 'subscription',
        resourcePublicId: 'SUB-P30',
        metadata: ['plan' => 'business'],
        requestId: 'REQ-P30-BILLING'
    );
    $audit->record(
        eventType: 'settings.timezone.updated',
        category: 'settings',
        riskLevel: 'info',
        result: 'success',
        accountId: $scope,
        actorType: 'user',
        actorId: $limitedId,
        actorPublicId: 'USR-P30-LIMITED',
        resourceType: 'settings',
        resourcePublicId: 'SET-P30',
        metadata: ['timezone' => 'America/Phoenix'],
        requestId: 'REQ-P30-SETTINGS'
    );
    $audit->record(
        eventType: 'integrity.request.denied',
        category: 'integrity',
        riskLevel: 'high',
        result: 'denied',
        accountId: $scope,
        actorType: 'system',
        resourceType: 'request',
        resourcePublicId: 'REQ-P30-DENIED',
        metadata: ['reason' => 'cross_site'],
        requestId: 'REQ-P30-INTEGRITY'
    );

    $ownerSnapshot = $query->snapshot($scope, $ownerId, 'customer_owner');
    $assert(count($ownerSnapshot['events']) === 3, 'Customer owner did not receive the complete account audit history.');
    $assert(($ownerSnapshot['summary']['high_or_critical'] ?? 0) === 1, 'Security dashboard risk summary is incorrect.');
    $assert(($ownerSnapshot['summary']['integrity_events'] ?? 0) === 1, 'Security dashboard integrity summary is incorrect.');
    $assert($ownerSnapshot['chain_valid'] === true, 'Security dashboard reported an intact chain as invalid.');

    $billingSnapshot = $query->snapshot($scope, $limitedId, 'billing_manager');
    $billingTypes = array_column($billingSnapshot['events'], 'event_type');
    sort($billingTypes);
    $assert($billingTypes === ['billing.plan.changed', 'settings.timezone.updated'], 'Billing visibility escaped its billing-or-own-event boundary.');

    $supportSnapshot = $query->snapshot($scope, $limitedId, 'support_member');
    $assert(count($supportSnapshot['events']) === 1 && ($supportSnapshot['events'][0]['event_type'] ?? '') === 'settings.timezone.updated', 'Support visibility escaped its own-actor boundary.');

    $csv = $export->build($scope, $ownerId, 'customer_owner', 'csv', ['risk_level' => 'high']);
    $assert($csv['row_count'] === 1, 'Protected CSV export ignored its risk filter.');
    $assert(str_contains($csv['content'], 'integrity.request.denied'), 'Protected CSV export omitted the selected event.');
    $assert(hash_equals($csv['content_hash'], hash('sha256', $csv['content'])), 'Protected export content hash does not match the returned content.');

    $exportReceipt = $pdo->prepare('SELECT status,row_count,content_hash FROM security_audit_exports WHERE public_id=:public_id');
    $exportReceipt->execute(['public_id' => $csv['public_id']]);
    $receipt = $exportReceipt->fetch(PDO::FETCH_ASSOC);
    $assert(is_array($receipt) && $receipt['status'] === 'ready' && (int) $receipt['row_count'] === 1, 'Protected export receipt was not finalized.');

    try {
        $export->build($scope, $limitedId, 'support_member', 'jsonl');
        $failures[] = 'Support role created a full account audit export.';
    } catch (RuntimeException) {
    }

    $context = ['operation' => 'delete_domain', 'resource' => 'DOM-P30'];
    $challenge = $reauth->issue($scope, $ownerId, 'domain.delete', $context, 300);
    $assert(!$reauth->satisfy($challenge['public_id'], $challenge['challenge'], $scope, $ownerId, 'domain.delete', ['operation' => 'wrong']), 'Reauthentication accepted the wrong action context.');
    $assert($reauth->satisfy($challenge['public_id'], $challenge['challenge'], $scope, $ownerId, 'domain.delete', $context), 'Valid reauthentication challenge was rejected.');
    $reauth->consume($challenge['public_id'], $scope, $ownerId, 'domain.delete', $context);
    try {
        $reauth->consume($challenge['public_id'], $scope, $ownerId, 'domain.delete', $context);
        $failures[] = 'A consumed reauthentication challenge was reused.';
    } catch (RuntimeException) {
    }

    $scopeKey = '203.0.113.55';
    $firstAttempt = $rateLimit->registerAttempt('ip', $scopeKey, 'auth.login', 2, 60, 120, 'REQ-P30-RATE-1');
    $secondAttempt = $rateLimit->registerAttempt('ip', $scopeKey, 'auth.login', 2, 60, 120, 'REQ-P30-RATE-2');
    $thirdAttempt = $rateLimit->registerAttempt('ip', $scopeKey, 'auth.login', 2, 60, 120, 'REQ-P30-RATE-3');
    $blockedAttempt = $rateLimit->registerAttempt('ip', $scopeKey, 'auth.login', 2, 60, 120, 'REQ-P30-RATE-4');
    $assert($firstAttempt['allowed'] && $secondAttempt['allowed'], 'Rate limiter denied attempts before the configured threshold.');
    $assert(!$thirdAttempt['allowed'] && $thirdAttempt['retry_after'] === 120, 'Rate limiter did not block at the configured threshold.');
    $assert(!$blockedAttempt['allowed'] && $blockedAttempt['retry_after'] > 0, 'Rate limiter did not retain the active block.');
    $assert($thirdAttempt['bucket_hash'] === hash('sha256', 'ip|auth.login|' . $scopeKey), 'Rate-limit bucket identity is not privacy hashed deterministically.');
    $rateLimit->clear('ip', $scopeKey, 'auth.login');
    $afterClear = $rateLimit->registerAttempt('ip', $scopeKey, 'auth.login', 2, 60, 120, 'REQ-P30-RATE-5');
    $assert($afterClear['allowed'] && $afterClear['attempt_count'] === 1, 'Clearing a rate-limit bucket did not reset enforcement.');

    $native = $pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES);
    $assert($native === false || $native === 0, 'Phase 30 runtime proof did not use native PDO prepares.');

    $pdo->rollBack();
} catch (Throwable $exception) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    $failures[] = $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 30 security runtime database failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 30 security query, export, reauthentication and rate-limit database certification passed.\n");
