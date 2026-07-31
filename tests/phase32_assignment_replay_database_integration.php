<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\Database;
use Vp3\Operations\NullOperationalNotificationAdapter;
use Vp3\Operations\OperationalAuditService;
use Vp3\Operations\OperationalIncidentService;
use Vp3\Operations\OperationalNotificationService;
use Vp3\Operations\OperationsSecretCipher;
use Vp3\Security\SecurityAuditService;
use Vp3\Security\SecurityIncidentResponseService;
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
    $pdo->beginTransaction();
    $suffix = strtoupper(bin2hex(random_bytes(5)));
    $now = gmdate('Y-m-d H:i:s');
    $passwordHash = password_hash('Phase32-Assignment!42', PASSWORD_DEFAULT);
    if (!is_string($passwordHash)) {
        throw new RuntimeException('Unable to hash the assignment test password.');
    }

    $pdo->prepare(
        "INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at)
         VALUES (:public_id,'organization','active',:display_name,:created_at,:updated_at)"
    )->execute([
        'public_id' => 'P32A-' . $suffix,
        'display_name' => 'Phase 32 Assignment Replay',
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    $accountId = (int) $pdo->lastInsertId();

    $createUser = static function (
        PDO $pdo,
        int $accountId,
        string $suffix,
        string $label,
        string $role,
        string $passwordHash,
        string $now
    ): array {
        $publicId = 'U32A-' . strtoupper(substr(hash('sha256', $suffix . '|' . $label), 0, 20));
        $email = strtolower($label . '-' . $suffix . '@example.test');
        $pdo->prepare(
            "INSERT INTO users
             (public_id,email,email_normalized,password_hash,display_name,status,email_verified_at,created_at,updated_at)
             VALUES (:public_id,:email,:email_normalized,:password_hash,:display_name,'active',:verified_at,:created_at,:updated_at)"
        )->execute([
            'public_id' => $publicId,
            'email' => $email,
            'email_normalized' => $email,
            'password_hash' => $passwordHash,
            'display_name' => 'Phase 32 ' . ucfirst($label),
            'verified_at' => $now,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        $id = (int) $pdo->lastInsertId();
        $pdo->prepare(
            "INSERT INTO account_users (account_id,user_id,role,status,created_at,updated_at)
             VALUES (:account,:user,:role,'active',:created,:updated)"
        )->execute([
            'account' => $accountId,
            'user' => $id,
            'role' => $role,
            'created' => $now,
            'updated' => $now,
        ]);
        return ['id' => $id, 'public_id' => $publicId];
    };

    $owner = $createUser($pdo, $accountId, $suffix, 'owner', 'customer_owner', $passwordHash, $now);
    $supportA = $createUser($pdo, $accountId, $suffix, 'support-a', 'support_member', $passwordHash, $now);
    $supportB = $createUser($pdo, $accountId, $suffix, 'support-b', 'support_member', $passwordHash, $now);

    $operationsCipher = new OperationsSecretCipher(base64_encode(random_bytes(32)), 'phase32-assignment-test');
    $operationalAudit = new OperationalAuditService($database);
    $notifications = new OperationalNotificationService(
        $database,
        $operationsCipher,
        new NullOperationalNotificationAdapter(),
        $operationalAudit,
        30
    );
    $incidents = new OperationalIncidentService($database, $operationalAudit, $notifications);
    $audit = new SecurityAuditService($database);
    $response = new SecurityIncidentResponseService(
        $database,
        $incidents,
        $operationsCipher,
        new SecurityReauthenticationService($database),
        $audit
    );

    $event = $audit->record(
        eventType: 'auth.login.assignment_test',
        category: 'authentication',
        riskLevel: 'high',
        result: 'denied',
        accountId: $accountId,
        actorType: 'system',
        requestId: 'REQ-P32A-EVENT-' . $suffix
    );
    $promotion = $response->promoteAuditEvent(
        $accountId,
        $owner['id'],
        'customer_owner',
        $event['public_id'],
        'REQ-P32A-PROMOTE-' . $suffix
    );
    $requestId = 'REQ-P32A-ASSIGN-' . $suffix;
    $assigned = $response->assignCase(
        $accountId,
        $owner['id'],
        'customer_owner',
        $promotion['case_public_id'],
        $supportA['public_id'],
        $requestId
    );
    $assert($assigned, 'The first valid case assignment was not applied.');

    $exactReplay = $response->assignCase(
        $accountId,
        $owner['id'],
        'customer_owner',
        $promotion['case_public_id'],
        $supportA['public_id'],
        $requestId
    );
    $assert($exactReplay === false, 'An exact assignment replay was applied a second time.');

    $expectCode(
        fn () => $response->assignCase(
            $accountId,
            $owner['id'],
            'customer_owner',
            $promotion['case_public_id'],
            $supportB['public_id'],
            $requestId
        ),
        'security_response_request_conflict',
        'A reused assignment request ID selected a different responder.'
    );

    $assignmentReceipts = $pdo->prepare(
        "SELECT COUNT(*) FROM security_response_actions
         WHERE account_scope=:account AND request_id=:request_id AND action_type='assign_case'"
    );
    $assignmentReceipts->execute(['account' => $accountId, 'request_id' => $requestId]);
    $assert((int) $assignmentReceipts->fetchColumn() === 1, 'Assignment replay created duplicate immutable receipts.');

    $pdo->prepare(
        "UPDATE security_incident_cases SET case_status='resolved' WHERE public_id=:public_id AND account_scope=:account"
    )->execute(['public_id' => $promotion['case_public_id'], 'account' => $accountId]);
    $expectCode(
        fn () => $response->assignCase(
            $accountId,
            $owner['id'],
            'customer_owner',
            $promotion['case_public_id'],
            $supportB['public_id'],
            'REQ-P32A-RESOLVED-' . $suffix
        ),
        'security_case_resolved',
        'A resolved security case was reassigned.'
    );

    $native = $pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES);
    $assert($native === false || $native === 0, 'Assignment replay proof did not use native PDO prepares.');
    $pdo->rollBack();
} catch (Throwable $exception) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    $failures[] = $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 32 assignment replay database failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 32 assignment replay and conflict database certification passed.\n");
