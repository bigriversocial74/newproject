<?php

declare(strict_types=1);

use Vp3\Auth\AuthAuditService;
use Vp3\Auth\AuthPublicException;
use Vp3\Auth\AuthSecretCipher;
use Vp3\Auth\MfaService;
use Vp3\Database;
use Vp3\Operations\NullOperationalNotificationAdapter;
use Vp3\Operations\OperationalAuditService;
use Vp3\Operations\OperationalIncidentService;
use Vp3\Operations\OperationalNotificationService;
use Vp3\Operations\OperationsSecretCipher;
use Vp3\Security\SecurityAuditService;
use Vp3\Security\SecurityIncidentResponseService;
use Vp3\Security\SecurityReauthenticationProofService;
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
    $future = gmdate('Y-m-d H:i:s', time() + 3600);
    $passwordPlain = 'Phase32-Security-Response!42';
    $passwordHash = password_hash($passwordPlain, PASSWORD_DEFAULT);
    if (!is_string($passwordHash)) {
        throw new RuntimeException('Unable to hash the Phase 32 test password.');
    }

    $pdo->prepare(
        "INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at)
         VALUES (:public_id,'organization','active',:display_name,:created_at,:updated_at)"
    )->execute([
        'public_id' => 'P32-' . substr($suffix, 0, 12),
        'display_name' => 'Phase 32 Security Response',
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    $accountId = (int) $pdo->lastInsertId();

    $createUser = static function (PDO $pdo, string $suffix, string $label, string $role, int $accountId, string $passwordHash, string $now): array {
        $publicId = 'U32-' . substr(hash('sha256', $suffix . '|' . $label), 0, 20);
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
             VALUES (:account_id,:user_id,:role,'active',:created_at,:updated_at)"
        )->execute([
            'account_id' => $accountId,
            'user_id' => $id,
            'role' => $role,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        return ['id' => $id, 'public_id' => $publicId];
    };

    $owner = $createUser($pdo, $suffix, 'owner', 'customer_owner', $accountId, $passwordHash, $now);
    $support = $createUser($pdo, $suffix, 'support', 'support_member', $accountId, $passwordHash, $now);
    $target = $createUser($pdo, $suffix, 'target', 'support_member', $accountId, $passwordHash, $now);
    $billing = $createUser($pdo, $suffix, 'billing', 'billing_manager', $accountId, $passwordHash, $now);

    $operationsCipher = new OperationsSecretCipher(base64_encode(random_bytes(32)), 'phase32-operations-test');
    $operationalAudit = new OperationalAuditService($database);
    $notifications = new OperationalNotificationService(
        $database,
        $operationsCipher,
        new NullOperationalNotificationAdapter(),
        $operationalAudit,
        30
    );
    $operationalIncidents = new OperationalIncidentService($database, $operationalAudit, $notifications);
    $securityAudit = new SecurityAuditService($database);
    $reauthentication = new SecurityReauthenticationService($database);
    $authAudit = new AuthAuditService($database);
    $mfa = new MfaService(
        $database,
        new AuthSecretCipher(base64_encode(random_bytes(32)), 'phase32-auth-test'),
        $authAudit,
        300,
        10
    );
    $proof = new SecurityReauthenticationProofService($database, $mfa, $reauthentication, $securityAudit);
    $response = new SecurityIncidentResponseService(
        $database,
        $operationalIncidents,
        $operationsCipher,
        $reauthentication,
        $securityAudit
    );

    $highEvent = $securityAudit->record(
        eventType: 'integrity.request.denied',
        category: 'integrity',
        riskLevel: 'high',
        result: 'denied',
        accountId: $accountId,
        actorType: 'system',
        resourceType: 'request',
        resourcePublicId: 'REQ-P32-' . $suffix,
        metadata: ['reason' => 'cross_site'],
        requestId: 'REQ-P32-EVENT-' . $suffix
    );
    $case = $response->promoteAuditEvent(
        $accountId,
        $owner['id'],
        'customer_owner',
        $highEvent['public_id'],
        'REQ-P32-PROMOTE-' . $suffix
    );
    $assert(preg_match('/^SEC-CASE-[A-F0-9]{20}$/', $case['case_public_id']) === 1, 'Security event promotion did not create a bounded case identity.');
    $assert(preg_match('/^OPS-INC-[A-F0-9]{20}$/', $case['incident_public_id']) === 1, 'Security event promotion did not create an operational incident.');
    $assert($case['status'] === 'triage' && $case['replayed'] === false, 'New security case did not enter triage.');

    $replay = $response->promoteAuditEvent(
        $accountId,
        $owner['id'],
        'customer_owner',
        $highEvent['public_id'],
        'REQ-P32-PROMOTE-' . $suffix
    );
    $assert($replay['replayed'] === true && $replay['case_public_id'] === $case['case_public_id'], 'Security event promotion was not request-idempotent.');

    $response->assignCase(
        $accountId,
        $owner['id'],
        'customer_owner',
        $case['case_public_id'],
        $support['public_id'],
        'REQ-P32-ASSIGN-' . $suffix
    );
    $storedCase = $pdo->prepare('SELECT id,case_status,assigned_user_id FROM security_incident_cases WHERE public_id=:public_id');
    $storedCase->execute(['public_id' => $case['case_public_id']]);
    $storedCaseRow = $storedCase->fetch(PDO::FETCH_ASSOC);
    $assert(is_array($storedCaseRow) && (int) $storedCaseRow['assigned_user_id'] === $support['id'] && $storedCaseRow['case_status'] === 'investigating', 'Security case assignment did not persist or start investigation.');

    $notePlaintext = 'Investigated the source event and isolated the affected session set.';
    $note = $response->addEncryptedNote(
        $accountId,
        $support['id'],
        'support_member',
        $case['case_public_id'],
        $notePlaintext,
        'REQ-P32-NOTE-' . $suffix
    );
    $storedNote = $pdo->prepare('SELECT * FROM security_incident_notes WHERE public_id=:public_id');
    $storedNote->execute(['public_id' => $note['note_public_id']]);
    $storedNoteRow = $storedNote->fetch(PDO::FETCH_ASSOC);
    $assert(is_array($storedNoteRow), 'Encrypted security incident note did not persist.');
    if (is_array($storedNoteRow)) {
        $assert(!str_contains((string) $storedNoteRow['note_ciphertext'], $notePlaintext), 'Security incident note plaintext leaked into ciphertext storage.');
        $decrypted = $operationsCipher->decrypt(
            (string) $storedNoteRow['note_ciphertext'],
            (string) $storedNoteRow['note_nonce'],
            (string) $storedNoteRow['note_tag'],
            'security-incident-note|' . $accountId . '|' . $case['case_public_id'] . '|' . $note['note_public_id']
        );
        $assert($decrypted === $notePlaintext, 'Encrypted security incident note did not authenticate and decrypt correctly.');
        $assert(hash_equals((string) $storedNoteRow['note_hash'], hash('sha256', $notePlaintext)), 'Security incident note hash is incorrect.');
    }

    $lowEvent = $securityAudit->record(
        eventType: 'settings.viewed',
        category: 'settings',
        riskLevel: 'info',
        result: 'success',
        accountId: $accountId,
        actorType: 'account_user',
        actorId: $owner['id'],
        requestId: 'REQ-P32-LOW-' . $suffix
    );
    $expectCode(
        fn () => $response->promoteAuditEvent($accountId, $owner['id'], 'customer_owner', $lowEvent['public_id'], 'REQ-P32-LOW-PROMOTE-' . $suffix),
        'security_event_not_escalatable',
        'A low-risk successful event was promoted into an incident.'
    );
    $expectCode(
        fn () => $response->promoteAuditEvent($accountId, $billing['id'], 'billing_manager', $highEvent['public_id'], 'REQ-P32-BILLING-' . $suffix),
        'security_response_access_denied',
        'A billing manager promoted a security event.'
    );

    $insertSession = $pdo->prepare(
        "INSERT INTO auth_sessions
         (user_id,session_public_id,session_hash,ip_hash,user_agent_hash,last_seen_at,expires_at,
          inactivity_expires_at,absolute_expires_at,rotated_from_public_id,revoked_at,revocation_reason,
          revoked_by_user_id,created_at,updated_at)
         VALUES (:user_id,:public_id,:session_hash,:ip_hash,:user_agent_hash,:last_seen_at,:expires_at,
                 :inactivity_expires_at,:absolute_expires_at,NULL,NULL,NULL,NULL,:created_at,:updated_at)"
    );
    foreach (['A', 'B'] as $index) {
        $insertSession->execute([
            'user_id' => $target['id'],
            'public_id' => 'SES-P32-' . $index . '-' . $suffix,
            'session_hash' => hash('sha256', 'phase32-session-' . $index . '-' . $suffix),
            'ip_hash' => hash('sha256', '203.0.113.42'),
            'user_agent_hash' => hash('sha256', 'Phase32-Test-Agent'),
            'last_seen_at' => $now,
            'expires_at' => $future,
            'inactivity_expires_at' => $future,
            'absolute_expires_at' => $future,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
    }

    $reauthContext = ['target_user_public_id' => $target['public_id'], 'case_public_id' => $case['case_public_id']];
    $challenge = $proof->begin(
        $accountId,
        $owner['id'],
        'customer_owner',
        'security.emergency_revoke_sessions',
        $reauthContext,
        '203.0.113.42',
        'Phase32-Test-Agent'
    );
    $assert($challenge['mfa_required'] === false, 'Password-only fixture unexpectedly required MFA.');
    $expectCode(
        fn () => $proof->complete(
            $accountId,
            $owner['id'],
            'customer_owner',
            'security.emergency_revoke_sessions',
            $reauthContext,
            $challenge['reauthentication_public_id'],
            $challenge['challenge'],
            'wrong-password',
            null,
            null,
            '203.0.113.42',
            'Phase32-Test-Agent',
            'REQ-P32-REAUTH-DENY-' . $suffix
        ),
        'password_invalid',
        'Emergency reauthentication accepted an invalid password.'
    );
    $proof->complete(
        $accountId,
        $owner['id'],
        'customer_owner',
        'security.emergency_revoke_sessions',
        $reauthContext,
        $challenge['reauthentication_public_id'],
        $challenge['challenge'],
        $passwordPlain,
        null,
        null,
        '203.0.113.42',
        'Phase32-Test-Agent',
        'REQ-P32-REAUTH-' . $suffix
    );
    $revoked = $response->emergencyRevokeUserSessions(
        $accountId,
        $owner['id'],
        'customer_owner',
        $target['public_id'],
        $case['case_public_id'],
        $challenge['reauthentication_public_id'],
        'REQ-P32-REVOKE-' . $suffix
    );
    $assert($revoked === 2, 'Emergency response did not revoke every active target session.');
    $revokedSessions = $pdo->prepare(
        'SELECT COUNT(*) AS total,
                SUM(revocation_reason=\'security_incident_response\') AS correct_reason,
                SUM(revoked_by_user_id=:actor) AS correct_actor
         FROM auth_sessions WHERE user_id=:target AND revoked_at IS NOT NULL'
    );
    $revokedSessions->execute(['actor' => $owner['id'], 'target' => $target['id']]);
    $revokedSummary = $revokedSessions->fetch(PDO::FETCH_ASSOC) ?: [];
    $assert((int) ($revokedSummary['total'] ?? 0) === 2, 'Emergency response left active target sessions.');
    $assert((int) ($revokedSummary['correct_reason'] ?? 0) === 2, 'Emergency session revocation reason is incorrect.');
    $assert((int) ($revokedSummary['correct_actor'] ?? 0) === 2, 'Emergency session revocation did not preserve the acting owner.');

    $contained = $pdo->prepare('SELECT case_status FROM security_incident_cases WHERE public_id=:public_id');
    $contained->execute(['public_id' => $case['case_public_id']]);
    $assert($contained->fetchColumn() === 'contained', 'Emergency session revocation did not contain the linked security case.');

    try {
        $response->emergencyRevokeUserSessions(
            $accountId,
            $owner['id'],
            'customer_owner',
            $target['public_id'],
            $case['case_public_id'],
            $challenge['reauthentication_public_id'],
            'REQ-P32-REVOKE-REUSE-' . $suffix
        );
        $failures[] = 'A consumed emergency reauthentication challenge was reused.';
    } catch (RuntimeException) {
    }

    $assert($pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES) === false || $pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES) === 0, 'Phase 32 database proof did not use native PDO prepares.');
    $pdo->rollBack();
} catch (Throwable $exception) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    $failures[] = $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 32 security incident automation database failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 32 security incident promotion, encrypted notes, reauthentication and emergency session response passed.\n");
