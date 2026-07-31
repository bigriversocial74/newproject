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
use Vp3\Security\SecurityAlertPreferenceService;
use Vp3\Security\SecurityAuditService;
use Vp3\Security\SecurityCenterQueryService;
use Vp3\Security\SecurityIncidentAutomationService;
use Vp3\Security\SecurityIncidentResolutionService;
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
    $passwordPlain = 'Phase32-Operations!42';
    $passwordHash = password_hash($passwordPlain, PASSWORD_DEFAULT);
    if (!is_string($passwordHash)) {
        throw new RuntimeException('Unable to hash the Phase 32 operations password.');
    }

    $pdo->prepare(
        "INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at)
         VALUES (:public_id,'organization','active',:display_name,:created_at,:updated_at)"
    )->execute([
        'public_id' => 'P32O-' . substr($suffix, 0, 12),
        'display_name' => 'Phase 32 Security Operations',
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    $accountId = (int) $pdo->lastInsertId();

    $createUser = static function (PDO $pdo, string $suffix, string $label, string $role, int $accountId, string $passwordHash, string $now): array {
        $publicId = 'U32O-' . strtoupper(substr(hash('sha256', $suffix . '|' . $label), 0, 20));
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

    $operationsCipher = new OperationsSecretCipher(base64_encode(random_bytes(32)), 'phase32-operations-policy-test');
    $operationalAudit = new OperationalAuditService($database);
    $notifications = new OperationalNotificationService(
        $database,
        $operationsCipher,
        new NullOperationalNotificationAdapter(),
        $operationalAudit,
        30
    );
    $notifications->saveChannel(
        $accountId,
        'smtp',
        'Phase 32 Security Alerts',
        ['email' => 'security-' . strtolower($suffix) . '@example.test'],
        'warning',
        'REQ-P32O-CHANNEL-' . $suffix
    );
    $operationalIncidents = new OperationalIncidentService($database, $operationalAudit, $notifications);
    $securityAudit = new SecurityAuditService($database);
    $reauthentication = new SecurityReauthenticationService($database);
    $authAudit = new AuthAuditService($database);
    $mfa = new MfaService(
        $database,
        new AuthSecretCipher(base64_encode(random_bytes(32)), 'phase32-operations-auth-test'),
        $authAudit,
        300,
        10
    );
    $proof = new SecurityReauthenticationProofService($database, $mfa, $reauthentication, $securityAudit);
    $preferences = new SecurityAlertPreferenceService($database, $operationalIncidents, $securityAudit);
    $automation = new SecurityIncidentAutomationService($database, $operationalIncidents, $preferences, $securityAudit);
    $response = new SecurityIncidentResponseService(
        $database,
        $operationalIncidents,
        $operationsCipher,
        $reauthentication,
        $securityAudit
    );
    $resolution = new SecurityIncidentResolutionService(
        $database,
        $operationalIncidents,
        $reauthentication,
        $securityAudit
    );

    $disabled = $preferences->save(
        $accountId,
        $owner['id'],
        'customer_owner',
        false,
        'high',
        true,
        false,
        true,
        'REQ-P32O-POLICY-OFF-' . $suffix
    );
    $assert($disabled['automatic_promotion_enabled'] === false, 'Disabled automatic promotion did not persist independently.');
    $assert($disabled['notify_on_emergency_action'] === true, 'Emergency notification preference was lost when automatic promotion was disabled.');
    $expectCode(
        fn () => $preferences->save(
            $accountId,
            $billing['id'],
            'billing_manager',
            true,
            'high',
            true,
            true,
            true,
            'REQ-P32O-POLICY-BILLING-' . $suffix
        ),
        'security_alert_access_denied',
        'A billing manager changed security alert preferences.'
    );

    $highEvent = $securityAudit->record(
        eventType: 'auth.login.anomaly',
        category: 'authentication',
        riskLevel: 'high',
        result: 'denied',
        accountId: $accountId,
        actorType: 'system',
        resourceType: 'user',
        resourcePublicId: $target['public_id'],
        metadata: ['reason' => 'impossible_travel'],
        requestId: 'REQ-P32O-HIGH-' . $suffix
    );
    $disabledRun = $automation->runPass('phase32-disabled-' . $suffix, 20);
    $assert($disabledRun['promoted'] === 0, 'The worker promoted an event while account automation was disabled.');

    $enabledSilent = $preferences->save(
        $accountId,
        $owner['id'],
        'customer_owner',
        true,
        'high',
        true,
        false,
        true,
        'REQ-P32O-POLICY-SILENT-' . $suffix
    );
    $assert($enabledSilent['automatic_promotion_enabled'] === true && $enabledSilent['notify_on_promotion'] === false,
        'Silent automatic promotion policy did not persist.');
    $silentRun = $automation->runPass('phase32-silent-' . $suffix, 20);
    $assert($silentRun['promoted'] === 1 && $silentRun['failed'] === 0, 'Eligible high-risk event was not automatically promoted.');

    $caseStatement = $pdo->prepare(
        'SELECT c.id,c.public_id,c.operational_incident_id,c.case_status
         FROM security_incident_cases c WHERE c.source_audit_event_id=:event_id LIMIT 1'
    );
    $caseStatement->execute(['event_id' => $highEvent['id']]);
    $silentCase = $caseStatement->fetch(PDO::FETCH_ASSOC);
    $assert(is_array($silentCase), 'Automatic promotion did not create a security case.');
    if (!is_array($silentCase)) {
        throw new RuntimeException('Silent automatic case is required for the remaining proof.');
    }
    $queuedSilent = $pdo->prepare('SELECT COUNT(*) FROM operational_notifications WHERE incident_id=:incident');
    $queuedSilent->execute(['incident' => (int) $silentCase['operational_incident_id']]);
    $assert((int) $queuedSilent->fetchColumn() === 0, 'Disabled promotion notifications remained queued.');

    $response->assignCase(
        $accountId,
        $owner['id'],
        'customer_owner',
        (string) $silentCase['public_id'],
        $support['public_id'],
        'REQ-P32O-ASSIGN-' . $suffix
    );
    $noteText = 'Verified the anomalous login evidence, isolated active sessions, and documented containment ownership.';
    $response->addEncryptedNote(
        $accountId,
        $support['id'],
        'support_member',
        (string) $silentCase['public_id'],
        $noteText,
        'REQ-P32O-NOTE-' . $suffix
    );

    $query = new SecurityCenterQueryService($database, $operationsCipher);
    $snapshot = $query->snapshot($accountId, $owner['id'], 'customer_owner', [], 100);
    $matchingCases = array_values(array_filter(
        $snapshot['security_cases'],
        static fn (array $case): bool => (string) $case['public_id'] === (string) $silentCase['public_id']
    ));
    $assert(count($matchingCases) === 1, 'Security Center did not return the promoted case.');
    if ($matchingCases !== []) {
        $assert(($matchingCases[0]['assigned_user_public_id'] ?? null) === $support['public_id'], 'Security Center omitted the assigned responder.');
        $assert(($matchingCases[0]['notes'][0]['content'] ?? null) === $noteText, 'Security Center did not authenticate and decrypt the analyst note.');
    }
    $responderIds = array_column($snapshot['responders'], 'user_public_id');
    $assert(in_array($support['public_id'], $responderIds, true), 'Security Center omitted an eligible support responder.');

    $preferences->save(
        $accountId,
        $owner['id'],
        'customer_owner',
        true,
        'high',
        true,
        true,
        true,
        'REQ-P32O-POLICY-LOUD-' . $suffix
    );
    $criticalEvent = $securityAudit->record(
        eventType: 'integrity.audit_chain.mismatch',
        category: 'integrity',
        riskLevel: 'critical',
        result: 'failure',
        accountId: $accountId,
        actorType: 'system',
        resourceType: 'security_audit_chain',
        resourcePublicId: 'CHAIN-P32O-' . $suffix,
        metadata: ['scope' => $accountId],
        requestId: 'REQ-P32O-CRITICAL-' . $suffix
    );
    $loudRun = $automation->runPass('phase32-loud-' . $suffix, 20);
    $assert($loudRun['promoted'] === 1 && $loudRun['failed'] === 0, 'Critical event was not automatically promoted with alerts enabled.');
    $caseStatement->execute(['event_id' => $criticalEvent['id']]);
    $criticalCase = $caseStatement->fetch(PDO::FETCH_ASSOC);
    $assert(is_array($criticalCase), 'Critical automatic promotion did not create a case.');
    if (!is_array($criticalCase)) {
        throw new RuntimeException('Critical automatic case is required for resolution proof.');
    }
    $queuedLoud = $pdo->prepare('SELECT COUNT(*) FROM operational_notifications WHERE incident_id=:incident AND status=\'queued\'');
    $queuedLoud->execute(['incident' => (int) $criticalCase['operational_incident_id']]);
    $assert((int) $queuedLoud->fetchColumn() > 0, 'Enabled promotion notification did not route through Operations channels.');
    $recursiveRun = $automation->runPass('phase32-recursion-' . $suffix, 20);
    $assert($recursiveRun['promoted'] === 0, 'The automatic worker recursively promoted its own Phase 32 audit receipts.');

    $resolutionSummary = 'The integrity mismatch was validated as contained, the affected sessions were rotated, and chain verification now passes.';
    $resolutionContext = [
        'case_public_id' => (string) $criticalCase['public_id'],
        'resolution_hash' => hash('sha256', $resolutionSummary),
    ];
    $resolutionChallenge = $proof->begin(
        $accountId,
        $owner['id'],
        'customer_owner',
        'security.resolve_incident_case',
        $resolutionContext,
        '203.0.113.88',
        'Phase32-Operations-Agent'
    );
    $proof->complete(
        $accountId,
        $owner['id'],
        'customer_owner',
        'security.resolve_incident_case',
        $resolutionContext,
        $resolutionChallenge['reauthentication_public_id'],
        $resolutionChallenge['challenge'],
        $passwordPlain,
        null,
        null,
        '203.0.113.88',
        'Phase32-Operations-Agent',
        'REQ-P32O-RESOLVE-PROOF-' . $suffix
    );
    $resolved = $resolution->resolve(
        $accountId,
        $owner['id'],
        'customer_owner',
        (string) $criticalCase['public_id'],
        $resolutionSummary,
        $resolutionChallenge['reauthentication_public_id'],
        'REQ-P32O-RESOLVE-' . $suffix
    );
    $assert($resolved, 'Reauthenticated case resolution did not complete.');
    $resolvedState = $pdo->prepare(
        'SELECT c.case_status,i.status AS incident_status
         FROM security_incident_cases c INNER JOIN operational_incidents i ON i.id=c.operational_incident_id
         WHERE c.id=:id'
    );
    $resolvedState->execute(['id' => (int) $criticalCase['id']]);
    $resolvedRow = $resolvedState->fetch(PDO::FETCH_ASSOC) ?: [];
    $assert(($resolvedRow['case_status'] ?? null) === 'resolved' && ($resolvedRow['incident_status'] ?? null) === 'resolved',
        'Case resolution did not close both security and operational incident state.');
    $resolvedReplay = $resolution->resolve(
        $accountId,
        $owner['id'],
        'customer_owner',
        (string) $criticalCase['public_id'],
        $resolutionSummary,
        'SEC-REAUTH-NOT-REQUIRED-FOR-EXACT-REPLAY',
        'REQ-P32O-RESOLVE-' . $suffix
    );
    $assert($resolvedReplay === false, 'Exact case-resolution replay attempted to consume another challenge.');

    $pdo->prepare(
        "INSERT INTO auth_sessions
         (user_id,session_public_id,session_hash,ip_hash,user_agent_hash,last_seen_at,expires_at,
          inactivity_expires_at,absolute_expires_at,rotated_from_public_id,revoked_at,revocation_reason,
          revoked_by_user_id,created_at,updated_at)
         VALUES (:user_id,:public_id,:session_hash,:ip_hash,:user_agent_hash,:last_seen_at,:expires_at,
                 :inactivity_expires_at,:absolute_expires_at,NULL,NULL,NULL,NULL,:created_at,:updated_at)"
    )->execute([
        'user_id' => $target['id'],
        'public_id' => 'SES-P32O-' . $suffix,
        'session_hash' => hash('sha256', 'phase32-operations-session-' . $suffix),
        'ip_hash' => hash('sha256', '203.0.113.89'),
        'user_agent_hash' => hash('sha256', 'Phase32-Operations-Agent'),
        'last_seen_at' => $now,
        'expires_at' => $future,
        'inactivity_expires_at' => $future,
        'absolute_expires_at' => $future,
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    $emergencyContext = [
        'target_user_public_id' => $target['public_id'],
        'case_public_id' => (string) $silentCase['public_id'],
    ];
    $emergencyChallenge = $proof->begin(
        $accountId,
        $owner['id'],
        'customer_owner',
        'security.emergency_revoke_sessions',
        $emergencyContext,
        '203.0.113.89',
        'Phase32-Operations-Agent'
    );
    $proof->complete(
        $accountId,
        $owner['id'],
        'customer_owner',
        'security.emergency_revoke_sessions',
        $emergencyContext,
        $emergencyChallenge['reauthentication_public_id'],
        $emergencyChallenge['challenge'],
        $passwordPlain,
        null,
        null,
        '203.0.113.89',
        'Phase32-Operations-Agent',
        'REQ-P32O-EMERGENCY-PROOF-' . $suffix
    );
    $emergencyRequest = 'REQ-P32O-EMERGENCY-' . $suffix;
    $revoked = $response->emergencyRevokeUserSessions(
        $accountId,
        $owner['id'],
        'customer_owner',
        $target['public_id'],
        (string) $silentCase['public_id'],
        $emergencyChallenge['reauthentication_public_id'],
        $emergencyRequest
    );
    $assert($revoked === 1, 'Emergency response did not revoke the active target session.');
    $preferences->routeEmergencyAction($accountId, $owner['id'], $emergencyRequest);
    $emergencyIncident = $pdo->prepare(
        "SELECT COUNT(*) FROM operational_incidents
         WHERE account_scope=:account AND source_type='security_response_action' AND severity='critical'"
    );
    $emergencyIncident->execute(['account' => $accountId]);
    $assert((int) $emergencyIncident->fetchColumn() === 1, 'Emergency response did not route a critical Operations incident.');

    $preferences->save(
        $accountId,
        $owner['id'],
        'customer_owner',
        false,
        'high',
        true,
        true,
        true,
        'REQ-P32O-POLICY-FINAL-OFF-' . $suffix
    );
    $postDisableEvent = $securityAudit->record(
        eventType: 'auth.login.post_disable_anomaly',
        category: 'authentication',
        riskLevel: 'critical',
        result: 'denied',
        accountId: $accountId,
        actorType: 'system',
        requestId: 'REQ-P32O-POST-DISABLE-' . $suffix
    );
    $postDisableRun = $automation->runPass('phase32-final-disabled-' . $suffix, 20);
    $assert($postDisableRun['promoted'] === 0, 'Disabling automatic promotion did not stop future policy promotion.');
    $caseStatement->execute(['event_id' => $postDisableEvent['id']]);
    $assert($caseStatement->fetch(PDO::FETCH_ASSOC) === false, 'A post-disable event unexpectedly received a security case.');

    $native = $pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES);
    $assert($native === false || $native === 0, 'Phase 32 operations proof did not use native PDO prepares.');

    $pdo->rollBack();
} catch (Throwable $exception) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    $failures[] = $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 32 security operations database failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 32 policy automation, alert routing, Security Center and resolution database certification passed.\n");
