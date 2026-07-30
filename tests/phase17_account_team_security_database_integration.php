<?php

declare(strict_types=1);

use Vp3\Auth\AuthAuditService;
use Vp3\Auth\AuthPublicException;
use Vp3\Auth\AuthSecretCipher;
use Vp3\Auth\DatabaseSessionService;
use Vp3\Auth\Mail\NullMailAdapter;
use Vp3\Auth\MfaService;
use Vp3\Auth\TeamSecurityService;
use Vp3\ControlCenter\AccountSecurityQueryService;
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
$expectAuthCode = static function (callable $operation, string $code, string $message) use (&$failures): void {
    try {
        $operation();
        $failures[] = $message . ' No exception was raised.';
    } catch (AuthPublicException $exception) {
        if ($exception->publicCode() !== $code) {
            $failures[] = $message . ' Received ' . $exception->publicCode() . '.';
        }
    }
};

$base32Decode = static function (string $value): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $clean = strtoupper((string) preg_replace('/[^A-Z2-7]/i', '', $value));
    $bits = '';
    foreach (str_split($clean) as $character) {
        $position = strpos($alphabet, $character);
        if ($position === false) {
            throw new RuntimeException('Invalid base32 secret.');
        }
        $bits .= str_pad(decbin($position), 5, '0', STR_PAD_LEFT);
    }
    $output = '';
    foreach (str_split($bits, 8) as $chunk) {
        if (strlen($chunk) === 8) {
            $output .= chr(bindec($chunk));
        }
    }
    return $output;
};
$totp = static function (string $secret, int $counter) use ($base32Decode): string {
    $key = $base32Decode($secret);
    $binaryCounter = pack('N2', ($counter >> 32) & 0xFFFFFFFF, $counter & 0xFFFFFFFF);
    $hash = hash_hmac('sha1', $binaryCounter, $key, true);
    $offset = ord($hash[19]) & 0x0F;
    $value = ((ord($hash[$offset]) & 0x7F) << 24)
        | ((ord($hash[$offset + 1]) & 0xFF) << 16)
        | ((ord($hash[$offset + 2]) & 0xFF) << 8)
        | (ord($hash[$offset + 3]) & 0xFF);
    return str_pad((string) ($value % 1000000), 6, '0', STR_PAD_LEFT);
};

$accountIds = [];
$userIds = [];
try {
    $token = strtolower(bin2hex(random_bytes(6)));
    $upper = strtoupper($token);
    $now = gmdate('Y-m-d H:i:s');
    $passwordHash = password_hash('Phase17-Strong-Password!42', PASSWORD_DEFAULT);
    if (!is_string($passwordHash)) {
        throw new RuntimeException('Unable to hash test password.');
    }

    $createAccount = static function (string $suffix) use ($pdo, $upper, $now, &$accountIds): int {
        $pdo->prepare(
            "INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at)
             VALUES (:public,'organization','active',:name,:created_at,:updated_at)"
        )->execute([
            'public' => 'VP3-P17-' . $upper . '-' . strtoupper($suffix),
            'name' => 'Phase 17 ' . ucfirst($suffix),
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        $id = (int) $pdo->lastInsertId();
        $accountIds[] = $id;
        return $id;
    };
    $createUser = static function (string $suffix, string $email) use ($pdo, $upper, $now, $passwordHash, &$userIds): array {
        $public = 'USR-P17-' . $upper . '-' . strtoupper($suffix);
        $pdo->prepare(
            "INSERT INTO users
             (public_id,email,email_normalized,password_hash,display_name,status,email_verified_at,created_at,updated_at)
             VALUES (:public,:email,:normalized,:hash,:name,'active',:verified_at,:created_at,:updated_at)"
        )->execute([
            'public' => $public,
            'email' => $email,
            'normalized' => strtolower($email),
            'hash' => $passwordHash,
            'name' => 'Phase 17 ' . ucfirst($suffix),
            'verified_at' => $now,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        $id = (int) $pdo->lastInsertId();
        $userIds[] = $id;
        return ['id' => $id, 'public_id' => $public, 'email' => strtolower($email)];
    };
    $addMember = static function (int $accountId, int $userId, string $role) use ($pdo, $now): void {
        $pdo->prepare(
            "INSERT INTO account_users (account_id,user_id,role,status,created_at,updated_at)
             VALUES (:account,:user,:role,'active',:created_at,:updated_at)"
        )->execute([
            'account' => $accountId,
            'user' => $userId,
            'role' => $role,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
    };

    $accountA = $createAccount('primary');
    $accountB = $createAccount('isolated');
    $owner = $createUser('owner', 'owner-' . $token . '@example.test');
    $admin = $createUser('admin', 'admin-' . $token . '@example.test');
    $wrong = $createUser('wrong', 'wrong-' . $token . '@example.test');
    $invited = $createUser('invited', 'invited-' . $token . '@example.test');
    $expired = $createUser('expired', 'expired-' . $token . '@example.test');
    $addMember($accountA, $owner['id'], 'customer_owner');
    $addMember($accountA, $admin['id'], 'customer_admin');
    $addMember($accountB, $wrong['id'], 'customer_owner');

    $audit = new AuthAuditService($database);
    $mail = new NullMailAdapter();
    $cipher = new AuthSecretCipher(base64_encode(random_bytes(32)), 'phase17-test-key');
    $mfa = new MfaService($database, $cipher, $audit, 300, 8);
    $team = new TeamSecurityService($database, $mail, $audit, 'https://vp3.example.test', 7200);
    $sessions = new DatabaseSessionService($database, 1800, 43200, $audit);

    $encrypted = $cipher->encrypt('PHASE17-SECRET', 'phase17:context:a');
    $assert(
        $encrypted['ciphertext'] !== base64_encode('PHASE17-SECRET')
        && !str_contains($encrypted['ciphertext'], 'PHASE17-SECRET'),
        'Auth secret cipher exposed plaintext.'
    );
    $assert(
        $cipher->decrypt($encrypted['ciphertext'], $encrypted['nonce'], $encrypted['tag'], 'phase17:context:a') === 'PHASE17-SECRET',
        'Auth secret cipher could not decrypt with the correct context.'
    );
    try {
        $cipher->decrypt($encrypted['ciphertext'], $encrypted['nonce'], $encrypted['tag'], 'phase17:context:b');
        $failures[] = 'Auth secret cipher accepted the wrong authenticated context.';
    } catch (RuntimeException) {
    }

    $invite = $team->invite(
        $accountA,
        $owner['id'],
        'customer_owner',
        $invited['email'],
        'support_member',
        'REQ-P17-INVITE-A-' . $upper
    );
    $message = $mail->lastMessage();
    $assert(
        is_array($message) && str_contains($message['text_body'], 'team-invite.php?token='),
        'Invitation delivery did not contain an acceptance token.'
    );
    preg_match('/team-invite\.php\?token=([^\s]+)/', (string) ($message['text_body'] ?? ''), $match);
    $inviteToken = isset($match[1]) ? rawurldecode($match[1]) : '';
    $assert($inviteToken !== '', 'Invitation token could not be recovered from the test mail adapter.');
    $storedTokenHash = $pdo->prepare('SELECT token_hash FROM account_invitations WHERE public_id=:public');
    $storedTokenHash->execute(['public' => $invite['public_id']]);
    $hash = (string) $storedTokenHash->fetchColumn();
    $assert(
        $hash === hash('sha256', $inviteToken) && !hash_equals($hash, $inviteToken),
        'Invitation token was not stored as a one-way hash.'
    );

    $wrongRequest = 'REQ-P17-WRONG-' . $upper;
    $expectAuthCode(
        static fn () => $team->acceptInvitation($wrong['id'], $wrong['email'], $inviteToken, $wrongRequest),
        'team_invitation_email_mismatch',
        'A different verified email accepted an invitation.'
    );
    $deniedInvitation = $pdo->prepare(
        "SELECT COUNT(*) FROM account_security_receipts
         WHERE account_id=:account AND action='team.invitation_accepted'
           AND request_id=:request AND result='denied'"
    );
    $deniedInvitation->execute(['account' => $accountA, 'request' => $wrongRequest]);
    $assert((int) $deniedInvitation->fetchColumn() === 1, 'Invitation email-mismatch evidence did not persist.');

    $acceptedAccount = $team->acceptInvitation(
        $invited['id'],
        $invited['email'],
        $inviteToken,
        'REQ-P17-ACCEPT-' . $upper
    );
    $assert($acceptedAccount === $accountA, 'Invitation acceptance returned the wrong account.');
    $membership = $pdo->prepare(
        'SELECT role,status FROM account_users WHERE account_id=:account AND user_id=:user'
    );
    $membership->execute(['account' => $accountA, 'user' => $invited['id']]);
    $membershipRow = $membership->fetch(PDO::FETCH_ASSOC);
    $assert(
        is_array($membershipRow)
        && $membershipRow['role'] === 'support_member'
        && $membershipRow['status'] === 'active',
        'Invitation acceptance did not create the expected membership.'
    );
    $membership->execute(['account' => $accountB, 'user' => $invited['id']]);
    $assert($membership->fetchColumn() === false, 'Invitation acceptance leaked membership into another account.');
    $expectAuthCode(
        static fn () => $team->acceptInvitation(
            $invited['id'],
            $invited['email'],
            $inviteToken,
            'REQ-P17-REPLAY-' . $upper
        ),
        'team_invitation_invalid',
        'An accepted invitation token was replayed.'
    );

    $expiredInvite = $team->invite(
        $accountA,
        $owner['id'],
        'customer_owner',
        $expired['email'],
        'support_member',
        'REQ-P17-INVITE-X-' . $upper
    );
    $expiredMessage = $mail->lastMessage();
    preg_match('/team-invite\.php\?token=([^\s]+)/', (string) ($expiredMessage['text_body'] ?? ''), $expiredMatch);
    $expiredToken = isset($expiredMatch[1]) ? rawurldecode($expiredMatch[1]) : '';
    $pdo->prepare(
        'UPDATE account_invitations SET expires_at=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 MINUTE) WHERE public_id=:public'
    )->execute(['public' => $expiredInvite['public_id']]);
    $expiredRequest = 'REQ-P17-EXPIRED-' . $upper;
    $expectAuthCode(
        static fn () => $team->acceptInvitation($expired['id'], $expired['email'], $expiredToken, $expiredRequest),
        'team_invitation_invalid',
        'An expired invitation was accepted.'
    );
    $expiredState = $pdo->prepare('SELECT status FROM account_invitations WHERE public_id=:public');
    $expiredState->execute(['public' => $expiredInvite['public_id']]);
    $assert($expiredState->fetchColumn() === 'expired', 'Expired invitation status was not persisted.');
    $deniedInvitation->execute(['account' => $accountA, 'request' => $expiredRequest]);
    $assert((int) $deniedInvitation->fetchColumn() === 1, 'Expired invitation denial evidence did not persist.');

    $expectAuthCode(
        static fn () => $team->changeRole(
            $accountA,
            $owner['id'],
            'customer_owner',
            $owner['public_id'],
            'customer_admin',
            'REQ-P17-FINAL-' . $upper
        ),
        'team_final_owner_required',
        'The final active owner was demoted.'
    );
    $session = $sessions->create($admin['id'], '192.0.2.17', 'Phase17-Test-Agent');
    $team->changeRole(
        $accountA,
        $owner['id'],
        'customer_owner',
        $admin['public_id'],
        'customer_owner',
        'REQ-P17-PROMOTE-' . $upper
    );
    $team->setMembershipStatus(
        $accountA,
        $owner['id'],
        'customer_owner',
        $admin['public_id'],
        'suspended',
        'REQ-P17-SUSPEND-' . $upper
    );
    $revoked = $pdo->prepare(
        'SELECT revoked_at,revocation_reason FROM auth_sessions WHERE session_public_id=:public'
    );
    $revoked->execute(['public' => $session['public_id']]);
    $revokedRow = $revoked->fetch(PDO::FETCH_ASSOC);
    $assert(
        is_array($revokedRow)
        && $revokedRow['revoked_at'] !== null
        && $revokedRow['revocation_reason'] === 'membership_suspended',
        'Suspending a member did not revoke active sessions.'
    );

    $enrollment = $mfa->beginEnrollment(
        $owner['id'],
        $owner['email'],
        'Phase 17 Owner',
        'REQ-P17-MFA-BEGIN-' . $upper
    );
    $storedMethod = $pdo->prepare(
        'SELECT secret_ciphertext,secret_nonce,secret_tag,secret_key_id FROM auth_mfa_methods WHERE user_id=:user'
    );
    $storedMethod->execute(['user' => $owner['id']]);
    $methodRow = $storedMethod->fetch(PDO::FETCH_ASSOC);
    $assert(
        is_array($methodRow)
        && !str_contains((string) $methodRow['secret_ciphertext'], $enrollment['secret'])
        && $methodRow['secret_key_id'] === 'phase17-test-key',
        'MFA enrollment did not store encrypted key-identified secret evidence.'
    );

    $counter = intdiv(time(), 30);
    $validCodes = [
        $totp($enrollment['secret'], $counter - 1),
        $totp($enrollment['secret'], $counter),
        $totp($enrollment['secret'], $counter + 1),
    ];
    $invalidEnrollCode = '000000';
    foreach (['000000','111111','222222','333333','444444','555555','666666','777777','888888','999999'] as $candidate) {
        if (!in_array($candidate, $validCodes, true)) {
            $invalidEnrollCode = $candidate;
            break;
        }
    }
    $invalidEnrollRequest = 'REQ-P17-MFA-DENIED-' . $upper;
    $expectAuthCode(
        static fn () => $mfa->confirmEnrollment($owner['id'], $invalidEnrollCode, $invalidEnrollRequest),
        'mfa_code_invalid',
        'Invalid MFA enrollment code was accepted.'
    );
    $enrollmentDenied = $pdo->prepare(
        "SELECT COUNT(*) FROM account_security_receipts
         WHERE actor_user_id=:user AND action='mfa.enrollment_confirmed'
           AND request_id=:request AND result='denied'"
    );
    $enrollmentDenied->execute(['user' => $owner['id'], 'request' => $invalidEnrollRequest]);
    $assert((int) $enrollmentDenied->fetchColumn() === 1, 'Denied MFA enrollment evidence did not persist.');

    $confirmation = $mfa->confirmEnrollment(
        $owner['id'],
        $validCodes[1],
        'REQ-P17-MFA-CONFIRM-' . $upper
    );
    $assert(
        $confirmation['enabled'] === true && count($confirmation['recovery_codes']) === 8,
        'MFA enrollment did not return the configured recovery codes.'
    );
    $recoveryCode = $confirmation['recovery_codes'][0];

    $bindingChallenge = $mfa->createChallenge($owner['id'], '198.51.100.17', 'Phase17-MFA-Agent');
    $expectAuthCode(
        static fn () => $mfa->completeChallenge(
            $bindingChallenge['challenge_token'],
            $recoveryCode,
            '198.51.100.18',
            'Phase17-MFA-Agent',
            'REQ-P17-MFA-BIND-' . $upper
        ),
        'mfa_challenge_invalid',
        'MFA challenge accepted a different IP binding.'
    );
    $bindingState = $pdo->prepare(
        'SELECT consumed_at FROM auth_mfa_challenges WHERE public_id=:public'
    );
    $bindingState->execute(['public' => $bindingChallenge['challenge_public_id']]);
    $assert($bindingState->fetchColumn() !== null, 'A binding-mismatched MFA challenge was not consumed.');

    $recoveryChallenge = $mfa->createChallenge($owner['id'], '198.51.100.17', 'Phase17-MFA-Agent');
    $completedUser = $mfa->completeChallenge(
        $recoveryChallenge['challenge_token'],
        $recoveryCode,
        '198.51.100.17',
        'Phase17-MFA-Agent',
        'REQ-P17-MFA-RECOVERY-' . $upper
    );
    $assert($completedUser['id'] === $owner['id'], 'Recovery-code challenge returned the wrong user.');
    $recoveryUsed = $pdo->prepare(
        'SELECT used_at FROM auth_mfa_recovery_codes WHERE user_id=:user AND code_hash=:hash'
    );
    $recoveryUsed->execute([
        'user' => $owner['id'],
        'hash' => hash('sha256', str_replace('-', '', $recoveryCode)),
    ]);
    $assert($recoveryUsed->fetchColumn() !== null, 'Recovery code was not consumed.');

    $reuseChallenge = $mfa->createChallenge($owner['id'], '198.51.100.17', 'Phase17-MFA-Agent');
    $reuseRequest = 'REQ-P17-MFA-REUSE-' . $upper;
    $expectAuthCode(
        static fn () => $mfa->completeChallenge(
            $reuseChallenge['challenge_token'],
            $recoveryCode,
            '198.51.100.17',
            'Phase17-MFA-Agent',
            $reuseRequest
        ),
        'mfa_code_invalid',
        'A consumed recovery code was reused.'
    );
    $challengeDenied = $pdo->prepare(
        "SELECT COUNT(*) FROM account_security_receipts
         WHERE actor_user_id=:user AND action='mfa.challenge_completed'
           AND request_id=:request AND result='denied'"
    );
    $challengeDenied->execute(['user' => $owner['id'], 'request' => $reuseRequest]);
    $assert((int) $challengeDenied->fetchColumn() === 1, 'Denied recovery-code replay evidence did not persist.');

    $totpReplayChallenge = $mfa->createChallenge($owner['id'], '198.51.100.17', 'Phase17-MFA-Agent');
    $expectAuthCode(
        static fn () => $mfa->completeChallenge(
            $totpReplayChallenge['challenge_token'],
            $validCodes[1],
            '198.51.100.17',
            'Phase17-MFA-Agent',
            'REQ-P17-MFA-TOTP-REPLAY-' . $upper
        ),
        'mfa_code_invalid',
        'The TOTP code used for enrollment was replayed.'
    );

    $totpChallenge = $mfa->createChallenge($owner['id'], '198.51.100.17', 'Phase17-MFA-Agent');
    $totpUser = $mfa->completeChallenge(
        $totpChallenge['challenge_token'],
        $validCodes[2],
        '198.51.100.17',
        'Phase17-MFA-Agent',
        'REQ-P17-MFA-TOTP-' . $upper
    );
    $assert($totpUser['id'] === $owner['id'], 'A fresh TOTP challenge returned the wrong user.');
    $totpSecondReplay = $mfa->createChallenge($owner['id'], '198.51.100.17', 'Phase17-MFA-Agent');
    $expectAuthCode(
        static fn () => $mfa->completeChallenge(
            $totpSecondReplay['challenge_token'],
            $validCodes[2],
            '198.51.100.17',
            'Phase17-MFA-Agent',
            'REQ-P17-MFA-TOTP-REPLAY2-' . $upper
        ),
        'mfa_code_invalid',
        'A TOTP code was accepted twice.'
    );

    $lockChallenge = $mfa->createChallenge($owner['id'], '203.0.113.17', 'Phase17-Lock-Agent');
    for ($attempt = 1; $attempt <= 5; $attempt++) {
        $expectAuthCode(
            static fn () => $mfa->completeChallenge(
                $lockChallenge['challenge_token'],
                'not-a-code',
                '203.0.113.17',
                'Phase17-Lock-Agent',
                'REQ-P17-MFA-LOCK-' . $upper . '-' . $attempt
            ),
            'mfa_code_invalid',
            'MFA challenge locked before the configured attempt limit.'
        );
    }
    $expectAuthCode(
        static fn () => $mfa->completeChallenge(
            $lockChallenge['challenge_token'],
            'not-a-code',
            '203.0.113.17',
            'Phase17-Lock-Agent',
            'REQ-P17-MFA-LOCK-' . $upper . '-6'
        ),
        'mfa_challenge_locked',
        'MFA challenge did not lock at max_attempts.'
    );
    $lockState = $pdo->prepare(
        'SELECT attempt_count,max_attempts,consumed_at FROM auth_mfa_challenges WHERE public_id=:public'
    );
    $lockState->execute(['public' => $lockChallenge['challenge_public_id']]);
    $lockRow = $lockState->fetch(PDO::FETCH_ASSOC);
    $assert(
        is_array($lockRow)
        && (int) $lockRow['attempt_count'] === (int) $lockRow['max_attempts']
        && $lockRow['consumed_at'] !== null,
        'MFA attempt locking did not persist the terminal challenge state.'
    );
    $expectAuthCode(
        static fn () => $mfa->completeChallenge(
            $lockChallenge['challenge_token'],
            'not-a-code',
            '203.0.113.17',
            'Phase17-Lock-Agent',
            'REQ-P17-MFA-LOCK-' . $upper . '-7'
        ),
        'mfa_challenge_invalid',
        'A locked MFA challenge accepted another attempt.'
    );

    $query = new AccountSecurityQueryService($database, $mfa);
    $ownerSnapshot = $query->snapshot($accountA, $owner['id'], 'customer_owner', 'missing-current-session');
    $supportSnapshot = $query->snapshot($accountA, $invited['id'], 'support_member', 'missing-current-session');
    $assert(
        $ownerSnapshot['can_manage_team'] === true
        && count($ownerSnapshot['members']) >= 3
        && count($ownerSnapshot['invitations']) >= 2,
        'Owner security overview omitted authorized team information.'
    );
    $assert(
        $supportSnapshot['can_manage_team'] === false
        && count($supportSnapshot['members']) === 1
        && $supportSnapshot['members'][0]['current_user'] === true
        && $supportSnapshot['invitations'] === [],
        'Support-member security overview leaked team information.'
    );

    $receiptIntegrity = $pdo->query(
        "SELECT COUNT(*) FROM account_security_receipts
         WHERE CHAR_LENGTH(evidence_hash)<>64 OR evidence_hash REGEXP '[^0-9a-f]'"
    );
    $assert((int) $receiptIntegrity->fetchColumn() === 0, 'Security receipt evidence hashes are malformed.');
} catch (Throwable $exception) {
    $failures[] = $exception::class . ': ' . $exception->getMessage();
} finally {
    if ($userIds !== []) {
        $marks = implode(',', array_fill(0, count($userIds), '?'));
        foreach (['auth_mfa_recovery_codes','auth_mfa_challenges','auth_mfa_methods','auth_session_events','auth_sessions'] as $table) {
            $pdo->prepare("DELETE FROM {$table} WHERE user_id IN ({$marks})")->execute($userIds);
        }
        $pdo->prepare(
            "DELETE FROM account_security_receipts
             WHERE actor_user_id IN ({$marks}) OR target_user_id IN ({$marks})"
        )->execute([...$userIds, ...$userIds]);
        $pdo->prepare("DELETE FROM audit_events WHERE actor_id IN ({$marks})")->execute($userIds);
    }
    if ($accountIds !== []) {
        $marks = implode(',', array_fill(0, count($accountIds), '?'));
        $pdo->prepare("DELETE FROM account_security_receipts WHERE account_id IN ({$marks})")->execute($accountIds);
        $pdo->prepare("DELETE FROM audit_events WHERE account_id IN ({$marks})")->execute($accountIds);
        $pdo->prepare("DELETE FROM account_invitations WHERE account_id IN ({$marks})")->execute($accountIds);
        $pdo->prepare("DELETE FROM account_users WHERE account_id IN ({$marks})")->execute($accountIds);
        $pdo->prepare("DELETE FROM accounts WHERE id IN ({$marks})")->execute($accountIds);
    }
    if ($userIds !== []) {
        $marks = implode(',', array_fill(0, count($userIds), '?'));
        $pdo->prepare("DELETE FROM users WHERE id IN ({$marks})")->execute($userIds);
    }
}

if ($failures !== []) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}
echo "Phase 17 account, team, MFA, invitation and session integration passed.\n";
