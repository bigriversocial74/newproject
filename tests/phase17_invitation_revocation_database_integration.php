<?php

declare(strict_types=1);

use Vp3\Auth\AuthAuditService;
use Vp3\Auth\AuthPublicException;
use Vp3\Auth\TeamInvitationRevocationService;
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

$accountIds = [];
$userIds = [];
try {
    $suffix = strtoupper(bin2hex(random_bytes(6)));
    $now = gmdate('Y-m-d H:i:s');
    $future = gmdate('Y-m-d H:i:s', time() + 3600);
    $past = gmdate('Y-m-d H:i:s', time() - 60);
    $passwordHash = password_hash('Phase17-Revocation-Password!42', PASSWORD_DEFAULT);
    if (!is_string($passwordHash)) {
        throw new RuntimeException('Unable to hash the test password.');
    }

    $createAccount = static function (string $code, string $name) use ($pdo, $suffix, $now, &$accountIds): int {
        $publicId = 'VP3-' . $suffix . '-' . strtoupper($code);
        $pdo->prepare(
            "INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at)
             VALUES (:public,'organization','active',:name,:created_at,:updated_at)"
        )->execute([
            'public' => $publicId,
            'name' => $name,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        $id = (int) $pdo->lastInsertId();
        $accountIds[] = $id;
        return $id;
    };
    $createUser = static function (string $code, string $email) use ($pdo, $suffix, $now, $passwordHash, &$userIds): array {
        $publicId = 'USR-' . $suffix . '-' . strtoupper($code);
        $pdo->prepare(
            "INSERT INTO users
             (public_id,email,email_normalized,password_hash,display_name,status,email_verified_at,created_at,updated_at)
             VALUES (:public,:email,:normalized,:password_hash,:display_name,'active',:verified_at,:created_at,:updated_at)"
        )->execute([
            'public' => $publicId,
            'email' => $email,
            'normalized' => strtolower($email),
            'password_hash' => $passwordHash,
            'display_name' => 'Phase 17 Owner',
            'verified_at' => $now,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        $id = (int) $pdo->lastInsertId();
        $userIds[] = $id;
        return ['id' => $id, 'public_id' => $publicId, 'email' => $email];
    };
    $addMembership = static function (int $accountId, int $userId, string $role) use ($pdo, $now): void {
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
    $createInvitation = static function (
        int $accountId,
        int $inviterUserId,
        string $publicId,
        string $email,
        string $requestId,
        string $expiresAt
    ) use ($pdo, $now): void {
        $pdo->prepare(
            "INSERT INTO account_invitations
             (public_id,account_id,invited_email,invited_email_normalized,role,token_hash,status,
              invited_by_user_id,accepted_by_user_id,request_id,expires_at,accepted_at,revoked_at,created_at,updated_at)
             VALUES (:public,:account,:email,:normalized,'support_member',:token_hash,'pending',
                     :inviter,NULL,:request,:expires,NULL,NULL,:created_at,:updated_at)"
        )->execute([
            'public' => $publicId,
            'account' => $accountId,
            'email' => $email,
            'normalized' => strtolower($email),
            'token_hash' => hash('sha256', $publicId . '-token'),
            'inviter' => $inviterUserId,
            'request' => $requestId,
            'expires' => $expiresAt,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
    };

    $accountA = $createAccount('A', 'Phase 17 Revocation Primary');
    $accountB = $createAccount('B', 'Phase 17 Revocation Isolated');
    $owner = $createUser('O', 'owner-' . strtolower($suffix) . '@example.test');
    $addMembership($accountA, $owner['id'], 'customer_owner');

    $audit = new AuthAuditService($database);
    $service = new TeamInvitationRevocationService($database, $audit);

    $successInvitation = 'INV-' . strtoupper(bin2hex(random_bytes(10)));
    $successRequest = 'REQ-P17-REV-SUCCESS-' . $suffix;
    $createInvitation(
        $accountA,
        $owner['id'],
        $successInvitation,
        'success-' . strtolower($suffix) . '@example.test',
        'REQ-P17-REV-CREATE-1-' . $suffix,
        $future
    );
    $service->revoke($accountA, $owner['id'], 'customer_owner', $successInvitation, $successRequest);

    $status = $pdo->prepare('SELECT status,revoked_at FROM account_invitations WHERE public_id=:public');
    $status->execute(['public' => $successInvitation]);
    $successRow = $status->fetch(PDO::FETCH_ASSOC);
    $assert(
        is_array($successRow) && $successRow['status'] === 'revoked' && $successRow['revoked_at'] !== null,
        'An authorized owner did not revoke the pending invitation.'
    );

    $receipt = $pdo->prepare(
        "SELECT COUNT(*) FROM account_security_receipts
         WHERE account_id=:account AND actor_user_id=:actor AND action='team.invitation_revoked'
           AND request_id=:request AND result='success'"
    );
    $receipt->execute(['account' => $accountA, 'actor' => $owner['id'], 'request' => $successRequest]);
    $assert((int) $receipt->fetchColumn() === 1, 'Successful invitation revocation receipt did not persist.');

    $service->revoke($accountA, $owner['id'], 'customer_owner', $successInvitation, $successRequest);
    $receipt->execute(['account' => $accountA, 'actor' => $owner['id'], 'request' => $successRequest]);
    $assert((int) $receipt->fetchColumn() === 1, 'Successful invitation revocation replay created duplicate evidence.');

    $staleInvitation = 'INV-' . strtoupper(bin2hex(random_bytes(10)));
    $staleRequest = 'REQ-P17-REV-STALE-' . $suffix;
    $createInvitation(
        $accountA,
        $owner['id'],
        $staleInvitation,
        'stale-' . strtolower($suffix) . '@example.test',
        'REQ-P17-REV-CREATE-2-' . $suffix,
        $future
    );
    $pdo->prepare(
        "UPDATE account_users SET role='support_member',updated_at=UTC_TIMESTAMP()
         WHERE account_id=:account AND user_id=:user"
    )->execute(['account' => $accountA, 'user' => $owner['id']]);
    $expectCode(
        static fn () => $service->revoke(
            $accountA,
            $owner['id'],
            'customer_owner',
            $staleInvitation,
            $staleRequest
        ),
        'team_permission_denied',
        'A stale owner role revoked an invitation.'
    );
    $status->execute(['public' => $staleInvitation]);
    $assert($status->fetchColumn() === 'pending', 'A stale owner role changed the invitation state.');

    $deniedReceipt = $pdo->prepare(
        "SELECT COUNT(*) FROM account_security_receipts
         WHERE account_id=:account AND actor_user_id=:actor AND action='team.invitation_revoked'
           AND request_id=:request AND result='denied'"
    );
    $deniedReceipt->execute(['account' => $accountA, 'actor' => $owner['id'], 'request' => $staleRequest]);
    $assert((int) $deniedReceipt->fetchColumn() === 1, 'Stale-role denial evidence did not persist.');

    $pdo->prepare(
        "UPDATE account_users SET role='customer_owner',status='suspended',updated_at=UTC_TIMESTAMP()
         WHERE account_id=:account AND user_id=:user"
    )->execute(['account' => $accountA, 'user' => $owner['id']]);
    $suspendedInvitation = 'INV-' . strtoupper(bin2hex(random_bytes(10)));
    $suspendedRequest = 'REQ-P17-REV-SUSPENDED-' . $suffix;
    $createInvitation(
        $accountA,
        $owner['id'],
        $suspendedInvitation,
        'suspended-' . strtolower($suffix) . '@example.test',
        'REQ-P17-REV-CREATE-3-' . $suffix,
        $future
    );
    $expectCode(
        static fn () => $service->revoke(
            $accountA,
            $owner['id'],
            'customer_owner',
            $suspendedInvitation,
            $suspendedRequest
        ),
        'team_permission_denied',
        'A suspended owner revoked an invitation.'
    );
    $status->execute(['public' => $suspendedInvitation]);
    $assert($status->fetchColumn() === 'pending', 'A suspended owner changed the invitation state.');

    $pdo->prepare(
        "UPDATE account_users SET status='active',updated_at=UTC_TIMESTAMP()
         WHERE account_id=:account AND user_id=:user"
    )->execute(['account' => $accountA, 'user' => $owner['id']]);
    $isolatedInvitation = 'INV-' . strtoupper(bin2hex(random_bytes(10)));
    $isolatedRequest = 'REQ-P17-REV-ISOLATED-' . $suffix;
    $createInvitation(
        $accountB,
        $owner['id'],
        $isolatedInvitation,
        'isolated-' . strtolower($suffix) . '@example.test',
        'REQ-P17-REV-CREATE-4-' . $suffix,
        $future
    );
    $expectCode(
        static fn () => $service->revoke(
            $accountB,
            $owner['id'],
            'customer_owner',
            $isolatedInvitation,
            $isolatedRequest
        ),
        'team_permission_denied',
        'An owner from another account revoked an isolated invitation.'
    );
    $status->execute(['public' => $isolatedInvitation]);
    $assert($status->fetchColumn() === 'pending', 'Cross-account invitation isolation failed.');

    $expiredInvitation = 'INV-' . strtoupper(bin2hex(random_bytes(10)));
    $expiredRequest = 'REQ-P17-REV-EXPIRED-' . $suffix;
    $createInvitation(
        $accountA,
        $owner['id'],
        $expiredInvitation,
        'expired-' . strtolower($suffix) . '@example.test',
        'REQ-P17-REV-CREATE-5-' . $suffix,
        $past
    );
    $expectCode(
        static fn () => $service->revoke(
            $accountA,
            $owner['id'],
            'customer_owner',
            $expiredInvitation,
            $expiredRequest
        ),
        'team_invitation_invalid',
        'An expired invitation was revoked as pending.'
    );
    $status->execute(['public' => $expiredInvitation]);
    $assert($status->fetchColumn() === 'pending', 'Expired invitation persistence was mutated by revocation.');
    $deniedReceipt->execute(['account' => $accountA, 'actor' => $owner['id'], 'request' => $expiredRequest]);
    $assert((int) $deniedReceipt->fetchColumn() === 1, 'Expired-invitation denial evidence did not persist.');

    $badHashes = $pdo->query(
        "SELECT COUNT(*) FROM account_security_receipts
         WHERE CHAR_LENGTH(evidence_hash)<>64 OR evidence_hash REGEXP '[^0-9a-f]'"
    );
    $assert((int) $badHashes->fetchColumn() === 0, 'Invitation revocation evidence hashes are malformed.');
} catch (Throwable $exception) {
    $failures[] = $exception::class . ': ' . $exception->getMessage();
} finally {
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
        $pdo->prepare("DELETE FROM audit_events WHERE actor_id IN ({$marks})")->execute($userIds);
        $pdo->prepare("DELETE FROM users WHERE id IN ({$marks})")->execute($userIds);
    }
}

if ($failures !== []) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}

echo "Phase 17 invitation revocation authorization integration passed.\n";
