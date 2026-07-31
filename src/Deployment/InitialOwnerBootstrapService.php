<?php

declare(strict_types=1);

namespace Vp3\Deployment;

use PDO;
use RuntimeException;
use Vp3\Auth\PasswordPolicy;
use Vp3\Database;

final class InitialOwnerBootstrapService
{
    public function __construct(
        private readonly Database $database,
        private readonly PasswordPolicy $passwordPolicy
    ) {
    }

    /** @return array{account_public_id:string,user_public_id:string,email:string,replayed:bool} */
    public function bootstrap(
        string $email,
        string $displayName,
        string $accountName,
        string $password,
        string $requestId
    ): array {
        $email = strtolower(trim($email));
        $displayName = trim($displayName);
        $accountName = trim($accountName);
        $requestId = trim($requestId);

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new RuntimeException('A valid initial owner email address is required.');
        }
        if ($displayName === '' || mb_strlen($displayName) > 190) {
            throw new RuntimeException('The initial owner display name must be between 1 and 190 characters.');
        }
        if ($accountName === '' || mb_strlen($accountName) > 190) {
            throw new RuntimeException('The initial account name must be between 1 and 190 characters.');
        }
        if (!preg_match('/^[A-Za-z0-9._:-]{8,80}$/', $requestId)) {
            throw new RuntimeException('A valid initial owner bootstrap request ID is required.');
        }
        $this->passwordPolicy->assertValid($password);

        return $this->database->transaction(function (PDO $pdo) use (
            $email,
            $displayName,
            $accountName,
            $password,
            $requestId
        ): array {
            $prior = $pdo->prepare(
                "SELECT result FROM platform_deployment_receipts
                 WHERE request_id=:request_id AND action_type='bootstrap_owner' LIMIT 1 FOR UPDATE"
            );
            $prior->execute(['request_id' => $requestId]);
            if ($prior->fetchColumn() === 'success') {
                $existing = $this->singleOwner($pdo);
                if (is_array($existing)
                    && hash_equals(strtolower((string) $existing['email']), $email)
                    && hash_equals((string) $existing['display_name'], $displayName)
                    && hash_equals((string) $existing['account_name'], $accountName)) {
                    return [
                        'account_public_id' => (string) $existing['account_public_id'],
                        'user_public_id' => (string) $existing['user_public_id'],
                        'email' => (string) $existing['email'],
                        'replayed' => true,
                    ];
                }
                throw new RuntimeException('initial_owner_bootstrap_request_conflict');
            }

            $lockAcquired = (int) $pdo->query(
                'SELECT GET_LOCK(\'vp3-initial-owner-bootstrap\',0)'
            )->fetchColumn();
            if ($lockAcquired !== 1) {
                throw new RuntimeException('initial_owner_bootstrap_lock_unavailable');
            }
            try {
                $accountCount = (int) $pdo->query('SELECT COUNT(*) FROM accounts')->fetchColumn();
                $userCount = (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
                if ($accountCount !== 0 || $userCount !== 0) {
                    throw new RuntimeException('initial_owner_bootstrap_not_available');
                }

                $accountPublicId = 'ACC-' . strtoupper(bin2hex(random_bytes(12)));
                $userPublicId = 'USR-' . strtoupper(bin2hex(random_bytes(12)));
                $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                if (!is_string($passwordHash) || $passwordHash === '') {
                    throw new RuntimeException('Unable to hash the initial owner password.');
                }
                $now = gmdate('Y-m-d H:i:s');

                $pdo->prepare(
                    "INSERT INTO accounts
                     (public_id,account_type,status,display_name,legal_name,created_at,updated_at)
                     VALUES (:public_id,'organization','active',:display_name,NULL,:created_at,:updated_at)"
                )->execute([
                    'public_id' => $accountPublicId,
                    'display_name' => $accountName,
                    'created_at' => $now,
                    'updated_at' => $now,
                ]);
                $accountId = (int) $pdo->lastInsertId();

                $pdo->prepare(
                    "INSERT INTO users
                     (public_id,email,email_normalized,password_hash,display_name,status,email_verified_at,
                      last_login_at,created_at,updated_at)
                     VALUES (:public_id,:email,:email_normalized,:password_hash,:display_name,'active',
                      :verified_at,NULL,:created_at,:updated_at)"
                )->execute([
                    'public_id' => $userPublicId,
                    'email' => $email,
                    'email_normalized' => $email,
                    'password_hash' => $passwordHash,
                    'display_name' => $displayName,
                    'verified_at' => $now,
                    'created_at' => $now,
                    'updated_at' => $now,
                ]);
                $userId = (int) $pdo->lastInsertId();

                $pdo->prepare(
                    "INSERT INTO account_users
                     (account_id,user_id,role,status,created_at,updated_at)
                     VALUES (:account_id,:user_id,'customer_owner','active',:created_at,:updated_at)"
                )->execute([
                    'account_id' => $accountId,
                    'user_id' => $userId,
                    'created_at' => $now,
                    'updated_at' => $now,
                ]);

                $evidence = hash('sha256', implode('|', [
                    $accountPublicId,
                    $userPublicId,
                    hash('sha256', $email),
                    $requestId,
                ]));
                $pdo->prepare(
                    "INSERT INTO platform_deployment_receipts
                     (public_id,deployment_run_id,request_id,action_type,result,evidence_hash,created_at)
                     VALUES (:public_id,NULL,:request_id,'bootstrap_owner','success',:evidence_hash,:created_at)"
                )->execute([
                    'public_id' => 'PLATFORM-RECEIPT-' . strtoupper(bin2hex(random_bytes(10))),
                    'request_id' => $requestId,
                    'evidence_hash' => $evidence,
                    'created_at' => $now . '.000000',
                ]);

                return [
                    'account_public_id' => $accountPublicId,
                    'user_public_id' => $userPublicId,
                    'email' => $email,
                    'replayed' => false,
                ];
            } finally {
                $pdo->query('SELECT RELEASE_LOCK(\'vp3-initial-owner-bootstrap\')')->fetchColumn();
            }
        });
    }

    /** @return array<string,mixed>|null */
    private function singleOwner(PDO $pdo): ?array
    {
        $statement = $pdo->query(
            "SELECT a.public_id AS account_public_id,a.display_name AS account_name,
                    u.public_id AS user_public_id,u.email,u.display_name
             FROM account_users au
             INNER JOIN accounts a ON a.id=au.account_id
             INNER JOIN users u ON u.id=au.user_id
             WHERE au.role='customer_owner' AND au.status='active'
               AND a.status='active' AND u.status='active'
             ORDER BY au.id ASC LIMIT 2"
        );
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        return count($rows) === 1 ? $rows[0] : null;
    }
}
