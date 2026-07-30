<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\Database;
use Vp3\Recovery\RecoveryControlCenterActionService;
use Vp3\Recovery\RecoveryControlCenterQueryService;

$root = dirname(__DIR__);
$autoload = $root . '/vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
} else {
    spl_autoload_register(static function (string $class) use ($root): void {
        $prefix = 'Vp3\\';
        if (!str_starts_with($class, $prefix)) return;
        $path = $root . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($path)) require $path;
    });
}

$dsn = getenv('VP3_TEST_DSN') ?: '';
if ($dsn === '') { fwrite(STDERR, "VP3_TEST_DSN is required.\n"); exit(1); }
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
$assert = static function (bool $condition, string $message) use (&$failures): void { if (!$condition) $failures[] = $message; };
$expectCode = static function (callable $operation, string $code, string $message) use (&$failures): void {
    try { $operation(); $failures[] = $message . ' No exception was raised.'; }
    catch (AuthPublicException $exception) { if ($exception->publicCode() !== $code) $failures[] = $message . ' Received ' . $exception->publicCode() . '.'; }
};

$accountIds = [];
$userIds = [];
$releaseId = null;
$productInserted = false;
$productId = null;
try {
    $suffix = strtoupper(bin2hex(random_bytes(5)));
    $token = strtolower($suffix);
    $now = gmdate('Y-m-d H:i:s');
    $periodEnd = gmdate('Y-m-d H:i:s', time() + 2592000);
    $planId = (int) $pdo->query("SELECT id FROM plans WHERE code='standard' LIMIT 1")->fetchColumn();
    if ($planId < 1) throw new RuntimeException('VP3 Standard plan seed is missing.');
    $passwordHash = password_hash('Phase19-Recovery-Test!42', PASSWORD_DEFAULT);
    if (!is_string($passwordHash)) throw new RuntimeException('Unable to hash test password.');

    $createAccount = static function (string $label) use ($pdo, $suffix, $now, &$accountIds): int {
        $pdo->prepare("INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at) VALUES (:public_id,'organization','active',:display_name,:created_at,:updated_at)")
            ->execute(['public_id' => 'P19-' . $suffix . '-' . strtoupper(substr($label, 0, 2)), 'display_name' => 'Phase 19 ' . ucfirst($label), 'created_at' => $now, 'updated_at' => $now]);
        $id = (int) $pdo->lastInsertId(); $accountIds[] = $id; return $id;
    };
    $createUser = static function (string $label) use ($pdo, $suffix, $now, $passwordHash, &$userIds): int {
        $email = strtolower($label . '-' . $suffix . '@example.test');
        $pdo->prepare("INSERT INTO users (public_id,email,email_normalized,password_hash,display_name,status,email_verified_at,created_at,updated_at) VALUES (:public_id,:email,:email_normalized,:password_hash,:display_name,'active',:verified_at,:created_at,:updated_at)")
            ->execute(['public_id' => 'U19-' . substr($suffix, 0, 6) . '-' . strtoupper(substr(hash('sha256', $label), 0, 8)), 'email' => $email, 'email_normalized' => $email, 'password_hash' => $passwordHash, 'display_name' => 'Phase 19 ' . ucfirst($label), 'verified_at' => $now, 'created_at' => $now, 'updated_at' => $now]);
        $id = (int) $pdo->lastInsertId(); $userIds[] = $id; return $id;
    };
    $membership = static function (int $accountId, int $userId, string $role) use ($pdo, $now): void {
        $pdo->prepare("INSERT INTO account_users (account_id,user_id,role,status,created_at,updated_at) VALUES (:account_id,:user_id,:role,'active',:created_at,:updated_at)")
            ->execute(['account_id' => $accountId, 'user_id' => $userId, 'role' => $role, 'created_at' => $now, 'updated_at' => $now]);
    };
    $createPod = static function (int $accountId, string $label) use ($pdo, $token, $suffix, $now, $periodEnd, $planId): array {
        $upper = strtoupper(substr($suffix, 0, 7) . '-' . strtoupper(substr($label, 0, 2)));
        $pdo->prepare("INSERT INTO subscriptions (public_id,account_id,plan_id,status,starts_at,current_period_starts_at,current_period_ends_at,created_at,updated_at) VALUES (:public_id,:account_id,:plan_id,'active',:starts_at,:period_start,:period_end,:created_at,:updated_at)")
            ->execute(['public_id' => 'SUB19-' . $upper, 'account_id' => $accountId, 'plan_id' => $planId, 'starts_at' => $now, 'period_start' => $now, 'period_end' => $periodEnd, 'created_at' => $now, 'updated_at' => $now]);
        $subscriptionId = (int) $pdo->lastInsertId();
        $hostname = 'p19-' . $token . '-' . $label . '.vp3.me';
        $pdo->prepare("INSERT INTO domain_registrations (public_id,account_id,subscription_id,label,hostname,status,routing_status,ssl_status,registered_at,renews_at,expires_at,created_at,updated_at) VALUES (:public_id,:account_id,:subscription_id,:label,:hostname,'active','active','active',:registered_at,:renews_at,:expires_at,:created_at,:updated_at)")
            ->execute(['public_id' => 'DOM19-' . $upper, 'account_id' => $accountId, 'subscription_id' => $subscriptionId, 'label' => 'p19-' . $token . '-' . $label, 'hostname' => $hostname, 'registered_at' => $now, 'renews_at' => $periodEnd, 'expires_at' => $periodEnd, 'created_at' => $now, 'updated_at' => $now]);
        $domainId = (int) $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO entitlement_bundles (public_id,account_id,subscription_id,domain_registration_id,plan_id,snapshot_hash,created_at,updated_at) VALUES (:public_id,:account_id,:subscription_id,:domain_id,:plan_id,:snapshot_hash,:created_at,:updated_at)")
            ->execute(['public_id' => 'BUN19-' . $upper, 'account_id' => $accountId, 'subscription_id' => $subscriptionId, 'domain_id' => $domainId, 'plan_id' => $planId, 'snapshot_hash' => hash('sha256', 'bundle-' . $upper), 'created_at' => $now, 'updated_at' => $now]);
        $bundleId = (int) $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO licenses (public_id,account_id,subscription_id,domain_registration_id,entitlement_bundle_id,product_type,status,starts_at,renews_at,expires_at,created_at,updated_at) VALUES (:public_id,:account_id,:subscription_id,:domain_id,:bundle_id,'pod','active',:starts_at,:renews_at,:expires_at,:created_at,:updated_at)")
            ->execute(['public_id' => 'LIC19-' . $upper, 'account_id' => $accountId, 'subscription_id' => $subscriptionId, 'domain_id' => $domainId, 'bundle_id' => $bundleId, 'starts_at' => $now, 'renews_at' => $periodEnd, 'expires_at' => $periodEnd, 'created_at' => $now, 'updated_at' => $now]);
        $licenseId = (int) $pdo->lastInsertId();
        $podPublic = 'POD19-' . $upper;
        $pdo->prepare("INSERT INTO pod_deployments (public_id,account_id,subscription_id,domain_registration_id,license_id,status,installation_fingerprint,installed_version,update_channel,storage_usage_bytes,storage_allowance_bytes,last_heartbeat_at,routing_status,ssl_status,backup_status,license_status,activated_at,created_at,updated_at) VALUES (:public_id,:account_id,:subscription_id,:domain_id,:license_id,'active',:fingerprint,'19.0.0','stable',268435456,1073741824,:heartbeat,'active','active','verified','active',:activated_at,:created_at,:updated_at)")
            ->execute(['public_id' => $podPublic, 'account_id' => $accountId, 'subscription_id' => $subscriptionId, 'domain_id' => $domainId, 'license_id' => $licenseId, 'fingerprint' => hash('sha256', 'pod-' . $upper), 'heartbeat' => $now, 'activated_at' => $now, 'created_at' => $now, 'updated_at' => $now]);
        return ['id' => (int) $pdo->lastInsertId(), 'public_id' => $podPublic, 'hostname' => $hostname];
    };

    $accountA = $createAccount('alpha'); $accountB = $createAccount('bravo');
    $ownerA = $createUser('owner-a'); $adminA = $createUser('admin-a'); $supportA = $createUser('support-a'); $ownerB = $createUser('owner-b');
    $membership($accountA, $ownerA, 'customer_owner'); $membership($accountA, $adminA, 'customer_admin'); $membership($accountA, $supportA, 'support_member'); $membership($accountB, $ownerB, 'customer_owner');
    $podA = $createPod($accountA, 'alpha'); $podB = $createPod($accountB, 'bravo');

    $productId = (int) $pdo->query("SELECT id FROM software_products WHERE target_type='pod' LIMIT 1")->fetchColumn();
    if ($productId < 1) {
        $pdo->prepare("INSERT INTO software_products (public_id,code,name,target_type,status,created_at,updated_at) VALUES (:public_id,:code,'VP3 POD','pod','active',:created_at,:updated_at)")
            ->execute(['public_id' => 'PROD19-' . $suffix, 'code' => 'pod-p19-' . $token, 'created_at' => $now, 'updated_at' => $now]);
        $productId = (int) $pdo->lastInsertId(); $productInserted = true;
    }
    $releasePublic = 'REL19-' . $suffix;
    $releaseVersion = '19.0.' . (1000 + hexdec(substr($suffix, 0, 4)));
    $pdo->prepare("INSERT INTO software_releases (public_id,product_id,version,channel,status,release_notes_hash,manifest_hash,manifest_signature,signature_algorithm,signing_key_id,emergency_override,published_at,created_at,updated_at) VALUES (:public_id,:product_id,:version,'stable','published',:notes_hash,:manifest_hash,:manifest_signature,'ed25519','phase19-key',0,:published_at,:created_at,:updated_at)")
        ->execute(['public_id' => $releasePublic, 'product_id' => $productId, 'version' => $releaseVersion, 'notes_hash' => hash('sha256', 'notes-' . $suffix), 'manifest_hash' => hash('sha256', 'manifest-' . $suffix), 'manifest_signature' => base64_encode(random_bytes(64)), 'published_at' => $now, 'created_at' => $now, 'updated_at' => $now]);
    $releaseId = (int) $pdo->lastInsertId();
    $pdo->prepare("INSERT INTO release_rollouts (release_id,status,percentage,cohort_seed,starts_at,created_at,updated_at) VALUES (:release_id,'active',100,:cohort_seed,:starts_at,:created_at,:updated_at)")
        ->execute(['release_id' => $releaseId, 'cohort_seed' => 'phase19-' . $suffix, 'starts_at' => $now, 'created_at' => $now, 'updated_at' => $now]);
    $pdo->prepare("INSERT INTO release_compatibility_rules (release_id,minimum_current_version,maximum_current_version,database_family,created_at) VALUES (:release_id,'19.0.0','19.0.9','any',:created_at)")
        ->execute(['release_id' => $releaseId, 'created_at' => $now]);

    $query = new RecoveryControlCenterQueryService($database);
    $actions = new RecoveryControlCenterActionService($database);

    $policy = $actions->savePolicy($accountA, $ownerA, 'customer_owner', $podA['public_id'], 1440, 14, 30, 'REQ-P19-POL-' . $suffix);
    $assert(str_starts_with($policy['public_id'], 'BACKUP-POLICY-'), 'Backup policy did not return a public ID.');
    $backup = $actions->enqueueBackup($accountA, $adminA, 'customer_admin', $podA['public_id'], 'REQ-P19-BACK-' . $suffix, 'IDEM-P19-BACK-' . $suffix);
    $replay = $actions->enqueueBackup($accountA, $adminA, 'customer_admin', $podA['public_id'], 'REQ-P19-BACK-R-' . $suffix, 'IDEM-P19-BACK-' . $suffix);
    $assert($backup['public_id'] === $replay['public_id'] && $replay['replayed'] === true, 'Backup idempotency replay failed.');

    $backupJobId = (int) $pdo->query("SELECT id FROM backup_jobs WHERE public_id=" . $pdo->quote($backup['public_id']))->fetchColumn();
    $snapshotPublic = 'SNAP19-' . $suffix;
    $pdo->prepare("INSERT INTO backup_snapshots (public_id,account_id,backup_job_id,target_type,pod_deployment_id,homeserver_device_id,status,snapshot_hash,provider_reference_ciphertext,provider_reference_nonce,provider_reference_tag,encryption_key_id,size_bytes,verification_status,verified_at,created_at,updated_at) VALUES (:public_id,:account_id,:backup_job_id,'pod',:pod_id,NULL,'verified',:snapshot_hash,:ciphertext,:nonce,:tag,'phase19-backup-key',536870912,'verified',:verified_at,:created_at,:updated_at)")
        ->execute(['public_id' => $snapshotPublic, 'account_id' => $accountA, 'backup_job_id' => $backupJobId, 'pod_id' => $podA['id'], 'snapshot_hash' => hash('sha256', 'snapshot-' . $suffix), 'ciphertext' => base64_encode(random_bytes(48)), 'nonce' => base64_encode(random_bytes(12)), 'tag' => base64_encode(random_bytes(16)), 'verified_at' => $now, 'created_at' => $now, 'updated_at' => $now]);

    $expectCode(fn () => $actions->enqueueRestore($accountA, $ownerA, 'customer_owner', $snapshotPublic, 'restore', 'REQ-P19-BADCONF-' . $suffix, 'IDEM-P19-BADCONF-' . $suffix), 'recovery_restore_confirmation_required', 'Restore accepted an inexact confirmation.');
    $restore = $actions->enqueueRestore($accountA, $ownerA, 'customer_owner', $snapshotPublic, 'RESTORE', 'REQ-P19-REST-' . $suffix, 'IDEM-P19-REST-' . $suffix);
    $assert(str_starts_with($restore['public_id'], 'RESTORE-JOB-'), 'Restore did not queue with a public ID.');
    $expectCode(fn () => $actions->enqueueRestore($accountB, $ownerB, 'customer_owner', $snapshotPublic, 'RESTORE', 'REQ-P19-XREST-' . $suffix, 'IDEM-P19-XREST-' . $suffix), 'recovery_snapshot_not_found', 'Cross-account restore was not denied.');

    $update = $actions->enqueueUpdate($accountA, $ownerA, 'customer_owner', $podA['public_id'], $releasePublic, 'REQ-P19-UPD-' . $suffix, 'IDEM-P19-UPD-' . $suffix);
    $updateId = (int) $pdo->query("SELECT id FROM update_jobs WHERE public_id=" . $pdo->quote($update['public_id']))->fetchColumn();
    $assert((int) $pdo->query('SELECT COUNT(*) FROM update_steps WHERE job_id=' . $updateId)->fetchColumn() === 7, 'Update did not create all certified stages.');
    $actions->transitionUpdate($accountA, $ownerA, 'customer_owner', $update['public_id'], 'pause_update', 'REQ-P19-PAUSE-' . $suffix);
    $assert($pdo->query('SELECT status FROM update_jobs WHERE id=' . $updateId)->fetchColumn() === 'paused', 'Update pause failed.');
    $actions->transitionUpdate($accountA, $ownerA, 'customer_owner', $update['public_id'], 'resume_update', 'REQ-P19-RESUME-' . $suffix);
    $assert($pdo->query('SELECT status FROM update_jobs WHERE id=' . $updateId)->fetchColumn() === 'queued', 'Update resume failed.');

    $expectCode(fn () => $actions->enqueueBackup($accountA, $supportA, 'support_member', $podA['public_id'], 'REQ-P19-DENY-' . $suffix, 'IDEM-P19-DENY-' . $suffix), 'recovery_permission_denied', 'Support member queued a backup.');
    $expectCode(fn () => $actions->enqueueBackup($accountA, $adminA, 'customer_owner', $podA['public_id'], 'REQ-P19-STALE-' . $suffix, 'IDEM-P19-STALE-' . $suffix), 'recovery_permission_denied', 'Stale caller role was trusted.');
    $deniedAudit = $pdo->prepare("SELECT COUNT(*) FROM audit_events WHERE account_id=:account_id AND event_type='recovery.backup_enqueue' AND result='denied'");
    $deniedAudit->execute(['account_id' => $accountA]);
    $assert((int) $deniedAudit->fetchColumn() >= 2, 'Denied or stale-role recovery attempts did not persist evidence.');

    $snapshot = $query->snapshot($accountA);
    $assert(count($snapshot['pods']) === 1 && $snapshot['pods'][0]['public_id'] === $podA['public_id'], 'Recovery overview returned the wrong POD.');
    $assert(count($snapshot['snapshots']) === 1 && $snapshot['snapshots'][0]['public_id'] === $snapshotPublic, 'Recovery overview omitted the verified snapshot.');
    $assert(count($snapshot['update_jobs']) === 1 && count($snapshot['update_jobs'][0]['steps']) === 7, 'Recovery overview omitted update stage state.');
    $json = json_encode($snapshot, JSON_THROW_ON_ERROR);
    foreach (['provider_reference_ciphertext','provider_reference_nonce','provider_reference_tag','encryption_key_id','pre_update_backup_reference','pre_update_backup_hash','lease_token','locked_by','last_error_message','snapshot_hash','receipt_hash'] as $forbidden) {
        $assert(!str_contains($json, $forbidden), 'Recovery payload exposed forbidden field ' . $forbidden . '.');
    }
    $other = $query->snapshot($accountB);
    $otherJson = json_encode($other, JSON_THROW_ON_ERROR);
    $assert(!str_contains($otherJson, $podA['public_id']) && !str_contains($otherJson, $snapshotPublic), 'Cross-account recovery data leaked.');

    if ($failures !== []) throw new RuntimeException("Phase 19 assertions failed:\n- " . implode("\n- ", $failures));
    echo "Phase 19 Recovery Control Center database integration passed.\n";
} finally {
    if ($accountIds !== [] || $userIds !== [] || $releaseId !== null) {
        $pdo->exec('SET FOREIGN_KEY_CHECKS=0');
        if ($accountIds !== []) {
            $ids = implode(',', array_map('intval', $accountIds));
            foreach (['audit_events','backup_receipts','update_receipts','storage_alerts','storage_observations','restore_jobs','backup_verifications','backup_snapshots','backup_jobs','backup_policies','update_steps','update_jobs','pod_provisioning_jobs','pod_deployments','licenses','entitlement_bundles','domain_registrations','subscriptions','account_users'] as $table) {
                if ($table === 'update_steps') $pdo->exec("DELETE us FROM update_steps us JOIN update_jobs uj ON uj.id=us.job_id WHERE uj.account_id IN ($ids)");
                elseif ($table === 'backup_verifications') $pdo->exec("DELETE bv FROM backup_verifications bv JOIN backup_snapshots bs ON bs.id=bv.snapshot_id WHERE bs.account_id IN ($ids)");
                elseif ($table === 'storage_alerts') $pdo->exec("DELETE sa FROM storage_alerts sa JOIN storage_observations so ON so.id=sa.observation_id WHERE so.account_id IN ($ids)");
                else $pdo->exec("DELETE FROM $table WHERE account_id IN ($ids)");
            }
            $pdo->exec("DELETE FROM accounts WHERE id IN ($ids)");
        }
        if ($userIds !== []) $pdo->exec('DELETE FROM users WHERE id IN (' . implode(',', array_map('intval', $userIds)) . ')');
        if ($releaseId !== null) {
            $pdo->exec('DELETE FROM release_compatibility_rules WHERE release_id=' . (int) $releaseId);
            $pdo->exec('DELETE FROM release_rollouts WHERE release_id=' . (int) $releaseId);
            $pdo->exec('DELETE FROM software_releases WHERE id=' . (int) $releaseId);
        }
        if ($productInserted && $productId !== null) $pdo->exec('DELETE FROM software_products WHERE id=' . (int) $productId);
        $pdo->exec('SET FOREIGN_KEY_CHECKS=1');
    }
}
