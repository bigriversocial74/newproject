from pathlib import Path

path = Path("src/Updates/SoftwareUpdateService.php")
source = path.read_text(encoding="utf-8")


def replace_once(old: str, new: str, label: str) -> None:
    global source
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    source = source.replace(old, new, 1)


replace_once(
    """                $this->queueLease->renew($pdo, 'update_jobs', (int) $job['id'], (string) $job['lease_token']);
                $statement = $pdo->prepare(\"UPDATE update_jobs SET status='running',current_stage=:stage,updated_at=UTC_TIMESTAMP() WHERE id=:id AND lease_token=:token\");
                $statement->execute(['stage' => $stage, 'id' => $job['id'], 'token' => $job['lease_token']]);
                $this->queueLease->assertUpdated($statement);
                $pdo->prepare(\"UPDATE update_steps SET status='running',attempts=attempts+1,started_at=COALESCE(started_at,UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=:id\")
                    ->execute(['id' => $step['id']]);
""",
    """                $this->queueLease->renew($pdo, 'update_jobs', (int) $job['id'], (string) $job['lease_token']);
                $this->ownedTransaction($job, function (PDO $owned) use ($job, $step, $stage): void {
                    $owned->prepare(\"UPDATE update_jobs SET status='running',current_stage=:stage,updated_at=UTC_TIMESTAMP() WHERE id=:id AND lease_token=:token\")
                        ->execute(['stage' => $stage, 'id' => $job['id'], 'token' => $job['lease_token']]);
                    $owned->prepare(\"UPDATE update_steps SET status='running',attempts=attempts+1,started_at=COALESCE(started_at,UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=:id\")
                        ->execute(['id' => $step['id']]);
                });
""",
    "stage ownership transition",
)

replace_once(
    """                    $pdo->prepare(
                        'UPDATE update_jobs SET pre_update_backup_reference=:reference,pre_update_backup_hash=:hash,
                         pre_update_backup_verified=1,updated_at=UTC_TIMESTAMP() WHERE id=:id'
                    )->execute(['reference' => substr($reference, 0, 512), 'hash' => $hash, 'id' => $job['id']]);
                    $job['pre_update_backup_reference'] = $reference;
                    $job['pre_update_backup_hash'] = $hash;
                    $job['pre_update_backup_verified'] = 1;
""",
    """                    $job['pre_update_backup_reference'] = $reference;
                    $job['pre_update_backup_hash'] = $hash;
                    $job['pre_update_backup_verified'] = 1;
""",
    "backup metadata deferral",
)

replace_once(
    """                } elseif ($stage === 'completed') {
                    $result = ['completed' => true];
                    $this->updateVersion($pdo, $job, (string) $release['version']);
""",
    """                } elseif ($stage === 'completed') {
                    $result = ['completed' => true];
""",
    "target version deferral",
)

replace_once(
    """                $this->queueLease->renew($pdo, 'update_jobs', (int) $job['id'], (string) $job['lease_token']);
                $hash = hash('sha256', $this->json($result));
                $pdo->prepare(
                    \"UPDATE update_steps SET status='completed',receipt_hash=:hash,completed_at=UTC_TIMESTAMP(),
                     last_error_code=NULL,last_error_message=NULL,updated_at=UTC_TIMESTAMP() WHERE id=:id\"
                )->execute(['hash' => $hash, 'id' => $step['id']]);
                $this->receipt($pdo, (int) $job['account_id'], (int) $job['id'], (int) $step['id'], (string) $job['request_id'], $stage, 'success', $hash, $this->metadata($result));
""",
    """                $this->queueLease->renew($pdo, 'update_jobs', (int) $job['id'], (string) $job['lease_token']);
                $hash = hash('sha256', $this->json($result));
                $this->ownedTransaction($job, function (PDO $owned) use ($job, $step, $stage, $result, $hash, $release): void {
                    if ($stage === 'backing_up') {
                        $owned->prepare(
                            'UPDATE update_jobs SET pre_update_backup_reference=:reference,pre_update_backup_hash=:hash,
                             pre_update_backup_verified=1,updated_at=UTC_TIMESTAMP() WHERE id=:id AND lease_token=:token'
                        )->execute([
                            'reference' => substr((string) $job['pre_update_backup_reference'], 0, 512),
                            'hash' => (string) $job['pre_update_backup_hash'],
                            'id' => $job['id'],
                            'token' => $job['lease_token'],
                        ]);
                    }
                    if ($stage === 'completed') {
                        $this->updateVersion($owned, $job, (string) $release['version']);
                    }
                    $owned->prepare(
                        \"UPDATE update_steps SET status='completed',receipt_hash=:hash,completed_at=UTC_TIMESTAMP(),
                         last_error_code=NULL,last_error_message=NULL,updated_at=UTC_TIMESTAMP() WHERE id=:id\"
                    )->execute(['hash' => $hash, 'id' => $step['id']]);
                    $this->receipt($owned, (int) $job['account_id'], (int) $job['id'], (int) $step['id'], (string) $job['request_id'], $stage, 'success', $hash, $this->metadata($result));
                });
""",
    "lease-owned success finalization",
)

path.write_text(source, encoding="utf-8")
