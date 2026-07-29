from pathlib import Path

path = Path("src/Infrastructure/InfrastructureProviderService.php")
source = path.read_text(encoding="utf-8")
old = """                $this->queueLease->renew($pdo, 'provider_operations', (int) $operation['id'], (string) $operation['lease_token'], ['running','hosting','dns','certificate','verifying']);
                $status = str_starts_with($stage, 'hosting') ? 'hosting'
                    : (str_starts_with($stage, 'dns') ? 'dns'
                    : (str_starts_with($stage, 'certificate') ? 'certificate'
                    : ($stage === 'verify' ? 'verifying' : 'running')));
                $statement = $pdo->prepare('UPDATE provider_operations SET status=:status,current_stage=:stage,updated_at=UTC_TIMESTAMP() WHERE id=:id AND lease_token=:token');
                $statement->execute(['status' => $status, 'stage' => $stage, 'id' => $operation['id'], 'token' => $operation['lease_token']]);
                $this->queueLease->assertUpdated($statement);
                $pdo->prepare(\"UPDATE provider_operation_steps SET status='running',attempts=attempts+1,started_at=COALESCE(started_at,UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=:id\")
                    ->execute(['id' => $step['id']]);
"""
new = """                $this->queueLease->renew($pdo, 'provider_operations', (int) $operation['id'], (string) $operation['lease_token'], ['running','hosting','dns','certificate','verifying']);
                $status = str_starts_with($stage, 'hosting') ? 'hosting'
                    : (str_starts_with($stage, 'dns') ? 'dns'
                    : (str_starts_with($stage, 'certificate') ? 'certificate'
                    : ($stage === 'verify' ? 'verifying' : 'running')));
                $this->ownedTransaction($operation, function (PDO $owned) use ($operation, $step, $stage, $status): void {
                    $owned->prepare('UPDATE provider_operations SET status=:status,current_stage=:stage,updated_at=UTC_TIMESTAMP() WHERE id=:id AND lease_token=:token')
                        ->execute(['status' => $status, 'stage' => $stage, 'id' => $operation['id'], 'token' => $operation['lease_token']]);
                    $owned->prepare(\"UPDATE provider_operation_steps SET status='running',attempts=attempts+1,started_at=COALESCE(started_at,UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=:id\")
                        ->execute(['id' => $step['id']]);
                });
"""
count = source.count(old)
if count != 1:
    raise SystemExit(f"infrastructure stage ownership transition: expected exactly one match, found {count}")
path.write_text(source.replace(old, new, 1), encoding="utf-8")
