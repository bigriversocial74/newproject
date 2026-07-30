<?php

declare(strict_types=1);

namespace Vp3\Recovery;

use PDO;
use Vp3\Auth\AuthPublicException;
use Vp3\Database;
use Vp3\Updates\SoftwareUpdateService;

final class RecoveryControlCenterActionService
{
    private const ROLES = ['customer_owner', 'customer_admin'];

    public function __construct(private readonly Database $db) {}

    /** @return array{public_id:string,status:string} */
    public function savePolicy(int $account, int $actor, string $role, string $podPublic, int $interval, int $count, int $days, string $request): array
    {
        if ($interval < 15 || $interval > 525600 || $count < 1 || $count > 365 || $days < 1 || $days > 3650) {
            throw new AuthPublicException('recovery_policy_invalid', 'Backup policy values are outside the supported limits.', 422);
        }
        return $this->run($account, $actor, $role, 'backup_policy_save', $podPublic, $request,
            function (PDO $pdo) use ($account, $actor, $podPublic, $interval, $count, $days, $request): array {
                $pod = $this->pod($pdo, $account, $podPublic);
                $q = $pdo->prepare("SELECT id,public_id FROM backup_policies WHERE target_type='pod' AND pod_deployment_id=:pod LIMIT 1 FOR UPDATE");
                $q->execute(['pod' => $pod['id']]); $row = $q->fetch(PDO::FETCH_ASSOC);
                if (is_array($row)) {
                    $id = (int) $row['id']; $public = (string) $row['public_id'];
                    $pdo->prepare("UPDATE backup_policies SET status='active',schedule_interval_minutes=:interval,retention_count=:count,retention_days=:days,require_verification=1,next_run_at=COALESCE(next_run_at,UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=:id AND account_id=:account")
                        ->execute(['interval'=>$interval,'count'=>$count,'days'=>$days,'id'=>$id,'account'=>$account]);
                } else {
                    $public = 'BACKUP-POLICY-' . strtoupper(bin2hex(random_bytes(12)));
                    $pdo->prepare("INSERT INTO backup_policies (public_id,account_id,target_type,pod_deployment_id,status,schedule_interval_minutes,retention_count,retention_days,require_verification,next_run_at,created_at,updated_at) VALUES (:public,:account,'pod',:pod,'active',:interval,:count,:days,1,UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())")
                        ->execute(['public'=>$public,'account'=>$account,'pod'=>$pod['id'],'interval'=>$interval,'count'=>$count,'days'=>$days]);
                    $id = (int) $pdo->lastInsertId();
                }
                $hash = hash('sha256', implode('|', [$account,$id,$interval,$count,$days,$request]));
                $this->backupReceipt($pdo,$account,null,null,null,$request,'backup_policy_saved',$hash);
                $this->audit($pdo,$account,$actor,'recovery.backup_policy_saved','success','backup_policy',$public,$request);
                return ['public_id'=>$public,'status'=>'active'];
            });
    }

    /** @return array{public_id:string,status:string,replayed:bool} */
    public function enqueueBackup(int $account, int $actor, string $role, string $podPublic, string $request, string $idem): array
    {
        return $this->run($account,$actor,$role,'backup_enqueue',$podPublic,$request,
            function (PDO $pdo) use ($account,$actor,$podPublic,$request,$idem): array {
                $pod = $this->pod($pdo,$account,$podPublic);
                $q=$pdo->prepare('SELECT public_id,pod_deployment_id,job_type,status FROM backup_jobs WHERE account_id=:account AND idempotency_key=:idem LIMIT 1 FOR UPDATE');
                $q->execute(['account'=>$account,'idem'=>$idem]); $old=$q->fetch(PDO::FETCH_ASSOC);
                if (is_array($old)) {
                    if ((int)$old['pod_deployment_id']!==(int)$pod['id'] || $old['job_type']!=='on_demand') $this->conflict();
                    return ['public_id'=>(string)$old['public_id'],'status'=>(string)$old['status'],'replayed'=>true];
                }
                $public='BACKUP-JOB-'.strtoupper(bin2hex(random_bytes(12)));
                $pdo->prepare("INSERT INTO backup_jobs (public_id,account_id,target_type,pod_deployment_id,job_type,status,idempotency_key,request_id,available_at,created_at,updated_at) VALUES (:public,:account,'pod',:pod,'on_demand','queued',:idem,:request,UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())")
                    ->execute(['public'=>$public,'account'=>$account,'pod'=>$pod['id'],'idem'=>$idem,'request'=>$request]);
                $id=(int)$pdo->lastInsertId(); $hash=hash('sha256',"$account|$id|$podPublic|$request");
                $this->backupReceipt($pdo,$account,$id,null,null,$request,'backup_queued',$hash);
                $this->audit($pdo,$account,$actor,'recovery.backup_queued','success','backup_job',$public,$request);
                return ['public_id'=>$public,'status'=>'queued','replayed'=>false];
            });
    }

    /** @return array{public_id:string,status:string,replayed:bool} */
    public function enqueueRestore(int $account, int $actor, string $role, string $snapshotPublic, string $confirm, string $request, string $idem): array
    {
        if ($confirm !== 'RESTORE') throw new AuthPublicException('recovery_restore_confirmation_required','Restore requires the exact confirmation RESTORE.',422);
        return $this->run($account,$actor,$role,'restore_enqueue',$snapshotPublic,$request,
            function (PDO $pdo) use ($account,$actor,$snapshotPublic,$request,$idem): array {
                $q=$pdo->prepare("SELECT s.id FROM backup_snapshots s JOIN pod_deployments p ON p.id=s.pod_deployment_id AND p.account_id=s.account_id WHERE s.public_id=:public AND s.account_id=:account AND s.target_type='pod' AND s.status='verified' AND s.verification_status='verified' LIMIT 1 FOR UPDATE");
                $q->execute(['public'=>$snapshotPublic,'account'=>$account]); $snapshot=(int)$q->fetchColumn();
                if ($snapshot<1) throw new AuthPublicException('recovery_snapshot_not_found','Only an account-owned verified snapshot can be restored.',404);
                $q=$pdo->prepare('SELECT public_id,snapshot_id,status FROM restore_jobs WHERE account_id=:account AND idempotency_key=:idem LIMIT 1 FOR UPDATE');
                $q->execute(['account'=>$account,'idem'=>$idem]); $old=$q->fetch(PDO::FETCH_ASSOC);
                if (is_array($old)) {
                    if ((int)$old['snapshot_id']!==$snapshot) $this->conflict();
                    return ['public_id'=>(string)$old['public_id'],'status'=>(string)$old['status'],'replayed'=>true];
                }
                $public='RESTORE-JOB-'.strtoupper(bin2hex(random_bytes(12)));
                $pdo->prepare("INSERT INTO restore_jobs (public_id,account_id,snapshot_id,status,idempotency_key,request_id,available_at,created_at,updated_at) VALUES (:public,:account,:snapshot,'queued',:idem,:request,UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())")
                    ->execute(['public'=>$public,'account'=>$account,'snapshot'=>$snapshot,'idem'=>$idem,'request'=>$request]);
                $id=(int)$pdo->lastInsertId(); $hash=hash('sha256',"$account|$id|$snapshotPublic|$request");
                $this->backupReceipt($pdo,$account,null,$id,$snapshot,$request,'restore_queued',$hash);
                $this->audit($pdo,$account,$actor,'recovery.restore_queued','success','restore_job',$public,$request);
                return ['public_id'=>$public,'status'=>'queued','replayed'=>false];
            });
    }

    /** @return array{public_id:string,status:string,replayed:bool} */
    public function enqueueUpdate(int $account, int $actor, string $role, string $podPublic, string $releasePublic, string $request, string $idem): array
    {
        return $this->run($account,$actor,$role,'update_enqueue',$podPublic,$request,
            function (PDO $pdo) use ($account,$actor,$podPublic,$releasePublic,$request,$idem): array {
                $pod=$this->pod($pdo,$account,$podPublic); $release=$this->release($pdo,$releasePublic); $this->eligible($release,$pod);
                $q=$pdo->prepare('SELECT public_id,pod_deployment_id,release_id,status FROM update_jobs WHERE account_id=:account AND idempotency_key=:idem LIMIT 1 FOR UPDATE');
                $q->execute(['account'=>$account,'idem'=>$idem]); $old=$q->fetch(PDO::FETCH_ASSOC);
                if (is_array($old)) {
                    if ((int)$old['pod_deployment_id']!==(int)$pod['id'] || (int)$old['release_id']!==(int)$release['id']) $this->conflict();
                    return ['public_id'=>(string)$old['public_id'],'status'=>(string)$old['status'],'replayed'=>true];
                }
                $public='UPDATE-'.strtoupper(bin2hex(random_bytes(12)));
                $pdo->prepare("INSERT INTO update_jobs (public_id,account_id,target_type,pod_deployment_id,release_id,status,previous_version,target_version,idempotency_key,request_id,available_at,created_at,updated_at) VALUES (:public,:account,'pod',:pod,:release,'queued',:previous,:target,:idem,:request,UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())")
                    ->execute(['public'=>$public,'account'=>$account,'pod'=>$pod['id'],'release'=>$release['id'],'previous'=>$pod['current_version'],'target'=>$release['version'],'idem'=>$idem,'request'=>$request]);
                $id=(int)$pdo->lastInsertId(); $step=$pdo->prepare("INSERT INTO update_steps (job_id,stage,sequence_no,status,created_at,updated_at) VALUES (:job,:stage,:sequence,'pending',UTC_TIMESTAMP(),UTC_TIMESTAMP())");
                foreach (SoftwareUpdateService::STAGES as $i=>$stage) $step->execute(['job'=>$id,'stage'=>$stage,'sequence'=>$i+1]);
                $hash=hash('sha256',"$account|$id|$podPublic|$releasePublic|$request");
                $this->updateReceipt($pdo,$account,$id,$request,'update_queued',$hash);
                $this->audit($pdo,$account,$actor,'recovery.update_queued','success','update_job',$public,$request);
                return ['public_id'=>$public,'status'=>'queued','replayed'=>false];
            });
    }

    public function transitionUpdate(int $account, int $actor, string $role, string $jobPublic, string $action, string $request): void
    {
        $rule=match(strtolower($action)){'pause_update'=>[['queued','running'],'paused'],'resume_update'=>[['paused','failed'],'queued'],default=>throw new AuthPublicException('recovery_update_action_invalid','The update action is invalid.',422)};
        $this->run($account,$actor,$role,$action,$jobPublic,$request,function(PDO $pdo)use($account,$actor,$jobPublic,$action,$request,$rule):array{
            $q=$pdo->prepare("SELECT id,status FROM update_jobs WHERE public_id=:public AND account_id=:account AND target_type='pod' LIMIT 1 FOR UPDATE");
            $q->execute(['public'=>$jobPublic,'account'=>$account]); $job=$q->fetch(PDO::FETCH_ASSOC);
            if(!is_array($job)) throw new AuthPublicException('recovery_update_not_found','The update job was not found.',404);
            if(!in_array($job['status'],$rule[0],true)) throw new AuthPublicException('recovery_update_transition_invalid','The update job cannot make that transition.',409);
            $pdo->prepare('UPDATE update_jobs SET status=:status,request_id=:request,available_at=UTC_TIMESTAMP(),locked_at=NULL,locked_by=NULL,locked_until=NULL,lease_token=NULL,updated_at=UTC_TIMESTAMP() WHERE id=:id AND account_id=:account')
                ->execute(['status'=>$rule[1],'request'=>$request,'id'=>$job['id'],'account'=>$account]);
            $hash=hash('sha256',"$account|{$job['id']}|{$rule[1]}|$request"); $this->updateReceipt($pdo,$account,(int)$job['id'],$request,$action,$hash);
            $this->audit($pdo,$account,$actor,'recovery.'.$action,'success','update_job',$jobPublic,$request); return [];
        });
    }

    /** @template T @param callable(PDO):T $work @return T */
    private function run(int $account,int $actor,string $role,string $operation,string $resource,string $request,callable $work):mixed
    {
        try{return $this->db->transaction(function(PDO $pdo)use($account,$actor,$role,$work):mixed{$this->authorize($pdo,$account,$actor,$role);return $work($pdo);});}
        catch(AuthPublicException $e){if($e->publicCode()==='recovery_permission_denied')$this->db->transaction(fn(PDO $pdo)=>$this->audit($pdo,$account,$actor,'recovery.'.$operation,'denied','recovery_resource',$resource,$request));throw $e;}
    }

    private function authorize(PDO $pdo,int $account,int $actor,string $role):void
    {
        $q=$pdo->prepare("SELECT role FROM account_users WHERE account_id=:account AND user_id=:actor AND status='active' LIMIT 1 FOR UPDATE");$q->execute(['account'=>$account,'actor'=>$actor]);$stored=$q->fetchColumn();
        if(!is_string($stored)||!hash_equals($stored,$role)||!in_array($stored,self::ROLES,true))throw new AuthPublicException('recovery_permission_denied','An active customer owner or administrator membership is required for recovery actions.',403);
    }

    /** @return array<string,mixed> */
    private function pod(PDO $pdo,int $account,string $public):array
    {
        $q=$pdo->prepare("SELECT id,public_id,installed_version current_version,update_channel FROM pod_deployments WHERE public_id=:public AND account_id=:account AND status IN ('active','degraded') LIMIT 1 FOR UPDATE");$q->execute(['public'=>$public,'account'=>$account]);$row=$q->fetch(PDO::FETCH_ASSOC);
        if(!is_array($row))throw new AuthPublicException('recovery_pod_not_found','An eligible account-owned POD was not found.',404);return $row;
    }

    /** @return array<string,mixed> */
    private function release(PDO $pdo,string $public):array
    {
        $q=$pdo->prepare("SELECT r.*,p.target_type,rr.status rollout_status,rr.percentage,rr.cohort_seed,rr.starts_at,rr.ends_at,c.minimum_current_version,c.maximum_current_version FROM software_releases r JOIN software_products p ON p.id=r.product_id JOIN release_rollouts rr ON rr.release_id=r.id JOIN release_compatibility_rules c ON c.release_id=r.id WHERE r.public_id=:public LIMIT 1 FOR UPDATE");$q->execute(['public'=>$public]);$row=$q->fetch(PDO::FETCH_ASSOC);
        if(!is_array($row))throw new AuthPublicException('recovery_release_not_found','The software release was not found.',404);return $row;
    }

    /** @param array<string,mixed> $r @param array<string,mixed> $p */
    private function eligible(array $r,array $p):void
    {
        $bad=$r['status']!=='published'||$r['rollout_status']!=='active'||$r['target_type']!=='pod'||!is_string($r['manifest_hash'])||$r['manifest_hash']===''||!is_string($r['manifest_signature'])||$r['manifest_signature']==='';
        $bad=$bad||($r['starts_at']!==null&&strtotime((string)$r['starts_at'])>time())||($r['ends_at']!==null&&strtotime((string)$r['ends_at'])<time())||($r['channel']==='beta'&&$p['update_channel']!=='beta');
        $current=(string)$p['current_version'];$bad=$bad||$current===''||version_compare($current,(string)$r['version'],'>=')||($r['minimum_current_version']&&version_compare($current,(string)$r['minimum_current_version'],'<'))||($r['maximum_current_version']&&version_compare($current,(string)$r['maximum_current_version'],'>'));
        $emergency=$r['channel']==='security'&&(int)$r['emergency_override']===1;if(!$emergency){$bucket=hexdec(substr(hash('sha256',$r['cohort_seed'].'|'.$p['public_id']),0,8))%100;$bad=$bad||$bucket>=(int)$r['percentage'];}
        if($bad)throw new AuthPublicException('recovery_release_ineligible','The signed release is not eligible for this POD.',409);
    }

    private function conflict():never{throw new AuthPublicException('recovery_idempotency_conflict','The idempotency key was already used for another recovery request.',409);}

    private function backupReceipt(PDO $pdo,int $account,?int $backup,?int $restore,?int $snapshot,string $request,string $operation,string $hash):void
    {$pdo->prepare("INSERT INTO backup_receipts (public_id,account_id,backup_job_id,restore_job_id,snapshot_id,request_id,operation,result,receipt_hash,created_at) VALUES (:public,:account,:backup,:restore,:snapshot,:request,:operation,'success',:hash,UTC_TIMESTAMP())")->execute(['public'=>'BACKUP-RECEIPT-'.strtoupper(bin2hex(random_bytes(10))),'account'=>$account,'backup'=>$backup,'restore'=>$restore,'snapshot'=>$snapshot,'request'=>substr($request,0,64),'operation'=>substr($operation,0,100),'hash'=>$hash]);}

    private function updateReceipt(PDO $pdo,int $account,int $job,string $request,string $operation,string $hash):void
    {$pdo->prepare("INSERT INTO update_receipts (public_id,account_id,job_id,request_id,operation,result,receipt_hash,created_at) VALUES (:public,:account,:job,:request,:operation,'success',:hash,UTC_TIMESTAMP())")->execute(['public'=>'UPDATE-RECEIPT-'.strtoupper(bin2hex(random_bytes(10))),'account'=>$account,'job'=>$job,'request'=>substr($request,0,64),'operation'=>substr($operation,0,100),'hash'=>$hash]);}

    private function audit(PDO $pdo,int $account,int $actor,string $event,string $result,string $type,string $public,string $request):void
    {$pdo->prepare("INSERT INTO audit_events (request_id,actor_type,actor_id,account_id,event_type,resource_type,resource_public_id,result,created_at) VALUES (:request,'user',:actor,:account,:event,:type,:public,:result,UTC_TIMESTAMP())")->execute(['request'=>substr($request,0,64),'actor'=>$actor,'account'=>$account,'event'=>substr($event,0,100),'type'=>substr($type,0,80),'public'=>substr($public,0,190),'result'=>$result]);}
}
