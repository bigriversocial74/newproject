SET NAMES utf8mb4;
SET time_zone = '+00:00';

SET @vp3_phase8_has_global_snapshot_hash = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='backup_snapshots' AND INDEX_NAME='uq_backup_snapshot_hash'
);
SET @vp3_phase8_drop_global_snapshot_hash_sql = IF(
    @vp3_phase8_has_global_snapshot_hash>0,
    'ALTER TABLE backup_snapshots DROP INDEX uq_backup_snapshot_hash',
    'SELECT 1'
);
PREPARE vp3_phase8_drop_global_snapshot_hash_statement FROM @vp3_phase8_drop_global_snapshot_hash_sql;
EXECUTE vp3_phase8_drop_global_snapshot_hash_statement;
DEALLOCATE PREPARE vp3_phase8_drop_global_snapshot_hash_statement;

SET @vp3_phase8_has_pod_snapshot_hash = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='backup_snapshots' AND INDEX_NAME='uq_backup_snapshot_pod_hash'
);
SET @vp3_phase8_pod_snapshot_hash_sql = IF(
    @vp3_phase8_has_pod_snapshot_hash=0,
    'ALTER TABLE backup_snapshots ADD UNIQUE KEY uq_backup_snapshot_pod_hash (pod_deployment_id, snapshot_hash)',
    'SELECT 1'
);
PREPARE vp3_phase8_pod_snapshot_hash_statement FROM @vp3_phase8_pod_snapshot_hash_sql;
EXECUTE vp3_phase8_pod_snapshot_hash_statement;
DEALLOCATE PREPARE vp3_phase8_pod_snapshot_hash_statement;

SET @vp3_phase8_has_homeserver_snapshot_hash = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='backup_snapshots' AND INDEX_NAME='uq_backup_snapshot_homeserver_hash'
);
SET @vp3_phase8_homeserver_snapshot_hash_sql = IF(
    @vp3_phase8_has_homeserver_snapshot_hash=0,
    'ALTER TABLE backup_snapshots ADD UNIQUE KEY uq_backup_snapshot_homeserver_hash (homeserver_device_id, snapshot_hash)',
    'SELECT 1'
);
PREPARE vp3_phase8_homeserver_snapshot_hash_statement FROM @vp3_phase8_homeserver_snapshot_hash_sql;
EXECUTE vp3_phase8_homeserver_snapshot_hash_statement;
DEALLOCATE PREPARE vp3_phase8_homeserver_snapshot_hash_statement;
