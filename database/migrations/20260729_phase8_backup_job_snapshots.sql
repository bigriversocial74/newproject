SET NAMES utf8mb4;
SET time_zone = '+00:00';

SET @vp3_phase8_has_snapshot_id = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='backup_jobs' AND COLUMN_NAME='snapshot_id'
);
SET @vp3_phase8_snapshot_id_sql = IF(
    @vp3_phase8_has_snapshot_id=0,
    'ALTER TABLE backup_jobs ADD COLUMN snapshot_id BIGINT UNSIGNED NULL AFTER homeserver_device_id',
    'SELECT 1'
);
PREPARE vp3_phase8_snapshot_id_statement FROM @vp3_phase8_snapshot_id_sql;
EXECUTE vp3_phase8_snapshot_id_statement;
DEALLOCATE PREPARE vp3_phase8_snapshot_id_statement;

SET @vp3_phase8_has_snapshot_key = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='backup_jobs' AND INDEX_NAME='idx_backup_job_snapshot'
);
SET @vp3_phase8_snapshot_key_sql = IF(
    @vp3_phase8_has_snapshot_key=0,
    'ALTER TABLE backup_jobs ADD KEY idx_backup_job_snapshot (snapshot_id)',
    'SELECT 1'
);
PREPARE vp3_phase8_snapshot_key_statement FROM @vp3_phase8_snapshot_key_sql;
EXECUTE vp3_phase8_snapshot_key_statement;
DEALLOCATE PREPARE vp3_phase8_snapshot_key_statement;

SET @vp3_phase8_has_snapshot_fk = (
    SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='backup_jobs' AND CONSTRAINT_NAME='fk_backup_job_snapshot'
);
SET @vp3_phase8_snapshot_fk_sql = IF(
    @vp3_phase8_has_snapshot_fk=0,
    'ALTER TABLE backup_jobs ADD CONSTRAINT fk_backup_job_snapshot FOREIGN KEY (snapshot_id) REFERENCES backup_snapshots(id) ON DELETE SET NULL',
    'SELECT 1'
);
PREPARE vp3_phase8_snapshot_fk_statement FROM @vp3_phase8_snapshot_fk_sql;
EXECUTE vp3_phase8_snapshot_fk_statement;
DEALLOCATE PREPARE vp3_phase8_snapshot_fk_statement;
