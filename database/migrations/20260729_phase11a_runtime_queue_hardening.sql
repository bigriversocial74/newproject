SET NAMES utf8mb4;
SET time_zone = '+00:00';

SET @v11a_bo_lb_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='billing_outbox' AND COLUMN_NAME='locked_by'
);
SET @v11a_bo_lb_sql = IF(@v11a_bo_lb_e=0,
    'ALTER TABLE billing_outbox ADD COLUMN locked_by VARCHAR(128) NULL',
    'SELECT 1');
PREPARE v11a_bo_lb_s FROM @v11a_bo_lb_sql;
EXECUTE v11a_bo_lb_s;
DEALLOCATE PREPARE v11a_bo_lb_s;

SET @v11a_bo_lu_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='billing_outbox' AND COLUMN_NAME='locked_until'
);
SET @v11a_bo_lu_sql = IF(@v11a_bo_lu_e=0,
    'ALTER TABLE billing_outbox ADD COLUMN locked_until DATETIME NULL',
    'SELECT 1');
PREPARE v11a_bo_lu_s FROM @v11a_bo_lu_sql;
EXECUTE v11a_bo_lu_s;
DEALLOCATE PREPARE v11a_bo_lu_s;

SET @v11a_bo_lt_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='billing_outbox' AND COLUMN_NAME='lease_token'
);
SET @v11a_bo_lt_sql = IF(@v11a_bo_lt_e=0,
    'ALTER TABLE billing_outbox ADD COLUMN lease_token CHAR(64) NULL',
    'SELECT 1');
PREPARE v11a_bo_lt_s FROM @v11a_bo_lt_sql;
EXECUTE v11a_bo_lt_s;
DEALLOCATE PREPARE v11a_bo_lt_s;

SET @v11a_ppj_lu_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='pod_provisioning_jobs' AND COLUMN_NAME='locked_until'
);
SET @v11a_ppj_lu_sql = IF(@v11a_ppj_lu_e=0,
    'ALTER TABLE pod_provisioning_jobs ADD COLUMN locked_until DATETIME NULL',
    'SELECT 1');
PREPARE v11a_ppj_lu_s FROM @v11a_ppj_lu_sql;
EXECUTE v11a_ppj_lu_s;
DEALLOCATE PREPARE v11a_ppj_lu_s;

SET @v11a_ppj_lt_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='pod_provisioning_jobs' AND COLUMN_NAME='lease_token'
);
SET @v11a_ppj_lt_sql = IF(@v11a_ppj_lt_e=0,
    'ALTER TABLE pod_provisioning_jobs ADD COLUMN lease_token CHAR(64) NULL',
    'SELECT 1');
PREPARE v11a_ppj_lt_s FROM @v11a_ppj_lt_sql;
EXECUTE v11a_ppj_lt_s;
DEALLOCATE PREPARE v11a_ppj_lt_s;

SET @v11a_uj_lu_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='update_jobs' AND COLUMN_NAME='locked_until'
);
SET @v11a_uj_lu_sql = IF(@v11a_uj_lu_e=0,
    'ALTER TABLE update_jobs ADD COLUMN locked_until DATETIME NULL',
    'SELECT 1');
PREPARE v11a_uj_lu_s FROM @v11a_uj_lu_sql;
EXECUTE v11a_uj_lu_s;
DEALLOCATE PREPARE v11a_uj_lu_s;

SET @v11a_uj_lt_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='update_jobs' AND COLUMN_NAME='lease_token'
);
SET @v11a_uj_lt_sql = IF(@v11a_uj_lt_e=0,
    'ALTER TABLE update_jobs ADD COLUMN lease_token CHAR(64) NULL',
    'SELECT 1');
PREPARE v11a_uj_lt_s FROM @v11a_uj_lt_sql;
EXECUTE v11a_uj_lt_s;
DEALLOCATE PREPARE v11a_uj_lt_s;

SET @v11a_bj_lu_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='backup_jobs' AND COLUMN_NAME='locked_until'
);
SET @v11a_bj_lu_sql = IF(@v11a_bj_lu_e=0,
    'ALTER TABLE backup_jobs ADD COLUMN locked_until DATETIME NULL',
    'SELECT 1');
PREPARE v11a_bj_lu_s FROM @v11a_bj_lu_sql;
EXECUTE v11a_bj_lu_s;
DEALLOCATE PREPARE v11a_bj_lu_s;

SET @v11a_bj_lt_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='backup_jobs' AND COLUMN_NAME='lease_token'
);
SET @v11a_bj_lt_sql = IF(@v11a_bj_lt_e=0,
    'ALTER TABLE backup_jobs ADD COLUMN lease_token CHAR(64) NULL',
    'SELECT 1');
PREPARE v11a_bj_lt_s FROM @v11a_bj_lt_sql;
EXECUTE v11a_bj_lt_s;
DEALLOCATE PREPARE v11a_bj_lt_s;

SET @v11a_rj_lu_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='restore_jobs' AND COLUMN_NAME='locked_until'
);
SET @v11a_rj_lu_sql = IF(@v11a_rj_lu_e=0,
    'ALTER TABLE restore_jobs ADD COLUMN locked_until DATETIME NULL',
    'SELECT 1');
PREPARE v11a_rj_lu_s FROM @v11a_rj_lu_sql;
EXECUTE v11a_rj_lu_s;
DEALLOCATE PREPARE v11a_rj_lu_s;

SET @v11a_rj_lt_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='restore_jobs' AND COLUMN_NAME='lease_token'
);
SET @v11a_rj_lt_sql = IF(@v11a_rj_lt_e=0,
    'ALTER TABLE restore_jobs ADD COLUMN lease_token CHAR(64) NULL',
    'SELECT 1');
PREPARE v11a_rj_lt_s FROM @v11a_rj_lt_sql;
EXECUTE v11a_rj_lt_s;
DEALLOCATE PREPARE v11a_rj_lt_s;

SET @v11a_po_lu_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='provider_operations' AND COLUMN_NAME='locked_until'
);
SET @v11a_po_lu_sql = IF(@v11a_po_lu_e=0,
    'ALTER TABLE provider_operations ADD COLUMN locked_until DATETIME NULL',
    'SELECT 1');
PREPARE v11a_po_lu_s FROM @v11a_po_lu_sql;
EXECUTE v11a_po_lu_s;
DEALLOCATE PREPARE v11a_po_lu_s;

SET @v11a_po_lt_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='provider_operations' AND COLUMN_NAME='lease_token'
);
SET @v11a_po_lt_sql = IF(@v11a_po_lt_e=0,
    'ALTER TABLE provider_operations ADD COLUMN lease_token CHAR(64) NULL',
    'SELECT 1');
PREPARE v11a_po_lt_s FROM @v11a_po_lt_sql;
EXECUTE v11a_po_lt_s;
DEALLOCATE PREPARE v11a_po_lt_s;

SET @v11a_on_lu_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='operational_notifications' AND COLUMN_NAME='locked_until'
);
SET @v11a_on_lu_sql = IF(@v11a_on_lu_e=0,
    'ALTER TABLE operational_notifications ADD COLUMN locked_until DATETIME NULL',
    'SELECT 1');
PREPARE v11a_on_lu_s FROM @v11a_on_lu_sql;
EXECUTE v11a_on_lu_s;
DEALLOCATE PREPARE v11a_on_lu_s;

SET @v11a_on_lt_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='operational_notifications' AND COLUMN_NAME='lease_token'
);
SET @v11a_on_lt_sql = IF(@v11a_on_lt_e=0,
    'ALTER TABLE operational_notifications ADD COLUMN lease_token CHAR(64) NULL',
    'SELECT 1');
PREPARE v11a_on_lt_s FROM @v11a_on_lt_sql;
EXECUTE v11a_on_lt_s;
DEALLOCATE PREPARE v11a_on_lt_s;

SET @v11a_bo_ix_e = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='billing_outbox' AND INDEX_NAME='idx_billing_outbox_lease'
);
SET @v11a_bo_ix_sql = IF(@v11a_bo_ix_e=0,
    'ALTER TABLE billing_outbox ADD KEY idx_billing_outbox_lease (status, available_at, locked_until, id)',
    'SELECT 1');
PREPARE v11a_bo_ix_s FROM @v11a_bo_ix_sql;
EXECUTE v11a_bo_ix_s;
DEALLOCATE PREPARE v11a_bo_ix_s;

SET @v11a_ppj_ix_e = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='pod_provisioning_jobs' AND INDEX_NAME='idx_pod_job_lease'
);
SET @v11a_ppj_ix_sql = IF(@v11a_ppj_ix_e=0,
    'ALTER TABLE pod_provisioning_jobs ADD KEY idx_pod_job_lease (status, available_at, locked_until, id)',
    'SELECT 1');
PREPARE v11a_ppj_ix_s FROM @v11a_ppj_ix_sql;
EXECUTE v11a_ppj_ix_s;
DEALLOCATE PREPARE v11a_ppj_ix_s;

SET @v11a_uj_ix_e = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='update_jobs' AND INDEX_NAME='idx_update_job_lease'
);
SET @v11a_uj_ix_sql = IF(@v11a_uj_ix_e=0,
    'ALTER TABLE update_jobs ADD KEY idx_update_job_lease (status, available_at, locked_until, id)',
    'SELECT 1');
PREPARE v11a_uj_ix_s FROM @v11a_uj_ix_sql;
EXECUTE v11a_uj_ix_s;
DEALLOCATE PREPARE v11a_uj_ix_s;

SET @v11a_bj_ix_e = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='backup_jobs' AND INDEX_NAME='idx_backup_job_lease'
);
SET @v11a_bj_ix_sql = IF(@v11a_bj_ix_e=0,
    'ALTER TABLE backup_jobs ADD KEY idx_backup_job_lease (status, available_at, locked_until, id)',
    'SELECT 1');
PREPARE v11a_bj_ix_s FROM @v11a_bj_ix_sql;
EXECUTE v11a_bj_ix_s;
DEALLOCATE PREPARE v11a_bj_ix_s;

SET @v11a_rj_ix_e = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='restore_jobs' AND INDEX_NAME='idx_restore_job_lease'
);
SET @v11a_rj_ix_sql = IF(@v11a_rj_ix_e=0,
    'ALTER TABLE restore_jobs ADD KEY idx_restore_job_lease (status, available_at, locked_until, id)',
    'SELECT 1');
PREPARE v11a_rj_ix_s FROM @v11a_rj_ix_sql;
EXECUTE v11a_rj_ix_s;
DEALLOCATE PREPARE v11a_rj_ix_s;

SET @v11a_po_ix_e = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='provider_operations' AND INDEX_NAME='idx_provider_operation_lease'
);
SET @v11a_po_ix_sql = IF(@v11a_po_ix_e=0,
    'ALTER TABLE provider_operations ADD KEY idx_provider_operation_lease (status, available_at, locked_until, id)',
    'SELECT 1');
PREPARE v11a_po_ix_s FROM @v11a_po_ix_sql;
EXECUTE v11a_po_ix_s;
DEALLOCATE PREPARE v11a_po_ix_s;

SET @v11a_on_ix_e = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='operational_notifications' AND INDEX_NAME='idx_operational_notification_lease'
);
SET @v11a_on_ix_sql = IF(@v11a_on_ix_e=0,
    'ALTER TABLE operational_notifications ADD KEY idx_operational_notification_lease (status, available_at, locked_until, id)',
    'SELECT 1');
PREPARE v11a_on_ix_s FROM @v11a_on_ix_sql;
EXECUTE v11a_on_ix_s;
DEALLOCATE PREPARE v11a_on_ix_s;
