SET NAMES utf8mb4;
SET time_zone = '+00:00';

UPDATE auth_sessions
SET inactivity_expires_at = COALESCE(inactivity_expires_at, expires_at),
    absolute_expires_at = COALESCE(absolute_expires_at, expires_at),
    updated_at = COALESCE(updated_at, created_at)
WHERE inactivity_expires_at IS NULL OR absolute_expires_at IS NULL OR updated_at IS NULL;

ALTER TABLE auth_sessions
    MODIFY inactivity_expires_at DATETIME NOT NULL,
    MODIFY absolute_expires_at DATETIME NOT NULL,
    MODIFY updated_at DATETIME NOT NULL;

SET @v11b_s_rbu_fk_e = (
    SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA=DATABASE()
      AND TABLE_NAME='auth_sessions'
      AND CONSTRAINT_NAME='fk_auth_sessions_revoked_by_user'
);
SET @v11b_s_rbu_fk_sql = IF(@v11b_s_rbu_fk_e=0,
    'ALTER TABLE auth_sessions ADD CONSTRAINT fk_auth_sessions_revoked_by_user FOREIGN KEY (revoked_by_user_id) REFERENCES users(id) ON DELETE SET NULL',
    'SELECT 1');
PREPARE v11b_s_rbu_fk_s FROM @v11b_s_rbu_fk_sql;
EXECUTE v11b_s_rbu_fk_s;
DEALLOCATE PREPARE v11b_s_rbu_fk_s;

SET @v11b_evt_req_ix_e = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA=DATABASE()
      AND TABLE_NAME='email_verification_tokens'
      AND INDEX_NAME='idx_email_verification_request'
);
SET @v11b_evt_req_ix_sql = IF(@v11b_evt_req_ix_e=0,
    'ALTER TABLE email_verification_tokens ADD KEY idx_email_verification_request (request_id)',
    'SELECT 1');
PREPARE v11b_evt_req_ix_s FROM @v11b_evt_req_ix_sql;
EXECUTE v11b_evt_req_ix_s;
DEALLOCATE PREPARE v11b_evt_req_ix_s;

SET @v11b_prt_req_ix_e = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA=DATABASE()
      AND TABLE_NAME='password_reset_tokens'
      AND INDEX_NAME='idx_password_reset_request'
);
SET @v11b_prt_req_ix_sql = IF(@v11b_prt_req_ix_e=0,
    'ALTER TABLE password_reset_tokens ADD KEY idx_password_reset_request (request_id)',
    'SELECT 1');
PREPARE v11b_prt_req_ix_s FROM @v11b_prt_req_ix_sql;
EXECUTE v11b_prt_req_ix_s;
DEALLOCATE PREPARE v11b_prt_req_ix_s;
