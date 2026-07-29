SET NAMES utf8mb4;
SET time_zone = '+00:00';

SET @v11b_s_ie_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='auth_sessions' AND COLUMN_NAME='inactivity_expires_at'
);
SET @v11b_s_ie_sql = IF(@v11b_s_ie_e=0,
    'ALTER TABLE auth_sessions ADD COLUMN inactivity_expires_at DATETIME NULL AFTER expires_at',
    'SELECT 1');
PREPARE v11b_s_ie_s FROM @v11b_s_ie_sql;
EXECUTE v11b_s_ie_s;
DEALLOCATE PREPARE v11b_s_ie_s;

SET @v11b_s_ae_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='auth_sessions' AND COLUMN_NAME='absolute_expires_at'
);
SET @v11b_s_ae_sql = IF(@v11b_s_ae_e=0,
    'ALTER TABLE auth_sessions ADD COLUMN absolute_expires_at DATETIME NULL AFTER inactivity_expires_at',
    'SELECT 1');
PREPARE v11b_s_ae_s FROM @v11b_s_ae_sql;
EXECUTE v11b_s_ae_s;
DEALLOCATE PREPARE v11b_s_ae_s;

SET @v11b_s_rf_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='auth_sessions' AND COLUMN_NAME='rotated_from_public_id'
);
SET @v11b_s_rf_sql = IF(@v11b_s_rf_e=0,
    'ALTER TABLE auth_sessions ADD COLUMN rotated_from_public_id VARCHAR(64) NULL AFTER absolute_expires_at',
    'SELECT 1');
PREPARE v11b_s_rf_s FROM @v11b_s_rf_sql;
EXECUTE v11b_s_rf_s;
DEALLOCATE PREPARE v11b_s_rf_s;

SET @v11b_s_rr_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='auth_sessions' AND COLUMN_NAME='revocation_reason'
);
SET @v11b_s_rr_sql = IF(@v11b_s_rr_e=0,
    'ALTER TABLE auth_sessions ADD COLUMN revocation_reason VARCHAR(64) NULL AFTER revoked_at',
    'SELECT 1');
PREPARE v11b_s_rr_s FROM @v11b_s_rr_sql;
EXECUTE v11b_s_rr_s;
DEALLOCATE PREPARE v11b_s_rr_s;

SET @v11b_s_rbu_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='auth_sessions' AND COLUMN_NAME='revoked_by_user_id'
);
SET @v11b_s_rbu_sql = IF(@v11b_s_rbu_e=0,
    'ALTER TABLE auth_sessions ADD COLUMN revoked_by_user_id BIGINT UNSIGNED NULL AFTER revocation_reason',
    'SELECT 1');
PREPARE v11b_s_rbu_s FROM @v11b_s_rbu_sql;
EXECUTE v11b_s_rbu_s;
DEALLOCATE PREPARE v11b_s_rbu_s;

SET @v11b_s_up_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='auth_sessions' AND COLUMN_NAME='updated_at'
);
SET @v11b_s_up_sql = IF(@v11b_s_up_e=0,
    'ALTER TABLE auth_sessions ADD COLUMN updated_at DATETIME NULL AFTER created_at',
    'SELECT 1');
PREPARE v11b_s_up_s FROM @v11b_s_up_sql;
EXECUTE v11b_s_up_s;
DEALLOCATE PREPARE v11b_s_up_s;

UPDATE auth_sessions
SET inactivity_expires_at = COALESCE(inactivity_expires_at, expires_at),
    absolute_expires_at = COALESCE(absolute_expires_at, expires_at),
    updated_at = COALESCE(updated_at, created_at)
WHERE inactivity_expires_at IS NULL OR absolute_expires_at IS NULL OR updated_at IS NULL;

SET @v11b_s_ix_e = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='auth_sessions' AND INDEX_NAME='idx_auth_sessions_active_user'
);
SET @v11b_s_ix_sql = IF(@v11b_s_ix_e=0,
    'ALTER TABLE auth_sessions ADD KEY idx_auth_sessions_active_user (user_id, revoked_at, inactivity_expires_at, absolute_expires_at)',
    'SELECT 1');
PREPARE v11b_s_ix_s FROM @v11b_s_ix_sql;
EXECUTE v11b_s_ix_s;
DEALLOCATE PREPARE v11b_s_ix_s;

SET @v11b_s_rf_ix_e = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='auth_sessions' AND INDEX_NAME='idx_auth_sessions_rotated_from'
);
SET @v11b_s_rf_ix_sql = IF(@v11b_s_rf_ix_e=0,
    'ALTER TABLE auth_sessions ADD KEY idx_auth_sessions_rotated_from (rotated_from_public_id)',
    'SELECT 1');
PREPARE v11b_s_rf_ix_s FROM @v11b_s_rf_ix_sql;
EXECUTE v11b_s_rf_ix_s;
DEALLOCATE PREPARE v11b_s_rf_ix_s;

SET @v11b_evt_m_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='auth_session_events' AND COLUMN_NAME='metadata_json'
);
SET @v11b_evt_m_sql = IF(@v11b_evt_m_e=0,
    'ALTER TABLE auth_session_events ADD COLUMN metadata_json JSON NULL AFTER user_agent_hash',
    'SELECT 1');
PREPARE v11b_evt_m_s FROM @v11b_evt_m_sql;
EXECUTE v11b_evt_m_s;
DEALLOCATE PREPARE v11b_evt_m_s;

SET @v11b_evt_req_ix_e = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='auth_session_events' AND INDEX_NAME='idx_auth_session_events_request'
);
SET @v11b_evt_req_ix_sql = IF(@v11b_evt_req_ix_e=0,
    'ALTER TABLE auth_session_events ADD KEY idx_auth_session_events_request (request_id)',
    'SELECT 1');
PREPARE v11b_evt_req_ix_s FROM @v11b_evt_req_ix_sql;
EXECUTE v11b_evt_req_ix_s;
DEALLOCATE PREPARE v11b_evt_req_ix_s;

SET @v11b_evt_type_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='auth_session_events' AND COLUMN_NAME='event_type'
      AND COLUMN_TYPE LIKE '%created%' AND COLUMN_TYPE LIKE '%rotated%' AND COLUMN_TYPE LIKE '%revoked%'
      AND COLUMN_TYPE LIKE '%expired%' AND COLUMN_TYPE LIKE '%rejected%'
);
SET @v11b_evt_type_sql = IF(@v11b_evt_type_e=0,
    'ALTER TABLE auth_session_events MODIFY event_type ENUM(''created'',''rotated'',''revoked'',''expired'',''rejected'') NOT NULL',
    'SELECT 1');
PREPARE v11b_evt_type_s FROM @v11b_evt_type_sql;
EXECUTE v11b_evt_type_s;
DEALLOCATE PREPARE v11b_evt_type_s;

SET @v11b_evt_inv_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='email_verification_tokens' AND COLUMN_NAME='invalidated_at'
);
SET @v11b_evt_inv_sql = IF(@v11b_evt_inv_e=0,
    'ALTER TABLE email_verification_tokens ADD COLUMN invalidated_at DATETIME NULL AFTER consumed_at',
    'SELECT 1');
PREPARE v11b_evt_inv_s FROM @v11b_evt_inv_sql;
EXECUTE v11b_evt_inv_s;
DEALLOCATE PREPARE v11b_evt_inv_s;

SET @v11b_evt_req_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='email_verification_tokens' AND COLUMN_NAME='request_id'
);
SET @v11b_evt_req_sql = IF(@v11b_evt_req_e=0,
    'ALTER TABLE email_verification_tokens ADD COLUMN request_id VARCHAR(64) NULL AFTER user_id',
    'SELECT 1');
PREPARE v11b_evt_req_s FROM @v11b_evt_req_sql;
EXECUTE v11b_evt_req_s;
DEALLOCATE PREPARE v11b_evt_req_s;

SET @v11b_prt_inv_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='password_reset_tokens' AND COLUMN_NAME='invalidated_at'
);
SET @v11b_prt_inv_sql = IF(@v11b_prt_inv_e=0,
    'ALTER TABLE password_reset_tokens ADD COLUMN invalidated_at DATETIME NULL AFTER consumed_at',
    'SELECT 1');
PREPARE v11b_prt_inv_s FROM @v11b_prt_inv_sql;
EXECUTE v11b_prt_inv_s;
DEALLOCATE PREPARE v11b_prt_inv_s;

SET @v11b_prt_req_e = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='password_reset_tokens' AND COLUMN_NAME='request_id'
);
SET @v11b_prt_req_sql = IF(@v11b_prt_req_e=0,
    'ALTER TABLE password_reset_tokens ADD COLUMN request_id VARCHAR(64) NULL AFTER user_id',
    'SELECT 1');
PREPARE v11b_prt_req_s FROM @v11b_prt_req_sql;
EXECUTE v11b_prt_req_s;
DEALLOCATE PREPARE v11b_prt_req_s;

SET @v11b_evt_active_ix_e = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='email_verification_tokens' AND INDEX_NAME='idx_email_verification_active'
);
SET @v11b_evt_active_ix_sql = IF(@v11b_evt_active_ix_e=0,
    'ALTER TABLE email_verification_tokens ADD KEY idx_email_verification_active (user_id, consumed_at, invalidated_at, expires_at)',
    'SELECT 1');
PREPARE v11b_evt_active_ix_s FROM @v11b_evt_active_ix_sql;
EXECUTE v11b_evt_active_ix_s;
DEALLOCATE PREPARE v11b_evt_active_ix_s;

SET @v11b_prt_active_ix_e = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='password_reset_tokens' AND INDEX_NAME='idx_password_reset_active'
);
SET @v11b_prt_active_ix_sql = IF(@v11b_prt_active_ix_e=0,
    'ALTER TABLE password_reset_tokens ADD KEY idx_password_reset_active (user_id, consumed_at, invalidated_at, expires_at)',
    'SELECT 1');
PREPARE v11b_prt_active_ix_s FROM @v11b_prt_active_ix_sql;
EXECUTE v11b_prt_active_ix_s;
DEALLOCATE PREPARE v11b_prt_active_ix_s;
