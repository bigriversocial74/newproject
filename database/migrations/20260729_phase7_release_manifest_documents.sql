SET NAMES utf8mb4;
SET time_zone = '+00:00';

SET @vp3_phase7_has_manifest_document = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='software_releases' AND COLUMN_NAME='manifest_document'
);
SET @vp3_phase7_manifest_document_sql = IF(
    @vp3_phase7_has_manifest_document=0,
    'ALTER TABLE software_releases ADD COLUMN manifest_document LONGTEXT NULL AFTER manifest_hash',
    'SELECT 1'
);
PREPARE vp3_phase7_manifest_document_statement FROM @vp3_phase7_manifest_document_sql;
EXECUTE vp3_phase7_manifest_document_statement;
DEALLOCATE PREPARE vp3_phase7_manifest_document_statement;
