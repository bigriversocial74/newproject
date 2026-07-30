SET NAMES utf8mb4;
SET time_zone = '+00:00';

DROP PROCEDURE IF EXISTS vp3_phase13_release_trust_upgrade;
DELIMITER $$
CREATE PROCEDURE vp3_phase13_release_trust_upgrade()
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = 'release_artifacts'
          AND column_name = 'file_name'
    ) THEN
        ALTER TABLE release_artifacts
            ADD COLUMN file_name VARCHAR(190) NULL AFTER storage_reference;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = 'release_artifacts'
          AND column_name = 'authenticode_thumbprint'
    ) THEN
        ALTER TABLE release_artifacts
            ADD COLUMN authenticode_thumbprint VARCHAR(64) NULL AFTER sha256;
    END IF;
END$$
DELIMITER ;
CALL vp3_phase13_release_trust_upgrade();
DROP PROCEDURE IF EXISTS vp3_phase13_release_trust_upgrade;
