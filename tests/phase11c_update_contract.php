<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

$path = $root . '/src/Updates/LocalPodSoftwareUpdateAdapter.php';
$assert(is_file($path), 'Local POD software update adapter is missing.');
$source = is_file($path) ? (string) file_get_contents($path) : '';
foreach ([
    'PortableLocalPodBackupAdapter',
    'createPreUpdateBackup',
    'verifyBackup',
    'release_artifacts',
    'hash_file',
    'size_bytes',
    'safeArchivePath',
    'zipEntryIsSymlink',
    'vp3-update.json',
    'MYSQL_PWD',
    "['bypass_shell' => true]",
    'pre_update_backup_reference',
    'restoreBackup',
    'shared/config',
    'installation checksum validation',
    'The local POD update adapter does not execute private HomeServer updates',
] as $contract) {
    $assert(str_contains($source, $contract), 'Local POD update adapter is missing contract: ' . $contract);
}
$assert(!str_contains($source, 'extractTo('), 'Local POD update adapter uses unsafe bulk ZIP extraction.');
$assert(!str_contains($source, '--password='), 'Local POD update adapter exposes the database password in process arguments.');
$assert(!str_contains($source, 'shell_exec('), 'Local POD update adapter invokes an interpolated shell command.');

$resolver = (string) file_get_contents($root . '/src/Backups/DatabaseDumpBinaryResolver.php');
foreach (['--no-tablespaces', '--add-drop-table', 'database-dump-schema', 'chmod($wrapper, 0700)'] as $contract) {
    $assert(str_contains($resolver, $contract), 'Identity-preserving database dump resolver is missing contract: ' . $contract);
}
$assert(!str_contains($resolver, '--add-drop-database'), 'Backup tooling still destroys the tenant database identity during restore.');
$assert(!str_contains($resolver, "'--databases'"), 'Backup tooling still recreates the tenant database during restore.');

$resetter = (string) file_get_contents($root . '/src/Backups/DatabaseSchemaResetter.php');
foreach ([
    'information_schema.EVENTS',
    'information_schema.ROUTINES',
    'information_schema.TRIGGERS',
    'information_schema.TABLES',
    'DROP EVENT',
    'DROP PROCEDURE',
    'DROP FUNCTION',
    'DROP TRIGGER',
    'DROP VIEW',
    'DROP TABLE',
    'FOREIGN_KEY_CHECKS=0',
    'FOREIGN_KEY_CHECKS=1',
] as $contract) {
    $assert(str_contains($resetter, $contract), 'Connection-preserving schema resetter is missing contract: ' . $contract);
}

$portable = (string) file_get_contents($root . '/src/Backups/PortableLocalPodBackupAdapter.php');
foreach (['DatabaseSchemaResetter', 'verifyBackup', 'database_schema_reset', 'databaseState'] as $contract) {
    $assert(str_contains($portable, $contract), 'Portable backup adapter is missing restore-safety contract: ' . $contract);
}

$factory = (string) file_get_contents($root . '/src/Runtime/AdapterFactory.php');
$assert(str_contains($factory, 'LocalPodSoftwareUpdateAdapter'), 'Local POD update adapter is not factory-wired.');
$assert(str_contains($factory, "driver === 'local-pod'"), 'The local-pod update driver is not factory-wired.');

if ($failures !== []) {
    fwrite(STDERR, "Phase 11C update contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

echo "Phase 11C local POD update and rollback contract passed.\n";
