<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

foreach ([
    'src/Backups/LocalPodBackupAdapter.php',
    'src/Backups/SymlinkAwareLocalPodBackupAdapter.php',
    'src/Backups/PortableLocalPodBackupAdapter.php',
    'src/Operations/SmtpOperationalNotificationAdapter.php',
] as $path) {
    $assert(is_file($root . '/' . $path), 'Extended Phase 11C adapter file is missing: ' . $path);
}

$backup = (string) file_get_contents($root . '/src/Backups/LocalPodBackupAdapter.php');
foreach ([
    'sodium_crypto_secretstream_xchacha20poly1305_init_push',
    'sodium_crypto_secretstream_xchacha20poly1305_init_pull',
    'MYSQL_PWD',
    'proc_open',
    "['bypass_shell' => true]",
    '--single-transaction',
    'snapshot_hash',
    'restoreDatabase',
    'assertSnapshot',
] as $contract) {
    $assert(str_contains($backup, $contract), 'Encrypted backup adapter is missing contract: ' . $contract);
}
$assert(!str_contains($backup, '--password='), 'Database password is exposed in the backup command arguments.');
$assert(!str_contains($backup, 'shell_exec('), 'Backup adapter invokes a shell.');

$portable = (string) file_get_contents($root . '/src/Backups/PortableLocalPodBackupAdapter.php');
foreach (['rewrite the restored POD current-release link', 'rewrite the restored POD shared-configuration link', 'portable_links_verified'] as $contract) {
    $assert(str_contains($portable, $contract), 'Portable restore adapter is missing contract: ' . $contract);
}

$notifications = (string) file_get_contents($root . '/src/Operations/SmtpOperationalNotificationAdapter.php');
foreach (['payload_hash', 'recipient_hash', 'contains no credentials or private POD/HomeServer content'] as $contract) {
    $assert(str_contains($notifications, $contract), 'SMTP operational adapter is missing contract: ' . $contract);
}

$factory = (string) file_get_contents($root . '/src/Runtime/AdapterFactory.php');
foreach (['PortableLocalPodBackupAdapter', "driver === 'local-pod'", 'SmtpOperationalNotificationAdapter', "driver === 'smtp'"] as $contract) {
    $assert(str_contains($factory, $contract), 'Adapter factory is missing extended Phase 11C wiring: ' . $contract);
}

if ($failures !== []) {
    fwrite(STDERR, "Extended Phase 11C contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

echo "Extended Phase 11C backup and notification contract passed.\n";
