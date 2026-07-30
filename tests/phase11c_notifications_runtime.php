<?php

declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix = 'Vp3\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $path = dirname(__DIR__) . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($path)) {
        require $path;
    }
});

use Vp3\Auth\Mail\NullMailAdapter;
use Vp3\Operations\SmtpOperationalNotificationAdapter;

$failures = [];
$mail = new NullMailAdapter();
$adapter = new SmtpOperationalNotificationAdapter($mail);
$payload = [
    'incident_public_id' => 'OPS-INCIDENT-RUNTIME',
    'event_type' => 'pod_offline',
    'status' => 'open',
    'severity' => 'critical',
    'title' => "POD offline\nunsafe-header-attempt",
    'payload_hash' => hash('sha256', 'phase11c-notification'),
];

try {
    $result = $adapter->deliver(['email' => 'operations@example.test'], $payload);
    $message = $mail->lastMessage();
    if (($result['delivered'] ?? false) !== true || ($result['channel'] ?? '') !== 'smtp') {
        $failures[] = 'Operational SMTP adapter did not return a delivery receipt.';
    }
    if ($message === null || $message['recipient'] !== 'operations@example.test') {
        $failures[] = 'Operational SMTP adapter did not deliver through the mail contract.';
    } elseif (str_contains($message['subject'], "\n") || str_contains($message['subject'], "\r")) {
        $failures[] = 'Operational SMTP subject retained a header-injection newline.';
    }
    if ($message !== null && (str_contains($message['text_body'], 'password') || str_contains($message['text_body'], 'token='))) {
        $failures[] = 'Operational SMTP body contains secret-like content.';
    }
} catch (Throwable $exception) {
    $failures[] = 'Valid operational SMTP delivery failed: ' . $exception->getMessage();
}

try {
    $adapter->deliver(['email' => 'invalid-address'], $payload);
    $failures[] = 'Operational SMTP adapter accepted an invalid recipient.';
} catch (RuntimeException) {
    // Expected.
}

try {
    $adapter->deliver(['email' => 'operations@example.test'], array_replace($payload, ['payload_hash' => 'not-a-hash']));
    $failures[] = 'Operational SMTP adapter accepted an invalid evidence hash.';
} catch (RuntimeException) {
    // Expected.
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 11C notification runtime failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

echo "Phase 11C SMTP operational notification runtime certification passed.\n";
