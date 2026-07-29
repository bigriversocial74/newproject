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

use Vp3\Auth\AuthPublicException;
use Vp3\Auth\Mail\MailAdapterFactory;
use Vp3\Auth\Mail\NullMailAdapter;
use Vp3\Auth\Mail\SmtpMailAdapter;
use Vp3\Runtime\RuntimeConfigurationValidator;

$failures = [];

$exception = new AuthPublicException('stable_code', 'Stable message.', 403);
if ($exception->publicCode() !== 'stable_code' || $exception->httpStatus() !== 403) {
    $failures[] = 'AuthPublicException did not preserve the stable public contract.';
}

$null = MailAdapterFactory::create(['driver' => 'null'], 'test');
if (!$null instanceof NullMailAdapter) {
    $failures[] = 'Test environment did not receive the null mail adapter.';
} else {
    $null->send('owner@example.test', 'Subject', 'Body');
    $message = $null->lastMessage();
    if ($message === null || $message['recipient'] !== 'owner@example.test') {
        $failures[] = 'Null mail adapter did not retain a delivered test message.';
    }
}

try {
    MailAdapterFactory::create(['driver' => 'null'], 'production');
    $failures[] = 'Production accepted the null mail adapter.';
} catch (RuntimeException) {
    // Expected.
}

try {
    new SmtpMailAdapter('smtp.example.test', 587, 'tls', 'user', 'pass', 'sender@example.test', "Unsafe\nName");
    $failures[] = 'SMTP adapter accepted mail-header injection.';
} catch (RuntimeException) {
    // Expected.
}

$validator = new RuntimeConfigurationValidator();
$base = [
    'app' => ['env' => 'test', 'base_url' => 'https://vp3.test', 'session_secure' => true],
    'queue' => ['lease_seconds' => 900],
    'auth' => [
        'session_inactivity_ttl_seconds' => 300,
        'session_absolute_ttl_seconds' => 600,
        'login_attempt_limit' => 8,
        'login_attempt_window_seconds' => 900,
    ],
    'mail' => ['driver' => 'null'],
];
try {
    $validator->validate($base, true);
} catch (Throwable $exception) {
    $failures[] = 'Valid test configuration was rejected: ' . $exception->getMessage();
}

$invalidTtl = $base;
$invalidTtl['auth']['session_absolute_ttl_seconds'] = 299;
try {
    $validator->validate($invalidTtl, true);
    $failures[] = 'Absolute session TTL shorter than inactivity TTL was accepted.';
} catch (RuntimeException) {
    // Expected.
}

if ($failures !== []) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}

echo "Phase 11B runtime certification passed.\n";
