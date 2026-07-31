<?php

declare(strict_types=1);

use Vp3\Http\PublicResponseGuard;

$root = dirname(__DIR__);
$autoload = $root . '/vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
} else {
    spl_autoload_register(static function (string $class) use ($root): void {
        $prefix = 'Vp3\\';
        if (!str_starts_with($class, $prefix)) {
            return;
        }
        $path = $root . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($path)) {
            require $path;
        }
    });
}

$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

$raw = [
    'data' => [
        'id' => 91,
        'account_id' => 12,
        'public_id' => 'ACC-P25-PUBLIC',
        'request_id' => 'REQ-P25-PUBLIC',
        'signing_key_id' => 'KEY-P25-PUBLIC',
        'amount_due' => 2500,
        'nested' => [
            ['license_id' => 77, 'license_public_id' => 'LIC-P25-PUBLIC'],
            ['job_id' => 33, 'public_id' => 'JOB-P25-PUBLIC'],
        ],
    ],
];
$safe = PublicResponseGuard::sanitize($raw);
$assert(!isset($safe['data']['id'], $safe['data']['account_id']), 'Top-level internal identifiers were not removed.');
$assert(!isset($safe['data']['nested'][0]['license_id'], $safe['data']['nested'][1]['job_id']), 'Nested internal identifiers were not removed.');
$assert(($safe['data']['public_id'] ?? null) === 'ACC-P25-PUBLIC', 'Public identity was removed.');
$assert(($safe['data']['request_id'] ?? null) === 'REQ-P25-PUBLIC', 'Request identity was removed.');
$assert(($safe['data']['signing_key_id'] ?? null) === 'KEY-P25-PUBLIC', 'Signing-key identity was removed.');
$assert(($safe['data']['amount_due'] ?? null) === 2500, 'Customer-visible numeric data was removed.');

try {
    PublicResponseGuard::assertSafe($raw);
    $failures[] = 'Raw internal identifiers passed the public response assertion.';
} catch (LogicException) {
}
try {
    PublicResponseGuard::assertSafe($safe);
} catch (Throwable $exception) {
    $failures[] = 'Sanitized response failed validation: ' . $exception->getMessage();
}

$jsonResponse = (string) file_get_contents($root . '/src/Http/JsonResponse.php');
$guard = (string) file_get_contents($root . '/src/Http/PublicResponseGuard.php');
$controlBootstrap = (string) file_get_contents($root . '/public/api/control-center/v1/_bootstrap.php');
$controlEndpoint = (string) file_get_contents($root . '/src/Http/ControlCenterEndpoint.php');
$homeServerEndpoint = (string) file_get_contents($root . '/src/Http/HomeServerEndpoint.php');

$assert(str_contains($jsonResponse, 'PublicResponseGuard::sanitize($payload)') && str_contains($jsonResponse, 'PublicResponseGuard::assertSafe($payload)'), 'JSON responses do not sanitize and validate enabled public payloads.');
$assert(str_contains($controlBootstrap, 'PublicResponseGuard::enable()'), 'Control Center bootstrap does not enable the public response boundary.');
$assert(str_contains($controlEndpoint, 'PublicResponseGuard::enable()'), 'Control Center account contexts do not enable the public response boundary.');
$assert(str_contains($homeServerEndpoint, 'PublicResponseGuard::enable()'), 'HomeServer browser account contexts do not enable the public response boundary.');
$assert(str_contains($guard, "'source_id' => true") && str_contains($guard, "'license_id' => true") && str_contains($guard, "'session_id' => true"), 'The forbidden-key catalog omits required internal relationships.');

$deviceMethodStart = strpos($homeServerEndpoint, 'public static function requireMethod(string $method)');
$browserMethodStart = strpos($homeServerEndpoint, 'public static function requireBrowserMethod(string $method)');
$payloadMethodStart = strpos($homeServerEndpoint, 'public static function payload()');
$deviceMethodSource = $deviceMethodStart !== false
    && $browserMethodStart !== false
    && $deviceMethodStart < $browserMethodStart
        ? substr($homeServerEndpoint, $deviceMethodStart, $browserMethodStart - $deviceMethodStart)
        : '';
$browserMethodSource = $browserMethodStart !== false
    && $payloadMethodStart !== false
    && $browserMethodStart < $payloadMethodStart
        ? substr($homeServerEndpoint, $browserMethodStart, $payloadMethodStart - $browserMethodStart)
        : '';

$assert($deviceMethodSource !== '' && !str_contains($deviceMethodSource, 'PublicResponseGuard::enable()'), 'Device bearer helpers unexpectedly enable the browser response boundary.');
$assert($browserMethodSource !== '' && str_contains($browserMethodSource, 'PublicResponseGuard::enable()'), 'HomeServer browser helper does not enable the public response boundary.');

if ($failures !== []) {
    fwrite(STDERR, "Phase 25 public response boundary contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 25 public response boundary contract passed.\n");
