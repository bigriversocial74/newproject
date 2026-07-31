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
        if (!str_starts_with($class, $prefix)) return;
        $path = $root . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($path)) require $path;
    });
}

$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void { if (!$condition) $failures[] = $message; };

$raw = [
    'data' => [
        'user' => ['id' => 11, 'public_id' => 'USR-P27-PUBLIC', 'email' => 'person@example.test', 'display_name' => 'Person', 'status' => 'active'],
        'session' => ['id' => 22, 'user_id' => 11, 'public_id' => 'SES-P27-PUBLIC', 'absolute_expires_at' => '2030-01-01 00:00:00'],
        'csrf_token' => 'csrf-public-token',
    ],
];
$safe = PublicResponseGuard::sanitize($raw);
PublicResponseGuard::assertSafe($safe);
$assert(!isset($safe['data']['user']['id'], $safe['data']['session']['id'], $safe['data']['session']['user_id']), 'Authentication response retained internal IDs.');
$assert(($safe['data']['user']['public_id'] ?? null) === 'USR-P27-PUBLIC', 'Authentication response lost the public user identity.');
$assert(($safe['data']['session']['public_id'] ?? null) === 'SES-P27-PUBLIC', 'Authentication response lost the public session identity.');
$assert(($safe['data']['csrf_token'] ?? null) === 'csrf-public-token', 'Authentication response lost the CSRF token.');

$authEndpoint = (string) file_get_contents($root . '/src/Http/AuthEndpoint.php');
$register = (string) file_get_contents($root . '/public/api/auth/register.php');
$current = (string) file_get_contents($root . '/public/api/auth/current.php');
$login = (string) file_get_contents($root . '/public/api/auth/login.php');
$assert(str_contains($authEndpoint, 'PublicResponseGuard::enable()'), 'AuthEndpoint does not enable the public response boundary.');
$assert(str_contains($register, "'account_public_id'") && str_contains($register, "'user_public_id'"), 'Registration omits public identities.');
$assert(!str_contains($register, "'account_id' =>") && !str_contains($register, "'user_id' =>"), 'Registration exposes numeric identities.');
$assert(str_contains($current, "'user' => \$current['user']") && str_contains($current, "'session' => \$current['session']"), 'Current-session endpoint no longer returns the certified authentication context.');
$assert(str_contains($login, "'user' => \$user") && str_contains($login, "'session' => \$applicationSession"), 'Login endpoint no longer returns the certified authentication context.');

foreach (glob($root . '/public/api/auth/*.php') ?: [] as $path) {
    $source = (string) file_get_contents($path);
    $assert(str_contains($source, 'AuthEndpoint::requireMethod'), basename($path) . ' bypasses the guarded authentication boundary.');
    foreach (["'account_id' =>", "'user_id' =>", "'session_id' =>"] as $forbidden) {
        $assert(!str_contains($source, $forbidden), basename($path) . ' explicitly emits internal identity ' . $forbidden . '.');
    }
    $assert(!str_contains($source, '$exception->getMessage()'), basename($path) . ' leaks internal exception messages.');
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 27 public authentication response contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 27 public authentication response contract passed.\n");
