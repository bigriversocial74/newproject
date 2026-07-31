<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\Auth\AuthRuntimeConfigurationValidator;
use Vp3\Http\AuthRequestIntegrity;
use Vp3\Http\SessionManager;

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
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) $failures[] = $message;
};
$expectRejected = static function (callable $callback, string $message) use (&$failures): void {
    try {
        $callback();
        $failures[] = $message;
    } catch (AuthPublicException $exception) {
        if ($exception->publicCode() !== 'untrusted_request_origin' || $exception->httpStatus() !== 403) {
            $failures[] = 'Request integrity rejection did not use the stable public contract.';
        }
    }
};

$guard = new AuthRequestIntegrity('https://vp3.example.test', 'production');
try {
    $guard->assertTrusted([
        'HTTP_HOST' => 'vp3.example.test',
        'HTTP_ORIGIN' => 'https://vp3.example.test',
        'HTTP_SEC_FETCH_SITE' => 'same-origin',
    ]);
    $guard->assertTrusted([
        'HTTP_HOST' => 'vp3.example.test:443',
        'HTTP_REFERER' => 'https://vp3.example.test/account/security?view=sessions',
    ]);
} catch (Throwable $exception) {
    $failures[] = 'Trusted same-origin authentication request was rejected: ' . $exception->getMessage();
}

$expectRejected(static fn () => $guard->assertTrusted([
    'HTTP_HOST' => 'vp3.example.test',
    'HTTP_ORIGIN' => 'https://attacker.example.test',
]), 'Cross-origin authentication request was accepted.');
$expectRejected(static fn () => $guard->assertTrusted([
    'HTTP_HOST' => 'attacker.example.test',
    'HTTP_ORIGIN' => 'https://vp3.example.test',
]), 'Mismatched request host was accepted.');
$expectRejected(static fn () => $guard->assertTrusted([
    'HTTP_HOST' => 'vp3.example.test',
    'HTTP_ORIGIN' => 'null',
]), 'Opaque null origin was accepted.');
$expectRejected(static fn () => $guard->assertTrusted([
    'HTTP_HOST' => 'vp3.example.test',
    'HTTP_ORIGIN' => 'https://vp3.example.test',
    'HTTP_SEC_FETCH_SITE' => 'cross-site',
]), 'Cross-site fetch metadata was accepted.');
$expectRejected(static fn () => $guard->assertTrusted([
    'HTTP_HOST' => 'vp3.example.test',
]), 'Production request without Origin or Referer was accepted.');

try {
    (new AuthRequestIntegrity('http://127.0.0.1:8080', 'test'))->assertTrusted([
        'HTTP_HOST' => '127.0.0.1:8080',
    ]);
} catch (Throwable $exception) {
    $failures[] = 'Test environment without browser source headers was rejected: ' . $exception->getMessage();
}

$session = new SessionManager(['name' => '__Host-vp3_phase28', 'secure' => true]);
$parameters = $session->cookieParameters();
$assert($parameters['path'] === '/', 'Session cookie path is not root-scoped.');
$assert($parameters['secure'] === true, 'Session cookie is not Secure.');
$assert($parameters['httponly'] === true, 'Session cookie is not HttpOnly.');
$assert(in_array($parameters['samesite'], ['Lax', 'Strict'], true), 'Session cookie SameSite is not explicit and safe.');
$assert(!array_key_exists('domain', $parameters), 'Session cookie parameters include a Domain attribute.');
try {
    new SessionManager(['name' => '__Host-insecure', 'secure' => false]);
    $failures[] = '__Host- session cookie accepted insecure transport.';
} catch (RuntimeException) {
    // Expected.
}
try {
    new SessionManager(['name' => 'vp3_none', 'secure' => true, 'same_site' => 'None']);
    $failures[] = 'Session cookie accepted SameSite=None.';
} catch (RuntimeException) {
    // Expected.
}

$production = [
    'app' => [
        'env' => 'production',
        'base_url' => 'https://vp3.example.test',
        'session_name' => '__Host-vp3_session',
        'session_secure' => true,
    ],
    'auth' => [
        'mfa_challenge_ttl_seconds' => 300,
        'mfa_recovery_code_count' => 10,
        'team_invitation_ttl_seconds' => 604800,
        'secret_encryption_key_base64' => base64_encode(str_repeat('k', 32)),
        'secret_encryption_key_id' => 'auth-test-key',
    ],
];
$validator = new AuthRuntimeConfigurationValidator();
try {
    $validator->validate($production, false);
} catch (Throwable $exception) {
    $failures[] = 'Valid production authentication transport configuration was rejected: ' . $exception->getMessage();
}
$invalidName = $production;
$invalidName['app']['session_name'] = 'vp3_session';
try {
    $validator->validate($invalidName, false);
    $failures[] = 'Production accepted a session cookie without the __Host- prefix.';
} catch (RuntimeException) {
    // Expected.
}
$invalidBase = $production;
$invalidBase['app']['base_url'] = 'https://vp3.example.test/control-center';
try {
    $validator->validate($invalidBase, false);
    $failures[] = 'Production accepted a non-origin APP_BASE_URL.';
} catch (RuntimeException) {
    // Expected.
}

$required = [
    'src/Http/AuthRequestIntegrity.php',
    'src/Http/AuthEndpoint.php',
    'src/Http/SessionManager.php',
    'src/Auth/AuthRuntimeConfigurationValidator.php',
    '.github/workflows/phase28-auth-request-session-transport.yml',
];
foreach ($required as $path) {
    $assert(is_file($root . '/' . $path), 'Missing Phase 28 file: ' . $path);
}
$bootstrap = (string) @file_get_contents($root . '/bootstrap.php');
$endpoint = (string) @file_get_contents($root . '/src/Http/AuthEndpoint.php');
$sessionSource = (string) @file_get_contents($root . '/src/Http/SessionManager.php');
$validatorSource = (string) @file_get_contents($root . '/src/Auth/AuthRuntimeConfigurationValidator.php');
$phase27Workflow = (string) @file_get_contents($root . '/.github/workflows/phase27-public-authentication-response.yml');
$retainedWorkflow = (string) @file_get_contents($root . '/.github/workflows/vp3-retained-certification.yml');
$assert(str_contains($bootstrap, 'AuthEndpoint::configureRequestIntegrity($authRequestIntegrity)')
    && str_contains($bootstrap, "'auth_request_integrity' => $" . 'authRequestIntegrity'),
    'Bootstrap does not centrally configure the authentication request boundary.');
$assert(str_contains($endpoint, 'self::$requestIntegrity->assertTrusted($_SERVER)')
    && str_contains($endpoint, 'request_integrity_unavailable'),
    'AuthEndpoint does not enforce the configured request boundary.');
$assert(str_contains($sessionSource, "session.use_trans_sid', '0'")
    && str_contains($sessionSource, 'cookieParameters()')
    && !str_contains($sessionSource, "'domain' =>"),
    'Session transport does not disable trans-SID or preserve host-only cookie parameters.');
$assert(str_contains($validatorSource, "'__Host-'")
    && str_contains($validatorSource, 'canonical HTTPS origin'),
    'Production validator does not enforce canonical origin and __Host- cookies.');
$assert(str_contains($phase27Workflow, 'workflow_dispatch') && !str_contains($phase27Workflow, 'pull_request:'),
    'Phase 27 workflow still auto-triggers on Phase 28 pull requests.');
$assert(str_contains($retainedWorkflow, 'phase27_public_authentication_response_contract.php')
    && substr_count($retainedWorkflow, 'phase27_public_authentication_response_database_integration.php') >= 2,
    'Consolidated retained certification does not retain Phase 27 coverage.');

if ($failures !== []) {
    fwrite(STDERR, "Phase 28 authentication request/session transport failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 28 authentication request/session transport contract passed.\n");
