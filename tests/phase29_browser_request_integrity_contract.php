<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\Http\AuthRequestIntegrity;
use Vp3\Http\BrowserRequestIntegrity;

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
$expectRejected = static function (
    callable $callback,
    string $expectedCode,
    int $expectedStatus,
    string $message
) use (&$failures): void {
    try {
        $callback();
        $failures[] = $message;
    } catch (AuthPublicException $exception) {
        if ($exception->publicCode() !== $expectedCode || $exception->httpStatus() !== $expectedStatus) {
            $failures[] = sprintf(
                'Request rejection used %s/%d instead of %s/%d.',
                $exception->publicCode(),
                $exception->httpStatus(),
                $expectedCode,
                $expectedStatus
            );
        }
    }
};

$guard = new BrowserRequestIntegrity('https://vp3.example.test', 'production');
try {
    $guard->assertTrustedMutation([
        'REQUEST_METHOD' => 'POST',
        'HTTP_HOST' => 'vp3.example.test',
        'HTTP_ORIGIN' => 'https://vp3.example.test',
        'HTTP_SEC_FETCH_SITE' => 'same-origin',
        'CONTENT_TYPE' => 'application/json; charset=utf-8',
    ], 'POST');
    $guard->assertTrustedMutation([
        'REQUEST_METHOD' => 'POST',
        'HTTP_HOST' => 'vp3.example.test:443',
        'HTTP_REFERER' => 'https://vp3.example.test/homeservers.php?account=acct_public',
        'CONTENT_TYPE' => 'application/problem+json',
    ], 'POST');
} catch (Throwable $exception) {
    $failures[] = 'Trusted browser mutation was rejected: ' . $exception->getMessage();
}

$expectRejected(static fn () => $guard->assertTrustedMutation([
    'REQUEST_METHOD' => 'POST',
    'HTTP_HOST' => 'vp3.example.test',
    'HTTP_ORIGIN' => 'https://attacker.example.test',
    'CONTENT_TYPE' => 'application/json',
], 'POST'), 'untrusted_request_origin', 403, 'Cross-origin browser mutation was accepted.');
$expectRejected(static fn () => $guard->assertTrustedMutation([
    'REQUEST_METHOD' => 'POST',
    'HTTP_HOST' => 'attacker.example.test',
    'HTTP_ORIGIN' => 'https://vp3.example.test',
    'CONTENT_TYPE' => 'application/json',
], 'POST'), 'untrusted_request_origin', 403, 'Mismatched browser request host was accepted.');
$expectRejected(static fn () => $guard->assertTrustedMutation([
    'REQUEST_METHOD' => 'POST',
    'HTTP_HOST' => 'vp3.example.test',
    'HTTP_ORIGIN' => 'null',
    'CONTENT_TYPE' => 'application/json',
], 'POST'), 'untrusted_request_origin', 403, 'Opaque null browser origin was accepted.');
$expectRejected(static fn () => $guard->assertTrustedMutation([
    'REQUEST_METHOD' => 'POST',
    'HTTP_HOST' => 'vp3.example.test',
    'HTTP_ORIGIN' => 'https://vp3.example.test',
    'HTTP_SEC_FETCH_SITE' => 'cross-site',
    'CONTENT_TYPE' => 'application/json',
], 'POST'), 'untrusted_request_origin', 403, 'Cross-site Fetch Metadata was accepted.');
$expectRejected(static fn () => $guard->assertTrustedMutation([
    'REQUEST_METHOD' => 'POST',
    'HTTP_HOST' => 'vp3.example.test',
    'CONTENT_TYPE' => 'application/json',
], 'POST'), 'untrusted_request_origin', 403, 'Production browser mutation without source evidence was accepted.');
$expectRejected(static fn () => $guard->assertTrustedMutation([
    'REQUEST_METHOD' => 'POST',
    'HTTP_HOST' => 'vp3.example.test',
    'HTTP_ORIGIN' => 'https://vp3.example.test',
    'CONTENT_TYPE' => 'text/plain',
], 'POST'), 'unsupported_media_type', 415, 'Non-JSON browser mutation was accepted.');

try {
    (new BrowserRequestIntegrity('http://127.0.0.1:8080', 'test'))->assertTrustedMutation([
        'REQUEST_METHOD' => 'POST',
        'HTTP_HOST' => '127.0.0.1:8080',
        'CONTENT_TYPE' => 'application/json',
    ], 'POST');
} catch (Throwable $exception) {
    $failures[] = 'Test client without browser source headers was rejected: ' . $exception->getMessage();
}

try {
    (new AuthRequestIntegrity('https://vp3.example.test', 'production'))->assertTrusted([
        'HTTP_HOST' => 'vp3.example.test',
        'HTTP_ORIGIN' => 'https://vp3.example.test',
        'HTTP_SEC_FETCH_SITE' => 'same-origin',
    ]);
} catch (Throwable $exception) {
    $failures[] = 'Phase 28 authentication integrity compatibility was broken: ' . $exception->getMessage();
}

$required = [
    'src/Http/BrowserRequestIntegrity.php',
    'src/Http/AuthRequestIntegrity.php',
    'src/Http/ControlCenterEndpoint.php',
    'src/Http/HomeServerEndpoint.php',
    '.github/workflows/phase29-browser-request-integrity.yml',
];
foreach ($required as $path) {
    $assert(is_file($root . '/' . $path), 'Missing Phase 29 file: ' . $path);
}

$controlCenter = (string) @file_get_contents($root . '/src/Http/ControlCenterEndpoint.php');
$homeServer = (string) @file_get_contents($root . '/src/Http/HomeServerEndpoint.php');
$controlBootstrap = (string) @file_get_contents($root . '/public/api/control-center/v1/_bootstrap.php');
$homeServerBootstrap = (string) @file_get_contents($root . '/public/api/homeserver/v1/_bootstrap.php');
$controlRequirePosition = strpos($controlCenter, 'self::assertTrustedBrowserRequest($requiredMethod)');
$controlPayloadPosition = strpos($controlCenter, 'public static function payload()');
$assert($controlRequirePosition !== false
    && $controlPayloadPosition !== false
    && $controlRequirePosition < $controlPayloadPosition
    && str_contains($controlCenter, "self::assertTrustedBrowserRequest(strtoupper((string) (\$_SERVER['REQUEST_METHOD'] ?? 'POST')))")
    && str_contains($controlCenter, 'self::$requestIntegrity->assertTrustedMutation($_SERVER, $method)'),
    'Control Center integrity is not enforced both before payload parsing and before account resolution.');
$assert(str_contains($homeServer, 'public static function requireBrowserMethod(string $method)')
    && str_contains($homeServer, 'public static function requireMethod(string $method)')
    && str_contains($homeServer, 'self::$requestIntegrity->assertTrustedMutation($_SERVER, $method)'),
    'HomeServer browser and bearer request boundaries are not explicit.');
$assert(str_contains($controlBootstrap, 'ControlCenterEndpoint::configureRequestIntegrity($requestIntegrity)')
    && str_contains($homeServerBootstrap, 'HomeServerEndpoint::configureRequestIntegrity($requestIntegrity)'),
    'Browser request integrity is not configured in both browser API bootstraps.');

$browserEndpoints = [
    'register.php',
    'suspend.php',
    'revoke.php',
    'replace.php',
    'transfer-request.php',
    'transfer-accept.php',
    'fleet.php',
    'registration-options.php',
];
foreach ($browserEndpoints as $filename) {
    $source = (string) @file_get_contents($root . '/public/api/homeserver/v1/' . $filename);
    $assert(str_contains($source, "HomeServerEndpoint::requireBrowserMethod('POST')"),
        'HomeServer browser endpoint does not enforce the browser request boundary: ' . $filename);
    $integrityPosition = strpos($source, "HomeServerEndpoint::requireBrowserMethod('POST')");
    $payloadPosition = strpos($source, 'HomeServerEndpoint::payload()');
    $assert($integrityPosition !== false && $payloadPosition !== false && $integrityPosition < $payloadPosition,
        'HomeServer browser endpoint parses its payload before integrity validation: ' . $filename);
}

$deviceEndpoints = [
    'activate.php',
    'heartbeat.php',
    'lease.php',
    'manifest.php',
    'update-receipt.php',
];
foreach ($deviceEndpoints as $filename) {
    $source = (string) @file_get_contents($root . '/public/api/homeserver/v1/' . $filename);
    $assert(str_contains($source, "HomeServerEndpoint::requireMethod('POST')")
        && !str_contains($source, 'requireBrowserMethod'),
        'Bearer-authenticated HomeServer endpoint was moved behind the browser-session boundary: ' . $filename);
}

$phase28Workflow = (string) @file_get_contents($root . '/.github/workflows/phase28-auth-request-session-transport.yml');
$retainedWorkflow = (string) @file_get_contents($root . '/.github/workflows/vp3-retained-certification.yml');
$assert(str_contains($phase28Workflow, 'workflow_dispatch') && !str_contains($phase28Workflow, 'pull_request:'),
    'Phase 28 workflow still auto-triggers on Phase 29 pull requests.');
$assert(str_contains($retainedWorkflow, 'phase28_auth_request_session_transport_contract.php')
    && substr_count($retainedWorkflow, 'phase28_auth_request_session_transport_database_integration.php') >= 2,
    'Consolidated retained certification does not retain Phase 28 coverage.');

if ($failures !== []) {
    fwrite(STDERR, "Phase 29 browser request integrity failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 29 browser request integrity contract passed.\n");
