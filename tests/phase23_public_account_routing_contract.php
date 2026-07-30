<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void { if (!$condition) $failures[] = $message; };
$read = static function (string $path) use ($root): string {
    $content = file_get_contents($root . '/' . $path);
    if ($content === false) throw new RuntimeException('Unable to read ' . $path);
    return $content;
};

$required = [
    'src/ControlCenter/PublicAccountIdentityResolver.php',
    'src/ControlCenter/AccountPageContext.php',
    'src/ControlCenter/ControlCenterPage.php',
    'src/Http/ControlCenterEndpoint.php',
    'src/Http/HomeServerEndpoint.php',
    'public/homeservers.php',
    'public/api/homeserver/v1/register.php',
    'public/api/homeserver/v1/transfer-request.php',
    'public/api/homeserver/v1/transfer-accept.php',
    'tests/phase23_public_account_routing_database_integration.php',
];
foreach ($required as $path) $assert(is_file($root . '/' . $path), 'Missing Phase 23 file ' . $path . '.');

$resolver = $read('src/ControlCenter/PublicAccountIdentityResolver.php');
$context = $read('src/ControlCenter/AccountPageContext.php');
$shell = $read('src/ControlCenter/ControlCenterPage.php');
$endpoint = $read('src/Http/ControlCenterEndpoint.php');
$homeEndpoint = $read('src/Http/HomeServerEndpoint.php');
$homePage = $read('public/homeservers.php');
$register = $read('public/api/homeserver/v1/register.php');
$transferRequest = $read('public/api/homeserver/v1/transfer-request.php');
$transferAccept = $read('public/api/homeserver/v1/transfer-accept.php');
$shellClient = $read('public/assets/control-center-shell.js');

$assert(str_contains($resolver, "JOIN accounts a ON a.id=au.account_id"), 'Public account resolver does not resolve identities server-side.');
$assert(str_contains($resolver, "au.status='active'") && str_contains($resolver, "a.status='active'"), 'Public account resolver permits inactive membership/account state.');
$assert(str_contains($resolver, 'hash_equals((string) $membership[\'public_id\'], $requestedPublicId)'), 'Public account resolver does not compare selected identities safely.');
$assert(str_contains($resolver, 'account_identity_invalid'), 'Malformed public account identities lack a stable public error.');
$assert(str_contains($resolver, "'account_id' => (int) \$selected['id']"), 'Resolver no longer provides internal IDs to server-side services.');
$assert(str_contains($resolver, "'account_public_id' => (string) \$selected['public_id']"), 'Resolver omits the public account identity.');

$assert(str_contains($context, 'new PublicAccountIdentityResolver'), 'Page context bypasses the shared resolver.');
$assert(str_contains($context, "\$_GET['account']"), 'Page routing does not use the public account query.');
$assert(str_contains($shell, '?account='), 'Control Center shell does not emit public account routes.');
$assert(str_contains($shell, 'data-account-public-id'), 'Control Center shell omits the public account data attribute.');
$assert(!str_contains($shell, 'data-account-id=') && !str_contains($shell, '?account_id='), 'Control Center shell exposes numeric account routing.');
$assert(str_contains($homePage, 'data-account-public-id') && str_contains($homePage, '?account='), 'HomeServer page exposes numeric account routing.');
$assert(!str_contains($homePage, 'data-account-id=') && !str_contains($homePage, '?account_id='), 'HomeServer page retains numeric account markup.');
$assert(str_contains($shellClient, 'url.searchParams.set("account", picker.value)'), 'Account picker does not switch by public account identity.');
$assert(!str_contains($shellClient, 'account_id'), 'Account picker retains numeric routing.');

foreach ([$endpoint, $homeEndpoint] as $boundary) {
    $assert(str_contains($boundary, 'new PublicAccountIdentityResolver'), 'A browser API boundary bypasses the shared public account resolver.');
    $assert(str_contains($boundary, "array_key_exists('account_id', \$payload)"), 'A browser API boundary accepts legacy numeric account payloads.');
    $assert(str_contains($boundary, 'account_public_identity_required'), 'A browser API boundary lacks a stable legacy-payload error.');
    $assert(str_contains($boundary, "payload['account_public_id']"), 'A browser API boundary does not read the public account identity.');
}

$browserFiles = [
    'public/assets/control-center.js',
    'public/assets/billing-control-center.js',
    'public/assets/homeserver-fleet.js',
    'public/assets/homeserver-transfer-accept.js',
    'public/assets/account-security.js',
    'public/assets/operations-control-center.js',
    'public/assets/recovery-control-center.js',
    'public/assets/infrastructure-control-center.js',
    'public/assets/federated-settings.js',
];
foreach ($browserFiles as $path) {
    $browser = $read($path);
    $assert(str_contains($browser, 'account_public_id'), $path . ' does not send a public account identity.');
    foreach (['account_id', 'dataset.accountId', 'data-account-id', 'target_account_id'] as $forbidden) {
        $assert(!str_contains($browser, $forbidden), $path . ' contains forbidden numeric account pattern ' . $forbidden . '.');
    }
    $assert(!str_contains($browser, 'localStorage') && !str_contains($browser, 'sessionStorage'), $path . ' persists account state in browser storage.');
}

$assert(str_contains($register, "unset(\$result['device_id'])") && str_contains($register, "'account_public_id'"), 'HomeServer registration response is not public-identity-only.');
$assert(str_contains($transferAccept, "unset(\$result['license_id'])") && str_contains($transferAccept, "'account_public_id'"), 'Transfer acceptance response is not public-identity-only.');
$assert(str_contains($transferRequest, "payload['target_account_public_id']"), 'Transfer request does not accept a public destination account identity.');
$assert(!str_contains($transferRequest, "payload['target_account_id']"), 'Transfer request accepts a numeric destination account identity.');
$assert(str_contains($transferRequest, "SELECT id FROM accounts WHERE public_id=:public"), 'Transfer destination is not resolved server-side.');

$allChanged = implode("\n", array_map($read, [
    'src/ControlCenter/AccountPageContext.php',
    'src/ControlCenter/ControlCenterPage.php',
    'src/Http/ControlCenterEndpoint.php',
    'src/Http/HomeServerEndpoint.php',
    'public/homeservers.php',
]));
$assert(!str_contains($allChanged, "\$_GET['account_id']"), 'Page/server routing still reads a numeric account query.');

if ($failures !== []) {
    fwrite(STDERR, "Phase 23 public account routing contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 23 public account routing contract passed.\n");
