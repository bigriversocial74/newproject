<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};
$read = static function (string $path) use ($root, &$failures): string {
    $absolute = $root . '/' . $path;
    if (!is_file($absolute)) {
        $failures[] = 'Missing Phase 33 operator file: ' . $path;
        return '';
    }
    $content = file_get_contents($absolute);
    if (!is_string($content)) {
        $failures[] = 'Unable to read Phase 33 operator file: ' . $path;
        return '';
    }
    return $content;
};

$bootstrap = $read('src/Deployment/InitialOwnerBootstrapService.php');
$bootstrapCli = $read('tools/vp3-bootstrap-owner.php');
$signer = $read('src/Deployment/PlatformReleaseSignatureService.php');
$releaseCli = $read('tools/build-platform-release.php');
$health = $read('src/Deployment/DeploymentHealthService.php');
$healthCli = $read('tools/vp3-deployment-health.php');

$assert(str_contains($bootstrap, "au.role='customer_owner'"), 'Initial bootstrap does not create or resolve the customer owner role.');
$assert(str_contains($bootstrap, 'password_hash($password, PASSWORD_DEFAULT)'), 'Initial owner password does not use the current PHP password hash.');
$assert(str_contains($bootstrap, 'PasswordPolicy'), 'Initial owner bootstrap bypasses the retained password policy.');
$assert(str_contains($bootstrap, 'SELECT COUNT(*) FROM accounts'), 'Initial bootstrap does not require an empty account table.');
$assert(str_contains($bootstrap, 'SELECT COUNT(*) FROM users'), 'Initial bootstrap does not require an empty user table.');
$assert(str_contains($bootstrap, "action_type='bootstrap_owner'"), 'Initial bootstrap lacks a replay-safe deployment receipt.');
$assert(!str_contains($bootstrap, "'password' =>"), 'Initial owner plaintext password is persisted in a statement payload.');
$assert(str_contains($bootstrapCli, "array_key_exists('password', $options)"), 'Owner bootstrap CLI does not reject command-line passwords.');
$assert(str_contains($bootstrapCli, 'VP3_BOOTSTRAP_OWNER_PASSWORD'), 'Owner bootstrap CLI lacks a protected environment secret path.');
$assert(str_contains($bootstrapCli, 'stty -echo'), 'Owner bootstrap CLI does not hide interactive password input.');
$assert(!str_contains($bootstrapCli, '--password='), 'Owner bootstrap CLI documents or accepts a password argument.');

$assert(str_contains($signer, 'sodium_crypto_sign_detached'), 'Platform release manifests are not signed with Ed25519.');
$assert(str_contains($signer, 'sodium_crypto_sign_verify_detached'), 'Platform release signatures are not verified.');
$assert(str_contains($signer, 'sodium_crypto_sign_publickey_from_secretkey'), 'Release signing key pairs are not cross-validated.');
$assert(str_contains($signer, 'sodium_memzero'), 'Release signing private key material is not cleared.');
$assert(str_contains($releaseCli, 'platform-release-manifest.json'), 'Release artifact builder omits the manifest artifact.');
$assert(str_contains($releaseCli, 'platform-release-signature.json'), 'Release artifact builder omits the detached signature artifact.');
$assert(str_contains($releaseCli, 'VP3_PLATFORM_RELEASE_OUTPUT_ROOT'), 'Release artifact output is not explicitly bounded.');

foreach (['database', 'schema', 'active_release', 'latest_deployment', 'failed_steps', 'worker_entrypoints'] as $check) {
    $assert(str_contains($health, "'" . $check . "'"), 'Deployment health report omits ' . $check . '.');
}
$assert(str_contains($health, "action_type='platform_health_verify'"), 'Deployment health does not persist replay-safe receipts.');
$assert(str_contains($health, 'scheduler_contract'), 'Deployment health omits the worker scheduler contract.');
$assert(str_contains($healthCli, 'VP3_DEPLOYMENT_HEALTH_REQUEST_ID'), 'Deployment health CLI lacks a stable request identity.');

if ($failures !== []) {
    fwrite(STDERR, "Phase 33 operator controls contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 33 operator controls contract passed.\n");
