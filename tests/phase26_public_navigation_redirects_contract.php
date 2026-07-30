<?php

declare(strict_types=1);

use Vp3\ControlCenter\ControlCenterUrl;

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
$rejects = static function (callable $work) use (&$failures): bool {
    try { $work(); } catch (InvalidArgumentException) { return true; } catch (Throwable $exception) {
        $failures[] = 'Unexpected URL-boundary exception: ' . $exception::class . ': ' . $exception->getMessage();
        return false;
    }
    return false;
};

$relative = ControlCenterUrl::relative('/billing.php', 'ACC-26.PUBLIC', ['checkout' => 'success']);
$assert($relative === '/billing.php?account=ACC-26.PUBLIC&checkout=success', 'Relative URL does not carry the public account identity deterministically.');
$absolute = ControlCenterUrl::absolute('https://vp3.example.test', '/billing.php', 'ACC-26.PUBLIC');
$assert($absolute === 'https://vp3.example.test/billing.php?account=ACC-26.PUBLIC', 'Absolute URL is not secure and public-account-scoped.');
$assert($rejects(fn () => ControlCenterUrl::relative('//evil.example/path.php', 'ACC-26.PUBLIC')), 'Protocol-relative paths were accepted.');
$assert($rejects(fn () => ControlCenterUrl::relative('/billing.php', '1')), 'Malformed public account identity was accepted.');
$assert($rejects(fn () => ControlCenterUrl::relative('/billing.php', 'ACC-26.PUBLIC', ['account_id' => 42])), 'Numeric account override was accepted.');
$assert($rejects(fn () => ControlCenterUrl::relative('/billing.php', 'ACC-26.PUBLIC', ['account' => 'OTHER'])), 'Public account override was accepted.');
$assert($rejects(fn () => ControlCenterUrl::relative('/billing.php', 'ACC-26.PUBLIC', ['state' => ['nested']])), 'Non-scalar query value was accepted.');
$assert($rejects(fn () => ControlCenterUrl::absolute('http://vp3.example.test', '/billing.php', 'ACC-26.PUBLIC')), 'Non-HTTPS base URL was accepted.');
$assert($rejects(fn () => ControlCenterUrl::absolute('https://user@vp3.example.test', '/billing.php', 'ACC-26.PUBLIC')), 'Username-bearing base URL was accepted.');
$assert($rejects(fn () => ControlCenterUrl::absolute('https://user:pass@vp3.example.test', '/billing.php', 'ACC-26.PUBLIC')), 'Credential-bearing base URL was accepted.');

$billingAction = (string) file_get_contents($root . '/public/api/control-center/v1/billing-action.php');
$shell = (string) file_get_contents($root . '/src/ControlCenter/ControlCenterPage.php');
$builder = (string) file_get_contents($root . '/src/ControlCenter/ControlCenterUrl.php');
$assert(str_contains($billingAction, 'ControlCenterUrl::absolute') && str_contains($billingAction, "\$account['account_public_id']"), 'Stripe return URLs bypass the public account URL builder.');
$assert(str_contains($shell, 'ControlCenterUrl::relative'), 'Shared navigation bypasses the public account URL builder.');
$assert(str_contains($builder, 'PHP_QUERY_RFC3986') && str_contains($builder, "array_key_exists('account_id', \$query)"), 'URL builder lacks encoded query and account-override protection.');
foreach (['success_url', 'cancel_url', 'return_url'] as $field) {
    $assert(!str_contains($billingAction, "\$payload['{$field}']"), 'Billing accepts a caller-controlled redirect field: ' . $field . '.');
}

$scanRoots = [$root . '/public', $root . '/src/ControlCenter'];
foreach ($scanRoots as $scanRoot) {
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($scanRoot, FilesystemIterator::SKIP_DOTS));
    foreach ($iterator as $file) {
        if (!$file->isFile() || !in_array(strtolower($file->getExtension()), ['php', 'js'], true)) continue;
        $source = (string) file_get_contents($file->getPathname());
        if (preg_match('/[?&]account_id=/', $source) === 1) {
            $failures[] = 'Generated numeric account URL remains in ' . substr($file->getPathname(), strlen($root) + 1) . '.';
        }
        if (preg_match('/searchParams\.(?:set|append)\(["\']account_id["\']/', $source) === 1) {
            $failures[] = 'Browser URL API writes numeric account identity in ' . substr($file->getPathname(), strlen($root) + 1) . '.';
        }
    }
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 26 public navigation contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 26 public navigation and redirect contract passed.\n");
