<?php

declare(strict_types=1);

use Vp3\Queue\QueueLease;
use Vp3\Runtime\AdapterFactory;
use Vp3\Runtime\RuntimeConfigurationValidator;

$root = dirname(__DIR__);
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

$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

try {
    $config = require $root . '/config/config-example.php';
    $validator = new RuntimeConfigurationValidator();
    $validator->validate($config, true);
    $assert(($config['app']['env'] ?? null) === 'development', 'Example config did not default to development.');

    $production = $config;
    $production['app']['env'] = 'production';
    $rejectedExample = false;
    try {
        $validator->validate($production, true);
    } catch (RuntimeException) {
        $rejectedExample = true;
    }
    $assert($rejectedExample, 'Production accepted config-example.php.');

    $rejectedNullAdapter = false;
    try {
        AdapterFactory::provisioning('null', 'production');
    } catch (RuntimeException) {
        $rejectedNullAdapter = true;
    }
    $assert($rejectedNullAdapter, 'Production accepted the null provisioning adapter.');
    $assert(AdapterFactory::provisioning('null', 'development') instanceof Vp3\Provisioning\PodProvisioningAdapter, 'Development null provisioning adapter was unavailable.');

    $lease = new QueueLease(60);
    $tokenA = $lease->token();
    $tokenB = $lease->token();
    $assert(strlen($tokenA) === 64 && ctype_xdigit($tokenA), 'Queue lease token format is invalid.');
    $assert($tokenA !== $tokenB, 'Queue lease tokens were not unique.');

    $rejectedLease = false;
    try {
        new QueueLease(5);
    } catch (RuntimeException) {
        $rejectedLease = true;
    }
    $assert($rejectedLease, 'Unsafe queue lease duration was accepted.');
} catch (Throwable $exception) {
    $failures[] = $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 11A runtime failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 11A runtime configuration and adapter certification passed.\n");
