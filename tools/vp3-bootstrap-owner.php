<?php

declare(strict_types=1);

use Vp3\Auth\PasswordPolicy;
use Vp3\Database;
use Vp3\Deployment\InitialOwnerBootstrapService;

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

$options = [];
foreach (array_slice($argv, 1) as $argument) {
    if (!str_starts_with($argument, '--') || !str_contains($argument, '=')) {
        continue;
    }
    [$key, $value] = explode('=', substr($argument, 2), 2);
    $options[strtolower(trim($key))] = trim($value);
}
if (array_key_exists('password', $options)) {
    fwrite(STDERR, "Passwords are prohibited in command-line arguments.\n");
    exit(1);
}

$readPassword = static function (): string {
    $environment = getenv('VP3_BOOTSTRAP_OWNER_PASSWORD');
    if (is_string($environment) && $environment !== '') {
        return $environment;
    }
    if (!function_exists('posix_isatty') || !posix_isatty(STDIN)) {
        throw new RuntimeException('Set VP3_BOOTSTRAP_OWNER_PASSWORD or run this command in an interactive terminal.');
    }
    fwrite(STDERR, 'Initial owner password: ');
    $stty = shell_exec('stty -g 2>/dev/null');
    if (!is_string($stty) || trim($stty) === '') {
        throw new RuntimeException('Unable to protect terminal password input.');
    }
    shell_exec('stty -echo 2>/dev/null');
    try {
        $password = fgets(STDIN);
    } finally {
        shell_exec('stty ' . escapeshellarg(trim($stty)) . ' 2>/dev/null');
        fwrite(STDERR, PHP_EOL);
    }
    if (!is_string($password)) {
        throw new RuntimeException('Unable to read the initial owner password.');
    }
    return rtrim($password, "\r\n");
};

try {
    $configPath = $root . '/config/config.php';
    if (!is_file($configPath)) {
        throw new RuntimeException('Initial owner bootstrap requires config/config.php.');
    }
    $config = require $configPath;
    if (!is_array($config)) {
        throw new RuntimeException('VP3 configuration did not return an array.');
    }
    $email = (string) ($options['email'] ?? getenv('VP3_BOOTSTRAP_OWNER_EMAIL') ?: '');
    $displayName = (string) ($options['display-name'] ?? getenv('VP3_BOOTSTRAP_OWNER_NAME') ?: '');
    $accountName = (string) ($options['account-name'] ?? getenv('VP3_BOOTSTRAP_ACCOUNT_NAME') ?: '');
    $requestId = (string) ($options['request-id'] ?? getenv('VP3_BOOTSTRAP_REQUEST_ID') ?: '');
    $password = $readPassword();

    $service = new InitialOwnerBootstrapService(
        new Database((array) $config['database']),
        new PasswordPolicy((int) ($config['auth']['password_min_length'] ?? 12))
    );
    $result = $service->bootstrap($email, $displayName, $accountName, $password, $requestId);
    $password = str_repeat("\0", strlen($password));
    fwrite(STDOUT, json_encode(['ok' => true, 'data' => $result], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT) . PHP_EOL);
} catch (Throwable $exception) {
    fwrite(STDOUT, json_encode([
        'ok' => false,
        'error' => [
            'code' => substr(trim((string) preg_replace('/[^a-z0-9._:-]+/', '_', strtolower($exception->getMessage())), '_'), 0, 100),
            'message' => 'Initial owner bootstrap did not complete.',
        ],
    ], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT) . PHP_EOL);
    exit(1);
}
