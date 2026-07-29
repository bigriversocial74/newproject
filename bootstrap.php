<?php

declare(strict_types=1);

use Vp3\Auth\AuthService;
use Vp3\Auth\PasswordPolicy;
use Vp3\Database;
use Vp3\Http\SessionManager;

$autoload = __DIR__ . '/vendor/autoload.php';
if (!is_file($autoload)) {
    spl_autoload_register(static function (string $class): void {
        $prefix = 'Vp3\\';
        if (!str_starts_with($class, $prefix)) {
            return;
        }
        $path = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($path)) {
            require $path;
        }
    });
} else {
    require $autoload;
}

$configFile = __DIR__ . '/config/config.php';
if (!is_file($configFile)) {
    $configFile = __DIR__ . '/config/config-example.php';
}
$config = require $configFile;

$database = new Database($config['database']);
$passwordPolicy = new PasswordPolicy((int) $config['auth']['password_min_length']);
$auth = new AuthService($database, $passwordPolicy);
$session = new SessionManager([
    'name' => (string) $config['app']['session_name'],
    'secure' => (bool) $config['app']['session_secure'],
]);

return [
    'config' => $config,
    'database' => $database,
    'auth' => $auth,
    'session' => $session,
];
