<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\Database;
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

$dsn = getenv('VP3_TEST_DSN') ?: '';
if ($dsn === '') {
    fwrite(STDERR, "VP3_TEST_DSN is required.\n");
    exit(1);
}
$database = new Database([
    'dsn' => $dsn,
    'username' => getenv('VP3_TEST_DB_USER') ?: 'root',
    'password' => getenv('VP3_TEST_DB_PASSWORD') ?: '',
    'options' => [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ],
]);
$pdo = $database->pdo();
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) $failures[] = $message;
};

try {
    $pdo->exec('CREATE TEMPORARY TABLE phase29_browser_integrity_probe (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, marker VARCHAR(64) NOT NULL)');
    $insert = $pdo->prepare('INSERT INTO phase29_browser_integrity_probe (marker) VALUES (?)');
    $guard = new BrowserRequestIntegrity('https://vp3.example.test', 'production');

    $guard->assertTrustedMutation([
        'REQUEST_METHOD' => 'POST',
        'HTTP_HOST' => 'vp3.example.test',
        'HTTP_ORIGIN' => 'https://vp3.example.test',
        'HTTP_SEC_FETCH_SITE' => 'same-origin',
        'CONTENT_TYPE' => 'application/json',
    ], 'POST');
    $insert->execute(['trusted']);

    try {
        $guard->assertTrustedMutation([
            'REQUEST_METHOD' => 'POST',
            'HTTP_HOST' => 'vp3.example.test',
            'HTTP_ORIGIN' => 'https://attacker.example.test',
            'HTTP_SEC_FETCH_SITE' => 'cross-site',
            'CONTENT_TYPE' => 'application/json',
        ], 'POST');
        $insert->execute(['cross-origin']);
        $failures[] = 'Cross-origin request reached the database mutation probe.';
    } catch (AuthPublicException $exception) {
        $assert($exception->publicCode() === 'untrusted_request_origin' && $exception->httpStatus() === 403,
            'Cross-origin database-bound request lost the stable public rejection contract.');
    }

    try {
        $guard->assertTrustedMutation([
            'REQUEST_METHOD' => 'POST',
            'HTTP_HOST' => 'vp3.example.test',
            'HTTP_ORIGIN' => 'https://vp3.example.test',
            'HTTP_SEC_FETCH_SITE' => 'same-origin',
            'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
        ], 'POST');
        $insert->execute(['wrong-media']);
        $failures[] = 'Non-JSON request reached the database mutation probe.';
    } catch (AuthPublicException $exception) {
        $assert($exception->publicCode() === 'unsupported_media_type' && $exception->httpStatus() === 415,
            'Non-JSON database-bound request lost the stable media-type rejection contract.');
    }

    $markers = $pdo->query('SELECT marker FROM phase29_browser_integrity_probe ORDER BY id')->fetchAll(PDO::FETCH_COLUMN);
    $assert($markers === ['trusted'], 'Rejected browser requests produced database state.');
    $native = $pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES);
    $assert($native === false || $native === 0, 'Phase 29 database proof did not use native PDO prepares.');
} catch (Throwable $exception) {
    $failures[] = $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 29 browser request integrity database failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 29 browser request integrity database certification passed.\n");
