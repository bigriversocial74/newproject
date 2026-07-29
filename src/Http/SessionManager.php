<?php

declare(strict_types=1);

namespace Vp3\Http;

use RuntimeException;

final class SessionManager
{
    private const APPLICATION_TOKEN_KEY = '_vp3_application_session';
    private const CSRF_KEY = '_csrf';

    /** @param array{name:string,secure:bool} $config */
    public function __construct(private readonly array $config)
    {
    }

    public function start(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_samesite', 'Lax');
        session_name($this->config['name']);
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'domain' => '',
            'secure' => $this->config['secure'],
            'httponly' => true,
            'samesite' => 'Lax',
        ]);

        if (!session_start()) {
            throw new RuntimeException('Unable to start session.');
        }
    }

    public function regenerate(): void
    {
        $this->start();
        if (!session_regenerate_id(true)) {
            throw new RuntimeException('Unable to rotate session identifier.');
        }
        unset($_SESSION[self::CSRF_KEY]);
    }

    public function put(string $key, mixed $value): void
    {
        $this->start();
        $_SESSION[$key] = $value;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $this->start();
        return $_SESSION[$key] ?? $default;
    }

    public function forget(string $key): void
    {
        $this->start();
        unset($_SESSION[$key]);
    }

    public function setApplicationToken(string $token): void
    {
        if ($token === '') {
            throw new RuntimeException('Application session token is required.');
        }
        $this->start();
        $_SESSION[self::APPLICATION_TOKEN_KEY] = $token;
    }

    public function applicationToken(): string
    {
        $this->start();
        return is_string($_SESSION[self::APPLICATION_TOKEN_KEY] ?? null)
            ? (string) $_SESSION[self::APPLICATION_TOKEN_KEY]
            : '';
    }

    public function clearApplicationToken(): void
    {
        $this->start();
        unset($_SESSION[self::APPLICATION_TOKEN_KEY]);
    }

    public function destroy(): void
    {
        $this->start();
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', [
                'expires' => time() - 42000,
                'path' => $params['path'],
                'domain' => $params['domain'],
                'secure' => $params['secure'],
                'httponly' => $params['httponly'],
                'samesite' => $params['samesite'] ?? 'Lax',
            ]);
        }
        session_destroy();
    }

    public function csrfToken(): string
    {
        $this->start();
        if (!isset($_SESSION[self::CSRF_KEY]) || !is_string($_SESSION[self::CSRF_KEY])) {
            $_SESSION[self::CSRF_KEY] = bin2hex(random_bytes(32));
        }
        return (string) $_SESSION[self::CSRF_KEY];
    }

    public function assertCsrf(string $token): void
    {
        $expected = $this->csrfToken();
        if ($token === '' || !hash_equals($expected, $token)) {
            throw new RuntimeException('Invalid CSRF token.');
        }
    }
}
