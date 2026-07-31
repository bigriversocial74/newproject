<?php

declare(strict_types=1);

namespace Vp3\Http;

use RuntimeException;

final class SessionManager
{
    private const APPLICATION_TOKEN_KEY = '_vp3_application_session';
    private const CSRF_KEY = '_csrf';
    private const COOKIE_PATH = '/';
    private const DEFAULT_SAME_SITE = 'Lax';

    /** @param array{name:string,secure:bool,same_site?:string} $config */
    public function __construct(private readonly array $config)
    {
        $name = trim((string) ($this->config['name'] ?? ''));
        if ($name === '' || strlen($name) > 128 || preg_match('/^[A-Za-z0-9_-]+$/', $name) !== 1) {
            throw new RuntimeException('The session cookie name is invalid.');
        }
        if (str_starts_with($name, '__Host-') && !$this->config['secure']) {
            throw new RuntimeException('__Host- session cookies require Secure transport.');
        }
        $this->sameSite();
    }

    /** @return array{lifetime:int,path:string,secure:bool,httponly:bool,samesite:string} */
    public function cookieParameters(): array
    {
        return [
            'lifetime' => 0,
            'path' => self::COOKIE_PATH,
            'secure' => (bool) $this->config['secure'],
            'httponly' => true,
            'samesite' => $this->sameSite(),
        ];
    }

    public function start(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        $parameters = $this->cookieParameters();
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.use_trans_sid', '0');
        ini_set('session.cookie_secure', $parameters['secure'] ? '1' : '0');
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_samesite', $parameters['samesite']);
        session_name($this->config['name']);
        session_set_cookie_params($parameters);

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
            $parameters = $this->cookieParameters();
            unset($parameters['lifetime']);
            setcookie(session_name(), '', ['expires' => time() - 42000] + $parameters);
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

    private function sameSite(): string
    {
        $value = ucfirst(strtolower(trim((string) ($this->config['same_site'] ?? self::DEFAULT_SAME_SITE))));
        if (!in_array($value, ['Lax', 'Strict'], true)) {
            throw new RuntimeException('Session SameSite must be Lax or Strict.');
        }
        return $value;
    }
}
