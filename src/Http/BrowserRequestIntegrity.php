<?php

declare(strict_types=1);

namespace Vp3\Http;

use InvalidArgumentException;
use Throwable;
use Vp3\Auth\AuthPublicException;

final class BrowserRequestIntegrity
{
    private string $scheme;
    private string $origin;
    private string $authority;
    private bool $sourceRequired;

    public function __construct(string $baseUrl, string $environment)
    {
        [$this->scheme, $this->origin, $this->authority] = $this->canonicalBaseUrl($baseUrl);
        $this->sourceRequired = strtolower(trim($environment)) === 'production';
    }

    /** @param array<string,mixed> $server */
    public function assertTrusted(array $server): void
    {
        try {
            $this->assertTrustedHeaders($server);
        } catch (AuthPublicException $exception) {
            throw $exception;
        } catch (Throwable) {
            $this->rejectOrigin();
        }
    }

    /** @param array<string,mixed> $server */
    public function assertTrustedMutation(array $server, ?string $expectedMethod = null): void
    {
        $method = strtoupper(trim((string) ($server['REQUEST_METHOD'] ?? 'GET')));
        if ($expectedMethod !== null && $method !== strtoupper($expectedMethod)) {
            throw new AuthPublicException(
                'method_not_allowed',
                strtoupper($expectedMethod) . ' required.',
                405
            );
        }

        $this->assertTrusted($server);

        if (in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            $this->assertJsonContentType($server);
        }
    }

    /** @param array<string,mixed> $server */
    private function assertTrustedHeaders(array $server): void
    {
        $hostHeader = trim((string) ($server['HTTP_HOST'] ?? ''));
        if ($hostHeader === '' && !$this->sourceRequired) {
            $hostHeader = trim((string) ($server['SERVER_NAME'] ?? ''));
        }
        if ($hostHeader === '' || !hash_equals($this->authority, $this->authorityFromHostHeader($hostHeader))) {
            $this->rejectOrigin();
        }

        $fetchSite = strtolower(trim((string) ($server['HTTP_SEC_FETCH_SITE'] ?? '')));
        if ($fetchSite !== '' && !in_array($fetchSite, ['same-origin', 'none'], true)) {
            $this->rejectOrigin();
        }

        $origin = trim((string) ($server['HTTP_ORIGIN'] ?? ''));
        if ($origin !== '') {
            if (strtolower($origin) === 'null' || !hash_equals($this->origin, $this->originFromUrl($origin, false))) {
                $this->rejectOrigin();
            }
            return;
        }

        $referer = trim((string) ($server['HTTP_REFERER'] ?? ''));
        if ($referer !== '') {
            if (!hash_equals($this->origin, $this->originFromUrl($referer, true))) {
                $this->rejectOrigin();
            }
            return;
        }

        if ($this->sourceRequired) {
            $this->rejectOrigin();
        }
    }

    /** @param array<string,mixed> $server */
    private function assertJsonContentType(array $server): void
    {
        $contentType = strtolower(trim((string) ($server['CONTENT_TYPE'] ?? $server['HTTP_CONTENT_TYPE'] ?? '')));
        $mediaType = trim(explode(';', $contentType, 2)[0] ?? '');
        $isJson = $mediaType === 'application/json'
            || preg_match('~^application/[a-z0-9!#$&^_.+\-]+\+json$~', $mediaType) === 1;

        if (!$isJson) {
            throw new AuthPublicException(
                'unsupported_media_type',
                'A JSON request body is required.',
                415
            );
        }
    }

    /** @return array{0:string,1:string,2:string} */
    private function canonicalBaseUrl(string $baseUrl): array
    {
        $parts = parse_url(trim($baseUrl));
        if (!is_array($parts)) {
            throw new InvalidArgumentException('The application base URL is invalid.');
        }
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = strtolower((string) ($parts['host'] ?? ''));
        $path = (string) ($parts['path'] ?? '');
        if (!in_array($scheme, ['http', 'https'], true)
            || $host === ''
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['query'])
            || isset($parts['fragment'])
            || !in_array($path, ['', '/'], true)) {
            throw new InvalidArgumentException('The application base URL must be a canonical HTTP origin.');
        }
        $port = isset($parts['port']) ? (int) $parts['port'] : null;
        $authority = $this->formatAuthority($host, $port, $scheme);
        return [$scheme, $scheme . '://' . $authority, $authority];
    }

    private function authorityFromHostHeader(string $hostHeader): string
    {
        if ($hostHeader === '' || preg_match('/[\s\/\?#@,]/', $hostHeader) === 1) {
            $this->rejectOrigin();
        }
        $parts = parse_url($this->scheme . '://' . $hostHeader);
        if (!is_array($parts)
            || trim((string) ($parts['host'] ?? '')) === ''
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['query'])
            || isset($parts['fragment'])
            || (isset($parts['path']) && $parts['path'] !== '')) {
            $this->rejectOrigin();
        }
        return $this->formatAuthority(
            strtolower((string) $parts['host']),
            isset($parts['port']) ? (int) $parts['port'] : null,
            $this->scheme
        );
    }

    private function originFromUrl(string $url, bool $allowPath): string
    {
        $parts = parse_url($url);
        if (!is_array($parts)) {
            $this->rejectOrigin();
        }
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = strtolower((string) ($parts['host'] ?? ''));
        $path = (string) ($parts['path'] ?? '');
        if (!in_array($scheme, ['http', 'https'], true)
            || $host === ''
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['fragment'])
            || (!$allowPath && (!in_array($path, ['', '/'], true) || isset($parts['query'])))) {
            $this->rejectOrigin();
        }
        return $scheme . '://' . $this->formatAuthority(
            $host,
            isset($parts['port']) ? (int) $parts['port'] : null,
            $scheme
        );
    }

    private function formatAuthority(string $host, ?int $port, string $scheme): string
    {
        $host = trim($host, '[]');
        if ($host === '' || preg_match('/[\s\/\?#@,]/', $host) === 1) {
            throw new InvalidArgumentException('The request host is invalid.');
        }
        if (str_contains($host, ':')) {
            $host = '[' . $host . ']';
        }
        if ($port !== null && ($port < 1 || $port > 65535)) {
            throw new InvalidArgumentException('The request port is invalid.');
        }
        $defaultPort = $scheme === 'https' ? 443 : 80;
        return $port === null || $port === $defaultPort ? $host : $host . ':' . $port;
    }

    private function rejectOrigin(): never
    {
        throw new AuthPublicException(
            'untrusted_request_origin',
            'The request origin is not trusted.',
            403
        );
    }
}
