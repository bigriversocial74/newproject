<?php

declare(strict_types=1);

namespace Vp3\ControlCenter;

use InvalidArgumentException;

final class ControlCenterUrl
{
    /**
     * @param array<string,scalar|null> $query
     */
    public static function relative(string $path, string $accountPublicId, array $query = []): string
    {
        $path = trim($path);
        $accountPublicId = trim($accountPublicId);
        if (!preg_match('#^/[A-Za-z0-9/_-]+\.php$#', $path) || str_starts_with($path, '//')) {
            throw new InvalidArgumentException('A valid local Control Center path is required.');
        }
        if (!preg_match('/^[A-Za-z0-9._:-]{3,64}$/', $accountPublicId)) {
            throw new InvalidArgumentException('A valid public VP3 account identity is required.');
        }
        if (array_key_exists('account', $query) || array_key_exists('account_id', $query)) {
            throw new InvalidArgumentException('The account identity cannot be overridden.');
        }
        $parameters = ['account' => $accountPublicId];
        foreach ($query as $key => $value) {
            if (!preg_match('/^[A-Za-z][A-Za-z0-9_-]{0,63}$/', (string) $key)) {
                throw new InvalidArgumentException('A valid Control Center query key is required.');
            }
            if ($value !== null && !is_scalar($value)) {
                throw new InvalidArgumentException('Control Center query values must be scalar.');
            }
            if ($value !== null) {
                $parameters[(string) $key] = $value;
            }
        }
        return $path . '?' . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * @param array<string,scalar|null> $query
     */
    public static function absolute(string $baseUrl, string $path, string $accountPublicId, array $query = []): string
    {
        $baseUrl = rtrim(trim($baseUrl), '/');
        $parts = parse_url($baseUrl);
        if (!is_array($parts)
            || strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || trim((string) ($parts['host'] ?? '')) === ''
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['query'])
            || isset($parts['fragment'])) {
            throw new InvalidArgumentException('A valid secure VP3 base URL is required.');
        }
        return $baseUrl . self::relative($path, $accountPublicId, $query);
    }
}
