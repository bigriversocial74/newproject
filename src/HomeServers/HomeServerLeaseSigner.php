<?php

declare(strict_types=1);

namespace Vp3\HomeServers;

use RuntimeException;

final class HomeServerLeaseSigner
{
    public function __construct(
        private readonly string $signingKey,
        private readonly string $keyId = 'homeserver-hs256-v1'
    ) {
    }

    /** @param array<string,mixed> $claims @return array{document:string,signature:string,key_id:string,document_hash:string,signature_hash:string} */
    public function sign(array $claims): array
    {
        $this->assertConfigured();
        $document = $this->canonicalJson($claims);
        $signature = $this->base64Url(hash_hmac('sha256', $document, $this->signingKey, true));
        return [
            'document' => $this->base64Url($document),
            'signature' => $signature,
            'key_id' => $this->keyId,
            'document_hash' => hash('sha256', $document),
            'signature_hash' => hash('sha256', $signature),
        ];
    }

    public function verify(string $document, string $signature): bool
    {
        $this->assertConfigured();
        $decoded = $this->base64UrlDecode($document);
        if ($decoded === null) {
            return false;
        }
        $expected = $this->base64Url(hash_hmac('sha256', $decoded, $this->signingKey, true));
        return hash_equals($expected, $signature);
    }

    public function keyId(): string
    {
        return $this->keyId;
    }

    private function assertConfigured(): void
    {
        if (strlen($this->signingKey) < 32) {
            throw new RuntimeException('HomeServer lease signing is unavailable until a 32-byte signing key is configured.');
        }
    }

    private function canonicalJson(mixed $value): string
    {
        $normalize = static function (mixed $item) use (&$normalize): mixed {
            if (!is_array($item)) {
                return $item;
            }
            if (array_is_list($item)) {
                return array_map($normalize, $item);
            }
            ksort($item);
            foreach ($item as $key => $child) {
                $item[$key] = $normalize($child);
            }
            return $item;
        };
        return json_encode($normalize($value), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $value): ?string
    {
        $padding = strlen($value) % 4;
        if ($padding > 0) {
            $value .= str_repeat('=', 4 - $padding);
        }
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);
        return is_string($decoded) ? $decoded : null;
    }
}
