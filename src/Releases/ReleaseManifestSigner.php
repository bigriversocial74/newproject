<?php

declare(strict_types=1);

namespace Vp3\Releases;

use RuntimeException;

final class ReleaseManifestSigner
{
    public function __construct(
        private readonly string $privateKeyBase64,
        private readonly string $publicKeyBase64,
        private readonly string $keyId = 'release-ed25519-v1'
    ) {
    }

    /** @param array<string,mixed> $manifest @return array{manifest:string,manifest_hash:string,signature:string,key_id:string,algorithm:string} */
    public function sign(array $manifest): array
    {
        $this->assertSodium();
        $private = base64_decode($this->privateKeyBase64, true);
        if (!is_string($private) || strlen($private) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new RuntimeException('A valid Ed25519 release signing private key is required.');
        }
        $document = $this->canonicalJson($manifest);
        $signature = sodium_crypto_sign_detached($document, $private);
        return [
            'manifest' => $this->base64Url($document),
            'manifest_hash' => hash('sha256', $document),
            'signature' => $this->base64Url($signature),
            'key_id' => $this->keyId,
            'algorithm' => 'Ed25519',
        ];
    }

    public function verify(string $manifest, string $signature): bool
    {
        $this->assertSodium();
        $public = base64_decode($this->publicKeyBase64, true);
        $document = $this->base64UrlDecode($manifest);
        $signatureBytes = $this->base64UrlDecode($signature);
        if (!is_string($public) || strlen($public) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
            || $document === null || $signatureBytes === null
            || strlen($signatureBytes) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return false;
        }
        return sodium_crypto_sign_verify_detached($signatureBytes, $document, $public);
    }

    public function keyId(): string
    {
        return $this->keyId;
    }

    private function assertSodium(): void
    {
        if (!function_exists('sodium_crypto_sign_detached')) {
            throw new RuntimeException('The sodium extension is required for signed release manifests.');
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
