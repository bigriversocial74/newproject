<?php

declare(strict_types=1);

namespace Vp3\HomeServers;

use RuntimeException;

final class HomeServerLeaseSigner
{
    private readonly bool $legacyHmacMode;
    private readonly string $privateKeyBase64;
    private readonly string $publicKeyBase64;
    private readonly string $keyId;

    /**
     * The three-argument form is the production Ed25519 contract.
     * The two-argument form remains available only for retained pre-Phase-13 tests and non-production migration compatibility.
     */
    public function __construct(string $privateKeyOrLegacySecret, string $publicKeyOrLegacyKeyId, ?string $keyId = null)
    {
        $this->legacyHmacMode = $keyId === null;
        if ($this->legacyHmacMode) {
            $this->privateKeyBase64 = $privateKeyOrLegacySecret;
            $this->publicKeyBase64 = '';
            $this->keyId = $publicKeyOrLegacyKeyId;
            return;
        }
        $this->privateKeyBase64 = $privateKeyOrLegacySecret;
        $this->publicKeyBase64 = $publicKeyOrLegacyKeyId;
        $this->keyId = (string) $keyId;
    }

    /** @param array<string,mixed> $claims @return array{document:string,signature:string,key_id:string,algorithm:string,document_hash:string,signature_hash:string} */
    public function sign(array $claims): array
    {
        $document = $this->canonicalJson($claims);
        if ($this->legacyHmacMode) {
            if (strlen($this->privateKeyBase64) < 32) {
                throw new RuntimeException('Legacy HomeServer lease signing requires a 32-byte key.');
            }
            $signature = $this->base64Url(hash_hmac('sha256', $document, $this->privateKeyBase64, true));
            return $this->result($document, $signature, 'HS256');
        }

        $this->assertSodium();
        $private = base64_decode($this->privateKeyBase64, true);
        if (!is_string($private) || strlen($private) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new RuntimeException('A valid Ed25519 HomeServer lease signing private key is required.');
        }
        $signature = $this->base64Url(sodium_crypto_sign_detached($document, $private));
        return $this->result($document, $signature, 'Ed25519');
    }

    public function verify(string $document, string $signature): bool
    {
        $decoded = $this->base64UrlDecode($document);
        if ($decoded === null) {
            return false;
        }
        if ($this->legacyHmacMode) {
            if (strlen($this->privateKeyBase64) < 32) {
                return false;
            }
            return hash_equals(
                $this->base64Url(hash_hmac('sha256', $decoded, $this->privateKeyBase64, true)),
                $signature
            );
        }

        $this->assertSodium();
        $public = base64_decode($this->publicKeyBase64, true);
        $signatureBytes = $this->base64UrlDecode($signature);
        if (!is_string($public) || strlen($public) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
            || $signatureBytes === null || strlen($signatureBytes) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return false;
        }
        return sodium_crypto_sign_verify_detached($signatureBytes, $decoded, $public);
    }

    public function keyId(): string
    {
        return $this->keyId;
    }

    public function algorithm(): string
    {
        return $this->legacyHmacMode ? 'HS256' : 'Ed25519';
    }

    /** @return array{document:string,signature:string,key_id:string,algorithm:string,document_hash:string,signature_hash:string} */
    private function result(string $document, string $signature, string $algorithm): array
    {
        return [
            'document' => $this->base64Url($document),
            'signature' => $signature,
            'key_id' => $this->keyId,
            'algorithm' => $algorithm,
            'document_hash' => hash('sha256', $document),
            'signature_hash' => hash('sha256', $signature),
        ];
    }

    private function assertSodium(): void
    {
        if (!function_exists('sodium_crypto_sign_detached')) {
            throw new RuntimeException('The sodium extension is required for Ed25519 HomeServer leases.');
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
