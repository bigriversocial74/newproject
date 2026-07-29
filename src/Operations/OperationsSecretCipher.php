<?php

declare(strict_types=1);

namespace Vp3\Operations;

use RuntimeException;

final class OperationsSecretCipher
{
    public function __construct(
        private readonly string $keyBase64,
        private readonly string $keyId = 'operations-aes256gcm-v1'
    ) {
    }

    /** @return array{ciphertext:string,nonce:string,tag:string,key_id:string} */
    public function encrypt(string $plaintext, string $context): array
    {
        $nonce = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $this->key(), OPENSSL_RAW_DATA, $nonce, $tag, $context, 16);
        if (!is_string($ciphertext) || strlen($tag) !== 16) {
            throw new RuntimeException('Operations secret encryption failed.');
        }
        return [
            'ciphertext' => base64_encode($ciphertext),
            'nonce' => base64_encode($nonce),
            'tag' => base64_encode($tag),
            'key_id' => $this->keyId,
        ];
    }

    public function decrypt(string $ciphertext, string $nonce, string $tag, string $context): string
    {
        $ciphertextBytes = base64_decode($ciphertext, true);
        $nonceBytes = base64_decode($nonce, true);
        $tagBytes = base64_decode($tag, true);
        if (!is_string($ciphertextBytes) || !is_string($nonceBytes) || !is_string($tagBytes)) {
            throw new RuntimeException('Operations secret encoding is invalid.');
        }
        $plaintext = openssl_decrypt($ciphertextBytes, 'aes-256-gcm', $this->key(), OPENSSL_RAW_DATA, $nonceBytes, $tagBytes, $context);
        if (!is_string($plaintext)) {
            throw new RuntimeException('Operations secret authentication failed.');
        }
        return $plaintext;
    }

    public function keyId(): string
    {
        return $this->keyId;
    }

    private function key(): string
    {
        $key = base64_decode($this->keyBase64, true);
        if (!is_string($key) || strlen($key) !== 32) {
            throw new RuntimeException('A valid 32-byte operations encryption key is required.');
        }
        return $key;
    }
}
