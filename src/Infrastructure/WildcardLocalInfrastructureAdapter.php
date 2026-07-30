<?php

declare(strict_types=1);

namespace Vp3\Infrastructure;

use RuntimeException;

final class WildcardLocalInfrastructureAdapter implements HostingProviderAdapter, DnsProviderAdapter, CertificateProviderAdapter
{
    private string $baseDomain;
    private string $deploymentRoot;
    private bool $wildcardDnsReady;
    private bool $wildcardTlsReady;

    /** @param array<string,mixed> $configuration */
    public function __construct(array $configuration)
    {
        $this->baseDomain = $this->hostname((string) ($configuration['wildcard_base_domain'] ?? 'vp3.me'));
        $this->deploymentRoot = $this->absolutePath((string) ($configuration['deployment_root'] ?? ''));
        $this->wildcardDnsReady = (bool) ($configuration['wildcard_dns_ready'] ?? false);
        $this->wildcardTlsReady = (bool) ($configuration['wildcard_tls_ready'] ?? false);
    }

    public function allocateHosting(array $authContext, array $deployment): array
    {
        $publicId = $this->deploymentPublicId($deployment);
        $path = $this->deploymentPath($publicId);
        if (!is_dir($this->deploymentRoot) && !mkdir($this->deploymentRoot, 0750, true) && !is_dir($this->deploymentRoot)) {
            throw new RuntimeException('Unable to create the wildcard-local deployment root.');
        }

        return [
            'provider_reference' => 'wildcard-local-hosting:' . strtolower($publicId),
            'status' => is_dir($path) ? 'allocated' : 'reserved',
            'shared_wildcard_route' => '*.' . $this->baseDomain,
        ];
    }

    public function verifyHosting(array $authContext, string $providerReference): array
    {
        $publicId = $this->providerPublicId($providerReference, 'wildcard-local-hosting:');
        $path = $this->deploymentPath($publicId);
        $marker = $path . '/shared/.vp3/deployment.json';

        return [
            'verified' => is_dir($path) && is_file($marker),
            'status' => is_dir($path) && is_file($marker) ? 'active' : 'pending',
            'provider_reference' => $providerReference,
        ];
    }

    public function releaseHosting(array $authContext, string $providerReference): array
    {
        $publicId = $this->providerPublicId($providerReference, 'wildcard-local-hosting:');

        return [
            'released' => false,
            'delegated_to_provisioning_rollback' => true,
            'deployment_public_id_hash' => hash('sha256', $publicId),
        ];
    }

    public function upsertRecord(array $authContext, string $hostname, string $recordType, string $recordValue): array
    {
        $hostname = $this->podHostname($hostname);
        $recordType = strtoupper(trim($recordType));
        if (!in_array($recordType, ['A', 'AAAA', 'CNAME'], true)) {
            throw new RuntimeException('Wildcard-local DNS supports A, AAAA, or CNAME records only.');
        }
        if (!$this->wildcardDnsReady) {
            throw new RuntimeException('The wildcard DNS route is not marked ready.');
        }
        if (trim($recordValue) === '') {
            throw new RuntimeException('The wildcard DNS record value cannot be empty.');
        }

        return [
            'provider_reference' => 'wildcard-local-dns:' . $this->baseDomain,
            'hostname_hash' => hash('sha256', $hostname),
            'record_type' => $recordType,
            'record_value_hash' => hash('sha256', trim($recordValue)),
            'shared' => true,
        ];
    }

    public function verifyRecord(array $authContext, string $providerReference, string $hostname, string $recordType, string $recordValue): array
    {
        $this->providerBaseDomain($providerReference, 'wildcard-local-dns:');
        $this->podHostname($hostname);

        return [
            'verified' => $this->wildcardDnsReady,
            'provider_reference' => $providerReference,
            'record_type' => strtoupper(trim($recordType)),
            'record_value_hash' => hash('sha256', trim($recordValue)),
        ];
    }

    public function removeRecord(array $authContext, string $providerReference): array
    {
        $this->providerBaseDomain($providerReference, 'wildcard-local-dns:');

        return [
            'removed' => false,
            'shared_wildcard_record_preserved' => true,
            'provider_reference' => $providerReference,
        ];
    }

    public function requestCertificate(array $authContext, string $hostname): array
    {
        $hostname = $this->podHostname($hostname);
        if (!$this->wildcardTlsReady) {
            throw new RuntimeException('The wildcard TLS certificate is not marked ready.');
        }

        return [
            'provider_reference' => 'wildcard-local-certificate:' . $this->baseDomain,
            'hostname_hash' => hash('sha256', $hostname),
            'certificate_hostname' => '*.' . $this->baseDomain,
            'shared' => true,
        ];
    }

    public function verifyCertificate(array $authContext, string $providerReference, string $hostname): array
    {
        $this->providerBaseDomain($providerReference, 'wildcard-local-certificate:');
        $this->podHostname($hostname);

        return [
            'verified' => $this->wildcardTlsReady,
            'provider_reference' => $providerReference,
            'certificate_hostname' => '*.' . $this->baseDomain,
        ];
    }

    public function revokeCertificate(array $authContext, string $providerReference): array
    {
        $this->providerBaseDomain($providerReference, 'wildcard-local-certificate:');

        return [
            'revoked' => false,
            'shared_wildcard_certificate_preserved' => true,
            'provider_reference' => $providerReference,
        ];
    }

    /** @param array<string,mixed> $deployment */
    private function deploymentPublicId(array $deployment): string
    {
        $publicId = strtolower(trim((string) ($deployment['public_id'] ?? '')));
        if (!preg_match('/^pod-[a-z0-9]+$/', $publicId)) {
            throw new RuntimeException('The deployment public ID is invalid for wildcard-local hosting.');
        }
        return $publicId;
    }

    private function providerPublicId(string $reference, string $prefix): string
    {
        if (!str_starts_with($reference, $prefix)) {
            throw new RuntimeException('The wildcard-local hosting provider reference is invalid.');
        }
        return $this->deploymentPublicId(['public_id' => substr($reference, strlen($prefix))]);
    }

    private function providerBaseDomain(string $reference, string $prefix): string
    {
        if (!str_starts_with($reference, $prefix)) {
            throw new RuntimeException('The wildcard-local shared provider reference is invalid.');
        }
        $domain = $this->hostname(substr($reference, strlen($prefix)));
        if (!hash_equals($this->baseDomain, $domain)) {
            throw new RuntimeException('The wildcard-local provider reference targets another base domain.');
        }
        return $domain;
    }

    private function deploymentPath(string $publicId): string
    {
        return rtrim($this->deploymentRoot, '/') . '/' . strtolower($publicId);
    }

    private function podHostname(string $hostname): string
    {
        $hostname = $this->hostname($hostname);
        if ($hostname === $this->baseDomain || !str_ends_with($hostname, '.' . $this->baseDomain)) {
            throw new RuntimeException('The hostname is outside the wildcard-local base domain.');
        }
        return $hostname;
    }

    private function hostname(string $hostname): string
    {
        $hostname = strtolower(rtrim(trim($hostname), '.'));
        if ($hostname === '' || strlen($hostname) > 253 || !preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/', $hostname)) {
            throw new RuntimeException('The wildcard-local hostname is invalid.');
        }
        return $hostname;
    }

    private function absolutePath(string $path): string
    {
        $path = trim($path);
        if ($path === '' || (!str_starts_with($path, '/') && !preg_match('/^[A-Za-z]:[\\\\\/]/', $path))) {
            throw new RuntimeException('The wildcard-local deployment root must be an absolute path.');
        }
        return rtrim(str_replace('\\', '/', $path), '/');
    }
}
