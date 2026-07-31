<?php

declare(strict_types=1);

namespace Vp3\Reliability;

use Closure;
use RuntimeException;
use Vp3\Database;

final class ReliabilityProbeExecutor
{
    /** @param Closure(array<string,mixed>):array<string,mixed>|null $override */
    public function __construct(
        private readonly Database $database,
        private readonly string $applicationRoot,
        private readonly ?Closure $override = null
    ) {
    }

    /** @param array<string,mixed> $probe @return array{status:string,latency_ms:?int,value_numeric:?float,error_code:?string,evidence:array<string,mixed>} */
    public function execute(array $probe): array
    {
        if ($this->override !== null) {
            return $this->normalize(($this->override)($probe));
        }

        $type = strtolower((string) ($probe['probe_type'] ?? ''));
        $target = trim((string) ($probe['target_value'] ?? ''));
        $timeoutMs = max(250, min(30000, (int) ($probe['timeout_ms'] ?? 5000)));
        $started = hrtime(true);

        try {
            $result = match ($type) {
                'http' => $this->http($target, $timeoutMs),
                'dns' => $this->dns($target),
                'ssl' => $this->ssl($target, $timeoutMs),
                'database' => $this->database(),
                'worker' => $this->worker($target),
                'queue' => $this->queue($target),
                'storage' => $this->storage($target),
                default => throw new RuntimeException('Unsupported reliability probe type.'),
            };
            $latency = (int) round((hrtime(true) - $started) / 1_000_000);
            $result['latency_ms'] ??= $latency;
            return $this->normalize($result);
        } catch (\Throwable $exception) {
            return [
                'status' => 'failure',
                'latency_ms' => (int) round((hrtime(true) - $started) / 1_000_000),
                'value_numeric' => null,
                'error_code' => $this->errorCode($exception),
                'evidence' => [
                    'probe_type' => $type,
                    'result' => 'failure',
                    'error_code' => $this->errorCode($exception),
                ],
            ];
        }
    }

    /** @return array<string,mixed> */
    private function http(string $target, int $timeoutMs): array
    {
        $parts = parse_url($target);
        if (!is_array($parts)
            || strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || trim((string) ($parts['host'] ?? '')) === ''
            || isset($parts['user'])
            || isset($parts['pass'])) {
            throw new RuntimeException('Reliability HTTP targets must be canonical HTTPS URLs without credentials.');
        }
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => $timeoutMs / 1000,
                'ignore_errors' => true,
                'header' => "User-Agent: VP3-Reliability/35\r\nAccept: text/plain,application/json,text/html\r\nConnection: close\r\n",
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'SNI_enabled' => true,
            ],
        ]);
        $body = @file_get_contents($target, false, $context, 0, 4096);
        $headers = $http_response_header ?? [];
        $status = 0;
        if (isset($headers[0]) && preg_match('/\s(\d{3})(?:\s|$)/', (string) $headers[0], $match)) {
            $status = (int) $match[1];
        }
        if ($body === false || $status < 200 || $status >= 400) {
            throw new RuntimeException('HTTP probe did not receive a successful response.');
        }
        return [
            'status' => 'success',
            'value_numeric' => (float) $status,
            'error_code' => null,
            'evidence' => ['probe_type' => 'http', 'http_status' => $status, 'body_sample_bytes' => strlen($body)],
        ];
    }

    /** @return array<string,mixed> */
    private function dns(string $target): array
    {
        $host = strtolower(rtrim($target, '.'));
        if (!filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            throw new RuntimeException('A valid DNS hostname is required.');
        }
        $records = dns_get_record($host, DNS_A | DNS_AAAA | DNS_CNAME);
        if (!is_array($records) || $records === []) {
            throw new RuntimeException('DNS probe returned no address records.');
        }
        return [
            'status' => 'success',
            'value_numeric' => (float) count($records),
            'error_code' => null,
            'evidence' => ['probe_type' => 'dns', 'record_count' => count($records)],
        ];
    }

    /** @return array<string,mixed> */
    private function ssl(string $target, int $timeoutMs): array
    {
        $host = strtolower(rtrim($target, '.'));
        if (!filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            throw new RuntimeException('A valid TLS hostname is required.');
        }
        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => true,
                'verify_peer_name' => true,
                'peer_name' => $host,
                'SNI_enabled' => true,
            ],
        ]);
        $socket = @stream_socket_client(
            'ssl://' . $host . ':443',
            $errno,
            $error,
            $timeoutMs / 1000,
            STREAM_CLIENT_CONNECT,
            $context
        );
        if (!is_resource($socket)) {
            throw new RuntimeException('TLS connection failed.');
        }
        $parameters = stream_context_get_params($socket);
        fclose($socket);
        $certificate = $parameters['options']['ssl']['peer_certificate'] ?? null;
        if ($certificate === null) {
            throw new RuntimeException('TLS certificate was not captured.');
        }
        $parsed = openssl_x509_parse($certificate, false);
        $expires = is_array($parsed) ? (int) ($parsed['validTo_time_t'] ?? 0) : 0;
        if ($expires <= time()) {
            throw new RuntimeException('TLS certificate is expired.');
        }
        $days = (int) floor(($expires - time()) / 86400);
        return [
            'status' => 'success',
            'value_numeric' => (float) $days,
            'error_code' => null,
            'evidence' => ['probe_type' => 'ssl', 'days_remaining' => $days],
        ];
    }

    /** @return array<string,mixed> */
    private function database(): array
    {
        $value = $this->database->pdo()->query('SELECT 1')->fetchColumn();
        if ((int) $value !== 1) {
            throw new RuntimeException('Database probe did not return the expected value.');
        }
        return [
            'status' => 'success',
            'value_numeric' => 1.0,
            'error_code' => null,
            'evidence' => ['probe_type' => 'database', 'connected' => true],
        ];
    }

    /** @return array<string,mixed> */
    private function worker(string $target): array
    {
        [$environmentKey, $maximumAge] = array_pad(explode(':', strtolower($target), 2), 2, '300');
        if (!in_array($environmentKey, ['staging', 'production'], true)) {
            throw new RuntimeException('Worker probes require staging or production.');
        }
        $maximumAge = max(60, min(3600, (int) $maximumAge));
        $statement = $this->database->pdo()->prepare(
            'SELECT worker_last_seen_at FROM platform_deployment_environments
             WHERE environment_key=:environment AND environment_status<>\'disabled\' LIMIT 1'
        );
        $statement->execute(['environment' => $environmentKey]);
        $seen = $statement->fetchColumn();
        if (!is_string($seen)) {
            throw new RuntimeException('Deployment worker heartbeat is unavailable.');
        }
        $age = time() - strtotime($seen . ' UTC');
        if ($age < 0 || $age > $maximumAge) {
            throw new RuntimeException('Deployment worker heartbeat is stale.');
        }
        return [
            'status' => 'success',
            'value_numeric' => (float) $age,
            'error_code' => null,
            'evidence' => ['probe_type' => 'worker', 'heartbeat_age_seconds' => $age],
        ];
    }

    /** @return array<string,mixed> */
    private function queue(string $target): array
    {
        $limit = max(1, min(10000, (int) ($target === '' ? 100 : $target)));
        $count = (int) $this->database->pdo()->query(
            "SELECT COUNT(*) FROM platform_release_promotions
             WHERE promotion_status IN ('approved','scheduled','queued','deploying','rollback_queued','rolling_back')"
        )->fetchColumn();
        if ($count > $limit) {
            throw new RuntimeException('Platform release queue depth exceeds the configured threshold.');
        }
        return [
            'status' => 'success',
            'value_numeric' => (float) $count,
            'error_code' => null,
            'evidence' => ['probe_type' => 'queue', 'open_jobs' => $count, 'threshold' => $limit],
        ];
    }

    /** @return array<string,mixed> */
    private function storage(string $target): array
    {
        if ($target !== 'application_root') {
            throw new RuntimeException('Only the protected application-root storage target is supported.');
        }
        $free = disk_free_space($this->applicationRoot);
        $total = disk_total_space($this->applicationRoot);
        if ($free === false || $total === false || $total <= 0) {
            throw new RuntimeException('Storage capacity could not be measured.');
        }
        $freePercent = round(($free / $total) * 100, 4);
        if ($freePercent < 10) {
            throw new RuntimeException('Application storage has less than ten percent free capacity.');
        }
        return [
            'status' => 'success',
            'value_numeric' => $freePercent,
            'error_code' => null,
            'evidence' => ['probe_type' => 'storage', 'free_percent' => $freePercent],
        ];
    }

    /** @param array<string,mixed> $result @return array{status:string,latency_ms:?int,value_numeric:?float,error_code:?string,evidence:array<string,mixed>} */
    private function normalize(array $result): array
    {
        $status = strtolower((string) ($result['status'] ?? 'failure'));
        if (!in_array($status, ['success', 'failure'], true)) {
            throw new RuntimeException('Reliability probe adapters must return success or failure.');
        }
        $evidence = $result['evidence'] ?? [];
        if (!is_array($evidence)) {
            $evidence = [];
        }
        return [
            'status' => $status,
            'latency_ms' => isset($result['latency_ms']) ? max(0, (int) $result['latency_ms']) : null,
            'value_numeric' => isset($result['value_numeric']) ? (float) $result['value_numeric'] : null,
            'error_code' => $status === 'failure'
                ? substr((string) ($result['error_code'] ?? 'probe_failed'), 0, 100)
                : null,
            'evidence' => $evidence,
        ];
    }

    private function errorCode(\Throwable $exception): string
    {
        $class = strtolower((new \ReflectionClass($exception))->getShortName());
        return substr(preg_replace('/[^a-z0-9]+/', '_', $class . '_' . $exception->getMessage()) ?: 'probe_failed', 0, 100);
    }
}
