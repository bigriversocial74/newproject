<?php

declare(strict_types=1);

namespace Vp3\Http;

final class AuthRequestIntegrity
{
    private BrowserRequestIntegrity $browserRequestIntegrity;

    public function __construct(string $baseUrl, string $environment)
    {
        $this->browserRequestIntegrity = new BrowserRequestIntegrity($baseUrl, $environment);
    }

    /** @param array<string,mixed> $server */
    public function assertTrusted(array $server): void
    {
        $this->browserRequestIntegrity->assertTrusted($server);
    }
}
