<?php

declare(strict_types=1);

namespace Vp3\Auth\Mail;

use RuntimeException;

final class SmtpMailAdapter implements MailAdapter
{
    public function __construct(
        private readonly string $host,
        private readonly int $port,
        private readonly string $encryption,
        private readonly string $username,
        private readonly string $password,
        private readonly string $senderEmail,
        private readonly string $senderName,
        private readonly int $timeoutSeconds = 15
    ) {
        if (!in_array($this->encryption, ['tls', 'ssl'], true)) {
            throw new RuntimeException('SMTP encryption must be tls or ssl.');
        }
        foreach ([$this->senderEmail, $this->senderName] as $headerValue) {
            $this->assertSafeHeader($headerValue);
        }
        if (!filter_var($this->senderEmail, FILTER_VALIDATE_EMAIL)) {
            throw new RuntimeException('SMTP sender email is invalid.');
        }
    }

    public function send(string $recipient, string $subject, string $textBody, string $htmlBody = ''): void
    {
        $this->assertSafeHeader($recipient);
        $this->assertSafeHeader($subject);
        if (!filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
            throw new RuntimeException('Mail recipient is invalid.');
        }

        $context = stream_context_create([
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'allow_self_signed' => false,
                'peer_name' => $this->host,
                'SNI_enabled' => true,
            ],
        ]);
        $transport = $this->encryption === 'ssl' ? 'ssl://' : 'tcp://';
        $socket = @stream_socket_client(
            $transport . $this->host . ':' . $this->port,
            $errorNumber,
            $errorMessage,
            $this->timeoutSeconds,
            STREAM_CLIENT_CONNECT,
            $context
        );
        if (!is_resource($socket)) {
            throw new RuntimeException('SMTP connection failed.');
        }
        stream_set_timeout($socket, $this->timeoutSeconds);

        try {
            $this->expect($socket, [220]);
            $hostname = gethostname() ?: 'localhost';
            $this->command($socket, 'EHLO ' . $hostname, [250]);
            if ($this->encryption === 'tls') {
                $this->command($socket, 'STARTTLS', [220]);
                if (!stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                    throw new RuntimeException('SMTP TLS negotiation failed.');
                }
                $this->command($socket, 'EHLO ' . $hostname, [250]);
            }
            if ($this->username !== '') {
                $this->command($socket, 'AUTH LOGIN', [334]);
                $this->command($socket, base64_encode($this->username), [334]);
                $this->command($socket, base64_encode($this->password), [235]);
            }
            $this->command($socket, 'MAIL FROM:<' . $this->senderEmail . '>', [250]);
            $this->command($socket, 'RCPT TO:<' . $recipient . '>', [250, 251]);
            $this->command($socket, 'DATA', [354]);

            $boundary = 'vp3_' . bin2hex(random_bytes(12));
            $headers = [
                'Date: ' . gmdate('D, d M Y H:i:s') . ' +0000',
                'From: ' . $this->encodeHeader($this->senderName) . ' <' . $this->senderEmail . '>',
                'To: <' . $recipient . '>',
                'Subject: ' . $this->encodeHeader($subject),
                'Message-ID: <' . bin2hex(random_bytes(16)) . '@' . $hostname . '>',
                'MIME-Version: 1.0',
                'Content-Type: multipart/alternative; boundary="' . $boundary . '"',
            ];
            $body = '--' . $boundary . "\r\n"
                . "Content-Type: text/plain; charset=UTF-8\r\n"
                . "Content-Transfer-Encoding: quoted-printable\r\n\r\n"
                . quoted_printable_encode($textBody) . "\r\n";
            if ($htmlBody !== '') {
                $body .= '--' . $boundary . "\r\n"
                    . "Content-Type: text/html; charset=UTF-8\r\n"
                    . "Content-Transfer-Encoding: quoted-printable\r\n\r\n"
                    . quoted_printable_encode($htmlBody) . "\r\n";
            }
            $body .= '--' . $boundary . "--\r\n";
            $message = implode("\r\n", $headers) . "\r\n\r\n" . $body;
            $message = preg_replace('/(?m)^\./', '..', $message) ?? $message;
            fwrite($socket, $message . "\r\n.\r\n");
            $this->expect($socket, [250]);
            $this->command($socket, 'QUIT', [221]);
        } finally {
            fclose($socket);
        }
    }

    /** @param resource $socket @param list<int> $expectedCodes */
    private function command($socket, string $command, array $expectedCodes): void
    {
        fwrite($socket, $command . "\r\n");
        $this->expect($socket, $expectedCodes);
    }

    /** @param resource $socket @param list<int> $expectedCodes */
    private function expect($socket, array $expectedCodes): void
    {
        $line = '';
        do {
            $chunk = fgets($socket, 8192);
            if ($chunk === false) {
                throw new RuntimeException('SMTP server closed the connection unexpectedly.');
            }
            $line = $chunk;
        } while (strlen($chunk) >= 4 && $chunk[3] === '-');

        $code = (int) substr($line, 0, 3);
        if (!in_array($code, $expectedCodes, true)) {
            throw new RuntimeException('SMTP server rejected the request.');
        }
    }

    private function assertSafeHeader(string $value): void
    {
        if (str_contains($value, "\r") || str_contains($value, "\n")) {
            throw new RuntimeException('Mail header contains invalid characters.');
        }
    }

    private function encodeHeader(string $value): string
    {
        return '=?UTF-8?B?' . base64_encode($value) . '?=';
    }
}
