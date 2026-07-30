<?php

declare(strict_types=1);

namespace Vp3\Operations;

use RuntimeException;
use Vp3\Auth\Mail\MailAdapter;

final class SmtpOperationalNotificationAdapter implements OperationalNotificationAdapter
{
    public function __construct(private readonly MailAdapter $mail)
    {
    }

    public function deliver(array $destination, array $payload): array
    {
        $recipient = trim((string) ($destination['email'] ?? $destination['recipient'] ?? ''));
        if (!filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
            throw new RuntimeException('Operational SMTP destination requires a valid email address.');
        }

        $severity = strtoupper($this->singleLine((string) ($payload['severity'] ?? 'INFO')));
        $title = $this->singleLine((string) ($payload['title'] ?? 'VP3 operational notification'));
        $incident = $this->singleLine((string) ($payload['incident_public_id'] ?? 'unknown'));
        $eventType = $this->singleLine((string) ($payload['event_type'] ?? 'unknown'));
        $status = $this->singleLine((string) ($payload['status'] ?? 'unknown'));
        $payloadHash = strtolower(trim((string) ($payload['payload_hash'] ?? '')));
        if (!preg_match('/^[a-f0-9]{64}$/', $payloadHash)) {
            throw new RuntimeException('Operational notification payload hash is invalid.');
        }

        $subject = '[VP3 ' . $severity . '] ' . $title;
        $body = implode("\n", [
            'VP3 operational notification',
            '',
            'Incident: ' . $incident,
            'Severity: ' . $severity,
            'Event: ' . $eventType,
            'Status: ' . $status,
            'Title: ' . $title,
            'Evidence hash: ' . $payloadHash,
            '',
            'This notification intentionally contains no credentials or private POD/HomeServer content.',
        ]);
        $this->mail->send($recipient, $subject, $body);

        return [
            'delivered' => true,
            'channel' => 'smtp',
            'provider_request_id' => substr(hash('sha256', $recipient . '|' . $incident . '|' . $eventType . '|' . $payloadHash), 0, 40),
            'recipient_hash' => hash('sha256', strtolower($recipient)),
        ];
    }

    private function singleLine(string $value): string
    {
        $value = trim(str_replace(["\r", "\n"], ' ', $value));
        return mb_substr($value, 0, 190);
    }
}
