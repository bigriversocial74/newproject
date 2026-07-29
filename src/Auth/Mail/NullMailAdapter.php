<?php

declare(strict_types=1);

namespace Vp3\Auth\Mail;

final class NullMailAdapter implements MailAdapter
{
    /** @var list<array{recipient:string,subject:string,text_body:string,html_body:string}> */
    private array $messages = [];

    public function send(string $recipient, string $subject, string $textBody, string $htmlBody = ''): void
    {
        $this->messages[] = [
            'recipient' => $recipient,
            'subject' => $subject,
            'text_body' => $textBody,
            'html_body' => $htmlBody,
        ];
    }

    /** @return list<array{recipient:string,subject:string,text_body:string,html_body:string}> */
    public function messages(): array
    {
        return $this->messages;
    }

    /** @return array{recipient:string,subject:string,text_body:string,html_body:string}|null */
    public function lastMessage(): ?array
    {
        return $this->messages === [] ? null : $this->messages[array_key_last($this->messages)];
    }
}
