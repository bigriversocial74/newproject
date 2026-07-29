<?php

declare(strict_types=1);

namespace Vp3\Auth\Mail;

interface MailAdapter
{
    public function send(string $recipient, string $subject, string $textBody, string $htmlBody = ''): void;
}
