<?php

declare(strict_types=1);

namespace Vp3\Auth;

interface AuthMailAdapter
{
    /** @return array{provider_message_id:string} */
    public function send(string $recipient, string $subject, string $textBody, string $htmlBody): array;
}
