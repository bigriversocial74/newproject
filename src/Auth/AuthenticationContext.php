<?php

declare(strict_types=1);

namespace Vp3\Auth;

use Vp3\Http\SessionManager;

final class AuthenticationContext
{
    public function __construct(
        private readonly SessionManager $session,
        private readonly DatabaseSessionService $databaseSessions
    ) {
    }

    /** @return array{user:array{id:int,public_id:string,email:string,display_name:string,status:string},session:array{public_id:string,last_seen_at:string,inactivity_expires_at:string,absolute_expires_at:string,created_at:string}} */
    public function requireCurrent(string $ip, string $userAgent, bool $touch = true): array
    {
        return $this->databaseSessions->validate($this->session->applicationToken(), $ip, $userAgent, $touch);
    }
}
