# Phase 27 — Public Authentication Response and Session Identity Boundary

## Initial audit

Score: **3.9/10**

Phases 23–26 hardened Control Center account routing, public responses, and generated URLs. The standalone `/api/auth/*` family remained outside that public-response boundary. Login and current-session endpoints returned raw authentication-context arrays containing internal user/session database identifiers, and registration explicitly returned numeric account and user IDs.

## Scope

- Enable `PublicResponseGuard` for every authentication endpoint through `AuthEndpoint::requireMethod`.
- Recursively remove internal user, account, session and relationship IDs before JSON encoding.
- Preserve public user/session identities, email, display name, status, expiration timestamps, CSRF token and stable public errors.
- Return public account and user identities from registration.
- Keep internal IDs available only to server-side authentication, session, MFA, audit and membership services.
- Preserve token hashing, cookie/session rotation, CSRF, MFA challenge, password-reset and email-verification contracts.

## Security boundary

Authentication APIs never return verification/reset tokens, plaintext session tokens, internal exception messages or database IDs. Browser session selection and revocation continue to use `session_public_id`. Authentication endpoints remain no-store through `JsonResponse`.

## Certification

- PHP 8.2 and PHP 8.3.
- MySQL 8 and MariaDB 10.11 with native PDO.
- Cumulative installer imported twice on both engines.
- Real registration, database-session creation and authentication-context validation.
- Raw internal user IDs proven present server-side, then absent after public sanitization.
- Public account, user and session identities retained.
- All retained Phase 2 through Phase 26 workflows.

## Merge gate

Remain draft and unmerged until the complete exact-head matrix passes, no review threads remain, and the post-green audit scores Phase 27 at **10/10**.
