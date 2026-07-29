# Phase 11B — Identity and Authentication Completion

## Starting audit

Initial score: **4.5/10**.

The inherited implementation authenticated through PHP session state, accepted pending-verification users, hardcoded throttling and token lifetimes, lacked production email delivery, had incomplete logout/device revocation, and exposed internal exception messages from authentication endpoints.

## Implemented architecture

### Database-backed sessions

A cryptographically random application session token is issued after successful verified login. Only its SHA-256 hash is stored in `auth_sessions`. The browser token is held inside the hardened PHP session shell and is validated against the database on every authenticated request.

Each session records a public device/session identifier, user binding, IP hash, user-agent hash, last-seen time, inactivity expiry, absolute expiry, rotation lineage, revocation time, revocation reason, and revoking user. Validation rejects missing, unknown, revoked, expired, inactive-user, and binding-mismatch sessions.

Rotation atomically revokes the old token and inserts its replacement. A repeated or concurrent use of the old token cannot create another valid replacement.

### Session controls

The authenticated API exposes:

- current user and current database session
- active session/device listing
- current-session logout
- logout of all other sessions
- logout of all sessions
- selected-device revocation
- explicit session rotation

Cookie-authenticated mutations require CSRF validation. Cross-user session revocation is denied by the database update predicate and creates denial audit evidence.

### Registration and verification

Registration relies on the unique email constraint as the final concurrency authority and maps duplicate-key races to a stable public response. New users and accounts remain pending until email verification succeeds.

Verification and resend tokens are random, stored only as hashes, configurable by TTL, one-time use, and invalidated when replaced or consumed. Login is rejected until the user status is active.

### Password recovery

Password-reset requests return the same public response regardless of account existence. Eligible users receive a one-time reset link through the configured mail adapter. Prior unconsumed reset tokens are invalidated. Completion changes the password transactionally, consumes the token, invalidates alternatives, and revokes every active session.

### Mail delivery

Development and test environments use an inspectable null adapter. Production requires the SMTP adapter and fails closed when configuration is missing or unsafe.

The SMTP implementation enforces TLS or implicit SSL, validates the peer and peer name, rejects self-signed certificates, rejects mail-header injection, dot-stuffs message data, and never logs credentials or message tokens.

### Safe public errors

Authentication endpoints use stable public error codes and generic messages. Internal exception text, SQL details, plaintext verification tokens, plaintext reset tokens, and application session tokens are not returned by production endpoints.

## Configuration

Phase 11B uses:

- `AUTH_LOGIN_ATTEMPT_LIMIT`
- `AUTH_LOGIN_ATTEMPT_WINDOW_SECONDS`
- `AUTH_VERIFICATION_TTL_SECONDS`
- `AUTH_PASSWORD_RESET_TTL_SECONDS`
- `AUTH_SESSION_INACTIVITY_TTL_SECONDS`
- `AUTH_SESSION_ABSOLUTE_TTL_SECONDS`
- `MAIL_DRIVER`
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_ENCRYPTION`
- `SMTP_USERNAME`
- `SMTP_PASSWORD`
- `MAIL_SENDER_EMAIL`
- `MAIL_SENDER_NAME`

Production requires HTTPS, secure cookies, an SMTP mail driver, valid sender configuration, and encrypted SMTP transport.

## Audit evidence

Durable audit and session-event evidence covers registration, verification requests, verification completion, login success, login failure, throttling, session creation, rotation, revocation, rejection, expiration, password-reset request, password-reset completion, current logout, logout others, and logout all.

Audit metadata is filtered to prevent passwords, tokens, authorization values, cookies, SMTP credentials, or email bodies from being stored.

## Certification boundary

The permanent Phase 11B workflow runs PHP 8.2 and PHP 8.3 syntax/static/runtime certification, imports the cumulative schema twice on MySQL 8 and MariaDB 10.11, executes retained Phase 2–11A tests, and runs the Phase 11B database lifecycle suite on both database engines.

A final score and exact-head certification are recorded only after the workflow is green and the implementation receives a separate post-green security audit.
