# Phase 28 — Authentication Request Integrity and Secure Session Transport

## Initial audit

Score: **4.1/10**

Phase 27 removed internal database identities from authentication responses. The browser request boundary still relied on method checks and CSRF alone: authentication endpoints did not validate the configured application origin, request host, `Origin`, `Referer`, or Fetch Metadata. The PHP session shell used strict cookies but did not permanently certify the `__Host-` production contract or guarantee identical host-only attributes during cookie deletion.

## Scope

- Add a canonical `AuthRequestIntegrity` policy configured from `APP_BASE_URL` and `APP_ENV` during bootstrap.
- Validate the exact public host and normalized origin before every `/api/auth/*` request is handled.
- Accept same-origin `Origin` or `Referer` evidence and reject cross-origin, opaque `null`, malformed, missing-production-source, and cross-site Fetch Metadata requests.
- Preserve test and development clients that omit browser source headers while still validating supplied host/origin metadata.
- Return one stable public 403 contract: `untrusted_request_origin`.
- Require production `APP_BASE_URL` to be a canonical HTTPS origin.
- Require production `APP_SESSION_NAME` to use the `__Host-` prefix with secure transport.
- Keep session cookies root-scoped, host-only, Secure when configured, HttpOnly, explicit `SameSite=Lax` or `Strict`, strict-mode, cookie-only, and trans-SID disabled.
- Delete the session cookie using the exact same path, Secure, HttpOnly, and SameSite attributes without a Domain attribute.

## Security boundary

The canonical application origin comes from validated server configuration, never from request headers. `X-Forwarded-Host` and similar untrusted proxy headers are not accepted. Production requests require the public `Host` plus either same-origin `Origin` or same-origin `Referer` evidence. Fetch Metadata, when present, must be `same-origin` or `none`.

The `__Host-` prefix requires Secure transport, root path, and no Domain attribute. Internal database session tokens remain opaque and server-side; Phase 28 changes only browser request and cookie transport boundaries.

## Certification

- PHP 8.2 and PHP 8.3 syntax and retained contracts.
- MySQL 8 and MariaDB 10.11 with native PDO.
- Cumulative installer imported twice on both database engines.
- Real registration, verification delivery, account activation, database-session creation, PHP-session storage, and database-session validation.
- Same-origin request acceptance and cross-origin/host/null/missing-source rejection.
- Runtime cookie-parameter proof for root path, Secure, HttpOnly, SameSite, and no Domain scope.
- Phase 27 workflow retired to manual-only and Phase 27 added to consolidated retained certification.

## Merge gate

Remain draft and unmerged until the Phase 28 four-job workflow passes on the exact head. Then mark ready once, run the single retained-certification workflow, close review threads, verify zero branch drift, and complete the post-green **10/10** audit.
