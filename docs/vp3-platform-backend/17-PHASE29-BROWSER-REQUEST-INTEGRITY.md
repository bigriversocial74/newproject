# Phase 29 — Browser Request Integrity and Cross-Site Mutation Boundary

## Initial audit

Score: **4.2/10**

Phase 28 established trusted-origin validation for `/api/auth/*` and hardened host-only session transport. Authenticated Control Center and browser-driven HomeServer requests still reached JSON parsing before a shared canonical-host, same-origin, Fetch Metadata, and media-type boundary. HomeServer endpoints also shared one method helper between browser-session and bearer-device authentication modes.

## Scope

Phase 29 establishes one reusable browser-request integrity policy for session-cookie-authenticated customer APIs.

- Validate the exact canonical public Host configured by `APP_BASE_URL`.
- Require a same-origin `Origin` or `Referer` in production.
- Reject cross-site Fetch Metadata, opaque `null`, malformed origins, and unexpected hosts.
- Require `application/json` or an `application/*+json` media type for browser mutation requests.
- Run integrity checks before body parsing, authentication-context resolution, CSRF validation, or database work.
- Apply the boundary to every `/api/control-center/v1/*` request through the shared endpoint helper.
- Revalidate the Control Center boundary before account-context resolution so a future route-helper omission still fails closed before session, CSRF, or database access.
- Apply the boundary to HomeServer registration, registration options, fleet reads, suspension, revocation, replacement, transfer requests, and transfer acceptance.
- Preserve Phase 28 authentication behavior through the existing `AuthRequestIntegrity` compatibility facade.

## Public rejection contract

Untrusted browser source or host evidence returns:

- HTTP `403`
- error code `untrusted_request_origin`

Unsupported browser mutation media types return:

- HTTP `415`
- error code `unsupported_media_type`

The public response does not disclose which host, origin, referer, or Fetch Metadata comparison failed.

## Control Center defense in depth

`ControlCenterEndpoint::requireMethod()` validates the browser boundary before request-body parsing.

`ControlCenterEndpoint::accountContextForRoles()` independently revalidates the same boundary before authentication-context resolution, CSRF validation, public-account resolution, or database-backed customer actions. The second validation is intentional defense in depth and does not replace the required pre-parsing route check.

## HomeServer authentication-mode separation

`HomeServerEndpoint::requireBrowserMethod()` is reserved for browser-session and CSRF-protected account operations.

`HomeServerEndpoint::requireMethod()` remains the transport-neutral method check used by device-credential endpoints. Activation, heartbeat, lease refresh, manifest selection, installer delivery, and update receipts retain their bearer-authenticated control-plane contracts and are not forced behind browser-origin requirements.

## Exclusions

Phase 29 does not apply the browser-session policy to:

- bearer-authenticated HomeServer device APIs;
- Stripe webhooks;
- workers and command-line execution;
- internal service calls;
- public read-only resources that do not use the authenticated browser mutation boundary.

## Environment behavior

Production requires canonical request Host evidence and same-origin `Origin` or `Referer` evidence. Development and test clients may omit browser source headers, but any supplied Host, Origin, Referer, or Fetch Metadata value is still validated.

Phase 28 production deployment requirements remain unchanged:

- `APP_SESSION_NAME=__Host-vp3_session`
- `APP_SESSION_SECURE=1`
- canonical HTTPS `APP_BASE_URL`

## Certification

- PHP 8.2 and PHP 8.3 syntax and retained contracts.
- MySQL 8 and MariaDB 10.11 with native PDO prepares.
- Cumulative installer imported twice on both database engines.
- Trusted same-origin JSON acceptance.
- Cross-origin, host mismatch, opaque origin, cross-site metadata, missing production source, and non-JSON rejection.
- Proof that rejected requests do not produce database state.
- Static proof that Control Center integrity runs before parsing and again before account resolution.
- Static proof that all browser HomeServer endpoints validate integrity before payload parsing.
- Static proof that bearer-authenticated HomeServer endpoints remain outside the browser boundary.
- Retained Phase 28 authentication request and secure session transport certification.

## Change boundary

Phase 29 introduces no database migrations and no application configuration-file changes.

## Merge gate

Remain draft and unmerged until the Phase 29 four-job workflow and the consolidated retained certification pass on one exact head, the branch is current with `main`, and all review threads are closed.
