# Phase 23 — Public Account Routing and Browser Identity Boundary

## Objective

Remove internal numeric VP3 account IDs from Control Center URLs, HTML data attributes, account pickers, browser API payloads, HomeServer activation bundles, and transfer requests. Internal IDs remain available only after server-side public identity resolution and authorization.

## Browser contract

- Routes use `?account=<account_public_id>`.
- Account picker values are account public IDs.
- Shared page markup exposes `data-account-public-id` only.
- Browser API payloads use `account_public_id`.
- One-time HomeServer activation bundles use `account_public_id`.
- HomeServer transfers use `target_account_public_id`.
- Browser controllers must not emit `account_id`, `target_account_id`, `data-account-id`, or `?account_id=`.

## Server contract

- `PublicAccountIdentityResolver` validates bounded public IDs and resolves only active memberships, active accounts, and permitted roles.
- Page context, Control Center APIs, and HomeServer browser APIs use the same resolver.
- Legacy numeric browser payloads are rejected with `account_public_identity_required`.
- Internal numeric account IDs are returned only inside server-side context arrays for existing certified services.
- Bearer-authenticated HomeServer device endpoints remain unchanged.

## HomeServer bundle and transfer boundary

- Registration and transfer acceptance responses remove internal `device_id` or `license_id` fields before browser delivery.
- Activation bundles display and copy public account and device identities only.
- Destination transfer accounts are resolved from `target_account_public_id` server-side.

## Certification

- PHP 8.2 and PHP 8.3 syntax and retained contracts.
- MySQL 8 and MariaDB 10.11 native-PDO resolver isolation.
- Default authorized account resolution.
- Exact public account selection.
- cross-account and role denial.
- suspended membership and inactive account denial.
- malformed public identity rejection.
- browser source scan for numeric account identity patterns.
- repeated cumulative installer imports on both database engines.
- all retained Phase 2–22 workflows.
