# Phase 26 — Public Account Navigation, Redirect and Return URL Boundary

## Initial audit

Score: **4.1/10**

Phase 23 replaced browser account request payloads and page selection with public identities. Phase 25 removed internal IDs from public responses. A remaining redirect path still generated Stripe checkout, cancel and portal return URLs with a numeric `account_id`, and navigation URL construction was duplicated in the shared shell.

## Scope

- Add one validated `ControlCenterUrl` builder for relative and absolute Control Center URLs.
- Require local `.php` paths and public account identities.
- Reject protocol-relative paths, malformed identities and account-identity overrides.
- Require HTTPS and a valid host for absolute return URLs.
- Encode query parameters with RFC 3986 rules.
- Route shared brand and navigation links through the builder.
- Route Stripe checkout success, cancellation and billing-portal returns through the builder.
- Use the public `account` query parameter exclusively.
- Reject generated `account_id` URLs across public PHP/JavaScript and shared Control Center source.

## Security boundary

The browser may choose an account only through its public identity. Internal account IDs remain server-side service arguments after membership authorization. Caller-provided success, cancel and return URLs remain prohibited. External Stripe redirects remain restricted to exact HTTPS Stripe hosts.

## Certification

- PHP 8.2 and PHP 8.3.
- MySQL 8 and MariaDB 10.11 using native PDO.
- Cumulative installer imported twice on both engines.
- Public account resolution and URL generation proof.
- Malformed path, base URL, identity and override rejection.
- Source-wide numeric account URL regression scan.
- All retained Phase 2 through Phase 25 workflows.

## Merge gate

Remain draft and unmerged until the complete exact-head matrix passes, no review threads remain, and the post-green audit scores Phase 26 at **10/10**.
