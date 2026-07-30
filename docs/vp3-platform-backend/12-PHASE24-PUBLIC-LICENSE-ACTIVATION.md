# Phase 24 — Public License Identity and HomeServer Activation Boundary

## Objective

Remove internal numeric HomeServer license IDs from browser-visible registration options, forms, API requests, transfer acceptance, and one-time activation bundles. Internal license IDs remain available only after server-side public identity resolution and are revalidated by the existing certified control-plane transactions.

## Browser contract

- Eligible license options expose `license_public_id`, Domain/subscription public IDs, status, dates, plan, and hostname only.
- HomeServer registration sends `license_public_id`.
- Transfer acceptance sends `target_license_public_id`.
- Activation bundles display and copy `license_public_id`.
- Browser code must not emit `license_id` or `target_license_id`.

## Server contract

- `HomeServerLicenseIdentityResolver` validates bounded public IDs.
- Resolution requires account ownership, HomeServer product type, eligible license/subscription/Domain state, and no non-revoked device occupying the license.
- Registration and transfer acceptance reject legacy numeric license fields with `license_public_identity_required`.
- Public license identities are resolved to internal IDs server-side immediately before calling existing certified control-plane operations.
- Registration and transfer responses remove internal device/license IDs and bind the public account and license identities.

## Certification

- PHP 8.2 and PHP 8.3.
- MySQL 8 and MariaDB 10.11 native-PDO resolver isolation.
- eligible public list with no numeric IDs.
- exact public license resolution.
- cross-account, wrong-product, inactive, expired, occupied, and malformed identity rejection.
- browser and endpoint source scan for numeric license fields.
- repeated cumulative installer imports on both database engines.
- all retained Phase 2–23 workflows.
