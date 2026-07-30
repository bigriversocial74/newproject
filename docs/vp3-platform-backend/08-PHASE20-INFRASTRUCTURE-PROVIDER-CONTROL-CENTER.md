# Phase 20 — Infrastructure Provider, DNS, SSL and Hosting Control Center

Initial audit score: **3.4/10**

## Existing certified foundation

- AES-256-GCM encrypted provider credentials with key/version context
- account-scoped hosting, DNS, and certificate connections
- POD infrastructure bindings
- durable provision, reconcile, and teardown operations
- staged hosting, DNS, certificate, verification, and activation workflows
- leased workers, request receipts, idempotency, pause, resume, and retry-safe processing
- production-safe provider adapters and null-adapter restrictions

## Control Center gap

The infrastructure engine is certified, but customers cannot currently:

- view provider connection status without exposing credentials
- add or rotate hosting, DNS, or certificate connections
- revoke unused provider connections
- view POD infrastructure bindings
- queue or inspect provisioning and reconciliation
- pause or resume infrastructure operations
- request protected teardown with exact confirmation
- review customer-safe operation stages and receipts

## Phase 20 scope

- authenticated Infrastructure area in the VP3 Control Center
- owner/administrator-only provider and infrastructure mutations
- customer-safe provider connection inventory and credential-version metadata
- encrypted connection creation and rotation
- public-ID-only provider connection revocation
- POD-to-provider infrastructure binding management
- provision and reconcile operations
- exact-confirmation infrastructure teardown
- pause and resume controls
- hosting, DNS, certificate, verification, and final-state progress
- customer-safe routing, SSL, binding, and operation histories

## Security and privacy boundary

The browser must never receive provider credentials, ciphertext, nonce, tag, encryption key IDs, decrypted authentication context, provider response bodies, provider resource secrets, worker locks, lease tokens, raw adapter errors, POD configuration, database credentials, or private POD/HomeServer content.

Every mutation must require a current session, CSRF token, bounded request identity, active owner/administrator membership revalidated inside the same transaction, account-scoped public resource IDs, and replay-safe evidence.

## Certification gate

Phase 20 remains draft and unmerged until PHP 8.2/8.3, MySQL 8, MariaDB 10.11, repeated cumulative installer imports, permanent Phase 20 security/privacy/database certification, all retained Phase 2–19 workflows, and a final **10/10** exact-head audit pass.
