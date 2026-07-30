# Phase 22 — Federated Settings and Authority Control Center

## Initial audit

**Score: 4.1/10**

The Phase 15 federated settings engine is certified, signed, revisioned, conflict-safe, and limited to non-secret catalog entries. Its browser surface remains outside the unified VP3 Control Center, duplicates authentication/account selection, uses the shared HomeServer endpoint error boundary, exposes an internal account identity in signed documents, and never supplies a HomeServer device identity for shared settings.

## Objective

Integrate federated settings into the authenticated VP3 Control Center without changing the certified device-sync contract. Browser snapshots must use public identities, stable public errors, transactional owner/admin authorization, and an explicit account-owned HomeServer selector for shared settings.

## Scope

- unified Settings page and Control Center navigation
- owner/admin-only settings page and browser APIs
- account-scoped VP3 settings and device-scoped shared settings
- account-owned HomeServer selector using public device IDs
- HomeServer-authority settings remain read-only in VP3
- transactionally revalidated active membership for updates
- optimistic revision conflicts with stable public error codes
- customer-safe Ed25519-signed browser snapshots using account/device public IDs
- no internal account/device IDs in browser responses or signed documents
- no secret catalog entries, device credentials, fingerprints, lease tokens, private content, or raw runtime errors
- existing HomeServer device-sync endpoints and signed numeric internal contract remain unchanged

## Certification gate

Phase 22 remains draft and unmerged until:

- PHP 8.2 and PHP 8.3 pass
- MySQL 8 and MariaDB 10.11 pass
- the cumulative installer imports twice on both engines
- account and shared setting updates pass with native PDO prepares
- optimistic conflicts, stale roles, unauthorized roles, and cross-account device isolation pass
- browser signature verification and public-identity claims pass
- secret/private fields are absent from browser snapshots
- all retained Phase 2–21 workflows pass on the exact head
- the final post-green audit reaches 10/10
