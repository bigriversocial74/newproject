# Phase 21 — Domain and POD Lifecycle Authorization Control Center

## Initial audit

**Score: 4.0/10**

The Domain and POD Control Center already exposes substantial lifecycle capability, but its legacy endpoints use generic account membership context, accept browser-visible numeric subscription identifiers, and invoke mutation services without atomically revalidating the actor's current role. Support and billing memberships must not be able to register, suspend, release, provision, retry, or roll back customer infrastructure.

## Objective

Create one owner/administrator-only lifecycle boundary for VP3-managed Domains and POD deployments while preserving the proven Phase 3 and Phase 5 service logic.

## Scope

- owner/admin-only Domain and POD pages and APIs
- public subscription, Domain, POD, license, and job identities in browser payloads
- Domain availability, registration, reservation activation, suspension, and exact-confirmation release
- POD provisioning, pause, resume, retry, and exact-confirmation rollback
- active membership and resource row locks in the same transaction as each mutation
- savepoint-backed nested transactions so existing certified services remain atomic inside the authorization facade
- one open POD lifecycle job per deployment
- stale-role, support-member, billing-manager, and cross-account denial evidence
- customer-safe lifecycle snapshots without internal IDs, worker locks, raw worker errors, provider references, configuration secrets, or private content

## Certification gate

Phase 21 remains draft and unmerged until:

- PHP 8.2 and PHP 8.3 pass
- MySQL 8 and MariaDB 10.11 pass
- the cumulative installer imports twice on both engines
- nested transaction commit, rollback, and savepoint behavior pass
- Domain and POD lifecycle authorization passes with native PDO prepares
- public-ID-only and cross-account isolation pass
- replay-safe registration/provisioning and one-open-job serialization pass
- stale-role and unauthorized-role evidence pass
- every retained Phase 2–20 workflow passes on the exact head
- the final post-green audit reaches 10/10
