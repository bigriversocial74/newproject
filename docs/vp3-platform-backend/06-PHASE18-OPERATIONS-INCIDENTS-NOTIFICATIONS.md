# Phase 18 — Operations, Incidents and Notifications Control Center

Initial audit score: **3.2/10**

## Existing certified foundation

Phase 10 already provides:

- account-scoped operational health signals
- deduplicated incidents and append-only incident events
- encrypted notification destinations
- durable notification delivery and receipts
- monitoring passes and automatic recovery resolution
- tamper-evident operational audit evidence
- system-wide readiness assessments

The current VP3 customer Control Center does not expose this foundation. Its navigation contains Dashboard, Billing & Plans, Domains, PODs, HomeServers, and Account & Security only.

## Phase 18 objective

Add a customer-safe Operations area that lets authorized account members understand service health, manage incidents, and configure operational notifications without exposing provider secrets, private POD/HomeServer content, global platform data, or other accounts.

## Required customer experience

- Operations navigation item inside the authenticated Control Center
- account health summary for PODs, Domains, HomeServers, backups, updates, provisioning, and provider operations
- active and resolved incident lists with severity, status, source category, occurrence count, and safe timestamps
- incident event timeline using hashes and customer-safe labels only
- acknowledgement and resolution actions with CSRF, request identity, idempotency, account membership, and role enforcement
- encrypted notification-channel management for supported adapters
- active, paused, and revoked channel states
- severity thresholds
- delivery status and receipt summaries without destination plaintext or provider responses
- refresh and accessible status messaging

## Authorization contract

- `customer_owner` and `customer_admin`: full account operations view, incident acknowledgement/resolution, and notification-channel management
- `support_member`: account operations view and incident acknowledgement only
- `billing_manager`: no operations access unless granted a separate operational role in a future phase
- every query and mutation must bind the selected account server-side
- caller-supplied account IDs, roles, actor IDs, resource IDs, and redirect targets are never trusted

## Privacy and security boundaries

The browser may receive only customer-safe operational metadata:

- public references
- source categories
- health/status/severity labels
- occurrence counts
- bounded timestamps
- evidence and receipt hashes

The browser must never receive:

- notification destination plaintext
- encryption nonces, tags, or key identifiers
- provider credentials or provider response bodies
- internal database IDs
- private POD files, prompts, conversations, models, backups, or configuration
- HomeServer fingerprints, credentials, private content, or local execution data
- global readiness data or operational records from other accounts

All pages must use no-store responses, restrictive CSP, external scripts/styles, no browser persistence, and no inline executable content.

## Implementation plan

1. Build an account-scoped operations query service and customer-safe read model.
2. Add Operations page, external JavaScript/CSS, and role-aware navigation.
3. Add POST-only overview and mutation APIs using the retained Control Center authorization boundary.
4. Harden incident acknowledgement/resolution with transactional membership revalidation and durable replay receipts.
5. Add encrypted notification-channel actions without exposing destinations after save.
6. Add PHP 8.2/8.3 static and runtime contracts.
7. Add MySQL 8 and MariaDB 10.11 account-isolation, role, incident, notification, replay, privacy, and repeated-installer tests.
8. Run all retained Phase 2–17 workflows and complete a post-green 10/10 audit.

## Merge gate

Phase 18 must remain draft and unmerged until:

- PHP 8.2 and PHP 8.3 pass
- MySQL 8 and MariaDB 10.11 pass
- the cumulative installer imports twice on both engines
- account isolation and role boundaries are proven
- destination secrecy and customer-safe response contracts are proven
- incident mutations are transactional and replay-safe
- every retained Phase 2–17 workflow passes on the exact head
- the final audit reaches a genuine **10/10**
