# Phase 18 — Operations, Incidents and Notification Control Center

Initial audit score: **3.2/10**

## Existing foundation

Phase 10 already provides account-scoped health signals, deduplicated incidents, append-only incident events, encrypted notification channels, durable delivery queues, monitoring, automatic recovery resolution, tamper-evident audit evidence, and readiness assessments.

## Missing customer control-plane surface

- no authenticated Operations navigation entry
- no account-safe operations snapshot
- no customer incident timeline
- no role-aware acknowledge/resolve controls
- no notification-channel management page
- no customer-safe delivery summary
- no permanent Phase 18 PHP/MySQL/MariaDB certification

## Role boundary

- `customer_owner` and `customer_admin`: full view, incident acknowledge/resolve, notification-channel management
- `support_member`: account operations view and incident acknowledgement only
- `billing_manager`: no Operations access

## Privacy boundary

Never expose destination plaintext, encryption material, provider responses, customer files, prompts, conversations, model data, HomeServer private content, device credentials, fingerprints, or internal worker lock data.
