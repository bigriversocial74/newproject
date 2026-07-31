# Phase 32 — Security Incident Automation and Emergency Response

## Baseline

- Repository: `bigriversocial74/newproject`
- Base: Phase 31 merge `a45e6e28f3dc593d529340060244015721b700fd`
- Branch: `feature/vp3-phase-32-security-incident-automation`
- Initial audit score: **4.9/10**

## Contract

Phase 32 turns the Phase 30 audit ledger and Phase 31 Security Center into an actionable incident-response system.

The response boundary must:

- promote only qualifying high/critical, failed/denied, or request-integrity events
- route promoted evidence into the retained operational incident lifecycle
- create one account-scoped security case per source audit event
- allow owners and administrators to assign active owner, administrator, or support responders
- allow assigned support responders to add encrypted analyst notes
- retain only encrypted notes and evidence hashes in VP3
- require current-password proof and MFA when enabled before emergency action
- consume each sensitive-action reauthentication exactly once
- revoke all target sessions transactionally while preserving the acting administrator
- write immutable response-action receipts and tamper-evident audit evidence
- expose no raw session tokens, passwords, MFA secrets, note plaintext, private keys, or protected customer content

## Database objects

- `security_incident_cases`
- `security_incident_notes`
- `security_alert_preferences`
- `security_response_actions`

The Phase 32 migration is included in `database/single-install-manifest.txt`. The final deployment contract remains one generated standalone file:

`database/vp3-single-install.sql`

No separate Phase 32 SQL import is permitted after certification.

## First implementation slice

- qualifying audit-event promotion
- operational incident creation and replay-safe case identity
- case assignment with active membership validation
- encrypted analyst notes using authenticated AES-256-GCM storage
- password and optional MFA proof bound to Phase 30 reauthentication challenges
- emergency account-scoped session revocation
- response receipts and Phase 30 ledger events
- POST-only Control Center action endpoint
- native MySQL 8 and MariaDB 10.11 database proof
- PHP 8.2 and PHP 8.3 source and contract certification

## Remaining work

- Security Center case and responder UI
- alert preference controls and notification routing
- automatic policy-based promotion worker
- incident resolution and case closure under reauthentication
- final committed standalone SQL byte-for-byte gate
- consolidated retained Phase 2–32 certification
- final changed-file, review-thread, and branch-drift audit
