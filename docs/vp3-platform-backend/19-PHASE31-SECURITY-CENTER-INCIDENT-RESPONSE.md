# Phase 31 — Security Center and Incident Response

## Baseline

- Repository: `bigriversocial74/newproject`
- Base: Phase 30 merge `1bf6fb42bef5acc07f6e3219cfcd606ef7ced1da`
- Branch: `feature/vp3-phase-31-security-center-incident-response`
- Initial audit score: **5.1/10**

## Initial audit

VP3 already has strong personal account security controls, a tamper-evident Phase 30 audit ledger, and a certified Phase 18 operational incident system. These capabilities are separated across Account & Security, Operations, and API-only audit endpoints. Account owners and administrators do not have one place to review security posture, chain integrity, denied activity, active sessions, and open incidents.

## Phase 31 contract

Phase 31 establishes a dedicated owner/administrator Security Center that:

- calculates an account-wide security posture from tamper-evident audit evidence and active incidents
- treats audit-chain verification failure as a critical, maximum-risk condition
- displays high/critical, denied/failed, integrity, active-session, and incident metrics
- filters the Phase 30 ledger by category, risk, result, event type, and date range
- uses the protected Phase 30 CSV export service
- displays active Phase 18 operational incidents and recent incident lifecycle events
- keeps incident acknowledgement and resolution inside the certified Operations action boundary until security-specific escalation is added
- uses only public account and event identities in the browser
- does not persist account or evidence state in browser storage
- does not expose private POD content, HomeServer content, tokens, secrets, raw client network data, or internal database identifiers

## First vertical slice

The first slice adds:

- `public/security-center.php`
- `public/assets/security-center.css`
- `public/assets/security-center.js`
- `public/api/control-center/v1/security-center-overview.php`
- `src/Security/SecurityCenterQueryService.php`
- owner/admin navigation in the shared Control Center shell
- a permanent Phase 31 static contract

This slice introduces no database migration. `database/vp3-single-install.sql` remains the single standalone deployment file and remains unchanged until Phase 31 requires durable incident-response state.

## Remaining Phase 31 scope

- security-audit-event escalation into the operational incident lifecycle
- security-specific incident assignment and ownership
- encrypted analyst notes and evidence attachments by hash/reference only
- sensitive-action reauthentication for incident resolution and emergency session revocation
- account-wide session inventory and targeted emergency revocation
- security alert routing and notification preferences
- native-PDO integration tests on MySQL 8 and MariaDB 10.11
- focused and retained Phase 2–31 certification

## Certification gate

Keep Phase 31 draft and unmerged until the final exact head passes:

- PHP 8.2 and PHP 8.3
- MySQL 8 and MariaDB 10.11
- committed standalone installer regenerated with zero byte diff
- standalone installer imported twice on both database engines
- retained Phase 2–31 contracts and database integration
- owner/admin access and stale-role denial
- public-identity, CSRF, request-integrity, CSP, no-browser-storage, and no-innerHTML checks
- final changed-file, review-thread, and branch-drift audit
- final **10/10** certification
