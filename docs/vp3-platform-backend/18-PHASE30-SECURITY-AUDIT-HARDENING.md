# Phase 30 — Security Audit Hardening and Standalone Database Installer

## Baseline

- Repository: `bigriversocial74/newproject`
- Base: Phase 29 merge `3171c803fefb10d66677226259f45ecb381d5523`
- Branch: `feature/vp3-phase-30-security-audit-hardening`
- Initial audit score: **4.8/10**

## Initial audit

VP3 already records authentication, session, security and operational events, but the evidence is fragmented across multiple tables and services. Authentication audit rows are mutable, metadata redaction is shallow, account chains are not tamper evident, protected export and retention contracts are absent, and the cumulative installer is a list of `SOURCE` directives rather than a standalone SQL file.

## Phase 30 contract

Phase 30 establishes one append-only security evidence boundary for authentication, sessions, MFA, account teams, billing, domains, PODs, HomeServers, federated settings, browser-request integrity and platform administration.

Each event carries:

- public event identity
- account scope and per-account sequence number
- request and correlation identities
- category, risk level and result
- actor and resource identities
- privacy-hashed IP address and user agent
- recursively redacted metadata
- deterministic metadata hash
- previous and current chain hashes
- UTC microsecond timestamps

The ledger serializes each account scope through a locked chain head and verifies the complete chain from sequence one through the current head.

## Database objects

- `security_audit_heads`
- `security_audit_events`
- `security_audit_retention_policies`
- `security_audit_exports`
- `security_reauthentication_challenges`
- `security_rate_limit_buckets`

The default event-retention policy is seven years. Export records retain hashes and lifecycle metadata, not unprotected exported content.

## Privacy and secret handling

The audit service recursively removes passwords, passphrases, tokens, secrets, authorization headers, cookies, CSRF material, credentials, private keys, recovery codes, ciphertext and raw request/response bodies. Client IP and user-agent values are stored only as SHA-256 hashes. Metadata is bounded by depth, entry count and string length before deterministic canonical hashing.

## Standalone installer contract

`database/vp3-single-install.sql` must be a real standalone import file.

- `database/single-install-manifest.txt` defines the retained migration order.
- `tools/build-single-install.php` deterministically expands every migration.
- The generated file contains no `SOURCE` directives.
- MySQL 8 and MariaDB 10.11 certification import the generated file twice.
- The Phase 30 workflow publishes the exact generated SQL file as `vp3-phase30-single-install`.

No phase-by-phase manual SQL imports are part of the deployment contract.

## Certification gate

Keep Phase 30 draft and unmerged until the exact final head passes:

- PHP 8.2 retained Phase 2–30 contracts
- PHP 8.3 retained Phase 2–30 contracts
- MySQL 8 standalone installer imported twice plus retained Phase 2–30 database tests
- MariaDB 10.11 standalone installer imported twice plus retained Phase 2–30 database tests
- deterministic standalone installer generation with no `SOURCE` directives
- append, redaction, independent account sequencing and tamper-detection database proofs
- final changed-file and review-thread audit
- final **10/10** certification
