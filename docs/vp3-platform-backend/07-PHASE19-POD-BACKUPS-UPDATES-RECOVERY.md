# Phase 19 — POD Backups, Updates, Storage and Recovery Control Center

Initial audit score: **3.6/10**

## Existing certified foundation

- durable scheduled and on-demand backup jobs
- encrypted backup provider metadata
- verified backup snapshots and restore queues
- storage allowance, usage, and threshold monitoring
- signed release catalog and channel eligibility
- leased software-update stages
- mandatory verified pre-update backup
- post-update verification and automatic rollback
- production POD adapters and retained cross-engine tests

## Missing customer control-plane surface

- no customer backup policy controls
- no on-demand backup action
- no verified snapshot history
- no account-safe restore workflow
- no eligible update selection or update queue controls
- no update-stage history or customer-safe receipts
- no dedicated storage/recovery status view
- no Phase 19 account-isolation, privacy, destructive-confirmation, and cross-engine certification

## Scope

- add a Recovery & Updates area to the authenticated VP3 Control Center
- account-scoped POD storage and recovery summaries
- backup policy scheduling and retention
- on-demand verified backups
- verified snapshot history
- exact-confirmation restore queueing
- eligible published release selection by target channel
- update queueing, pause, and resume
- update-stage and rollback status
- customer-safe backup/update receipts without provider references, backup content, credentials, lock ownership, lease tokens, raw adapter errors, or protected configuration

## Role boundary

- `customer_owner` and `customer_admin`: full recovery and update management
- `support_member`: no destructive backup, restore, or update authority in this phase
- `billing_manager`: no Recovery & Updates access

## Certification gate

Keep draft and unmerged until PHP 8.2/8.3, MySQL 8, MariaDB 10.11, repeated cumulative imports, retained Phase 2–18 workflows, and permanent Phase 19 privacy/security/database tests pass on the exact head, followed by a final 10/10 audit.
