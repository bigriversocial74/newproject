# Phase 11C Production Adapter Certification

## Scope

Phase 11C completes the first production adapter set for VP3 local POD hosting:

- checksum-pinned ZIP deployment
- safe archive extraction
- isolated MySQL or MariaDB database and user creation
- generated shared tenant configuration
- wildcard Domain and TLS routing
- encrypted POD backup and authenticated verification
- connection-preserving complete schema restore
- signed software updates, tenant SQL migrations, and automatic rollback
- SMTP operational notifications
- fixed production ZIP and standalone cumulative SQL artifacts

## Provisioning proof

The database-aware local provisioning adapter resolves the authoritative account, Domain, license, deployment, and hostname records before modifying the filesystem or database server. It creates isolated tenant credentials, extracts into an immutable release, writes protected shared configuration, activates the release atomically, and verifies database connectivity and the configured entrypoint.

## Restore proof

Restore verifies the encrypted snapshot before destructive work. It removes post-snapshot events, procedures, functions, triggers, views, and tables while preserving the tenant database identity and connection credentials. It then imports the verified snapshot and rewrites active release and shared configuration links.

The hosted POD backup adapter rejects private HomeServer content.

## Update proof

The update adapter resolves the signed release artifact, validates size and SHA-256, creates a verified encrypted pre-update backup, safely extracts the new release, executes only declared tenant SQL migrations, verifies the active release, and restores the exact pre-update snapshot after a failed installation or verification.

Rollback evidence is stored in the canonical `update_receipts` schema. Tenant credentials are excluded from receipts.

## Delivery artifacts

The production artifact workflow generates fixed-name outputs:

- `vp3-production.zip`
- `vp3-production.sql`
- `SHA256SUMS.txt`
- `artifact-manifest.json`
- `DEPLOYMENT.md`

The SQL artifact is standalone and does not depend on client-side `SOURCE` paths. The ZIP excludes live configuration, environment files, tests, Git metadata, generated tenant state, and secrets.

## Permanent certification matrix

The final exact branch head must pass:

- PHP 8.2 platform, syntax, retained, and Phase 11C suites
- PHP 8.3 platform, syntax, retained, and Phase 11C suites
- MySQL 8 cumulative installer imported twice
- MySQL 8 retained, provisioning, backup, restore, update, and rollback drills
- MariaDB 10.11 cumulative installer imported twice
- MariaDB 10.11 retained, provisioning, backup, restore, update, and rollback drills
- production ZIP and standalone SQL build and verification

## Scoring rule

Initial Phase 11C score: **2.5/10**.

Phase 11C may be recorded as **10/10** only when the final branch head passes every permanent status, the pull request head remains identical to that certified commit, and the merged `main` commit is verified.
