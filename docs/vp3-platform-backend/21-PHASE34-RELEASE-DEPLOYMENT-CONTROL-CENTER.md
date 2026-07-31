# Phase 34 — Release & Deployment Control Center

## Purpose

Phase 34 converts the Phase 33 deployment engine from a host-only CLI into a protected, approval-driven Control Center. It does not expose database passwords, signing keys, backup paths, shell commands, or unrestricted platform deployment authority to a browser.

## Authority boundary

Release authority is separate from ordinary customer administration.

- A VP3 account must first be explicitly registered in `platform_operator_accounts` by a host operator.
- The browser user must also hold an active `customer_owner` or `customer_admin` membership in that account.
- Production environment registration, production approval, and rollback require `customer_owner`.
- A production promotion must be requested and approved by different owners.
- Production approval and rollback consume a one-time, action-bound reauthentication challenge backed by current-password verification and MFA when enabled.
- Revoking the platform-operator grant immediately removes Release & Deployment Control Center access.

Grant or revoke an operator account only from the protected host:

```bash
VP3_PLATFORM_OPERATOR_CONFIRM=GRANT_PLATFORM_OPERATOR \
php tools/vp3-grant-platform-operator.php grant \
  --account=ACC-PUBLIC-ID \
  --owner=USR-PUBLIC-ID \
  --request-id=grant-platform-operator-20260731
```

```bash
VP3_PLATFORM_OPERATOR_CONFIRM=REVOKE_PLATFORM_OPERATOR \
php tools/vp3-grant-platform-operator.php revoke \
  --account=ACC-PUBLIC-ID \
  --owner=USR-PUBLIC-ID \
  --request-id=revoke-platform-operator-20260731
```

## Signed release identity

Phase 34 uses release manifest format `vp3-platform-release-v2`. The Ed25519-signed manifest includes:

- release version and exact commit
- schema level and ordered migration checksums
- standalone SQL installer checksum and byte count
- migration-manifest checksum
- deterministic application source-tree SHA-256 and source-file count

Create the signed artifact on the release host:

```bash
export VP3_RELEASE_COMMIT=<exact-certified-commit>
export VP3_PLATFORM_RELEASE_OUTPUT_ROOT=/srv/vp3/platform-releases
php tools/build-platform-release.php
```

Register the candidate into the Control Center ledger:

```bash
export VP3_PLATFORM_RELEASE_OUTPUT_ROOT=/srv/vp3/platform-releases
php tools/vp3-register-release-candidate.php \
  --manifest=/srv/vp3/platform-releases/34.0.0/platform-release-manifest.json \
  --signature=/srv/vp3/platform-releases/34.0.0/platform-release-signature.json
```

The registry verifies the self-hash, trusted key identity, detached Ed25519 signature, source-tree identity, and bounded artifact location. It stores only public release evidence and a hash of the artifact directory—not a filesystem path.

## Central control plane and target databases

The VP3 Control Center database and each deployment target may be separate databases.

The central database stores:

- operator authority
- release candidates
- staging/production environment identities
- non-secret configuration fingerprints
- maintenance windows and approvals
- promotion/rollback queue state
- target deployment and backup **public IDs**
- copied non-secret deployment steps and health evidence
- tamper-evident promotion events and replay receipts

The target database stores the Phase 33 deployment ledger, verified backups, migration records, and active release. There are deliberately no foreign keys from the central queue to a target deployment database.

## Environment configuration fingerprints

Generate the target fingerprint on each host using its protected configuration:

```bash
VP3_PLATFORM_ENVIRONMENT_KEY=staging \
VP3_PLATFORM_TARGET_DB_DSN='mysql:host=127.0.0.1;dbname=vp3_staging;charset=utf8mb4' \
VP3_PLATFORM_TARGET_DB_USERNAME='vp3_staging' \
VP3_PLATFORM_TARGET_DB_PASSWORD='<protected>' \
VP3_PLATFORM_TARGET_APP_ENV=production \
VP3_PLATFORM_TARGET_BASE_URL=https://staging.vp3.me \
php tools/vp3-environment-fingerprint.php
```

The fingerprint contains only deterministic, non-secret deployment configuration. Database passwords, encryption keys, signing keys, and SMTP credentials are excluded. Register the returned SHA-256 in the Control Center environment form. A worker blocks readiness when its locally computed fingerprint differs.

## Worker configuration

Run one dedicated worker for staging and one for production. Each worker receives its target database credentials only through protected process environment variables.

```bash
VP3_PLATFORM_ENVIRONMENT_KEY=staging \
VP3_PLATFORM_RELEASE_WORKER_ID=vp3-release-staging-01 \
VP3_PLATFORM_TARGET_DB_DSN='mysql:host=127.0.0.1;dbname=vp3_staging;charset=utf8mb4' \
VP3_PLATFORM_TARGET_DB_USERNAME='vp3_staging' \
VP3_PLATFORM_TARGET_DB_PASSWORD='<protected>' \
VP3_PLATFORM_TARGET_APP_ENV=production \
VP3_PLATFORM_TARGET_BASE_URL=https://staging.vp3.me \
VP3_PLATFORM_BACKUP_ROOT=/srv/vp3/platform-backups/staging \
php workers/platform-releases.php
```

Schedule each worker at least once per minute. Use a stable `VP3_PLATFORM_RELEASE_WORKER_ID`. Active jobs use a recoverable lease; a replacement worker may reclaim an expired `deploying` or `rolling_back` job. A recovered production job may finish outside the maintenance window because safe completion or rollback is preferable to leaving a partially applied deployment abandoned.

## Promotion sequence

1. Register the signed release candidate.
2. Register staging and production origins plus their configuration fingerprints.
3. Allow both workers to report current readiness.
4. Queue staging deployment.
5. Confirm staging runs the selected candidate and remains ready.
6. Create an owner-approved production maintenance window, no longer than six hours.
7. Request production promotion.
8. A different owner completes current-password/MFA reauthentication and approves it.
9. The production worker claims the job only while the approved window is open.
10. The worker verifies signed release/source identity, creates a target backup, applies the ordered upgrade, copies target run/backup/step evidence centrally, verifies deployment health, and activates the candidate.

## Rollback and failure handling

Rollback is available only when the central promotion record contains both the target deployment run public ID and verified backup public ID. An owner must complete action-bound reauthentication before queuing rollback.

The worker invokes the Phase 33 exact-restore path, copies target rollback evidence, updates the environment candidate, and appends a tamper-evident rollback event.

When promotion execution fails:

- the promotion becomes `failed`
- the environment becomes `blocked`
- any recoverable target run/backup identity and step evidence are copied centrally
- the worker lease is cleared
- a critical Operations incident is opened and routed through configured notification channels

## Fresh installation and upgrade

Fresh installations continue to use only:

`database/vp3-single-install.sql`

Existing Phase 33 installations use the Phase 33 ordered upgrade runner. Do not import the cumulative installer over a live database.

Phase 34 appends:

`database/migrations/20260731_phase34_release_deployment_control_center.sql`

## Disaster recovery

1. Preserve the central Control Center database and every target database independently.
2. Preserve target backup files and protected deployment journals.
3. Restore the target database through the Phase 33 verified backup mechanism.
4. Restart the appropriate environment worker with the same protected target configuration.
5. Confirm the environment fingerprint and readiness are current.
6. Review copied promotion steps, event-chain integrity, and the corresponding Operations incident before resuming promotions.

Never place target database credentials, release signing private keys, backup paths, or plaintext configuration secrets in the browser, central release records, logs, screenshots, support tickets, or PR comments.
