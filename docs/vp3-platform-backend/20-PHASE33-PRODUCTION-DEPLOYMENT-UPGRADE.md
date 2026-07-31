# Phase 33 — Production Deployment, Upgrade and Release Certification

## Purpose

Phase 33 turns the certified VP3 application and database into an operable production release. It provides one fresh-install SQL file, ordered checksum upgrades, protected database backups, automatic failed-upgrade restoration, release identity, deployment receipts, initial-owner bootstrap, signed release artifacts, and post-deployment health verification.

## Production prerequisites

- PHP 8.2 or 8.3 with PDO MySQL, JSON, mbstring, OpenSSL, Sodium, and ZIP.
- MySQL 8 or MariaDB 10.11.
- `config/config.php` with a canonical HTTPS `APP_BASE_URL` and production-safe session settings.
- Executable MySQL-compatible client and dump binaries.
- An absolute backup directory writable only by the deployment account.
- A deployment account authorized to run PHP CLI, the database clients, and the VP3 workers.
- Ed25519 release signing keys stored outside the repository.

Recommended protected environment:

```text
VP3_RELEASE_COMMIT=<exact deployed commit>
VP3_PLATFORM_BACKUP_ROOT=/srv/vp3/platform-backups
VP3_PLATFORM_MYSQL_BINARY=/usr/bin/mysql
VP3_PLATFORM_MYSQLDUMP_BINARY=/usr/bin/mysqldump
VP3_PLATFORM_DEPLOYMENT_LOCK_NAME=vp3-platform-deployment
RELEASE_SIGNING_PRIVATE_KEY_B64=<protected secret>
RELEASE_SIGNING_PUBLIC_KEY_B64=<public key>
RELEASE_SIGNING_KEY_ID=<stable key id>
```

Never pass database, owner, or release-signing passwords in command-line arguments.

## Clean installation

1. Deploy the exact certified repository commit.
2. Preserve the production `config/config.php` and protected key material.
3. Run preflight:

```bash
php tools/vp3-deploy.php preflight
```

4. Install into an empty database using the one committed file:

```bash
VP3_DEPLOYMENT_REQUEST_ID=install-<unique-id> \
php tools/vp3-deploy.php install
```

The install command imports `database/vp3-single-install.sql`, records all ordered migration checksums, verifies required tables, activates release `33.0.0`, and writes immutable deployment receipts.

## Signed release artifact

Generate the canonical manifest and detached Ed25519 signature:

```bash
VP3_PLATFORM_RELEASE_OUTPUT_ROOT=/srv/vp3/releases \
php tools/build-platform-release.php
```

The release directory contains:

- `platform-release-manifest.json`
- `platform-release-signature.json`

The manifest identifies the exact commit, schema level, migration paths and checksums, installer checksum, migration-manifest checksum, and total byte sizes. The signature file contains the public key, key ID, algorithm, manifest hash, and detached signature. The private key is never written to the artifact.

## Initial owner bootstrap

Bootstrap is available only when both `accounts` and `users` are empty. Provide the password through a protected environment variable or hidden terminal prompt:

```bash
VP3_BOOTSTRAP_OWNER_EMAIL=founder@example.com \
VP3_BOOTSTRAP_OWNER_NAME='Founder Name' \
VP3_BOOTSTRAP_ACCOUNT_NAME='VP3 Organization' \
VP3_BOOTSTRAP_REQUEST_ID=owner-<unique-id> \
VP3_BOOTSTRAP_OWNER_PASSWORD='<protected secret>' \
php tools/vp3-bootstrap-owner.php
```

The command creates one active organization, one verified active user, and one active `customer_owner` membership. Password arguments are prohibited. Exact request replay returns the same public identities; a second bootstrap is rejected.

## Existing installation upgrade

1. Deploy the new code without deleting the previous protected configuration or backup directory.
2. Build and verify the signed release artifact.
3. Run preflight.
4. Run the upgrade:

```bash
VP3_DEPLOYMENT_REQUEST_ID=upgrade-<unique-id> \
php tools/vp3-deploy.php upgrade
```

The upgrade obtains a database advisory lock, writes a protected filesystem journal, creates and verifies a transaction-consistent database dump, reconciles a Phase 32 migration baseline, applies only missing ordered migrations, rejects changed applied checksums, runs post-upgrade smoke verification, activates the release, and writes immutable receipts.

Do not reimport the cumulative installer into an existing production database. The installer is for an empty database; existing installations use the upgrade command.

## Verification and workers

Run release and schema verification:

```bash
php tools/vp3-deploy.php verify
```

Write a deployment-health receipt:

```bash
VP3_DEPLOYMENT_HEALTH_REQUEST_ID=health-<unique-id> \
php tools/vp3-deployment-health.php
```

The health report verifies database connectivity, all migration checksums, the active release, latest deployment state, failed deployment steps, and the seven production worker entrypoints.

Schedule the retained workers with stable worker identities:

```text
workers/pod-provisioning.php
workers/software-updates.php
workers/backups.php
workers/infrastructure.php
workers/homeserver-monitor.php
workers/operations.php
workers/security-incidents.php
```

Each scheduler invocation should set a stable `VP3_WORKER_ID`, run under the deployment account, and capture non-secret exit status and JSON output.

## Automatic failed-upgrade recovery

If a migration or post-upgrade verification fails after backup creation, Phase 33:

1. marks the deployment failed;
2. enters `rolling_back` state when the deployment ledger is available;
3. verifies the backup SHA-256 checksum;
4. removes database tables created after the backup;
5. restores the verified dump;
6. records `rolled_back` in the protected filesystem journal.

The original exception remains the command failure so the deployment system cannot mistake a restored failed release for a successful release.

## Manual rollback

Use the public deployment-run identity and a new request identity:

```bash
VP3_DEPLOYMENT_REQUEST_ID=rollback-<unique-id> \
php tools/vp3-deploy.php rollback --run=PLATFORM-RUN-<identity>
```

Manual rollback verifies that the run owns a verified backup receipt before restoring it. Backups are not located from caller-controlled paths.

## Disaster recovery

When the application database is unavailable or the deployment ledger was lost:

1. stop web traffic and all VP3 workers;
2. preserve the current database and protected journal directory for investigation;
3. select the backup referenced by the last trusted `PLATFORM-RUN-*.json` journal;
4. verify its SHA-256 checksum against the journal or retained receipt;
5. restore into a new empty database when possible;
6. deploy the exact signed release identified by the journal;
7. run `verify` and `vp3-deployment-health.php`;
8. resume workers before reopening traffic.

Do not delete backup dumps or journals until the replacement deployment has completed verification and the retention policy permits deletion.

## Certification contract

Phase 33 certification requires:

- PHP 8.2 and PHP 8.3 syntax and static contracts;
- MySQL 8 and MariaDB 10.11;
- the committed standalone installer reproduced byte-for-byte;
- repeated fresh installer import;
- clean installation into a disposable empty database;
- Phase 32-to-33 upgrade with verified backup;
- migration checksum tamper rejection;
- deliberately broken partially applied migration followed by automatic exact restore;
- initial-owner bootstrap and replay tests;
- Ed25519 signature and tamper-rejection tests;
- deployment-health receipts;
- retained Phase 2–33 certification on the exact final head.
