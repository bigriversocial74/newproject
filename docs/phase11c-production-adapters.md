# Phase 11C — Production Adapters

## Status

Phase 11C replaces the null infrastructure boundaries introduced in earlier phases with production-capable adapters.

Initial score before Phase 11C: **2.5/10**.

The existing queue, receipt, encryption, deployment, backup, update, and operations services were production-oriented, but every external adapter still failed closed through a null implementation.

## POD deployment mode

The first production deployment mode is `local` provisioning with `wildcard-local` infrastructure.

This mode does not require a cPanel or WHM credential for each customer POD. A hosting administrator configures the wildcard route and wildcard certificate once. VP3 then provisions each POD under its authoritative `*.vp3.me` hostname.

### Provisioning sequence

1. Confirm the account, subscription, Domain, and POD license are eligible.
2. Resolve the authoritative hostname from `domain_registrations`.
3. Reserve the local POD deployment directory.
4. Create an isolated MySQL or MariaDB database and database user.
5. Generate a high-entropy database password and application key.
6. Verify the configured release ZIP against its required SHA-256 checksum.
7. Inspect every ZIP entry before extraction.
8. Reject traversal paths, absolute paths, symbolic links, oversized archives, and excessive file counts.
9. Extract into a new immutable release directory.
10. Atomically switch the POD `current` link to the new release.
11. Generate the POD configuration from authoritative VP3 and database state.
12. Store the configuration under shared deployment storage and link the active release to it.
13. Write owner-bootstrap and license metadata.
14. Verify the entrypoint, shared configuration, license state, tenant database connection, wildcard hostname, and TLS readiness.
15. Activate the deployment.

### Filesystem layout

```text
<deployment-root>/pod-<id>/
├── current -> releases/<version>-<checksum-prefix>
├── releases/
│   └── <version>-<checksum-prefix>/
└── shared/
    ├── config/config.php
    └── .vp3/
        ├── active.json
        ├── database.json
        ├── deployment.json
        ├── license.json
        └── owner-bootstrap.json
```

The generated configuration and database credential state do not live inside an immutable release. Updating or replacing the ZIP therefore does not overwrite tenant credentials or customer-preserved configuration.

## Required server configuration

```env
VP3_PROVISIONING_DRIVER=local
VP3_INFRASTRUCTURE_PROVIDER_DRIVER=wildcard-local

VP3_POD_DEPLOYMENT_ROOT=/srv/vp3/pods
VP3_POD_RELEASE_ZIP=/srv/vp3/releases/pod.zip
VP3_POD_RELEASE_VERSION=1.0.0
VP3_POD_RELEASE_SHA256=<sha256-of-pod.zip>
VP3_POD_CONFIGURATION_PATH=config/config.php
VP3_POD_ENTRYPOINT_PATH=public/index.php

VP3_WILDCARD_BASE_DOMAIN=vp3.me
VP3_WILDCARD_DNS_READY=1
VP3_WILDCARD_TLS_READY=1

VP3_POD_DB_ADMIN_DSN=mysql:host=127.0.0.1;charset=utf8mb4
VP3_POD_DB_ADMIN_USERNAME=<server-held-administrator>
VP3_POD_DB_ADMIN_PASSWORD=<server-held-secret>
VP3_POD_DB_HOST=127.0.0.1
VP3_POD_DB_PORT=3306
VP3_POD_DB_USER_HOST=localhost
```

The database administrator credential is entered only on the deployed VP3 server. It is not committed to GitHub, stored in the VP3 control database, included in deployment receipts, or sent to the POD.

## ZIP requirements

The ZIP may contain files directly at its root or one enclosing directory. When one enclosing directory is detected, VP3 removes that wrapper while extracting.

The ZIP must contain the configured entrypoint. The production runtime requires a pinned SHA-256 checksum and the PHP ZIP extension.

## Configuration behavior

VP3 builds the configuration with:

- production application URL
- generated application key
- deployment public ID
- tenant database DSN, host, port, name, username, password, and charset
- account, Domain, and license identity
- hostname
- installation fingerprint
- update channel
- storage allowance

Existing protected paths are preserved during later configuration writes. The default protected paths are:

- `database.password`
- `app.key`
- `customer`

## Rollback

Rollback removes POD-specific activation, license, configuration, release selection, database, database user, and deployment files in reverse stage order.

The shared wildcard DNS record and wildcard certificate are never deleted when one POD is rolled back.

## Current certification boundary

The permanent Phase 11C workflow covers:

- PHP 8.2 and PHP 8.3
- syntax and runtime extension validation
- retained Phase 2–11B tests
- ZIP checksum enforcement
- ZIP traversal rejection
- wildcard-domain isolation
- MySQL 8 cumulative schema import twice
- MariaDB 10.11 cumulative schema import twice
- real tenant database/user creation
- generated-credential connectivity
- shared configuration persistence
- absence of tenant passwords from control-plane receipts and deployment rows
- complete local POD rollback

Phase 11C is not complete until every production adapter in scope is implemented, independently audited, and exact-head certified.
