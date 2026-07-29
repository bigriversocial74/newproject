# Configuration

Copy `config-example.php` to `config.php` for every deployed environment. Supply secrets through environment variables and never commit `config.php`.

`config-example.php` defaults to `development`. VP3 refuses to start in `production` when the example file is being used, when required secrets are empty or malformed, or when any provider driver is still `null`.

## Required production values

- `APP_ENV=production`
- `APP_BASE_URL=https://vp3.me`
- `APP_SESSION_NAME=vp3_session`
- `APP_SESSION_SECURE=1`
- `DB_DSN=mysql:host=...;dbname=...;charset=utf8mb4`
- `DB_USERNAME=...`
- `DB_PASSWORD=...`
- `STRIPE_SECRET_KEY=...`
- `STRIPE_WEBHOOK_SECRET=...`
- `HOMESERVER_LEASE_SIGNING_KEY=...` with at least 32 bytes
- `RELEASE_SIGNING_PRIVATE_KEY_B64=...` decoding to 64 bytes
- `RELEASE_SIGNING_PUBLIC_KEY_B64=...` decoding to 32 bytes
- `BACKUP_METADATA_ENCRYPTION_KEY_B64=...` decoding to 32 bytes
- `PROVIDER_SECRET_ENCRYPTION_KEY_B64=...` decoding to 32 bytes
- `OPERATIONS_SECRET_ENCRYPTION_KEY_B64=...` decoding to 32 bytes
- `VP3_PROVISIONING_DRIVER=...`
- `VP3_UPDATE_PROVIDER_DRIVER=...`
- `VP3_BACKUP_PROVIDER_DRIVER=...`
- `VP3_INFRASTRUCTURE_PROVIDER_DRIVER=...`
- `VP3_OPERATIONS_NOTIFICATION_DRIVER=...`

The production driver values cannot be `null`. Phase 11C will provide the real adapter implementations and their supported driver names.

## Queue leases

`VP3_QUEUE_LEASE_SECONDS` controls the worker lease for provisioning, billing reconciliation, updates, backups, restores, infrastructure operations, and notifications. It must be between 30 and 3600 seconds and defaults to 900 seconds.

Provider request timeouts must be shorter than the queue lease. Workers may recover a running job only after its lease expires, and only the worker holding the current lease token may complete or fail it.
