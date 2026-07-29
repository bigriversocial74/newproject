# Phase 11A — Runtime and Queue Hardening

Phase 11A converts VP3 background processing from timestamp-only locks to expiring, token-owned worker leases.

## Runtime safety

- Production cannot silently load `config-example.php`.
- Example configuration defaults to `development`, not `production`.
- Production requires HTTPS, secure cookies, database credentials, Stripe secrets, signing keys, encryption keys, and non-null provider drivers.
- Driver configuration is resolved through an adapter factory instead of being ignored.
- Composer declares every PHP extension used by the application.

## Queue lease contract

Every durable queue stores:

- `locked_by`
- `locked_at`
- `locked_until`
- `lease_token`

Workers claim queued work or work whose lease has expired. A worker must still own the same lease token before it can renew, complete, retry, fail, or write delivery receipts. Long multi-stage jobs renew their lease before and after provider operations.

The default lease is 900 seconds and is configurable with `VP3_QUEUE_LEASE_SECONDS`. Provider timeouts must remain below the configured lease duration.

## Hardened queues

- Stripe billing provisioning outbox
- POD provisioning and rollback
- Software updates and rollback
- Backups and retention deletion
- Restores
- Hosting, DNS, and certificate operations
- Operational notifications

## Deployment boundary

Null adapters remain available only for development and test. Production startup rejects them until real Phase 11C provider adapters are installed.
