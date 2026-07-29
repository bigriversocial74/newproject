# VP3 HomeServer Control Plane v1

## Authority boundary

VP3 is the software authority for HomeServer licenses, registered devices, activation, entitlement leases, heartbeats, release channels, signed manifests, installer authorization, installer delivery, update receipts, suspension, revocation, replacement, and transfer.

Microgifter is not consulted by these routes. Microgifter remains a separate provider authority for Microgifter pairing, merchant/site access, datasets, CRM, campaigns, commerce, gifting, synchronization, and operational receipts.

HomeServer remains the owner of its local data, models, agents, conversations, MCP runtime, tools, skills, backups, and local permissions.

## Base path

`/api/homeserver/v1/`

All JSON endpoints accept and return UTF-8 JSON. Request bodies are limited to 64 KiB. Device calls require an `Authorization: Bearer <device credential>` header and an `X-Request-ID` value of 8–64 safe characters.

Account mutation routes require an authenticated VP3 browser session, CSRF token, and an active owner or administrator membership in the selected `account_id`.

## Account routes

### POST `register.php`

Registers one device against one eligible HomeServer license.

Required:

- `account_id`
- `license_id`
- `device_fingerprint`
- `request_id`
- `idempotency_key`
- CSRF token

The one-time device credential and enrollment code are returned only for a newly created registration. Idempotent replay returns the same device identity without re-exposing secrets.

### POST `suspend.php`

Suspends or resumes a registered device. Suspension revokes active VP3 software entitlement leases and installer grants. It does not revoke independent provider/frontend pairings.

### POST `revoke.php`

Permanently revokes a device and its active software authority. Replacement or transfer must issue new credentials.

### POST `replace.php`

Revokes the old device identity and registers a replacement fingerprint against the same license. Historical revoked device rows are retained for audit evidence.

### POST `transfer-request.php`

Creates a short-lived, single-use transfer code for a specific target VP3 account.

### POST `transfer-accept.php`

Accepts a pending transfer into an eligible unused HomeServer license owned by the target account. The device credential and enrollment code rotate during transfer.

## Device routes

### POST `activate.php`

Validates the account, device credential, and one-time enrollment code. Successful activation returns a signed entitlement lease immediately.

Required:

- `account_id`
- `device_public_id`
- `enrollment_code`
- bearer device credential
- `request_id`

### POST `heartbeat.php`

Validates the device credential and fingerprint, records bounded health/version data, and returns the current VP3 software-authority status and update channel.

### POST `lease.php`

Returns a newly signed short-lived entitlement lease for an eligible active device. Suspended, revoked, expired, or ineligible devices fail closed.

### POST `manifest.php`

Returns the newest eligible signed HomeServer release for the device channel and rollout cohort.

Required:

- `device_public_id`
- `current_version`
- `platform`
- `architecture`
- bearer device credential
- `request_id`

When an update is available, the response includes:

- release public ID, version, and channel
- canonical manifest document
- Ed25519 signature, algorithm, signing-key ID, and manifest hash
- artifact SHA-256 and byte size
- short-lived installer grant token and download path

### GET `installer-download.php?grant=<token>`

Streams an authorized installer from VP3-managed local release storage. Grants are hashed at rest, short-lived, device/release/artifact scoped, revocable, and bounded to three reads for download resumption.

The route rejects traversal and remote storage URLs, resolves the file beneath the configured release root, and verifies exact size and SHA-256 before streaming.

### POST `update-receipt.php`

Accepts an idempotent update receipt for `downloaded`, `staged`, `installed`, `rolled_back`, or `failed`. Prompts, conversations, local evidence, and private HomeServer data are not accepted or stored by this route.

## Environment configuration

- `VP3_HOMESERVER_LEASE_SIGNING_KEY`
- `VP3_HOMESERVER_LEASE_SIGNING_KEY_ID`
- `VP3_RELEASE_PRIVATE_KEY_B64`
- `VP3_RELEASE_PUBLIC_KEY_B64`
- `VP3_RELEASE_SIGNING_KEY_ID`
- `VP3_HOMESERVER_ARTIFACT_ROOT`
- `VP3_HOMESERVER_INSTALLER_GRANT_TTL_SECONDS` (default 600)
- `VP3_HOMESERVER_TRANSFER_TTL_SECONDS` (default 1800)

Private signing material must be injected through production secret management and must never be committed. HomeServer distributions should embed only the trusted Ed25519 public key or approved public-key set.

## Installer storage contract

`release_artifacts.storage_reference` is a relative path beneath `VP3_HOMESERVER_ARTIFACT_ROOT`. It must not contain `..`, an absolute path, or a URL scheme.

Before a release is published:

1. Upload the installer beneath the artifact root.
2. Record its relative storage reference, SHA-256, and exact byte size.
3. Generate and sign the canonical release manifest.
4. Publish the rollout.

## Database installation

The cumulative installer includes:

`database/migrations/20260729_phase12_homeserver_control_plane.sql`

Run `database/vp3-single-install.sql` through the VP3 deployment process. The Phase 12 migration is repeat-safe for MySQL 8 and MariaDB 10.11. It must not be imported into the Microgifter database or the HomeServer local SQLite database.

## Cutover sequence

1. Deploy the VP3 database migration and API routes.
2. Configure lease and release signing secrets and the installer artifact root.
3. Publish a VP3-compatible HomeServer release and signed manifest.
4. Add the VP3 network client to HomeServer.
5. Register and activate the current installed HomeServer with VP3.
6. Verify heartbeat, lease refresh, signed manifest, installer grant, download, update receipt, and rollback.
7. Change the HomeServer local authority state from `microgifter_legacy` to `vp3` only after successful verification.
8. Deploy the coordinated Microgifter authority-separation change.

No cutover should occur solely because the VP3 API code is deployed. Activation and a valid entitlement lease are required before HomeServer changes authority.
