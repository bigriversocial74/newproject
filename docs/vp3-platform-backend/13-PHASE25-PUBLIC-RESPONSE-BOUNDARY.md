# Phase 25 — Control Center Public Response and Internal-ID Eradication

## Initial audit

Score: **3.8/10**

Phase 23 and Phase 24 replaced browser account and HomeServer-license routing with public identities. The remaining browser boundary still allowed internal database identifiers to appear inside several response snapshots, including account, subscription, Domain, POD, job, incident and HomeServer relationship IDs.

## Scope

Phase 25 establishes one recursive public-response boundary for authenticated customer APIs.

- Enable the boundary for all Control Center APIs.
- Enable the boundary for federated-settings requests through the shared Control Center context.
- Enable the boundary for HomeServer browser/account requests without changing bearer-authenticated device contracts.
- Remove exact internal database identifier keys recursively before JSON encoding.
- Validate the final response after sanitization.
- Preserve public IDs, request IDs, signing-key IDs, provider-neutral status codes, counts, limits, monetary values and timestamps.
- Preserve no-store JSON behavior and existing public error envelopes.

## Forbidden response keys

The boundary removes generic `id` and known internal relationship keys including account, user, plan, subscription, Domain, entitlement, license, deployment, device, release, snapshot, backup, restore, policy, job, provider binding, operation, incident, channel, notification, membership, invitation, session, actor, target and source database IDs.

## Exclusions

Authenticated HomeServer device endpoints retain their existing private signed-control-plane contracts. Phase 25 does not change database relationships, migrations, device manifests, leases, heartbeat payloads, update receipts or server-side service arguments.

## Certification

- PHP 8.2 and PHP 8.3 syntax and retained contracts.
- MySQL 8 and MariaDB 10.11 with native PDO prepares.
- Cumulative installer imported twice on both engines.
- Real dashboard, billing, account-security and HomeServer fleet snapshots sanitized and recursively inspected.
- Public account, Domain, subscription, license and device identities retained.
- All retained Phase 2 through Phase 24 workflows.
- No review threads, branch drift, migration drift or configuration drift.

## Merge gate

Remain draft and unmerged until the complete exact-head matrix passes and the post-green audit scores Phase 25 at **10/10**.
