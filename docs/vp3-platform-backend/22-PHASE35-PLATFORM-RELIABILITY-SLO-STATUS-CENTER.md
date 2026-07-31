# Phase 35 — Platform Reliability, SLOs & Status Center

## Purpose

Phase 35 adds continuous production reliability management above the Phase 18 Operations incident system and the Phase 34 Release & Deployment Control Center. It measures service health between deployments, calculates error-budget consumption, suppresses expected failures during approved maintenance, correlates changes with release identity, and publishes a customer-safe status page.

Phase 35 does not expose provider credentials, database credentials, private endpoints, filesystem paths, probe targets, internal IDs, private POD content, HomeServer content, or raw adapter errors to the browser or public status page.

## Authority

The Reliability & Status Control Center is available only to an account that:

1. has an active `platform_operator_accounts` grant;
2. has an active account;
3. is accessed by an active `customer_owner` or `customer_admin` membership.

Only `customer_owner` may enable or reconfigure the public status page. Ordinary customer accounts cannot inspect or control platform reliability.

## Components and objectives

A reliability component represents a customer-safe service boundary such as:

- VP3 platform and API
- public HTTPS endpoint
- DNS
- TLS certificate
- primary database
- release worker
- deployment queue
- application storage
- external provider
- POD
- HomeServer

Each component has exactly one service-level objective with:

- availability target in basis points;
- optional latency target;
- rolling evaluation window;
- warning and critical burn-rate thresholds;
- consecutive-failure threshold;
- recovery-success threshold.

A single failed probe does not open an incident. The failure threshold must be reached, or a sufficiently sampled rolling error budget or latency objective must be breached.

## Probe targets

Probe targets are stored only in the protected central database. Query services remove `target_value`, target hashes, worker lease hashes, account scope, and internal IDs before returning data.

Supported target formats:

- HTTPS: canonical `https://` URL without credentials or fragments
- DNS: hostname
- TLS: hostname
- database: `primary`
- release worker: `staging:<maximum-age-seconds>` or `production:<maximum-age-seconds>`
- release queue: numeric open-job threshold
- storage: `application_root`
- manual dependency: `manual`

HTTP, DNS, and TLS probes validate public network behavior. Database, worker, queue, and storage probes use protected local runtime access. Manual probes accept customer-safe provider/POD/HomeServer observations without storing external credentials.

## Worker

Run the dedicated reliability worker at least once per minute:

```bash
VP3_RELIABILITY_WORKER_ID=vp3-reliability-01 \
VP3_RELIABILITY_MAX_PER_RUN=25 \
VP3_RELIABILITY_LEASE_SECONDS=300 \
php workers/reliability.php
```

The worker:

1. claims one due probe under a database row lock;
2. records a hashed worker lease;
3. checks whether an approved Phase 34 maintenance window is active;
4. executes the protected probe or records `maintenance`;
5. writes an immutable observation;
6. recalculates the rolling error budget;
7. evaluates failure, recovery, latency, and burn-rate thresholds;
8. appends a tamper-evident status event when the component changes;
9. opens, escalates, or resolves the linked Phase 18 Operations incident;
10. clears the lease and schedules the next run.

Expired leases are recoverable. A stable worker identity should be used for operational diagnosis.

## Maintenance synchronization

A component may be linked to a Phase 34 staging or production environment. An approved maintenance window is active only while:

- the environment matches the component;
- the window has an approver;
- the window status is `scheduled` or `open`;
- the current UTC time is inside the window.

During that period, observations are stored as `maintenance`. They do not count as successes or failures, do not consume the error budget, and do not open a new reliability incident. The component status is visibly `maintenance`.

## Error budgets and burn rates

For each observation, Phase 35 calculates:

- total non-maintenance probes in the rolling window;
- failed probes;
- measured availability in basis points;
- budget consumption;
- burn rate;
- budget state: `healthy`, `warning`, or `exhausted`.

Budget-only escalation requires a meaningful sample size to prevent early false alarms. Consecutive failures remain the primary immediate-outage signal.

## Incident automation

When a component becomes `degraded` or `major_outage`, Phase 35 opens or escalates one monitor-managed Operations incident using source type `reliability_component`.

The link table guarantees one active incident per component. When the configured recovery-success threshold is reached and the component returns to `operational`, the linked incident is resolved with evidence from the recovery observation and current error budget.

All normal Operations notification routing remains active.

## Release correlation

Components linked to a Phase 34 environment include the environment’s active signed release identity. The Control Center compares failure rates during the sixty minutes before and after the latest completed deployment when samples exist.

This correlation is diagnostic evidence, not automatic proof that a release caused an incident.

## Public status page

An owner may publish a status page at:

```text
/status.php?status=<public-slug>
```

The public page contains only:

- explicitly public components;
- customer-safe component names, types, and status;
- objective availability/latency summaries;
- active and recent public messages;
- optional public status history;
- generated timestamp.

It omits:

- account and resource public IDs;
- probe targets and hashes;
- environment IDs and fingerprints;
- release promotion IDs;
- worker identities and leases;
- incident IDs;
- internal database IDs;
- raw errors and infrastructure details.

The page has a restrictive CSP and a short public cache lifetime.

## Status communication

Owners and administrators may publish scheduled maintenance, incident, and resolution messages. Messages can apply to one public component or all components. Requests are replay-safe and conflicting reuse of a request ID is rejected.

## Fresh installation and upgrade

Fresh installations continue to use only:

`database/vp3-single-install.sql`

Existing Phase 34 installations apply:

`database/migrations/20260731_phase35_platform_reliability_slo_status_center.sql`

through the certified Phase 33 ordered upgrade runner. Do not import the cumulative installer over a live database.

## Certification

Phase 35 certification must pass:

- PHP 8.2
- PHP 8.3
- MySQL 8
- MariaDB 10.11
- deterministic cumulative installer generation and double import
- platform-operator authorization
- request replay and conflict handling
- protected target redaction
- consecutive-failure false-positive protection
- approved-maintenance suppression
- rolling error-budget calculation
- automatic incident open/escalation/recovery
- tamper-evident status-event chain verification
- public-status privacy boundary
- retained Phase 2–35 contracts and database integrations
