<!-- Consolidated review volume: 01-CORE-ARCHITECTURE-CONTRACTS.md; part 1 of 4 -->

# VP3.me Backend Build Plan
> Final implementation baseline. Individual source documents are consolidated into review volumes for repository storage.

---

<!-- Source: 01-VP3-BACKEND-SPECIFICATION.md -->

# VP3.me Backend Specification

## 1. Product boundary

VP3.me is the management and control platform for the hosted POD product and related HomeServer entitlements.

VP3.me is authoritative for:
- customer account and subscription state;
- Domain Code ownership and routing state;
- plans and entitlement resolution;
- POD and HomeServer licenses;
- hosted storage allowance;
- deployment metadata and operational health;
- release and update eligibility;
- backup retention policy;
- billing, renewal, grace, suspension, and termination state;
- administrator operations and audit history.

The POD remains authoritative for:
- public and private website content;
- CRM, blog, portfolio, media, streaming, and social data;
- POD-local users and settings;
- application data and customer-owned records;
- local feature usage and installed component state.

The HomeServer remains authoritative for:
- private knowledge and files;
- local models and runtimes;
- agent state, tools, credentials, and conversations;
- MCP runtime and local permissions;
- private compute and local execution receipts.

VP3.me must not copy customer POD content or HomeServer private knowledge into its control database.

## 2. Application architecture

Recommended structure:

```text
app/
  Auth/
  Customers/
  DomainCodes/
  Catalog/
  Billing/
  Licensing/
  Deployments/
  Provisioning/
  HomeServers/
  Releases/
  Updates/
  Backups/
  Storage/
  Notifications/
  Support/
  Audit/
  Security/
  Shared/
api/
  v1/
admin/
customer/
workers/
database/
tests/
```

Business logic belongs in services and policies, not page controllers.

## 3. Technology requirements

The implementation should support the existing PHP deployment environment and use:
- PHP 8.2 and 8.3 compatibility;
- MySQL 8 and MariaDB 10.11 compatibility where practical;
- PDO with prepared statements;
- database migrations with deterministic ordering;
- queue-backed long-running operations;
- environment-based configuration;
- encrypted secret storage;
- structured JSON logs and request IDs;
- server-side authorization policies;
- append-only operational audit events.

## 4. Core modules

### 4.1 Authentication and customers

Responsibilities:
- registration and sign-in;
- password reset;
- session management and rotation;
- optional MFA extension point;
- customer organizations;
- customer member roles;
- billing and support contacts;
- login and security events.

Roles:
- customer_owner;
- customer_admin;
- billing_manager;
- support_member;
- vp3_support;
- vp3_operations;
- vp3_admin;
- vp3_super_admin.

### 4.2 Domain Code registry

Responsibilities:
- availability search;
- temporary reservation;
- purchase conversion;
- ownership assignment;
- renewal and expiration;
- aliases and redirects;
- transfers and administrative holds;
- routing and SSL state;
- event history.

A database-level unique constraint must prevent duplicate ownership.

### 4.3 Plans, subscriptions, and entitlements

Plans resolve into normalized entitlements. Application code must check capabilities and limits, not plan names.

Initial entitlement keys:
- storage_bytes;
- pod_installation_limit;
- homeserver_limit;
- mcp_client_limit;
- update_channel;
- automatic_updates;
- managed_security;
- backup_retention_days;
- support_tier;
- custom_domain_alias_limit;
- pod_user_limit;
- api_access;
- security_update_access.

### 4.4 Licensing

Responsibilities:
- issue, assign, renew, suspend, restore, expire, and terminate licenses;
- resolve entitlements from subscription state;
- sign entitlement documents;
- validate POD and HomeServer requests;
- rotate tokens and signing keys;
- record validation and administrator receipts.

### 4.5 POD deployment registry

Responsibilities:
- deployment identity;
- Domain Code assignment;
- hosting location reference;
- installed version and update channel;
- installation fingerprint;
- storage usage summary;
- health heartbeat;
- provisioning status;
- SSL, backup, update, and license status.

### 4.6 HomeServer registry

Responsibilities:
- licensed HomeServer identity;
- customer assignment;
- pairing status;
- current software and MCP versions;
- permitted paired-front-end count;
- last heartbeat;
- operational state and update channel.

Do not store HomeServer knowledge, prompts, model data, or tool credentials.

### 4.7 Provisioning

Provisioning begins automatically after successful purchase. The customer does not perform a separate activation.

Stages:
- payment_confirmed;
- domain_registered;
- hosting_allocated;
- database_created;
- pod_installed;
- configuration_written;
- owner_account_created;
- license_injected;
- ssl_requested;
- installation_verified;
- deployment_active.

Provisioning must be resumable and idempotent.

### 4.8 Releases and updates

Responsibilities:
- product and release records;
- signed release manifests;
- stable and beta channels;
- compatibility rules;
- staged rollout controls;
- pre-update backup requirement;
- update receipts;
- automatic rollback;
- emergency security release policy.

### 4.9 Backups

Responsibilities:
- scheduled and on-demand backup jobs;
- pre-update snapshots;
- verification state;
- retention enforcement;
- restore requests and receipts;
- encrypted storage metadata;
- failed-backup alerts.

A backup is not successful until verification passes.

### 4.10 Monitoring and notifications

Monitor only operational metadata:
- endpoint reachability;
- SSL state;
- database connectivity summary;
- storage threshold;
- last heartbeat;
- updater state;
- backup state;
- license validation state;
- HomeServer pairing availability.

Notifications:
- POD ready;
- payment failed;
- renewal approaching;
- storage threshold reached;
- update available/completed/failed;
- backup failed;
- license grace/suspension;
- HomeServer offline;
- security alert.

## 5. Status vocabularies

### License
- active
- grace
- suspended
- expired
- terminated

### Subscription
- trialing
- active
- past_due
- grace
- canceled
- expired

### Deployment
- pending
- provisioning
- active
- degraded
- suspended
- failed
- archived

### Provisioning job
- queued
- running
- waiting
- retrying
- completed
- failed
- canceled

### Update job
- queued
- validating
- backing_up
- downloading
- installing
- migrating
- verifying
- completed
- rolling_back
- rolled_back
- failed

### Backup
- queued
- running
- verifying
- verified
- failed
- expired
- deleted

## 6. Operational rules

- Every mutation receives a request ID and idempotency key when applicable.
- Every administrator mutation creates an audit receipt.
- Customer ownership is verified server-side for every resource request.
- Billing webhooks are idempotent.
- Provisioning and updates never run inside the checkout HTTP request.
