# Phase 1 Implementation Scope

Phase 1 begins production backend work for the VP3.me management platform.

## Deliverables

- PHP application bootstrap and configuration loading
- environment example without live secrets
- database connection layer
- additive MySQL/MariaDB migrations
- VP3 accounts and account users
- domain registrations
- products, plans, subscriptions, and entitlement definitions
- separate POD and HomeServer license records
- domain-to-license bundle service
- audit event foundation
- idempotent bundle issuance service
- initial automated tests for one-domain/one-POD-license/one-HomeServer-license invariants

## Excluded from Phase 1

- live Stripe checkout
- live DNS or SSL provisioning
- POD installation
- HomeServer device pairing
- signed entitlement issuance
- release publishing
- automatic updates
- production deployment

Those capabilities build on the Phase 1 records and service boundaries.
