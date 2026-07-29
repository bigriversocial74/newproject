# VP3.me Domain-Centered License Bundle Contract

## Commercial anchor

An active VP3 domain registration is the commercial and licensing anchor.

Each active domain registration receives exactly:

- one POD license;
- one HomeServer license.

The POD and HomeServer licenses are distinct records with independent product scopes, status history, tokens, assignments, and audit receipts. Both records are linked to the same VP3 account, domain registration, subscription, plan, and entitlement bundle.

A VP3 account may own multiple active domain registrations. Each active domain registration creates its own POD/HomeServer license pair. The account itself is not a single global product license.

## Required relationship

```text
VP3 Account
└── Domain Registration
    ├── POD License
    └── HomeServer License
```

## Required invariants

1. One active domain registration has one active POD license assignment.
2. One active domain registration has one active HomeServer license assignment.
3. A POD license cannot be assigned to a different domain without an explicit audited rebind.
4. A HomeServer license cannot be assigned to a different domain without an explicit audited replacement or rebind.
5. A domain transfer must transfer or reissue both linked licenses through an audited workflow.
6. Canceling one product entitlement must not silently delete either deployment or local customer data.
7. Temporary VP3 outages must not disable the public POD or local HomeServer operation.

## Status behavior

Supported states:

- `pending`
- `active`
- `grace`
- `suspended`
- `canceled`
- `expired`
- `terminated`
- `unknown`

Status changes are applied to each product license independently, while the subscription and domain registration remain the upstream commercial source.

## Provisioning behavior

After successful Stripe payment and confirmed domain registration:

1. Create the subscription.
2. Create the domain registration.
3. Create the POD license.
4. Create the HomeServer license.
5. Assign both licenses to the domain registration.
6. Create the POD deployment record.
7. Queue POD installation.
8. Make the HomeServer download and pairing entitlement available.
9. Issue separate signed entitlement documents for the POD and HomeServer.
10. Record the complete bundle issuance in the audit stream.

## Product boundaries

The POD license governs:

- hosted storage allowance;
- POD update channel;
- automatic POD update eligibility;
- managed security eligibility;
- backup retention;
- POD support tier;
- POD deployment assignment.

The HomeServer license governs:

- device allowance;
- HomeServer release channels;
- premium update eligibility;
- pairing and Sync Codes;
- provider connection;
- site and merchant assignments;
- capability and dataset grants;
- entitlement leases.

## Non-destructive enforcement

License expiration, suspension, provider outage, or billing failure must never directly delete customer content, local files, Knowledge Vault data, models, agents, backups, or credentials.

The public POD should remain available where practical. The HomeServer must continue local operation. Restricted states may limit cloud services, premium updates, new storage consumption, or administrative changes according to policy.
