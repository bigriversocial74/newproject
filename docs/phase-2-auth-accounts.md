# Phase 2 — Authentication and Accounts

## Scope

This phase introduces the minimum PHP foundation required for VP3.me customer authentication and account ownership.

Included:

- PHP 8.1+ project bootstrap;
- PDO database service with transactions;
- secure session cookies and CSRF token support;
- customer account and owner-user registration;
- normalized unique email enforcement;
- password policy and `PASSWORD_DEFAULT` hashing;
- sign-in with session rotation;
- email-verification token foundation;
- password-reset token foundation;
- account membership roles;
- authentication session records;
- privacy-safe login-attempt records;
- audit-event foundation;
- additive MySQL/MariaDB migration;
- PHP 8.1 and PHP 8.3 validation workflow.

## Deployment

1. Copy `config/config-example.php` to `config/config.php`.
2. Supply production database and application values through environment variables.
3. Import `database/migrations/20260728_phase2_auth_accounts.sql`.
4. Point the web server document root at `public/`.
5. Keep `config/config.php` outside deployment overwrites.

## API endpoints

- `POST /api/auth/register.php`
- `POST /api/auth/login.php`

## Boundaries

This phase does not yet implement Stripe, Domain registrations, POD/HomeServer license issuance, provisioning, email transport, or administrator UI integration. Those remain subsequent phases.
