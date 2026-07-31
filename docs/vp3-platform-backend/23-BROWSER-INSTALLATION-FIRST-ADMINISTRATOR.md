# Browser Installation and First Administrator

## Purpose

This installation path is for operators who deploy VP3 through a hosting control panel, file manager, and phpMyAdmin rather than a command shell.

## Installation sequence

1. Download and extract the certified deployment ZIP.
2. Rename `config/config-example.php` to `config/config.php`.
3. Edit the clearly marked `$vp3LocalSettings` block at the top of `config/config.php`.
4. Create an empty MySQL 8 or MariaDB 10.11 database.
5. Import `database/vp3-single-install.sql` with phpMyAdmin or the hosting database manager.
6. Open `/setup.php` on the deployed VP3 domain.
7. Enter the private setup key from `config/config.php` and create the first administrator.

## Required config values

The basic editable block contains:

- production environment
- canonical HTTPS application URL
- database DSN
- database username
- database password
- 32-byte base64 authentication encryption key
- private first-user setup key

Advanced deployments may override these values with protected environment variables, but environment variables are not required for the browser installation path.

## First-administrator security boundary

`public/setup.php` is a one-time bootstrap surface. It:

- requires `config/config.php`;
- rejects unchanged example secrets;
- requires a valid 32-byte base64 authentication encryption key;
- requires an HTTPS production origin;
- verifies that the certified SQL tables exist;
- requires a private setup key using constant-time comparison;
- uses a strict same-site, HTTP-only session cookie and CSRF token;
- limits failed setup-key attempts within the setup session;
- creates the owner and platform-operator grant in one outer transaction;
- creates one verified active user, one active organization, and one active `customer_owner` membership;
- grants the account platform-operator authority when enabled in config;
- permanently locks when either an account or user exists.

The setup key and owner password are never written to deployment receipts or returned in the response.

## After setup

The success page returns the public `ACC-...` and `USR-...` identities for deployment records. Reloading `/setup.php` after creation shows the locked state. The setup file may remain deployed because the database lock condition prevents reuse, although a host may additionally restrict or remove public access to it after installation.

## Existing installations

Do not use `/setup.php` to add normal users or additional owners. Existing installations use the authenticated Account, Team and Security Control Center. Do not reimport `database/vp3-single-install.sql` over an existing database.
