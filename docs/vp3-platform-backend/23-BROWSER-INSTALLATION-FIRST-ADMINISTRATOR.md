# Browser Installation and First Administrator

## Purpose

This installation path is for operators who deploy VP3 through a hosting control panel, file manager, and phpMyAdmin rather than a command shell.

## Installation sequence

1. Download and extract the certified deployment ZIP.
2. Rename `config/config-example-browser.php` to `config/config.php`.
3. Edit only the domain and database values in `$vp3LocalSettings`.
4. Create an empty MySQL 8 or MariaDB 10.11 database.
5. Import `database/vp3-single-install.sql` with phpMyAdmin or the hosting database manager.
6. Open `/setup.php` on the deployed VP3 domain.
7. Create the first administrator.

## Required config values

The short browser-editable config inherits the complete advanced defaults from `config/config-example.php`. Its editable block contains only:

- canonical HTTPS application URL
- database DSN
- database username
- database password

The config automatically generates a cryptographically secure 32-byte authentication encryption key and persists it in `config/config-generated-secrets.php`. The file is created with restricted permissions when supported, excluded from Git, and reused on every later request. Preserve both `config/config.php` and `config/config-generated-secrets.php` during future deployments.

The browser config automatically sets the application to production, enables secure sessions, enables one-time browser setup, and grants the first owner platform-operator access. Advanced deployments may still override settings with protected environment variables, but environment variables are not required for this browser installation path.

## First-administrator security boundary

`public/setup.php` is a one-time bootstrap surface. It:

- requires `config/config.php`;
- verifies the automatically generated 32-byte encryption key;
- requires an HTTPS production origin;
- verifies that the certified SQL tables exist;
- uses a strict same-site, HTTP-only session cookie and CSRF token;
- creates the owner and platform-operator grant in one outer transaction;
- creates one verified active user, one active organization, and one active `customer_owner` membership;
- grants the account platform-operator authority;
- permanently locks when either an account or user exists.

The administrator password and generated encryption key are never written to deployment receipts or returned in the page response.

## After setup

The success page returns the public `ACC-...` and `USR-...` identities for deployment records. Reloading `/setup.php` after creation shows the locked state. The setup file may remain deployed because the database lock condition prevents reuse, although a host may additionally restrict or remove public access to it after installation.

## Existing installations

Do not use `/setup.php` to add normal users or additional owners. Existing installations use the authenticated Account, Team and Security Control Center. Do not reimport `database/vp3-single-install.sql` over an existing database.
