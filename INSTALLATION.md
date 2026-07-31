# VP3 Control-Panel Installation

1. Extract the deployment ZIP into the application directory.
2. Rename `config/config-example-browser.php` to `config/config.php`.
3. Edit only the domain and database values in `$vp3LocalSettings`.
4. Create an empty MySQL 8 or MariaDB 10.11 database.
5. Import `database/vp3-single-install.sql` using phpMyAdmin or the hosting database manager.
6. Open `https://YOUR-DOMAIN/setup.php`.
7. Create the first administrator.
8. Save the returned `ACC-...` and `USR-...` public identities.

VP3 automatically generates its private encryption key in `config/config-generated-secrets.php`. Preserve that file and `config/config.php` during future deployments. The first account is created as an active verified `customer_owner` and receives platform-operator access. The browser setup page permanently locks after the first account or user is created.
