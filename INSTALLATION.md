# VP3 Control-Panel Installation

1. Extract the deployment ZIP into the application directory.
2. Rename `config/config-example.php` to `config/config.php`.
3. Edit the `$vp3LocalSettings` block at the top of `config/config.php`.
4. Create an empty MySQL 8 or MariaDB 10.11 database.
5. Import `database/vp3-single-install.sql` using phpMyAdmin or the hosting database manager.
6. Open `https://YOUR-DOMAIN/setup.php`.
7. Enter the private setup key from `config/config.php` and create the first administrator.
8. Save the returned `ACC-...` and `USR-...` public identities.

The browser setup page permanently locks after the first account or user is created.
