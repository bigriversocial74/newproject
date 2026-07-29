# Configuration

Copy `config-example.php` to `config.php` for local or deployed use. Supply secrets through environment variables. Never commit `config.php`.

Required production values:

- `APP_ENV=production`
- `APP_BASE_URL=https://vp3.me`
- `APP_SESSION_NAME=vp3_session`
- `APP_SESSION_SECURE=1`
- `DB_DSN=mysql:host=...;dbname=...;charset=utf8mb4`
- `DB_USERNAME=...`
- `DB_PASSWORD=...`
