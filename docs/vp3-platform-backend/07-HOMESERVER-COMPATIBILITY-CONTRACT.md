# HomeServer Management Compatibility Contract

VP3.me will implement or adapt the existing HomeServer provider routes without redesigning HomeServer product features:

- `POST /api/homeserver/v1/pairing/exchange`
- `POST /api/homeserver/v1/entitlements/refresh`
- `POST /api/homeserver/v1/devices/heartbeat`
- `POST /api/homeserver/v1/devices/credentials/rotate`
- `POST /api/homeserver/v1/updates/authorize`
- `POST /api/homeserver/v1/updates/receipts`
- `POST /api/homeserver/v1/devices/replacements/start`
- `POST /api/homeserver/v1/devices/replacements/complete`

The management website is authoritative for account, subscription, license, device registration, pairing, entitlement leases, capability grants, site and merchant assignments, release availability, update eligibility, and cloud-side receipts.

HomeServer remains authoritative for local files, Knowledge Vault data, models, agents, conversations, MCP clients, tools, skills, backups, local configuration, installed-update verification, local security decisions, and automatic rollback.

VP3.me must never become a remote kill switch for local HomeServer operation. Bootstrap, security, and recovery updates remain available without an active paid subscription. Premium maintenance, feature, and preview updates may require an eligible HomeServer license.
