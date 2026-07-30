from __future__ import annotations

from pathlib import Path
import re

FILES = [
    Path('public/assets/control-center.js'),
    Path('public/assets/billing-control-center.js'),
    Path('public/assets/homeserver-fleet.js'),
    Path('public/assets/homeserver-transfer-accept.js'),
    Path('public/assets/account-security.js'),
    Path('public/assets/operations-control-center.js'),
    Path('public/assets/recovery-control-center.js'),
    Path('public/assets/infrastructure-control-center.js'),
    Path('public/assets/federated-settings.js'),
]

for path in FILES:
    source = path.read_text(encoding='utf-8')
    updated = re.sub(r'\baccountId\b', 'accountPublicId', source)
    updated = updated.replace('dataset.accountId', 'dataset.accountPublicId')
    updated = updated.replace('account_id', 'account_public_id')
    updated = updated.replace('Number(root.dataset.accountPublicId || 0)', "String(root.dataset.accountPublicId || '')")
    updated = updated.replace('Number(accountSelect?.value || root.dataset.accountPublicId || 0)', "String(accountSelect?.value || root.dataset.accountPublicId || '')")
    updated = updated.replace('Number(accountSelect.value || root.dataset.accountPublicId || 0)', "String(accountSelect.value || root.dataset.accountPublicId || '')")
    updated = updated.replace('url.searchParams.set("account_public_id", String(accountPublicId));', 'url.searchParams.set("account", accountPublicId);')
    updated = updated.replace("url.searchParams.set('account_public_id', String(accountPublicId));", "url.searchParams.set('account', accountPublicId);")
    if path.name == 'homeserver-fleet.js':
        updated = updated.replace('<span>Account ID</span><code>${Number(bundle.account_public_id)}</code>', '<span>Account public ID</span><code>${escapeHtml(bundle.account_public_id || accountPublicId())}</code>')
        updated = updated.replace('account_public_id: Number(bundle.account_public_id)', 'account_public_id: bundle.account_public_id || accountPublicId()')
        updated = updated.replace('account_public_id: accountPublicId()', 'account_public_id: accountPublicId()')
        updated = updated.replace('const target = Number(window.prompt("Enter the destination VP3 account ID:") || 0);\n        if (!target) return;', 'const target = String(window.prompt("Enter the destination VP3 account public ID:") || "").trim();\n        if (!target) return;')
    if path.name == 'homeserver-transfer-accept.js':
        updated = updated.replace('<span>Account ID</span><code>${bundleAccountPublicId}</code>', '<span>Account public ID</span><code>${escapeHtml(bundle.account_public_id || bundleAccountPublicId)}</code>')
        updated = updated.replace('account_public_id: bundleAccountPublicId', 'account_public_id: bundle.account_public_id || bundleAccountPublicId')
    if updated == source:
        raise SystemExit(f'No Phase 23 transformation applied to {path}')
    path.write_text(updated, encoding='utf-8')

for path in FILES:
    source = path.read_text(encoding='utf-8')
    forbidden = ['dataset.accountId', 'account_id', 'Number(root.dataset.accountPublicId', 'Number(accountSelect']
    for needle in forbidden:
        if needle in source:
            raise SystemExit(f'{path} still contains forbidden browser account identity pattern: {needle}')

Path('tools/phase23_public_account_rewrite.py').unlink()
Path('.github/workflows/phase23-public-account-rewrite.yml').unlink()
