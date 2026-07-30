(() => {
  'use strict';

  const root = document.querySelector('[data-federated-settings]');
  if (!root) return;

  const accountId = () => Number(root.dataset.accountId || 0);
  const csrfToken = root.dataset.csrfToken || '';
  const groups = document.getElementById('settings-groups');
  const summary = document.getElementById('settings-summary');
  const notice = document.getElementById('settings-notice');
  const accountSelect = document.getElementById('settings-account');
  const refreshButton = document.getElementById('refresh-settings');
  const syncButton = document.getElementById('sync-settings');
  let snapshot = null;

  const escapeHtml = (value) => String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');

  const showNotice = (message, tone = 'info') => {
    notice.innerHTML = message ? `<div class="notice ${escapeHtml(tone)}">${escapeHtml(message)}</div>` : '';
  };

  const post = async (url, payload) => {
    const response = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({ account_id: accountId(), ...payload }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body?.error?.message || `Request failed with HTTP ${response.status}`);
    }
    return body.data;
  };

  const categoryTitle = (category) => ({
    appearance: 'Appearance',
    regional: 'Regional',
    updates: 'Updates',
    notifications: 'Notifications',
    privacy: 'Privacy',
    commerce: 'Commerce defaults',
  }[category] || category.replaceAll('_', ' '));

  const authorityLabel = (authority) => ({
    vp3: 'VP3 authority',
    homeserver: 'HomeServer authority',
    shared: 'Shared authority',
  }[authority] || authority);

  const control = (setting) => {
    const disabled = setting.editable_in_vp3 ? '' : ' disabled';
    const key = escapeHtml(setting.setting_key);
    if (setting.value_type === 'boolean') {
      return `<label class="switch"><input type="checkbox" data-setting-input="${key}" data-revision="${setting.revision}"${setting.value ? ' checked' : ''}${disabled}><span></span><em>${setting.value ? 'Enabled' : 'Disabled'}</em></label>`;
    }
    if (setting.value_type === 'enum') {
      const options = (setting.allowed_values || []).map((value) => `<option value="${escapeHtml(value)}"${value === setting.value ? ' selected' : ''}>${escapeHtml(value)}</option>`).join('');
      return `<select data-setting-input="${key}" data-revision="${setting.revision}"${disabled}>${options}</select>`;
    }
    if (setting.value_type === 'integer') {
      return `<input type="number" data-setting-input="${key}" data-revision="${setting.revision}" value="${escapeHtml(setting.value)}"${disabled}>`;
    }
    return `<input type="text" maxlength="200" data-setting-input="${key}" data-revision="${setting.revision}" value="${escapeHtml(setting.value)}"${disabled}>`;
  };

  const render = (data) => {
    snapshot = data;
    summary.innerHTML = [
      ['Revision', data.max_revision],
      ['Settings', data.settings.length],
      ['Snapshot', String(data.snapshot_hash).slice(0, 12)],
      ['Sync model', 'Conflict-safe'],
    ].map(([label, value]) => `<article><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></article>`).join('');

    const byCategory = new Map();
    data.settings.forEach((setting) => {
      if (!byCategory.has(setting.category)) byCategory.set(setting.category, []);
      byCategory.get(setting.category).push(setting);
    });
    groups.innerHTML = [...byCategory.entries()].map(([category, settings]) => `
      <section class="settings-group">
        <header><div><span class="eyebrow">${escapeHtml(category)}</span><h2>${escapeHtml(categoryTitle(category))}</h2></div><span>${settings.length} settings</span></header>
        <div class="settings-list">
          ${settings.map((setting) => `
            <article class="setting-row ${setting.editable_in_vp3 ? '' : 'locked'}">
              <div class="setting-copy"><div class="setting-title"><strong>${escapeHtml(setting.label)}</strong><span class="authority ${escapeHtml(setting.authority)}">${escapeHtml(authorityLabel(setting.authority))}</span></div><p>${escapeHtml(setting.description)}</p><small>${escapeHtml(setting.setting_key)} · revision ${setting.revision} · ${escapeHtml(setting.scope)}</small></div>
              <div class="setting-control">${control(setting)}</div>
            </article>`).join('')}
        </div>
      </section>`).join('');

    groups.querySelectorAll('[data-setting-input]').forEach((input) => {
      input.addEventListener('change', async () => {
        if (input.disabled) return;
        const setting = data.settings.find((item) => item.setting_key === input.dataset.settingInput);
        if (!setting) return;
        let value = input.value;
        if (setting.value_type === 'boolean') value = input.checked;
        if (setting.value_type === 'integer') value = Number.parseInt(input.value, 10);
        input.disabled = true;
        showNotice(`Saving ${setting.label}…`);
        try {
          const updated = await post('/api/settings/v1/update.php', {
            setting_key: setting.setting_key,
            value,
            expected_revision: Number(input.dataset.revision || 0),
          });
          render(updated);
          showNotice(`${setting.label} saved. HomeServer will receive it during the next settings sync.`, 'success');
        } catch (error) {
          showNotice(error.message, 'error');
          await load();
        }
      });
    });
  };

  const load = async () => {
    groups.innerHTML = '<div class="loading">Loading shared settings…</div>';
    showNotice('');
    try {
      render(await post('/api/settings/v1/snapshot.php', {}));
    } catch (error) {
      groups.innerHTML = '<div class="loading error">Shared settings are unavailable.</div>';
      showNotice(error.message, 'error');
    }
  };

  accountSelect?.addEventListener('change', () => {
    const url = new URL(window.location.href);
    url.searchParams.set('account_id', accountSelect.value);
    window.location.assign(url.toString());
  });
  refreshButton?.addEventListener('click', load);
  syncButton?.addEventListener('click', async () => {
    await load();
    showNotice('Open HomeServer Control Center and choose Sync Now to exchange this revisioned snapshot.', 'success');
  });

  load();
})();
