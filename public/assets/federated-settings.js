(() => {
  'use strict';

  const root = document.querySelector('[data-federated-settings]');
  const shell = document.querySelector('[data-control-center]');
  if (!root || !shell) return;

  const accountPublicId = Number(shell.dataset.accountPublicId || 0);
  const csrfToken = shell.dataset.csrfToken || '';
  const groups = document.getElementById('settings-groups');
  const summary = document.getElementById('settings-summary');
  const notice = document.getElementById('settings-notice');
  const deviceSelect = document.getElementById('settings-device');
  const deviceState = document.getElementById('settings-device-state');
  const refreshButton = document.getElementById('refresh-settings');
  let snapshot = null;

  const escapeHtml = (value) => String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');

  const requestId = () => {
    const identity = globalThis.crypto?.randomUUID?.()
      || `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    return `settings:${identity}`.slice(0, 64);
  };

  const showNotice = (message, tone = 'info') => {
    notice.innerHTML = message
      ? `<div class="notice ${escapeHtml(tone)}">${escapeHtml(message)}</div>`
      : '';
  };

  const post = async (url, payload, request = null) => {
    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'X-CSRF-Token': csrfToken,
    };
    if (request) headers['X-Request-ID'] = request;
    const response = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers,
      body: JSON.stringify({
        account_public_id: accountPublicId,
        csrf_token: csrfToken,
        ...payload,
        ...(request ? { request_id: request } : {}),
      }),
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
  }[category] || String(category).replaceAll('_', ' '));

  const authorityLabel = (authority) => ({
    vp3: 'VP3 authority',
    homeserver: 'HomeServer authority',
    shared: 'Shared authority',
  }[authority] || authority);

  const selectedDevice = () => String(deviceSelect?.value || '');

  const canEdit = (setting, data) => Boolean(
    setting.editable_in_vp3
    && (!setting.requires_device || data.selected_device_public_id)
  );

  const control = (setting, data) => {
    const disabled = canEdit(setting, data) ? '' : ' disabled';
    const key = escapeHtml(setting.setting_key);
    if (setting.value_type === 'boolean') {
      return `<label class="settings-switch"><input type="checkbox" data-setting-input="${key}" data-revision="${setting.revision}"${setting.value ? ' checked' : ''}${disabled}><span></span><em>${setting.value ? 'Enabled' : 'Disabled'}</em></label>`;
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

  const renderDevices = (data) => {
    const selected = String(data.selected_device_public_id || '');
    deviceSelect.innerHTML = [
      '<option value="">Account settings only</option>',
      ...data.devices.map((device) => `<option value="${escapeHtml(device.public_id)}">${escapeHtml(device.public_id)} · ${escapeHtml(device.status)}</option>`),
    ].join('');
    deviceSelect.value = selected;
    const active = data.devices.find((device) => device.public_id === selected);
    if (active) {
      const version = active.software_version ? ` · version ${escapeHtml(active.software_version)}` : '';
      deviceState.innerHTML = `<strong>${escapeHtml(active.public_id)}</strong><span>${escapeHtml(active.status)} · ${escapeHtml(active.pairing_status)}${version}</span>`;
    } else if (data.devices.length > 0) {
      deviceState.innerHTML = '<strong>Account settings only</strong><span>Select a HomeServer to edit shared preferences.</span>';
    } else {
      deviceState.innerHTML = '<strong>No HomeServer available</strong><span>Pair an account-owned HomeServer before editing shared preferences.</span>';
    }
  };

  const render = (data) => {
    snapshot = data;
    renderDevices(data);
    summary.innerHTML = [
      ['Revision', data.max_revision],
      ['Settings', data.settings.length],
      ['HomeServers', data.devices.length],
      ['Signature', data.signature_algorithm || 'Unavailable'],
    ].map(([label, value]) => `<article class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></article>`).join('');

    const byCategory = new Map();
    data.settings.forEach((setting) => {
      if (!byCategory.has(setting.category)) byCategory.set(setting.category, []);
      byCategory.get(setting.category).push(setting);
    });
    groups.innerHTML = [...byCategory.entries()].map(([category, settings]) => `
      <section class="panel settings-group">
        <header class="panel-head"><div><span class="eyebrow">${escapeHtml(category)}</span><h3>${escapeHtml(categoryTitle(category))}</h3></div><span>${settings.length} settings</span></header>
        <div class="settings-list">
          ${settings.map((setting) => {
            const lockedReason = setting.authority === 'homeserver'
              ? 'Managed locally by HomeServer'
              : (setting.requires_device && !data.selected_device_public_id ? 'Select a HomeServer to edit' : '');
            return `<article class="settings-row ${canEdit(setting, data) ? '' : 'locked'}">
              <div class="settings-copy">
                <div class="settings-title"><strong>${escapeHtml(setting.label)}</strong><span class="settings-authority ${escapeHtml(setting.authority)}">${escapeHtml(authorityLabel(setting.authority))}</span></div>
                <p>${escapeHtml(setting.description)}</p>
                <small>${escapeHtml(setting.setting_key)} · revision ${setting.revision} · ${escapeHtml(setting.scope)}${lockedReason ? ` · ${escapeHtml(lockedReason)}` : ''}</small>
              </div>
              <div class="settings-input">${control(setting, data)}</div>
            </article>`;
          }).join('')}
        </div>
      </section>`).join('');

    groups.querySelectorAll('[data-setting-input]').forEach((input) => {
      input.addEventListener('change', async () => {
        if (input.disabled || !snapshot) return;
        const setting = snapshot.settings.find((item) => item.setting_key === input.dataset.settingInput);
        if (!setting) return;
        let value = input.value;
        if (setting.value_type === 'boolean') value = input.checked;
        if (setting.value_type === 'integer') value = Number.parseInt(input.value, 10);
        const devicePublicId = setting.requires_device ? selectedDevice() : null;
        input.disabled = true;
        showNotice(`Saving ${setting.label}…`);
        try {
          const updated = await post('/api/settings/v1/update.php', {
            setting_key: setting.setting_key,
            value,
            expected_revision: Number(input.dataset.revision || 0),
            device_public_id: devicePublicId,
          }, requestId());
          render(updated);
          showNotice(`${setting.label} saved in the ${setting.requires_device ? 'selected HomeServer' : 'VP3 account'} scope.`, 'success');
        } catch (error) {
          showNotice(error.message, 'error');
          await load(devicePublicId || selectedDevice());
        }
      });
    });
  };

  const load = async (devicePublicId = selectedDevice()) => {
    groups.innerHTML = '<div class="empty">Loading federated settings…</div>';
    showNotice('');
    try {
      render(await post('/api/settings/v1/snapshot.php', {
        device_public_id: devicePublicId || null,
      }));
    } catch (error) {
      groups.innerHTML = '<div class="empty error">Federated settings are unavailable.</div>';
      showNotice(error.message, 'error');
    }
  };

  deviceSelect?.addEventListener('change', () => load(selectedDevice()));
  refreshButton?.addEventListener('click', () => load(selectedDevice()));
  load('');
})();
