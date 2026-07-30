(() => {
  'use strict';

  const root = document.querySelector('[data-control-center][data-page="operations"]');
  if (!root) return;

  const accountId = Number(root.dataset.accountId || 0);
  const csrfToken = String(root.dataset.csrfToken || '');
  const notice = document.getElementById('operations-notice');
  const dialog = document.getElementById('operations-dialog');
  const dialogForm = document.getElementById('operations-dialog-form');
  const dialogTitle = document.getElementById('operations-dialog-title');
  const dialogBody = document.getElementById('operations-dialog-body');
  const dialogConfirm = document.getElementById('operations-dialog-confirm');
  let snapshot = null;

  const node = (tag, className = '', text = null) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== null) element.textContent = String(text);
    return element;
  };
  const clear = (element) => { while (element?.firstChild) element.removeChild(element.firstChild); };
  const requestId = (prefix) => `${prefix}-${globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`}`
    .replace(/[^A-Za-z0-9._:-]/g, '').slice(0, 64);
  const date = (value) => {
    if (!value) return '—';
    const parsed = new Date(`${String(value).replace(' ', 'T')}Z`);
    return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
  };
  const words = (value) => String(value || 'unknown').replaceAll('_', ' ');
  const statusClass = (value) => `status status-${String(value || 'unknown').toLowerCase().replace(/[^a-z0-9_-]/g, '')}`;
  const showNotice = (message, kind = 'info') => {
    clear(notice);
    notice?.appendChild(node('div', `notice ${kind}`, message));
  };
  const post = async (path, payload = {}) => {
    const finalPayload = { ...payload, account_id: accountId, csrf_token: csrfToken };
    const headers = { 'Content-Type': 'application/json', Accept: 'application/json' };
    if (payload.request_id) headers['X-Request-ID'] = String(payload.request_id);
    const response = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers,
      body: JSON.stringify(finalPayload),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body?.error?.message || 'Unable to complete the operations request.');
    return body.data;
  };
  const field = (name, label, type = 'text', value = '') => {
    const wrapper = node('label');
    wrapper.appendChild(node('span', '', label));
    const input = node('input');
    input.name = name;
    input.type = type;
    input.value = value;
    input.required = true;
    if (type === 'email') input.autocomplete = 'email';
    wrapper.appendChild(input);
    return wrapper;
  };
  const textarea = (name, label, maxLength = 500) => {
    const wrapper = node('label');
    wrapper.appendChild(node('span', '', label));
    const input = node('textarea');
    input.name = name;
    input.required = true;
    input.maxLength = maxLength;
    input.rows = 5;
    wrapper.appendChild(input);
    return wrapper;
  };
  const select = (name, label, values, selected = '') => {
    const wrapper = node('label');
    wrapper.appendChild(node('span', '', label));
    const input = node('select');
    input.name = name;
    values.forEach((value) => {
      const option = node('option', '', words(value));
      option.value = value;
      option.selected = value === selected;
      input.appendChild(option);
    });
    wrapper.appendChild(input);
    return wrapper;
  };
  const ask = (title, fields, confirmLabel = 'Confirm') => new Promise((resolve) => {
    clear(dialogBody);
    dialogTitle.textContent = title;
    dialogConfirm.textContent = confirmLabel;
    fields.forEach((item) => dialogBody.appendChild(item));

    const cleanup = () => {
      dialogForm.removeEventListener('submit', submit);
      dialog.removeEventListener('close', closed);
    };
    const submit = (event) => {
      event.preventDefault();
      if (event.submitter?.value !== 'confirm') {
        dialog.close('cancel');
        return;
      }
      const values = Object.fromEntries(new FormData(dialogForm).entries());
      dialog.close('confirm');
      cleanup();
      resolve(values);
    };
    const closed = () => {
      if (dialog.returnValue !== 'confirm') {
        cleanup();
        resolve(null);
      }
    };

    dialogForm.addEventListener('submit', submit);
    dialog.addEventListener('close', closed);
    dialog.showModal();
  });

  const renderMetrics = () => {
    const target = document.getElementById('operations-metrics');
    clear(target);
    const metrics = snapshot.metrics;
    const rows = [
      ['Unhealthy signals', metrics.signals_unhealthy],
      ['Critical signals', metrics.signals_critical],
      ['Open incidents', metrics.incidents_open],
      ['Acknowledged', metrics.incidents_acknowledged],
      ['Resolved', metrics.incidents_resolved],
      ['Failed deliveries', metrics.deliveries_failed],
    ];
    rows.forEach(([label, value]) => {
      const item = node('div', 'metric');
      item.append(node('span', '', label), node('strong', '', value));
      target.appendChild(item);
    });
  };

  const renderHealth = () => {
    const target = document.getElementById('operations-health');
    clear(target);
    if (!snapshot.health_signals.length) {
      target.appendChild(node('div', 'empty', 'No account-scoped health signals have been recorded.'));
      return;
    }
    snapshot.health_signals.forEach((signal) => {
      const row = node('div', 'operations-row');
      const main = node('div', 'operations-row-main');
      main.append(
        node('strong', '', words(signal.source_type)),
        node('p', '', `Reference ${signal.source_reference} · Observed ${date(signal.observed_at)}`),
      );
      const badges = node('div', 'operations-badges');
      badges.append(node('span', statusClass(signal.status), words(signal.status)));
      badges.append(node('span', statusClass(signal.severity), words(signal.severity)));
      row.append(main, badges);
      target.appendChild(row);
    });
  };

  const actOnIncident = async (incident, action) => {
    let resolutionSummary = '';
    if (action === 'resolve_incident') {
      const values = await ask(
        'Resolve Incident',
        [textarea('resolution_summary', 'Resolution summary')],
        'Resolve Incident',
      );
      if (!values) return;
      resolutionSummary = String(values.resolution_summary || '');
    } else {
      const values = await ask(
        'Acknowledge Incident',
        [node('p', 'operations-confirmation', `Acknowledge “${incident.title}”?`)],
        'Acknowledge',
      );
      if (!values) return;
    }

    try {
      await post('/api/control-center/v1/operations-action.php', {
        action,
        incident_public_id: incident.public_id,
        resolution_summary: resolutionSummary,
        request_id: requestId(action === 'resolve_incident' ? 'REQ-OPS-RESOLVE' : 'REQ-OPS-ACK'),
      });
      await load();
      showNotice(action === 'resolve_incident' ? 'Incident resolved.' : 'Incident acknowledged.', 'success');
    } catch (error) {
      showNotice(error.message, 'error');
    }
  };

  const renderIncidents = () => {
    const target = document.getElementById('operations-incidents');
    clear(target);
    if (!snapshot.incidents.length) {
      target.appendChild(node('div', 'empty', 'No operational incidents were found for this account.'));
      return;
    }
    snapshot.incidents.forEach((incident) => {
      const row = node('div', 'operations-row incident-row');
      const main = node('div', 'operations-row-main');
      const title = node('div', 'operations-title-line');
      title.append(node('strong', '', incident.title));
      title.append(node('span', statusClass(incident.severity), words(incident.severity)));
      title.append(node('span', statusClass(incident.status), words(incident.status)));
      main.append(
        title,
        node('p', '', `${words(incident.source_type)} · ${incident.public_id} · ${incident.occurrence_count} occurrence${incident.occurrence_count === 1 ? '' : 's'}`),
        node('small', '', `First ${date(incident.first_detected_at)} · Last ${date(incident.last_detected_at)}`),
      );
      const actions = node('div', 'operations-actions');
      if (incident.status === 'open' && snapshot.permissions.can_acknowledge) {
        const acknowledge = node('button', 'button small', 'Acknowledge');
        acknowledge.type = 'button';
        acknowledge.addEventListener('click', () => actOnIncident(incident, 'acknowledge_incident'));
        actions.appendChild(acknowledge);
      }
      if (incident.status !== 'resolved' && snapshot.permissions.can_resolve) {
        const resolve = node('button', 'button primary small', 'Resolve');
        resolve.type = 'button';
        resolve.addEventListener('click', () => actOnIncident(incident, 'resolve_incident'));
        actions.appendChild(resolve);
      }
      row.append(main, actions);
      target.appendChild(row);
    });
  };

  const renderEvents = () => {
    const target = document.getElementById('operations-events');
    clear(target);
    if (!snapshot.incident_events.length) {
      target.appendChild(node('div', 'empty', 'No incident timeline events were found.'));
      return;
    }
    snapshot.incident_events.forEach((event) => {
      const row = node('div', 'operations-row compact');
      const main = node('div', 'operations-row-main');
      main.append(
        node('strong', '', `${words(event.event_type)} · ${words(event.status)}`),
        node('p', '', `${event.incident_public_id} · ${words(event.actor_type)} · ${date(event.occurred_at)}`),
      );
      row.append(main, node('span', statusClass(event.severity), words(event.severity)));
      target.appendChild(row);
    });
  };

  const setChannelStatus = async (channel, status) => {
    const values = await ask(
      `${words(status)} Notification Channel`,
      [node('p', 'operations-confirmation', `${words(status)} “${channel.label}”? The encrypted destination will not be displayed.`)],
      words(status),
    );
    if (!values) return;
    try {
      await post('/api/control-center/v1/operations-action.php', {
        action: 'set_notification_channel_status',
        channel_public_id: channel.public_id,
        status,
        request_id: requestId('REQ-OPS-CHANNEL'),
      });
      await load();
      showNotice(`Notification channel ${words(status)}.`, 'success');
    } catch (error) {
      showNotice(error.message, 'error');
    }
  };

  const renderChannels = () => {
    const target = document.getElementById('operations-channels');
    clear(target);
    if (!snapshot.notification_channels.length) {
      target.appendChild(node('div', 'empty', 'No notification channels are configured.'));
      return;
    }
    snapshot.notification_channels.forEach((channel) => {
      const row = node('div', 'operations-row');
      const main = node('div', 'operations-row-main');
      main.append(
        node('strong', '', channel.label),
        node('p', '', `${words(channel.type)} · ${words(channel.severity_threshold)} and above · Updated ${date(channel.updated_at)}`),
      );
      const actions = node('div', 'operations-actions');
      actions.appendChild(node('span', statusClass(channel.status), words(channel.status)));
      if (snapshot.permissions.can_manage_channels) {
        if (channel.status === 'active') {
          const pause = node('button', 'button small', 'Pause');
          pause.type = 'button';
          pause.addEventListener('click', () => setChannelStatus(channel, 'paused'));
          actions.appendChild(pause);
        } else if (channel.status === 'paused') {
          const activate = node('button', 'button small', 'Activate');
          activate.type = 'button';
          activate.addEventListener('click', () => setChannelStatus(channel, 'active'));
          actions.appendChild(activate);
        }
        if (channel.status !== 'revoked') {
          const revoke = node('button', 'button danger small', 'Revoke');
          revoke.type = 'button';
          revoke.addEventListener('click', () => setChannelStatus(channel, 'revoked'));
          actions.appendChild(revoke);
        }
      }
      row.append(main, actions);
      target.appendChild(row);
    });
  };

  const renderDeliveries = () => {
    const target = document.getElementById('operations-deliveries');
    clear(target);
    if (!snapshot.deliveries.length) {
      target.appendChild(node('div', 'empty', 'No notification delivery records were found.'));
      return;
    }
    snapshot.deliveries.forEach((delivery) => {
      const row = node('div', 'operations-row compact');
      const main = node('div', 'operations-row-main');
      main.append(
        node('strong', '', `${delivery.channel_label} · ${words(delivery.event_type)}`),
        node('p', '', `${delivery.incident_public_id} · Attempt ${delivery.attempts}/${delivery.max_attempts} · ${date(delivery.delivered_at || delivery.updated_at)}`),
      );
      row.append(main, node('span', statusClass(delivery.status), words(delivery.status)));
      target.appendChild(row);
    });
  };

  const addChannel = async () => {
    const values = await ask(
      'Add Email Notification Channel',
      [
        field('label', 'Channel label'),
        field('email', 'Notification email', 'email'),
        select('severity_threshold', 'Minimum severity', ['info', 'warning', 'critical'], 'warning'),
      ],
      'Save Channel',
    );
    if (!values) return;
    try {
      await post('/api/control-center/v1/operations-action.php', {
        action: 'save_notification_channel',
        label: values.label,
        email: values.email,
        severity_threshold: values.severity_threshold,
        request_id: requestId('REQ-OPS-CHANNEL-SAVE'),
      });
      await load();
      showNotice('Encrypted notification channel saved.', 'success');
    } catch (error) {
      showNotice(error.message, 'error');
    }
  };

  const render = () => {
    renderMetrics();
    renderHealth();
    renderIncidents();
    renderEvents();
    renderChannels();
    renderDeliveries();
    document.getElementById('add-notification-channel').hidden = !snapshot.permissions.can_manage_channels;
  };

  const load = async () => {
    try {
      snapshot = await post('/api/control-center/v1/operations-overview.php');
      render();
    } catch (error) {
      showNotice(error.message, 'error');
    }
  };

  document.getElementById('refresh-operations')?.addEventListener('click', load);
  document.getElementById('add-notification-channel')?.addEventListener('click', addChannel);
  load();
})();
