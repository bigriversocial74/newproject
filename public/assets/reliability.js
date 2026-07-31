(() => {
  'use strict';

  const root = document.querySelector('[data-control-center]');
  if (!root || root.dataset.page !== 'reliability') return;

  const accountPublicId = root.dataset.accountPublicId || '';
  const csrfToken = root.dataset.csrfToken || '';
  const state = { data: null };
  const byId = (id) => document.getElementById(id);
  const notice = byId('reliability-notice');

  const requestId = (prefix) => `${prefix}-${Date.now()}-${crypto.getRandomValues(new Uint32Array(1))[0].toString(16)}`;
  const text = (tag, value, className) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = value == null || value === '' ? '—' : String(value);
    return node;
  };
  const statusNode = (value) => text('span', String(value || 'unknown').replaceAll('_', ' '), `status reliability-status state-${String(value || 'unknown')}`);
  const formatDate = (value) => {
    if (!value) return '—';
    const normalized = String(value).replace(' ', 'T').replace(/\.(\d{3})\d+$/, '.$1');
    const date = new Date(normalized + (normalized.endsWith('Z') ? '' : 'Z'));
    return Number.isNaN(date.valueOf()) ? String(value) : date.toLocaleString();
  };
  const utcValue = (value) => {
    if (!value) return '';
    const normalized = String(value).replace(' ', 'T').replace(/\.\d+$/, '');
    return normalized.slice(0, 16);
  };
  const setNotice = (message, kind = 'info') => {
    notice.replaceChildren();
    if (message) notice.append(text('div', message, `reliability-notice ${kind}`));
  };

  async function post(path, payload, prefix) {
    const id = payload.request_id || requestId(prefix);
    const response = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
        'X-Request-ID': id,
        'X-Requested-With': 'XMLHttpRequest'
      },
      body: JSON.stringify({ ...payload, account_public_id: accountPublicId, csrf_token: csrfToken, request_id: id })
    });
    const documentBody = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(documentBody?.error?.message || 'The reliability request failed.');
    return documentBody.data;
  }

  async function load() {
    setNotice('Refreshing reliability state…');
    try {
      state.data = await post('/api/control-center/v1/reliability-overview.php', {}, 'reliability-overview');
      render();
      setNotice('');
    } catch (error) {
      setNotice(error.message, 'error');
    }
  }

  function render() {
    renderMetrics();
    renderComponents();
    renderMessages();
    renderWindows();
    renderEvents();
    populateSelects();
    populateSettings();
  }

  function renderMetrics() {
    const metrics = byId('reliability-metrics');
    metrics.replaceChildren();
    const values = [
      ['Overall status', String(state.data?.overall_status || 'unknown').replaceAll('_', ' ')],
      ['Components', state.data?.metrics?.components ?? 0],
      ['Degraded', state.data?.metrics?.degraded ?? 0],
      ['Major outages', state.data?.metrics?.major_outage ?? 0],
      ['Open incidents', state.data?.metrics?.open_incidents ?? 0],
      ['Budget alerts', (state.data?.metrics?.budget_warning ?? 0) + (state.data?.metrics?.budget_exhausted ?? 0)]
    ];
    values.forEach(([label, value]) => {
      const card = document.createElement('div');
      card.className = 'metric';
      card.append(text('span', label), text('strong', value));
      metrics.append(card);
    });
  }

  function renderComponents() {
    const container = byId('reliability-components');
    container.replaceChildren();
    const components = state.data?.components || [];
    byId('reliability-component-count').textContent = `${components.length} components`;
    if (!components.length) {
      container.append(text('div', 'Add the first reliability component to begin.', 'empty'));
      return;
    }
    components.forEach((component) => {
      const card = document.createElement('article');
      card.className = 'reliability-card';
      const header = document.createElement('header');
      const identity = document.createElement('div');
      identity.append(text('span', `${component.component_type} · ${component.visibility}`, 'eyebrow'), text('h4', component.display_name));
      header.append(identity, statusNode(component.current_status));
      card.append(header);

      const details = document.createElement('dl');
      const availability = Number(component.budget?.availability_bps ?? 10000) / 100;
      const target = Number(component.objective?.availability_target_bps ?? 9990) / 100;
      [
        ['Availability', `${availability.toFixed(2)}% / ${target.toFixed(2)}% target`],
        ['Burn rate', Number(component.budget?.burn_rate ?? 0).toFixed(2)],
        ['Budget', component.budget?.budget_status || 'healthy'],
        ['Latest probe', component.latest_result ? `${component.latest_result.result_status} · ${formatDate(component.latest_result.observed_at)}` : 'No observations'],
        ['Release', component.release ? `${component.release.version} · ${component.release.commit_sha.slice(0, 12)}` : 'Not linked'],
        ['Incident', component.incident?.active ? `${component.incident.severity} · ${component.incident.status}` : 'None']
      ].forEach(([key, value]) => details.append(text('dt', key), text('dd', value)));
      card.append(details);

      if (component.deployment_correlation) {
        const correlation = component.deployment_correlation;
        const before = correlation.before_failure_rate == null ? '—' : `${correlation.before_failure_rate}%`;
        const after = correlation.after_failure_rate == null ? '—' : `${correlation.after_failure_rate}%`;
        card.append(text('p', `Release ${correlation.release_version}: failures ${before} before → ${after} after`, 'reliability-correlation'));
      }

      const probeList = document.createElement('div');
      probeList.className = 'probe-chip-list';
      (component.probes || []).forEach((probe) => {
        const chip = text('span', `${probe.probe_type} · ${probe.interval_seconds}s`, 'probe-chip');
        chip.dataset.probePublicId = probe.public_id;
        probeList.append(chip);
      });
      if (probeList.childNodes.length) card.append(probeList);

      const actions = document.createElement('footer');
      actions.className = 'reliability-actions';
      const edit = text('button', 'Edit component', 'button small');
      edit.type = 'button';
      edit.dataset.action = 'edit-component';
      edit.dataset.publicId = component.public_id;
      const objective = text('button', 'Edit objective', 'button small');
      objective.type = 'button';
      objective.dataset.action = 'edit-objective';
      objective.dataset.publicId = component.public_id;
      actions.append(edit, objective);
      card.append(actions);
      container.append(card);
    });
  }

  function renderMessages() {
    const container = byId('reliability-messages');
    container.replaceChildren();
    const messages = state.data?.status_messages || [];
    if (!messages.length) {
      container.append(text('div', 'No status communication has been published.', 'empty'));
      return;
    }
    messages.forEach((message) => {
      const card = document.createElement('article');
      card.className = 'reliability-card compact';
      const header = document.createElement('header');
      const identity = document.createElement('div');
      identity.append(text('span', message.component_name || 'All components', 'eyebrow'), text('h4', message.title));
      header.append(identity, statusNode(message.message_status));
      card.append(header, text('p', message.message), text('small', `${formatDate(message.starts_at)}${message.ends_at ? ` – ${formatDate(message.ends_at)}` : ''}`));
      if (!['resolved', 'cancelled'].includes(message.message_status)) {
        const actions = document.createElement('footer');
        actions.className = 'reliability-actions';
        const resolve = text('button', 'Resolve message', 'button small');
        resolve.type = 'button';
        resolve.dataset.action = 'resolve-message';
        resolve.dataset.publicId = message.public_id;
        actions.append(resolve);
        card.append(actions);
      }
      container.append(card);
    });
  }

  function renderWindows() {
    const container = byId('reliability-windows');
    container.replaceChildren();
    const windows = state.data?.maintenance_windows || [];
    if (!windows.length) {
      container.append(text('div', 'No recent Phase 34 maintenance windows.', 'empty'));
      return;
    }
    windows.forEach((window) => {
      const card = document.createElement('article');
      card.className = 'reliability-card compact maintenance-card';
      const header = document.createElement('header');
      const identity = document.createElement('div');
      identity.append(text('span', window.environment_name, 'eyebrow'), text('h4', window.reason));
      header.append(identity, statusNode(window.window_status));
      card.append(header, text('small', `${formatDate(window.starts_at)} – ${formatDate(window.ends_at)}`));
      container.append(card);
    });
  }

  function renderEvents() {
    const container = byId('reliability-events');
    container.replaceChildren();
    const events = state.data?.status_events || [];
    if (!events.length) {
      container.append(text('div', 'No component transitions have been recorded.', 'empty'));
      return;
    }
    events.forEach((event) => {
      const row = document.createElement('article');
      row.className = 'reliability-event';
      row.append(statusNode(event.current_status));
      const body = document.createElement('div');
      body.append(
        text('strong', event.display_name),
        text('p', `${String(event.previous_status).replaceAll('_', ' ')} → ${String(event.current_status).replaceAll('_', ' ')}`),
        text('small', `${String(event.reason_code).replaceAll('_', ' ')} · ${formatDate(event.occurred_at)}`)
      );
      row.append(body);
      container.append(row);
    });
  }

  function fillSelect(select, rows, includeBlank, labeler) {
    select.replaceChildren();
    if (includeBlank) {
      const blank = document.createElement('option');
      blank.value = '';
      blank.textContent = includeBlank;
      select.append(blank);
    }
    rows.forEach((row) => {
      const option = document.createElement('option');
      option.value = row.public_id;
      option.textContent = labeler(row);
      select.append(option);
    });
  }

  function populateSelects() {
    const components = state.data?.components || [];
    fillSelect(byId('reliability-objective-component'), components, '', (row) => row.display_name);
    fillSelect(byId('reliability-probe-component'), components, '', (row) => row.display_name);
    fillSelect(byId('reliability-message-component'), components, 'All components', (row) => row.display_name);
    const environments = [];
    const seen = new Set();
    components.forEach((component) => {
      if (component.environment && !seen.has(component.environment.public_id)) {
        seen.add(component.environment.public_id);
        environments.push(component.environment);
      }
    });
    (state.data?.maintenance_windows || []).forEach((window) => {
      if (!seen.has(window.environment_public_id)) {
        seen.add(window.environment_public_id);
        environments.push({
          public_id: window.environment_public_id,
          display_name: window.environment_name,
          environment_key: window.environment_key
        });
      }
    });
    fillSelect(byId('reliability-component-environment'), environments, 'No release environment', (row) => `${row.display_name} · ${row.environment_key}`);
    const manual = [];
    components.forEach((component) => {
      (component.probes || []).filter((probe) => probe.probe_type === 'manual').forEach((probe) => {
        manual.push({ public_id: probe.public_id, label: `${component.display_name} · manual` });
      });
    });
    fillSelect(byId('reliability-manual-probe'), manual, '', (row) => row.label);
  }

  function populateSettings() {
    const form = byId('reliability-status-form');
    const settings = state.data?.status_settings || {};
    form.elements.public_slug.value = settings.public_slug || '';
    form.elements.page_title.value = settings.page_title || '';
    form.elements.page_description.value = settings.page_description || '';
    form.elements.public_enabled.checked = Boolean(settings.public_enabled);
    form.elements.show_history.checked = settings.show_history !== false;
    const link = byId('reliability-public-link');
    if (state.data?.public_status_url) {
      link.href = state.data.public_status_url;
      link.hidden = false;
    } else {
      link.hidden = true;
    }
    const messageForm = byId('reliability-message-form');
    if (!messageForm.elements.starts_at.value) {
      const date = new Date();
      date.setSeconds(0, 0);
      messageForm.elements.starts_at.value = date.toISOString().slice(0, 16);
    }
  }

  async function submit(form, action, prefix, transform) {
    const values = Object.fromEntries(new FormData(form).entries());
    const payload = transform ? transform(values, form) : values;
    setNotice('Saving reliability changes…');
    try {
      await post('/api/control-center/v1/reliability-action.php', { action, ...payload }, prefix);
      form.reset();
      await load();
      setNotice('Reliability changes saved.', 'success');
    } catch (error) {
      setNotice(error.message, 'error');
    }
  }

  byId('reliability-component-form').addEventListener('submit', (event) => {
    event.preventDefault();
    submit(event.currentTarget, 'save_component', 'save-component', (values, form) => ({
      ...values,
      enabled: form.elements.enabled.checked,
      display_order: Number(values.display_order || 100),
      component_public_id: values.component_public_id || null,
      environment_public_id: values.environment_public_id || null
    }));
  });

  byId('reliability-objective-form').addEventListener('submit', (event) => {
    event.preventDefault();
    submit(event.currentTarget, 'save_objective', 'save-objective', (values) => ({
      ...values,
      availability_target_bps: Number(values.availability_target_bps),
      latency_target_ms: values.latency_target_ms === '' ? null : Number(values.latency_target_ms),
      evaluation_window_minutes: Number(values.evaluation_window_minutes),
      warning_burn_rate: Number(values.warning_burn_rate),
      critical_burn_rate: Number(values.critical_burn_rate),
      consecutive_failure_threshold: Number(values.consecutive_failure_threshold),
      recovery_success_threshold: Number(values.recovery_success_threshold)
    }));
  });

  byId('reliability-probe-form').addEventListener('submit', (event) => {
    event.preventDefault();
    submit(event.currentTarget, 'save_probe', 'save-probe', (values, form) => ({
      ...values,
      enabled: form.elements.enabled.checked,
      interval_seconds: Number(values.interval_seconds),
      timeout_ms: Number(values.timeout_ms),
      probe_public_id: values.probe_public_id || null
    }));
  });

  byId('reliability-manual-form').addEventListener('submit', (event) => {
    event.preventDefault();
    submit(event.currentTarget, 'record_manual_observation', 'manual-observation', (values) => ({
      ...values,
      latency_ms: values.latency_ms === '' ? null : Number(values.latency_ms),
      value_numeric: values.value_numeric === '' ? null : Number(values.value_numeric),
      error_code: values.error_code || null
    }));
  });

  byId('reliability-status-form').addEventListener('submit', (event) => {
    event.preventDefault();
    submit(event.currentTarget, 'save_status_settings', 'status-settings', (values, form) => ({
      ...values,
      public_enabled: form.elements.public_enabled.checked,
      show_history: form.elements.show_history.checked
    }));
  });

  byId('reliability-message-form').addEventListener('submit', (event) => {
    event.preventDefault();
    submit(event.currentTarget, 'publish_status_message', 'status-message', (values) => ({
      ...values,
      component_public_id: values.component_public_id || null,
      starts_at: new Date(values.starts_at + ':00Z').toISOString(),
      ends_at: values.ends_at ? new Date(values.ends_at + ':00Z').toISOString() : null
    }));
  });

  byId('reliability-components').addEventListener('click', (event) => {
    const control = event.target.closest('button[data-action]');
    if (!control) return;
    const component = (state.data?.components || []).find((row) => row.public_id === control.dataset.publicId);
    if (!component) return;
    if (control.dataset.action === 'edit-component') {
      const form = byId('reliability-component-form');
      form.elements.component_public_id.value = component.public_id;
      form.elements.component_key.value = component.component_key;
      form.elements.display_name.value = component.display_name;
      form.elements.component_type.value = component.component_type;
      form.elements.visibility.value = component.visibility;
      form.elements.environment_public_id.value = component.environment?.public_id || '';
      form.elements.display_order.value = component.display_order;
      form.elements.enabled.checked = true;
      form.scrollIntoView({ behavior: 'smooth', block: 'center' });
    } else if (control.dataset.action === 'edit-objective') {
      const form = byId('reliability-objective-form');
      const objective = component.objective;
      form.elements.component_public_id.value = component.public_id;
      form.elements.availability_target_bps.value = objective.availability_target_bps;
      form.elements.latency_target_ms.value = objective.latency_target_ms ?? '';
      form.elements.evaluation_window_minutes.value = objective.evaluation_window_minutes;
      form.elements.warning_burn_rate.value = objective.warning_burn_rate;
      form.elements.critical_burn_rate.value = objective.critical_burn_rate;
      form.elements.consecutive_failure_threshold.value = objective.consecutive_failure_threshold;
      form.elements.recovery_success_threshold.value = objective.recovery_success_threshold;
      form.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  });

  byId('reliability-messages').addEventListener('click', async (event) => {
    const control = event.target.closest('button[data-action="resolve-message"]');
    if (!control) return;
    setNotice('Resolving public status message…');
    try {
      await post('/api/control-center/v1/reliability-action.php', {
        action: 'resolve_status_message',
        message_public_id: control.dataset.publicId
      }, 'resolve-message');
      await load();
      setNotice('Status message resolved.', 'success');
    } catch (error) {
      setNotice(error.message, 'error');
    }
  });

  byId('reliability-refresh').addEventListener('click', load);
  load();
})();
