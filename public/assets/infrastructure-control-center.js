(() => {
  'use strict';

  const root = document.querySelector('[data-control-center][data-page="infrastructure"]');
  if (!root) return;

  const accountPublicId = String(root.dataset.accountPublicId || '');
  const csrfToken = root.dataset.csrfToken || '';
  const notice = document.getElementById('infrastructure-notice');
  const metrics = document.getElementById('infrastructure-metrics');
  const connections = document.getElementById('infrastructure-connections');
  const bindings = document.getElementById('infrastructure-bindings');
  const operations = document.getElementById('infrastructure-operations');
  const attention = document.getElementById('infrastructure-attention');
  const connectionForm = document.getElementById('infrastructure-connection-form');
  const provisionForm = document.getElementById('infrastructure-provision-form');
  const confirmDialog = document.getElementById('infrastructure-confirm-dialog');
  const confirmForm = document.getElementById('infrastructure-confirm-form');
  const confirmValue = document.getElementById('infrastructure-confirm-value');
  let pendingTeardown = null;

  const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
  }[character]));

  const requestId = () => `REQ-P20-${crypto.randomUUID().replaceAll('-', '').toUpperCase()}`;
  const idempotencyKey = (scope) => `IDEM-P20-${scope}-${crypto.randomUUID().replaceAll('-', '').toUpperCase()}`;

  const showNotice = (message, kind = 'success') => {
    notice.className = `notice ${kind}`;
    notice.textContent = message;
  };

  const clearNotice = () => {
    notice.className = '';
    notice.textContent = '';
  };

  const post = async (path, payload) => {
    const response = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
        'X-Request-ID': payload.request_id || requestId(),
        ...(payload.idempotency_key ? { 'Idempotency-Key': payload.idempotency_key } : {})
      },
      body: JSON.stringify({ account_public_id: accountPublicId, csrf_token: csrfToken, ...payload })
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body?.error?.message || 'The infrastructure request failed.');
    }
    return body.data;
  };

  const badge = (status) => `<span class="status-badge status-${escapeHtml(status)}">${escapeHtml(status || 'unknown')}</span>`;
  const date = (value) => value ? new Date(`${String(value).replace(' ', 'T')}Z`).toLocaleString() : '—';

  const renderMetrics = (data) => {
    const items = [
      ['Active connections', data.connections_active],
      ['PODs', data.pods_total],
      ['Active bindings', data.bindings_active],
      ['Open operations', data.operations_open],
      ['Failed operations', data.operations_failed]
    ];
    metrics.innerHTML = items.map(([label, value]) =>
      `<div class="metric"><span>${escapeHtml(label)}</span><strong>${Number(value || 0)}</strong></div>`
    ).join('');
  };

  const renderConnections = (rows) => {
    if (!rows.length) {
      connections.innerHTML = '<div class="empty">No provider connections have been saved.</div>';
      return;
    }
    connections.innerHTML = rows.map((row) => `
      <article class="infrastructure-row">
        <div class="infrastructure-row-main">
          <div class="infrastructure-title-line">
            <strong>${escapeHtml(row.display_name)}</strong>
            ${badge(row.status)}
          </div>
          <span>${escapeHtml(row.provider_type)} · ${escapeHtml(row.provider_code)}</span>
          <small>Credential version ${Number(row.credential_version)} · ${Number(row.active_binding_count)} active binding(s) · Updated ${escapeHtml(date(row.updated_at))}</small>
        </div>
        <div class="infrastructure-row-actions">
          ${row.status === 'active' && Number(row.active_binding_count) === 0
            ? `<button class="button danger compact" type="button" data-action="revoke-connection" data-public-id="${escapeHtml(row.public_id)}">Revoke</button>`
            : ''}
        </div>
      </article>
    `).join('');
  };

  const renderBindings = (rows) => {
    if (!rows.length) {
      bindings.innerHTML = '<div class="empty">No POD infrastructure bindings exist yet.</div>';
      return;
    }
    bindings.innerHTML = rows.map((row) => `
      <article class="infrastructure-card">
        <header>
          <div>
            <div class="infrastructure-title-line"><strong>${escapeHtml(row.hostname)}</strong>${badge(row.status)}</div>
            <span>POD ${escapeHtml(row.pod_public_id)} · Routing ${escapeHtml(row.routing_status)} · SSL ${escapeHtml(row.ssl_status)}</span>
          </div>
          <div class="infrastructure-row-actions">
            ${!['disabled', 'tearing_down'].includes(row.status)
              ? `<button class="button light compact" type="button" data-action="reconcile" data-public-id="${escapeHtml(row.public_id)}">Reconcile</button>` : ''}
            ${row.status !== 'disabled'
              ? `<button class="button danger compact" type="button" data-action="teardown" data-public-id="${escapeHtml(row.public_id)}">Teardown</button>` : ''}
          </div>
        </header>
        <div class="infrastructure-status-grid">
          <div><span>Hosting</span><strong>${escapeHtml(row.hosting_connection.display_name)}</strong>${badge(row.hosting_status || 'pending')}</div>
          <div><span>DNS</span><strong>${escapeHtml(row.dns_connection.display_name)}</strong>${badge(row.dns_status || 'pending')}</div>
          <div><span>Certificate</span><strong>${escapeHtml(row.certificate_connection.display_name)}</strong>${badge(row.certificate_status || 'pending')}</div>
        </div>
        <footer>
          <small>Certificate expires ${escapeHtml(date(row.certificate_expires_at))}</small>
          <small>Updated ${escapeHtml(date(row.updated_at))}</small>
        </footer>
      </article>
    `).join('');
  };

  const renderOperations = (rows) => {
    if (!rows.length) {
      operations.innerHTML = '<div class="empty">No infrastructure operations have been queued.</div>';
      return;
    }
    operations.innerHTML = rows.map((row) => `
      <article class="infrastructure-card operation-card">
        <header>
          <div>
            <div class="infrastructure-title-line"><strong>${escapeHtml(row.operation_type)} · ${escapeHtml(row.hostname)}</strong>${badge(row.status)}</div>
            <span>${escapeHtml(row.public_id)} · Stage ${escapeHtml(row.current_stage || 'queued')}</span>
          </div>
          <div class="infrastructure-row-actions">
            ${['queued', 'running', 'hosting', 'dns', 'certificate', 'verifying'].includes(row.status)
              ? `<button class="button light compact" type="button" data-action="pause-operation" data-public-id="${escapeHtml(row.public_id)}">Pause</button>` : ''}
            ${['paused', 'failed'].includes(row.status)
              ? `<button class="button primary compact" type="button" data-action="resume-operation" data-public-id="${escapeHtml(row.public_id)}">Resume</button>` : ''}
          </div>
        </header>
        <div class="infrastructure-steps">
          ${row.steps.map((step) => `
            <div class="infrastructure-step ${escapeHtml(step.status)}">
              <span>${Number(step.sequence_no)}</span>
              <strong>${escapeHtml(step.stage.replaceAll('_', ' '))}</strong>
              ${badge(step.status)}
            </div>
          `).join('')}
        </div>
        <footer>
          <small>Attempts ${Number(row.attempts)} / ${Number(row.max_attempts)}</small>
          <small>Updated ${escapeHtml(date(row.updated_at))}</small>
        </footer>
      </article>
    `).join('');
  };

  const renderAttention = (rows) => {
    if (!rows.length) {
      attention.innerHTML = '<div class="empty">No infrastructure items require attention.</div>';
      return;
    }
    attention.innerHTML = rows.map((row) => `
      <article class="attention-item severity-${escapeHtml(row.severity)}">
        <strong>${escapeHtml(row.title)}</strong>
        <small>${escapeHtml(row.kind)} · ${escapeHtml(row.resource_public_id)}</small>
      </article>
    `).join('');
  };

  const option = (value, label) => `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`;

  const fillSelects = (data) => {
    const podSelect = document.getElementById('infrastructure-pod');
    const hostingSelect = document.getElementById('infrastructure-hosting');
    const dnsSelect = document.getElementById('infrastructure-dns');
    const certificateSelect = document.getElementById('infrastructure-certificate');

    const availablePods = data.pods.filter((pod) => !pod.binding_public_id);
    podSelect.innerHTML = '<option value="">Select a POD</option>' + availablePods.map((pod) =>
      option(pod.public_id, `${pod.hostname} · ${pod.status}`)
    ).join('');

    const active = (type) => data.connections.filter((row) => row.status === 'active' && row.provider_type === type);
    hostingSelect.innerHTML = '<option value="">Select hosting</option>' + active('hosting').map((row) => option(row.public_id, row.display_name)).join('');
    dnsSelect.innerHTML = '<option value="">Select DNS</option>' + active('dns').map((row) => option(row.public_id, row.display_name)).join('');
    certificateSelect.innerHTML = '<option value="">Select certificate</option>' + active('certificate').map((row) => option(row.public_id, row.display_name)).join('');
  };

  const render = (data) => {
    renderMetrics(data.metrics);
    renderConnections(data.connections);
    renderBindings(data.bindings);
    renderOperations(data.operations);
    renderAttention(data.attention);
    fillSelects(data);
  };

  const load = async (announce = false) => {
    if (announce) clearNotice();
    try {
      const data = await post('/api/control-center/v1/infrastructure-overview.php', { request_id: requestId() });
      render(data);
      if (announce) showNotice('Infrastructure status refreshed.');
    } catch (error) {
      showNotice(error.message, 'error');
    }
  };

  const mutate = async (payload, successMessage) => {
    clearNotice();
    try {
      await post('/api/control-center/v1/infrastructure-action.php', payload);
      showNotice(successMessage);
      await load(false);
    } catch (error) {
      showNotice(error.message, 'error');
    }
  };

  connectionForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    let authContext;
    try {
      authContext = JSON.parse(document.getElementById('infrastructure-provider-auth').value);
    } catch {
      showNotice('Authentication JSON must be valid.', 'error');
      return;
    }
    if (!authContext || Array.isArray(authContext) || typeof authContext !== 'object') {
      showNotice('Authentication JSON must be an object.', 'error');
      return;
    }
    await mutate({
      action: 'save_connection',
      provider_type: document.getElementById('infrastructure-provider-type').value,
      provider_code: document.getElementById('infrastructure-provider-code').value.trim().toLowerCase(),
      display_name: document.getElementById('infrastructure-provider-name').value.trim(),
      auth_context: authContext,
      request_id: requestId()
    }, 'Provider connection encrypted and saved.');
    document.getElementById('infrastructure-provider-auth').value = '';
  });

  provisionForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    await mutate({
      action: 'provision',
      pod_public_id: document.getElementById('infrastructure-pod').value,
      hosting_connection_public_id: document.getElementById('infrastructure-hosting').value,
      dns_connection_public_id: document.getElementById('infrastructure-dns').value,
      certificate_connection_public_id: document.getElementById('infrastructure-certificate').value,
      request_id: requestId(),
      idempotency_key: idempotencyKey('PROVISION')
    }, 'POD infrastructure provisioning queued.');
  });

  root.addEventListener('click', async (event) => {
    const button = event.target.closest('button[data-action]');
    if (!button) return;
    const action = button.dataset.action;
    const publicId = button.dataset.publicId || '';

    if (action === 'revoke-connection') {
      if (!window.confirm('Revoke this unused provider connection? Its encrypted credential envelope will be replaced.')) return;
      await mutate({
        action: 'revoke_connection',
        connection_public_id: publicId,
        request_id: requestId()
      }, 'Provider connection revoked.');
      return;
    }

    if (action === 'reconcile') {
      await mutate({
        action: 'reconcile',
        binding_public_id: publicId,
        request_id: requestId(),
        idempotency_key: idempotencyKey('RECONCILE')
      }, 'Infrastructure reconciliation queued.');
      return;
    }

    if (action === 'teardown') {
      pendingTeardown = publicId;
      confirmValue.value = '';
      confirmDialog.showModal();
      confirmValue.focus();
      return;
    }

    if (action === 'pause-operation' || action === 'resume-operation') {
      await mutate({
        action,
        operation_public_id: publicId,
        request_id: requestId()
      }, action === 'pause-operation' ? 'Infrastructure operation paused.' : 'Infrastructure operation resumed.');
    }
  });

  confirmForm.addEventListener('submit', async (event) => {
    const submitter = event.submitter;
    if (!submitter || submitter.value !== 'confirm') {
      pendingTeardown = null;
      return;
    }
    event.preventDefault();
    if (confirmValue.value !== 'TEARDOWN') {
      showNotice('Teardown requires the exact confirmation TEARDOWN.', 'error');
      return;
    }
    const bindingPublicId = pendingTeardown;
    pendingTeardown = null;
    confirmDialog.close();
    await mutate({
      action: 'teardown',
      binding_public_id: bindingPublicId,
      confirmation: 'TEARDOWN',
      request_id: requestId(),
      idempotency_key: idempotencyKey('TEARDOWN')
    }, 'Protected infrastructure teardown queued.');
  });

  document.getElementById('infrastructure-refresh').addEventListener('click', () => load(true));
  load(false);
})();
