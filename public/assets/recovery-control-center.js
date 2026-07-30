(() => {
  'use strict';

  const root = document.querySelector('[data-control-center][data-page="recovery"]');
  if (!root) return;
  const accountId = Number(root.dataset.accountId || 0);
  const csrfToken = String(root.dataset.csrfToken || '');
  const notice = document.getElementById('recovery-notice');
  const dialog = document.getElementById('recovery-dialog');
  const dialogForm = document.getElementById('recovery-dialog-form');
  const dialogTitle = document.getElementById('recovery-dialog-title');
  const dialogBody = document.getElementById('recovery-dialog-body');
  let snapshot = null;

  const node = (tag, className = '', text = null) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== null) element.textContent = String(text);
    return element;
  };
  const clear = (element) => { while (element?.firstChild) element.removeChild(element.firstChild); };
  const token = (prefix) => `${prefix}-${globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`}`.replace(/[^A-Za-z0-9._:-]/g, '').slice(0, 64);
  const idempotency = (prefix) => `${prefix}-${globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`}`.replace(/[^A-Za-z0-9._:-]/g, '').slice(0, 128);
  const date = (value) => {
    if (!value) return '—';
    const parsed = new Date(`${String(value).replace(' ', 'T')}Z`);
    return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
  };
  const bytes = (value) => {
    let amount = Number(value || 0);
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let index = 0;
    while (amount >= 1024 && index < units.length - 1) { amount /= 1024; index += 1; }
    return `${amount.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
  };
  const label = (value) => String(value || 'unknown').replaceAll('_', ' ');
  const status = (value) => node('span', `status status-${String(value || 'unknown').replace(/[^a-z0-9_-]/gi, '').toLowerCase()}`, label(value));
  const showNotice = (message, kind = 'info') => { clear(notice); notice.appendChild(node('div', `notice ${kind}`, message)); };

  const post = async (path, payload = {}) => {
    const response = await fetch(path, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ ...payload, account_id: accountId, csrf_token: csrfToken }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body?.error?.message || 'Unable to complete the recovery request.');
    return body.data;
  };

  const input = (name, title, type = 'text', value = '') => {
    const wrapper = node('label');
    wrapper.appendChild(node('span', '', title));
    const field = node('input'); field.name = name; field.type = type; field.value = value; field.required = true;
    wrapper.appendChild(field); return wrapper;
  };
  const select = (name, title, options, selected = '') => {
    const wrapper = node('label'); wrapper.appendChild(node('span', '', title));
    const field = node('select'); field.name = name; field.required = true;
    options.forEach(([value, text]) => { const option = node('option', '', text); option.value = value; option.selected = value === selected; field.appendChild(option); });
    wrapper.appendChild(field); return wrapper;
  };
  const ask = (title, fields, confirmLabel = 'Confirm') => new Promise((resolve) => {
    clear(dialogBody); dialogTitle.textContent = title; fields.forEach((field) => dialogBody.appendChild(field));
    document.getElementById('recovery-dialog-confirm').textContent = confirmLabel;
    const cleanup = () => { dialogForm.removeEventListener('submit', submit); dialog.removeEventListener('close', closed); };
    const submit = (event) => {
      event.preventDefault();
      if (event.submitter?.value !== 'confirm') { dialog.close('cancel'); return; }
      const values = Object.fromEntries(new FormData(dialogForm).entries()); dialog.close('confirm'); cleanup(); resolve(values);
    };
    const closed = () => { if (dialog.returnValue !== 'confirm') { cleanup(); resolve(null); } };
    dialogForm.addEventListener('submit', submit); dialog.addEventListener('close', closed); dialog.showModal();
  });

  const action = async (payload, successMessage) => {
    try {
      await post('/api/control-center/v1/recovery-action.php', payload);
      showNotice(successMessage, 'success'); await load();
    } catch (error) { showNotice(error.message, 'error'); }
  };

  const renderMetrics = () => {
    const target = document.getElementById('recovery-metrics'); clear(target);
    const metrics = snapshot.metrics;
    [
      ['PODs', metrics.pods],
      ['Storage', `${bytes(metrics.storage_usage_bytes)} / ${bytes(metrics.storage_allowance_bytes)}`],
      ['Storage used', `${metrics.storage_usage_percent}%`],
      ['Verified snapshots', metrics.verified_snapshots],
      ['Active jobs', metrics.active_jobs],
      ['Available releases', metrics.available_releases],
    ].forEach(([title, value]) => { const item = node('div', 'metric'); item.append(node('span', '', title), node('strong', '', value)); target.appendChild(item); });
  };

  const policyAction = async (pod) => {
    const policy = pod.policy || {};
    const values = await ask('Backup policy', [
      select('interval_minutes', 'Schedule', [['60', 'Hourly'], ['360', 'Every 6 hours'], ['720', 'Every 12 hours'], ['1440', 'Daily'], ['10080', 'Weekly']], String(policy.interval_minutes || 1440)),
      input('retention_count', 'Snapshots to retain', 'number', String(policy.retention_count || 14)),
      input('retention_days', 'Maximum retention days', 'number', String(policy.retention_days || 30)),
    ], 'Save Policy');
    if (!values) return;
    await action({ action: 'save_policy', pod_public_id: pod.public_id, interval_minutes: Number(values.interval_minutes), retention_count: Number(values.retention_count), retention_days: Number(values.retention_days), request_id: token('REQ-P19-POLICY') }, 'Backup policy saved.');
  };

  const updateAction = async (pod) => {
    const releases = snapshot.eligible_releases[pod.public_id] || [];
    if (!releases.length) return showNotice('No eligible signed release is available for this POD.', 'info');
    const values = await ask('Install signed release', [
      select('release_public_id', 'Release', releases.map((release) => [release.public_id, `${release.version} · ${release.channel}${release.emergency ? ' · emergency' : ''}`])),
    ], 'Queue Update');
    if (!values) return;
    await action({ action: 'update', pod_public_id: pod.public_id, release_public_id: values.release_public_id, request_id: token('REQ-P19-UPDATE'), idempotency_key: idempotency('IDEM-P19-UPDATE') }, 'Software update queued.');
  };

  const renderPods = () => {
    const target = document.getElementById('recovery-pods'); clear(target);
    if (!snapshot.pods.length) return target.appendChild(node('div', 'empty', 'No active or degraded POD deployments were found.'));
    snapshot.pods.forEach((pod) => {
      const card = node('article', 'recovery-card');
      const head = node('div', 'recovery-card-head');
      const title = node('div'); title.append(node('strong', '', pod.hostname), node('p', '', `${pod.installed_version || 'version unknown'} · ${label(pod.update_channel)} channel`));
      head.append(title, status(pod.status));
      const storage = node('div', 'recovery-storage');
      const bar = node('div', 'recovery-bar'); const fill = node('span'); fill.style.width = `${Math.min(100, Number(pod.storage_usage_percent || 0))}%`; bar.appendChild(fill);
      storage.append(node('div', 'recovery-storage-copy', `${bytes(pod.storage_usage_bytes)} of ${bytes(pod.storage_allowance_bytes)} · ${pod.storage_usage_percent}%`), bar);
      const policy = node('p', 'recovery-detail', pod.policy ? `Backup ${label(pod.policy.status)} · every ${pod.policy.interval_minutes} minutes · retain ${pod.policy.retention_count} / ${pod.policy.retention_days} days` : 'No backup policy configured.');
      const releases = snapshot.eligible_releases[pod.public_id] || [];
      const releaseText = node('p', 'recovery-detail', releases.length ? `${releases.length} eligible signed release(s).` : 'No newer eligible signed release.');
      const actions = node('div', 'recovery-actions');
      const policyButton = node('button', 'button small', pod.policy ? 'Edit Policy' : 'Create Policy'); policyButton.type = 'button'; policyButton.addEventListener('click', () => policyAction(pod));
      const backupButton = node('button', 'button small', 'Back Up Now'); backupButton.type = 'button'; backupButton.addEventListener('click', () => action({ action: 'backup_now', pod_public_id: pod.public_id, request_id: token('REQ-P19-BACKUP'), idempotency_key: idempotency('IDEM-P19-BACKUP') }, 'On-demand backup queued.'));
      const updateButton = node('button', 'button small primary', 'Install Update'); updateButton.type = 'button'; updateButton.disabled = releases.length === 0; updateButton.addEventListener('click', () => updateAction(pod));
      actions.append(policyButton, backupButton, updateButton);
      card.append(head, storage, policy, releaseText, actions); target.appendChild(card);
    });
  };

  const renderSnapshots = () => {
    const target = document.getElementById('recovery-snapshots'); clear(target);
    if (!snapshot.snapshots.length) return target.appendChild(node('div', 'empty', 'No POD snapshots have been created.'));
    snapshot.snapshots.forEach((item) => {
      const row = node('div', 'list-row');
      const main = node('div'); main.append(node('strong', '', item.hostname), node('p', '', `${bytes(item.size_bytes)} · created ${date(item.created_at)} · verified ${date(item.verified_at)}`));
      const actions = node('div', 'recovery-row-actions'); actions.appendChild(status(item.status));
      if (item.restorable) {
        const restore = node('button', 'button small', 'Restore'); restore.type = 'button'; restore.addEventListener('click', async () => {
          const values = await ask('Restore verified snapshot', [input('confirmation', 'Type RESTORE to continue')], 'Queue Restore');
          if (!values) return;
          await action({ action: 'restore', snapshot_public_id: item.public_id, confirmation: values.confirmation, request_id: token('REQ-P19-RESTORE'), idempotency_key: idempotency('IDEM-P19-RESTORE') }, 'Verified restore queued.');
        }); actions.appendChild(restore);
      }
      row.append(main, actions); target.appendChild(row);
    });
  };

  const renderJobs = () => {
    const target = document.getElementById('recovery-jobs'); clear(target);
    const items = [
      ...snapshot.backup_jobs.map((item) => ({ ...item, kind: 'Backup' })),
      ...snapshot.restore_jobs.map((item) => ({ ...item, kind: 'Restore' })),
    ].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
    if (!items.length) return target.appendChild(node('div', 'empty', 'No backup or restore jobs were found.'));
    items.forEach((item) => {
      const row = node('div', 'list-row'); const main = node('div');
      main.append(node('strong', '', `${item.kind} · ${item.hostname}`), node('p', '', `${label(item.job_type || item.kind)} · ${date(item.created_at)} · attempts ${item.attempts}`));
      row.append(main, status(item.status)); target.appendChild(row);
    });
  };

  const renderUpdates = () => {
    const target = document.getElementById('recovery-updates'); clear(target);
    if (!snapshot.update_jobs.length) return target.appendChild(node('div', 'empty', 'No software update jobs were found.'));
    snapshot.update_jobs.forEach((item) => {
      const card = node('article', 'recovery-update');
      const head = node('div', 'recovery-card-head'); const title = node('div');
      title.append(node('strong', '', `${item.hostname} → ${item.target_version}`), node('p', '', `${item.previous_version || 'unknown'} · ${label(item.channel)} · ${date(item.created_at)}`));
      head.append(title, status(item.status));
      const protection = node('p', 'recovery-detail', item.pre_update_backup_verified ? 'Verified pre-update backup available.' : 'Pre-update backup will be required before installation.');
      const stages = node('div', 'recovery-stages'); item.steps.forEach((step) => stages.appendChild(node('span', `stage stage-${step.status}`, label(step.stage))));
      const actions = node('div', 'recovery-actions');
      if (item.can_pause) { const button = node('button', 'button small', 'Pause'); button.type = 'button'; button.addEventListener('click', () => action({ action: 'pause_update', job_public_id: item.public_id, request_id: token('REQ-P19-PAUSE') }, 'Update paused.')); actions.appendChild(button); }
      if (item.can_resume) { const button = node('button', 'button small primary', 'Resume'); button.type = 'button'; button.addEventListener('click', () => action({ action: 'resume_update', job_public_id: item.public_id, request_id: token('REQ-P19-RESUME') }, 'Update returned to the queue.')); actions.appendChild(button); }
      card.append(head, protection, stages, actions); target.appendChild(card);
    });
  };

  const render = () => { renderMetrics(); renderPods(); renderSnapshots(); renderJobs(); renderUpdates(); };
  const load = async () => {
    try {
      snapshot = await post('/api/control-center/v1/recovery-overview.php'); render();
    } catch (error) { showNotice(error.message, 'error'); }
  };
  document.getElementById('recovery-refresh')?.addEventListener('click', load);
  load();
})();
