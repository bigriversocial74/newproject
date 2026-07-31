(() => {
  'use strict';

  const root = document.querySelector('[data-control-center]');
  if (!root || root.dataset.page !== 'releases') return;

  const accountPublicId = root.dataset.accountPublicId || '';
  const csrfToken = root.dataset.csrfToken || '';
  const state = { data: null, reauth: null };
  const byId = (id) => document.getElementById(id);
  const notice = byId('release-notice');

  const requestId = (prefix) => `${prefix}-${Date.now()}-${crypto.getRandomValues(new Uint32Array(1))[0].toString(16)}`;
  const text = (tag, value, className) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = value == null || value === '' ? '—' : String(value);
    return node;
  };
  const button = (label, action, publicId, className = 'button small') => {
    const node = document.createElement('button');
    node.type = 'button';
    node.className = className;
    node.textContent = label;
    node.dataset.action = action;
    node.dataset.publicId = publicId;
    return node;
  };
  const status = (value) => {
    const node = text('span', String(value || 'unknown').replaceAll('_', ' '), `status release-status status-${String(value || 'unknown')}`);
    return node;
  };
  const formatDate = (value) => {
    if (!value) return '—';
    const normalized = String(value).replace(' ', 'T').replace(/\.(\d{3})\d+$/, '.$1');
    const date = new Date(normalized + (normalized.endsWith('Z') ? '' : 'Z'));
    return Number.isNaN(date.valueOf()) ? String(value) : date.toLocaleString();
  };
  const setNotice = (message, kind = 'info') => {
    notice.replaceChildren();
    if (!message) return;
    notice.append(text('div', message, `release-notice ${kind}`));
  };

  async function post(path, payload, prefix = 'release') {
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
    const document = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(document?.error?.message || 'The release control request failed.');
    return document.data;
  }

  async function load() {
    setNotice('Refreshing release and deployment state…');
    try {
      state.data = await post('/api/control-center/v1/release-deployment-overview.php', {}, 'release-overview');
      render();
      setNotice('');
    } catch (error) {
      setNotice(error.message, 'error');
    }
  }

  function render() {
    renderMetrics();
    renderEnvironments();
    renderCandidates();
    renderWindows();
    renderPromotions();
    renderHealth();
    populateSelects();
  }

  function renderMetrics() {
    const metrics = byId('release-metrics');
    metrics.replaceChildren();
    const values = [
      ['Verified candidates', state.data?.summary?.verified_candidates ?? 0],
      ['Pending approvals', state.data?.summary?.pending_approvals ?? 0],
      ['Queued deployments', state.data?.summary?.queued_deployments ?? 0],
      ['Failed deployments', state.data?.summary?.failed_deployments ?? 0]
    ];
    values.forEach(([label, value]) => {
      const card = document.createElement('div');
      card.className = 'metric';
      card.append(text('span', label), text('strong', value));
      metrics.append(card);
    });
  }

  function renderEnvironments() {
    const container = byId('release-environments');
    container.replaceChildren();
    const environments = state.data?.environments || [];
    if (!environments.length) {
      container.append(text('div', 'Register staging and production environments to begin.', 'empty'));
      return;
    }
    environments.forEach((environment) => {
      const card = document.createElement('article');
      card.className = 'release-card';
      const head = document.createElement('header');
      const title = document.createElement('div');
      title.append(text('span', environment.environment_key, 'eyebrow'), text('h4', environment.display_name));
      head.append(title, status(environment.readiness_status));
      const details = document.createElement('dl');
      [
        ['URL', environment.base_url],
        ['Current release', environment.current_release_version || 'Not recorded'],
        ['Commit', environment.current_commit_sha ? environment.current_commit_sha.slice(0, 12) : '—'],
        ['Worker seen', formatDate(environment.worker_last_seen_at)],
        ['Health checked', formatDate(environment.last_health_at)],
        ['Config fingerprint', environment.config_fingerprint ? environment.config_fingerprint.slice(0, 16) + '…' : 'Not set']
      ].forEach(([key, value]) => {
        details.append(text('dt', key), text('dd', value));
      });
      card.append(head, details);
      container.append(card);
    });
  }

  function renderCandidates() {
    const container = byId('release-candidates');
    container.replaceChildren();
    const candidates = state.data?.candidates || [];
    byId('release-candidate-count').textContent = `${candidates.length} candidates`;
    if (!candidates.length) {
      container.append(text('div', 'No signed release candidate has been registered on this host.', 'empty'));
      return;
    }
    candidates.forEach((candidate) => {
      const card = document.createElement('article');
      card.className = 'release-card compact';
      const head = document.createElement('header');
      const identity = document.createElement('div');
      identity.append(text('span', `Schema ${candidate.schema_level}`, 'eyebrow'), text('h4', candidate.release_version));
      head.append(identity, status(candidate.candidate_status));
      card.append(head);
      card.append(text('p', `Commit ${candidate.commit_sha.slice(0, 12)} · ${candidate.migration_count} migrations · ${candidate.source_file_count} source files`));
      const hashes = text('code', `Manifest ${candidate.manifest_sha256.slice(0, 14)}… · Source ${candidate.source_tree_sha256.slice(0, 14)}… · Installer ${candidate.installer_sha256.slice(0, 14)}…`, 'release-hash');
      card.append(hashes, text('small', `Verified ${formatDate(candidate.verified_at)} with ${candidate.signing_key_id}`));
      const staging = (state.data?.environments || []).find((item) => item.environment_key === 'staging');
      if (staging) {
        const actions = document.createElement('footer');
        actions.className = 'release-actions';
        actions.append(button('Deploy to Staging', 'deploy-staging', candidate.public_id, 'button primary small'));
        card.append(actions);
      }
      container.append(card);
    });
  }

  function renderWindows() {
    const container = byId('release-windows');
    container.replaceChildren();
    const windows = state.data?.maintenance_windows || [];
    byId('release-window-count').textContent = `${windows.length} windows`;
    if (!windows.length) {
      container.append(text('div', 'No current maintenance windows.', 'empty'));
      return;
    }
    windows.forEach((window) => {
      const card = document.createElement('article');
      card.className = 'release-card compact';
      const head = document.createElement('header');
      const identity = document.createElement('div');
      identity.append(text('span', window.environment_key, 'eyebrow'), text('h4', `${formatDate(window.starts_at)} – ${formatDate(window.ends_at)}`));
      head.append(identity, status(window.window_status));
      card.append(head, text('p', window.reason));
      const footer = document.createElement('footer');
      footer.append(text('small', window.approved_by_user_public_id ? 'Owner approved' : 'Owner approval required'));
      if (!window.approved_by_user_public_id && state.data?.operator?.role === 'customer_owner') {
        footer.append(button('Approve Window', 'approve-window', window.public_id));
      }
      card.append(footer);
      container.append(card);
    });
  }

  function renderPromotions() {
    const container = byId('release-promotions');
    container.replaceChildren();
    const promotions = state.data?.promotions || [];
    byId('release-promotion-count').textContent = `${promotions.length} promotions`;
    if (!promotions.length) {
      container.append(text('div', 'No release promotions have been requested.', 'empty'));
      return;
    }
    promotions.forEach((promotion) => {
      const card = document.createElement('article');
      card.className = 'release-promotion';
      const head = document.createElement('header');
      const identity = document.createElement('div');
      identity.append(
        text('span', `${promotion.source_environment_key} → ${promotion.target_environment_key}`, 'eyebrow'),
        text('h4', `${promotion.release_version} · ${promotion.commit_sha.slice(0, 12)}`)
      );
      head.append(identity, status(promotion.promotion_status));
      card.append(head);

      const facts = document.createElement('div');
      facts.className = 'release-facts';
      [
        ['Requested', formatDate(promotion.requested_at)],
        ['Scheduled', formatDate(promotion.scheduled_for)],
        ['Run', promotion.deployment_run_public_id || 'Not started'],
        ['Backup', promotion.backup_public_id || 'Pending'],
        ['Event chain', promotion.event_chain_valid ? 'Valid' : 'Invalid'],
        ['Evidence', promotion.evidence_hash ? promotion.evidence_hash.slice(0, 16) + '…' : 'Pending']
      ].forEach(([key, value]) => {
        const item = document.createElement('div');
        item.append(text('span', key), text('strong', value));
        facts.append(item);
      });
      card.append(facts);

      if (promotion.failure_code || promotion.deployment_error_code) {
        card.append(text('p', `Failure: ${promotion.failure_code || promotion.deployment_error_code}`, 'release-error'));
      }
      if (promotion.steps?.length) {
        const details = document.createElement('details');
        details.append(text('summary', `Deployment steps (${promotion.steps.length})`));
        const list = document.createElement('div');
        list.className = 'release-step-list';
        promotion.steps.forEach((step) => {
          const row = document.createElement('div');
          row.append(text('span', `${step.step_order}. ${step.step_key}`), status(step.step_status));
          list.append(row);
        });
        details.append(list);
        card.append(details);
      }

      const actions = document.createElement('footer');
      actions.className = 'release-actions';
      if (promotion.promotion_status === 'requested' && state.data?.operator?.role === 'customer_owner') {
        actions.append(button('Approve Promotion', 'approve-promotion', promotion.public_id, 'button primary small'));
      }
      if (['requested', 'approved', 'scheduled', 'queued'].includes(promotion.promotion_status)) {
        actions.append(button('Cancel', 'cancel-promotion', promotion.public_id));
      }
      if (['completed', 'failed'].includes(promotion.promotion_status)
          && promotion.deployment_run_public_id
          && promotion.backup_public_id
          && state.data?.operator?.role === 'customer_owner') {
        actions.append(button('Rollback', 'rollback', promotion.public_id, 'button danger small'));
      }
      card.append(actions);
      container.append(card);
    });
  }

  function renderHealth() {
    const container = byId('release-health');
    container.replaceChildren();
    const health = state.data?.health || [];
    if (!health.length) {
      container.append(text('div', 'No environment health snapshot has been captured.', 'empty'));
      return;
    }
    health.forEach((snapshot) => {
      const card = document.createElement('article');
      card.className = 'release-card compact';
      const head = document.createElement('header');
      const identity = document.createElement('div');
      identity.append(text('span', snapshot.environment_key, 'eyebrow'), text('h4', snapshot.release_version || 'Unassigned release'));
      head.append(identity, status(snapshot.health_status));
      card.append(head, text('small', `Captured ${formatDate(snapshot.captured_at)} by ${snapshot.captured_by}`));
      const checks = document.createElement('dl');
      Object.entries(snapshot.checks || {}).forEach(([key, value]) => checks.append(text('dt', key.replaceAll('_', ' ')), text('dd', value)));
      card.append(checks);
      container.append(card);
    });
  }

  function fillSelect(select, rows, label, selectedValue = '') {
    select.replaceChildren();
    if (!rows.length) {
      const option = document.createElement('option');
      option.value = '';
      option.textContent = 'None available';
      select.append(option);
      return;
    }
    rows.forEach((row) => {
      const option = document.createElement('option');
      option.value = row.public_id;
      option.textContent = label(row);
      if (row.public_id === selectedValue) option.selected = true;
      select.append(option);
    });
  }

  function populateSelects() {
    const environments = state.data?.environments || [];
    const candidates = (state.data?.candidates || []).filter((candidate) => ['verified', 'approved', 'promoted'].includes(candidate.candidate_status));
    const windows = (state.data?.maintenance_windows || []).filter((window) => ['scheduled', 'open'].includes(window.window_status));
    fillSelect(byId('release-window-environment'), environments.filter((item) => item.environment_key === 'production'), (item) => item.display_name);
    fillSelect(byId('release-promotion-candidate'), candidates, (item) => `${item.release_version} · ${item.commit_sha.slice(0, 10)}`);
    fillSelect(byId('release-promotion-source'), environments.filter((item) => item.environment_key === 'staging'), (item) => item.display_name);
    fillSelect(byId('release-promotion-target'), environments.filter((item) => item.environment_key === 'production'), (item) => item.display_name);
    fillSelect(byId('release-promotion-window'), windows.filter((item) => item.environment_key === 'production' && item.approved_by_user_public_id), (item) => `${formatDate(item.starts_at)} – ${formatDate(item.ends_at)}`);
  }

  async function mutate(action, payload, prefix) {
    setNotice('Applying release control action…');
    try {
      await post('/api/control-center/v1/release-deployment-action.php', { action, ...payload }, prefix);
      await load();
      setNotice('Release control action completed.', 'success');
    } catch (error) {
      setNotice(error.message, 'error');
    }
  }

  function utcValue(value) {
    if (!value) return '';
    const date = new Date(value);
    if (Number.isNaN(date.valueOf())) throw new Error('Enter a valid date and time.');
    return date.toISOString();
  }

  byId('release-refresh').addEventListener('click', load);
  byId('release-environment-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(event.currentTarget));
    mutate('save_environment', data, 'save-environment');
  });
  byId('release-window-form').addEventListener('submit', (event) => {
    event.preventDefault();
    try {
      const data = Object.fromEntries(new FormData(event.currentTarget));
      data.starts_at = utcValue(data.starts_at);
      data.ends_at = utcValue(data.ends_at);
      mutate('schedule_maintenance', data, 'schedule-maintenance');
    } catch (error) {
      setNotice(error.message, 'error');
    }
  });
  byId('release-promotion-form').addEventListener('submit', (event) => {
    event.preventDefault();
    try {
      const data = Object.fromEntries(new FormData(event.currentTarget));
      data.scheduled_for = data.scheduled_for ? utcValue(data.scheduled_for) : null;
      mutate('request_promotion', data, 'request-promotion');
    } catch (error) {
      setNotice(error.message, 'error');
    }
  });

  root.addEventListener('click', async (event) => {
    const target = event.target.closest('button[data-action]');
    if (!target) return;
    const publicId = target.dataset.publicId || '';
    if (target.dataset.action === 'deploy-staging') {
      const staging = (state.data?.environments || []).find((item) => item.environment_key === 'staging');
      if (!staging) {
        setNotice('Register the staging environment first.', 'error');
        return;
      }
      mutate('request_staging_deployment', {
        candidate_public_id: publicId,
        staging_environment_public_id: staging.public_id
      }, 'deploy-staging');
    } else if (target.dataset.action === 'approve-window') {
      mutate('approve_maintenance', { maintenance_window_public_id: publicId }, 'approve-maintenance');
    } else if (target.dataset.action === 'cancel-promotion') {
      mutate('cancel_promotion', { promotion_public_id: publicId }, 'cancel-promotion');
    } else if (target.dataset.action === 'approve-promotion') {
      await beginReauthentication('approve', publicId);
    } else if (target.dataset.action === 'rollback') {
      await beginReauthentication('rollback', publicId);
    }
  });

  async function beginReauthentication(mode, promotionPublicId) {
    const action = mode === 'approve' ? 'begin_promotion_reauthentication' : 'begin_rollback_reauthentication';
    try {
      const challenge = await post('/api/control-center/v1/release-deployment-action.php', {
        action,
        promotion_public_id: promotionPublicId
      }, `begin-${mode}`);
      state.reauth = { mode, promotionPublicId, ...challenge };
      byId('release-reauth-title').textContent = mode === 'approve' ? 'Approve production promotion' : 'Authorize production rollback';
      byId('release-reauth-description').textContent = mode === 'approve'
        ? 'Confirm your current password and MFA to approve this production release.'
        : 'Confirm your current password and MFA to queue rollback through the protected worker.';
      byId('release-mfa-field').hidden = !challenge.mfa_required;
      byId('release-reauth-dialog').showModal();
    } catch (error) {
      setNotice(error.message, 'error');
    }
  }

  byId('release-reauth-form').addEventListener('submit', async (event) => {
    if (event.submitter?.value !== 'confirm') return;
    event.preventDefault();
    const reauth = state.reauth;
    if (!reauth) return;
    const form = new FormData(event.currentTarget);
    const completeAction = reauth.mode === 'approve'
      ? 'complete_promotion_reauthentication'
      : 'complete_rollback_reauthentication';
    try {
      await post('/api/control-center/v1/release-deployment-action.php', {
        action: completeAction,
        promotion_public_id: reauth.promotionPublicId,
        reauthentication_public_id: reauth.reauthentication_public_id,
        challenge: reauth.challenge,
        current_password: String(form.get('current_password') || ''),
        mfa_challenge_token: reauth.mfa_challenge_token,
        mfa_code: String(form.get('mfa_code') || '')
      }, `complete-${reauth.mode}`);
      byId('release-reauth-dialog').close();
      event.currentTarget.reset();
      const finalAction = reauth.mode === 'approve' ? 'approve_promotion' : 'queue_rollback';
      await mutate(finalAction, {
        promotion_public_id: reauth.promotionPublicId,
        reauthentication_public_id: reauth.reauthentication_public_id
      }, reauth.mode === 'approve' ? 'approve-promotion' : 'queue-rollback');
    } catch (error) {
      setNotice(error.message, 'error');
    } finally {
      state.reauth = null;
    }
  });

  load();
})();
