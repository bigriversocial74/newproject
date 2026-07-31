(() => {
  'use strict';

  const root = document.querySelector('[data-control-center][data-page="security-center"]');
  if (!root) return;

  const accountPublicId = String(root.dataset.accountPublicId || '');
  const csrfToken = String(root.dataset.csrfToken || '');
  const notice = document.getElementById('security-center-notice');
  const filtersForm = document.getElementById('security-center-filters');
  const policyForm = document.getElementById('security-alert-preferences');
  const reauthDialog = document.getElementById('security-reauth-dialog');
  const reauthForm = document.getElementById('security-reauth-form');
  let snapshot = null;

  const node = (tag, className = '', text = null) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== null) element.textContent = String(text);
    return element;
  };
  const clear = (element) => { while (element?.firstChild) element.removeChild(element.firstChild); };
  const date = (value) => {
    if (!value) return '—';
    const parsed = new Date(`${String(value).replace(' ', 'T')}Z`);
    return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
  };
  const requestId = (prefix = 'SEC') => {
    const random = globalThis.crypto?.randomUUID?.().replaceAll('-', '') || `${Date.now()}${Math.random().toString(16).slice(2)}`;
    return `${prefix}-${random}`.slice(0, 80);
  };
  const showNotice = (message, kind = 'info') => {
    clear(notice);
    notice?.appendChild(node('div', `notice ${kind}`, message));
  };
  const post = async (path, payload = {}) => {
    const response = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', Accept: 'application/json'},
      body: JSON.stringify({
        ...payload,
        account_public_id: accountPublicId,
        csrf_token: csrfToken,
        request_id: payload.request_id || requestId(),
      }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body?.error?.message || 'Unable to complete the security request.');
    return body.data;
  };
  const activeFilters = () => {
    const values = Object.fromEntries(new FormData(filtersForm).entries());
    return Object.fromEntries(Object.entries(values).filter(([, value]) => String(value).trim() !== ''));
  };
  const chip = (value, prefix = '') => node('span', `security-chip ${prefix}${String(value).toLowerCase()}`, String(value).replaceAll('_', ' '));
  const button = (label, className = 'button small') => {
    const value = node('button', className, label);
    value.type = 'button';
    return value;
  };
  const select = (items, selectedValue, valueKey, labelBuilder) => {
    const field = node('select');
    const empty = node('option', '', 'Unassigned');
    empty.value = '';
    field.appendChild(empty);
    items.forEach((item) => {
      const option = node('option', '', labelBuilder(item));
      option.value = String(item[valueKey]);
      option.selected = String(item[valueKey]) === String(selectedValue || '');
      field.appendChild(option);
    });
    return field;
  };

  const renderPosture = () => {
    const target = document.getElementById('security-center-posture');
    target.dataset.status = snapshot.posture.status;
    clear(target);
    const score = node('div', 'security-posture-score');
    score.append(node('span', '', 'Risk score'), node('strong', '', snapshot.posture.score));
    const summary = node('div');
    summary.appendChild(node('span', 'eyebrow', 'Audit-chain integrity'));
    summary.appendChild(node(
      'h3',
      snapshot.posture.chain_valid ? 'security-chain-valid' : 'security-chain-invalid',
      snapshot.posture.chain_valid ? 'Chain verified' : 'Integrity failure detected'
    ));
    summary.appendChild(node('p', '', `${snapshot.posture.status.replaceAll('_', ' ')} posture · Evaluated ${date(snapshot.posture.evaluated_at)}`));
    target.append(score, summary);
  };

  const renderMetrics = () => {
    const target = document.getElementById('security-center-metrics');
    clear(target);
    [
      ['Audit events', snapshot.metrics.audit_events],
      ['High / critical', snapshot.metrics.high_or_critical],
      ['Denied / failed', snapshot.metrics.denied_or_failed],
      ['Active sessions', snapshot.metrics.active_sessions],
      ['Active cases', snapshot.metrics.security_cases_active],
      ['Unassigned cases', snapshot.metrics.security_cases_unassigned],
      ['Critical incidents', snapshot.metrics.active_critical_incidents],
    ].forEach(([label, value]) => {
      const item = node('div', 'metric');
      item.append(node('span', '', label), node('strong', '', value));
      target.appendChild(item);
    });
  };

  const renderPolicy = () => {
    const policy = snapshot.alert_preferences;
    policyForm.elements.automatic_promotion_enabled.checked = Boolean(policy.automatic_promotion_enabled);
    policyForm.elements.minimum_risk.value = policy.minimum_risk;
    policyForm.elements.include_integrity_failures.checked = Boolean(policy.include_integrity_failures);
    policyForm.elements.notify_on_promotion.checked = Boolean(policy.notify_on_promotion);
    policyForm.elements.notify_on_emergency_action.checked = Boolean(policy.notify_on_emergency_action);
    document.getElementById('security-policy-status').textContent = policy.automatic_promotion_enabled
      ? `Enabled · ${policy.minimum_risk}+`
      : 'Disabled';
  };

  const savePolicy = async () => {
    const submit = policyForm.querySelector('button[type="submit"]');
    try {
      submit.disabled = true;
      const data = await post('/api/control-center/v1/security-response-action.php', {
        action: 'save_alert_preferences',
        automatic_promotion_enabled: policyForm.elements.automatic_promotion_enabled.checked,
        minimum_risk: policyForm.elements.minimum_risk.value,
        include_integrity_failures: policyForm.elements.include_integrity_failures.checked,
        notify_on_promotion: policyForm.elements.notify_on_promotion.checked,
        notify_on_emergency_action: policyForm.elements.notify_on_emergency_action.checked,
        request_id: requestId('SEC-POLICY'),
      });
      snapshot.alert_preferences = data;
      renderPolicy();
      showNotice('Security alert policy saved.', 'success');
    } catch (error) {
      showNotice(error.message || 'Unable to save the security alert policy.', 'error');
    } finally {
      submit.disabled = false;
    }
  };

  const collectReauthentication = (title, description, mfaRequired) => new Promise((resolve) => {
    reauthForm.reset();
    document.getElementById('security-reauth-title').textContent = title;
    document.getElementById('security-reauth-description').textContent = description;
    document.getElementById('security-mfa-field').hidden = !mfaRequired;
    const handler = (event) => {
      event.preventDefault();
      const submitterValue = event.submitter?.value || '';
      reauthForm.removeEventListener('submit', handler);
      reauthDialog.close();
      if (submitterValue !== 'confirm') {
        resolve(null);
        return;
      }
      resolve({
        current_password: String(reauthForm.elements.current_password.value || ''),
        mfa_code: String(reauthForm.elements.mfa_code.value || ''),
      });
    };
    reauthForm.addEventListener('submit', handler);
    reauthDialog.showModal();
  });

  const reauthenticate = async ({kind, context, title, description}) => {
    const beginAction = kind === 'resolve'
      ? 'begin_case_resolution_reauthentication'
      : 'begin_emergency_reauthentication';
    const completeAction = kind === 'resolve'
      ? 'complete_case_resolution_reauthentication'
      : 'complete_emergency_reauthentication';
    const begin = await post('/api/control-center/v1/security-response-action.php', {
      action: beginAction,
      ...context,
      request_id: requestId('SEC-REAUTH-BEGIN'),
    });
    const proof = await collectReauthentication(title, description, Boolean(begin.mfa_required));
    if (!proof) return null;
    await post('/api/control-center/v1/security-response-action.php', {
      action: completeAction,
      ...context,
      reauthentication_public_id: begin.reauthentication_public_id,
      challenge: begin.challenge,
      current_password: proof.current_password,
      mfa_challenge_token: begin.mfa_challenge_token,
      mfa_code: proof.mfa_code,
      request_id: requestId('SEC-REAUTH-COMPLETE'),
    });
    return begin.reauthentication_public_id;
  };

  const assignCase = async (casePublicId, assigneeUserPublicId, trigger) => {
    try {
      trigger.disabled = true;
      await post('/api/control-center/v1/security-response-action.php', {
        action: 'assign_case',
        case_public_id: casePublicId,
        assignee_user_public_id: assigneeUserPublicId,
        request_id: requestId('SEC-ASSIGN'),
      });
      showNotice('Security responder assigned.', 'success');
      await load();
    } catch (error) {
      showNotice(error.message || 'Unable to assign the security case.', 'error');
    } finally {
      trigger.disabled = false;
    }
  };

  const addNote = async (casePublicId, textarea, trigger) => {
    const content = String(textarea.value || '').trim();
    if (!content) return showNotice('Enter a security case note first.', 'error');
    try {
      trigger.disabled = true;
      await post('/api/control-center/v1/security-response-action.php', {
        action: 'add_note',
        case_public_id: casePublicId,
        note: content,
        request_id: requestId('SEC-NOTE'),
      });
      textarea.value = '';
      showNotice('Encrypted security note added.', 'success');
      await load();
    } catch (error) {
      showNotice(error.message || 'Unable to add the security note.', 'error');
    } finally {
      trigger.disabled = false;
    }
  };

  const emergencyRevoke = async (casePublicId, targetUserPublicId, trigger) => {
    if (!targetUserPublicId) return showNotice('Select an account user with an active session.', 'error');
    try {
      trigger.disabled = true;
      const context = {case_public_id: casePublicId, target_user_public_id: targetUserPublicId};
      const reauthenticationPublicId = await reauthenticate({
        kind: 'emergency',
        context,
        title: 'Emergency session revocation',
        description: 'This revokes every active session for the selected account user and records a critical security response receipt.',
      });
      if (!reauthenticationPublicId) return;
      const result = await post('/api/control-center/v1/security-response-action.php', {
        action: 'emergency_revoke_sessions',
        ...context,
        reauthentication_public_id: reauthenticationPublicId,
        request_id: requestId('SEC-EMERGENCY'),
      });
      showNotice(`Emergency response completed. ${result.revoked_count} session(s) revoked.`, 'success');
      await load();
    } catch (error) {
      showNotice(error.message || 'Unable to complete the emergency response.', 'error');
    } finally {
      trigger.disabled = false;
    }
  };

  const resolveCase = async (casePublicId, summary, trigger) => {
    const resolutionSummary = String(summary || '').trim();
    if (resolutionSummary.length < 10) return showNotice('Enter a resolution summary of at least 10 characters.', 'error');
    try {
      trigger.disabled = true;
      const context = {case_public_id: casePublicId, resolution_summary: resolutionSummary};
      const reauthenticationPublicId = await reauthenticate({
        kind: 'resolve',
        context,
        title: 'Resolve security case',
        description: 'Closing a security case also resolves its linked operational incident and creates immutable resolution evidence.',
      });
      if (!reauthenticationPublicId) return;
      await post('/api/control-center/v1/security-response-action.php', {
        action: 'resolve_case',
        ...context,
        reauthentication_public_id: reauthenticationPublicId,
        request_id: requestId('SEC-RESOLVE'),
      });
      showNotice('Security case resolved.', 'success');
      await load();
    } catch (error) {
      showNotice(error.message || 'Unable to resolve the security case.', 'error');
    } finally {
      trigger.disabled = false;
    }
  };

  const renderCases = () => {
    const target = document.getElementById('security-center-cases');
    const count = document.getElementById('security-case-count');
    clear(target);
    count.textContent = `${snapshot.security_cases.length} case${snapshot.security_cases.length === 1 ? '' : 's'}`;
    if (!snapshot.security_cases.length) return target.appendChild(node('div', 'empty', 'No security cases have been promoted.'));

    snapshot.security_cases.forEach((securityCase) => {
      const card = node('article', 'security-case-card');
      const header = node('header', 'security-case-header');
      const identity = node('div');
      identity.append(
        node('span', 'eyebrow', securityCase.public_id),
        node('h4', '', securityCase.title),
        node('p', '', `${securityCase.event_type.replaceAll('.', ' ')} · ${date(securityCase.occurred_at)}`)
      );
      const statuses = node('div', 'security-evidence-meta');
      statuses.append(chip(securityCase.risk_level, 'risk-'), chip(securityCase.case_status, 'result-'));
      header.append(identity, statuses);
      card.appendChild(header);

      const facts = node('div', 'security-case-facts');
      [
        ['Category', securityCase.category],
        ['Result', securityCase.result],
        ['Incident', securityCase.incident_public_id],
        ['Last action', date(securityCase.last_action_at)],
      ].forEach(([label, value]) => {
        const fact = node('div');
        fact.append(node('span', '', label), node('strong', '', value));
        facts.appendChild(fact);
      });
      card.appendChild(facts);

      const notes = node('div', 'security-case-notes');
      notes.appendChild(node('h5', '', 'Encrypted analyst notes'));
      if (!securityCase.notes.length) {
        notes.appendChild(node('p', 'empty', 'No analyst notes have been added.'));
      } else {
        securityCase.notes.forEach((note) => {
          const item = node('div', 'security-note');
          item.append(
            node('strong', '', `${note.author_user_name} · ${date(note.created_at)}`),
            node('p', '', note.content_available ? note.content : 'Encrypted note could not be authenticated.'),
            node('small', '', `Evidence ${note.note_hash.slice(0, 16)}…`)
          );
          notes.appendChild(item);
        });
      }
      card.appendChild(notes);

      if (securityCase.case_status !== 'resolved') {
        const controls = node('div', 'security-case-controls');
        const assignment = node('div', 'security-control-group');
        assignment.appendChild(node('label', '', 'Assigned responder'));
        const assignee = select(
          snapshot.responders,
          securityCase.assigned_user_public_id,
          'user_public_id',
          (item) => `${item.display_name} · ${item.role.replaceAll('_', ' ')}`
        );
        const assign = button('Assign');
        assign.addEventListener('click', () => assignCase(securityCase.public_id, assignee.value, assign));
        assignment.append(assignee, assign);

        const noteGroup = node('div', 'security-control-group security-control-wide');
        noteGroup.appendChild(node('label', '', 'Add encrypted note'));
        const noteInput = node('textarea');
        noteInput.maxLength = 4000;
        noteInput.rows = 3;
        noteInput.placeholder = 'Record investigation evidence, containment steps, or follow-up.';
        const noteButton = button('Add Note');
        noteButton.addEventListener('click', () => addNote(securityCase.public_id, noteInput, noteButton));
        noteGroup.append(noteInput, noteButton);

        const emergencyGroup = node('div', 'security-control-group');
        emergencyGroup.appendChild(node('label', '', 'Emergency session target'));
        const targetSelect = select(
          snapshot.session_targets,
          '',
          'user_public_id',
          (item) => `${item.display_name} · ${item.active_sessions} active session${item.active_sessions === 1 ? '' : 's'}`
        );
        const revokeButton = button('Revoke Sessions', 'button small danger');
        revokeButton.addEventListener('click', () => emergencyRevoke(securityCase.public_id, targetSelect.value, revokeButton));
        emergencyGroup.append(targetSelect, revokeButton);

        const resolveGroup = node('div', 'security-control-group security-control-wide');
        resolveGroup.appendChild(node('label', '', 'Resolution summary'));
        const resolutionInput = node('textarea');
        resolutionInput.maxLength = 2000;
        resolutionInput.rows = 3;
        resolutionInput.placeholder = 'Summarize the verified cause, response, and why the case is safe to close.';
        const resolveButton = button('Resolve Case', 'button small primary');
        resolveButton.addEventListener('click', () => resolveCase(securityCase.public_id, resolutionInput.value, resolveButton));
        resolveGroup.append(resolutionInput, resolveButton);

        controls.append(assignment, emergencyGroup, noteGroup, resolveGroup);
        card.appendChild(controls);
      }
      target.appendChild(card);
    });
  };

  const renderIncidents = () => {
    const target = document.getElementById('security-center-incidents');
    clear(target);
    if (!snapshot.incidents.length) return target.appendChild(node('div', 'empty', 'No active incidents were found.'));
    snapshot.incidents.forEach((incident) => {
      const row = node('div', 'list-row');
      const main = node('div');
      main.append(node('strong', '', incident.title), node('p', '', `${incident.source_type.replaceAll('_', ' ')} · ${incident.occurrence_count} occurrence${incident.occurrence_count === 1 ? '' : 's'} · ${date(incident.last_detected_at)}`));
      const meta = node('div', 'security-evidence-meta');
      meta.append(chip(incident.severity, 'risk-'), chip(incident.status, 'result-'));
      row.append(main, meta);
      target.appendChild(row);
    });
  };

  const renderResponseActions = () => {
    const target = document.getElementById('security-center-response-actions');
    clear(target);
    if (!snapshot.recent_response_actions.length) return target.appendChild(node('div', 'empty', 'No security response actions are available.'));
    snapshot.recent_response_actions.slice(0, 30).forEach((action) => {
      const row = node('div', 'list-row');
      const main = node('div');
      main.append(
        node('strong', '', action.action_type.replaceAll('_', ' ')),
        node('p', '', `${action.actor_user_name} · ${date(action.created_at)}`),
        node('small', '', action.case_public_id || action.target_user_name || action.public_id)
      );
      const meta = node('div', 'security-evidence-meta');
      meta.appendChild(chip(action.result, 'result-'));
      row.append(main, meta);
      target.appendChild(row);
    });
  };

  const promoteEvent = async (eventPublicId, trigger) => {
    try {
      trigger.disabled = true;
      await post('/api/control-center/v1/security-response-action.php', {
        action: 'promote_event',
        event_public_id: eventPublicId,
        request_id: requestId('SEC-PROMOTE'),
      });
      showNotice('Security event promoted to an incident case.', 'success');
      await load();
    } catch (error) {
      showNotice(error.message || 'Unable to promote the security event.', 'error');
    } finally {
      trigger.disabled = false;
    }
  };

  const renderEvents = () => {
    const target = document.getElementById('security-center-events');
    const count = document.getElementById('security-center-event-count');
    clear(target);
    count.textContent = `${snapshot.audit_events.length} event${snapshot.audit_events.length === 1 ? '' : 's'}`;
    if (!snapshot.audit_events.length) return target.appendChild(node('div', 'empty', 'No events match the current filters.'));
    snapshot.audit_events.forEach((event) => {
      const row = node('div', 'security-evidence-row');
      const identity = node('div');
      identity.append(node('strong', '', event.event_type.replaceAll('.', ' ')), node('small', '', event.public_id));
      const category = node('div'); category.appendChild(chip(event.category));
      const risk = node('div'); risk.appendChild(chip(event.risk_level, 'risk-'));
      const result = node('div'); result.appendChild(chip(event.result, 'result-'));
      const occurred = node('div');
      occurred.append(node('span', '', date(event.occurred_at)), node('small', '', event.resource_type || 'account'));
      if (['high', 'critical'].includes(event.risk_level) || ['failure', 'denied'].includes(event.result) || event.category === 'integrity') {
        const promote = button('Promote');
        promote.addEventListener('click', () => promoteEvent(event.public_id, promote));
        occurred.appendChild(promote);
      }
      row.append(identity, category, risk, result, occurred);
      target.appendChild(row);
    });
  };

  const load = async () => {
    try {
      snapshot = await post('/api/control-center/v1/security-center-overview.php', {filters: activeFilters(), limit: 200});
      renderPosture();
      renderMetrics();
      renderPolicy();
      renderCases();
      renderIncidents();
      renderResponseActions();
      renderEvents();
    } catch (error) {
      showNotice(error.message || 'Unable to load the Security Center.', 'error');
    }
  };

  const exportEvidence = async () => {
    const exportButton = document.getElementById('security-center-export');
    try {
      exportButton.disabled = true;
      const result = await post('/api/control-center/v1/security-audit-export.php', {format: 'csv', filters: activeFilters()});
      const bytes = Uint8Array.from(atob(result.content_base64), (character) => character.charCodeAt(0));
      const url = URL.createObjectURL(new Blob([bytes], {type: 'text/csv;charset=utf-8'}));
      const anchor = node('a');
      anchor.href = url;
      anchor.download = `vp3-security-evidence-${result.public_id}.csv`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      showNotice(`Exported ${result.row_count} security events.`, 'success');
    } catch (error) {
      showNotice(error.message || 'Unable to export security evidence.', 'error');
    } finally {
      exportButton.disabled = false;
    }
  };

  policyForm?.addEventListener('submit', (event) => { event.preventDefault(); savePolicy(); });
  filtersForm?.addEventListener('submit', (event) => { event.preventDefault(); load(); });
  document.getElementById('security-filter-reset')?.addEventListener('click', () => { filtersForm.reset(); load(); });
  document.getElementById('security-center-refresh')?.addEventListener('click', load);
  document.getElementById('security-center-export')?.addEventListener('click', exportEvidence);
  load();
})();
