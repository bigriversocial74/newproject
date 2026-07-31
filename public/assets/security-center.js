(() => {
  'use strict';

  const root = document.querySelector('[data-control-center][data-page="security-center"]');
  if (!root) return;

  const accountPublicId = String(root.dataset.accountPublicId || '');
  const csrfToken = String(root.dataset.csrfToken || '');
  const notice = document.getElementById('security-center-notice');
  const filtersForm = document.getElementById('security-center-filters');
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
  const showNotice = (message, kind = 'info') => {
    clear(notice);
    notice?.appendChild(node('div', `notice ${kind}`, message));
  };
  const post = async (path, payload = {}) => {
    const response = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', Accept: 'application/json'},
      body: JSON.stringify({...payload, account_public_id: accountPublicId, csrf_token: csrfToken}),
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

  const renderPosture = () => {
    const target = document.getElementById('security-center-posture');
    target.dataset.status = snapshot.posture.status;
    clear(target);
    const score = node('div', 'security-posture-score');
    score.append(node('span', '', 'Risk score'), node('strong', '', snapshot.posture.score));
    const summary = node('div');
    summary.appendChild(node('span', 'eyebrow', 'Audit-chain integrity'));
    const heading = node('h3', snapshot.posture.chain_valid ? 'security-chain-valid' : 'security-chain-invalid', snapshot.posture.chain_valid ? 'Chain verified' : 'Integrity failure detected');
    summary.appendChild(heading);
    summary.appendChild(node('p', '', `${snapshot.posture.status.replaceAll('_', ' ')} posture · Evaluated ${date(snapshot.posture.evaluated_at)}`));
    target.append(score, summary);
  };

  const renderMetrics = () => {
    const target = document.getElementById('security-center-metrics');
    clear(target);
    const metrics = [
      ['Audit events', snapshot.metrics.audit_events],
      ['High / critical', snapshot.metrics.high_or_critical],
      ['Denied / failed', snapshot.metrics.denied_or_failed],
      ['Integrity events', snapshot.metrics.integrity_events],
      ['Active sessions', snapshot.metrics.active_sessions],
      ['Open incidents', snapshot.metrics.incidents_open],
      ['Critical incidents', snapshot.metrics.active_critical_incidents],
    ];
    metrics.forEach(([label, value]) => {
      const item = node('div', 'metric');
      item.append(node('span', '', label), node('strong', '', value));
      target.appendChild(item);
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

  const renderIncidentEvents = () => {
    const target = document.getElementById('security-center-incident-events');
    clear(target);
    if (!snapshot.recent_incident_events.length) return target.appendChild(node('div', 'empty', 'No incident activity is available.'));
    snapshot.recent_incident_events.forEach((event) => {
      const row = node('div', 'list-row');
      const main = node('div');
      main.append(node('strong', '', event.event_type.replaceAll('_', ' ')), node('p', '', `${event.actor_type.replaceAll('_', ' ')} · ${date(event.occurred_at)}`));
      const meta = node('div', 'security-evidence-meta');
      meta.append(chip(event.severity, 'risk-'), chip(event.status, 'result-'));
      row.append(main, meta);
      target.appendChild(row);
    });
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
      const occurred = node('div'); occurred.append(node('span', '', date(event.occurred_at)), node('small', '', event.resource_type || 'account'));
      row.append(identity, category, risk, result, occurred);
      target.appendChild(row);
    });
  };

  const load = async () => {
    try {
      snapshot = await post('/api/control-center/v1/security-center-overview.php', {filters: activeFilters(), limit: 200});
      renderPosture(); renderMetrics(); renderIncidents(); renderIncidentEvents(); renderEvents();
    } catch (error) {
      showNotice(error.message || 'Unable to load the Security Center.', 'error');
    }
  };

  const exportEvidence = async () => {
    const button = document.getElementById('security-center-export');
    try {
      button.disabled = true;
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
      button.disabled = false;
    }
  };

  filtersForm?.addEventListener('submit', (event) => { event.preventDefault(); load(); });
  document.getElementById('security-filter-reset')?.addEventListener('click', () => { filtersForm.reset(); load(); });
  document.getElementById('security-center-refresh')?.addEventListener('click', load);
  document.getElementById('security-center-export')?.addEventListener('click', exportEvidence);
  load();
})();
