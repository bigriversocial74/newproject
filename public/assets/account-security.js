(() => {
  'use strict';

  const root = document.querySelector('[data-control-center][data-page="account-security"]');
  if (!root) return;
  const accountId = Number(root.dataset.accountId || 0);
  const csrfToken = String(root.dataset.csrfToken || '');
  const notice = document.getElementById('security-notice');
  const dialog = document.getElementById('security-dialog');
  const dialogForm = document.getElementById('security-dialog-form');
  const dialogTitle = document.getElementById('security-dialog-title');
  const dialogBody = document.getElementById('security-dialog-body');
  let snapshot = null;
  let pendingEnrollment = null;

  const node = (tag, className = '', text = null) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== null) element.textContent = String(text);
    return element;
  };
  const clear = (element) => { while (element?.firstChild) element.removeChild(element.firstChild); };
  const token = (prefix) => `${prefix}-${globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`}`.replace(/[^A-Za-z0-9._:-]/g, '').slice(0, 64);
  const date = (value) => {
    if (!value) return '—';
    const parsed = new Date(`${String(value).replace(' ', 'T')}Z`);
    return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
  };
  const statusClass = (value) => `status status-${String(value || 'unknown').toLowerCase().replace(/[^a-z0-9_-]/g, '')}`;
  const showNotice = (message, kind = 'info') => { clear(notice); notice?.appendChild(node('div', `notice ${kind}`, message)); };
  const post = async (path, payload = {}, accountScoped = true) => {
    const finalPayload = accountScoped ? { ...payload, account_id: accountId, csrf_token: csrfToken } : { ...payload, csrf_token: csrfToken };
    const response = await fetch(path, {
      method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(finalPayload),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body?.error?.message || 'Unable to complete the security request.');
    return body.data;
  };
  const input = (name, label, type = 'text', value = '') => {
    const wrapper = node('label'); wrapper.appendChild(node('span', '', label));
    const field = node('input'); field.name = name; field.type = type; field.value = value;
    if (type === 'password') field.autocomplete = 'current-password';
    wrapper.appendChild(field); return wrapper;
  };
  const select = (name, label, values, selected = '') => {
    const wrapper = node('label'); wrapper.appendChild(node('span', '', label)); const field = node('select'); field.name = name;
    values.forEach((value) => { const option = node('option', '', value.replaceAll('_', ' ')); option.value = value; option.selected = value === selected; field.appendChild(option); });
    wrapper.appendChild(field); return wrapper;
  };
  const ask = (title, fields, confirmLabel = 'Confirm') => new Promise((resolve) => {
    clear(dialogBody); dialogTitle.textContent = title; fields.forEach((field) => dialogBody.appendChild(field));
    document.getElementById('security-dialog-confirm').textContent = confirmLabel;
    const close = () => { dialogForm.removeEventListener('submit', submit); dialog.removeEventListener('close', closed); };
    const submit = (event) => {
      event.preventDefault(); const submitter = event.submitter?.value;
      if (submitter !== 'confirm') { dialog.close('cancel'); return; }
      const values = Object.fromEntries(new FormData(dialogForm).entries()); dialog.close('confirm'); close(); resolve(values);
    };
    const closed = () => { if (dialog.returnValue !== 'confirm') { close(); resolve(null); } };
    dialogForm.addEventListener('submit', submit); dialog.addEventListener('close', closed); dialog.showModal();
  });

  const currentMember = () => snapshot?.members?.find((member) => member.current_user) || null;
  const renderMetrics = () => {
    const target = document.getElementById('security-metrics'); clear(target);
    const rows = [
      ['Current role', String(snapshot.current_role || 'member').replaceAll('_', ' ')],
      ['MFA', snapshot.mfa.enabled ? 'Enabled' : 'Not enabled'],
      ['Recovery codes', snapshot.mfa.recovery_codes_remaining],
      ['Active sessions', snapshot.sessions.length],
      ['Team members', snapshot.members.length],
      ['Pending invitations', snapshot.invitations.filter((item) => item.status === 'pending').length],
    ];
    rows.forEach(([label, value]) => { const item = node('div', 'metric'); item.append(node('span', '', label), node('strong', '', value)); target.appendChild(item); });
  };
  const renderProfile = () => {
    const member = currentMember(); const summary = document.getElementById('profile-summary'); clear(summary);
    if (!member) return summary.appendChild(node('div', 'empty', 'Profile information is unavailable.'));
    summary.append(node('strong', '', member.display_name), node('span', '', member.email), node('span', 'team-role', member.role.replaceAll('_', ' ')));
    const form = document.getElementById('profile-form'); form.elements.display_name.value = member.display_name;
  };
  const renderMfa = () => {
    const target = document.getElementById('mfa-content'); const badge = document.getElementById('mfa-status'); clear(target);
    badge.className = snapshot.mfa.enabled ? 'status status-active' : 'status status-disabled'; badge.textContent = snapshot.mfa.enabled ? 'Enabled' : 'Not enabled';
    if (pendingEnrollment) {
      target.appendChild(node('div', 'security-secret-warning', 'Add this secret to your authenticator now. It will not be shown again after confirmation.'));
      target.append(node('strong', '', 'Authenticator secret'), node('code', '', pendingEnrollment.secret), node('strong', '', 'Authenticator URI'), node('code', '', pendingEnrollment.otpauth_uri));
      const code = input('code', 'Six-digit verification code'); code.querySelector('input').inputMode = 'numeric'; code.querySelector('input').maxLength = 6;
      const confirm = node('button', 'button primary', 'Confirm MFA'); confirm.type = 'button'; confirm.addEventListener('click', async () => {
        try {
          confirm.disabled = true;
          const result = await post('/api/control-center/v1/mfa-action.php', { action: 'confirm', code: code.querySelector('input').value, request_id: token('REQ-MFA') });
          pendingEnrollment = null; await load(); showRecoveryCodes(result.recovery_codes || []);
        } catch (error) { confirm.disabled = false; showNotice(error.message, 'error'); }
      });
      target.append(code, confirm); return;
    }
    if (snapshot.mfa.enabled) {
      target.append(node('p', '', `Enabled ${date(snapshot.mfa.activated_at)} · ${snapshot.mfa.recovery_codes_remaining} unused recovery codes remain.`));
      const disable = node('button', 'button light', 'Disable MFA'); disable.type = 'button'; disable.addEventListener('click', disableMfa); target.appendChild(disable);
    } else {
      target.appendChild(node('p', '', 'Protect sign-in with a time-based authenticator and one-time recovery codes.'));
      const enable = node('button', 'button primary', 'Enable MFA'); enable.type = 'button'; enable.addEventListener('click', beginMfa); target.appendChild(enable);
    }
  };
  const showRecoveryCodes = (codes) => {
    const target = document.getElementById('mfa-content'); clear(target);
    target.appendChild(node('div', 'security-secret-warning', 'Save these recovery codes now. Each code works once and VP3 cannot display them again.'));
    const grid = node('div', 'recovery-codes'); codes.forEach((code) => grid.appendChild(node('code', '', code))); target.appendChild(grid);
    const done = node('button', 'button primary', 'I Saved the Codes'); done.type = 'button'; done.addEventListener('click', () => { renderMfa(); }); target.appendChild(done);
  };
  const renderSessions = () => {
    const target = document.getElementById('security-sessions'); clear(target);
    if (!snapshot.sessions.length) return target.appendChild(node('div', 'empty', 'No active sessions were found.'));
    snapshot.sessions.forEach((session) => {
      const row = node('div', 'list-row'); const main = node('div'); main.append(node('strong', '', session.current ? 'Current session' : 'VP3 session'), node('p', '', `Last active ${date(session.last_seen_at)} · Expires ${date(session.absolute_expires_at)}`));
      const actions = node('div', 'security-row-actions'); const button = node('button', session.current ? 'button light' : 'button small', session.current ? 'Sign Out' : 'Revoke'); button.type = 'button'; button.addEventListener('click', () => revokeSession(session)); actions.appendChild(button); row.append(main, actions); target.appendChild(row);
    });
  };
  const renderTeam = () => {
    const section = document.getElementById('team-section');
    const inviteButton = document.getElementById('invite-member');
    section.hidden = !snapshot.can_manage_team;
    if (inviteButton) inviteButton.disabled = !snapshot.can_manage_team;
    if (!snapshot.can_manage_team) return;
    const members = document.getElementById('team-members'); clear(members);
    snapshot.members.forEach((member) => {
      const row = node('div', 'list-row'); const main = node('div'); main.append(node('strong', '', member.display_name), node('p', '', `${member.email} · ${member.role.replaceAll('_', ' ')} · ${member.active_sessions} sessions`));
      const actions = node('div', 'security-row-actions');
      const role = node('button', 'button small', 'Change Role'); role.type = 'button'; role.disabled = member.current_user; role.addEventListener('click', () => changeRole(member));
      const status = node('button', member.status === 'active' ? 'button light' : 'button small', member.status === 'active' ? 'Suspend' : 'Activate'); status.type = 'button'; status.disabled = member.current_user; status.addEventListener('click', () => setStatus(member, member.status === 'active' ? 'suspended' : 'active'));
      const remove = node('button', 'button light', 'Remove'); remove.type = 'button'; remove.disabled = member.current_user; remove.addEventListener('click', () => setStatus(member, 'removed'));
      actions.append(role, status, remove); row.append(main, actions); members.appendChild(row);
    });
    const invitations = document.getElementById('team-invitations'); clear(invitations);
    if (!snapshot.invitations.length) invitations.appendChild(node('div', 'empty', 'No invitations have been created.'));
    snapshot.invitations.forEach((invite) => {
      const row = node('div', 'list-row'); const main = node('div'); main.append(node('strong', '', invite.email), node('p', '', `${invite.role.replaceAll('_', ' ')} · Expires ${date(invite.expires_at)}`));
      const actions = node('div', 'security-row-actions'); actions.appendChild(node('span', statusClass(invite.status), invite.status));
      if (invite.status === 'pending') { const revoke = node('button', 'button small', 'Revoke'); revoke.type = 'button'; revoke.addEventListener('click', () => revokeInvitation(invite)); actions.appendChild(revoke); }
      row.append(main, actions); invitations.appendChild(row);
    });
  };
  const renderEvents = () => {
    const target = document.getElementById('security-events'); clear(target);
    if (!snapshot.security_events.length) return target.appendChild(node('div', 'empty', 'No security history is available.'));
    snapshot.security_events.forEach((event) => {
      const row = node('div', 'list-row security-event'); const main = node('div'); main.append(node('strong', '', event.event_type.replaceAll('.', ' ')), node('p', '', event.resource_public_id || event.resource_type || 'Account security'));
      const meta = node('div', 'security-event-meta'); meta.append(node('span', statusClass(event.result), event.result), node('span', '', date(event.created_at))); row.append(main, meta); target.appendChild(row);
    });
  };
  const load = async () => {
    try {
      snapshot = await post('/api/control-center/v1/account-security-overview.php');
      renderMetrics(); renderProfile(); renderMfa(); renderSessions(); renderTeam(); renderEvents();
      if (new URLSearchParams(location.search).get('invitation') === 'accepted') showNotice('The account invitation was accepted.', 'success');
    } catch (error) { showNotice(error.message || 'Unable to load account security.', 'error'); }
  };

  const beginMfa = async () => { try { pendingEnrollment = await post('/api/control-center/v1/mfa-action.php', { action: 'begin', request_id: token('REQ-MFA') }); renderMfa(); } catch (error) { showNotice(error.message, 'error'); } };
  const disableMfa = async () => { const values = await ask('Disable MFA', [input('password', 'Current password', 'password')], 'Disable MFA'); if (!values) return; try { await post('/api/control-center/v1/mfa-action.php', { action: 'disable', password: values.password, request_id: token('REQ-MFA') }); pendingEnrollment = null; await load(); showNotice('MFA was disabled.', 'success'); } catch (error) { showNotice(error.message, 'error'); } };
  const revokeSession = async (session) => { try { await post('/api/auth/revoke-session.php', { session_public_id: session.public_id }, false); if (session.current) location.assign('/'); else { await load(); showNotice('The session was revoked.', 'success'); } } catch (error) { showNotice(error.message, 'error'); } };
  const changeRole = async (member) => { const values = await ask('Change Team Role', [select('role', 'Role', snapshot.roles, member.role)], 'Change Role'); if (!values) return; await teamAction({ action: 'change_role', member_public_id: member.public_id, role: values.role }, 'The team role was updated.'); };
  const setStatus = async (member, status) => { const values = await ask(`${status === 'removed' ? 'Remove' : status === 'suspended' ? 'Suspend' : 'Activate'} Member`, [node('p', '', `${member.display_name} · ${member.email}`)], status === 'removed' ? 'Remove Member' : 'Confirm'); if (!values) return; await teamAction({ action: 'set_status', member_public_id: member.public_id, status }, 'The membership status was updated.'); };
  const revokeInvitation = async (invite) => { const values = await ask('Revoke Invitation', [node('p', '', invite.email)], 'Revoke'); if (!values) return; await teamAction({ action: 'revoke_invitation', invitation_public_id: invite.public_id }, 'The invitation was revoked.'); };
  const teamAction = async (payload, message) => { try { await post('/api/control-center/v1/team-action.php', { ...payload, request_id: token('REQ-TEAM') }); await load(); showNotice(message, 'success'); } catch (error) { showNotice(error.message, 'error'); } };

  document.getElementById('profile-form')?.addEventListener('submit', async (event) => { event.preventDefault(); const values = Object.fromEntries(new FormData(event.currentTarget).entries()); try { await post('/api/control-center/v1/profile-action.php', { ...values, request_id: token('REQ-PROFILE') }); event.currentTarget.elements.current_password.value = ''; await load(); showNotice('Your profile was updated.', 'success'); } catch (error) { showNotice(error.message, 'error'); } });
  document.getElementById('password-form')?.addEventListener('submit', async (event) => { event.preventDefault(); const values = Object.fromEntries(new FormData(event.currentTarget).entries()); try { await post('/api/auth/change-password.php', values, false); event.currentTarget.reset(); await load(); showNotice('Your password was changed and other sessions were revoked.', 'success'); } catch (error) { showNotice(error.message, 'error'); } });
  document.getElementById('logout-others')?.addEventListener('click', async () => { try { await post('/api/auth/logout-others.php', {}, false); await load(); showNotice('Other active sessions were revoked.', 'success'); } catch (error) { showNotice(error.message, 'error'); } });
  document.getElementById('invite-member')?.addEventListener('click', async () => { const values = await ask('Invite Team Member', [input('email', 'Email address', 'email'), select('role', 'Role', snapshot.roles, 'support_member')], 'Send Invitation'); if (!values) return; await teamAction({ action: 'invite', email: values.email, role: values.role }, 'The invitation was created and sent.'); });
  document.getElementById('refresh-security')?.addEventListener('click', load);
  load();
})();
