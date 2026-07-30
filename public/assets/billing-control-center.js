(() => {
  'use strict';
  const root = document.querySelector('[data-control-center][data-page="billing"]');
  if (!root) return;
  const accountPublicId = String(root.dataset.accountPublicId || '');
  const csrfToken = String(root.dataset.csrfToken || '');
  const notice = document.getElementById('billing-notice');
  const portalButton = document.getElementById('open-billing-portal');
  let snapshot = null;

  const node = (tag, className = '', text = null) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== null) element.textContent = String(text);
    return element;
  };
  const clear = (element) => { while (element?.firstChild) element.removeChild(element.firstChild); };
  const token = (prefix) => `${prefix}-${globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`}`.replace(/[^A-Za-z0-9._:-]/g, '').slice(0, 64);
  const money = (amount, currency = 'USD') => {
    const value = Number(amount || 0) / 100;
    try { return new Intl.NumberFormat(undefined, { style: 'currency', currency: String(currency).toUpperCase() }).format(value); }
    catch { return `${String(currency).toUpperCase()} ${value.toFixed(2)}`; }
  };
  const date = (value) => {
    if (!value) return '—';
    const parsed = new Date(`${String(value).replace(' ', 'T')}Z`);
    return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
  };
  const statusClass = (value) => `status billing-status status-${String(value || 'unknown').toLowerCase().replace(/[^a-z0-9_-]/g, '')}`;
  const showNotice = (message, kind = 'info') => { clear(notice); notice?.appendChild(node('div', `notice ${kind}`, message)); };
  const post = async (path, payload = {}) => {
    const response = await fetch(path, {
      method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ ...payload, account_public_id: accountPublicId, csrf_token: csrfToken }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body?.error?.message || 'Unable to complete the billing request.');
    return body.data;
  };
  const trustedStripeUrl = (value, expectedHost) => {
    const url = new URL(String(value || ''));
    if (url.protocol !== 'https:' || url.hostname.toLowerCase() !== expectedHost) throw new Error('The billing provider returned an untrusted redirect.');
    return url.href;
  };

  const renderMetrics = (metrics) => {
    const target = document.getElementById('billing-metrics'); clear(target);
    [['Active subscriptions', metrics.active_subscriptions], ['Needs attention', metrics.billing_attention], ['Open invoices', metrics.open_invoices],
      ['Failed payments', metrics.failed_payments], ['Total billed', money(metrics.amount_due, metrics.currency)], ['Total paid', money(metrics.amount_paid, metrics.currency)]]
      .forEach(([label, value]) => { const item = node('div', 'metric'); item.append(node('span', '', label), node('strong', '', value)); target.appendChild(item); });
  };
  const renderAttention = (items) => {
    const target = document.getElementById('billing-attention'); clear(target);
    document.getElementById('billing-attention-count').textContent = String(items.length);
    if (!items.length) return target.appendChild(node('div', 'empty', 'No billing issues require attention.'));
    items.forEach((item) => {
      const card = node('div', `attention-item ${item.severity || 'info'}`); const body = node('div');
      body.append(node('strong', '', item.title), node('p', '', item.detail)); card.appendChild(body);
      if (item.action === 'portal' && snapshot?.portal_available) { const button = node('button', 'button small', 'Resolve in Billing Portal'); button.type = 'button'; button.dataset.billingAction = 'portal'; card.appendChild(button); }
      target.appendChild(card);
    });
  };
  const renderSubscriptions = (items) => {
    const target = document.getElementById('billing-subscriptions'); clear(target);
    if (!items.length) return target.appendChild(node('div', 'empty', 'No subscriptions are attached to this account.'));
    items.forEach((item) => {
      const row = node('div', 'list-row billing-list-row'); const main = node('div');
      main.append(node('strong', '', item.plan.name), node('p', '', `${item.plan.billing_interval} · ${money(item.plan.amount, item.plan.currency)}`));
      const meta = node('div', 'billing-row-meta');
      meta.append(node('span', statusClass(item.status), item.status), node('span', '', `Renews ${date(item.period_ends_at)}`), node('span', '', `${item.domain_count} Domains · ${item.license_count} licenses`));
      if (item.grace_ends_at) meta.appendChild(node('span', 'warning-text', `Grace ends ${date(item.grace_ends_at)}`));
      row.append(main, meta); target.appendChild(row);
    });
  };
  const renderPlans = (items, subscriptions) => {
    const target = document.getElementById('billing-plans'); clear(target);
    const currentPlans = new Set(subscriptions.filter((item) => ['active', 'trialing', 'past_due', 'grace'].includes(item.status)).map((item) => item.plan.public_id));
    if (!items.length) return target.appendChild(node('div', 'empty', 'No active plans are available.'));
    items.forEach((item) => {
      const hasCurrentSubscription = currentPlans.has(item.public_id); const card = node('article', 'billing-plan-card');
      card.append(node('span', 'eyebrow', item.billing_interval), node('h4', '', item.name), node('strong', 'billing-price', money(item.amount, item.currency)), node('p', '', `${item.entitlement_count} entitlement settings included.`));
      const button = node('button', hasCurrentSubscription ? 'button light' : 'button primary', hasCurrentSubscription ? 'Add Another' : 'Choose Plan');
      button.type = 'button'; button.disabled = !item.available_for_checkout; button.dataset.billingAction = 'checkout'; button.dataset.planPublicId = item.public_id;
      card.appendChild(button); target.appendChild(card);
    });
  };
  const renderInvoices = (items) => {
    const target = document.getElementById('billing-invoices'); clear(target);
    if (!items.length) return target.appendChild(node('div', 'empty', 'No invoices have been recorded.'));
    const table = node('table', 'billing-table'); const head = node('thead'); const header = node('tr');
    ['Created', 'Status', 'Amount', 'Paid', 'Remaining', 'Invoice'].forEach((label) => header.appendChild(node('th', '', label))); head.appendChild(header);
    const body = node('tbody'); items.forEach((item) => {
      const row = node('tr'); row.append(node('td', '', date(item.created_at)), node('td', statusClass(item.status), item.status), node('td', '', money(item.amount_due, item.currency)), node('td', '', money(item.amount_paid, item.currency)), node('td', '', money(item.amount_remaining, item.currency)));
      const links = node('td', 'billing-links'); [['View', item.hosted_url], ['PDF', item.pdf_url]].forEach(([label, href]) => { if (href) { const link = node('a', '', label); link.href = href; link.target = '_blank'; link.rel = 'noopener noreferrer'; links.appendChild(link); } });
      if (!links.childNodes.length) links.textContent = '—'; row.appendChild(links); body.appendChild(row);
    }); table.append(head, body); target.appendChild(table);
  };
  const renderActivity = (targetId, items, type) => {
    const target = document.getElementById(targetId); clear(target);
    if (!items.length) return target.appendChild(node('div', 'empty', type === 'payment' ? 'No payment attempts have been recorded.' : 'No refunds have been recorded.'));
    items.forEach((item) => { const row = node('div', 'list-row billing-list-row'); const main = node('div'); main.append(node('strong', '', money(item.amount, item.currency)), node('p', '', date(item.created_at))); const meta = node('div', 'billing-row-meta'); meta.appendChild(node('span', statusClass(item.status), item.status));
      if (type === 'payment') { if (item.payment_method_type) meta.appendChild(node('span', '', item.payment_method_type)); if (item.failure_message) meta.appendChild(node('span', 'warning-text', item.failure_message)); }
      else { if (item.reason) meta.appendChild(node('span', '', item.reason)); if (item.failure_reason) meta.appendChild(node('span', 'warning-text', item.failure_reason)); }
      row.append(main, meta); target.appendChild(row); });
  };
  const load = async () => {
    try { snapshot = await post('/api/control-center/v1/billing-overview.php'); renderMetrics(snapshot.metrics); renderAttention(snapshot.attention); renderSubscriptions(snapshot.subscriptions); renderPlans(snapshot.plans, snapshot.subscriptions); renderInvoices(snapshot.invoices); renderActivity('billing-payments', snapshot.payments, 'payment'); renderActivity('billing-refunds', snapshot.refunds, 'refund'); portalButton.disabled = !snapshot.portal_available;
      const checkout = new URLSearchParams(location.search).get('checkout'); if (checkout === 'success') showNotice('Stripe Checkout completed. Billing status will update after the signed webhook is processed.', 'success'); if (checkout === 'canceled') showNotice('Checkout was canceled. No billing change was made.'); }
    catch (error) { showNotice(error.message || 'Unable to load billing.', 'error'); }
  };
  const runAction = async (action, planPublicId = null) => {
    showNotice(action === 'portal' ? 'Opening secure billing portal…' : 'Creating secure checkout…');
    const result = await post('/api/control-center/v1/billing-action.php', { action, plan_public_id: planPublicId, request_id: token('REQ-BILL'), idempotency_key: token('IDEM-BILL') });
    location.assign(trustedStripeUrl(result.url, action === 'portal' ? 'billing.stripe.com' : 'checkout.stripe.com'));
  };
  document.addEventListener('click', (event) => { const button = event.target.closest('[data-billing-action]'); if (!button || button.disabled) return; button.disabled = true; runAction(button.dataset.billingAction, button.dataset.planPublicId || null).catch((error) => { button.disabled = false; showNotice(error.message || 'Unable to open secure billing.', 'error'); }); });
  document.getElementById('refresh-billing')?.addEventListener('click', load);
  portalButton?.addEventListener('click', () => { if (portalButton.disabled) return; portalButton.disabled = true; runAction('portal').catch((error) => { portalButton.disabled = false; showNotice(error.message || 'Unable to open billing portal.', 'error'); }); });
  load();
})();
