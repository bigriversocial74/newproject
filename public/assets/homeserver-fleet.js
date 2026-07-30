(() => {
  "use strict";

  const root = document.querySelector("[data-homeserver-fleet]");
  if (!root) return;

  const csrfToken = root.dataset.csrfToken || "";
  const accountSelect = document.querySelector("#fleet-account");
  const state = { fleet: null, options: [], busy: false, notice: null, oneTimeBundle: null };

  const escapeHtml = (value) => String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

  const humanize = (value) => String(value || "unknown").replaceAll("_", " ");
  const accountId = () => Number(accountSelect?.value || root.dataset.accountId || 0);
  const requestId = () => `vp3-ui-${crypto.randomUUID()}`;
  const idempotencyKey = () => `vp3-ui-${crypto.randomUUID()}`;
  const formatDate = (value) => {
    if (!value) return "Not yet";
    const date = new Date(`${String(value).replace(" ", "T")}Z`);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
  };

  async function api(path, payload = {}) {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
      body: JSON.stringify({ account_id: accountId(), csrf_token: csrfToken, ...payload }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data?.error?.message || `VP3 request failed with HTTP ${response.status}`);
    return data.data;
  }

  function renderMetrics() {
    const summary = state.fleet?.summary || {};
    const values = [
      ["Total", summary.total || 0],
      ["Active", summary.active || 0],
      ["Online", summary.online || 0],
      ["Attention", summary.attention || 0],
      ["Pending", summary.pending_pairing || 0],
      ["Suspended", summary.suspended || 0],
    ];
    return values.map(([label, value]) => `<article class="metric"><span>${escapeHtml(label)}</span><strong>${Number(value)}</strong></article>`).join("");
  }

  function deviceCard(device) {
    const lease = device.lease;
    const receipt = device.last_update_receipt;
    const canSuspend = !["suspended", "revoked"].includes(device.status);
    const canResume = device.status === "suspended";
    const canReplace = device.status !== "revoked";
    return `<article class="device-card" data-device="${escapeHtml(device.device_public_id)}">
      <div class="device-top"><div><h3>${escapeHtml(device.device_public_id)}</h3><small>${escapeHtml(device.license_public_id)} · ${escapeHtml(device.update_channel)} channel</small></div><span class="status ${escapeHtml(device.status.replaceAll("_", "-"))}">${escapeHtml(humanize(device.status))}</span></div>
      <div class="device-grid">
        <div><span>Software</span><strong>${escapeHtml(device.software_version || "Not reported")}</strong></div>
        <div><span>Last heartbeat</span><strong>${escapeHtml(formatDate(device.last_heartbeat_at))}</strong></div>
        <div><span>Lease</span><strong>${escapeHtml(lease ? `${humanize(lease.status)} · ${formatDate(lease.expires_at)}` : "Not issued")}</strong></div>
        <div><span>Last update</span><strong>${escapeHtml(receipt ? `${humanize(receipt.disposition)} · ${formatDate(receipt.created_at)}` : "No receipt")}</strong></div>
        <div><span>Frontends</span><strong>${Number(device.paired_frontend_count)} / ${Number(device.frontend_limit)}</strong></div>
        <div><span>Pairing</span><strong>${escapeHtml(humanize(device.pairing_status))}</strong></div>
        <div><span>Events (24h)</span><strong>${Number(device.event_count_24h || 0)}</strong></div>
        <div><span>MCP</span><strong>${escapeHtml(device.mcp_version || "Not reported")}</strong></div>
      </div>
      <div class="device-actions">
        ${canSuspend ? `<button class="button ghost" data-action="suspend" type="button">Suspend</button>` : ""}
        ${canResume ? `<button class="button ghost" data-action="resume" type="button">Resume</button>` : ""}
        ${canReplace ? `<button class="button ghost" data-action="replace" type="button">Replace Device</button>` : ""}
        ${device.status !== "revoked" ? `<button class="button danger" data-action="revoke" type="button">Revoke</button>` : ""}
        ${device.status !== "revoked" ? `<button class="button ghost" data-action="transfer" type="button">Transfer</button>` : ""}
      </div>
    </article>`;
  }

  function render() {
    document.querySelector("#fleet-metrics").innerHTML = renderMetrics();
    const list = document.querySelector("#fleet-devices");
    const devices = state.fleet?.devices || [];
    list.innerHTML = devices.length ? devices.map(deviceCard).join("") : `<div class="empty">No HomeServers are registered to this account yet.</div>`;
    document.querySelector("#fleet-notice").innerHTML = state.notice ? `<div class="notice ${escapeHtml(state.notice.kind)}">${escapeHtml(state.notice.message)}</div>` : "";
    const licenseSelect = document.querySelector("#register-license");
    if (licenseSelect) {
      licenseSelect.innerHTML = `<option value="">Select eligible license</option>${state.options.map((option) => `<option value="${Number(option.license_id)}">${escapeHtml(option.hostname)} · ${escapeHtml(option.plan_name)} · ${escapeHtml(option.license_public_id)}</option>`).join("")}`;
    }
    document.querySelectorAll("button").forEach((button) => { if (button.closest("[data-homeserver-fleet]")) button.disabled = state.busy || button.disabled; });
    bindActions();
    renderModal();
  }

  function renderModal() {
    const modal = document.querySelector("#fleet-secret-modal");
    const bundle = state.oneTimeBundle;
    if (!bundle) { modal.hidden = true; modal.innerHTML = ""; return; }
    modal.hidden = false;
    modal.innerHTML = `<div class="modal-card"><h2>One-time HomeServer activation bundle</h2><p class="help">Copy these values into the HomeServer Control Center now. VP3 will not display the credential or enrollment code again.</p><div class="secret-grid">
      <div class="secret-row"><span>Account ID</span><code>${accountId()}</code></div>
      <div class="secret-row"><span>Device public ID</span><code>${escapeHtml(bundle.device_public_id)}</code></div>
      <div class="secret-row"><span>Device credential</span><code>${escapeHtml(bundle.credential || "Unavailable on replay")}</code></div>
      <div class="secret-row"><span>Enrollment code</span><code>${escapeHtml(bundle.enrollment_code || "Unavailable on replay")}</code></div>
    </div><div class="modal-actions"><button id="copy-bundle" class="button primary" type="button">Copy Bundle</button><button id="close-bundle" class="button ghost" type="button">I Stored It</button></div></div>`;
    document.querySelector("#copy-bundle")?.addEventListener("click", copyBundle);
    document.querySelector("#close-bundle")?.addEventListener("click", () => { state.oneTimeBundle = null; renderModal(); });
  }

  async function copyBundle() {
    const bundle = state.oneTimeBundle;
    if (!bundle) return;
    const text = JSON.stringify({ account_id: accountId(), device_public_id: bundle.device_public_id, credential: bundle.credential, enrollment_code: bundle.enrollment_code }, null, 2);
    await navigator.clipboard.writeText(text);
    state.notice = { kind: "success", message: "One-time activation bundle copied." };
    render();
  }

  async function load() {
    state.busy = true;
    state.notice = null;
    render();
    try {
      const [fleet, options] = await Promise.all([
        api("/api/homeserver/v1/fleet.php"),
        api("/api/homeserver/v1/registration-options.php"),
      ]);
      state.fleet = fleet;
      state.options = Array.isArray(options?.licenses) ? options.licenses : [];
    } catch (error) {
      state.notice = { kind: "warning", message: String(error) };
    } finally {
      state.busy = false;
      render();
    }
  }

  async function register(event) {
    event.preventDefault();
    const licenseId = Number(document.querySelector("#register-license")?.value || 0);
    const fingerprint = document.querySelector("#register-fingerprint")?.value?.trim() || "";
    if (!licenseId || !/^[a-f0-9]{64}$/i.test(fingerprint)) {
      state.notice = { kind: "warning", message: "Select an eligible license and paste the 64-character HomeServer fingerprint." };
      render();
      return;
    }
    state.busy = true; render();
    try {
      state.oneTimeBundle = await api("/api/homeserver/v1/register.php", { license_id: licenseId, device_fingerprint: fingerprint, request_id: requestId(), idempotency_key: idempotencyKey() });
      document.querySelector("#register-form")?.reset();
      state.notice = { kind: "success", message: "HomeServer registered. Complete activation in Control Center using the one-time bundle." };
      await load();
    } catch (error) {
      state.notice = { kind: "warning", message: String(error) };
    } finally { state.busy = false; render(); }
  }

  async function deviceAction(event) {
    const action = event.currentTarget.dataset.action;
    const card = event.currentTarget.closest("[data-device]");
    const devicePublicId = card?.dataset.device || "";
    if (!devicePublicId) return;
    try {
      if (action === "suspend" || action === "resume") {
        const confirmation = window.prompt(`Type ${action === "suspend" ? "SUSPEND" : "RESUME"} to continue:`);
        if (confirmation !== (action === "suspend" ? "SUSPEND" : "RESUME")) return;
        await api("/api/homeserver/v1/suspend.php", { device_public_id: devicePublicId, suspended: action === "suspend", request_id: requestId() });
      } else if (action === "revoke") {
        if (window.prompt("Type REVOKE to permanently revoke this HomeServer:") !== "REVOKE") return;
        await api("/api/homeserver/v1/revoke.php", { device_public_id: devicePublicId, request_id: requestId() });
      } else if (action === "replace") {
        const fingerprint = window.prompt("Paste the replacement HomeServer's 64-character local fingerprint:");
        if (!fingerprint) return;
        state.oneTimeBundle = await api("/api/homeserver/v1/replace.php", { device_public_id: devicePublicId, replacement_fingerprint: fingerprint.trim(), request_id: requestId(), idempotency_key: idempotencyKey() });
      } else if (action === "transfer") {
        const target = Number(window.prompt("Enter the destination VP3 account ID:") || 0);
        if (!target) return;
        const transfer = await api("/api/homeserver/v1/transfer-request.php", { device_public_id: devicePublicId, target_account_id: target, request_id: requestId() });
        state.notice = { kind: "success", message: `Transfer created. Provide the one-time transfer code to the destination owner: ${transfer.transfer_code || "created"}` };
      }
      await load();
    } catch (error) {
      state.notice = { kind: "warning", message: String(error) };
      render();
    }
  }

  function bindActions() {
    document.querySelectorAll("[data-action]").forEach((button) => button.addEventListener("click", deviceAction, { once: true }));
  }

  document.querySelector("#register-form")?.addEventListener("submit", register);
  document.querySelector("#refresh-fleet")?.addEventListener("click", load);
  accountSelect?.addEventListener("change", load);
  load();
})();
