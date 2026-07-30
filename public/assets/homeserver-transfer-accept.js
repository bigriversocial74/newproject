(() => {
  "use strict";

  const root = document.querySelector("[data-homeserver-fleet]");
  const stack = root?.querySelector(".grid.two > aside.grid");
  const accountSelect = document.querySelector("#control-center-account");
  if (!root || !stack || !accountSelect) return;

  const csrfToken = root.dataset.csrfToken || "";
  const escapeHtml = (value) => String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
  const accountId = () => Number(accountSelect.value || root.dataset.accountId || 0);
  const requestId = () => `vp3-transfer-${crypto.randomUUID()}`;
  let licenses = [];

  const card = document.createElement("article");
  card.className = "panel";
  card.innerHTML = `<header class="panel-head"><div><h3>Accept Transfer</h3><p>Move an authorized HomeServer into this VP3 account.</p></div></header><form id="accept-transfer-form" class="form"><label><span>One-time transfer code</span><input id="accept-transfer-code" type="password" minlength="12" maxlength="64" autocomplete="new-password" required></label><label><span>Destination license</span><select id="accept-transfer-license" required><option value="">Loading eligible licenses…</option></select></label><p class="help">Acceptance rotates the device credential, revokes previous VP3 authority, and creates a new one-time activation bundle for the destination owner.</p><button class="button primary" type="submit">Accept Transfer</button></form>`;
  stack.append(card);

  async function api(path, payload = {}) {
    const body = { ...payload, account_id: accountId(), csrf_token: csrfToken };
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
      body: JSON.stringify(body),
    });
    const responseBody = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(responseBody?.error?.message || `VP3 request failed with HTTP ${response.status}`);
    return responseBody.data;
  }

  async function loadLicenses() {
    try {
      const options = await api("/api/homeserver/v1/registration-options.php");
      licenses = Array.isArray(options?.licenses) ? options.licenses : [];
      const select = card.querySelector("#accept-transfer-license");
      select.innerHTML = `<option value="">Select eligible license</option>${licenses.map((license) => `<option value="${Number(license.license_id)}">${escapeHtml(license.hostname)} · ${escapeHtml(license.license_public_id)}</option>`).join("")}`;
    } catch (error) {
      const select = card.querySelector("#accept-transfer-license");
      select.innerHTML = `<option value="">${escapeHtml(error instanceof Error ? error.message : "Unable to load licenses")}</option>`;
    }
  }

  function showBundle(bundle) {
    const bundleAccountId = accountId();
    let modal = document.querySelector("#transfer-secret-modal");
    if (!modal) {
      modal = document.createElement("div");
      modal.id = "transfer-secret-modal";
      modal.className = "modal";
      document.body.append(modal);
    }
    modal.hidden = false;
    modal.innerHTML = `<div class="modal-card"><h3>Transferred HomeServer activation bundle</h3><p class="help">These rotated values are displayed once. Paste them into the transferred HomeServer's Control Center now.</p><div class="secret-grid"><div class="secret-row"><span>Account ID</span><code>${bundleAccountId}</code></div><div class="secret-row"><span>Device public ID</span><code>${escapeHtml(bundle.device_public_id)}</code></div><div class="secret-row"><span>Device credential</span><code>${escapeHtml(bundle.credential)}</code></div><div class="secret-row"><span>Enrollment code</span><code>${escapeHtml(bundle.enrollment_code)}</code></div></div><div class="modal-actions"><button id="copy-transfer-bundle" class="button primary" type="button">Copy Bundle</button><button id="close-transfer-bundle" class="button ghost" type="button">I Stored It</button></div></div>`;
    modal.querySelector("#copy-transfer-bundle")?.addEventListener("click", async () => {
      await navigator.clipboard.writeText(JSON.stringify({ account_id: bundleAccountId, device_public_id: bundle.device_public_id, credential: bundle.credential, enrollment_code: bundle.enrollment_code }, null, 2));
    });
    modal.querySelector("#close-transfer-bundle")?.addEventListener("click", () => {
      modal.innerHTML = "";
      modal.hidden = true;
    });
  }

  card.querySelector("#accept-transfer-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const codeInput = card.querySelector("#accept-transfer-code");
    const code = codeInput?.value?.trim() || "";
    const licenseId = Number(card.querySelector("#accept-transfer-license")?.value || 0);
    if (!code || !licenseId) return;
    const button = event.currentTarget.querySelector("button[type=submit]");
    button.disabled = true;
    try {
      const bundle = await api("/api/homeserver/v1/transfer-accept.php", { transfer_code: code, target_license_id: licenseId, request_id: requestId() });
      codeInput.value = "";
      showBundle(bundle);
      await loadLicenses();
      document.querySelector("#refresh-fleet")?.click();
    } catch (error) {
      window.alert(error instanceof Error ? error.message : "Unable to accept the HomeServer transfer.");
    } finally {
      button.disabled = false;
    }
  });

  loadLicenses();
})();
