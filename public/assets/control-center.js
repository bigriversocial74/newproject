(() => {
  "use strict";

  const root = document.querySelector("[data-control-center]");
  if (!root) return;

  const page = root.dataset.page || "dashboard";
  const accountPublicId = String(root.dataset.accountPublicId || '');
  const csrfToken = root.dataset.csrfToken || "";
  const state = { snapshot: null, busy: false, notice: null, availabilityTimer: null };

  const escapeHtml = (value) => String(value ?? "")
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#039;");
  const humanize = (value) => String(value || "unknown").replaceAll("_", " ");
  const statusClass = (value) => humanize(value).replaceAll(" ", "-").toLowerCase();
  const formatDate = (value) => {
    if (!value) return "Not yet";
    const normalized = String(value).includes("T") ? String(value) : `${String(value).replace(" ", "T")}Z`;
    const date = new Date(normalized);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
  };
  const formatBytes = (value) => {
    let bytes = Number(value || 0);
    if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let index = 0;
    while (bytes >= 1024 && index < units.length - 1) { bytes /= 1024; index += 1; }
    return `${bytes.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
  };
  const formatMoney = (minor, currency = "USD") => new Intl.NumberFormat("en-US", {
    style: "currency", currency: String(currency || "USD").toUpperCase(),
  }).format(Number(minor || 0) / 100);
  const token = () => crypto.randomUUID();

  async function api(path, payload = {}, options = {}) {
    const body = { ...payload };
    const headers = { "Content-Type": "application/json", "X-CSRF-Token": csrfToken };
    if (options.request) {
      body.request_id = body.request_id || `vp3-ui-${token()}`;
      headers["X-Request-ID"] = body.request_id;
    }
    if (options.idempotency) {
      body.idempotency_key = body.idempotency_key || `vp3-ui-${token()}`;
      headers["Idempotency-Key"] = body.idempotency_key;
    }
    body.account_public_id = accountPublicId;
    body.csrf_token = csrfToken;
    const response = await fetch(path, {
      method: "POST", credentials: "same-origin", cache: "no-store", headers, body: JSON.stringify(body),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result?.error?.message || "The VP3 request failed.");
    return result.data;
  }

  function showNotice(message, kind = "success") {
    state.notice = { message, kind };
    const host = document.querySelector("#control-center-notice");
    if (host) host.innerHTML = `<div class="notice ${escapeHtml(kind)}">${escapeHtml(message)}</div>`;
  }

  function setBusy(busy) {
    state.busy = busy;
    root.classList.toggle("loading", busy);
    root.querySelectorAll("button").forEach((button) => { button.disabled = busy; });
  }

  const metric = (label, value, detailText = "") => `<article class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong>${detailText ? `<small>${escapeHtml(detailText)}</small>` : ""}</article>`;
  const status = (value) => `<span class="status ${escapeHtml(statusClass(value))}">${escapeHtml(humanize(value))}</span>`;
  const detail = (label, value) => `<div class="detail"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
  const withAccount = (path) => {
    const url = new URL(path, window.location.origin);
    url.searchParams.set("account", accountPublicId);
    return `${url.pathname}${url.search}${url.hash}`;
  };

  function renderDashboard(data) {
    const m = data.metrics;
    document.querySelector("#dashboard-metrics").innerHTML = [
      metric("Domains", m.domains_total, `${m.domains_active} active`),
      metric("PODs", m.pods_total, `${m.pods_active} active`),
      metric("HomeServers", m.homeservers_total, `${m.homeservers_online} online`),
      metric("Subscriptions", m.subscriptions_active, `${m.subscriptions_attention} need attention`),
      metric("Open incidents", m.open_incidents, `${m.critical_incidents} critical`),
      metric("Attention", data.attention.length, "Across the selected account"),
    ].join("");

    document.querySelector("#attention-count").textContent = String(data.attention.length);
    document.querySelector("#dashboard-attention").innerHTML = data.attention.length ? data.attention.map((item) => `
      <a class="attention ${escapeHtml(item.severity)}" href="${escapeHtml(withAccount(item.href))}">
        <span class="attention-bar"></span><span><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.detail)}</small></span><em>${escapeHtml(humanize(item.type))}</em>
      </a>`).join("") : '<div class="empty">No active account attention items.</div>';

    document.querySelector("#dashboard-estate").innerHTML = [
      ["Domains", `${m.domains_active}/${m.domains_total} active`, m.domains_attention, "/domains.php"],
      ["POD deployments", `${m.pods_active}/${m.pods_total} active`, m.pods_attention, "/pods.php"],
      ["HomeServers", `${m.homeservers_online}/${m.homeservers_total} online`, m.homeservers_attention, "/homeservers.php"],
    ].map(([label, summary, needs, href]) => `<a class="card soft card-link" href="${escapeHtml(withAccount(href))}"><div class="card-top"><div><h4>${escapeHtml(label)}</h4><p>${escapeHtml(summary)}</p></div>${needs ? status(`${needs} attention`) : status("healthy")}</div></a>`).join("");

    document.querySelector("#dashboard-subscriptions").innerHTML = data.subscriptions.length ? data.subscriptions.map((subscription) => `
      <article class="card"><div class="card-top"><div><h4>${escapeHtml(subscription.plan.name)}</h4><p>${escapeHtml(formatMoney(subscription.plan.price_minor, subscription.plan.currency))} / ${escapeHtml(subscription.plan.billing_interval)}</p></div>${status(subscription.status)}</div>
      <div class="detail-grid">${detail("Subscription", subscription.public_id)}${detail("Plan", subscription.plan.code)}${detail("Period ends", formatDate(subscription.current_period_ends_at))}${detail("Grace ends", formatDate(subscription.grace_ends_at))}</div></article>`).join("") : '<div class="empty">No subscriptions are registered.</div>';

    document.querySelector("#dashboard-incidents").innerHTML = data.incidents.length ? data.incidents.map((incident) => `
      <article class="card"><div class="card-top"><div><h4>${escapeHtml(incident.title)}</h4><p>${escapeHtml(humanize(incident.source_type))} · ${escapeHtml(formatDate(incident.last_detected_at))}</p></div>${status(incident.severity)}</div><div class="detail-grid">${detail("Status", humanize(incident.status))}${detail("Occurrences", incident.occurrence_count)}${detail("Incident", incident.public_id)}${detail("First detected", formatDate(incident.first_detected_at))}</div></article>`).join("") : '<div class="empty">No open account incidents.</div>';
  }

  function renderDomains(data) {
    const m = data.metrics;
    document.querySelector("#domain-metrics").innerHTML = [
      metric("Registered", m.domains_total), metric("Active", m.domains_active), metric("Attention", m.domains_attention),
      metric("With POD", data.domains.filter((d) => d.pod).length), metric("With HomeServer", data.domains.filter((d) => d.homeserver).length), metric("Open incidents", m.open_incidents),
    ].join("");

    const subscriptions = data.subscriptions.filter((item) => ["active", "trialing"].includes(item.status));
    document.querySelector("#domain-subscription").innerHTML = '<option value="">Choose an active subscription</option>' + subscriptions.map((item) => `<option value="${escapeHtml(item.public_id)}">${escapeHtml(item.plan.name)} · ${escapeHtml(item.public_id)}</option>`).join("");

    document.querySelector("#domain-list").innerHTML = data.domains.length ? data.domains.map((domain) => {
      const actions = [];
      if (domain.status === "reserved") actions.push(`<button class="button success" data-domain-action="activate_reserved" data-domain="${escapeHtml(domain.public_id)}">Activate Reservation</button>`);
      if (["active", "grace"].includes(domain.status)) actions.push(`<button class="button warning" data-domain-action="suspend" data-domain="${escapeHtml(domain.public_id)}">Suspend</button>`);
      if (["suspended", "expired", "reserved"].includes(domain.status)) actions.push(`<button class="button danger" data-domain-action="release" data-domain="${escapeHtml(domain.public_id)}" data-hostname="${escapeHtml(domain.hostname)}">Release</button>`);
      if (!domain.pod && domain.pod_license && ["active", "grace"].includes(domain.status)) actions.push(`<a class="button primary" href="${escapeHtml(withAccount(`/pods.php#provision-${domain.public_id}`))}">Provision POD</a>`);
      return `<article class="card" id="${escapeHtml(domain.public_id)}"><div class="card-top"><div><h4>${escapeHtml(domain.hostname)}</h4><p>${escapeHtml(domain.public_id)} · ${escapeHtml(domain.subscription.plan_name)}</p></div>${status(domain.status)}</div>
        <div class="detail-grid">${detail("Routing", humanize(domain.routing_status))}${detail("SSL", humanize(domain.ssl_status))}${detail("POD license", domain.pod_license ? humanize(domain.pod_license.status) : "Not issued")}${detail("HomeServer", domain.homeserver ? humanize(domain.homeserver.status) : "Not registered")}${detail("POD", domain.pod ? humanize(domain.pod.status) : "Not provisioned")}${detail("Renews", formatDate(domain.renews_at))}${detail("Expires", formatDate(domain.expires_at))}${detail("Administrative holds", domain.active_holds)}</div>
        <div class="actions">${actions.join("")}</div></article>`;
    }).join("") : '<div class="empty">No Domains are registered for this account.</div>';
  }

  function renderPods(data) {
    const m = data.metrics;
    document.querySelector("#pod-metrics").innerHTML = [
      metric("Deployments", m.pods_total), metric("Active", m.pods_active), metric("Attention", m.pods_attention),
      metric("Routing active", data.pods.filter((p) => p.routing_status === "active").length), metric("SSL active", data.pods.filter((p) => p.ssl_status === "active").length), metric("Backups verified", data.pods.filter((p) => p.backup_status === "verified").length),
    ].join("");

    const eligible = data.domains.filter((domain) => !domain.pod && domain.pod_license && ["active", "grace"].includes(domain.status) && ["active", "grace"].includes(domain.pod_license.status));
    document.querySelector("#pod-domain").innerHTML = '<option value="">Choose an eligible Domain</option>' + eligible.map((domain) => `<option value="${escapeHtml(domain.public_id)}">${escapeHtml(domain.hostname)} · ${escapeHtml(domain.pod_license.public_id)}</option>`).join("");

    document.querySelector("#pod-list").innerHTML = data.pods.length ? data.pods.map((pod) => {
      const job = pod.latest_job;
      const actions = [];
      if (job && ["queued", "running", "retrying", "waiting"].includes(job.status)) actions.push(`<button class="button warning" data-pod-action="pause" data-job="${escapeHtml(job.public_id)}">Pause Job</button>`);
      if (job && job.status === "paused") actions.push(`<button class="button success" data-pod-action="resume" data-job="${escapeHtml(job.public_id)}">Resume Job</button>`);
      if (job && job.status === "failed") actions.push(`<button class="button warning" data-pod-action="retry" data-job="${escapeHtml(job.public_id)}">Retry Job</button>`);
      if (["active", "degraded", "failed", "suspended"].includes(pod.status)) actions.push(`<button class="button danger" data-pod-action="rollback" data-deployment="${escapeHtml(pod.public_id)}" data-hostname="${escapeHtml(pod.domain.hostname)}">Queue Rollback</button>`);
      const percentage = Math.min(100, Math.max(0, Number(pod.storage_usage_percent)));
      const progressClass = percentage >= 90 ? "storage-progress danger" : "storage-progress";
      return `<article class="card" id="${escapeHtml(pod.public_id)}"><div class="card-top"><div><h4>${escapeHtml(pod.domain.hostname)}</h4><p>${escapeHtml(pod.public_id)} · ${escapeHtml(pod.installed_version || "Installation pending")}</p></div>${status(pod.status)}</div>
        <div class="detail-grid">${detail("Routing", humanize(pod.routing_status))}${detail("SSL", humanize(pod.ssl_status))}${detail("Backup", humanize(pod.backup_status))}${detail("License", humanize(pod.license_status))}${detail("Update channel", pod.update_channel)}${detail("Heartbeat", formatDate(pod.last_heartbeat_at))}${detail("Latest job", job ? `${humanize(job.status)} · ${humanize(job.current_stage || job.job_type)}` : "No job")}${detail("Attempts", job ? job.attempts : 0)}</div>
        <div><p class="subtle">Storage ${escapeHtml(formatBytes(pod.storage_usage_bytes))} of ${escapeHtml(formatBytes(pod.storage_allowance_bytes))} · ${escapeHtml(pod.storage_usage_percent)}%</p><progress class="${progressClass}" max="100" value="${percentage}">${percentage}%</progress></div>
        ${job?.requires_attention ? '<div class="notice danger section-space">The latest worker attempt requires attention. Review Operations for customer-safe evidence.</div>' : ""}
        <div class="actions section-space">${actions.join("")}</div></article>`;
    }).join("") : '<div class="empty">No POD deployments exist for this account.</div>';
  }

  function render() {
    const data = state.snapshot;
    if (!data) return;
    if (page === "dashboard") renderDashboard(data);
    if (page === "domains") renderDomains(data);
    if (page === "pods") renderPods(data);
    if (state.notice) showNotice(state.notice.message, state.notice.kind);
  }

  async function load() {
    setBusy(true);
    try {
      state.snapshot = await api("/api/control-center/v1/overview.php");
      render();
    } catch (error) {
      showNotice(error instanceof Error ? error.message : "Unable to load the VP3 account.", "danger");
    } finally {
      setBusy(false);
    }
  }

  function modal(title, body, confirmLabel, confirmClass = "danger", collect = () => true) {
    const host = document.querySelector("#control-center-modal");
    if (!host) return Promise.resolve(false);
    return new Promise((resolve) => {
      host.hidden = false;
      host.innerHTML = `<section class="modal-card"><h3>${escapeHtml(title)}</h3>${body}<div class="modal-actions"><button type="button" class="button ghost" data-modal-cancel>Cancel</button><button type="button" class="button ${escapeHtml(confirmClass)}" data-modal-confirm>${escapeHtml(confirmLabel)}</button></div></section>`;
      const close = (value) => { host.hidden = true; host.innerHTML = ""; resolve(value); };
      host.querySelector("[data-modal-cancel]").addEventListener("click", () => close(false));
      host.querySelector("[data-modal-confirm]").addEventListener("click", () => {
        try { close(collect(host)); } catch (error) { showNotice(error instanceof Error ? error.message : "The confirmation is invalid.", "danger"); }
      });
      host.addEventListener("click", (event) => { if (event.target === host) close(false); }, { once: true });
    });
  }

  document.querySelector("#refresh-control-center")?.addEventListener("click", load);

  document.querySelector("#domain-label")?.addEventListener("input", (event) => {
    const preview = document.querySelector("#domain-preview");
    const label = String(event.target.value || "").trim().toLowerCase();
    clearTimeout(state.availabilityTimer);
    preview.className = "help";
    if (label.length < 3) { preview.textContent = "Enter at least three characters."; return; }
    preview.textContent = `Checking ${label}.vp3.me…`;
    state.availabilityTimer = setTimeout(async () => {
      try {
        const result = await api("/api/control-center/v1/domain-action.php", { action: "availability", label });
        preview.textContent = result.available ? `${result.hostname} is available.` : `${result.hostname} is already registered.`;
        preview.className = result.available ? "help" : "notice danger";
      } catch (error) {
        preview.className = "notice danger";
        preview.textContent = error instanceof Error ? error.message : "Unable to check availability.";
      }
    }, 320);
  });

  document.querySelector("#domain-register-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    setBusy(true);
    try {
      const result = await api("/api/control-center/v1/domain-action.php", {
        action: "register", subscription_public_id: document.querySelector("#domain-subscription").value, label: document.querySelector("#domain-label").value,
      }, { request: true, idempotency: true });
      showNotice(`${result.hostname} was registered with paired POD and HomeServer licenses.`);
      event.target.reset();
      await load();
    } catch (error) { showNotice(error instanceof Error ? error.message : "Unable to register the Domain.", "danger"); } finally { setBusy(false); }
  });

  document.querySelector("#pod-provision-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    setBusy(true);
    try {
      const result = await api("/api/control-center/v1/pod-action.php", {
        action: "provision", domain_public_id: document.querySelector("#pod-domain").value,
      }, { request: true, idempotency: true });
      showNotice(`POD provisioning job ${result.job_public_id} was queued.`);
      event.target.reset();
      await load();
    } catch (error) { showNotice(error instanceof Error ? error.message : "Unable to queue POD provisioning.", "danger"); } finally { setBusy(false); }
  });

  root.addEventListener("click", async (event) => {
    const domainButton = event.target.closest("[data-domain-action]");
    const podButton = event.target.closest("[data-pod-action]");
    if (!domainButton && !podButton) return;
    event.preventDefault();

    if (domainButton) {
      const action = domainButton.dataset.domainAction;
      const payload = { action, domain_public_id: domainButton.dataset.domain };
      if (action === "suspend") {
        const result = await modal(
          "Suspend Domain",
          '<p class="subtle">Suspension is non-destructive but disables the Domain and paired entitlements until repaired.</p><label class="form"><span>Reason</span><textarea id="modal-reason" maxlength="500" placeholder="Operational or billing reason"></textarea></label>',
          "Suspend", "warning",
          (host) => {
            const reason = String(host.querySelector("#modal-reason")?.value || "").trim();
            if (!reason) throw new Error("A suspension reason is required.");
            return { reason };
          }
        );
        if (!result) return;
        payload.reason = result.reason;
      }
      if (action === "release") {
        const ok = await modal("Release Domain", `<div class="notice danger">Release ${escapeHtml(domainButton.dataset.hostname)} and terminate its active Domain lifecycle. This action requires the exact server-side confirmation.</div>`, "Release Domain");
        if (!ok) return;
        payload.confirmation = "RELEASE";
      }
      setBusy(true);
      try {
        await api("/api/control-center/v1/domain-action.php", payload, { request: true, idempotency: true });
        showNotice(`Domain action ${humanize(action)} completed.`);
        await load();
      } catch (error) { showNotice(error instanceof Error ? error.message : "Unable to complete the Domain action.", "danger"); } finally { setBusy(false); }
    }

    if (podButton) {
      const action = podButton.dataset.podAction;
      const payload = { action, job_public_id: podButton.dataset.job, deployment_public_id: podButton.dataset.deployment };
      if (action === "rollback") {
        const ok = await modal("Queue POD Rollback", `<div class="notice danger">Queue a verified rollback for ${escapeHtml(podButton.dataset.hostname)}. The durable worker will perform the rollback and verification.</div>`, "Queue Rollback");
        if (!ok) return;
        payload.confirmation = "ROLLBACK";
      }
      setBusy(true);
      try {
        const result = await api("/api/control-center/v1/pod-action.php", payload, { request: true, idempotency: action === "rollback" });
        showNotice(action === "rollback" ? `Rollback job ${result.job_public_id} was queued.` : `POD job ${humanize(action)} completed.`);
        await load();
      } catch (error) { showNotice(error instanceof Error ? error.message : "Unable to complete the POD action.", "danger"); } finally { setBusy(false); }
    }
  });

  load();
})();
