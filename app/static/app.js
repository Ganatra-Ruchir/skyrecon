/* SkyRecon console. No framework, no build step, no inline handlers (CSP-safe). */
(() => {
  "use strict";

  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const SEV = ["critical", "high", "medium", "low", "info"];
  const SEV_COLOR = {
    critical: "#f87171", high: "#fb923c", medium: "#fbbf24",
    low: "#38bdf8", info: "#61728a",
  };

  // Tokens live in memory only: a page reload requires signing in again, and
  // nothing sensitive is left in localStorage for another script to read.
  const auth = { access: null, refresh: null, role: null, email: null };

  const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  async function api(path, { method = "GET", body, raw = false } = {}) {
    const res = await fetch(path, {
      method,
      headers: {
        ...(body ? { "Content-Type": "application/json" } : {}),
        ...(auth.access ? { Authorization: `Bearer ${auth.access}` } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    if (res.status === 401 && auth.refresh && path !== "/api/auth/refresh") {
      if (await renew()) return api(path, { method, body, raw });
      signOut();
      throw new Error("session expired");
    }
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = (await res.json()).detail ?? detail; } catch { /* non-JSON */ }
      throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
    }
    return raw ? res.text() : (res.status === 204 ? null : res.json());
  }

  async function renew() {
    try {
      const r = await fetch("/api/auth/refresh", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: auth.refresh }),
      });
      if (!r.ok) return false;
      const t = await r.json();
      auth.access = t.access_token; auth.refresh = t.refresh_token;
      return true;
    } catch { return false; }
  }

  /* ── sign in ─────────────────────────────────────────── */
  $("#login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = $("#login-error"); err.textContent = "";
    $("#login-btn").disabled = true;
    try {
      const body = {
        email: $("#email").value.trim(),
        password: $("#password").value,
      };
      const code = $("#totp").value.trim();
      if (code) body.totp = code;

      const t = await api("/api/auth/login", { method: "POST", body });
      auth.access = t.access_token; auth.refresh = t.refresh_token; auth.role = t.role;
      const me = await api("/api/auth/me");
      auth.email = me.email;
      $("#who-email").textContent = me.email;
      $("#who-role").textContent = me.role;
      $("#login").hidden = true;
      $("#app").hidden = false;
      refreshAll();
    } catch (ex) {
      err.textContent = ex.message;
      if (/second factor/i.test(ex.message)) $("#totp-wrap").hidden = false;
    } finally {
      $("#login-btn").disabled = false;
    }
  });

  function signOut() {
    if (auth.refresh) {
      fetch("/api/auth/logout", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: auth.refresh }),
      }).catch(() => {});
    }
    auth.access = auth.refresh = auth.role = null;
    $("#app").hidden = true; $("#login").hidden = false;
    $("#password").value = "";
  }
  $("#logout").addEventListener("click", signOut);

  /* ── navigation ──────────────────────────────────────── */
  $("#tabs").addEventListener("click", (e) => {
    const tab = e.target.closest(".tab");
    if (!tab) return;
    $$(".tab").forEach((t) => t.classList.toggle("on", t === tab));
    $$(".view").forEach((v) => v.classList.toggle("on", v.dataset.view === tab.dataset.view));
    load(tab.dataset.view);
  });

  /* ── renderers ───────────────────────────────────────── */
  function bars(host, entries, colorFor) {
    const max = Math.max(1, ...entries.map(([, v]) => v));
    host.innerHTML = entries.map(([label, value]) => `
      <div class="bar-row">
        <span class="lbl">${esc(label)}</span>
        <span class="bar-track"><span class="bar-fill${value ? "" : " zero"}"
          style="width:${(value / max) * 100}%; background:${colorFor(label)}"></span></span>
        <span class="val">${value}</span>
      </div>`).join("") || `<p class="empty">no data yet</p>`;
  }

  async function loadOverview() {
    const s = await api("/api/stats");
    $("#kpis").innerHTML = `
      <div class="kpi"><div class="n">${s.indicators}</div><div class="k">Indicators</div></div>
      <div class="kpi ${s.alerts_open ? "crit" : "ok"}"><div class="n">${s.alerts_open}</div><div class="k">Open alerts</div></div>
      <div class="kpi"><div class="n">${s.events_24h}</div><div class="k">Events · 24h</div></div>
      <div class="kpi ok"><div class="n">${s.rules_enabled}</div><div class="k">Rules enabled</div></div>
      <div class="kpi warn"><div class="n">${s.alerts_total}</div><div class="k">Alerts all time</div></div>`;

    const title = (k) => k.charAt(0).toUpperCase() + k.slice(1);
    bars($("#sev-chart"), SEV.map((k) => [title(k), s.by_severity[k] || 0]),
         (k) => SEV_COLOR[k.toLowerCase()]);
    bars($("#mitre-chart"),
      Object.entries(s.mitre_coverage).filter(([, v]) => v > 0),
      () => "#a78bfa");

    $("#top-iocs tbody").innerHTML = s.top_indicators.length
      ? s.top_indicators.map((i) => `<tr>
          <td class="ioc">${esc(i.value)}</td>
          <td><span class="pill">${esc(i.type)}</span></td>
          <td class="mono">${i.hits} hits</td></tr>`).join("")
      : `<tr><td class="empty" colspan="3">nothing observed yet</td></tr>`;
  }

  async function loadIndicators() {
    const type = $("#filter-type").value;
    const rows = await api(`/api/indicators?limit=200${type ? `&ioc_type=${type}` : ""}`);
    $("#ioc-table tbody").innerHTML = rows.length ? rows.map((i) => {
      const why = (i.enrichment?.reasons || []).slice(0, 2).join("; ");
      const sig = i.enrichment?.signals || {};
      const location = [sig.geo_city, sig.geo_region, sig.geo_country_code]
        .filter(Boolean).join(", ");
      return `<tr>
        <td class="ioc">${esc(i.defanged)}</td>
        <td><span class="pill">${esc(i.ioc_type)}</span></td>
        <td><span class="pill sev-${esc(i.severity)}">${esc(i.severity)}</span></td>
        <td class="mono">${i.effective_confidence}</td>
        <td class="mono">${i.risk_score}</td>
        <td class="mono">${i.hit_count}</td>
        <td>${esc(location) || "—"}</td>
        <td class="why">${esc(why) || "—"}</td></tr>`;
    }).join("") : `<tr><td class="empty" colspan="8">no indicators stored yet</td></tr>`;
  }

  const LABEL = {
    rule: "Rule", description: "Why it fired", indicator: "Indicator",
    type: "Type", confidence: "Confidence", reasons: "Signals",
    anomaly: "Anomaly score", occurrences: "Occurrences",
  };

  function detailBlock(detail) {
    const rows = Object.entries(detail)
      .filter(([, v]) => v !== null && v !== undefined && v !== "" &&
                         !(Array.isArray(v) && !v.length))
      .map(([k, v]) => {
        const value = Array.isArray(v)
          ? v.map((x) => `<span class="chip">${esc(String(x))}</span>`).join("")
          : esc(String(v));
        return `<div class="dt">${esc(LABEL[k] || k)}</div><div class="dd">${value}</div>`;
      }).join("");
    return rows ? `<div class="alert-detail">${rows}</div>` : "";
  }

  async function loadAlerts() {
    const state = $("#filter-state").value;
    const rows = await api(`/api/alerts${state ? `?state=${state}` : ""}`);
    const host = $("#alert-list");
    if (!rows.length) { host.innerHTML = `<p class="empty">queue is clear</p>`; return; }

    host.innerHTML = rows.map((a) => `
      <article class="alert ${esc(a.severity)}">
        <div class="alert-head">
          <span class="alert-title">${esc(a.title)}</span>
          <span class="pill sev-${esc(a.severity)}">${esc(a.severity)} · ${a.score}</span>
        </div>
        <div class="alert-meta">
          <span>${new Date(a.created_at).toLocaleString()}</span>
          <span>state: ${esc(a.state)}</span>
          ${a.occurrences > 1 ? `<span class="rep">seen ${a.occurrences}×</span>` : ""}
          ${a.mitre.map((m) => `<span class="tech" title="${esc(m.name)}">${esc(m.id)} ${esc(m.tactic)}</span>`).join("")}
        </div>
        ${a.detail ? detailBlock(a.detail) : ""}
        ${a.state === "open" ? `<div class="alert-actions">
          <button class="btn ghost sm triage" data-id="${esc(a.id)}" data-state="triaged">Acknowledge</button>
          <button class="btn ghost sm triage" data-id="${esc(a.id)}" data-state="resolved">Resolve</button>
          <button class="btn ghost sm triage" data-id="${esc(a.id)}" data-state="false_positive">False positive</button>
        </div>` : ""}
      </article>`).join("");
  }

  $("#alert-list").addEventListener("click", async (e) => {
    const btn = e.target.closest(".triage");
    if (!btn) return;
    btn.disabled = true;
    try {
      await api(`/api/alerts/${btn.dataset.id}/triage`, {
        method: "POST", body: { state: btn.dataset.state },
      });
      loadAlerts(); loadOverview();
    } catch (ex) { status(ex.message); btn.disabled = false; }
  });

  async function loadRules() {
    const rows = await api("/api/rules");
    $("#rule-list").innerHTML = rows.map((r) => `
      <div class="rule">
        <div class="rule-name">
          <span>${esc(r.name)}</span>
          <span class="pill sev-${esc(r.severity)}">${esc(r.severity)}${r.enabled ? "" : " · off"}</span>
        </div>
        <div class="rule-desc">${esc(r.description)}</div>
        <div class="rule-expr">${esc(r.expression)}</div>
        <div class="alert-meta" style="margin-top:8px">
          <span>${r.hit_count} hits</span>
          ${r.mitre.map((m) => `<span class="tech">${esc(m.id)}</span>`).join("")}
        </div>
      </div>`).join("") || `<p class="empty">no rules configured</p>`;
  }

  async function loadAudit() {
    const a = await api("/api/admin/audit?limit=120").catch(() => null);
    if (!a) {
      $("#chain-state").textContent = "requires admin";
      $("#audit-table tbody").innerHTML = `<tr><td class="empty" colspan="6">your role cannot read the audit trail</td></tr>`;
      return;
    }
    const chip = $("#chain-state");
    chip.textContent = a.chain_intact ? "chain verified" : `BROKEN at #${a.first_tampered_seq}`;
    chip.className = `chain ${a.chain_intact ? "ok" : "bad"}`;
    $("#audit-table tbody").innerHTML = a.entries.map((e) => `<tr>
      <td class="mono">${e.seq}</td>
      <td class="mono">${new Date(e.at).toLocaleString()}</td>
      <td>${esc(e.action)}</td>
      <td class="mono">${esc((e.target || "—").slice(0, 12))}</td>
      <td class="mono">${esc(e.outcome)}</td>
      <td class="mono">${esc(e.hash)}</td></tr>`).join("");
  }

  /* ── bulk ingest ─────────────────────────────────────── */
  $("#bulk-go").addEventListener("click", async () => {
    const text = $("#bulk-text").value.trim();
    if (!text) return;
    const out = $("#bulk-out");
    out.hidden = false; out.textContent = "extracting…";
    try {
      const r = await api("/api/indicators/bulk", {
        method: "POST",
        body: {
          text, source: $("#bulk-source").value || "report",
          severity: $("#bulk-severity").value, tags: [],
        },
      });
      out.textContent =
        `extracted ${r.extracted}\nstored    ${r.created.length}\n` +
        `reinforced ${r.reinforced.length}\n` +
        (r.rejected.length ? `discarded  ${r.rejected.length} (noise or invalid)\n` : "") +
        (r.created.length ? `\n${r.created.slice(0, 12).join("\n")}` : "");
      loadIndicators(); loadOverview();
    } catch (ex) { out.textContent = `error: ${ex.message}`; }
  });

  /* ── exports ─────────────────────────────────────────── */
  for (const [id, fmt] of [["#export-stix", "stix"], ["#export-csv", "csv"]]) {
    $(id).addEventListener("click", async () => {
      try {
        const body = await api(`/api/indicators/export/${fmt}?min_confidence=1`, { raw: true });
        const blob = new Blob([body], { type: "application/octet-stream" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `skyrecon-indicators.${fmt === "stix" ? "json" : "csv"}`;
        a.click();
        URL.revokeObjectURL(url);
      } catch (ex) { status(ex.message); }
    });
  }

  $("#filter-type").addEventListener("change", loadIndicators);
  $("#filter-state").addEventListener("change", loadAlerts);

  function status(msg) { $("#foot-status").textContent = msg; }

  const LOADERS = {
    overview: loadOverview, indicators: loadIndicators,
    alerts: loadAlerts, rules: loadRules, audit: loadAudit,
  };
  async function load(view) {
    try { await LOADERS[view](); status("connected"); }
    catch (ex) { status(ex.message); }
  }
  function refreshAll() { load("overview"); }

  // Keep the overview honest without hammering the API.
  setInterval(() => {
    if (!auth.access || $("#app").hidden) return;
    const active = $(".tab.on")?.dataset.view;
    if (active === "overview" || active === "alerts") load(active);
  }, 20000);
})();
