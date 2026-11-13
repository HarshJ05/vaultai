// VaultAI front end. Plain JavaScript, no framework: it calls the FastAPI endpoints
// and animates the results. All privacy logic lives on the server.

const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const pace = (ms) => (REDUCED ? 0 : ms);

const EXAMPLES = [
  "Hi, I'm Rohan Mehta. Please update my KYC: Aadhaar 2345 6789 0124, PAN ABCPM1234K. " +
  "Send the refund to account 50100123456789 (IFSC HDFC0001234) or to rohan@okaxis. " +
  "Call me on +91 98765 43210 if anything is missing.",
  "Draft a short welcome email to Priya Sharma (priya.sharma@acme.in) confirming her joining date. " +
  "She lives in Sector 45, Gurugram 122003, her DOB is 14/08/1999 and her phone is 9123456780. " +
  "Her laptop request is order ID 4521 8890 3321.",
  "Summarise the main benefits of retrieval-augmented generation for a customer support team in three bullet points.",
];

let framework = "DPDP";
let lastScanCount = 0;
let lastStats = {};

// ---- session id: one per browser tab; survives reloads when storage works ----
const newId = () => (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + Math.random().toString(16).slice(2));
let sessionId;
try { sessionId = sessionStorage.getItem("vaultai_sid") || newId(); sessionStorage.setItem("vaultai_sid", sessionId); }
catch { sessionId = newId(); }

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const d = data.detail;
    const msg = (d && d.message) || (Array.isArray(d) ? d.map((x) => x.msg).join("; ") : "") || `Request failed (${res.status})`;
    throw Object.assign(new Error(msg), { code: d && d.code });
  }
  return data;
}

// =========================================================================
// Header, region and transfer check
// =========================================================================
async function loadHealth() {
  const h = await api("/api/health");
  const llm = h.llm_mode === "gemini"
    ? `<span class="chip ok">AI model: ${esc(h.model)}</span>`
    : `<span class="chip warn" title="Set GEMINI_API_KEY to use a real model">AI model: demo mode</span>`;
  $("status").innerHTML = llm +
    `<span class="chip ${h.ner ? "ok" : "warn"}">Auto-detect: ${h.ner ? "on" : "patterns only"}</span>` +
    `<span class="chip">Tokens: ${h.token_style === "typed" ? "typed" : "random"}</span>`;
  $("erasureNote").textContent = h.notes.erasure;
  $("region").innerHTML = Object.entries(h.regions)
    .map(([code, label]) => `<option value="${code}"${code === "IN" ? " selected" : ""}>${esc(label)}</option>`).join("");
  $("nodeModel").textContent = h.llm_mode === "gemini" ? "sees tokens only" : "demo model, tokens only";
}

async function refreshTransfer() {
  $("safeguardsWrap").hidden = framework !== "GDPR";
  const q = new URLSearchParams({ region: $("region").value, framework, safeguards: $("safeguards").checked });
  try {
    const t = await api(`/api/transfer-check?${q}`);
    const pill = $("transferPill");
    pill.className = "pill " + (t.allowed ? "ok" : "bad");
    pill.textContent = t.allowed ? "Transfer allowed" : "Transfer blocked";
    pill.title = t.basis;
  } catch { /* ignore */ }
}

// =========================================================================
// Stats (count up when they change)
// =========================================================================
async function refreshStats() {
  try {
    const s = await api(`/api/stats/${sessionId}`);
    document.querySelectorAll(".stat .num").forEach((el) => {
      const k = el.dataset.k, to = s[k] ?? 0, from = lastStats[k] ?? 0;
      if (to === from && el.textContent === String(to)) return;
      countUp(el, from, to);
    });
    lastStats = s;
  } catch { /* ignore */ }
}
function countUp(el, from, to) {
  if (REDUCED || from === to) { el.textContent = to; return; }
  const t0 = performance.now(), dur = 600;
  const tick = (now) => {
    const p = Math.min(1, (now - t0) / dur);
    el.textContent = Math.round(from + (to - from) * (1 - Math.pow(1 - p, 3)));
    if (p < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
  el.classList.remove("bump"); void el.offsetWidth; el.classList.add("bump");
}

// =========================================================================
// Live detection while typing
// =========================================================================
function renderHighlight(text, entities, mapping = []) {
  if (!text.trim()) { $("highlight").innerHTML = '<span class="muted small">Detected personal data will be marked here.</span>'; return; }
  const phAt = new Map(mapping.map((m) => [m.start, m.placeholder]));
  let html = "", pos = 0;
  for (const e of entities) {
    html += esc(text.slice(pos, e.start));
    const ph = phAt.get(e.start);
    html += `<mark class="sens${e.redacted ? "" : " skip"}"${ph ? ` data-ph="${esc(ph)}"` : ""} title="${ph ? `Sent to the AI as ${esc(ph)}` : "Sensitive · will be tokenized"}">` +
      `${esc(text.slice(e.start, e.end))}</mark>`;
    pos = e.end;
  }
  $("highlight").innerHTML = html + esc(text.slice(pos));
}

function renderEntities(entities) {
  $("entityList").innerHTML = entities.map((e) => `
    <div class="ent">
      <span class="tag">${esc(e.type)}</span>
      <span class="why" title="${esc(e.reasons.join(" · "))}">${esc(e.reasons.join(" · "))}${e.redacted ? "" : " · kept (context only)"}</span>
      <span class="conf">${Math.round(e.score * 100)}%</span>
    </div>`).join("");
  const n = entities.filter((e) => e.redacted).length;
  lastScanCount = n;
  $("liveCount").textContent = n ? `${n} sensitive item${n > 1 ? "s" : ""} found · will be tokenized before sending` : "No personal data found";
  $("detailsBox").hidden = !entities.length;
}

function renderRisk(r) {
  $("riskbar").hidden = false;
  $("riskFill").style.width = `${r.score}%`;
  $("riskScore").textContent = `${r.score} · ${r.level}`;
}

let scanTimer;
function scheduleScan() {
  clearTimeout(scanTimer);
  scanTimer = setTimeout(async () => {
    const text = $("input").value;
    if (!text.trim()) { renderHighlight("", []); $("entityList").innerHTML = ""; $("riskbar").hidden = true; $("detailsBox").hidden = true; return; }
    try {
      const r = await api("/api/scan", { method: "POST", body: { text } });
      renderHighlight(text, r.entities); renderEntities(r.entities); renderRisk(r.risk);
    } catch { /* ignore while typing */ }
  }, 280);
}

// =========================================================================
// The animated data path
// =========================================================================
const nodes = () => [...document.querySelectorAll("#flow .node")];
const wires = () => [...document.querySelectorAll("#flow .wire")];

function resetFlow() {
  $("flow").classList.remove("idle");
  nodes().forEach((n) => { n.classList.remove("active", "done", "blocked"); n.querySelector(".nm").textContent = ""; });
  wires().forEach((w) => w.classList.remove("live", "done"));
  document.querySelectorAll(".step").forEach((s) => s.classList.remove("lit", "reveal"));
}
function setNode(i, state, metric) {
  const n = nodes()[i];
  n.classList.remove("active", "done", "blocked");
  n.classList.add(state);
  if (metric !== undefined) n.querySelector(".nm").textContent = metric;
}
async function runWire(i, ms = 380) {
  const w = wires()[i];
  w.classList.add("live");
  await sleep(pace(ms));
  w.classList.remove("live"); w.classList.add("done");
}
function lightStep(s, html) {
  const step = document.querySelector(`.step[data-s="${s}"]`);
  const box = step.querySelector(".box");
  box.innerHTML = html;
  step.classList.remove("reveal"); void step.offsetWidth;
  step.classList.add("lit", "reveal");
}

// Token chips pop in one after another
function tokenHtml(text) {
  let i = 0;
  return esc(text)
    .replace(/\[\[V_([A-Z0-9]+)\]\]/g, (_, id) =>
      `<span class="ph tok pop" style="--d:${(i++ * 0.06).toFixed(2)}s" data-ph="[[V_${id}]]" title="Random token · hover to trace it">[[V_${id}]]</span>`)
    .replace(/&lt;([A-Z][A-Z_]*?)_(\d+)&gt;/g, (_, type, n) =>
      `<span class="ph tok pop" style="--d:${(i++ * 0.06).toFixed(2)}s" data-ph="<${type}_${n}>">&lt;${type}_${n}&gt;</span>`);
}
function restoredHtml(segments) {
  let i = 0;
  return segments.map((s) =>
    s.status === "restored"
      ? `<span class="restored pop" style="--d:${(i++ * 0.06).toFixed(2)}s" data-ph="${esc(s.placeholder)}" title="Decrypted from ${esc(s.placeholder)}">${esc(s.text)}</span>`
      : s.status === "missing"
        ? `<span class="ph redacted-gone" title="${esc(s.placeholder)} was erased or expired">[REDACTED]</span>`
        : esc(s.text)).join("");
}

async function send() {
  const text = $("input").value;
  if (!text.trim()) return;
  const btn = $("sendBtn");
  $("error").hidden = true;
  btn.disabled = true; btn.classList.add("busy"); btn.querySelector("span").textContent = "Protecting…";
  resetFlow();
  $("flowHint").textContent = "Watch your message travel through the gateway…";

  const request = api("/api/chat", {
    method: "POST",
    body: { session_id: sessionId, text, framework, region: $("region").value, safeguards: $("safeguards").checked },
  });

  try {
    // 1. message leaves the browser
    setNode(0, "done", lastScanCount ? `${lastScanCount} sensitive` : "no personal data");
    setNode(1, "active", "scanning…");
    wires()[0].classList.add("live");
    const [r] = await Promise.all([request, sleep(pace(520))]);
    wires()[0].classList.remove("live"); wires()[0].classList.add("done");
    const t = r.timings_ms;
    const k = r.mapping.length;

    // 2. detect
    renderHighlight(text, r.entities, r.mapping); renderEntities(r.entities); renderRisk(r.risk);
    setNode(1, "done", `${k} found · ${t.detect} ms`);
    await runWire(1);

    // 3. encrypt & tokenize -> step 1 card
    setNode(2, "active", "encrypting…");
    await sleep(pace(300));
    setNode(2, "done", `${k} token${k === 1 ? "" : "s"} · ${t.tokenize} ms`);
    lightStep(1, tokenHtml(r.redacted_prompt));
    await runWire(2, 420);

    // 4. the AI model -> step 2 card
    setNode(3, "active", "thinking…");
    await sleep(pace(450));
    setNode(3, "done", `${r.llm_mode === "gemini" ? (r.llm_model || "Gemini") : "demo"} · ${t.llm} ms`);
    lightStep(2, tokenHtml(r.llm_reply_raw));
    await runWire(3);

    // 5. restore -> step 3 card
    setNode(4, "active", "decrypting…");
    await sleep(pace(300));
    setNode(4, "done", `${r.restored_placeholders.length} restored · ${t.restore} ms`);
    await runWire(4);
    setNode(5, "done", "delivered");
    lightStep(3, restoredHtml(r.reply_segments));
    $("flowHint").innerHTML = "Done. <b>Hover any token</b> to trace one value through every step.";
  } catch (e) {
    wires().forEach((w) => w.classList.remove("live"));
    if (e.code === "llm_error") {
      // the gateway worked; the AI provider failed. Show it at the AI model step.
      setNode(1, "done"); setNode(2, "done");
      wires().slice(0, 3).forEach((w) => w.classList.add("done"));
      setNode(3, "blocked", "AI unavailable");
      $("flowHint").textContent = "Your data was protected, but the AI model returned an error.";
    } else {
      const reason = e.code === "consent_required" ? "consent needed" : e.code === "transfer_blocked" ? "transfer blocked" : "error";
      setNode(1, "blocked", reason);
      $("flowHint").textContent = "Stopped at the gateway. Nothing was sent to the AI model.";
    }
    $("error").hidden = false;
    $("error").textContent = e.message;
    if (e.code === "consent_required") $("grantBtn").focus();
  } finally {
    btn.disabled = false; btn.classList.remove("busy"); btn.querySelector("span").textContent = "Send securely";
    refreshConsent(); refreshStats();
  }
}

// Hover a token anywhere: light it up in every step
document.addEventListener("mouseover", (e) => {
  const el = e.target.closest("[data-ph]");
  if (!el) return;
  const ph = el.dataset.ph;
  document.querySelectorAll("[data-ph]").forEach((x) => x.classList.toggle("linked", x.dataset.ph === ph));
});
document.addEventListener("mouseout", (e) => {
  if (e.target.closest("[data-ph]")) document.querySelectorAll(".linked").forEach((x) => x.classList.remove("linked"));
});

// =========================================================================
// Consent
// =========================================================================
async function refreshConsent() {
  const c = await api(`/api/consent/${sessionId}`);
  const pill = $("consentPill");
  pill.className = "pill" + (c.state === "active" ? " active" : c.state === "none" ? "" : " bad");
  pill.textContent = c.state === "active" ? `Active · ${Math.ceil(c.seconds_left / 60)} min left`
    : c.state === "none" ? "Not given" : c.state[0].toUpperCase() + c.state.slice(1);
  $("withdrawBtn").hidden = c.state !== "active";
  $("grantBtn").textContent = c.state === "active" ? "Extend" : "Give consent";
}

// =========================================================================
// Vault & lineage tab
// =========================================================================
const fmtTime = (iso) => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const EV_LABEL = { tokenized: "tokenized", restored: "restored", erased: "erased", session_erased: "session erased" };

async function loadVault() {
  const l = await api(`/api/lineage/${sessionId}`);
  $("lineage").innerHTML = l.tokens.length ? l.tokens.map((t, i) => `
    <div class="lin" style="animation: fadeUp .35s ease both; animation-delay:${Math.min(i, 12) * 0.04}s">
      <div class="lin-head">
        <span class="ph tok">${esc(t.token)}</span>
        <span class="pill ${t.in_vault ? "ok" : "bad"}">${t.in_vault ? "in vault · encrypted" : "erased"}</span>
      </div>
      <div class="lin-track">${t.events.map((ev, j) => `${j ? '<span class="lin-arrow"></span>' : ""}
        <span class="lin-ev ev-${esc(ev.event)}" title="${esc(ev.detail || "")}"><i></i>${esc(EV_LABEL[ev.event] || ev.event)} · ${fmtTime(ev.ts)}</span>`).join("")}
      </div>
    </div>`).join("")
    : `<p class="muted small">No tokens yet. Send a message on the Gateway tab.</p>`;

  const a = await api(`/api/audit?session_id=${sessionId}`);
  $("auditRows").innerHTML = a.events.length ? a.events.map((ev) => `
    <tr><td>${fmtTime(ev.ts)}</td><td><span class="ev ev-${esc(ev.event)}">${esc(ev.event)}</span></td>
    <td>${esc([ev.placeholder, ev.detail].filter(Boolean).join(" · "))}</td></tr>`).join("")
    : `<tr><td colspan="3" class="muted">No events yet.</td></tr>`;
}

// =========================================================================
// Wiring
// =========================================================================
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x === t));
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${t.dataset.tab}`));
  if (t.dataset.tab === "vault") loadVault();
  if (t.dataset.tab === "admin") adminInit();
}));

document.querySelectorAll("#framework button").forEach((b) => b.addEventListener("click", () => {
  framework = b.dataset.v;
  document.querySelectorAll("#framework button").forEach((x) => x.classList.toggle("on", x === b));
  refreshTransfer();
}));
$("region").addEventListener("change", refreshTransfer);
$("safeguards").addEventListener("change", refreshTransfer);

document.querySelectorAll("[data-ex]").forEach((b) => b.addEventListener("click", () => {
  $("input").value = EXAMPLES[+b.dataset.ex]; scheduleScan();
}));
$("input").addEventListener("input", scheduleScan);
$("sendBtn").addEventListener("click", send);
$("input").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) send(); });

$("grantBtn").addEventListener("click", async () => {
  await api("/api/consent", { method: "POST", body: { session_id: sessionId, minutes: +$("consentMinutes").value, purpose: "AI assistant conversation" } });
  $("error").hidden = true; refreshConsent();
});
$("withdrawBtn").addEventListener("click", async () => { await api(`/api/consent/${sessionId}`, { method: "DELETE" }); refreshConsent(); });

$("refreshVault").addEventListener("click", loadVault);

$("eraseForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const value = $("eraseValue").value.trim();
  if (!value) return;
  const out = $("eraseResult");
  try {
    const r = await api("/api/erase", { method: "POST", body: { value, reason: $("eraseReason").value } });
    out.className = "small result " + (r.erased ? "ok" : "");
    out.textContent = r.erased ? `Erased ${r.erased} stored cop${r.erased > 1 ? "ies" : "y"} everywhere. Logged in the audit trail.` : "No stored copy found. The request was still logged.";
    $("eraseValue").value = "";
    refreshStats();
  } catch (err) { out.className = "small result bad"; out.textContent = err.message; }
});

$("eraseSessionBtn").addEventListener("click", async () => {
  const r = await api("/api/erase-session", { method: "POST", body: { session_id: sessionId, reason: "user ended session" } });
  sessionId = newId();
  try { sessionStorage.setItem("vaultai_sid", sessionId); } catch { /* storage unavailable */ }
  $("eraseResult").className = "small result ok";
  $("eraseResult").textContent = `Session erased (${r.erased} entries). A new session has started.`;
  ["redacted", "raw", "final"].forEach((id) => ($(id).innerHTML = '<span class="muted">—</span>'));
  resetFlow(); $("flow").classList.add("idle");
  lastStats = {}; refreshConsent(); refreshStats();
});

// =========================================================================
// Admin console
// =========================================================================
const fmtDate = (iso) => new Date(iso).toLocaleString([], { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });

function showAdmin(name) {
  $("adminLogin").hidden = !!name;
  $("adminConsole").hidden = !name;
  if (name) { $("adminName").textContent = name; loadAdmin(); loadAdminAudit(); }
}

async function adminInit() {
  try { const me = await api("/api/admin/me"); showAdmin(me.username); }
  catch { showAdmin(null); setTimeout(() => $("adminPass").focus(), 50); }
}

async function adminCall(path, opts) {
  try { return await api(path, opts); }
  catch (e) { if (e.code === "admin_required") showAdmin(null); throw e; }
}

async function loadAdmin() {
  const q = $("adminSearch").value.trim();
  const r = await adminCall(`/api/admin/vault?q=${encodeURIComponent(q)}`);
  $("adminCount").textContent = `${r.entries.length} record${r.entries.length === 1 ? "" : "s"}`;
  $("adminRows").innerHTML = r.entries.length ? r.entries.map((e) => `
    <tr data-id="${e.id}">
      <td><span class="sid" title="${esc(e.session_id)}">${esc(e.session_id.slice(0, 8))}…</span></td>
      <td><span class="ph tok">${esc(e.token)}</span></td>
      <td>${esc(e.label)}</td>
      <td><span class="val" data-masked="${esc(e.masked)}">${esc(e.masked)}</span></td>
      <td class="small muted">${fmtDate(e.created_at)}</td>
      <td><div class="actions">
        <button class="btn sm" data-act="reveal">Reveal</button>
        <button class="btn sm danger" data-act="delete">Erase</button>
      </div></td>
    </tr>`).join("")
    : `<tr><td colspan="6" class="muted">${q ? "No records match." : "The vault is empty. Send a message on the Gateway tab first."}</td></tr>`;
}

async function loadAdminAudit() {
  const a = await adminCall("/api/admin/audit");
  $("adminAudit").innerHTML = a.events.length ? a.events.map((ev) => `
    <tr><td>${fmtTime(ev.ts)}</td><td><span class="sid">${ev.session_id ? esc(ev.session_id.slice(0, 8)) + "…" : "—"}</span></td>
    <td><span class="ev ev-${esc(ev.event)}">${esc(ev.event)}</span></td>
    <td>${esc([ev.placeholder, ev.detail].filter(Boolean).join(" · "))}</td></tr>`).join("")
    : `<tr><td colspan="4" class="muted">No events yet.</td></tr>`;
}

$("adminForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("adminErr").textContent = "";
  try {
    const r = await api("/api/admin/login", { method: "POST", body: { username: $("adminUser").value, password: $("adminPass").value } });
    $("adminPass").value = "";
    showAdmin(r.username);
  } catch (err) { $("adminErr").textContent = err.message; }
});

$("adminLogout").addEventListener("click", async () => {
  await api("/api/admin/logout", { method: "POST" });
  showAdmin(null);
});

let adminSearchTimer;
$("adminSearch").addEventListener("input", () => { clearTimeout(adminSearchTimer); adminSearchTimer = setTimeout(loadAdmin, 250); });
$("adminAuditRefresh").addEventListener("click", loadAdminAudit);

$("adminRows").addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-act]");
  if (!btn) return;
  const row = btn.closest("tr"), id = +row.dataset.id;
  if (btn.dataset.act === "reveal") {
    const cell = row.querySelector(".val");
    if (cell.classList.contains("revealed")) {          // hide again
      cell.textContent = cell.dataset.masked; cell.classList.remove("revealed"); btn.textContent = "Reveal"; return;
    }
    try {
      const r = await adminCall("/api/admin/reveal", { method: "POST", body: { id } });
      cell.textContent = r.value; cell.classList.add("revealed"); btn.textContent = "Hide";
      loadAdminAudit();
      setTimeout(() => { if (cell.isConnected) { cell.textContent = cell.dataset.masked; cell.classList.remove("revealed"); btn.textContent = "Reveal"; } }, 30000);
    } catch (err) { cell.textContent = err.message; }
  } else if (btn.dataset.act === "delete") {
    if (!btn.classList.contains("armed")) {               // two-step: click again to confirm
      btn.classList.add("armed"); btn.textContent = "Confirm";
      setTimeout(() => { btn.classList.remove("armed"); btn.textContent = "Erase"; }, 4000);
      return;
    }
    await adminCall("/api/admin/delete", { method: "POST", body: { id, reason: "erased from admin console" } });
    row.style.opacity = ".3";
    loadAdmin(); loadAdminAudit(); refreshStats();
  }
});

setInterval(refreshConsent, 30000);
loadHealth().then(() => {
  $("input").value = EXAMPLES[0];
  scheduleScan(); refreshConsent(); refreshTransfer(); refreshStats();
});
