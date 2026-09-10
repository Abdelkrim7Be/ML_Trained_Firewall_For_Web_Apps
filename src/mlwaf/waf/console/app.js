/* Operator console.
   No framework on purpose: the whole surface is one table, one detail pane and a
   slider, and a build step would cost more than it saves. */

const API = "/_waf";
const MAX_ROWS = 400;

const el = (id) => document.getElementById(id);
const state = {
  rows: [],
  selected: null,
  paused: false,
  status: null,
  filters: { verdict: "", attack_class: "", flagged: "", search: "" },
};

/* ---------- helpers ---------- */
const fmtTime = (ts) =>
  new Date(ts * 1000).toLocaleTimeString("en-GB", { hour12: false });

const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const truncate = (s, n) => (s && s.length > n ? s.slice(0, n) + "…" : s || "");

async function api(path, options) {
  const r = await fetch(API + path, options);
  if (!r.ok) throw new Error(`${r.status} ${path}`);
  return r.json();
}

const postJSON = (path, body) =>
  api(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

/* ---------- table ---------- */
function passesFilters(d) {
  const f = state.filters;
  if (f.verdict && d.verdict !== f.verdict) return false;
  if (f.attack_class && d.attack_class !== f.attack_class) return false;
  if (f.flagged && !d.would_block) return false;
  if (f.search) {
    const hay = (d.path + " " + (d.query || "")).toLowerCase();
    if (!hay.includes(f.search.toLowerCase())) return false;
  }
  return true;
}

function rowHTML(d, isNew) {
  const cls = [
    d.would_block ? "flag" : "",
    state.selected === d.id ? "sel" : "",
    isNew ? "new" : "",
  ].filter(Boolean).join(" ");

  const verdict = d.degraded ? "unscored" : d.verdict;
  const query = d.query ? `<span class="q">?${esc(truncate(d.query, 90))}</span>` : "";

  return `<tr class="${cls}" data-id="${d.id}">
    <td class="ts">${fmtTime(d.ts)}</td>
    <td class="verdict">${esc(verdict)}</td>
    <td class="cls">${d.would_block ? esc(d.attack_class) : ""}</td>
    <td class="score">${d.score.toFixed(3)}</td>
    <td class="lat">${d.latency_ms.toFixed(1)}</td>
    <td class="path">${esc(d.method)} ${esc(truncate(d.path, 60))}${query}</td>
  </tr>`;
}

function renderTable() {
  const visible = state.rows.filter(passesFilters);
  el("rows").innerHTML = visible.map((d) => rowHTML(d, false)).join("");
}

function prependRow(d) {
  state.rows.unshift(d);
  if (state.rows.length > MAX_ROWS) state.rows.length = MAX_ROWS;
  if (state.paused || !passesFilters(d)) return;

  const tbody = el("rows");
  tbody.insertAdjacentHTML("afterbegin", rowHTML(d, true));
  while (tbody.children.length > MAX_ROWS) tbody.lastElementChild.remove();
}

/* ---------- detail ---------- */
function contributionsHTML(list) {
  if (!list || !list.length) return "";
  const peak = Math.max(...list.map((c) => Math.abs(c.contribution))) || 1;
  const rows = list.map((c) => {
    const width = (Math.abs(c.contribution) / peak) * 100;
    const neg = c.contribution < 0 ? " neg" : "";
    const name = c.feature.replace(/^[a-z_]+__/, "");
    return `<div class="row">
      <div>
        <div class="feat">${esc(name)}</div>
        <div class="bar${neg}" style="width:${width}%"></div>
      </div>
      <div class="amt">${c.contribution > 0 ? "+" : ""}${c.contribution.toFixed(2)}</div>
    </div>`;
  }).join("");

  return `<section>
    <h3>what drove the score</h3>
    <div class="contrib">${rows}</div>
  </section>`;
}

function traceHTML(trace) {
  if (!trace || !trace.length) return "";
  const steps = trace.map((s) => `<div class="step">
      <div class="name">${esc(s.step)}</div>
      <div class="val">${esc(truncate(s.value, 400))}</div>
    </div>`).join("");
  return `<section><h3>decode trace</h3><div class="trace">${steps}</div></section>`;
}

function actionsHTML(d) {
  if (d.feedback) {
    return `<div class="actions"><div class="done">recorded as ${esc(d.feedback)}</div></div>`;
  }
  return `<div class="actions">
    <button class="ghost fp" data-fb="false_positive">false positive</button>
    <button class="ghost tp" data-fb="true_positive">true positive</button>
  </div>`;
}

async function showDetail(id) {
  state.selected = id;
  document.querySelectorAll("#rows tr").forEach((tr) =>
    tr.classList.toggle("sel", Number(tr.dataset.id) === id));

  const d = await api(`/decisions/${id}`);
  const ex = d.explanation || {};

  el("detail").innerHTML = `
    <section>
      <h3>request ${d.request_id}</h3>
      <dl class="kv">
        <dt>verdict</dt><dd class="${d.verdict === "block" ? "block" : ""}">${esc(d.verdict)}${d.degraded ? " (unscored)" : ""}</dd>
        <dt>score</dt><dd>${d.score.toFixed(4)} / ${d.threshold.toFixed(4)}</dd>
        <dt>class</dt><dd>${esc(d.attack_class)}</dd>
        <dt>method</dt><dd>${esc(d.method)}</dd>
        <dt>path</dt><dd>${esc(d.path)}</dd>
        ${d.query ? `<dt>query</dt><dd>${esc(truncate(d.query, 300))}</dd>` : ""}
        ${d.body_preview ? `<dt>body</dt><dd>${esc(truncate(d.body_preview, 300))}</dd>` : ""}
        <dt>reason</dt><dd>${esc(d.reason)}</dd>
        <dt>latency</dt><dd>${d.latency_ms.toFixed(2)} ms${d.cached ? " (cached)" : ""}</dd>
        <dt>decoded</dt><dd>${d.decode_depth} round${d.decode_depth === 1 ? "" : "s"}</dd>
      </dl>
    </section>
    ${traceHTML(ex.decode_trace)}
    ${contributionsHTML(ex.contributions)}
    ${actionsHTML(d)}`;

  el("detail").querySelectorAll("[data-fb]").forEach((b) =>
    b.addEventListener("click", async () => {
      await postJSON(`/decisions/${id}/feedback`, { label: b.dataset.fb });
      showDetail(id);
      refreshStatus();
    }));
}

/* ---------- sparkline ---------- */
function renderSpark(series) {
  const svg = el("spark");
  const w = svg.clientWidth || 300, h = 34;
  const peak = Math.max(1, ...series.map((b) => b.total));
  const step = w / Math.max(series.length, 1);

  const bars = series.map((b, i) => {
    const total = (b.total / peak) * h;
    const flagged = (b.flagged / peak) * h;
    const x = (i * step).toFixed(1);
    const bw = Math.max(step - 1, 1).toFixed(1);
    let out = `<rect x="${x}" y="${(h - total).toFixed(1)}" width="${bw}" height="${total.toFixed(1)}" fill="#212836"/>`;
    if (b.flagged) {
      out += `<rect x="${x}" y="${(h - flagged).toFixed(1)}" width="${bw}" height="${flagged.toFixed(1)}" fill="#E0A93B"/>`;
    }
    return out;
  }).join("");

  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  svg.innerHTML = bars;
}

/* ---------- status ---------- */
function renderStatus(s) {
  state.status = s;
  const sum = s.summary;
  el("s-total").textContent = sum.total;
  el("s-blocked").textContent = sum.blocked;
  el("s-flagged").textContent = sum.flagged;
  el("s-latency").innerHTML = `${sum.max_latency_ms.toFixed(1)}<span class="unit">ms</span>`;
  el("s-degraded").textContent = sum.degraded;
  el("upstream").textContent = s.upstream;

  const mins = Math.floor(s.uptime_seconds / 60);
  el("uptime").textContent = mins < 60
    ? `up ${mins}m`
    : `up ${Math.floor(mins / 60)}h ${mins % 60}m`;

  el("mode-detect").classList.toggle("on", !s.blocking);
  el("mode-block").classList.toggle("on", s.blocking);
  el("mode-block").classList.toggle("blocking", s.blocking);

  const thr = el("thr");
  if (document.activeElement !== thr) {
    thr.value = s.threshold;
    el("thr-val").textContent = Number(s.threshold).toFixed(3);
  }
}

async function refreshStatus() {
  try {
    renderStatus(await api("/status"));
    renderSpark((await api("/traffic")).series);
  } catch { /* the stream indicator already reports connectivity */ }
}

/* ---------- threshold ---------- */
let impactTimer = null;

function onThresholdInput() {
  const v = Number(el("thr").value);
  el("thr-val").textContent = v.toFixed(3);
  clearTimeout(impactTimer);
  impactTimer = setTimeout(async () => {
    const r = await api(`/threshold/impact?value=${v}`);
    const now = r.blocked_at_this_threshold;
    const before = r.blocked_at_current_threshold;
    const delta = now - before;
    const sign = delta > 0 ? "+" : "";
    el("thr-impact").innerHTML =
      `over last hour: <b>${now}</b> of ${r.total} blocked ` +
      `(${sign}${delta} vs current, ${r.flips.length} flip${r.flips.length === 1 ? "" : "s"})`;
  }, 180);
}

/* ---------- live stream ---------- */
function connect() {
  const es = new EventSource(`${API}/stream`);

  es.onopen = () => {
    el("dot").className = "dot live";
    el("conn").textContent = "live";
  };
  es.onerror = () => {
    el("dot").className = "dot down";
    el("conn").textContent = "reconnecting";
  };
  es.onmessage = (e) => {
    const d = JSON.parse(e.data);
    prependRow(d);
  };
}

/* ---------- wiring ---------- */
function bind() {
  el("rows").addEventListener("click", (e) => {
    const tr = e.target.closest("tr");
    if (tr) showDetail(Number(tr.dataset.id));
  });

  el("pause").addEventListener("click", () => {
    state.paused = !state.paused;
    el("pause").textContent = state.paused ? "resume" : "pause";
    if (!state.paused) renderTable();
  });

  const filterMap = {
    "f-verdict": "verdict",
    "f-class": "attack_class",
    "f-flagged": "flagged",
    "f-search": "search",
  };
  Object.entries(filterMap).forEach(([id, key]) => {
    el(id).addEventListener("input", () => {
      state.filters[key] = el(id).value;
      renderTable();
    });
  });

  el("thr").addEventListener("input", onThresholdInput);

  el("thr-apply").addEventListener("click", async () => {
    await postJSON("/threshold", { value: Number(el("thr").value) });
    el("thr-impact").textContent = "applied";
    refreshStatus();
  });

  el("thr-reset").addEventListener("click", () => {
    el("thr").value = state.status.threshold;
    onThresholdInput();
  });

  document.querySelectorAll(".mode-toggle button").forEach((b) =>
    b.addEventListener("click", async () => {
      await postJSON("/mode", { mode: b.dataset.mode });
      refreshStatus();
    }));
}

async function boot() {
  bind();
  await refreshStatus();
  const { decisions } = await api("/decisions?limit=200");
  state.rows = decisions;
  renderTable();
  connect();
  setInterval(refreshStatus, 3000);
  window.addEventListener("resize", () => refreshStatus());
}

boot();
