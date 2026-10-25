"use strict";
// adX web UI. All analysis runs in the Go backend; this draws the result and
// keeps the owned set. No external libraries.

const SEV = { crit: "Critical", high: "High", med: "Medium" };
let NODES = {};               // id -> {s:short, k:kind, t:tierZero}
let META = {};
const state = { owned: new Set(), sel: { kind: "none" }, tab: "linux", result: null, nodeCache: null, curCmds: [] };

const $ = sel => document.querySelector(sel);
const esc = t => String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

// Attack context: values the operator fills once, substituted into every
// command so the copied line is executable. Persisted per browser.
const CTX_KEY = "adx.ctx";
// [key, label, default]. Discovered values default to empty; attacker-chosen
// values (the machine account you create, the password you set) get a default.
const CTX_FIELDS = [
  ["user", "Username", ""], ["pass", "Password", ""], ["hash", "NT hash", ""],
  ["dcip", "DC host / IP", ""], ["domain", "Domain", ""],
  ["newpc", "New machine acct", "ADX01"], ["newpass", "Password you set", "Adx!2026pass"],
];
let ctx = loadCtx();
function loadCtx() {
  let c = {};
  try { c = JSON.parse(localStorage.getItem(CTX_KEY)) || {}; } catch { c = {}; }
  for (const [k, , def] of CTX_FIELDS) { if (def && !c[k]) c[k] = def; }
  return c;
}
function saveCtx() { try { localStorage.setItem(CTX_KEY, JSON.stringify(ctx)); } catch { } }
function subst(code) {
  const map = {
    user: ctx.user, password: ctx.pass, hash: ctx.hash, rc4: ctx.hash, nthash: ctx.hash,
    "dc-ip": ctx.dcip, "dc-fqdn": ctx.dcip, domain: ctx.domain, you: ctx.user,
    newpc: ctx.newpc, newpass: ctx.newpass,
  };
  let out = code;
  for (const tok in map) { if (map[tok]) out = out.split("<" + tok + ">").join(map[tok]); }
  return out;
}
function applyCtx() {
  document.querySelectorAll("#drawer pre[data-i]").forEach(pre => {
    const c = state.curCmds[+pre.dataset.i];
    if (c) pre.textContent = subst(c.code);
  });
}
const short = id => (NODES[id] ? NODES[id].s : id);
const api = (path, body) => fetch(path, body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : undefined).then(r => r.json());

async function boot() {
  const ov = await api("/api/overview");
  NODES = ov.nodes || {};
  META = ov.meta || {};
  renderHeader();
  if (META.empty) { showEmpty(); return; }
  $("#emptyState").hidden = true;
  await refresh();
}

const KIND_LABEL = { User: "Users", Computer: "Computers", Group: "Groups", OU: "OUs", GPO: "GPOs", Container: "Containers", Domain: "Domains", CertTemplate: "Cert templates", EnterpriseCA: "Enterprise CAs" };

function renderHeader() {
  $("#dataset").textContent = META.empty ? "no data" : (META.domain ? META.domain.toLowerCase() : "loaded");
  $("#clearBtn").hidden = !!META.empty;
  const browse = $("#browse");
  const order = ["User", "Computer", "Group", "OU", "GPO", "Container", "CertTemplate", "EnterpriseCA", "Domain"];
  const opts = ['<option value="">Browse…</option>'];
  for (const k of order) {
    if ((META.counts || {})[k]) opts.push(`<option value="${k}">${KIND_LABEL[k] || k} (${META.counts[k]})</option>`);
  }
  browse.innerHTML = opts.join("");
  browse.hidden = !!META.empty;
  if (META.empty) { $("#stats").innerHTML = ""; return; }
  const c = META.counts || {};
  const parts = [["User", "users"], ["Computer", "computers"], ["Group", "groups"]]
    .filter(([k]) => c[k]).map(([k, label]) => `<span><b>${c[k].toLocaleString()}</b> ${label}</span>`);
  parts.push(`<span><b>${(META.edgeCount || 0).toLocaleString()}</b> edges</span>`);
  parts.push(`<span><b id="ownedCount">${state.owned.size}</b> owned</span>`);
  $("#stats").innerHTML = parts.join("");
}

function showEmpty() {
  $("#rail").innerHTML = "";
  $("#drawer").innerHTML = "";
  $("#g").innerHTML = "";
  $("#emptyState").hidden = false;
}

async function refresh() {
  state.result = await api("/api/eval", { owned: [...state.owned] });
  $("#ownedCount") && ($("#ownedCount").textContent = state.owned.size);
  if (state.sel.kind === "none" && state.result.findings.length) state.sel = { kind: "finding", id: state.result.findings[0].id };
  renderRail();
  await renderMain();
}

function findingById(id) { return state.result.findings.find(f => f.id === id); }
function badgeMap() {
  const b = {};
  const rank = { crit: 0, high: 1, med: 2 };
  for (const f of state.result.findings) {
    if (!b[f.node] || rank[f.severity] < rank[b[f.node]]) b[f.node] = f.severity;
  }
  return b;
}

function renderRail() {
  const r = state.result, list = r.findings;
  const now = list.filter(f => f.status === "now");
  const entries = list.filter(f => f.status === "entry");
  const fastest = r.fastestId ? findingById(r.fastestId) : null;
  const ownedNames = [...state.owned].map(short).join(", ") || "nothing yet";
  let big, note;
  if (state.owned.size === 0 && entries.length) {
    big = `<span>${entries.length}</span> way${entries.length === 1 ? "" : "s"} in`;
    note = `No path from a standard domain user. Compromise one of the accounts below, then mark it owned to trace the rest.`;
  } else {
    big = `<span>${now.length}</span> exploitable now`;
    note = fastest
      ? `Fastest route to the domain: <b>${esc(fastest.title)}</b>, ${r.fastestSteps} step${r.fastestSteps === 1 ? "" : "s"}.`
      : state.owned.size ? "No direct route to the domain from your owned principals yet." : "Mark a compromised account as owned to rank paths from it.";
  }
  let html = `<div class="summary"><div class="eyebrow">Owned: ${esc(ownedNames)}</div>
    <div class="big">${big}</div><p>${note}</p></div>`;
  const groups = [["now", "Exploitable now"], ["entry", "Attack entry points — own one to start"], ["reach", "Reachable with extra steps"], ["blocked", "Not reachable yet"]];
  for (const [k, label] of groups) {
    const items = list.filter(f => f.status === k);
    if (!items.length) continue;
    html += `<div class="group-h"><span>${label}</span><span>${items.length}</span></div>`;
    for (const f of items) {
      const sub = k === "now" ? `<span class="status st-now">${f.toDomain ? `${f.stepsToDA} steps to domain` : "Usable now"}</span>`
        : k === "entry" ? `<span class="status st-entry">own it → ${esc(short(f.node))} in ${f.stepsToDA} step${f.stepsToDA === 1 ? "" : "s"}</span>`
          : k === "reach" ? `<span class="status st-reach">Reach in ${f.hops} step${f.hops === 1 ? "" : "s"}</span>`
            : `<span class="status st-blocked">No path from owned</span>`;
      const active = state.sel.kind === "finding" && state.sel.id === f.id ? " active" : "";
      html += `<button class="finding ${k}${active}" data-f="${esc(f.id)}"><span class="stripe sev-${f.severity}"></span><span class="t">${esc(f.title)}</span><span class="tgt">${esc(short(f.node))}</span><span class="s">${sub}</span></button>`;
    }
  }
  const rail = $("#rail");
  rail.innerHTML = html;
  rail.querySelectorAll("[data-f]").forEach(b => b.onclick = () => { state.sel = { kind: "finding", id: b.dataset.f }; renderRail(); renderMain(); });
}

const GLYPH = {
  user: '<circle cx="0" cy="-4" r="3.6"/><path d="M-6.5 7.5c0-4.5 3-6.5 6.5-6.5s6.5 2 6.5 6.5"/>',
  group: '<circle cx="-4" cy="-3.5" r="3"/><circle cx="4.5" cy="-3.5" r="3"/><path d="M-9.5 7c0-3.8 2.4-5.5 5.5-5.5s5.5 1.7 5.5 5.5M2 1.6c.8-.1 1.6-.1 2.5-.1 3.1 0 5.5 1.7 5.5 5.5"/>',
  computer: '<rect x="-8" y="-7.5" width="16" height="11" rx="1.5"/><path d="M-4 8h8M0 3.5v4.5"/>',
  domain: '<circle r="8"/><ellipse rx="3.4" ry="8"/><path d="M-8 0h16"/>',
  certtemplate: '<path d="M-6 -8h8l4 4v12h-12z"/><path d="M2 -8v4h4M-3 0h6M-3 3.5h6"/>',
  enterpriseca: '<path d="M-7 6h14M-5 6v-9l5-3 5 3v9M-2 6v-4h4v4"/>',
  gpo: '<rect x="-7" y="-7" width="14" height="14" rx="2"/><path d="M-3 -2h6M-3 2h6"/>',
  default: '<circle r="6"/>',
};
function glyph(kind) { return GLYPH[String(kind).toLowerCase()] || GLYPH.default; }

// Draw a subgraph. nodes: [{id,x,y}], edges: [{from,to,kind,hot}].
function drawGraph(nodes, edges, selId) {
  const R = 24, badge = state.result ? badgeMap() : {};
  const pos = Object.fromEntries(nodes.map(n => [n.id, n]));
  const anyHot = edges.some(e => e.hot);
  let s = `<defs>
    <marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="arrow" d="M0 0L10 5L0 10z"/></marker>
    <marker id="arh" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="arrow-hot" d="M0 0L10 5L0 10z"/></marker></defs>`;
  for (const e of edges) {
    const A = pos[e.from], B = pos[e.to];
    if (!A || !B) continue;
    const dx = B.x - A.x, dy = B.y - A.y, L = Math.hypot(dx, dy) || 1, ux = dx / L, uy = dy / L;
    const x1 = A.x + ux * R, y1 = A.y + uy * R, x2 = B.x - ux * (R + 3), y2 = B.y - uy * (R + 3);
    const cls = `edge${e.hot ? " hot" : ""}${anyHot && !e.hot ? " dim" : ""}`;
    let ang = Math.atan2(dy, dx) * 180 / Math.PI; if (ang > 90 || ang < -90) ang += 180;
    const mx = (A.x + B.x) / 2, my = (A.y + B.y) / 2;
    s += `<g class="${cls}"><line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" marker-end="url(#${e.hot ? "arh" : "ar"})"/>
      <text x="${mx}" y="${my - 5}" text-anchor="middle" transform="rotate(${ang} ${mx} ${my})">${esc(e.kind)}</text></g>`;
  }
  for (const n of nodes) {
    const meta = NODES[n.id] || { s: n.id, k: "base", t: false };
    const owned = state.owned.has(n.id), isSel = n.id === selId;
    const cls = `node${n.hot ? " hot" : ""}${isSel ? " sel" : ""}${meta.t ? " t0" : ""}`;
    s += `<g class="${cls}" data-n="${esc(n.id)}" transform="translate(${n.x} ${n.y})" tabindex="0" role="button" aria-label="${esc(meta.s)}">
      ${owned ? `<circle class="own-ring" r="${R + 6}"/><text class="own-tag" y="${-R - 11}">OWNED</text>` : ""}
      <circle class="disc" r="${R}"/><g class="glyph">${glyph(meta.k)}</g>
      <text class="name" y="${R + 16}">${esc(meta.s)}</text>
      ${badge[n.id] ? `<g transform="translate(17 -17)"><circle class="b-${badge[n.id]}" r="8.5"/><text class="badge-t" y="4">!</text></g>` : ""}</g>`;
  }
  const g = $("#g");
  g.innerHTML = s;
  g.querySelectorAll("[data-n]").forEach(el => {
    const go = () => selectNode(el.dataset.n);
    el.onclick = go;
    el.onkeydown = ev => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); go(); } };
  });
}

function pathNodes(f) {
  if (f.path && f.path.length) {
    const ids = [f.path[0].from];
    f.path.forEach(e => ids.push(e.to));
    return { ids, edges: f.path.map(e => ({ ...e, hot: true })) };
  }
  const ids = f.chain && f.chain.length ? f.chain : [f.node];
  const edges = [];
  for (let i = 0; i + 1 < ids.length; i++) edges.push({ from: ids[i], to: ids[i + 1], kind: "", hot: true });
  return { ids, edges };
}

function layoutFinding(f) {
  const { ids, edges } = pathNodes(f);
  const W = 1090, H = 610, n = ids.length;
  const seen = new Set(), uniq = [];
  ids.forEach(id => { if (!seen.has(id)) { seen.add(id); uniq.push(id); } });
  const m = 90, span = n > 1 ? (W - 2 * m) / (uniq.length - 1 || 1) : 0;
  const nodes = uniq.map((id, i) => ({
    id, x: uniq.length === 1 ? W / 2 : m + i * span,
    y: H / 2 + (uniq.length > 3 ? (i % 2 ? -46 : 46) : 0),
    hot: true,
  }));
  drawGraph(nodes, edges, f.node);
}

async function layoutNode(id) {
  const d = await api("/api/node", { id, owned: [...state.owned] });
  state.nodeCache = d;
  const W = 1090, H = 610;
  const nodes = [{ id, x: W / 2, y: H / 2, hot: true }];
  const edges = [];
  const place = (list, side) => {
    const take = list.slice(0, 7);
    const x = side < 0 ? 170 : W - 170;
    take.forEach((rel, i) => {
      const y = take.length === 1 ? H / 2 : 90 + i * ((H - 180) / (take.length - 1 || 1));
      if (!nodes.find(nn => nn.id === rel.node)) nodes.push({ id: rel.node, x, y, hot: true });
      if (side < 0) edges.push({ from: rel.node, to: id, kind: rel.kind, hot: true });
      else edges.push({ from: id, to: rel.node, kind: rel.kind, hot: true });
    });
  };
  place(d.inbound || [], -1);
  place(d.outbound || [], 1);
  drawGraph(nodes, edges, id);
  renderNodeDrawer(d);
}

function renderTypeList(kind) {
  const items = Object.entries(NODES).filter(([, n]) => n.k === kind)
    .map(([id, n]) => ({ id, s: n.s, t: n.t }))
    .sort((a, b) => a.s < b.s ? -1 : a.s > b.s ? 1 : 0);
  const shown = items.slice(0, 500);
  $("#g").innerHTML = "";
  $("#drawer").innerHTML = `<div class="card">
    <div><button class="close" aria-label="Close" data-close>×</button>
      <div class="meta"><span class="mono">${esc(kind.toUpperCase())}</span></div>
      <h2>${items.length} ${esc(KIND_LABEL[kind] || kind)}</h2></div>
    <div class="linklist">${shown.map(o => `<button data-goto="${esc(o.id)}">${o.t ? '<span class="chip sev-high">T0</span>' : ""}${esc(o.s)}</button>`).join("")}</div>
    ${items.length > shown.length ? `<p class="mono">Showing the first ${shown.length}. Use search for a specific one.</p>` : ""}</div>`;
  wireDrawer();
}

async function renderMain() {
  if (state.sel.kind === "list") { renderTypeList(state.sel.k); return; }
  if (state.sel.kind === "finding") {
    const f = findingById(state.sel.id);
    if (!f) { state.sel = { kind: "none" }; return renderMain(); }
    layoutFinding(f);
    renderFindingDrawer(f);
  } else if (state.sel.kind === "node") {
    await layoutNode(state.sel.id);
  } else {
    $("#g").innerHTML = "";
    $("#drawer").innerHTML = `<div class="card"><div class="label">Nothing selected</div><p>Pick a finding on the left or click a node in the graph.</p></div>`;
  }
}

function statusLine(s) {
  return s === "now" ? '<span class="status st-now">Exploitable now</span>'
    : s === "entry" ? '<span class="status st-entry">Attack entry point</span>'
      : s === "reach" ? '<span class="status st-reach">Reachable with extra steps</span>'
        : '<span class="status st-blocked">Not reachable yet</span>';
}

function renderFindingDrawer(f) {
  const { ids } = pathNodes(f);
  const seen = new Set(), uniq = [];
  ids.forEach(id => { if (!seen.has(id)) { seen.add(id); uniq.push(id); } });
  let path = "";
  uniq.forEach((id, i) => {
    if (i) {
      const e = (f.path && f.path[i - 1]) ? f.path[i - 1].kind : "";
      path += `<span class="e">→ ${esc(e)}</span>`;
    }
    path += `<span class="p${state.owned.has(id) ? " own" : ""}" data-goto="${esc(id)}">${esc(short(id))}</span>`;
  });
  const cmdList = f.commands[state.tab] || [];
  state.curCmds = cmdList;
  const cmds = cmdList.length
    ? cmdList.map((c, i) => `<div class="cmd"><div class="c">${esc(c.label)}</div><pre data-i="${i}">${esc(subst(c.code))}</pre><button class="copy">Copy</button></div>`).join("")
    : `<p class="mono">This finding's steps describe the abuse; the specific commands live on the technique for each hop — click the nodes in the path.</p>`;
  const ctxForm = cmdList.length
    ? `<details class="ctx" open><summary>Session values — fill once, every command fills in</summary>
        <div class="ctxgrid">${CTX_FIELDS.map(([k, label]) => `<label>${esc(label)}<input id="ctx-${k}" spellcheck="false" autocapitalize="off" autocomplete="off"></label>`).join("")}</div></details>`
    : "";
  $("#drawer").innerHTML = `<div class="card">
    <div><button class="close" aria-label="Close" data-close>×</button>
      <div class="meta"><span class="chip sev-${f.severity}">${SEV[f.severity]}</span>${statusLine(f.status)}<span class="mono">${esc(short(f.node))}</span></div>
      <h2>${esc(f.title)}</h2></div>
    <div><div class="label">Why</div><p>${esc(f.why)}</p></div>
    <div><div class="label">Path${f.toDomain ? ` · ${f.stepsToDA} steps to domain` : ""}</div><div class="path">${path}</div></div>
    <div><div class="label">Steps</div><ol class="steps">${f.steps.map(s => `<li>${esc(s)}</li>`).join("")}</ol></div>
    ${ctxForm}
    <div><div class="tabs" role="tablist">
      <button role="tab" aria-selected="${state.tab === "linux"}" data-tab="linux">Linux · impacket</button>
      <button role="tab" aria-selected="${state.tab === "windows"}" data-tab="windows">Windows · Rubeus / PowerView</button></div>${cmds}</div>
    <div class="impact"><div class="label">Result</div><p>${esc(f.impact)}</p></div></div>`;
  wireDrawer();
  // Populate and wire the session fields.
  CTX_FIELDS.forEach(([k]) => {
    const el = $("#ctx-" + k);
    if (!el) return;
    el.value = ctx[k] || "";
    el.addEventListener("input", () => { ctx[k] = el.value.trim(); saveCtx(); applyCtx(); });
  });
  $("#drawer").querySelectorAll("[data-tab]").forEach(b => b.onclick = () => { state.tab = b.dataset.tab; renderFindingDrawer(f); });
  wireCopy();
}

function wireCopy() {
  $("#drawer").querySelectorAll(".copy").forEach(b => b.onclick = () => {
    const pre = b.previousElementSibling;
    const text = pre.textContent;
    const done = () => { b.textContent = "Copied"; setTimeout(() => (b.textContent = "Copy"), 1200); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, () => selectText(pre, done));
    } else {
      selectText(pre, done);
    }
  });
}

// Fallback copy for contexts where the async clipboard API is unavailable.
function selectText(el, done) {
  try {
    const r = document.createRange();
    r.selectNodeContents(el);
    const s = getSelection();
    s.removeAllRanges();
    s.addRange(r);
    const ok = document.execCommand && document.execCommand("copy");
    s.removeAllRanges();
    if (ok && done) { done(); return; }
    toast("Press Cmd/Ctrl+C to copy");
  } catch {
    toast("Press Cmd/Ctrl+C to copy");
  }
}

function renderNodeDrawer(d) {
  const owned = state.owned.has(d.id);
  const reach = owned ? "Owned" : d.status === "now" ? "Controlled through group membership" : d.status === "reach" ? "Reachable from owned principals" : "Not reachable yet";
  const rels = (list, dir) => list && list.length
    ? `<div class="path">${list.slice(0, 40).map(r => dir === "out"
      ? `<span class="e">${esc(r.kind)} →</span><span class="p" data-goto="${esc(r.node)}">${esc(short(r.node))}</span>`
      : `<span class="p" data-goto="${esc(r.node)}">${esc(short(r.node))}</span><span class="e">→ ${esc(r.kind)}</span>`).join(" ")}</div>`
    : `<span class="mono">None</span>`;
  const props = Object.entries(d.props || {}).filter(([, v]) => v !== "" && v !== null)
    .slice(0, 16).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(typeof v === "object" ? JSON.stringify(v) : v)}</dd>`).join("");
  $("#drawer").innerHTML = `<div class="card">
    <div><button class="close" aria-label="Close" data-close>×</button>
      <div class="meta"><span class="mono">${esc(d.kind.toUpperCase())}${d.tierZero ? " · TIER 0" : ""}</span><span class="status ${owned || d.status === "now" ? "st-now" : d.status === "reach" ? "st-reach" : "st-blocked"}">${reach}</span></div>
      <h2>${esc(d.short)}</h2></div>
    <div><button class="btn ${owned ? "" : "primary"}" id="ownBtn">${owned ? "Unmark as owned" : "Mark as owned"}</button></div>
    ${props ? `<dl class="kv">${props}</dl>` : ""}
    ${d.findings && d.findings.length ? `<div><div class="label">Findings involving this node</div><div class="linklist">${d.findings.map(id => { const f = findingById(id); return f ? `<button data-f="${esc(id)}"><span class="chip sev-${f.severity}">!</span>${esc(f.title)}</button>` : ""; }).join("")}</div></div>` : ""}
    <div><div class="label">Outbound</div>${rels(d.outbound, "out")}</div>
    <div><div class="label">Inbound</div>${rels(d.inbound, "in")}</div></div>`;
  wireDrawer();
  $("#ownBtn").onclick = async () => {
    if (owned) state.owned.delete(d.id); else state.owned.add(d.id);
    toast(owned ? `${d.short} unmarked. Findings re-ranked.` : `${d.short} marked as owned. Findings re-ranked.`);
    await refresh();
  };
  $("#drawer").querySelectorAll("[data-f]").forEach(b => b.onclick = () => { state.sel = { kind: "finding", id: b.dataset.f }; renderRail(); renderMain(); });
}

function wireDrawer() {
  const c = $("#drawer").querySelector("[data-close]");
  if (c) c.onclick = () => { state.sel = { kind: "none" }; renderMain(); };
  $("#drawer").querySelectorAll("[data-goto]").forEach(el => el.onclick = () => selectNode(el.dataset.goto));
}

function selectNode(id) { state.sel = { kind: "node", id }; renderRail(); renderMain(); }

let tt;
function toast(msg) { const t = $("#toast"); t.textContent = msg; t.hidden = false; clearTimeout(tt); tt = setTimeout(() => t.hidden = true, 2600); }

// Search
let searchTimer;
$("#q").addEventListener("input", ev => {
  clearTimeout(searchTimer);
  const v = ev.target.value;
  searchTimer = setTimeout(async () => {
    const hits = await fetch("/api/search?q=" + encodeURIComponent(v)).then(r => r.json());
    $("#nodeList").innerHTML = hits.map(h => `<option value="${esc(h.s)}">`).join("");
  }, 150);
});
$("#q").addEventListener("change", async ev => {
  const v = ev.target.value.trim();
  if (!v) return;
  const hits = await fetch("/api/search?q=" + encodeURIComponent(v)).then(r => r.json());
  const hit = hits.find(h => h.s.toUpperCase() === v.toUpperCase()) || hits[0];
  if (hit) { selectNode(hit.id); ev.target.value = ""; } else toast(`No node matches "${v}".`);
});

// Upload
async function upload(files) {
  if (!files.length) return;
  const fd = new FormData();
  for (const f of files) fd.append("file", f);
  toast(`Parsing ${files.length} file${files.length === 1 ? "" : "s"}…`);
  try {
    const res = await fetch("/api/upload", { method: "POST", body: fd });
    if (!res.ok) { toast("Load failed: " + (await res.text())); return; }
    const r = await res.json();
    toast(`Loaded. ${r.nodes.toLocaleString()} nodes, ${r.findings} findings.`);
    state.sel = { kind: "none" };
    await boot();
  } catch (e) { toast("Load failed: " + e.message); }
}
$("#file").addEventListener("change", ev => { upload([...ev.target.files]); ev.target.value = ""; });

// Browse by type
$("#browse").addEventListener("change", ev => {
  const k = ev.target.value;
  if (k) { state.sel = { kind: "list", k }; renderRail(); renderMain(); }
});

// Clear loaded data
$("#clearBtn").addEventListener("click", async () => {
  if (!confirm("Clear all loaded data and return to an empty workspace?")) return;
  await fetch("/api/clear", { method: "POST" });
  state.owned.clear();
  state.sel = { kind: "none" };
  toast("Data cleared.");
  await boot();
});
const stage = $("#stage"), hint = $("#dropHint");
stage.addEventListener("dragover", ev => { ev.preventDefault(); hint.hidden = false; });
stage.addEventListener("dragleave", ev => { if (!stage.contains(ev.relatedTarget)) hint.hidden = true; });
stage.addEventListener("drop", ev => { ev.preventDefault(); hint.hidden = true; upload([...ev.dataTransfer.files]); });

// Heartbeat + unload signal: lets a local adX quit itself when this tab closes,
// while surviving tab switches (no signal) and reloads (a fresh beat cancels it).
const beat = () => fetch("/api/alive", { method: "POST", keepalive: true }).catch(() => { });
beat();
setInterval(beat, 2000);
addEventListener("pagehide", () => { try { navigator.sendBeacon("/api/bye"); } catch { } });

boot();
