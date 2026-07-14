"use strict";

const ICONS = {
  router: "📶", phone: "📱", computer: "💻", tv: "📺", printer: "🖨️",
  iot: "💡", game_console: "🎮", nas: "🗄️", camera: "📷", unknown: "❓",
};
const TYPE_LABEL = {
  router: "Router", phone: "Phone", computer: "Computer", tv: "TV / Streaming",
  printer: "Printer", iot: "Smart / IoT", game_console: "Game Console",
  nas: "NAS / Server", camera: "Camera", unknown: "Unknown",
};

let devices = [];
let events = [];
let status = {};

// --------------------------------------------------------------------------- //
// API helpers
// --------------------------------------------------------------------------- //
async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(path + " → " + res.status);
  return res.json();
}
const getJSON = (p) => api(p);
const patchJSON = (p, body) =>
  api(p, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

async function refreshAll() {
  [status, devices, events] = await Promise.all([
    getJSON("/api/status"),
    getJSON("/api/devices"),
    getJSON("/api/events"),
  ]);
  renderStatus();
  renderDevices();
  renderEvents();
  renderTopology();
}

// --------------------------------------------------------------------------- //
// Status strip
// --------------------------------------------------------------------------- //
function renderStatus() {
  const online = devices.filter((d) => d.is_online).length;
  const subs = status.subnets || (status.subnet ? [status.subnet] : []);
  const subnetLabel = subs.length > 1 ? `${subs[0]} +${subs.length - 1}` : (subs[0] || "—");
  const items = [
    [subs.length > 1 ? "Subnets" : "Subnet", subnetLabel],
    ["Gateway", status.gateway || "—"],
    ["Devices", `${online} online / ${devices.length}`],
    ["Last scan", status.scanning ? "scanning…" : fmtTime(status.last_scan)],
  ];
  document.getElementById("statusStrip").innerHTML = items
    .map(([l, v]) => `<div class="status-item"><span class="label">${l}</span><span class="value">${v}</span></div>`)
    .join("");
  const btn = document.getElementById("scanBtn");
  btn.disabled = !!status.scanning;
  btn.textContent = status.scanning ? "Scanning…" : "Scan now";
}

// --------------------------------------------------------------------------- //
// Device grid
// --------------------------------------------------------------------------- //
function renderDevices() {
  const grid = document.getElementById("deviceGrid");
  const empty = document.getElementById("devicesEmpty");
  empty.style.display = devices.length ? "none" : "block";

  // Router first, then online, then by IP.
  const sorted = [...devices].sort((a, b) => {
    if (a.device_type === "router") return -1;
    if (b.device_type === "router") return 1;
    if (a.is_online !== b.is_online) return a.is_online ? -1 : 1;
    return ipNum(a.ip) - ipNum(b.ip);
  });

  grid.innerHTML = sorted.map(deviceCard).join("");
  grid.querySelectorAll(".card").forEach((el) =>
    el.addEventListener("click", () => openDetail(el.dataset.key))
  );
}

function deviceCard(d) {
  const risky = (d.ports || []).filter((p) => p.risky);
  const riskBadges = risky.map((p) => `<span class="badge risk" title="${p.risky}">⚠ ${p.port}</span>`).join("");
  const portBadge = (d.ports || []).length
    ? `<span class="badge">${d.ports.length} open port${d.ports.length > 1 ? "s" : ""}</span>` : "";
  const trusted = d.trusted ? `<span class="badge trusted">✓ trusted</span>` : "";
  return `
    <div class="card" data-key="${enc(d.key)}">
      <div class="status-corner">
        <span class="dot ${d.is_online ? "online" : "offline"}"></span>${d.is_online ? "online" : "offline"}
      </div>
      <div class="top">
        <div class="icon">${ICONS[d.device_type] || ICONS.unknown}</div>
        <div>
          <div class="name">${enc(d.display_name)}</div>
          <div class="sub">${enc(d.ip)} · ${enc(d.vendor || "unknown vendor")}</div>
        </div>
      </div>
      <div class="meta">
        <span class="badge type">${TYPE_LABEL[d.device_type] || "Unknown"}</span>
        ${d.os_guess ? `<span class="badge">${enc(d.os_guess)}</span>` : ""}
        ${portBadge}${trusted}${riskBadges}
      </div>
      <div class="confidence-bar" title="Identification confidence: ${d.confidence}%">
        <i style="width:${Math.max(6, d.confidence)}%"></i>
      </div>
    </div>`;
}

// --------------------------------------------------------------------------- //
// Detail modal
// --------------------------------------------------------------------------- //
function openDetail(key) {
  const d = devices.find((x) => x.key === key);
  if (!d) return;
  const ports = (d.ports || []).length
    ? d.ports.map((p) => `<span class="badge ${p.risky ? "risk" : ""}" title="${p.risky || p.service}">${p.port} ${p.service || ""}</span>`).join(" ")
    : '<span class="sub">none detected</span>';
  const reasons = (d.reasons || []).map((r) => `• ${enc(r)}`).join("<br>");

  document.getElementById("modal").innerHTML = `
    <h2>${ICONS[d.device_type] || ICONS.unknown} ${enc(d.display_name)}</h2>
    <div class="sub">${TYPE_LABEL[d.device_type] || "Unknown"} · confidence ${d.confidence}%</div>
    <div class="kv">
      <div class="k">IP address</div><div>${enc(d.ip)}</div>
      <div class="k">MAC address</div><div>${enc(d.mac || "—")}</div>
      <div class="k">Vendor</div><div>${enc(d.vendor || "—")}</div>
      <div class="k">Hostname</div><div>${enc(d.hostname || "—")}</div>
      <div class="k">OS guess</div><div>${enc(d.os_guess || "—")}</div>
      <div class="k">Status</div><div>${d.is_online ? "🟢 online" : "⚪ offline"}</div>
      <div class="k">First seen</div><div>${fmtTime(d.first_seen)}</div>
      <div class="k">Last seen</div><div>${fmtTime(d.last_seen)}</div>
      <div class="k">Open ports</div><div class="ports-list">${ports}</div>
    </div>
    ${reasons ? `<div class="reasons"><b>Why identified this way:</b><br>${reasons}</div>` : ""}
    <div id="deepSection">${renderDeep(d)}</div>
    <div class="row">
      <input type="text" id="labelInput" placeholder="Custom name (e.g. Living Room TV)" value="${enc(d.label || "")}" />
    </div>
    <div class="row">
      <label class="toggle"><input type="checkbox" id="trustedInput" ${d.trusted ? "checked" : ""}/> Mark as trusted device</label>
    </div>
    <div class="actions">
      <button class="ghost" id="deepBtn" data-key="${enc(d.key)}">🔬 Deep Scan</button>
      <button class="ghost" id="closeModal">Close</button>
      <button class="primary" id="saveModal" data-key="${enc(d.key)}">Save</button>
    </div>`;

  document.getElementById("modalBackdrop").classList.add("open");
  document.getElementById("closeModal").onclick = closeModal;
  document.getElementById("deepBtn").onclick = (e) => doDeepScan(e.target.dataset.key);
  document.getElementById("saveModal").onclick = async (e) => {
    const label = document.getElementById("labelInput").value.trim();
    const trusted = document.getElementById("trustedInput").checked;
    await patchJSON(`/api/devices/${encodeURIComponent(e.target.dataset.key)}`, { label, trusted });
    closeModal();
    await refreshAll();
  };
}
function closeModal() {
  document.getElementById("modalBackdrop").classList.remove("open");
}

function renderDeep(d) {
  const det = d.details || {};
  const cves = d.cves || [];
  let html = "";

  if (det.upnp) {
    const u = det.upnp;
    const parts = [u.manufacturer, u.model_name, u.model_number].filter(Boolean).join(" ");
    html += kvline("UPnP", `${enc(u.friendly_name || parts)}${u.serial_number ? " · SN " + enc(u.serial_number) : ""}`);
  }
  if (det.mdns_model) html += kvline("mDNS model", enc(det.mdns_model));
  if (det.snmp && (det.snmp.descr || det.snmp.name)) {
    html += kvline("SNMP", enc(det.snmp.name || "") + (det.snmp.descr ? " · " + enc(det.snmp.descr) : ""));
  }
  if (det.passive && (det.passive.dhcp_os || det.passive.lldp_name)) {
    html += kvline("Passive", enc([det.passive.dhcp_os, det.passive.lldp_name].filter(Boolean).join(" · ")));
  }
  if (det.ports && det.ports.length) {
    const svc = det.ports.map((p) => {
      const bits = [p.http_server, p.banner, p.http_title, p.tls_cn].filter(Boolean).join(" ");
      return `${p.port}: ${enc(bits.slice(0, 60))}`;
    }).join("<br>");
    html += kvline("Services", svc);
  }

  if (cves.length) {
    const items = cves.slice(0, 12).map((c) =>
      `<div class="cve ${(c.severity || "").toLowerCase()}"><b>${enc(c.id)}</b>
       <span class="cve-sev">${enc(c.severity)} ${c.score || ""}</span>
       <div class="cve-sum">${enc((c.summary || "").slice(0, 140))}</div></div>`
    ).join("");
    html += `<div class="cve-block"><b>⚠ Known vulnerabilities (${cves.length})</b>${items}</div>`;
  }

  const when = d.deep_scanned_at ? `Last deep scan: ${fmtTime(d.deep_scanned_at)}` : "Not deep-scanned yet.";
  return `<div class="deep-wrap"><div class="deep-meta">${when}</div>${html || '<div class="sub">Run a deep scan to pull model, services, and known vulnerabilities.</div>'}</div>`;
}

function kvline(k, v) {
  return `<div class="deep-kv"><span class="dk">${enc(k)}</span><span class="dv">${v}</span></div>`;
}

async function doDeepScan(key) {
  const section = document.getElementById("deepSection");
  const btn = document.getElementById("deepBtn");
  if (btn) { btn.disabled = true; btn.textContent = "Scanning…"; }
  if (section) section.innerHTML = '<div class="sub">Running deep scan (UPnP, banners, SNMP, CVE lookup)… this can take ~30s.</div>';
  try {
    const updated = await api(`/api/devices/${encodeURIComponent(key)}/deepscan`, { method: "POST" });
    const idx = devices.findIndex((x) => x.key === key);
    if (idx >= 0) devices[idx] = updated;
    if (section) section.innerHTML = renderDeep(updated);
  } catch (e) {
    if (section) section.innerHTML = '<div class="sub">Deep scan failed.</div>';
  }
  if (btn) { btn.disabled = false; btn.textContent = "🔬 Deep Scan"; }
}

// --------------------------------------------------------------------------- //
// Topology (SVG: router in the center, devices on a ring)
// --------------------------------------------------------------------------- //
function renderTopology() {
  const svg = document.getElementById("topology");
  const rect = svg.getBoundingClientRect();
  const W = rect.width || 900, H = rect.height || 520;
  const cx = W / 2, cy = H / 2;
  const router = devices.find((d) => d.device_type === "router");
  const others = devices.filter((d) => d.device_type !== "router");
  const R = Math.min(W, H) / 2 - 80;

  let edges = "", nodes = "";
  others.forEach((d, i) => {
    const a = (2 * Math.PI * i) / Math.max(1, others.length) - Math.PI / 2;
    const x = cx + R * Math.cos(a), y = cy + R * Math.sin(a);
    edges += `<line x1="${cx}" y1="${cy}" x2="${x}" y2="${y}" stroke="${d.is_online ? "#2a3852" : "#1b2434"}" stroke-width="1.5"/>`;
    nodes += topoNode(d, x, y);
  });
  const centerNode = router
    ? topoNode(router, cx, cy, true)
    : `<g><circle cx="${cx}" cy="${cy}" r="30" fill="#1a2334" stroke="#2a4a76"/><text x="${cx}" y="${cy + 8}" text-anchor="middle" font-size="26">🌐</text><text x="${cx}" y="${cy + 46}" text-anchor="middle" fill="#8a97ab" font-size="11">Gateway</text></g>`;

  svg.innerHTML = edges + nodes + centerNode;
  svg.querySelectorAll("[data-key]").forEach((el) =>
    el.addEventListener("click", () => openDetail(el.dataset.key))
  );

  const types = [...new Set(devices.map((d) => d.device_type))];
  document.getElementById("legend").innerHTML = types
    .map((t) => `<span>${ICONS[t] || ICONS.unknown} ${TYPE_LABEL[t] || t}</span>`)
    .join("");
}

function topoNode(d, x, y, big = false) {
  const r = big ? 30 : 22;
  const name = (d.display_name || d.ip || "").slice(0, 16);
  const ring = d.is_online ? "#4f9dff" : "#3a4658";
  return `
    <g data-key="${enc(d.key)}" style="cursor:pointer">
      <circle cx="${x}" cy="${y}" r="${r}" fill="#131a26" stroke="${ring}" stroke-width="2"/>
      <text x="${x}" y="${y + (big ? 9 : 7)}" text-anchor="middle" font-size="${big ? 26 : 20}">${ICONS[d.device_type] || ICONS.unknown}</text>
      <text x="${x}" y="${y + r + 15}" text-anchor="middle" fill="#c3ccd9" font-size="11">${enc(name)}</text>
    </g>`;
}

// --------------------------------------------------------------------------- //
// Events
// --------------------------------------------------------------------------- //
function renderEvents() {
  const list = document.getElementById("eventList");
  document.getElementById("alertsEmpty").style.display = events.length ? "none" : "block";
  const unack = events.filter((e) => !e.acknowledged && e.severity !== "info").length;
  document.getElementById("alertCount").textContent = unack ? `(${unack})` : "";
  list.innerHTML = events
    .map((e) => `<div class="event ${e.severity}"><span class="etime">${fmtTime(e.ts)}</span><span class="emsg">${enc(e.message)}</span></div>`)
    .join("");
}

// --------------------------------------------------------------------------- //
// Traffic
// --------------------------------------------------------------------------- //
let trafficHistory = [];

async function refreshTraffic() {
  const [t, hist] = await Promise.all([
    getJSON("/api/traffic"),
    getJSON("/api/traffic/history?limit=180"),
  ]);
  trafficHistory = hist;
  renderTrafficCards(t.throughput);
  renderTrafficChart();
  renderConnTable(t.connections);
}

function renderTrafficCards(tp) {
  if (!tp) return;
  document.getElementById("tpDown").textContent = fmtRate(tp.recv_rate);
  document.getElementById("tpUp").textContent = fmtRate(tp.sent_rate);
  document.getElementById("tpConns").textContent = tp.connections ?? "—";
}

function renderTrafficChart() {
  const svg = document.getElementById("tpChart");
  const W = 800, H = 220, pad = 6;
  const data = trafficHistory;
  if (!data.length) { svg.innerHTML = ""; return; }
  const maxRate = Math.max(1, ...data.map((d) => Math.max(d.recv_rate, d.sent_rate)));
  const n = data.length;
  const x = (i) => pad + (i * (W - 2 * pad)) / Math.max(1, n - 1);
  const y = (v) => H - pad - (v / maxRate) * (H - 2 * pad);
  const line = (key) => data.map((d, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(d[key]).toFixed(1)}`).join(" ");
  const area = (key, color) =>
    `<path d="${line(key)} L${x(n - 1).toFixed(1)},${H - pad} L${x(0).toFixed(1)},${H - pad} Z" fill="${color}" opacity="0.12"/>`;
  svg.innerHTML =
    `<line x1="0" y1="${H - pad}" x2="${W}" y2="${H - pad}" stroke="#243044"/>` +
    area("recv_rate", "#4f9dff") + area("sent_rate", "#37e0a0") +
    `<path d="${line("recv_rate")}" fill="none" stroke="#4f9dff" stroke-width="2"/>` +
    `<path d="${line("sent_rate")}" fill="none" stroke="#37e0a0" stroke-width="2"/>` +
    `<text x="8" y="16" fill="#8a97ab" font-size="11">peak ${fmtRate(maxRate)}</text>`;
}

function renderConnTable(conns) {
  const tbody = document.querySelector("#connTable tbody");
  if (!conns || !conns.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="sub" style="padding:16px">No active outbound connections.</td></tr>`;
    return;
  }
  const byIp = {};
  devices.forEach((d) => { byIp[d.ip] = d.display_name; });
  const rows = conns.slice(0, 150).map((c) => {
    const dev = byIp[c.remote_ip] ? enc(byIp[c.remote_ip]) : "";
    return `<tr>
      <td class="proc">${enc(c.process || "—")}</td>
      <td>${enc(c.local)}</td>
      <td>${enc(c.remote_ip)}</td>
      <td>${enc(c.remote_port)}</td>
      <td>${enc(c.status)}</td>
      <td>${dev}</td>
    </tr>`;
  }).join("");
  tbody.innerHTML = rows;
}

function pushTrafficPoint(tp) {
  trafficHistory.push({ ts: new Date().toISOString(), sent_rate: tp.sent_rate, recv_rate: tp.recv_rate });
  if (trafficHistory.length > 180) trafficHistory.shift();
  if (document.getElementById("view-traffic").classList.contains("active")) {
    renderTrafficCards({ ...tp });
    renderTrafficChart();
  }
}

function fmtRate(bytesPerSec) {
  const b = bytesPerSec || 0;
  if (b < 1024) return `${b.toFixed(0)} B/s`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB/s`;
  return `${(b / 1024 / 1024).toFixed(2)} MB/s`;
}

// --------------------------------------------------------------------------- //
// Hunting (flows)
// --------------------------------------------------------------------------- //
async function refreshHunting() {
  const [stats, top] = await Promise.all([
    getJSON("/api/flows/stats"),
    getJSON("/api/flows/top?limit=15"),
  ]);
  renderFlowStats(stats);
  renderTopTalkers(top);
  await runFlowSearch();
}

function renderFlowStats(s) {
  const el = document.getElementById("flowStats");
  if (!s || !s.available) { el.innerHTML = `<div class="sub">Flow store initializing… flows appear as traffic is observed.</div>`; return; }
  const card = (label, val) => `<div class="tp-card"><span class="label">${label}</span><span class="value">${val}</span></div>`;
  el.innerHTML = card("Total flows", s.total_flows) + card("Distinct remotes", s.distinct_remotes) + card("External flows", s.external_flows);
}

function renderTopTalkers(top) {
  const el = document.getElementById("topTalkers");
  if (!top || !top.length) { el.innerHTML = `<div class="sub">No external flows yet.</div>`; return; }
  const max = Math.max(...top.map((t) => t.samples), 1);
  el.innerHTML = top.map((t) =>
    `<div class="talker" data-ip="${enc(t.remote_ip)}">
       <span>${enc(t.remote_ip)}</span><span class="cnt">${t.flows} flows</span>
       <div class="talker-bar" style="width:100%"><i style="width:${Math.round(t.samples / max * 100)}%"></i></div>
     </div>`
  ).join("");
  el.querySelectorAll(".talker").forEach((d) =>
    d.addEventListener("click", () => { document.getElementById("flowSearch").value = d.dataset.ip; runFlowSearch(); })
  );
}

async function runFlowSearch() {
  const search = document.getElementById("flowSearch").value.trim();
  const external = document.getElementById("flowExternal").checked;
  const flows = await getJSON(`/api/flows?search=${encodeURIComponent(search)}&external_only=${external}&limit=300`);
  const tbody = document.querySelector("#flowTable tbody");
  if (!flows.length) { tbody.innerHTML = `<tr><td colspan="7" class="sub" style="padding:16px">No flows match.</td></tr>`; return; }
  tbody.innerHTML = flows.map((f) =>
    `<tr>
      <td class="proc">${enc(f.process || "—")}</td>
      <td>${enc(f.local_ip)}</td>
      <td>${enc(f.remote_ip)}${f.remote_is_local ? " <span class='sub'>(LAN)</span>" : ""}</td>
      <td>${enc(f.remote_port)}</td>
      <td>${f.samples}</td>
      <td>${fmtTime(f.first_seen)}</td>
      <td>${fmtTime(f.last_seen)}</td>
    </tr>`
  ).join("");
}

// --------------------------------------------------------------------------- //
// Security
// --------------------------------------------------------------------------- //
async function refreshSecurity() {
  const [status, alerts] = await Promise.all([
    getJSON("/api/security/status"),
    getJSON("/api/security/ids-alerts?limit=100").catch(() => []),
  ]);
  renderSecStatus(status);
  renderIdsAlerts(alerts);
}

function renderSecStatus(s) {
  const chip = (on, label) =>
    `<div class="sec-chip"><span class="dot ${on ? "on" : "off"}"></span>${label}: <b>${on ? "ready" : "not set"}</b></div>`;
  document.getElementById("secStatus").innerHTML =
    chip(s.virustotal, "VirusTotal") +
    chip(s.sensor_configured, "IDS sensor") +
    chip(s.yara, "YARA rules") +
    chip(s.auto_check, "Auto threat-check");
}

function renderIdsAlerts(alerts) {
  const list = document.getElementById("idsList");
  document.getElementById("idsEmpty").style.display = alerts.length ? "none" : "block";
  list.innerHTML = alerts.map((a) =>
    `<div class="event ${a.severity}"><span class="etime">${enc(a.source)}</span>
     <span class="emsg">${enc(a.signature || a.category)} <span class="sub">${enc(a.src_ip)} → ${enc(a.dest_ip)}</span></span></div>`
  ).join("");
}

function verdictBlock(v) {
  const cls = ["clean", "malicious", "suspicious"].includes(v.verdict) ? v.verdict : "unknown";
  return `<span class="verdict ${cls}">${enc(v.verdict)}</span>
    <div class="kv2">${enc(v.indicator || v.file || "")}<br>${enc(v.detail || v.vt_detail || "")}
    ${v.sha256 ? "<br>sha256: " + enc(v.sha256) : ""}
    ${v.yara_matches && v.yara_matches.length ? "<br>YARA: " + enc(v.yara_matches.join(", ")) : ""}</div>`;
}

async function doIpCheck() {
  const ip = document.getElementById("ipInput").value.trim();
  if (!ip) return;
  const box = document.getElementById("ipResult");
  box.innerHTML = "<span class='sub'>checking…</span>";
  try {
    const v = await api("/api/security/check-ip", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip }),
    });
    box.innerHTML = verdictBlock(v);
  } catch (e) { box.innerHTML = "<span class='sub'>check failed</span>"; }
}

async function doFileScan() {
  const path = document.getElementById("fileInput").value.trim();
  if (!path) return;
  const box = document.getElementById("fileResult");
  box.innerHTML = "<span class='sub'>scanning…</span>";
  try {
    const r = await api("/api/security/scan-file", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path }),
    });
    box.innerHTML = r.error ? `<span class='sub'>${enc(r.error)}</span>`
      : verdictBlock({ verdict: r.vt_verdict, file: r.file, vt_detail: r.vt_detail, sha256: r.sha256, yara_matches: r.yara_matches });
  } catch (e) { box.innerHTML = "<span class='sub'>scan failed</span>"; }
}

// --------------------------------------------------------------------------- //
// Tabs, WebSocket, utils
// --------------------------------------------------------------------------- //
function setupTabs() {
  document.querySelectorAll("nav.tabs button").forEach((btn) =>
    btn.addEventListener("click", () => {
      document.querySelectorAll("nav.tabs button").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById("view-" + btn.dataset.view).classList.add("active");
      if (btn.dataset.view === "topology") renderTopology();
      if (btn.dataset.view === "traffic") refreshTraffic().catch(() => {});
      if (btn.dataset.view === "hunting") refreshHunting().catch(() => {});
      if (btn.dataset.view === "security") refreshSecurity().catch(() => {});
      if (btn.dataset.view === "alerts") api("/api/events/acknowledge", { method: "POST" }).then(refreshAll);
    })
  );
}

function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onmessage = (ev) => {
    let msg = {};
    try { msg = JSON.parse(ev.data); } catch (_) { return; }
    if (msg.type === "traffic") {
      pushTrafficPoint(msg.traffic);          // lightweight live update
    } else {
      refreshAll();                            // devices/events/status changed
    }
  };
  ws.onclose = () => setTimeout(connectWS, 3000);
  // keepalive
  setInterval(() => { try { ws.readyState === 1 && ws.send("ping"); } catch (_) {} }, 20000);
}

function ipNum(ip) {
  return (ip || "0.0.0.0").split(".").reduce((a, o) => a * 256 + (parseInt(o, 10) || 0), 0);
}
function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return d.toLocaleString();
}
function enc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// --------------------------------------------------------------------------- //
// Boot
// --------------------------------------------------------------------------- //
function initDisclaimer() {
  if (!localStorage.getItem("netscope_disclaimer_ok")) {
    document.getElementById("disclaimer").style.display = "block";
  }
  document.getElementById("dismissDisclaimer").onclick = () => {
    localStorage.setItem("netscope_disclaimer_ok", "1");
    document.getElementById("disclaimer").style.display = "none";
  };
}

document.getElementById("scanBtn").onclick = async () => {
  await api("/api/scan", { method: "POST" });
  status.scanning = true;
  renderStatus();
};
document.getElementById("modalBackdrop").onclick = (e) => {
  if (e.target.id === "modalBackdrop") closeModal();
};
document.getElementById("ipCheckBtn").onclick = doIpCheck;
document.getElementById("fileScanBtn").onclick = doFileScan;
document.getElementById("flowSearchBtn").onclick = () => runFlowSearch();
document.getElementById("flowSearch").addEventListener("keydown", (e) => { if (e.key === "Enter") runFlowSearch(); });

setupTabs();
initDisclaimer();
refreshAll().catch(() => {});
connectWS();
setInterval(refreshAll, 15000); // safety refresh in case a WS message is missed
