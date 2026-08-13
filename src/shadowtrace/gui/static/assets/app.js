const $ = (sel) => document.querySelector(sel);

async function api(path, opts = {}) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }
  return res.json();
}

function toast(msg) {
  const el = $("#toast");
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.hidden = true; }, 3200);
}

function setLiveUI(snap) {
  const running = !!snap?.running;
  $("#live-dot").classList.toggle("live", running);
  $("#live-dot").classList.toggle("idle", !running);
  $("#live-eyebrow").textContent = running ? "LIVE · MONITORING" : "LIVE · IDLE";
  $("#s-rate").textContent = snap?.events_last_minute ?? 0;
  const parts = [];
  if (snap?.watched_paths?.length) parts.push(`tail: ${snap.watched_paths.join(", ")}`);
  if (snap?.capture_iface) parts.push(`capture: ${snap.capture_iface}`);
  if (snap?.stream_bind) parts.push(`stream: ${snap.stream_bind}`);
  $("#source-meta").textContent = parts.length ? parts.join(" · ") : "No active watchers";
  renderFeed(snap?.recent_events || []);
}

function setStats(s) {
  $("#s-events").textContent = s.events ?? 0;
  $("#s-fps").textContent = s.fingerprints ?? 0;
  $("#s-clusters").textContent = s.clusters ?? 0;
}

function renderClusters(clusters) {
  const root = $("#clusters");
  if (!clusters?.length) {
    root.innerHTML = `<p class="empty">No clusters yet — start monitoring or ingest logs.</p>`;
    if (!$("#verdict").dataset.locked) {
      $("#verdict").textContent = "Waiting for traffic";
      $("#verdict").classList.remove("hit");
      $("#verdict-sub").textContent = "Tail auth/access logs, enable packet capture, or push events via API / UDP.";
    }
    return;
  }
  root.innerHTML = clusters.map((c) => {
    const multi = c.members.length > 1;
    const note = multi ? (c.notes || "linked") : "singleton";
    return `<article class="cluster ${multi ? "multi" : ""}">
      <div class="title">${c.label}${multi ? " — probable same operator" : ""}</div>
      <div class="meta">${note} · confidence ${(c.confidence * 100).toFixed(0)}%</div>
      <div class="members">${c.members.join("  →  ")}</div>
    </article>`;
  }).join("");

  const multi = clusters
    .filter((c) => c.members.length > 1)
    .sort((a, b) => b.confidence - a.confidence || b.members.length - a.members.length)[0];
  if (multi) {
    $("#verdict").textContent = `${multi.label} — probable same operator`;
    $("#verdict").classList.add("hit");
    $("#verdict-sub").textContent = `Cross-IP behavioral link: ${multi.members.join(", ")}`;
    $("#verdict").dataset.locked = "1";
  } else {
    $("#verdict").textContent = "Sources fingerprinted — no multi-IP operator link yet";
    $("#verdict").classList.remove("hit");
    $("#verdict-sub").textContent = "Continuing to score behavioral similarity as events arrive.";
    delete $("#verdict").dataset.locked;
  }
}

function renderFingerprints(fps) {
  const root = $("#fingerprints");
  if (!fps?.length) {
    root.innerHTML = `<p class="empty">No fingerprints yet.</p>`;
    return;
  }
  root.innerHTML = fps.map((fp) => {
    const s = fp.summary || {};
    const dims = [
      ["temporal", s.temporal_signature],
      ["enumeration", s.enumeration_pattern],
      ["protocol", s.protocol_sequence],
      ["username", s.username_behavior],
    ];
    const bars = dims.map(([k, v]) => {
      const pct = Math.round((v || 0) * 100);
      return `<div class="bar-row"><span>${k}</span><div class="bar"><i style="width:${pct}%"></i></div><span>${(v || 0).toFixed(2)}</span></div>`;
    }).join("");
    const labels = fp.labels || {};
    const labelText = Object.entries(labels).map(([k, v]) => `${k}:${v}`).join(" · ");
    return `<article class="fp">
      <div class="ip">${fp.src_ip}</div>
      <div class="meta" style="color:var(--muted);font-size:0.72rem">${fp.event_count} events</div>
      <div class="bars">${bars}</div>
      <div class="labels">${labelText}</div>
    </article>`;
  }).join("");
  requestAnimationFrame(() => {
    root.querySelectorAll(".bar > i").forEach((el) => {
      const w = el.style.width;
      el.style.width = "0";
      requestAnimationFrame(() => { el.style.width = w; });
    });
  });
}

function renderAttributions(attrs) {
  const tbody = $("#attr-table tbody");
  const rows = (attrs || []).slice(0, 40);
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty">No pairs yet.</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.map((a) => {
    const b = a.breakdown || {};
    const pct = Math.round(a.score * 100);
    return `<tr>
      <td>${a.ip_a}</td><td>${a.ip_b}</td>
      <td class="${pct >= 85 ? "score-hi" : ""}">${pct}%</td>
      <td>${(b.temporal_signature ?? 0).toFixed(2)}</td>
      <td>${(b.enumeration_pattern ?? 0).toFixed(2)}</td>
      <td>${(b.protocol_sequence ?? 0).toFixed(2)}</td>
      <td>${(b.username_behavior ?? 0).toFixed(2)}</td>
    </tr>`;
  }).join("");
}

function renderDetections(findings) {
  const root = $("#detections");
  if (!findings?.length) {
    root.innerHTML = `<p class="empty">No detector findings.</p>`;
    return;
  }
  root.innerHTML = findings.map((f) =>
    `<div class="det ${f.severity || ""}"><strong>${f.type}</strong> · ${f.src_ip}<br/><span style="color:var(--muted)">${f.detail}</span></div>`
  ).join("");
}

function renderFeed(events) {
  const root = $("#feed");
  if (!events?.length) {
    root.innerHTML = `<p class="empty">Event feed empty — waiting for live ingest.</p>`;
    return;
  }
  const rows = [...events].reverse().slice(0, 30);
  root.innerHTML = rows.map((e) =>
    `<div class="row"><span>${(e.ts || "").replace("T", " ").slice(0, 19)}</span><span class="ip">${e.src_ip || ""}</span><span class="type">${e.event_type || ""}${e.username ? " · " + e.username : ""}${e.path ? " · " + e.path : ""}</span></div>`
  ).join("");
}

function drawGraph(graph) {
  const canvas = $("#graph");
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const cssW = canvas.clientWidth || 640;
  const cssH = 420;
  canvas.width = cssW * dpr;
  canvas.height = cssH * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssW, cssH);

  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];
  if (!nodes.length) {
    ctx.fillStyle = "#7f93a4";
    ctx.font = "12px IBM Plex Mono";
    ctx.fillText("No graph data yet", 24, 40);
    return;
  }

  const cx = cssW / 2;
  const cy = cssH / 2;
  const r = Math.min(cssW, cssH) * 0.32;
  const pos = {};
  nodes.forEach((n, i) => {
    const ang = (i / nodes.length) * Math.PI * 2 - Math.PI / 2;
    pos[n.id] = { x: cx + Math.cos(ang) * r, y: cy + Math.sin(ang) * r };
  });

  const t = (Date.now() % 3000) / 3000;
  edges.forEach((e) => {
    const a = pos[e.source];
    const b = pos[e.target];
    if (!a || !b) return;
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    const w = e.weight || 0.5;
    ctx.strokeStyle = `rgba(61,214,198,${0.25 + w * 0.55 + Math.sin(t * Math.PI * 2) * 0.08})`;
    ctx.lineWidth = 1 + w * 2.5;
    ctx.stroke();
  });

  nodes.forEach((n) => {
    const p = pos[n.id];
    ctx.beginPath();
    ctx.arc(p.x, p.y, 8, 0, Math.PI * 2);
    ctx.fillStyle = n.cluster ? "#3dd6c6" : "#7f93a4";
    ctx.fill();
    ctx.strokeStyle = "#0a1014";
    ctx.lineWidth = 2;
    ctx.stroke();
    ctx.fillStyle = "#d7e2ea";
    ctx.font = "11px IBM Plex Mono";
    ctx.fillText(n.id, p.x + 12, p.y + 4);
  });
}

let graphAnim = null;
let lastGraph = { nodes: [], edges: [] };
function startGraphLoop(graph) {
  lastGraph = graph || lastGraph;
  cancelAnimationFrame(graphAnim);
  const tick = () => {
    drawGraph(lastGraph);
    graphAnim = requestAnimationFrame(tick);
  };
  tick();
}

async function refreshAll() {
  const [stats, clusters, fps, attrs, dets, graph, live] = await Promise.all([
    api("/api/stats"),
    api("/api/clusters"),
    api("/api/fingerprints"),
    api("/api/attributions"),
    api("/api/detections"),
    api("/api/graph"),
    api("/api/live/status"),
  ]);
  setStats(stats);
  setLiveUI(live);
  renderClusters(clusters.clusters || []);
  renderFingerprints(fps.fingerprints || []);
  renderAttributions(attrs.attributions || []);
  renderDetections(dets.findings || []);
  startGraphLoop(graph);
}

async function startMonitor() {
  const paths = ($("#mon-paths").value || "")
    .split(/[,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  const udpRaw = $("#mon-udp").value.trim();
  const body = {
    paths,
    kind: $("#mon-kind").value,
    capture: $("#mon-capture").checked,
    iface: $("#mon-iface").value.trim() || null,
    udp_port: udpRaw ? Number(udpRaw) : null,
    udp_host: "0.0.0.0",
  };
  try {
    await api("/api/live/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    toast("Live monitor started");
    await refreshAll();
  } catch (e) {
    toast(String(e.message || e));
  }
}

async function stopMonitor() {
  try {
    await api("/api/live/stop", { method: "POST" });
    toast("Monitor stopped");
    await refreshAll();
  } catch (e) {
    toast(String(e.message || e));
  }
}

async function reAttribute() {
  try {
    await api("/api/live/attribute", { method: "POST" });
    toast("Attribution refreshed");
    await refreshAll();
  } catch (e) {
    toast(String(e.message || e));
  }
}

async function resetDb() {
  if (!confirm("Clear all SHADOWTRACE data?")) return;
  try {
    await api("/api/reset", { method: "POST" });
    delete $("#verdict").dataset.locked;
    toast("Database cleared");
    await refreshAll();
  } catch (e) {
    toast(String(e.message || e));
  }
}

$("#btn-start").addEventListener("click", startMonitor);
$("#btn-stop").addEventListener("click", stopMonitor);
$("#btn-attribute").addEventListener("click", reAttribute);
$("#btn-reset").addEventListener("click", resetDb);

$("#file-input").addEventListener("change", async (ev) => {
  const file = ev.target.files?.[0];
  if (!file) return;
  const kind = $("#kind-select").value;
  const fd = new FormData();
  fd.append("file", file);
  try {
    const res = await fetch(`/api/ingest/upload?kind=${encodeURIComponent(kind)}`, {
      method: "POST",
      body: fd,
    });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    toast(`Ingested ${data.ingested} events`);
    await refreshAll();
  } catch (e) {
    toast(String(e.message || e));
  } finally {
    ev.target.value = "";
  }
});

$("#compare-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const ip_a = $("#ip-a").value.trim();
  const ip_b = $("#ip-b").value.trim();
  try {
    const r = await api("/api/compare", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip_a, ip_b }),
    });
    const b = r.breakdown || {};
    $("#compare-out").innerHTML = `<div class="compare-card">
      <div class="pct">${r.likely_same_actor_pct}%</div>
      <div>Likely same actor</div>
      <div style="margin-top:0.6rem;color:var(--muted);font-size:0.78rem">
        temporal ${b.temporal_signature?.toFixed(2)} ·
        enumeration ${b.enumeration_pattern?.toFixed(2)} ·
        protocol ${b.protocol_sequence?.toFixed(2)} ·
        username ${b.username_behavior?.toFixed(2)}
      </div>
    </div>`;
  } catch (e) {
    toast(String(e.message || e));
  }
});

function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws/live`);
  $("#ws-state").textContent = "websocket connecting";
  ws.onopen = () => { $("#ws-state").textContent = "websocket live"; };
  ws.onclose = () => {
    $("#ws-state").textContent = "websocket reconnecting…";
    setTimeout(connectWs, 2000);
  };
  ws.onerror = () => { try { ws.close(); } catch (_) {} };
  ws.onmessage = async (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    if (msg.type === "ping" || msg.type === "hello" || msg.type === "status") {
      if (msg.status) setLiveUI(msg.status);
      return;
    }
    if (msg.type === "events") {
      // light refresh of live counters
      try {
        const live = await api("/api/live/status");
        setLiveUI(live);
      } catch (_) {}
      return;
    }
    if (msg.type === "attribution") {
      setStats(msg.stats || {});
      renderClusters(msg.clusters || []);
      renderAttributions(msg.attributions || []);
      renderDetections(msg.findings || []);
      try {
        const [fps, graph, live] = await Promise.all([
          api("/api/fingerprints"),
          api("/api/graph"),
          api("/api/live/status"),
        ]);
        renderFingerprints(fps.fingerprints || []);
        startGraphLoop(graph);
        setLiveUI(live);
      } catch (_) {}
    }
  };
}

(async function boot() {
  try {
    const h = await api("/api/health");
    $("#api-health").textContent = `api ok · v${h.version}${h.live ? " · monitoring" : ""}`;
    await refreshAll();
    connectWs();
  } catch (e) {
    $("#api-health").textContent = "api offline";
    toast("API not reachable");
  }
})();
