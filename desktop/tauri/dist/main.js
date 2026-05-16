// Sidevers desktop frontend — vanilla JS, no bundler.
// Drives a live `sidevers-node` embedded in the Tauri process via
// `window.__TAURI__.core.invoke` (snake_case → camelCase param renaming).

const tauri = window.__TAURI__;
const invoke = tauri ? tauri.core.invoke : null;
const listen = tauri ? tauri.event.listen : null;

const $ = (id) => document.getElementById(id);

// Phase 3.B multi-side state -------------------------------------------------
// Hosted side currently selected as "active". Connect / Send / Pair commands
// operate on this side. Connections live in a map keyed by the active side's
// address (the Rust side holds the same map).
let activeSide = null;
// Track which sides currently have an open peer session so we can enable Send.
const connectedSides = new Set();
// Short-form labels for sides we've added/seen in this session, for the inbox
// to print "[work]" instead of the bech32 address. Keyed by side_address.
const sideLabels = new Map();

function clearStatus() {
  const el = $("error");
  el.textContent = "";
  el.classList.remove("ok");
}

function showError(msg) {
  const el = $("error");
  el.textContent = String(msg);
  el.classList.remove("ok");
}

function showOk(msg) {
  const el = $("error");
  el.textContent = msg;
  el.classList.add("ok");
}

async function call(cmd, args) {
  if (!invoke) {
    throw new Error(
      "Tauri runtime not available — open this page via `cargo tauri dev`, not a plain browser.",
    );
  }
  return await invoke(cmd, args);
}

function require(value, label) {
  if (!value || !value.trim()) {
    throw new Error(`${label} is required`);
  }
  return value.trim();
}

async function safe(fn) {
  clearStatus();
  try {
    await fn();
  } catch (e) {
    showError(e.message || e);
  }
}

function setStatus(running, text) {
  const dot = $("status-dot");
  dot.classList.toggle("dot-running", running);
  dot.classList.toggle("dot-idle", !running);
  $("status-text").textContent = text;
}

function disable(...ids) {
  for (const id of ids) $(id).disabled = true;
}
function enable(...ids) {
  for (const id of ids) $(id).disabled = false;
}

function shortenAddr(addr) {
  if (!addr || addr.length < 16) return addr || "";
  return `${addr.slice(0, 10)}…${addr.slice(-6)}`;
}

function setActiveSide(addr) {
  activeSide = addr;
  $("connect-from-side").value = addr || "";
  $("pair-from-side").value = addr || "";
  if (addr && connectedSides.has(addr)) {
    enable("send-dm");
  } else {
    disable("send-dm");
  }
  // Re-render the sides list so the visual highlight tracks the change.
  renderSides();
}

// ---- Live-node controls -----------------------------------------------

$("start-node").onclick = () =>
  safe(async () => {
    const dataDir = require($("data-dir").value, "data directory");
    const sideLabel = $("side-label").value.trim() || "work";
    const info = await call("start_node", { dataDir, sideLabel });
    sideLabels.set(info.side_address, sideLabel);
    setStatus(true, `Node up · primary ${shortenAddr(info.side_address)}`);
    disable("start-node");
    enable(
      "stop-node",
      "connect-peer",
      "gen-qr",
      "accept-qr",
      "refresh-sides",
      "add-side",
    );
    await refreshSides();
    setActiveSide(info.side_address);
    // Phase 3.A: rehydrate any DMs persisted from a prior run.
    await loadInboxHistory(info.side_address);
    showOk("node started");
  });

async function loadInboxHistory(sideAddress) {
  try {
    const history = await call("load_inbox_history", { sideAddress });
    // Render oldest first so the visual order ends up newest-on-top
    // after each prependInbox.
    for (let i = history.length - 1; i >= 0; i--) {
      const e = history[i];
      prependInbox(e.from, e.to, e.plaintext);
    }
  } catch (e) {
    // Non-fatal — log but don't block startup.
    console.warn("load_inbox_history failed:", e);
  }
}

$("stop-node").onclick = () =>
  safe(async () => {
    await call("stop_node");
    connectedSides.clear();
    sideLabels.clear();
    $("peer-side").value = "";
    $("qr-svg").innerHTML = "";
    $("qr-uri").value = "";
    $("qr-display").hidden = true;
    $("sides-list").innerHTML = "";
    setActiveSide(null);
    setStatus(false, "No node started");
    enable("start-node");
    disable(
      "stop-node",
      "connect-peer",
      "send-dm",
      "gen-qr",
      "accept-qr",
      "refresh-sides",
      "add-side",
    );
    showOk("node stopped");
  });

$("connect-peer").onclick = () =>
  safe(async () => {
    if (!activeSide) throw new Error("pick an active side first");
    const peerAddr = require($("peer-addr").value, "peer address");
    const resp = await call("connect_peer", {
      fromSide: activeSide,
      peerAddr,
    });
    $("peer-side").value = resp.peer_side;
    connectedSides.add(resp.from_side);
    if (activeSide === resp.from_side) enable("send-dm");
    showOk(`connected from ${shortenAddr(resp.from_side)}`);
  });

$("send-dm").onclick = () =>
  safe(async () => {
    if (!activeSide) throw new Error("pick an active side first");
    const text = require($("dm-text").value, "message text");
    await call("send_dm_live", { fromSide: activeSide, text });
    $("dm-text").value = "";
    showOk("DM sent");
  });

$("add-side").onclick = () =>
  safe(async () => {
    const label = $("extra-side-label").value.trim() || "extra";
    const resp = await call("add_side", { label });
    sideLabels.set(resp.side_address, label);
    $("extra-side-label").value = "";
    await refreshSides();
    showOk(`side added (${label}) on ${resp.listen_addr}`);
  });

// ---- Inbox event subscription -----------------------------------------

function prependInbox(from, to, plaintext) {
  const ul = $("inbox");
  const li = document.createElement("li");
  const meta = document.createElement("div");
  meta.className = "from";
  const toLabel = sideLabels.get(to) || shortenAddr(to);
  meta.textContent = `to [${toLabel}] · from ${shortenAddr(from)}`;
  const bodyDiv = document.createElement("div");
  bodyDiv.className = "body";
  bodyDiv.textContent = plaintext;
  li.appendChild(meta);
  li.appendChild(bodyDiv);
  ul.insertBefore(li, ul.firstChild);
}

if (listen) {
  listen("inbox:dm", (e) => {
    if (e && e.payload) {
      prependInbox(e.payload.from, e.payload.to, e.payload.plaintext);
    }
  });
}

// ---- Pairing flow -----------------------------------------------------

$("gen-qr").onclick = () =>
  safe(async () => {
    if (!activeSide) throw new Error("pick an active side first");
    const resp = await call("generate_pairing_qr_svg", {
      sideAddress: activeSide,
    });
    $("qr-svg").innerHTML = resp.svg;
    $("qr-uri").value = resp.uri;
    $("qr-display").hidden = false;
    showOk(`QR for ${shortenAddr(activeSide)} · valid for 10 minutes`);
  });

$("accept-qr").onclick = () =>
  safe(async () => {
    const qrUri = require($("accept-uri").value, "pairing URI");
    const resp = await call("accept_pairing_qr", { qrUri });
    $("accept-uri").value = "";
    sideLabels.set(resp.joined_side, "paired");
    await refreshSides();
    showOk(`paired · now hosting ${shortenAddr(resp.joined_side)}`);
  });

$("refresh-sides").onclick = () => safe(() => refreshSides());

let sidesCache = [];

async function refreshSides() {
  sidesCache = await call("list_sides");
  renderSides();
}

function renderSides() {
  const ul = $("sides-list");
  ul.innerHTML = "";
  if (sidesCache.length === 0) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "No sides hosted yet.";
    ul.appendChild(li);
    return;
  }
  for (const s of sidesCache) {
    const li = document.createElement("li");
    li.className = "side-row";
    if (s.side_address === activeSide) {
      li.classList.add("side-row-active");
    }
    if (connectedSides.has(s.side_address)) {
      li.classList.add("side-row-connected");
    }
    li.tabIndex = 0;
    li.setAttribute("role", "button");
    li.title = "Click to make this the active side";
    li.onclick = () => setActiveSide(s.side_address);
    li.onkeydown = (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        setActiveSide(s.side_address);
      }
    };

    const top = document.createElement("div");
    top.className = "side-top";
    const label = sideLabels.get(s.side_address) || "—";
    const tag = document.createElement("span");
    tag.className = "side-label";
    tag.textContent = label;
    // Phase 3.C lifecycle badge.
    const badge = document.createElement("span");
    badge.className = `side-badge lifecycle-${(s.lifecycle || "Created").toLowerCase()}`;
    badge.textContent = s.lifecycle || "Created";
    const dot = document.createElement("span");
    dot.className = "side-state";
    if (s.side_address === activeSide) dot.textContent = "● active";
    else if (connectedSides.has(s.side_address)) dot.textContent = "● connected";
    else dot.textContent = "";
    top.appendChild(tag);
    top.appendChild(badge);
    top.appendChild(dot);

    const a = document.createElement("div");
    a.className = "side-addr";
    a.textContent = s.side_address;
    const l = document.createElement("div");
    l.className = "side-listen";
    l.textContent = `listening on ${s.listen_addr}`;

    li.appendChild(top);
    li.appendChild(a);
    li.appendChild(l);

    // Phase 3.C retire button — only when not already retired.
    if (!s.is_retired) {
      const retireRow = document.createElement("div");
      retireRow.className = "side-actions";
      const retireBtn = document.createElement("button");
      retireBtn.className = "secondary side-retire";
      retireBtn.textContent = "Retire side";
      retireBtn.onclick = (e) => {
        e.stopPropagation();
        if (!confirm(`Retire ${shortenAddr(s.side_address)}? This signs a SideRetirement record and flips the side's lifecycle to Retired. New traffic from it will be flagged anomalous by peers.`)) {
          return;
        }
        safe(async () => {
          await call("retire_side_cmd", {
            sideAddress: s.side_address,
            reason: "user-retired",
          });
          await refreshSides();
          showOk(`retired ${shortenAddr(s.side_address)}`);
        });
      };
      retireRow.appendChild(retireBtn);
      li.appendChild(retireRow);
    }

    ul.appendChild(li);
  }
}

// ---- Boot diagnostics -------------------------------------------------

if (!invoke) {
  showError(
    "Tauri runtime not detected. Run `cargo tauri dev` (or `./desktop/build-desktop.sh`) instead of opening this HTML directly.",
  );
}
