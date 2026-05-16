// Sidevers desktop frontend — Phase 3 Stage C chat-first shell.
//
// State model:
//   - dataDir / nodeUp : node bootstrap info from auto_start_node
//   - sides            : Array<HostedSide> for the side rail
//   - activeSide       : bech32 address of the currently-selected side
//   - friends          : Map<side, Array<RelationshipView>>
//   - chats            : Map<side, Map<peer, Array<Message>>>
//   - sessions         : Map<"side|peer", {status, error?}>
//   - view             : {name, params} — main-pane router state
//   - advancedMode     : bool from settings.advanced_mode
//   - theme            : "system"|"light"|"dark" from settings.theme
//
// Boot:
//   onboarding.js runs first. If first-run, it shows the wizard; on
//   finish it dispatches to start_node + calls window.svBoot(...).
//   If returning user, it skips the wizard and calls auto_start_node
//   then window.svBoot(...). svBoot reveals the shell and renders.

const tauri = window.__TAURI__;
const invoke = tauri ? tauri.core.invoke : null;
const listen = tauri ? tauri.event.listen : null;

const $ = (id) => document.getElementById(id);

// =====================================================================
// State
// =====================================================================

const state = {
  dataDir: null,
  // sides : Array<{ side_address, listen_addr, lifecycle, is_retired, label? }>
  sides: [],
  activeSide: null,
  // friends : Map<sideAddr, Array<RelationshipView>>
  friends: new Map(),
  // chats : Map<sideAddr, Map<peerAddr, Array<{from,to,plaintext,received_at,kind}>>>
  chats: new Map(),
  // sessions : Map<"sideAddr|peerAddr", {status, error?}>
  sessions: new Map(),
  // sideLabels : Map<sideAddr, label> — set from the side's stored label
  sideLabels: new Map(),
  // friendDisplay : Map<peerAddr, {name, address}> — last-known display name
  friendDisplay: new Map(),
  view: { name: "welcome", params: {} },
  // Add-friend tab state
  addFriendTab: "share",
  advancedMode: false,
  theme: "system",
};

// =====================================================================
// Helpers
// =====================================================================

function t(key, vars) {
  if (window.__sv_i18n && typeof window.__sv_i18n.t === "function") {
    return window.__sv_i18n.t(key, vars);
  }
  return key;
}

async function call(cmd, args) {
  if (!invoke) {
    throw new Error(
      "Tauri runtime not available — open this page via `cargo tauri dev`, not a plain browser.",
    );
  }
  return await invoke(cmd, args);
}

function clearToast() {
  const el = $("error");
  if (!el) return;
  el.textContent = "";
  el.classList.remove("ok");
}

function showError(msg) {
  const el = $("error");
  if (!el) return;
  el.textContent = String(msg);
  el.classList.remove("ok");
  // Auto-clear after a few seconds so the toast doesn't linger.
  setTimeout(() => {
    if (el.textContent === String(msg)) clearToast();
  }, 5000);
}

function showOk(msg) {
  const el = $("error");
  if (!el) return;
  el.textContent = msg;
  el.classList.add("ok");
  setTimeout(() => {
    if (el.textContent === msg) clearToast();
  }, 3000);
}

async function safe(fn) {
  clearToast();
  try {
    await fn();
  } catch (e) {
    showError(e.message || e);
  }
}

function shortenAddr(addr) {
  if (!addr || typeof addr !== "string") return "";
  if (addr.length < 16) return addr;
  return `${addr.slice(0, 10)}…${addr.slice(-6)}`;
}

function avatarInitials(label) {
  if (!label) return "—";
  const trimmed = String(label).trim();
  if (!trimmed) return "—";
  // Take up to two characters; uppercase them. Works for "work" → "WO",
  // "private" → "PR", emojis → first codepoint, etc.
  return [...trimmed].slice(0, 2).join("").toUpperCase();
}

const AVATAR_PALETTE = [
  "#1d1d1f",
  "#3a3a3c",
  "#545454",
  "#6e6e73",
  "#86868b",
  "#2c2c2e",
  "#48484a",
  "#5a5a5e",
];

function avatarColor(address) {
  if (!address) return AVATAR_PALETTE[0];
  // Use the first hex byte after the bech32 prefix as the index seed.
  const cleaned = String(address).replace(/^sv1[qp]?/, "");
  let h = 0;
  for (let i = 0; i < Math.min(cleaned.length, 6); i++) {
    h = (h * 31 + cleaned.charCodeAt(i)) >>> 0;
  }
  return AVATAR_PALETTE[h % AVATAR_PALETTE.length];
}

function applyAvatar(el, address, label) {
  if (!el) return;
  el.textContent = avatarInitials(label || sideLabel(address) || "—");
  el.style.background = avatarColor(address);
  el.style.color = "#fff";
}

function sideLabel(address) {
  return state.sideLabels.get(address) || null;
}

function friendDisplayFor(addr) {
  const f = state.friendDisplay.get(addr);
  if (f && f.name) return f.name;
  return shortenAddr(addr);
}

function relativeTime(received_at) {
  if (!received_at) return "";
  const now = Math.floor(Date.now() / 1000);
  const delta = now - received_at;
  if (delta < 60) return `${delta}s`;
  if (delta < 3600) return `${Math.floor(delta / 60)}m`;
  if (delta < 86400) return `${Math.floor(delta / 3600)}h`;
  return `${Math.floor(delta / 86400)}d`;
}

function sessionKey(side, peer) {
  return `${side}|${peer}`;
}

// =====================================================================
// Boot — called by onboarding.js once the node is up.
// =====================================================================

window.svBoot = async function svBoot(nodeInfo, dataDir) {
  state.dataDir = dataDir || null;
  state.activeSide = nodeInfo?.side_address || null;
  if (nodeInfo?.side_address) {
    // The node's primary side label isn't returned in NodeInfo today,
    // so we'll fall back to a generic label until refreshSides runs.
    state.sideLabels.set(nodeInfo.side_address, sideLabel(nodeInfo.side_address) || "—");
  }

  // Reveal shell.
  const app = $("app");
  if (app) app.hidden = false;

  // Read settings (advanced mode + theme) BEFORE first render so the
  // shell paints with the right modifiers.
  await loadSettings();
  applyTheme(state.theme);
  applyAdvanced(state.advancedMode);

  await refreshSides();
  await refreshFriends(state.activeSide);
  await loadInboxHistory(state.activeSide);

  renderRail();
  renderInside();
  renderView();

  // Subscribe to inbox events.
  if (listen) {
    listen("inbox:dm", (e) => onInboxDm(e?.payload));
  }
};

// =====================================================================
// Settings (persisted via SideStore.settings)
// =====================================================================

async function loadSettings() {
  if (!state.dataDir) return;
  try {
    const adv = await call("get_setting", { dataDir: state.dataDir, key: "advanced_mode" });
    state.advancedMode = adv === "true";
  } catch {}
  try {
    const theme = await call("get_setting", { dataDir: state.dataDir, key: "theme" });
    if (theme === "light" || theme === "dark" || theme === "system") {
      state.theme = theme;
    }
  } catch {}
}

async function saveSetting(key, value) {
  if (!state.dataDir) return;
  try {
    await call("set_setting", { dataDir: state.dataDir, key, value: String(value) });
  } catch (e) {
    console.warn("set_setting failed:", e);
  }
}

function applyTheme(theme) {
  state.theme = theme || "system";
  const root = document.documentElement;
  if (state.theme === "dark") {
    root.classList.add("dark");
  } else if (state.theme === "light") {
    root.classList.remove("dark");
  } else {
    // system → follow prefers-color-scheme
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    root.classList.toggle("dark", prefersDark);
  }
}

function applyAdvanced(on) {
  state.advancedMode = !!on;
  document.body.classList.toggle("sv-advanced", state.advancedMode);
  const row = $("row-advanced-link");
  if (row) row.hidden = !state.advancedMode;
}

// =====================================================================
// Side rail
// =====================================================================

async function refreshSides() {
  try {
    state.sides = await call("list_sides");
  } catch (e) {
    console.warn("list_sides failed:", e);
    state.sides = [];
  }
  // We don't have labels in HostedSide today; preserve any we already
  // know (from start_node info or add_side response) and fall back to
  // the bech32 short form.
  for (const s of state.sides) {
    if (!state.sideLabels.has(s.side_address)) {
      state.sideLabels.set(s.side_address, sideLabel(s.side_address) || shortenAddr(s.side_address));
    }
  }
  // If activeSide isn't in the list (e.g. just retired), pick another.
  if (state.activeSide && !state.sides.some((s) => s.side_address === state.activeSide)) {
    const replacement = state.sides.find((s) => !s.is_retired) || state.sides[0];
    state.activeSide = replacement?.side_address || null;
    if (state.activeSide) await saveSetting("last_active_side", state.activeSide);
  }
}

function renderRail() {
  const ul = $("side-rail");
  if (!ul) return;
  ul.innerHTML = "";
  for (const s of state.sides) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.className = "sv-rail-btn";
    btn.setAttribute("aria-label", sideLabel(s.side_address) || s.side_address);
    btn.title = sideLabel(s.side_address) || s.side_address;
    if (s.side_address === state.activeSide) btn.setAttribute("data-active", "true");

    const av = document.createElement("span");
    av.className = "sv-avatar sv-rail-avatar";
    applyAvatar(av, s.side_address, sideLabel(s.side_address));
    btn.appendChild(av);

    // Unread badge — derived from inbox events received since the user
    // last opened a chat with this side. Stub for now: only show when
    // there's an unread map entry; full presence is Stage C8.
    // (Reserved DOM; render no badge yet.)

    btn.onclick = () => setActiveSide(s.side_address);
    li.appendChild(btn);
    ul.appendChild(li);
  }
}

async function setActiveSide(addr) {
  if (!addr || addr === state.activeSide) {
    state.activeSide = addr;
    renderRail();
    renderInside();
    renderView();
    return;
  }
  state.activeSide = addr;
  await saveSetting("last_active_side", addr);
  await refreshFriends(addr);
  await loadInboxHistory(addr);
  // Default view = welcome when switching sides.
  state.view = { name: "welcome", params: {} };
  renderRail();
  renderInside();
  renderView();
}

// =====================================================================
// In-side column (Friends + Chats)
// =====================================================================

async function refreshFriends(side) {
  if (!side) {
    return;
  }
  try {
    const rows = await call("list_relationships", { sideAddress: side });
    state.friends.set(side, rows);
    for (const r of rows) {
      state.friendDisplay.set(r.address, { name: r.nickname || null, address: r.address });
    }
  } catch (e) {
    console.warn("list_relationships failed:", e);
  }
}

function renderInside() {
  const titleEl = $("inside-title");
  const statsEl = $("inside-stats");
  const avatarEl = $("inside-avatar");

  if (!state.activeSide) {
    if (titleEl) titleEl.textContent = t("inside.no_side");
    if (statsEl) statsEl.textContent = "";
    if (avatarEl) {
      avatarEl.textContent = "—";
      avatarEl.style.background = "transparent";
      avatarEl.style.color = "var(--color-sv-text-muted)";
    }
    renderFriendsList([]);
    renderChatsList([]);
    return;
  }

  const label = sideLabel(state.activeSide) || shortenAddr(state.activeSide);
  if (titleEl) titleEl.textContent = label;
  if (avatarEl) applyAvatar(avatarEl, state.activeSide, label);

  const friends = state.friends.get(state.activeSide) || [];
  const chatsMap = state.chats.get(state.activeSide) || new Map();
  if (statsEl) {
    if (friends.length === 0) {
      statsEl.textContent = "";
    } else {
      // Online proxy = friends we've heard from in the last 5 min.
      const now = Math.floor(Date.now() / 1000);
      let online = 0;
      for (const f of friends) {
        const peerChats = chatsMap.get(f.address) || [];
        const last = peerChats.length
          ? peerChats[peerChats.length - 1].received_at || 0
          : 0;
        if (last && now - last < 300) online++;
      }
      statsEl.textContent = t("inside.live_label", {
        n: online,
        total: friends.length,
      });
    }
  }

  renderFriendsList(friends);
  // Build chat list from the per-side chats map; if a friend has no
  // chat history but does have a relationship, they don't show in the
  // Chats list (only Friends).
  const chatRows = [];
  for (const [peer, msgs] of chatsMap.entries()) {
    if (!msgs || msgs.length === 0) continue;
    const last = msgs[msgs.length - 1];
    chatRows.push({
      peer,
      last,
      preview: last.plaintext,
      received_at: last.received_at,
    });
  }
  chatRows.sort((a, b) => (b.received_at || 0) - (a.received_at || 0));
  renderChatsList(chatRows);
}

function renderFriendsList(friends) {
  const ul = $("friends-list");
  if (!ul) return;
  ul.innerHTML = "";
  if (friends.length === 0) {
    const li = document.createElement("li");
    li.className = "sv-inside-section-empty";
    li.textContent = t("inside.empty_friends");
    ul.appendChild(li);
    return;
  }
  for (const r of friends) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.className = "sv-row";
    if (
      state.view.name === "thread" &&
      state.view.params.peer === r.address
    ) {
      btn.setAttribute("data-active", "true");
    }

    const av = document.createElement("span");
    av.className = "sv-avatar sv-avatar-sm";
    applyAvatar(av, r.address, r.nickname || friendDisplayFor(r.address));
    btn.appendChild(av);

    const body = document.createElement("div");
    body.className = "sv-row-body";
    const title = document.createElement("span");
    title.className = "sv-row-title";
    title.textContent = r.nickname || friendDisplayFor(r.address);
    const sub = document.createElement("span");
    sub.className = "sv-row-sub";
    sub.textContent = r.peer_listen_addr || shortenAddr(r.address);
    body.appendChild(title);
    body.appendChild(sub);
    btn.appendChild(body);

    btn.onclick = () => openThread(r.address);
    li.appendChild(btn);
    ul.appendChild(li);
  }
}

function renderChatsList(rows) {
  const ul = $("chats-list");
  if (!ul) return;
  ul.innerHTML = "";
  if (rows.length === 0) {
    const li = document.createElement("li");
    li.className = "sv-inside-section-empty";
    li.textContent = t("inside.empty_chats");
    ul.appendChild(li);
    return;
  }
  for (const row of rows) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.className = "sv-row";
    if (
      state.view.name === "thread" &&
      state.view.params.peer === row.peer
    ) {
      btn.setAttribute("data-active", "true");
    }

    const av = document.createElement("span");
    av.className = "sv-avatar sv-avatar-sm";
    applyAvatar(av, row.peer, friendDisplayFor(row.peer));
    btn.appendChild(av);

    const body = document.createElement("div");
    body.className = "sv-row-body";
    const title = document.createElement("span");
    title.className = "sv-row-title";
    title.textContent = friendDisplayFor(row.peer);
    const sub = document.createElement("span");
    sub.className = "sv-row-sub";
    sub.textContent = row.preview || "";
    body.appendChild(title);
    body.appendChild(sub);
    btn.appendChild(body);

    const meta = document.createElement("span");
    meta.className = "sv-row-meta";
    meta.textContent = relativeTime(row.received_at);
    btn.appendChild(meta);

    btn.onclick = () => openThread(row.peer);
    li.appendChild(btn);
    ul.appendChild(li);
  }
}

// =====================================================================
// View router
// =====================================================================

function showView(name, params) {
  state.view = { name, params: params || {} };
  renderView();
  // Refresh the friend/chat highlight in the inside column.
  renderInside();
}

function renderView() {
  const viewMap = {
    welcome: renderWelcome,
    thread: renderThread,
    friend: renderFriend,
    "add-friend": renderAddFriend,
    "side-settings": renderSideSettings,
    settings: renderSettings,
    advanced: renderAdvanced,
  };
  for (const el of document.querySelectorAll("[data-view]")) {
    el.hidden = el.dataset.view !== state.view.name;
  }
  const fn = viewMap[state.view.name];
  if (fn) fn(state.view.params);
}

function renderWelcome() {
  // Nothing to render dynamically — copy is static. Button wires once
  // in attachStaticHandlers.
}

// ----- Thread view ---------------------------------------------------

async function openThread(peerAddress) {
  if (!state.activeSide) {
    showError(t("toast.no_side"));
    return;
  }
  state.view = { name: "thread", params: { peer: peerAddress } };
  // Try to resolve endpoint + open session in the background.
  ensureSessionFor(state.activeSide, peerAddress);
  renderInside();
  renderView();
}

function renderThread(params) {
  const peer = params?.peer;
  if (!peer) return;

  const friend = (state.friends.get(state.activeSide) || []).find(
    (r) => r.address === peer,
  );
  const nameEl = $("thread-name");
  const subEl = $("thread-sub");
  const avEl = $("thread-avatar");
  if (nameEl)
    nameEl.textContent = friend?.nickname || friendDisplayFor(peer);
  if (avEl) applyAvatar(avEl, peer, friend?.nickname || friendDisplayFor(peer));
  if (subEl) {
    const sess = state.sessions.get(sessionKey(state.activeSide, peer));
    let status = t("thread.offline");
    if (sess?.status === "open") status = t("thread.online");
    else if (sess?.status === "connecting") status = t("thread.connecting");
    else if (sess?.status === "error") status = sess.error || "error";
    subEl.textContent = friend?.peer_listen_addr
      ? `${status} · ${friend.peer_listen_addr}`
      : status;
  }

  // Messages.
  const list = $("thread-list");
  if (!list) return;
  list.innerHTML = "";

  const msgs =
    state.chats.get(state.activeSide)?.get(peer) || [];

  // If endpoint unknown, show prompt.
  if (!friend?.peer_listen_addr) {
    const block = document.createElement("div");
    block.className = "sv-empty";
    const p = document.createElement("p");
    p.textContent = t("thread.endpoint_missing");
    block.appendChild(p);
    const row = document.createElement("div");
    row.className = "sv-field-row";
    const input = document.createElement("input");
    input.type = "text";
    input.className = "sv-mono";
    input.placeholder = "127.0.0.1:50001";
    const btn = document.createElement("button");
    btn.textContent = t("btn.save");
    btn.onclick = () =>
      safe(async () => {
        const addr = input.value.trim();
        if (!addr) return;
        await call("update_relationship_endpoint", {
          sideAddress: state.activeSide,
          peerAddress: peer,
          peerListenAddr: addr,
        });
        await refreshFriends(state.activeSide);
        showOk(t("toast.endpoint_saved"));
        renderInside();
        renderView();
        ensureSessionFor(state.activeSide, peer);
      });
    row.appendChild(input);
    row.appendChild(btn);
    block.appendChild(row);
    list.appendChild(block);
    return;
  }

  if (msgs.length === 0) {
    const empty = document.createElement("div");
    empty.className = "sv-empty";
    const p = document.createElement("p");
    p.textContent = t("thread.empty");
    empty.appendChild(p);
    list.appendChild(empty);
    return;
  }

  for (const m of msgs) {
    const bubble = document.createElement("div");
    bubble.className =
      "sv-bubble " + (m.kind === "out" ? "sv-bubble-sent" : "sv-bubble-received");
    bubble.textContent = m.plaintext;
    list.appendChild(bubble);
    const meta = document.createElement("div");
    meta.className =
      "sv-bubble-meta" + (m.kind === "out" ? "" : " received");
    meta.textContent = relativeTime(m.received_at);
    list.appendChild(meta);
  }
  list.scrollTop = list.scrollHeight;
}

async function ensureSessionFor(side, peer) {
  const key = sessionKey(side, peer);
  const existing = state.sessions.get(key);
  if (existing?.status === "open" || existing?.status === "connecting") return;
  const friend = (state.friends.get(side) || []).find((r) => r.address === peer);
  if (!friend?.peer_listen_addr) {
    state.sessions.set(key, { status: "idle" });
    return;
  }
  state.sessions.set(key, { status: "connecting" });
  renderView();
  try {
    await call("connect_peer", {
      fromSide: side,
      peerAddr: friend.peer_listen_addr,
    });
    state.sessions.set(key, { status: "open" });
    renderView();
  } catch (e) {
    state.sessions.set(key, {
      status: "error",
      error: String(e?.message || e),
    });
    renderView();
  }
}

async function sendCurrentThread() {
  const peer = state.view?.params?.peer;
  if (!peer || !state.activeSide) return;
  const input = $("compose-text");
  if (!input) return;
  const text = input.value;
  if (!text || !text.trim()) return;
  // Ensure session.
  const key = sessionKey(state.activeSide, peer);
  const sess = state.sessions.get(key);
  if (sess?.status !== "open") {
    await ensureSessionFor(state.activeSide, peer);
    const after = state.sessions.get(key);
    if (after?.status !== "open") {
      throw new Error(after?.error || "couldn't open session");
    }
  }
  await call("send_dm_live", { fromSide: state.activeSide, text });
  // Mirror locally so the bubble shows immediately.
  const now = Math.floor(Date.now() / 1000);
  appendChat(state.activeSide, peer, {
    from: state.activeSide,
    to: peer,
    plaintext: text,
    received_at: now,
    kind: "out",
  });
  input.value = "";
  renderInside();
  renderView();
}

// ----- Friend detail view -------------------------------------------

function renderFriend(params) {
  const peer = params?.peer;
  if (!peer) return;
  const friend = (state.friends.get(state.activeSide) || []).find(
    (r) => r.address === peer,
  );
  if (!friend) {
    showError("no such friend");
    showView("welcome");
    return;
  }
  $("friend-name").textContent = friend.nickname || friendDisplayFor(peer);
  $("friend-address").textContent = peer;
  $("friend-nickname").value = friend.nickname || "";
  $("friend-endpoint").value = friend.peer_listen_addr || "";
  $("friend-caps").value = (friend.capabilities || []).join(", ");

  // Try to fetch the friend's published profile (best-effort).
  // Stage C8 wires this. For now, blank.
  $("friend-profile-bio").textContent = t("friend.profile_empty");
  const caps = $("friend-profile-caps");
  caps.innerHTML = "";
}

// ----- Add friend view -----------------------------------------------

function renderAddFriend() {
  // Tabs.
  for (const tab of document.querySelectorAll(".sv-tab[data-tab]")) {
    if (tab.dataset.tab === state.addFriendTab) {
      tab.setAttribute("data-active", "true");
    } else {
      tab.removeAttribute("data-active");
    }
  }
  for (const pane of document.querySelectorAll("[data-tab-pane]")) {
    pane.hidden = pane.dataset.tabPane !== state.addFriendTab;
  }
}

// ----- Side settings view -------------------------------------------

async function renderSideSettings() {
  if (!state.activeSide) return;
  const side = state.sides.find((s) => s.side_address === state.activeSide);
  if (side) {
    $("side-address").value = side.side_address;
    $("side-listen").value = side.listen_addr;
    $("side-lifecycle").value = side.lifecycle || "—";
  }
  // Load profile.
  try {
    const p = await call("get_profile", { sideAddress: state.activeSide });
    if (p) {
      $("profile-name").value = p.name || "";
      $("profile-bio").value = p.bio || "";
      $("profile-caps").value = (p.capabilities || []).join(", ");
    } else {
      $("profile-name").value = "";
      $("profile-bio").value = "";
      $("profile-caps").value = "";
    }
  } catch (e) {
    console.warn("get_profile failed:", e);
  }
}

// ----- Global settings view -----------------------------------------

function renderSettings() {
  $("settings-theme").value = state.theme;
  $("settings-advanced").value = state.advancedMode ? "true" : "false";
  const langSel = $("settings-lang");
  if (langSel && window.__sv_i18n) {
    langSel.value = window.__sv_i18n.currentLocale();
  }
  $("row-advanced-link").hidden = !state.advancedMode;
}

// ----- Advanced view -------------------------------------------------

function renderAdvanced() {
  // Static — handlers wired in attachStaticHandlers.
}

// =====================================================================
// Inbox event handler
// =====================================================================

function onInboxDm(payload) {
  if (!payload) return;
  const sideAddr = payload.to;
  const peer = payload.from;
  if (!sideAddr || !peer) return;
  appendChat(sideAddr, peer, {
    from: peer,
    to: sideAddr,
    plaintext: payload.plaintext,
    received_at: payload.received_at,
    kind: "in",
  });
  renderInside();
  if (
    state.view.name === "thread" &&
    state.view.params.peer === peer &&
    state.activeSide === sideAddr
  ) {
    renderView();
  }
}

function appendChat(side, peer, message) {
  if (!state.chats.has(side)) state.chats.set(side, new Map());
  const sideMap = state.chats.get(side);
  if (!sideMap.has(peer)) sideMap.set(peer, []);
  sideMap.get(peer).push(message);
}

async function loadInboxHistory(side) {
  if (!side) return;
  try {
    const history = await call("load_inbox_history", { sideAddress: side });
    // history is newest-first; reverse for chronological append.
    if (!state.chats.has(side)) state.chats.set(side, new Map());
    const sideMap = state.chats.get(side);
    sideMap.clear();
    for (let i = history.length - 1; i >= 0; i--) {
      const e = history[i];
      if (!sideMap.has(e.from)) sideMap.set(e.from, []);
      sideMap.get(e.from).push({
        from: e.from,
        to: e.to,
        plaintext: e.plaintext,
        received_at: e.received_at,
        kind: "in",
      });
    }
  } catch (e) {
    console.warn("load_inbox_history failed:", e);
  }
}

// =====================================================================
// Static handlers (DOM elements that exist once)
// =====================================================================

function attachStaticHandlers() {
  // Rail bottom actions.
  $("rail-add-side")?.addEventListener("click", () =>
    safe(async () => {
      const label = prompt("New side label?", "extra") || "";
      const trimmed = label.trim();
      if (!trimmed) return;
      const resp = await call("add_side", { label: trimmed });
      state.sideLabels.set(resp.side_address, trimmed);
      await refreshSides();
      renderRail();
      // Switch to it.
      await setActiveSide(resp.side_address);
      showOk(`side added (${trimmed})`);
    }),
  );
  $("rail-settings")?.addEventListener("click", () => showView("settings"));

  // Inside header titlerow → side settings.
  const titlerow = $("inside-titlerow");
  if (titlerow) {
    titlerow.addEventListener("click", () => showView("side-settings"));
    titlerow.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        showView("side-settings");
      }
    });
  }
  $("open-add-friend")?.addEventListener("click", () => showView("add-friend"));
  $("welcome-add-friend")?.addEventListener("click", () => showView("add-friend"));

  // Thread compose.
  $("compose-send")?.addEventListener("click", () => safe(sendCurrentThread));
  $("compose-text")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      safe(sendCurrentThread);
    }
  });
  $("thread-view-profile")?.addEventListener("click", () => {
    if (state.view.name === "thread") {
      showView("friend", { peer: state.view.params.peer });
    }
  });

  // Friend detail save/remove.
  $("friend-back")?.addEventListener("click", () => {
    const peer = state.view.params?.peer;
    if (peer) showView("thread", { peer });
    else showView("welcome");
  });
  $("friend-save")?.addEventListener("click", () =>
    safe(async () => {
      const peer = state.view.params?.peer;
      if (!peer || !state.activeSide) return;
      const friend = (state.friends.get(state.activeSide) || []).find(
        (r) => r.address === peer,
      );
      const nickname = $("friend-nickname").value.trim() || null;
      const endpoint = $("friend-endpoint").value.trim();
      const capsRaw = $("friend-caps").value.trim();
      const capabilities = capsRaw
        ? capsRaw.split(",").map((s) => s.trim()).filter(Boolean)
        : [];
      // Re-add (upserts) with new fields.
      await call("add_relationship_cmd", {
        sideAddress: state.activeSide,
        peerAddress: peer,
        nickname,
        capabilities,
        peerListenAddr: endpoint || friend?.peer_listen_addr || null,
      });
      await refreshFriends(state.activeSide);
      showOk(t("btn.save"));
      renderInside();
      renderView();
    }),
  );
  $("friend-remove")?.addEventListener("click", () =>
    safe(async () => {
      const peer = state.view.params?.peer;
      if (!peer || !state.activeSide) return;
      if (!confirm(`Remove ${friendDisplayFor(peer)} as a friend?`)) return;
      await call("remove_relationship_cmd", {
        sideAddress: state.activeSide,
        peerAddress: peer,
      });
      await refreshFriends(state.activeSide);
      showOk(t("btn.remove"));
      showView("welcome");
    }),
  );

  // Add-friend tabs + actions.
  for (const tab of document.querySelectorAll(".sv-tab[data-tab]")) {
    tab.addEventListener("click", () => {
      state.addFriendTab = tab.dataset.tab;
      renderAddFriend();
    });
  }
  $("add-friend-back")?.addEventListener("click", () => showView("welcome"));
  $("contact-qr-generate")?.addEventListener("click", () =>
    safe(async () => {
      if (!state.activeSide) throw new Error(t("toast.no_side"));
      const resp = await call("generate_contact_qr_svg", {
        sideAddress: state.activeSide,
      });
      $("contact-qr-svg").innerHTML = resp.svg;
      $("contact-qr-uri").value = resp.uri;
      $("contact-qr-block").hidden = false;
      showOk(t("toast.qr_shown"));
    }),
  );
  $("contact-paste-accept")?.addEventListener("click", () =>
    safe(async () => {
      if (!state.activeSide) throw new Error(t("toast.no_side"));
      const uri = $("contact-paste-uri").value.trim();
      if (!uri) throw new Error("paste a friend code first");
      const resp = await call("accept_contact_qr", {
        sideAddress: state.activeSide,
        qrUri: uri,
      });
      $("contact-paste-uri").value = "";
      await refreshFriends(state.activeSide);
      renderInside();
      showOk(
        t("toast.friend_added", {
          name: resp.display_name || shortenAddr(resp.friend_address),
        }),
      );
      // Drop into the new chat thread.
      showView("thread", { peer: resp.friend_address });
    }),
  );

  // Side settings: profile + retire.
  $("side-back")?.addEventListener("click", () => showView("welcome"));
  $("profile-load")?.addEventListener("click", () => safe(renderSideSettings));
  $("profile-save")?.addEventListener("click", () =>
    safe(async () => {
      if (!state.activeSide) throw new Error(t("toast.no_side"));
      const name = $("profile-name").value.trim() || null;
      const bio = $("profile-bio").value.trim() || null;
      const capsRaw = $("profile-caps").value.trim();
      const capabilities = capsRaw
        ? capsRaw.split(",").map((s) => s.trim()).filter(Boolean)
        : [];
      await call("set_profile", {
        sideAddress: state.activeSide,
        name,
        bio,
        capabilities,
      });
      showOk(t("toast.profile_saved"));
    }),
  );
  $("side-retire")?.addEventListener("click", () =>
    safe(async () => {
      if (!state.activeSide) throw new Error(t("toast.no_side"));
      if (
        !confirm(
          `Retire ${shortenAddr(state.activeSide)}? Peers will treat new traffic from this side as anomalous. Can't be undone.`,
        )
      )
        return;
      await call("retire_side_cmd", {
        sideAddress: state.activeSide,
        reason: "user-retired",
      });
      await refreshSides();
      showOk(t("toast.side_retired"));
      // Switch to another live side if available.
      const next = state.sides.find((s) => !s.is_retired);
      if (next) await setActiveSide(next.side_address);
      else {
        state.activeSide = null;
        renderRail();
        renderInside();
        showView("welcome");
      }
    }),
  );

  // Global settings.
  $("settings-back")?.addEventListener("click", () => showView("welcome"));
  $("settings-theme")?.addEventListener("change", (e) => {
    applyTheme(e.target.value);
    saveSetting("theme", e.target.value);
  });
  $("settings-lang")?.addEventListener("change", (e) => {
    if (window.__sv_i18n) window.__sv_i18n.setLocale(e.target.value);
  });
  $("settings-advanced")?.addEventListener("change", (e) => {
    applyAdvanced(e.target.value === "true");
    saveSetting("advanced_mode", e.target.value);
  });
  $("settings-open-advanced")?.addEventListener("click", () =>
    showView("advanced"),
  );
  $("settings-backup-save")?.addEventListener("click", () =>
    safe(async () => {
      const path = $("settings-backup-path").value.trim();
      if (!path) throw new Error("save path required");
      await call("write_seed_backup", { outPath: path });
      showOk(t("btn.save_seed"));
    }),
  );

  // Advanced view.
  $("advanced-back")?.addEventListener("click", () => showView("settings"));
  $("advanced-pair-generate")?.addEventListener("click", () =>
    safe(async () => {
      if (!state.activeSide) throw new Error(t("toast.no_side"));
      const resp = await call("generate_pairing_qr_svg", {
        sideAddress: state.activeSide,
      });
      $("pair-qr-svg").innerHTML = resp.svg;
      $("pair-qr-uri").value = resp.uri;
      $("pair-qr-block").hidden = false;
    }),
  );
  $("advanced-pair-accept")?.addEventListener("click", () =>
    safe(async () => {
      const uri = $("advanced-pair-accept-uri").value.trim();
      if (!uri) throw new Error("paste a pairing URI first");
      const resp = await call("accept_pairing_qr", { qrUri: uri });
      $("advanced-pair-accept-uri").value = "";
      await refreshSides();
      renderRail();
      showOk(`paired · now hosting ${shortenAddr(resp.joined_side)}`);
    }),
  );
  $("advanced-dial")?.addEventListener("click", () =>
    safe(async () => {
      if (!state.activeSide) throw new Error(t("toast.no_side"));
      const peerAddr = $("advanced-dial-addr").value.trim();
      if (!peerAddr) throw new Error("enter a peer addr");
      const resp = await call("connect_peer", {
        fromSide: state.activeSide,
        peerAddr,
      });
      // Add to sessions map so the thread view sees it as open.
      state.sessions.set(sessionKey(state.activeSide, resp.peer_side), {
        status: "open",
      });
      showOk(t("toast.connected", { name: shortenAddr(resp.peer_side) }));
      showView("thread", { peer: resp.peer_side });
    }),
  );

  // Theme: react to OS changes when on "system".
  window
    .matchMedia("(prefers-color-scheme: dark)")
    .addEventListener("change", () => {
      if (state.theme === "system") applyTheme("system");
    });
}

// Boot diagnostics if Tauri runtime is missing.
if (!invoke) {
  showError(
    "Tauri runtime not detected. Run `cargo tauri dev` (or `./desktop/build-desktop.sh`) instead of opening this HTML directly.",
  );
} else {
  attachStaticHandlers();
}
