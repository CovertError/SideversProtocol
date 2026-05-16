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
  // lastReadAt : Map<"side|peer", received_at> — when the user last
  // looked at this thread. Used to compute unread state. In-memory MVP.
  lastReadAt: new Map(),
  // sidePhotoUrls : Map<sideAddress, Tauri-converted-file-url> for the
  // local-only profile photo per side. None means initials fallback.
  sidePhotoUrls: new Map(),
  // personalSideAddress : bech32 of the user's implicit "Home" side.
  // The personal side never appears as a rail avatar — it's
  // represented by the Home button at the top of the rail. Friends
  // and 1:1 DMs live here. Stage D L1.5.
  personalSideAddress: null,
  view: { name: "welcome", params: {} },
  // Add-friend tab state
  addFriendTab: "share",
  advancedMode: false,
  theme: "system",
};

// Presence + unread helpers.
const PRESENCE_WINDOW_S = 300;

function lastInboxFrom(side, peer) {
  const msgs = state.chats.get(side)?.get(peer);
  if (!msgs || msgs.length === 0) return 0;
  // Walk back to find the last received message (kind === "in").
  for (let i = msgs.length - 1; i >= 0; i--) {
    if (msgs[i].kind === "in") return msgs[i].received_at || 0;
  }
  return 0;
}

function isPeerOnline(side, peer) {
  const last = lastInboxFrom(side, peer);
  if (!last) return false;
  const now = Math.floor(Date.now() / 1000);
  return now - last < PRESENCE_WINDOW_S;
}

function unreadCount(side, peer) {
  const msgs = state.chats.get(side)?.get(peer) || [];
  const cutoff = state.lastReadAt.get(sessionKey(side, peer)) || 0;
  let n = 0;
  for (const m of msgs) {
    if (m.kind === "in" && (m.received_at || 0) > cutoff) n++;
  }
  return n;
}

function markRead(side, peer) {
  state.lastReadAt.set(
    sessionKey(side, peer),
    Math.floor(Date.now() / 1000),
  );
}

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

// 12 monochrome buckets across the brand's sv-ink → sv-silver range.
// White text legible on every bucket. Hashed-from-address indexing
// gives different sides/friends visibly different shades while
// holding brand monochrome.
const AVATAR_PALETTE = [
  "#0a0a0c",
  "#15151a",
  "#1d1d1f",
  "#26262a",
  "#2f2f32",
  "#3a3a3c",
  "#48484a",
  "#545454",
  "#5a5a5e",
  "#6e6e73",
  "#7a7a7f",
  "#86868b",
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

// Tauri's convertFileSrc lets the webview load a filesystem path via
// a `tauri://localhost/...` URL. Falls back to a `file://` URL if the
// global isn't there (test env).
function fileSrc(path) {
  const c = tauri?.core?.convertFileSrc;
  if (typeof c === "function") return c(path);
  return path.startsWith("/") ? `file://${path}` : path;
}

function applyAvatar(el, address, label) {
  if (!el) return;
  const cached = state.sidePhotoUrls.get(address);
  if (cached) {
    // Photo set — replace initials with an <img>. Keep the background
    // transparent so the bitmap fills the avatar fully.
    el.textContent = "";
    el.dataset.hasPhoto = "true";
    el.style.background = "transparent";
    let img = el.querySelector("img");
    if (!img) {
      img = document.createElement("img");
      el.appendChild(img);
    }
    if (img.src !== cached) img.src = cached;
    img.alt = label || sideLabel(address) || "";
  } else {
    // No photo — render initials with a deterministic monochrome fill.
    delete el.dataset.hasPhoto;
    el.innerHTML = "";
    el.textContent = avatarInitials(label || sideLabel(address) || "—");
    el.style.background = avatarColor(address);
    el.style.color = "#fff";
  }
}

// Look up and cache the side's photo URL. Returns true if a photo
// was found (and triggers a re-render of the affected surfaces);
// false if none. Failures are silent — initials remain the fallback.
async function refreshSidePhoto(address) {
  if (!state.dataDir || !address) return false;
  try {
    const path = await call("get_side_avatar", {
      dataDir: state.dataDir,
      sideAddress: address,
    });
    if (path) {
      state.sidePhotoUrls.set(address, fileSrc(path));
      return true;
    }
    state.sidePhotoUrls.delete(address);
    return false;
  } catch (e) {
    console.warn("get_side_avatar failed:", e);
    return false;
  }
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
  await ensurePersonalSideAddress();
  // Best-effort prefetch of every side's photo so rail + inside-header
  // paint with the right avatar on the first render.
  await Promise.all(state.sides.map((s) => refreshSidePhoto(s.side_address)));
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
  try {
    const p = await call("get_setting", {
      dataDir: state.dataDir,
      key: "personal_side_address",
    });
    if (p) state.personalSideAddress = p;
  } catch {}
}

// Migration: pre-L1.5 installs never wrote personal_side_address. Pick
// the only hosted side (or the active one if multiple) and persist it.
// Called once after refreshSides on boot.
async function ensurePersonalSideAddress() {
  if (state.personalSideAddress) return;
  if (state.sides.length === 0) return;
  const chosen =
    state.sides.find((s) => s.side_address === state.activeSide) ||
    state.sides.find((s) => !s.is_retired) ||
    state.sides[0];
  state.personalSideAddress = chosen.side_address;
  await saveSetting("personal_side_address", chosen.side_address);
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
  // Switch activeSide off any side that is missing OR has been retired.
  // The retired side stays hosted (so it can still receive replies) but
  // the UI should not present it as the active identity any more.
  const active = state.activeSide
    ? state.sides.find((s) => s.side_address === state.activeSide)
    : null;
  if (state.activeSide && (!active || active.is_retired)) {
    const replacement =
      state.sides.find((s) => !s.is_retired) || null;
    state.activeSide = replacement?.side_address || null;
    if (state.activeSide) await saveSetting("last_active_side", state.activeSide);
  }
}

function renderRail() {
  const ul = $("side-rail");
  if (!ul) return;
  ul.innerHTML = "";

  // ---- Home button (always at top, represents the personal side) ----
  // The personal side is implicit — friends + 1:1 DMs live here, and
  // the user doesn't think of it as a "side" they manage. Stage D
  // Layer 2 adds group avatars below this; standalone non-personal
  // sides live in Advanced and are not surfaced on the rail.
  if (state.personalSideAddress) {
    const homeLi = document.createElement("li");
    const homeBtn = document.createElement("button");
    homeBtn.className = "sv-rail-btn";
    homeBtn.setAttribute("aria-label", t("rail.home_aria") || "Home");
    homeBtn.title = t("rail.home_title") || "Home — friends and DMs";
    if (state.activeSide === state.personalSideAddress) {
      homeBtn.setAttribute("data-active", "true");
    }
    homeBtn.innerHTML =
      '<svg viewBox="0 0 24 24" stroke-width="1.7" aria-hidden="true">' +
      '<path stroke-linecap="round" stroke-linejoin="round" ' +
      'd="m2.25 12 8.954-8.955c.44-.439 1.152-.439 1.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25"/>' +
      "</svg>";
    homeBtn.onclick = () => setActiveSide(state.personalSideAddress);
    homeLi.appendChild(homeBtn);
    ul.appendChild(homeLi);
  }

  // ---- Group + extra sides (everything that is NOT the personal side) ----
  // Hide retired sides too — the Rust side keeps them hosted (lifecycle:
  // Retired) so in-flight replies still arrive, but they shouldn't
  // appear as a switchable identity.
  const visible = state.sides.filter(
    (s) => !s.is_retired && s.side_address !== state.personalSideAddress,
  );
  for (const s of visible) {
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

  // Personal side surfaces as "Home" / friends-and-DMs; group/extra
  // sides surface under their own label. Stage D L1.5.
  const isPersonal = state.activeSide === state.personalSideAddress;
  const label = sideLabel(state.activeSide) || shortenAddr(state.activeSide);
  const headerTitle = isPersonal
    ? t("inside.home_title") || "Friends"
    : label;
  if (titleEl) titleEl.textContent = headerTitle;
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
    const unread = unreadCount(state.activeSide, r.address);
    if (
      state.view.name === "thread" &&
      state.view.params.peer === r.address
    ) {
      btn.setAttribute("data-active", "true");
    }
    if (unread > 0) btn.setAttribute("data-unread", "true");

    const wrap = document.createElement("span");
    wrap.className = "sv-avatar-wrap";
    const av = document.createElement("span");
    av.className = "sv-avatar sv-avatar-sm";
    applyAvatar(av, r.address, r.nickname || friendDisplayFor(r.address));
    wrap.appendChild(av);
    const pres = document.createElement("span");
    pres.className = "sv-avatar-presence";
    if (isPeerOnline(state.activeSide, r.address)) pres.classList.add("online");
    wrap.appendChild(pres);
    btn.appendChild(wrap);

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

    if (unread > 0) {
      const badge = document.createElement("span");
      badge.className = "sv-unread-badge";
      badge.textContent = unread > 99 ? "99+" : String(unread);
      btn.appendChild(badge);
    }

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
    const unread = unreadCount(state.activeSide, row.peer);
    if (
      state.view.name === "thread" &&
      state.view.params.peer === row.peer
    ) {
      btn.setAttribute("data-active", "true");
    }
    if (unread > 0) btn.setAttribute("data-unread", "true");

    const wrap = document.createElement("span");
    wrap.className = "sv-avatar-wrap";
    const av = document.createElement("span");
    av.className = "sv-avatar sv-avatar-sm";
    applyAvatar(av, row.peer, friendDisplayFor(row.peer));
    wrap.appendChild(av);
    const pres = document.createElement("span");
    pres.className = "sv-avatar-presence";
    if (isPeerOnline(state.activeSide, row.peer)) pres.classList.add("online");
    wrap.appendChild(pres);
    btn.appendChild(wrap);

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

    if (unread > 0) {
      const badge = document.createElement("span");
      badge.className = "sv-unread-badge";
      badge.textContent = unread > 99 ? "99+" : String(unread);
      btn.appendChild(badge);
    } else {
      const meta = document.createElement("span");
      meta.className = "sv-row-meta";
      meta.textContent = relativeTime(row.received_at);
      btn.appendChild(meta);
    }

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
  // Mark the thread as read NOW so the unread badge clears on click.
  markRead(state.activeSide, peerAddress);
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

  // Slack/Discord-style author rows. Consecutive messages from the
  // same author within GROUP_WINDOW_S group: the second-and-later
  // hide their avatar + header, leaving just an indented body that
  // visually attaches to the first message.
  const GROUP_WINDOW_S = 300;
  let prevFrom = null;
  let prevTs = 0;
  for (const m of msgs) {
    const sameAuthor = m.from === prevFrom;
    const closeInTime = m.received_at - prevTs <= GROUP_WINDOW_S;
    const grouped = sameAuthor && closeInTime;

    const row = document.createElement("div");
    row.className = "sv-msg" + (grouped ? " sv-msg-grouped" : "");

    const slot = document.createElement("div");
    slot.className = "sv-msg-avatar-slot";
    if (!grouped) {
      const author = m.kind === "out" ? state.activeSide : m.from;
      const av = document.createElement("span");
      av.className = "sv-avatar sv-avatar-sm";
      applyAvatar(
        av,
        author,
        m.kind === "out"
          ? sideLabel(state.activeSide) || ""
          : friendDisplayFor(m.from),
      );
      slot.appendChild(av);
    }
    row.appendChild(slot);

    const content = document.createElement("div");
    content.className = "sv-msg-content";
    if (!grouped) {
      const header = document.createElement("div");
      header.className = "sv-msg-header";
      const nameEl = document.createElement("span");
      nameEl.className = "sv-msg-name";
      nameEl.textContent =
        m.kind === "out" ? t("msg.you") : friendDisplayFor(m.from);
      const timeEl = document.createElement("span");
      timeEl.className = "sv-msg-time";
      timeEl.textContent = relativeTime(m.received_at);
      header.appendChild(nameEl);
      header.appendChild(timeEl);
      content.appendChild(header);
    }
    const body = document.createElement("div");
    body.className = "sv-msg-body";
    body.textContent = m.plaintext;
    content.appendChild(body);

    row.appendChild(content);
    list.appendChild(row);

    prevFrom = m.from;
    prevTs = m.received_at;
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

  // Stage D L1.5: reframe the side-settings view when the active side
  // is the implicit personal one. Personal = "My profile" (no retire,
  // no protocol-info clutter unless advanced mode is on). Other sides
  // = "Side settings" (full surface).
  const isPersonal = state.activeSide === state.personalSideAddress;
  const titleEl = $("side-settings-title");
  if (titleEl) {
    titleEl.textContent = isPersonal
      ? t("my_profile.h") || "My profile"
      : t("side_settings.h") || "Side settings";
  }
  const protoSection = $("side-settings-protocol-section");
  if (protoSection) protoSection.hidden = isPersonal && !state.advancedMode;
  const dangerSection = $("side-settings-danger-section");
  if (dangerSection) dangerSection.hidden = isPersonal;

  // Photo preview reflects the current cached avatar (initials or
  // image). applyAvatar handles either case based on sidePhotoUrls.
  const preview = $("side-photo-preview");
  if (preview)
    applyAvatar(preview, state.activeSide, sideLabel(state.activeSide));
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

// Frontend resize: pick an image file, decode via <img>, draw to a
// 256×256 <canvas>, encode as JPEG q=0.85, base64 it, hand off to
// `set_side_avatar`. The Rust side validates JPEG magic + size cap.
async function uploadSidePhoto(file) {
  if (!file || !state.activeSide || !state.dataDir) return;
  const TARGET = 256;
  const QUALITY = 0.85;

  const dataUrl = await new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error || new Error("read failed"));
    reader.onload = () => resolve(reader.result);
    reader.readAsDataURL(file);
  });

  const img = await new Promise((resolve, reject) => {
    const i = new Image();
    i.onerror = () => reject(new Error("not a valid image"));
    i.onload = () => resolve(i);
    i.src = dataUrl;
  });

  // Center-crop to a square, then scale to TARGET.
  const side = Math.min(img.width, img.height);
  const sx = (img.width - side) / 2;
  const sy = (img.height - side) / 2;
  const canvas = document.createElement("canvas");
  canvas.width = TARGET;
  canvas.height = TARGET;
  const ctx = canvas.getContext("2d");
  ctx.drawImage(img, sx, sy, side, side, 0, 0, TARGET, TARGET);

  const blob = await new Promise((resolve, reject) => {
    canvas.toBlob(
      (b) => (b ? resolve(b) : reject(new Error("canvas.toBlob failed"))),
      "image/jpeg",
      QUALITY,
    );
  });
  const buffer = await blob.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  // Convert bytes → base64 in chunks to avoid stack blowup on
  // String.fromCharCode(...bytes).
  let bin = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  const imageB64 = btoa(bin);

  await call("set_side_avatar", {
    dataDir: state.dataDir,
    sideAddress: state.activeSide,
    imageB64,
  });
  await refreshSidePhoto(state.activeSide);
  // Re-render anywhere the avatar appears.
  renderRail();
  renderInside();
  if (state.view.name === "side-settings") renderSideSettings();
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
  // If the message arrived while the user is actively viewing that
  // thread, auto-mark-read so the unread badge never appears for it.
  const isViewing =
    state.view.name === "thread" &&
    state.view.params.peer === peer &&
    state.activeSide === sideAddr;
  if (isViewing) {
    markRead(sideAddr, peer);
  }
  renderInside();
  if (isViewing) {
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
      const raw = await window.svPrompt(
        "Label for the new side (e.g. work, private, public).",
        "extra",
        { title: "New side", okLabel: "Create" },
      );
      if (raw == null) return;
      const trimmed = String(raw).trim();
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
  // Welcome quick-start: open Add-friend on the "Share me" tab and
  // auto-trigger the generate so the link is ready immediately.
  $("welcome-share")?.addEventListener("click", () => {
    state.addFriendTab = "share";
    showView("add-friend");
    setTimeout(() => $("contact-qr-generate")?.click(), 0);
  });
  // Welcome quick-start: jump straight to global settings, where the
  // side rail's "+ add side" + the existing side list both live.
  $("welcome-switch")?.addEventListener("click", () => showView("settings"));

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
      const ok = await window.svConfirm(
        `Remove ${friendDisplayFor(peer)} as a friend?`,
        { title: "Remove friend", okLabel: "Remove", danger: true },
      );
      if (!ok) return;
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
      // Reveal the "Copy link" affordance now that we have a URI.
      const copyBtn = $("contact-qr-copy");
      if (copyBtn) copyBtn.hidden = false;
      showOk(t("toast.qr_shown"));
    }),
  );
  $("contact-qr-copy")?.addEventListener("click", () =>
    safe(async () => {
      const uri = $("contact-qr-uri")?.value || "";
      if (!uri) throw new Error("no link to copy");
      try {
        await navigator.clipboard.writeText(uri);
        showOk(t("toast.invite_copied"));
      } catch {
        // Fallback for environments without clipboard permission.
        const ta = $("contact-qr-uri");
        ta?.select?.();
        document.execCommand("copy");
        showOk(t("toast.invite_copied"));
      }
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
      const rawName = $("profile-name").value.trim();
      // Username validation: identifier-shaped, ≤32 chars. Allow
      // [A-Za-z0-9._-]. Empty is allowed (= unset). Not enforced
      // for uniqueness; Phase 2 registry will handle that.
      if (rawName) {
        if (rawName.length > 32) {
          throw new Error(t("err.username_too_long"));
        }
        if (!/^[A-Za-z0-9._-]+$/.test(rawName)) {
          throw new Error(t("err.username_bad_chars"));
        }
      }
      const name = rawName || null;
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

  // Photo picker — file input is hidden; the Change button triggers it.
  $("side-photo-change")?.addEventListener("click", () => {
    $("side-photo-file")?.click();
  });
  $("side-photo-file")?.addEventListener("change", (e) =>
    safe(async () => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      await uploadSidePhoto(file);
      e.target.value = ""; // allow re-picking the same file
      showOk(t("toast.photo_saved"));
    }),
  );
  $("side-photo-clear")?.addEventListener("click", () =>
    safe(async () => {
      if (!state.activeSide) return;
      await call("clear_side_avatar", {
        dataDir: state.dataDir,
        sideAddress: state.activeSide,
      });
      state.sidePhotoUrls.delete(state.activeSide);
      renderRail();
      renderInside();
      renderSideSettings();
      showOk(t("toast.photo_cleared"));
    }),
  );
  $("side-retire")?.addEventListener("click", () =>
    safe(async () => {
      if (!state.activeSide) throw new Error(t("toast.no_side"));
      const ok = await window.svConfirm(
        `Retire ${shortenAddr(state.activeSide)}? Peers will treat new traffic from this side as anomalous. Can't be undone.`,
        { title: "Retire side", okLabel: "Retire", cancelLabel: "Cancel", danger: true },
      );
      if (!ok) return;
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
      if (!state.dataDir) throw new Error("no active data dir");
      const filename = $("settings-backup-filename").value.trim();
      const passphrase = $("settings-backup-passphrase").value;
      const confirm = $("settings-backup-passphrase-confirm").value;
      if (!filename) throw new Error("filename required");
      if (!passphrase) throw new Error("passphrase required (the backup is encrypted)");
      if (passphrase !== confirm) throw new Error("passphrases do not match");
      const written = await call("write_seed_backup", {
        dataDir: state.dataDir,
        filename,
        passphrase,
      });
      // Clear the passphrase fields so they don't linger in the DOM.
      $("settings-backup-passphrase").value = "";
      $("settings-backup-passphrase-confirm").value = "";
      showOk(`Encrypted seed saved to ${written}`);
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
