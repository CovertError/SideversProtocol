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
  // Stage D L2b: groups (verses) the user belongs to. Each rail
  // avatar below Home represents one entry. populated by list_groups.
  // groups : Array<GroupView>
  groups: [],
  // groupChats : Map<verse_address, Array<{from, plaintext, received_at, kind}>>
  // Filled by verse:post events; each entry is a decrypted group post.
  groupChats: new Map(),
  // activeGroup : GroupView | null — the currently-open group, if any.
  // When set, the compose box posts to this group and the thread
  // view renders groupChats.get(verse_address) instead of DMs.
  activeGroup: null,
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

// ---- Stage D L4: media (image + voice) helpers ----

// Cache fetched media URLs by hash so a re-render doesn't re-fetch.
const mediaUrlCache = new Map(); // hash_hex -> file URL
const mediaInFlight = new Set(); // hash_hex currently being fetched

// State for an in-progress voice recording. Holds the MediaRecorder
// instance + recorded chunks + the start timestamp for the elapsed
// counter. Only one recording at a time.
let voiceRec = null;

function blobToBase64(blob) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error || new Error("read failed"));
    reader.onload = () => {
      const result = reader.result;
      // Strip the data: URL prefix to get raw base64.
      const idx = result.indexOf(",");
      resolve(idx >= 0 ? result.slice(idx + 1) : result);
    };
    reader.readAsDataURL(blob);
  });
}

// Resize an image File to <= TARGET on each side via canvas, JPEG q=0.85.
// Returns base64 of the JPEG bytes.
async function resizeImageToBase64(file) {
  const TARGET = 1280;
  const QUALITY = 0.85;
  const dataUrl = await new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onerror = () => reject(r.error || new Error("read failed"));
    r.onload = () => resolve(r.result);
    r.readAsDataURL(file);
  });
  const img = await new Promise((resolve, reject) => {
    const i = new Image();
    i.onerror = () => reject(new Error("not a valid image"));
    i.onload = () => resolve(i);
    i.src = dataUrl;
  });
  let w = img.width;
  let h = img.height;
  if (Math.max(w, h) > TARGET) {
    const scale = TARGET / Math.max(w, h);
    w = Math.round(w * scale);
    h = Math.round(h * scale);
  }
  const canvas = document.createElement("canvas");
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext("2d");
  ctx.drawImage(img, 0, 0, w, h);
  const blob = await new Promise((resolve, reject) => {
    canvas.toBlob(
      (b) => (b ? resolve(b) : reject(new Error("canvas.toBlob failed"))),
      "image/jpeg",
      QUALITY,
    );
  });
  return blobToBase64(blob);
}

// Fetch a media object by hash. Returns a webview-loadable URL or
// throws on failure. Multiple concurrent renders for the same hash
// share a single in-flight promise so we don't fetch twice.
async function getMediaUrl(hash_hex, peer_dial, from_side) {
  if (!hash_hex) throw new Error("media: missing hash");
  if (mediaUrlCache.has(hash_hex)) return mediaUrlCache.get(hash_hex);
  if (mediaInFlight.has(hash_hex)) {
    // Spin until the in-flight call finishes. Cheap busy-wait
    // (resolves in ms); avoids re-fetching the same object.
    await new Promise((r) => setTimeout(r, 50));
    if (mediaUrlCache.has(hash_hex)) return mediaUrlCache.get(hash_hex);
  }
  mediaInFlight.add(hash_hex);
  try {
    const path = await call("fetch_media", {
      dataDir: state.dataDir,
      hashHex: hash_hex,
      peerListenAddr: peer_dial || null,
      fromSide: from_side || null,
    });
    const url = fileSrc(path);
    mediaUrlCache.set(hash_hex, url);
    return url;
  } finally {
    mediaInFlight.delete(hash_hex);
  }
}

// Build a message-body DOM node for a media message. The element
// kicks off the fetch on first render; on success the placeholder
// is swapped for the real <img> / <audio>.
function buildMediaBody(msg, peer_dial, from_side) {
  const wrap = document.createElement("div");
  if (msg.mediaKind === "image") {
    const ph = document.createElement("div");
    ph.className = "sv-msg-media-loading";
    ph.textContent = t("media.loading_image") || "Loading image…";
    wrap.appendChild(ph);
    getMediaUrl(msg.media_hash_hex, peer_dial, from_side)
      .then((url) => {
        const img = document.createElement("img");
        img.className = "sv-msg-image";
        img.src = url;
        img.alt = "";
        img.onclick = () => openImageModal(url);
        wrap.innerHTML = "";
        wrap.appendChild(img);
      })
      .catch((e) => {
        ph.className = "sv-msg-media-error";
        ph.textContent =
          (t("media.error_image") || "Image unavailable") + ": " + (e?.message || e);
      });
  } else if (msg.mediaKind === "voice") {
    const ph = document.createElement("div");
    ph.className = "sv-msg-media-loading";
    ph.textContent = t("media.loading_voice") || "Loading voice note…";
    wrap.appendChild(ph);
    getMediaUrl(msg.media_hash_hex, peer_dial, from_side)
      .then((url) => {
        const audio = document.createElement("audio");
        audio.className = "sv-msg-audio";
        audio.controls = true;
        audio.src = url;
        if (msg.media_mime) audio.type = msg.media_mime;
        wrap.innerHTML = "";
        wrap.appendChild(audio);
      })
      .catch((e) => {
        ph.className = "sv-msg-media-error";
        ph.textContent =
          (t("media.error_voice") || "Voice note unavailable") + ": " + (e?.message || e);
      });
  } else {
    // Unknown media kind — show the text body as fallback.
    wrap.textContent = msg.plaintext || "";
  }
  return wrap;
}

function openImageModal(url) {
  const modal = $("sv-image-modal");
  const img = $("sv-image-modal-img");
  if (!modal || !img) return;
  img.src = url;
  modal.hidden = false;
}

function closeImageModal() {
  const modal = $("sv-image-modal");
  if (modal) modal.hidden = true;
}

// Outgoing: send an image in the current thread. Uses the same
// ensure-session pattern as text DMs. Group media is deferred —
// post_to_group needs a different path.
async function sendImageInCurrentThread(file) {
  if (state.activeGroup) {
    showError(
      t("media.group_not_yet") ||
        "Media in groups is coming next — DMs only for now.",
    );
    return;
  }
  const peer = state.view?.params?.peer;
  if (!peer || !state.activeSide) return;
  const key = sessionKey(state.activeSide, peer);
  const sess = state.sessions.get(key);
  if (sess?.status !== "open") {
    await ensureSessionFor(state.activeSide, peer);
    const after = state.sessions.get(key);
    if (after?.status !== "open") {
      throw new Error(after?.error || "couldn't open session");
    }
  }
  const imageB64 = await resizeImageToBase64(file);
  const resp = await call("send_dm_media", {
    dataDir: state.dataDir,
    fromSide: state.activeSide,
    kind: "image",
    mediaB64: imageB64,
  });
  // Pre-warm cache so own image renders immediately without re-fetch.
  try {
    const url = await getMediaUrl(resp.hash_hex, null, state.activeSide);
    mediaUrlCache.set(resp.hash_hex, url);
  } catch {}
  const now = Math.floor(Date.now() / 1000);
  appendChat(state.activeSide, peer, {
    from: state.activeSide,
    to: peer,
    plaintext: "",
    received_at: now,
    kind: "out",
    mediaKind: "image",
    media_hash_hex: resp.hash_hex,
    media_size: resp.size,
    media_mime: resp.mime,
  });
  renderInside();
  renderView();
  showOk(t("toast.image_sent") || "Image sent");
}

async function startVoiceRecording() {
  if (state.activeGroup) {
    showError(
      t("media.group_not_yet") ||
        "Voice in groups is coming next — DMs only for now.",
    );
    return;
  }
  if (!navigator.mediaDevices?.getUserMedia) {
    throw new Error("microphone API unavailable in this webview");
  }
  const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  let mimeType = "audio/webm;codecs=opus";
  if (
    typeof MediaRecorder !== "undefined" &&
    !MediaRecorder.isTypeSupported?.(mimeType)
  ) {
    mimeType = MediaRecorder.isTypeSupported?.("audio/webm")
      ? "audio/webm"
      : MediaRecorder.isTypeSupported?.("audio/ogg")
        ? "audio/ogg"
        : "";
  }
  const rec = mimeType
    ? new MediaRecorder(stream, { mimeType })
    : new MediaRecorder(stream);
  const chunks = [];
  rec.ondataavailable = (e) => {
    if (e.data && e.data.size > 0) chunks.push(e.data);
  };
  voiceRec = {
    rec,
    chunks,
    stream,
    startedAt: Date.now(),
    mimeType: rec.mimeType || "audio/webm",
    timer: null,
  };
  rec.start();
  const indicator = $("compose-recording");
  if (indicator) indicator.hidden = false;
  const timeEl = $("compose-recording-time");
  voiceRec.timer = setInterval(() => {
    const sec = Math.floor((Date.now() - voiceRec.startedAt) / 1000);
    if (timeEl)
      timeEl.textContent = `${Math.floor(sec / 60)}:${String(sec % 60).padStart(2, "0")}`;
  }, 250);
}

function teardownVoiceRecording() {
  if (!voiceRec) return;
  clearInterval(voiceRec.timer);
  try {
    voiceRec.stream.getTracks().forEach((t) => t.stop());
  } catch {}
  const indicator = $("compose-recording");
  if (indicator) indicator.hidden = true;
  voiceRec = null;
}

function cancelVoiceRecording() {
  if (!voiceRec) return;
  try {
    voiceRec.rec.stop();
  } catch {}
  teardownVoiceRecording();
}

async function stopVoiceRecording() {
  if (!voiceRec) return;
  const peer = state.view?.params?.peer;
  if (!peer || !state.activeSide) {
    cancelVoiceRecording();
    return;
  }
  const rec = voiceRec.rec;
  const chunks = voiceRec.chunks;
  const mimeType = voiceRec.mimeType;
  // Wait for the final dataavailable event before reading chunks.
  const stopped = new Promise((resolve) => {
    rec.onstop = resolve;
  });
  try {
    rec.stop();
  } catch {}
  await stopped;
  teardownVoiceRecording();

  if (chunks.length === 0) {
    showError(t("toast.voice_empty") || "Voice recording was empty");
    return;
  }
  const blob = new Blob(chunks, { type: mimeType });

  // Ensure session before upload (same pattern as image send).
  const key = sessionKey(state.activeSide, peer);
  const sess = state.sessions.get(key);
  if (sess?.status !== "open") {
    await ensureSessionFor(state.activeSide, peer);
    const after = state.sessions.get(key);
    if (after?.status !== "open") {
      throw new Error(after?.error || "couldn't open session");
    }
  }
  const audioB64 = await blobToBase64(blob);
  const resp = await call("send_dm_media", {
    dataDir: state.dataDir,
    fromSide: state.activeSide,
    kind: "voice",
    mediaB64: audioB64,
  });
  try {
    const url = await getMediaUrl(resp.hash_hex, null, state.activeSide);
    mediaUrlCache.set(resp.hash_hex, url);
  } catch {}
  const now = Math.floor(Date.now() / 1000);
  appendChat(state.activeSide, peer, {
    from: state.activeSide,
    to: peer,
    plaintext: "",
    received_at: now,
    kind: "out",
    mediaKind: "voice",
    media_hash_hex: resp.hash_hex,
    media_size: resp.size,
    media_mime: resp.mime,
  });
  renderInside();
  renderView();
  showOk(t("toast.voice_sent") || "Voice note sent");
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
  await refreshGroups();
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
    listen("verse:post", (e) => onVersePost(e?.payload));
  }
};

async function refreshGroups() {
  if (!state.dataDir) {
    state.groups = [];
    return;
  }
  try {
    state.groups = await call("list_groups", { dataDir: state.dataDir });
  } catch (e) {
    console.warn("list_groups failed:", e);
    state.groups = [];
  }
}

function onVersePost(payload) {
  if (!payload || !payload.verse) return;
  const verse = payload.verse;
  if (!state.groupChats.has(verse)) state.groupChats.set(verse, []);
  state.groupChats.get(verse).push({
    from: payload.from,
    plaintext: payload.plaintext,
    received_at: payload.received_at,
    // Distinguish our own outgoing posts from received ones by
    // comparing `from` against the active group's member-side.
    kind:
      state.activeGroup &&
      state.activeGroup.verse_address === verse &&
      payload.from === state.activeGroup.member_side_address
        ? "out"
        : "in",
  });
  // If the user is looking at this group right now, repaint the thread.
  if (state.activeGroup && state.activeGroup.verse_address === verse) {
    renderView();
  }
  renderRail();
}

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
    if (
      !state.activeGroup &&
      state.activeSide === state.personalSideAddress
    ) {
      homeBtn.setAttribute("data-active", "true");
    }
    homeBtn.innerHTML =
      '<svg viewBox="0 0 24 24" stroke-width="1.7" aria-hidden="true">' +
      '<path stroke-linecap="round" stroke-linejoin="round" ' +
      'd="m2.25 12 8.954-8.955c.44-.439 1.152-.439 1.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25"/>' +
      "</svg>";
    homeBtn.onclick = () => {
      // Clear any group context so the in-side column flips back to
      // Friends + Chats.
      state.activeGroup = null;
      setActiveSide(state.personalSideAddress);
    };
    homeLi.appendChild(homeBtn);
    ul.appendChild(homeLi);
  }

  // ---- Group avatars (Stage D L2b) ----
  // Each group surfaces as an avatar between Home and the rail's
  // action buttons. Clicking switches activeSide to the group's
  // member-side AND sets state.activeGroup so the thread view
  // renders group posts instead of DMs.
  const groupMemberSides = new Set(
    state.groups.map((g) => g.member_side_address),
  );
  for (const group of state.groups) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.className = "sv-rail-btn";
    const label = group.name || shortenAddr(group.verse_address);
    btn.setAttribute("aria-label", label);
    btn.title = label;
    if (
      state.activeGroup &&
      state.activeGroup.verse_address === group.verse_address
    ) {
      btn.setAttribute("data-active", "true");
    }
    const av = document.createElement("span");
    av.className = "sv-avatar sv-rail-avatar";
    applyAvatar(av, group.verse_address, label);
    btn.appendChild(av);
    btn.onclick = () => openGroup(group);
    li.appendChild(btn);
    ul.appendChild(li);
  }

  // ---- Standalone non-personal, non-group sides ----
  // Rare today (Stage D's create_group covers the common "extra side"
  // case). Kept so power users who minted standalone sides via add_side
  // before groups landed still see them. Hide retired sides too.
  const visible = state.sides.filter(
    (s) =>
      !s.is_retired &&
      s.side_address !== state.personalSideAddress &&
      !groupMemberSides.has(s.side_address),
  );
  for (const s of visible) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.className = "sv-rail-btn";
    btn.setAttribute("aria-label", sideLabel(s.side_address) || s.side_address);
    btn.title = sideLabel(s.side_address) || s.side_address;
    if (s.side_address === state.activeSide && !state.activeGroup) {
      btn.setAttribute("data-active", "true");
    }

    const av = document.createElement("span");
    av.className = "sv-avatar sv-rail-avatar";
    applyAvatar(av, s.side_address, sideLabel(s.side_address));
    btn.appendChild(av);

    btn.onclick = () => setActiveSide(s.side_address);
    li.appendChild(btn);
    ul.appendChild(li);
  }
}

/// Switch the rail's selected context to a group. Sets activeGroup +
/// activeSide (the group's member-side), opens the group thread.
function openGroup(group) {
  state.activeGroup = group;
  state.activeSide = group.member_side_address;
  state.view = {
    name: "group-thread",
    params: { verse: group.verse_address },
  };
  renderRail();
  renderInside();
  renderView();
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

  // Stage D L2b: when a group is active, the in-side column shows
  // group framing — header is the group's name + role, and the
  // Friends/Chats lists are replaced with a single "this is a group"
  // hint. (Full member list + per-message list will land in L3.)
  if (state.activeGroup) {
    const g = state.activeGroup;
    if (titleEl) titleEl.textContent = g.name || shortenAddr(g.verse_address);
    if (avatarEl) applyAvatar(avatarEl, g.verse_address, g.name || "");
    if (statsEl) {
      statsEl.textContent =
        g.role === "moderator"
          ? t("inside.group_role_moderator") || "Group · you moderate"
          : t("inside.group_role_member") || "Group · member";
    }
    const friendsUl = $("friends-list");
    if (friendsUl) {
      friendsUl.innerHTML = "";
      const li = document.createElement("li");
      li.className = "sv-inside-section-empty";
      li.textContent =
        t("inside.group_hint") ||
        "Group chat is open in the main pane. Share the invite link from settings to add people.";
      friendsUl.appendChild(li);
    }
    const chatsUl = $("chats-list");
    if (chatsUl) chatsUl.innerHTML = "";
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
    // Stage D L2b: group chat reuses the thread view shell — same
    // HTML, different data source (groupChats vs DMs) and different
    // send path (post_to_group vs send_dm_live).
    "group-thread": renderGroupThread,
    friend: renderFriend,
    "add-friend": renderAddFriend,
    "side-settings": renderSideSettings,
    settings: renderSettings,
    advanced: renderAdvanced,
  };
  for (const el of document.querySelectorAll("[data-view]")) {
    // group-thread is rendered into the same DOM as data-view="thread".
    const matchName =
      state.view.name === "group-thread" ? "thread" : state.view.name;
    el.hidden = el.dataset.view !== matchName;
  }
  const fn = viewMap[state.view.name];
  if (fn) fn(state.view.params);
}

function renderGroupThread(params) {
  const verse = params?.verse;
  if (!verse || !state.activeGroup) return;
  const group = state.activeGroup;

  const nameEl = $("thread-name");
  const subEl = $("thread-sub");
  const avEl = $("thread-avatar");
  if (nameEl) nameEl.textContent = group.name || shortenAddr(verse);
  if (avEl) applyAvatar(avEl, verse, group.name || "");
  if (subEl) {
    const msgs = state.groupChats.get(verse) || [];
    subEl.textContent =
      group.role === "moderator"
        ? `Group · you moderate`
        : `Group · ${msgs.length} message${msgs.length === 1 ? "" : "s"}`;
  }
  // The "View profile" button only makes sense for 1:1 chats. Hide
  // it on group views; could later become "View group settings".
  const profileBtn = $("thread-view-profile");
  if (profileBtn) profileBtn.hidden = true;

  const list = $("thread-list");
  if (!list) return;
  list.innerHTML = "";

  const msgs = state.groupChats.get(verse) || [];
  if (msgs.length === 0) {
    const empty = document.createElement("div");
    empty.className = "sv-empty";
    const p = document.createElement("p");
    p.textContent = t("thread.empty");
    empty.appendChild(p);
    list.appendChild(empty);
    return;
  }

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
      const author = m.from;
      const av = document.createElement("span");
      av.className = "sv-avatar sv-avatar-sm";
      const label =
        m.kind === "out"
          ? group.name || ""
          : shortenAddr(m.from);
      applyAvatar(av, author, label);
      slot.appendChild(av);
    }
    row.appendChild(slot);
    const content = document.createElement("div");
    content.className = "sv-msg-content";
    if (!grouped) {
      const header = document.createElement("div");
      header.className = "sv-msg-header";
      const nameEl2 = document.createElement("span");
      nameEl2.className = "sv-msg-name";
      nameEl2.textContent =
        m.kind === "out" ? t("msg.you") : shortenAddr(m.from);
      const timeEl = document.createElement("span");
      timeEl.className = "sv-msg-time";
      timeEl.textContent = relativeTime(m.received_at);
      header.appendChild(nameEl2);
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
    if (m.mediaKind === "image" || m.mediaKind === "voice") {
      // Stage D L4: media bubble. peer_dial + from_side are needed so
      // the fetch path can dial the sender if we don't have the
      // object cached locally yet. For our own outgoing messages the
      // object IS already in our ObjectStore so no dial is needed.
      const friend = (state.friends.get(state.activeSide) || []).find(
        (r) => r.address === m.from || r.address === peer,
      );
      const peerDial = friend?.peer_listen_addr || null;
      body.appendChild(buildMediaBody(m, peerDial, state.activeSide));
    } else {
      body.textContent = m.plaintext;
    }
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
  const input = $("compose-text");
  if (!input) return;
  const text = input.value;
  if (!text || !text.trim()) return;

  // Stage D L2b: branch on whether we're in a group or a 1:1 chat.
  if (state.activeGroup) {
    const group = state.activeGroup;
    await call("post_to_group", {
      dataDir: state.dataDir,
      memberSideAddress: group.member_side_address,
      text,
    });
    // Mirror locally so the bubble shows immediately. Mark from =
    // our member-side so the renderGroupThread "you" check works.
    const now = Math.floor(Date.now() / 1000);
    if (!state.groupChats.has(group.verse_address))
      state.groupChats.set(group.verse_address, []);
    state.groupChats.get(group.verse_address).push({
      from: group.member_side_address,
      plaintext: text,
      received_at: now,
      kind: "out",
    });
    input.value = "";
    renderInside();
    renderView();
    return;
  }

  const peer = state.view?.params?.peer;
  if (!peer || !state.activeSide) return;
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
  // Stage D L4: pass media metadata (kind, hash, size, mime) through
  // to the in-memory chat log as `mediaKind` etc.; the `kind` field
  // in the chat-message object means direction ("in"/"out"), not
  // message type.
  appendChat(sideAddr, peer, {
    from: peer,
    to: sideAddr,
    plaintext: payload.plaintext,
    received_at: payload.received_at,
    kind: "in",
    mediaKind: payload.kind === "text" ? null : payload.kind,
    media_hash_hex: payload.media_hash_hex || null,
    media_size: payload.media_size || null,
    media_mime: payload.media_mime || null,
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
        mediaKind: e.kind === "text" ? null : e.kind,
        media_hash_hex: e.media_hash_hex || null,
        media_size: e.media_size || null,
        media_mime: e.media_mime || null,
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
  // Stage D L2b: the rail "+" now creates a group (the primary
  // surface). Power users who want a standalone non-group side can
  // still get one via Advanced (not surfaced in this MVP).
  $("rail-add-side")?.addEventListener("click", () =>
    safe(async () => {
      const raw = await window.svPrompt(
        t("create_group.prompt") ||
          "Group name — what should this space be called?",
        "",
        {
          title: t("create_group.title") || "Create a group",
          okLabel: t("btn.create_group") || "Create",
        },
      );
      if (raw == null) return;
      const trimmed = String(raw).trim();
      if (!trimmed) return;
      const resp = await call("create_group", {
        dataDir: state.dataDir,
        name: trimmed,
      });
      state.sideLabels.set(resp.member_side_address, trimmed);
      await refreshSides();
      await refreshGroups();
      renderRail();
      // Switch into the new group.
      const created = state.groups.find(
        (g) => g.verse_address === resp.verse_address,
      );
      if (created) openGroup(created);
      // Show the freshly-minted invite link so the user can copy it
      // to share. The Add-friend "Share me" tab is the natural place
      // — but for groups we should land in the group + a small toast.
      try {
        await navigator.clipboard.writeText(resp.group_invite_uri);
        showOk(
          t("toast.group_created_copied") ||
            "Group created · invite link copied to clipboard",
        );
      } catch {
        showOk(
          t("toast.group_created") ||
            "Group created · share its invite link from settings",
        );
      }
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

  // Stage D L4: attach image. The button clicks the hidden file
  // input; the input's change handler resizes + uploads + mirrors.
  $("compose-attach")?.addEventListener("click", () =>
    $("compose-image-file")?.click(),
  );
  $("compose-image-file")?.addEventListener("change", (e) =>
    safe(async () => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      e.target.value = ""; // allow re-pick of same file
      await sendImageInCurrentThread(file);
    }),
  );

  // Stage D L4: voice recording. Click mic to start, then either
  // Send (stop + upload) or Cancel (drop). Browser handles the
  // microphone-permission prompt the first time.
  $("compose-mic")?.addEventListener("click", () =>
    safe(async () => {
      if (voiceRec) return; // already recording
      await startVoiceRecording();
    }),
  );
  $("compose-recording-stop")?.addEventListener("click", () =>
    safe(stopVoiceRecording),
  );
  $("compose-recording-cancel")?.addEventListener("click", () => {
    cancelVoiceRecording();
  });

  // Stage D L4: image-modal close on click + Escape.
  $("sv-image-modal")?.addEventListener("click", closeImageModal);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeImageModal();
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
      const uri = $("contact-paste-uri").value.trim();
      if (!uri) throw new Error("paste a friend code first");

      // Stage D L2b: dispatch by URI prefix. Group invites and
      // friend invites share a single paste field but route to
      // different commands.
      if (uri.startsWith("sidevers-group:")) {
        const resp = await call("join_group_by_invite", {
          dataDir: state.dataDir,
          qrUri: uri,
        });
        $("contact-paste-uri").value = "";
        await refreshSides();
        await refreshGroups();
        if (resp.name) state.sideLabels.set(resp.member_side_address, resp.name);
        renderRail();
        // Land in the new group.
        const joined = state.groups.find(
          (g) => g.verse_address === resp.verse_address,
        );
        if (joined) openGroup(joined);
        showOk(
          t("toast.group_joined", { name: resp.name || "group" }) ||
            `Joined ${resp.name || "group"}`,
        );
        return;
      }

      // Default: friend (contact) code.
      if (!state.personalSideAddress)
        throw new Error("personal side missing");
      const resp = await call("accept_contact_qr", {
        sideAddress: state.personalSideAddress,
        qrUri: uri,
      });
      $("contact-paste-uri").value = "";
      await refreshFriends(state.personalSideAddress);
      renderInside();
      showOk(
        t("toast.friend_added", {
          name: resp.display_name || shortenAddr(resp.friend_address),
        }),
      );
      // Drop into the new chat thread. Switch to Home first so
      // friends list is the active context.
      state.activeGroup = null;
      state.activeSide = state.personalSideAddress;
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
