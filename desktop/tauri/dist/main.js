// Sidevers desktop frontend — vanilla JS, no bundler.
// Calls into the Tauri 2 Rust backend via window.__TAURI__.core.invoke.
// Tauri converts snake_case Rust command params to camelCase here.

const tauri = window.__TAURI__;
const invoke = tauri ? tauri.core.invoke : null;

const $ = (id) => document.getElementById(id);

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
      "Tauri runtime not available — run `cargo tauri dev` instead of opening this HTML directly.",
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

// --- Keys -------------------------------------------------------------

$("gen-master").onclick = () =>
  safe(async () => {
    $("master-seed").value = await call("generate_master");
    showOk("master seed generated");
  });

$("derive-side").onclick = () =>
  safe(async () => {
    const masterHex = require($("master-seed").value, "master seed");
    const label = require($("side-label").value, "side label");
    $("side-seed").value = await call("derive_side", { masterHex, label });
    showOk(`derived side under label "${label}"`);
  });

$("compute-pubkey").onclick = () =>
  safe(async () => {
    const seedHex = require($("side-seed").value, "side seed");
    $("pubkey").value = await call("pubkey_from_seed", { seedHex });
    showOk("pubkey computed");
  });

async function encodeAddrAs(kind) {
  await safe(async () => {
    const pubkeyHex = require($("pubkey").value, "pubkey");
    $("address").value = await call("encode_address", { pubkeyHex, kind });
    showOk(`encoded as ${kind} address`);
  });
}

$("encode-side-addr").onclick = () => encodeAddrAs("side");
$("encode-verse-addr").onclick = () => encodeAddrAs("verse");

// --- Send DM ----------------------------------------------------------

$("seal-dm").onclick = () =>
  safe(async () => {
    const senderSeedHex = require($("send-sender").value, "sender side seed");
    const recipientPubkeyHex = require(
      $("send-recipient").value,
      "recipient pubkey",
    );
    const text = require($("send-text").value, "message text");
    $("wire").value = await call("seal_dm", {
      senderSeedHex,
      recipientPubkeyHex,
      text,
    });
    showOk("DM sealed");
  });

$("copy-wire").onclick = () =>
  safe(async () => {
    const wire = $("wire").value.trim();
    if (!wire) {
      throw new Error("nothing to copy — seal a DM first");
    }
    await navigator.clipboard.writeText(wire);
    showOk("wire bytes copied to clipboard");
  });

// --- Open DM ----------------------------------------------------------

$("open-dm").onclick = () =>
  safe(async () => {
    const recipientSeedHex = require(
      $("recv-recipient").value,
      "recipient side seed",
    );
    const wireHex = require($("recv-wire").value, "wire bytes");
    $("plaintext").value = await call("open_dm", {
      recipientSeedHex,
      wireHex,
    });
    showOk("DM verified + decrypted");
  });

// On boot, surface whether we're running inside Tauri or just a plain
// browser preview — helps diagnose "buttons don't do anything".
if (!invoke) {
  showError(
    "Tauri runtime not detected. Buttons will fail until this page is loaded via `cargo tauri dev`.",
  );
}
