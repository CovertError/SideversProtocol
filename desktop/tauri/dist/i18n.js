// Sidevers desktop i18n (Phase 3.H).
//
// Minimal vanilla shim:
//   * Loads a JSON locale bundle from `locales/<lang>.json`.
//   * Substitutes every element with a `data-i18n="key"` attribute.
//   * For inputs / textareas, substitutes `data-i18n-placeholder="key"`.
//   * Sets `<html lang>` and `<html dir>` based on the locale.
//   * Picks the initial locale from `localStorage.sv_lang`, falling back
//     to `navigator.language` and finally to "en".
//
// Adding a language: drop a `locales/<lang>.json` mirroring en.json,
// add the code to `RTL_LOCALES` below if right-to-left.

const RTL_LOCALES = new Set(["ar", "he", "fa", "ur"]);
const SUPPORTED = ["en", "ar"];

let current = "en";
let dict = {};

function pickInitial() {
  const stored = localStorage.getItem("sv_lang");
  if (stored && SUPPORTED.includes(stored)) return stored;
  const nav = (navigator.language || "en").slice(0, 2).toLowerCase();
  return SUPPORTED.includes(nav) ? nav : "en";
}

export async function setLocale(lang) {
  if (!SUPPORTED.includes(lang)) lang = "en";
  current = lang;
  const resp = await fetch(`locales/${lang}.json`);
  if (!resp.ok) {
    console.warn(`i18n: failed to load locales/${lang}.json (${resp.status})`);
    return;
  }
  dict = await resp.json();
  document.documentElement.lang = lang;
  document.documentElement.dir = RTL_LOCALES.has(lang) ? "rtl" : "ltr";
  localStorage.setItem("sv_lang", lang);
  applyTranslations(document);
}

export function t(key, vars) {
  let s = dict[key] || key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      s = s.replace(new RegExp(`\\{${k}\\}`, "g"), String(v));
    }
  }
  return s;
}

export function applyTranslations(root) {
  for (const el of root.querySelectorAll("[data-i18n]")) {
    el.textContent = t(el.getAttribute("data-i18n"));
  }
  for (const el of root.querySelectorAll("[data-i18n-placeholder]")) {
    el.placeholder = t(el.getAttribute("data-i18n-placeholder"));
  }
  for (const el of root.querySelectorAll("[data-i18n-title]")) {
    el.title = t(el.getAttribute("data-i18n-title"));
  }
}

export function currentLocale() {
  return current;
}

// Auto-init: load the picked locale on import. Other modules can call
// `setLocale("ar")` later to switch at runtime.
const initial = pickInitial();

// Expose a minimal global so main.js (plain script, not a module) can
// call into the i18n machinery without sharing imports.
window.__sv_i18n = { setLocale, t, currentLocale, applyTranslations };

setLocale(initial).then(() => {
  // Sync the lang-switch <select> to the active locale and wire change.
  const sel = document.getElementById("lang-switch");
  if (sel) {
    sel.value = initial;
    sel.addEventListener("change", (e) => {
      const v = e.target.value;
      setLocale(v);
    });
  }
});
