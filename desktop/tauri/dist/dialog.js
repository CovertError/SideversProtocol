// In-DOM dialog helpers — replacement for window.confirm/prompt, which
// Tauri 2 webviews don't reliably support across the WebKit / WebView2 /
// WebKitGTK backends. Loaded before onboarding.js so both onboarding and
// main can use these helpers regardless of which file fires first.
//
// API:
//   window.svConfirm(message, opts)            → Promise<boolean>
//   window.svPrompt(message, defaultValue, opts) → Promise<string | null>
//
// `opts.okLabel` and `opts.cancelLabel` override the button text.
// `opts.danger` (boolean) marks the OK button as a destructive action.
//
// The modal is keyboard-friendly: Enter confirms, Escape cancels, the
// first focusable element receives focus on open, and clicking the
// backdrop cancels.

(function () {
  // Inject the modal DOM lazily on first use so we don't depend on a
  // particular index.html shape. Idempotent.
  let root = null;
  let titleEl = null;
  let bodyEl = null;
  let inputWrap = null;
  let inputEl = null;
  let okBtn = null;
  let cancelBtn = null;
  let backdrop = null;
  let resolveFn = null;
  let lastFocus = null;

  function ensureRoot() {
    if (root) return;
    root = document.createElement("div");
    root.id = "sv-modal";
    root.setAttribute("role", "dialog");
    root.setAttribute("aria-modal", "true");
    root.setAttribute("aria-labelledby", "sv-modal-title");
    root.hidden = true;
    root.innerHTML = `
      <div class="sv-modal-backdrop" data-sv-modal-cancel></div>
      <div class="sv-modal-card">
        <h2 class="sv-modal-title" id="sv-modal-title"></h2>
        <p class="sv-modal-body"></p>
        <div class="sv-modal-input-wrap" hidden>
          <input class="sv-modal-input" type="text" spellcheck="false" />
        </div>
        <div class="sv-modal-actions">
          <button class="sv-modal-cancel secondary" type="button"></button>
          <button class="sv-modal-ok" type="button"></button>
        </div>
      </div>`;
    document.body.appendChild(root);
    backdrop = root.querySelector("[data-sv-modal-cancel]");
    titleEl = root.querySelector(".sv-modal-title");
    bodyEl = root.querySelector(".sv-modal-body");
    inputWrap = root.querySelector(".sv-modal-input-wrap");
    inputEl = root.querySelector(".sv-modal-input");
    okBtn = root.querySelector(".sv-modal-ok");
    cancelBtn = root.querySelector(".sv-modal-cancel");

    backdrop.addEventListener("click", () => resolve(null));
    cancelBtn.addEventListener("click", () => resolve(null));
    okBtn.addEventListener("click", () => resolveOk());
    root.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        resolve(null);
      } else if (e.key === "Enter" && document.activeElement !== cancelBtn) {
        e.preventDefault();
        resolveOk();
      }
    });

    // Minimal CSS — keep it self-contained so the rest of the styling
    // sheets don't have to know about this. Mirrors the app's surface
    // colors via CSS variables that already exist in style.css; falls
    // back to sensible defaults if those variables aren't defined yet.
    if (!document.getElementById("sv-modal-style")) {
      const style = document.createElement("style");
      style.id = "sv-modal-style";
      style.textContent = `
#sv-modal { position: fixed; inset: 0; z-index: 9999; display: flex;
  align-items: center; justify-content: center; }
#sv-modal[hidden] { display: none; }
#sv-modal .sv-modal-backdrop { position: absolute; inset: 0;
  background: rgba(0,0,0,0.55); }
#sv-modal .sv-modal-card { position: relative; max-width: 440px;
  width: calc(100% - 2rem); background: var(--surface, #1a1a1a);
  color: var(--text, #eee); border-radius: 12px; padding: 1.25rem;
  box-shadow: 0 12px 40px rgba(0,0,0,0.6); }
#sv-modal .sv-modal-title { margin: 0 0 0.5rem 0; font-size: 1.1rem; }
#sv-modal .sv-modal-body { margin: 0 0 1rem 0; line-height: 1.45;
  white-space: pre-wrap; }
#sv-modal .sv-modal-input-wrap { margin-bottom: 1rem; }
#sv-modal .sv-modal-input { width: 100%; padding: 0.5rem 0.6rem;
  border-radius: 6px; border: 1px solid var(--border, #444);
  background: var(--input-bg, #111); color: inherit;
  font-family: inherit; font-size: 0.95rem; }
#sv-modal .sv-modal-actions { display: flex; gap: 0.5rem;
  justify-content: flex-end; }
#sv-modal .sv-modal-actions button { padding: 0.5rem 0.9rem;
  border-radius: 6px; border: 1px solid var(--border, #444);
  background: var(--button-bg, #2a2a2a); color: inherit;
  cursor: pointer; font: inherit; }
#sv-modal .sv-modal-actions .secondary { background: transparent; }
#sv-modal .sv-modal-actions .sv-modal-ok.danger {
  background: var(--danger, #b03030); border-color: var(--danger, #b03030);
  color: #fff; }
      `;
      document.head.appendChild(style);
    }
  }

  function resolve(value) {
    if (!resolveFn) return;
    const f = resolveFn;
    resolveFn = null;
    root.hidden = true;
    // Restore focus.
    if (lastFocus && typeof lastFocus.focus === "function") {
      try { lastFocus.focus(); } catch {}
    }
    lastFocus = null;
    f(value);
  }

  function resolveOk() {
    if (inputWrap && !inputWrap.hidden) {
      resolve(inputEl.value);
    } else {
      resolve(true);
    }
  }

  function open(opts) {
    ensureRoot();
    const {
      message = "",
      title = "",
      okLabel = "OK",
      cancelLabel = "Cancel",
      danger = false,
      promptDefault = null,
    } = opts || {};
    titleEl.textContent = title || "Confirm";
    titleEl.hidden = !title;
    bodyEl.textContent = message;
    okBtn.textContent = okLabel;
    cancelBtn.textContent = cancelLabel;
    okBtn.classList.toggle("danger", !!danger);
    if (promptDefault !== null) {
      inputWrap.hidden = false;
      inputEl.value = promptDefault;
    } else {
      inputWrap.hidden = true;
      inputEl.value = "";
    }

    lastFocus = document.activeElement;
    root.hidden = false;

    // Focus the input if prompt; otherwise the OK button.
    setTimeout(() => {
      if (!inputWrap.hidden) {
        inputEl.focus();
        inputEl.select();
      } else {
        okBtn.focus();
      }
    }, 0);

    return new Promise((res) => {
      resolveFn = res;
    });
  }

  window.svConfirm = function svConfirm(message, opts) {
    return open({
      message,
      title: opts?.title || "",
      okLabel: opts?.okLabel || "OK",
      cancelLabel: opts?.cancelLabel || "Cancel",
      danger: !!opts?.danger,
    }).then((v) => v === true);
  };

  window.svPrompt = function svPrompt(message, defaultValue, opts) {
    return open({
      message,
      title: opts?.title || "",
      okLabel: opts?.okLabel || "OK",
      cancelLabel: opts?.cancelLabel || "Cancel",
      promptDefault: defaultValue == null ? "" : String(defaultValue),
    }).then((v) => (typeof v === "string" ? v : null));
  };
})();
