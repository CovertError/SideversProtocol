// Sidevers onboarding wizard — Phase 3.D.
//
// Loads as a plain script (NOT a module) so it can interleave with
// main.js, which is also plain-script. On boot:
//
//   1. Asks the Rust side for the default data dir.
//   2. Asks `is_onboarded(default_data_dir)`. If true → hides
//      #onboarding entirely; main.js owns the page.
//   3. Otherwise: reveals #onboarding and runs the 5-step flow.
//      Each step's "Next" gates on the previous step's effect (data
//      dir typed, side created via start_node, seed file written).
//
// At the final step, calls `complete_onboarding(data_dir)` to flip
// the durable flag, then hides #onboarding and lets main.js take
// over without a reload — start_node has already been called, so the
// UI is in the same state it'd be in if the user clicked Start.
//
// Strings are i18n-driven via data-i18n attributes; the wizard
// doesn't construct dynamic copy itself.

(function () {
  const tauri = window.__TAURI__;
  if (!tauri) {
    // No Tauri runtime — opening dist/index.html in a browser. Hide
    // the wizard so the rest of the page is at least inspectable.
    const root = document.getElementById("onboarding");
    if (root) root.hidden = true;
    return;
  }
  const invoke = tauri.core.invoke;

  // Internal state: the data dir + side address chosen during the
  // flow. Closed over by all the step handlers.
  const state = {
    dataDir: "",
    sideAddress: "",
    seedBackedUp: false,
  };

  const root = document.getElementById("onboarding");
  if (!root) return;

  function showStep(n) {
    for (const s of root.querySelectorAll(".onboarding-screen")) {
      s.hidden = s.dataset.screen !== String(n);
    }
    for (const li of root.querySelectorAll(".onboarding-step")) {
      const sn = Number(li.dataset.step);
      li.classList.toggle("active", sn === n);
      li.classList.toggle("done", sn < n);
    }
  }

  function showError(id, msg) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = msg || "";
  }

  async function boot() {
    let defaultDir = "";
    try {
      defaultDir = await invoke("default_data_dir");
    } catch (e) {
      console.warn("default_data_dir failed:", e);
    }
    state.dataDir = defaultDir;

    // Check the onboarding flag against the default dir. If the user
    // had a previous install at a non-default path the flag won't be
    // here — they'll be re-onboarded. Acceptable for a Phase-1
    // reference client.
    let onboarded = false;
    try {
      if (defaultDir) {
        onboarded = await invoke("is_onboarded", { dataDir: defaultDir });
      }
    } catch (e) {
      console.warn("is_onboarded failed:", e);
    }
    if (onboarded) {
      root.hidden = true;
      return;
    }

    // Show the wizard. Wire each step.
    root.hidden = false;
    const ddInput = document.getElementById("ob-data-dir");
    if (ddInput) ddInput.value = defaultDir;

    document.getElementById("ob-next-1").onclick = () => showStep(2);

    document.getElementById("ob-back-2").onclick = () => showStep(1);
    document.getElementById("ob-next-2").onclick = () => {
      const v = ddInput.value.trim();
      if (!v) return;
      state.dataDir = v;
      showStep(3);
    };

    document.getElementById("ob-back-3").onclick = () => showStep(2);
    document.getElementById("ob-next-3").onclick = async () => {
      showError("ob-side-error", "");
      const label =
        document.getElementById("ob-side-label").value.trim() || "work";
      try {
        const info = await invoke("start_node", {
          dataDir: state.dataDir,
          sideLabel: label,
        });
        state.sideAddress = info.side_address;
        const finalAddr = document.getElementById("ob-final-address");
        if (finalAddr) finalAddr.value = info.side_address;
        // Pre-fill a default backup path so the user can hit save quickly.
        const backup = document.getElementById("ob-backup-path");
        if (backup && !backup.value) {
          backup.value = `${state.dataDir}/${label}.seed`;
        }
        showStep(4);
      } catch (e) {
        showError("ob-side-error", `Couldn't create side: ${e}`);
      }
    };

    document.getElementById("ob-back-4").onclick = () => showStep(3);
    document.getElementById("ob-save-seed").onclick = async () => {
      showError("ob-backup-error", "");
      const out = document.getElementById("ob-backup-path").value.trim();
      if (!out) {
        showError("ob-backup-error", "Pick a path first.");
        return;
      }
      try {
        await invoke("write_seed_backup", { outPath: out });
        state.seedBackedUp = true;
        document.getElementById("ob-next-4").disabled = false;
      } catch (e) {
        showError("ob-backup-error", `Couldn't write seed: ${e}`);
      }
    };
    document.getElementById("ob-next-4").onclick = () => {
      if (!state.seedBackedUp) return;
      showStep(5);
    };

    document.getElementById("ob-finish").onclick = async () => {
      try {
        await invoke("complete_onboarding", { dataDir: state.dataDir });
      } catch (e) {
        console.warn("complete_onboarding failed:", e);
      }
      root.hidden = true;
      // Pre-fill main UI's data-dir input + propagate the "node is
      // started" state. start_node was already called during step 3
      // so the main UI's buttons need to reflect that without the
      // user re-clicking Start.
      const mainDd = document.getElementById("data-dir");
      if (mainDd) mainDd.value = state.dataDir;
      const mainSl = document.getElementById("side-label");
      if (mainSl) mainSl.value = "work";
      const setDisabled = (id, v) => {
        const el = document.getElementById(id);
        if (el) el.disabled = v;
      };
      setDisabled("start-node", true);
      for (const id of [
        "stop-node",
        "connect-peer",
        "gen-qr",
        "accept-qr",
        "refresh-sides",
        "add-side",
      ]) {
        setDisabled(id, false);
      }
      // Update status indicator.
      const dot = document.getElementById("status-dot");
      if (dot) {
        dot.classList.add("dot-running");
        dot.classList.remove("dot-idle");
      }
      const statusText = document.getElementById("status-text");
      if (statusText) statusText.textContent = "Node up";
      // Refresh sides list so the new side appears.
      const btn = document.getElementById("refresh-sides");
      if (btn) btn.click();
    };

    showStep(1);
  }

  // Wait for the document to be ready before wiring anything.
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
