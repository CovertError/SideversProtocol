// Sidevers onboarding wizard — Phase 3.D + Stage C boot orchestrator.
//
// Loads as a plain script (NOT a module) so it can interleave with
// main.js, which is also plain-script. On boot:
//
//   1. Asks the Rust side for the default data dir.
//   2. Asks is_onboarded(default_data_dir). If true → skip the wizard,
//      call auto_start_node to rehydrate persisted sides, then hand
//      off to window.svBoot(nodeInfo, dataDir) which renders the
//      Stage C chat-first shell.
//   3. Otherwise: reveal #onboarding and run the 5-step wizard. On
//      finish, complete_onboarding flips the flag, and the wizard
//      hands off to window.svBoot() using the start_node response.
//
// The wizard step that creates the side calls start_node directly
// (mint-fresh path). Subsequent launches use auto_start_node, which
// loads the persisted side instead of minting a new one.

(function () {
  const tauri = window.__TAURI__;
  if (!tauri) {
    const root = document.getElementById("onboarding");
    if (root) root.hidden = true;
    return;
  }
  const invoke = tauri.core.invoke;

  const state = {
    dataDir: "",
    sideAddress: "",
    seedBackedUp: false,
    nodeInfo: null,
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

  function handoff(nodeInfo, dataDir) {
    root.hidden = true;
    if (typeof window.svBoot === "function") {
      window.svBoot(nodeInfo, dataDir);
    } else {
      // Race: main.js hasn't run yet (shouldn't happen with script
      // order in index.html, but be defensive). Poll briefly.
      let tries = 0;
      const t = setInterval(() => {
        if (typeof window.svBoot === "function") {
          clearInterval(t);
          window.svBoot(nodeInfo, dataDir);
        } else if (++tries > 50) {
          clearInterval(t);
          console.warn("svBoot never appeared");
        }
      }, 30);
    }
  }

  async function boot() {
    let defaultDir = "";
    try {
      defaultDir = await invoke("default_data_dir");
    } catch (e) {
      console.warn("default_data_dir failed:", e);
    }
    state.dataDir = defaultDir;

    let onboarded = false;
    try {
      if (defaultDir) {
        onboarded = await invoke("is_onboarded", { dataDir: defaultDir });
      }
    } catch (e) {
      console.warn("is_onboarded failed:", e);
    }

    if (onboarded) {
      // Returning user — auto-start the node from persisted sides.
      try {
        const nodeInfo = await invoke("auto_start_node", { dataDir: defaultDir });
        handoff(nodeInfo, defaultDir);
      } catch (e) {
        // No persisted sides yet (shouldn't happen if onboarding_completed
        // is set, but be tolerant) → fall back to wizard.
        console.warn("auto_start_node failed; showing wizard:", e);
        revealWizard(defaultDir);
      }
      return;
    }

    revealWizard(defaultDir);
  }

  function revealWizard(defaultDir) {
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
        state.nodeInfo = info;
        state.sideAddress = info.side_address;
        const finalAddr = document.getElementById("ob-final-address");
        if (finalAddr) finalAddr.value = info.side_address;
        const backupFn = document.getElementById("ob-backup-filename");
        if (backupFn && !backupFn.value) {
          backupFn.value = `${label}-seed.bin`;
        }
        // Persist label so the Stage C UI can render it on the avatar.
        try {
          await invoke("set_setting", {
            dataDir: state.dataDir,
            key: "last_active_side",
            value: info.side_address,
          });
        } catch (e) {
          console.warn("set last_active_side failed:", e);
        }
        showStep(4);
      } catch (e) {
        showError("ob-side-error", `Couldn't create side: ${e}`);
      }
    };

    document.getElementById("ob-back-4").onclick = () => showStep(3);
    document.getElementById("ob-save-seed").onclick = async () => {
      showError("ob-backup-error", "");
      const okEl = document.getElementById("ob-backup-ok");
      if (okEl) okEl.textContent = "";
      const filename = document.getElementById("ob-backup-filename").value.trim();
      const passphrase = document.getElementById("ob-backup-passphrase").value;
      const confirm = document.getElementById("ob-backup-passphrase-confirm").value;
      if (!filename) {
        showError("ob-backup-error", "Choose a filename.");
        return;
      }
      if (!passphrase) {
        showError("ob-backup-error", "Set a passphrase to encrypt the backup.");
        return;
      }
      if (passphrase !== confirm) {
        showError("ob-backup-error", "Passphrases do not match.");
        return;
      }
      try {
        const written = await invoke("write_seed_backup", {
          dataDir: state.dataDir,
          filename,
          passphrase,
        });
        if (okEl) okEl.textContent = `Saved (encrypted) to: ${written}`;
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
      handoff(state.nodeInfo, state.dataDir);
    };

    showStep(1);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
