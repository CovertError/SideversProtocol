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
    document.getElementById("ob-next-2").onclick = async () => {
      // Stage D Layer 1: combine "create your first side" into the
      // data-dir confirmation. Every new install gets a side labeled
      // "personal" automatically — the user can rename or add more
      // sides later from Settings.
      const v = ddInput.value.trim();
      if (!v) return;
      state.dataDir = v;
      showError("ob-side-error", "");
      const label = "personal";
      try {
        const info = await invoke("start_node", {
          dataDir: state.dataDir,
          sideLabel: label,
        });
        state.nodeInfo = info;
        state.sideAddress = info.side_address;
        const finalAddr = document.getElementById("ob-final-address");
        if (finalAddr) finalAddr.value = info.side_address;
        // Pre-fill the backup filename so step 4 opens with a sensible
        // default + the destination preview visible.
        const backupFn = document.getElementById("ob-backup-filename");
        if (backupFn && !backupFn.value) {
          backupFn.value = `${label}-seed.bin`;
          backupFn.dispatchEvent(new Event("input"));
        }
        // Persist last_active_side so the chat shell renders the new
        // side as the active rail avatar on first boot.
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
        showError("ob-side-error", `Couldn't create your personal side: ${e}`);
        // Surface the error visibly even though #ob-side-error is
        // hidden in the new flow — drop it inline above the data-dir
        // input so the user sees it.
        const sink = document.getElementById("ob-side-error");
        if (sink) sink.hidden = false;
      }
    };

    // Backup step (data-screen="4") now reverts to data-screen="2"
    // because the label-picker is gone.
    document.getElementById("ob-back-4").onclick = () => showStep(2);

    // ---- Step 4 live-validation wiring -----------------------------
    // The Save button enables only when filename + passphrase
    // (≥8 chars) + matching confirm are all present. The match
    // indicator updates as the user types so they don't have to
    // submit to find out something's wrong. The destination preview
    // shows the full path the encrypted file will land at.
    const fnEl = document.getElementById("ob-backup-filename");
    const ppEl = document.getElementById("ob-backup-passphrase");
    const cfEl = document.getElementById("ob-backup-passphrase-confirm");
    const saveBtn = document.getElementById("ob-save-seed");
    const matchEl = document.getElementById("ob-backup-match");
    const destEl = document.getElementById("ob-backup-dest");

    function t(key) {
      const i = window.__sv_i18n;
      return i && typeof i.t === "function" ? i.t(key) : key;
    }

    function updateBackupForm() {
      const filename = (fnEl.value || "").trim();
      const pp = ppEl.value || "";
      const cf = cfEl.value || "";

      // Destination preview.
      if (destEl) {
        if (filename) {
          destEl.textContent = `${state.dataDir}/backups/${filename}`;
        } else {
          destEl.textContent = t("onboard.backup.dest_hint");
        }
      }

      // Match indicator. Only shows once the user has typed in confirm.
      if (matchEl) {
        if (!cf) {
          matchEl.textContent = "";
          matchEl.classList.remove("ok", "bad");
        } else if (pp === cf) {
          matchEl.textContent = t("onboard.backup.match_yes");
          matchEl.classList.add("ok");
          matchEl.classList.remove("bad");
        } else {
          matchEl.textContent = t("onboard.backup.match_no");
          matchEl.classList.add("bad");
          matchEl.classList.remove("ok");
        }
      }

      // Enable Save only when everything's valid.
      const valid =
        filename.length > 0 && pp.length >= 8 && pp === cf;
      saveBtn.disabled = !valid;
    }

    fnEl.addEventListener("input", updateBackupForm);
    ppEl.addEventListener("input", updateBackupForm);
    cfEl.addEventListener("input", updateBackupForm);
    // Initialize once on each entry to step 4.
    updateBackupForm();

    document.getElementById("ob-save-seed").onclick = async () => {
      showError("ob-backup-error", "");
      const okEl = document.getElementById("ob-backup-ok");
      if (okEl) okEl.textContent = "";
      const filename = fnEl.value.trim();
      const passphrase = ppEl.value;
      try {
        const written = await invoke("write_seed_backup", {
          dataDir: state.dataDir,
          filename,
          passphrase,
        });
        if (okEl) {
          okEl.textContent = `${t("onboard.backup.saved_at")} ${written}`;
        }
        state.seedBackedUp = true;
        document.getElementById("ob-next-4").disabled = false;
        // Clear the passphrase inputs from memory once they've been
        // consumed; the user can't recover the file without the
        // passphrase they typed, but we don't need to keep it in the
        // input element either.
        ppEl.value = "";
        cfEl.value = "";
        updateBackupForm();
      } catch (e) {
        showError("ob-backup-error", `${t("onboard.backup.write_failed")} ${e}`);
      }
    };
    const skipBtn = document.getElementById("ob-skip-backup");
    if (skipBtn) {
      skipBtn.onclick = async () => {
        const ok = await window.svConfirm(
          t("onboard.backup.skip_confirm") ||
            "Without a recovery file, losing this device means losing this identity (unless you pair another device first). You can back up later from Settings → Backup. Skip for now?",
          { title: "Skip backup?", okLabel: "Skip for now", danger: true },
        );
        if (!ok) return;
        state.seedBackedUp = true;
        const okEl = document.getElementById("ob-backup-ok");
        if (okEl) okEl.textContent = t("onboard.backup.skipped");
        document.getElementById("ob-next-4").disabled = false;
      };
    }
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
