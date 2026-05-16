//! Sidevers reference-node daemon. Month 3 of Phase 1.

use std::fs;
use std::net::{Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use sidevers_core::keys::{SECRET_KEY_LEN, SideKey};
use sidevers_net::Node;

#[derive(Parser, Debug)]
#[command(
    name = "sidevers-node",
    version,
    about = "Sidevers reference-node daemon"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run as a listener: accept incoming connections, decrypt DMs, serve
    /// content-addressed objects.
    Listen {
        /// Path to the side seed.
        #[arg(long)]
        side: PathBuf,
        /// UDP port to listen on (0 = OS-assigned).
        #[arg(long, default_value_t = 4242)]
        port: u16,
        /// Directory for the object store and per-node state.
        #[arg(long)]
        data_dir: PathBuf,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .compact()
        .init();
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(cli))
}

async fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Listen {
            side,
            port,
            data_dir,
        } => listen(&side, port, &data_dir).await,
    }
}

async fn listen(side_path: &Path, port: u16, data_dir: &Path) -> Result<()> {
    let seed = read_seed(side_path).context("reading side seed")?;
    let side = SideKey::from_seed(&seed, "(daemon)");
    let listen_addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));

    let node = Node::start(side, listen_addr, data_dir).await?;
    println!("listening on {}", node.listen_addr());
    println!("address: {}", node.address());

    // Ctrl-C to shut down.
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                println!("\nshutting down…");
                node.shutdown().await;
                return Ok(());
            }
            dm_opt = node.next_direct_message() => {
                let Some(dm) = dm_opt else {
                    return Ok(());
                };
                let plain = String::from_utf8_lossy(&dm.plaintext);
                let from = hex::encode(&dm.envelope.from[..8]);
                println!("[dm from {}…]: {}", from, plain);
            }
        }
    }
}

/// Env var the daemon reads when the seed file is in the passphrase-sealed
/// format (Audit P1.1). For interactive use, prefer the Tauri client or
/// `sidevers-cli` and bring the unsealed seed into a tmpfs/ephemeral file.
const ENV_SEED_PASSPHRASE: &str = "SIDEVERS_SEED_PASSPHRASE";

/// Read a seed file, supporting both legacy 32-byte plaintext seeds and
/// the new passphrase-sealed format (`sidevers_core::keystore`). Sealed
/// files require `SIDEVERS_SEED_PASSPHRASE` to be set in the environment.
fn read_seed(path: &Path) -> Result<[u8; SECRET_KEY_LEN]> {
    let raw = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if raw.len() == SECRET_KEY_LEN {
        // Legacy plaintext seed (still supported; warn at startup so
        // operators know they're carrying the higher-exposure variant).
        eprintln!(
            "warning: {} is a plaintext seed file. Consider re-saving it as a passphrase-sealed seed (see sidevers-cli seed-seal).",
            path.display()
        );
        let mut arr = [0u8; SECRET_KEY_LEN];
        arr.copy_from_slice(&raw);
        return Ok(arr);
    }
    // Otherwise treat it as a sealed-seed CBOR file. Pull the passphrase
    // from the env (not the CLI args — keeping it off the process table).
    let passphrase = std::env::var(ENV_SEED_PASSPHRASE).map_err(|_| {
        anyhow::anyhow!(
            "{} is not a plaintext seed (length {}); set {ENV_SEED_PASSPHRASE} to open it",
            path.display(),
            raw.len()
        )
    })?;
    if passphrase.is_empty() {
        bail!("{ENV_SEED_PASSPHRASE} is empty");
    }
    let seed = sidevers_core::keystore::open_seed(&raw, &passphrase)
        .map_err(|e| anyhow::anyhow!("opening sealed seed {}: {e}", path.display()))?;
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn plaintext_seed_still_loads() {
        let seed = [0xAAu8; SECRET_KEY_LEN];
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&seed).unwrap();
        let loaded = read_seed(f.path()).unwrap();
        assert_eq!(loaded, seed);
    }

    #[test]
    fn sealed_seed_loads_with_correct_passphrase() {
        let seed = [0xBBu8; SECRET_KEY_LEN];
        let sealed = sidevers_core::keystore::seal_seed_with(
            &seed,
            "test-pass",
            &sidevers_core::keystore::Argon2Params::fast_for_tests(),
        )
        .unwrap();
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&sealed).unwrap();
        // Safety: tests are single-threaded by default; setting env here is OK
        // for the scope of this test (cleared at the end).
        unsafe {
            std::env::set_var(ENV_SEED_PASSPHRASE, "test-pass");
        }
        let loaded = read_seed(f.path()).unwrap();
        unsafe {
            std::env::remove_var(ENV_SEED_PASSPHRASE);
        }
        assert_eq!(loaded, seed);
    }

    #[test]
    fn sealed_seed_fails_with_wrong_passphrase() {
        let seed = [0xCCu8; SECRET_KEY_LEN];
        let sealed = sidevers_core::keystore::seal_seed_with(
            &seed,
            "right",
            &sidevers_core::keystore::Argon2Params::fast_for_tests(),
        )
        .unwrap();
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&sealed).unwrap();
        unsafe {
            std::env::set_var(ENV_SEED_PASSPHRASE, "wrong");
        }
        let err = read_seed(f.path()).unwrap_err();
        unsafe {
            std::env::remove_var(ENV_SEED_PASSPHRASE);
        }
        let msg = format!("{err:#}");
        assert!(msg.contains("opening sealed seed"), "got: {msg}");
    }

    #[test]
    fn sealed_seed_without_env_var_errors_clearly() {
        let seed = [0xDDu8; SECRET_KEY_LEN];
        let sealed = sidevers_core::keystore::seal_seed_with(
            &seed,
            "p",
            &sidevers_core::keystore::Argon2Params::fast_for_tests(),
        )
        .unwrap();
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&sealed).unwrap();
        unsafe {
            std::env::remove_var(ENV_SEED_PASSPHRASE);
        }
        let err = read_seed(f.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains(ENV_SEED_PASSPHRASE), "got: {msg}");
    }
}
