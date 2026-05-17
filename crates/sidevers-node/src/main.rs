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

/// Top-level seed reader: pulls the passphrase from the env when needed.
fn read_seed(path: &Path) -> Result<[u8; SECRET_KEY_LEN]> {
    let raw = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let passphrase = std::env::var(ENV_SEED_PASSPHRASE).ok();
    parse_seed_bytes(&raw, passphrase.as_deref(), path)
}

/// Pure seed parser, exposed so tests can avoid global env-var manipulation.
///
/// Supports both legacy 32-byte plaintext seeds (back-compat for existing
/// deployments) and the new `sidevers_core::keystore` passphrase-sealed
/// CBOR format. For sealed files, `passphrase` must be `Some(non-empty)`.
fn parse_seed_bytes(
    raw: &[u8],
    passphrase: Option<&str>,
    path_for_msgs: &Path,
) -> Result<[u8; SECRET_KEY_LEN]> {
    if raw.len() == SECRET_KEY_LEN {
        // Legacy plaintext seed. Still supported, but warn at startup so
        // operators know they're carrying the higher-exposure variant.
        eprintln!(
            "warning: {} is a plaintext seed file. Consider re-saving it as a passphrase-sealed seed.",
            path_for_msgs.display()
        );
        let mut arr = [0u8; SECRET_KEY_LEN];
        arr.copy_from_slice(raw);
        return Ok(arr);
    }
    let pw = passphrase.ok_or_else(|| {
        anyhow::anyhow!(
            "{} is not a plaintext seed (length {}); set {ENV_SEED_PASSPHRASE} to open it",
            path_for_msgs.display(),
            raw.len()
        )
    })?;
    if pw.is_empty() {
        bail!("{ENV_SEED_PASSPHRASE} is empty");
    }
    let seed = sidevers_core::keystore::open_seed(raw, pw)
        .map_err(|e| anyhow::anyhow!("opening sealed seed {}: {e}", path_for_msgs.display()))?;
    Ok(seed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::Path;

    fn dummy_path() -> &'static Path {
        Path::new("/dev/null/sv-test-seed")
    }

    #[test]
    fn plaintext_seed_still_loads() {
        let seed = [0xAAu8; SECRET_KEY_LEN];
        let loaded = parse_seed_bytes(&seed, None, dummy_path()).unwrap();
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
        let loaded = parse_seed_bytes(&sealed, Some("test-pass"), dummy_path()).unwrap();
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
        let err = parse_seed_bytes(&sealed, Some("wrong"), dummy_path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("opening sealed seed"), "got: {msg}");
    }

    #[test]
    fn sealed_seed_without_passphrase_errors_clearly() {
        let seed = [0xDDu8; SECRET_KEY_LEN];
        let sealed = sidevers_core::keystore::seal_seed_with(
            &seed,
            "p",
            &sidevers_core::keystore::Argon2Params::fast_for_tests(),
        )
        .unwrap();
        let err = parse_seed_bytes(&sealed, None, dummy_path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains(ENV_SEED_PASSPHRASE), "got: {msg}");
    }

    #[test]
    fn empty_passphrase_for_sealed_seed_errors_clearly() {
        let seed = [0xEEu8; SECRET_KEY_LEN];
        let sealed = sidevers_core::keystore::seal_seed_with(
            &seed,
            "p",
            &sidevers_core::keystore::Argon2Params::fast_for_tests(),
        )
        .unwrap();
        let err = parse_seed_bytes(&sealed, Some(""), dummy_path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("is empty"), "got: {msg}");
    }
}
