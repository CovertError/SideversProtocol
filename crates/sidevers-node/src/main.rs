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

fn read_seed(path: &Path) -> Result<[u8; SECRET_KEY_LEN]> {
    let raw = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if raw.len() != SECRET_KEY_LEN {
        bail!(
            "{} is {} bytes, expected {SECRET_KEY_LEN}",
            path.display(),
            raw.len()
        );
    }
    let mut arr = [0u8; SECRET_KEY_LEN];
    arr.copy_from_slice(&raw);
    Ok(arr)
}
