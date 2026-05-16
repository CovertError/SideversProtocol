//! CLI subcommand wiring (Phase 1 months 2–3).
//!
//! The on-disk format for keys is intentionally trivial: a 32-byte seed,
//! written raw. The on-disk format for envelopes and linkage proofs is the
//! canonical CBOR wire encoding — the same bytes a node would send. This
//! is so envelopes produced by `sidevers envelope sign` are bit-for-bit
//! comparable to envelopes produced by any other conforming implementation.
//!
//! Month-3 additions (`node ping`, `dm send`, `store put`, `store get`) spin
//! up transient ephemeral `Node` instances for one-shot network operations,
//! then shut down.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use sidevers_core::envelope::now_unix_seconds;
use sidevers_core::keys::{PUBLIC_KEY_LEN, SECRET_KEY_LEN};
use sidevers_core::linkage::LinkageProof;
use sidevers_core::messages::direct::{DirectBody, DirectKind, DirectMessagePayload};
use sidevers_core::payload as core_payload;
use sidevers_core::{Address, AddressKind, Envelope, MasterKey, MessageType, SideKey};
use sidevers_net::{Intent, Node, SideStore, StoredSide, fetch_object, send_dm};
use sidevers_storage::ObjectStore;

#[derive(Parser, Debug)]
#[command(name = "sidevers", version, about = "Sidevers CLI (Phase 1 month 2)")]
pub(crate) struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Key generation: master and side keys.
    #[command(subcommand)]
    Keygen(KeygenCmd),
    /// Show the bech32m address for a key.
    Addr(AddrArgs),
    /// Envelope: sign, verify, decode.
    #[command(subcommand)]
    Envelope(EnvelopeCmd),
    /// Linkage proofs: sign and verify.
    #[command(subcommand)]
    Linkage(LinkageCmd),
    /// Send a DirectMessage to a peer over the network.
    #[command(subcommand)]
    Dm(DmCmd),
    /// Content-addressed object storage (local put + remote get).
    #[command(subcommand)]
    Store(StoreCmd),
    /// Open + handshake against a peer, then close.
    Ping(PingArgs),
    /// Phase 3.I: multi-side management against a persistent data dir.
    #[command(subcommand)]
    Side(SideCmd),
}

#[derive(Subcommand, Debug)]
enum SideCmd {
    /// Mint a fresh side keypair, persist it in `<data_dir>/sides.db`,
    /// and print its bech32m address.
    Add {
        /// Data directory containing (or to contain) `sides.db`.
        #[arg(long)]
        data_dir: PathBuf,
        /// Label for the new side (e.g. "work", "private").
        #[arg(long)]
        label: String,
    },
    /// List every side persisted in `<data_dir>/sides.db`, with label
    /// + bech32m address + lifecycle.
    List {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Retire a side: signs + records a `SideRetirement` for the named
    /// side. Once retired the lifecycle flips to `Retired` and future
    /// peers SHOULD treat new envelopes from this side as anomalous.
    Retire {
        #[arg(long)]
        data_dir: PathBuf,
        /// Path to the side's 32-byte seed.
        #[arg(long)]
        side: PathBuf,
        /// Optional human-readable reason recorded in the retirement record.
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum DmCmd {
    /// Send a plain-text DirectMessage to a peer.
    Send {
        #[arg(long)]
        side: PathBuf,
        /// Recipient's bech32m address (sv1q…).
        #[arg(long)]
        to: String,
        /// Peer's network endpoint, e.g. 127.0.0.1:4242.
        #[arg(long)]
        host: String,
        #[arg(long)]
        text: String,
    },
}

#[derive(Subcommand, Debug)]
enum StoreCmd {
    /// Ingest a file into the local object store; print the BLAKE3 address.
    Put {
        /// Side seed (for any future authn; not strictly required for local put).
        #[arg(long)]
        side: PathBuf,
        #[arg(long)]
        data_dir: PathBuf,
        file: PathBuf,
    },
    /// Fetch an object from a peer over the network; verify and write to disk.
    Get {
        #[arg(long)]
        side: PathBuf,
        #[arg(long)]
        host: String,
        /// 64-character hex BLAKE3 address.
        #[arg(long)]
        hash: String,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Parser, Debug)]
struct PingArgs {
    #[arg(long)]
    side: PathBuf,
    #[arg(long)]
    host: String,
}

#[derive(Subcommand, Debug)]
enum KeygenCmd {
    /// Generate a fresh master key (Ed25519 seed) and write it to `--out`.
    Master {
        /// Path to write the 32-byte master seed.
        #[arg(long)]
        out: PathBuf,
    },
    /// Derive a side from a master under the given label, write seed to `--out`.
    Side {
        /// Path to the master seed.
        #[arg(long)]
        master: PathBuf,
        /// Side label (e.g. "private", "work", "close", "public").
        #[arg(long)]
        label: String,
        /// Path to write the 32-byte side seed.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Parser, Debug)]
struct AddrArgs {
    /// Address kind: "side" or "verse" (default "side").
    #[arg(long, default_value = "side")]
    kind: String,
    /// Read a side seed and use its public key.
    #[arg(
        long,
        conflicts_with = "pubkey_hex",
        required_unless_present = "pubkey_hex"
    )]
    seed: Option<PathBuf>,
    /// Or supply the 32-byte public key as hex.
    #[arg(long = "pubkey")]
    pubkey_hex: Option<String>,
}

#[derive(Subcommand, Debug)]
enum EnvelopeCmd {
    /// Sign a new envelope.
    Sign(EnvelopeSignArgs),
    /// Verify and report on an envelope file.
    Verify {
        /// Path to the envelope bytes.
        file: PathBuf,
    },
    /// Decode and pretty-print an envelope file. Includes payload decryption
    /// if `--side` is provided and the envelope is unicast to that side.
    Decode {
        file: PathBuf,
        /// Optional: a side seed to decrypt the payload.
        #[arg(long)]
        side: Option<PathBuf>,
    },
}

#[derive(Parser, Debug)]
struct EnvelopeSignArgs {
    /// The signing side's seed.
    #[arg(long)]
    side: PathBuf,
    /// Recipient address (bech32m). Omit for broadcast.
    #[arg(long)]
    to: Option<String>,
    /// Plain-text body for a DirectMessage; conflicts with --payload-file.
    #[arg(long, conflicts_with_all = ["payload_file", "message_type"])]
    text: Option<String>,
    /// Pre-encoded payload bytes (raw file). Use with --message-type.
    #[arg(long = "payload-file", requires = "message_type")]
    payload_file: Option<PathBuf>,
    /// Message type as 0xNN. Required when --payload-file is used.
    #[arg(long = "message-type", value_parser = parse_message_type)]
    message_type: Option<u8>,
    /// Output path for the signed envelope bytes.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Subcommand, Debug)]
enum LinkageCmd {
    /// Sign a linkage proof between two sides you own.
    Sign {
        #[arg(long = "side-a")]
        side_a: PathBuf,
        #[arg(long = "side-b")]
        side_b: PathBuf,
        /// Unix-seconds timestamp; defaults to now.
        #[arg(long)]
        issued_at: Option<u64>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a linkage proof file.
    Verify { file: PathBuf },
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Keygen(KeygenCmd::Master { out }) => keygen_master(&out),
        Command::Keygen(KeygenCmd::Side { master, label, out }) => {
            keygen_side(&master, &label, &out)
        }
        Command::Addr(args) => addr_show(args),
        Command::Envelope(EnvelopeCmd::Sign(args)) => envelope_sign(args),
        Command::Envelope(EnvelopeCmd::Verify { file }) => envelope_verify(&file),
        Command::Envelope(EnvelopeCmd::Decode { file, side }) => {
            envelope_decode(&file, side.as_deref())
        }
        Command::Linkage(LinkageCmd::Sign {
            side_a,
            side_b,
            issued_at,
            out,
        }) => linkage_sign(&side_a, &side_b, issued_at, &out),
        Command::Linkage(LinkageCmd::Verify { file }) => linkage_verify(&file),
        Command::Dm(DmCmd::Send {
            side,
            to,
            host,
            text,
        }) => dm_send(&side, &to, &host, &text).await,
        Command::Store(StoreCmd::Put {
            side,
            data_dir,
            file,
        }) => store_put(&side, &data_dir, &file).await,
        Command::Store(StoreCmd::Get {
            side,
            host,
            hash,
            out,
        }) => store_get(&side, &host, &hash, &out).await,
        Command::Ping(args) => node_ping(&args.side, &args.host).await,
        Command::Side(SideCmd::Add { data_dir, label }) => side_add(&data_dir, &label).await,
        Command::Side(SideCmd::List { data_dir }) => side_list(&data_dir).await,
        Command::Side(SideCmd::Retire {
            data_dir,
            side,
            reason,
        }) => side_retire(&data_dir, &side, reason).await,
    }
}

// ============================================================================
// side subcommands (Phase 3.I)
// ============================================================================

async fn side_add(data_dir: &Path, label: &str) -> Result<()> {
    tokio::fs::create_dir_all(data_dir)
        .await
        .with_context(|| format!("creating {}", data_dir.display()))?;
    let store = SideStore::open(data_dir).await?;
    let master = MasterKey::generate().context("generating master key")?;
    let side = master
        .derive_side(&label.into())
        .with_context(|| format!("deriving side for label {label:?}"))?;
    let address = side.public_bytes();
    let now = now_unix_seconds().context("clock")?;
    let stored = StoredSide {
        address,
        seed: side.to_seed(),
        label: Some(label.to_owned()),
        created_at: now,
        lifecycle: "Created".to_owned(),
        last_send_at: None,
        is_self_retired: false,
    };
    store.upsert_side(&stored).await?;
    println!("{}", Address::new(AddressKind::Side, address).encode());
    eprintln!(
        "added side {label:?} → {} (lifecycle Created)",
        hex::encode(address)
    );
    Ok(())
}

async fn side_list(data_dir: &Path) -> Result<()> {
    let store = SideStore::open(data_dir).await?;
    let sides = store.list_sides().await?;
    if sides.is_empty() {
        eprintln!("no sides hosted in {}", data_dir.display());
        return Ok(());
    }
    println!("LABEL\tADDRESS\tLIFECYCLE\tRETIRED");
    for s in sides {
        println!(
            "{}\t{}\t{}\t{}",
            s.label.as_deref().unwrap_or("(none)"),
            Address::new(AddressKind::Side, s.address).encode(),
            s.lifecycle,
            if s.is_self_retired { "yes" } else { "no" },
        );
    }
    Ok(())
}

async fn side_retire(data_dir: &Path, side_path: &Path, reason: Option<String>) -> Result<()> {
    let seed = read_seed(side_path)?;
    let side = SideKey::from_seed(&seed, "(cli-retire)");
    let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let node = Node::start(side, listen, data_dir).await?;
    let record = node.publish_retirement(reason).await?;
    node.shutdown().await;
    eprintln!(
        "retired side {} at {} ({})",
        Address::new(AddressKind::Side, record.side),
        record.retired_at,
        record.reason.as_deref().unwrap_or("(no reason)"),
    );
    Ok(())
}

// ============================================================================
// network subcommands (Month 3)
// ============================================================================

async fn dm_send(side_path: &Path, to_addr: &str, host: &str, text: &str) -> Result<()> {
    let seed = read_seed(side_path)?;
    let side = SideKey::from_seed(&seed, "(cli)");
    let to = Address::parse(to_addr).map_err(|e| anyhow!("--to: {e}"))?;
    if to.kind() != AddressKind::Side {
        bail!("--to must be a side address");
    }
    let peer_addr = resolve_host(host)?;

    let node = transient_node(side).await?;
    let session = node.dial(peer_addr, Intent::Direct).await?;
    send_dm(&session, node.side(), text.as_bytes()).await?;
    eprintln!("sent {} bytes to {}", text.len(), to_addr);
    drop(session);
    node.shutdown().await;
    Ok(())
}

async fn store_put(side_path: &Path, data_dir: &Path, file: &Path) -> Result<()> {
    let _seed = read_seed(side_path)?; // sanity-check the side exists
    let bytes = tokio::fs::read(file)
        .await
        .with_context(|| format!("reading {}", file.display()))?;
    let store = ObjectStore::open(data_dir).await?;
    let hash = store.put(bytes).await?;
    println!("{}", hex::encode(hash));
    Ok(())
}

async fn store_get(side_path: &Path, host: &str, hash_hex: &str, out: &Path) -> Result<()> {
    let seed = read_seed(side_path)?;
    let side = SideKey::from_seed(&seed, "(cli)");
    let hash_bytes = hex::decode(hash_hex).context("--hash must be hex")?;
    if hash_bytes.len() != 32 {
        bail!("--hash must be 32 bytes (64 hex chars)");
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash_bytes);
    let peer_addr = resolve_host(host)?;

    let node = transient_node(side).await?;
    let session = node.dial(peer_addr, Intent::Storage).await?;
    let bytes = fetch_object(&session, node.side(), &hash).await?;
    drop(session);
    node.shutdown().await;

    match bytes {
        Some(b) => {
            tokio::fs::write(out, &b)
                .await
                .with_context(|| format!("writing {}", out.display()))?;
            eprintln!("got {} bytes; hash verified", b.len());
            Ok(())
        }
        None => bail!("peer reported StorageMiss for that hash"),
    }
}

async fn node_ping(side_path: &Path, host: &str) -> Result<()> {
    let seed = read_seed(side_path)?;
    let side = SideKey::from_seed(&seed, "(cli)");
    let peer_addr = resolve_host(host)?;
    let node = transient_node(side).await?;
    let session = node.dial(peer_addr, Intent::Direct).await?;
    println!(
        "handshake OK; peer side: {}",
        Address::new(AddressKind::Side, session.peer_side)
    );
    drop(session);
    node.shutdown().await;
    Ok(())
}

async fn transient_node(side: SideKey) -> Result<Node> {
    // Ephemeral local port + temp data dir; the transient node is just here
    // to drive one outgoing operation.
    let tmp = tempfile::tempdir().context("creating temp dir")?;
    let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let node = Node::start(side, listen, tmp.path()).await?;
    // Leak the TempDir so its destructor doesn't run until process exit;
    // the temp dir backs the transient node's object store, which we don't
    // need to keep beyond this CLI invocation anyway.
    std::mem::forget(tmp);
    Ok(node)
}

fn resolve_host(host: &str) -> Result<SocketAddr> {
    host.to_socket_addrs()
        .with_context(|| format!("resolving {host}"))?
        .next()
        .ok_or_else(|| anyhow!("no address found for {host}"))
}

// ============================================================================
// keygen
// ============================================================================

fn keygen_master(out: &Path) -> Result<()> {
    let master = MasterKey::generate().context("generating master key")?;
    let seed = master.to_seed();
    write_secret(out, &seed)?;
    let addr = Address::from_public_key(AddressKind::Side, &master.public()).encode();
    eprintln!("wrote master seed to {}", out.display());
    eprintln!("master public address (note: master is not used on wire):");
    println!("{addr}");
    Ok(())
}

fn keygen_side(master_path: &Path, label: &str, out: &Path) -> Result<()> {
    let seed = read_seed(master_path).context("reading master seed")?;
    let master = MasterKey::from_seed(&seed);
    let side = master.derive_side(&label.into())?;
    let side_seed = side.to_seed();
    write_secret(out, &side_seed)?;
    let addr = Address::from_public_key(AddressKind::Side, &side.public()).encode();
    eprintln!("derived side '{label}' to {}", out.display());
    println!("{addr}");
    Ok(())
}

// ============================================================================
// addr
// ============================================================================

fn addr_show(args: AddrArgs) -> Result<()> {
    let kind = match args.kind.as_str() {
        "side" => AddressKind::Side,
        "verse" => AddressKind::Verse,
        other => bail!("unknown address kind: {other}"),
    };
    let key_bytes: [u8; PUBLIC_KEY_LEN] = if let Some(seed_path) = args.seed {
        let seed = read_seed(&seed_path)?;
        let side = SideKey::from_seed(&seed, "(cli)");
        side.public_bytes()
    } else if let Some(hex_str) = args.pubkey_hex {
        let raw = hex::decode(hex_str).context("decoding --pubkey hex")?;
        if raw.len() != PUBLIC_KEY_LEN {
            bail!(
                "expected {PUBLIC_KEY_LEN}-byte public key, got {} bytes",
                raw.len()
            );
        }
        let mut arr = [0u8; PUBLIC_KEY_LEN];
        arr.copy_from_slice(&raw);
        arr
    } else {
        unreachable!("clap enforces one of --seed / --pubkey")
    };
    println!("{}", Address::new(kind, key_bytes).encode());
    Ok(())
}

// ============================================================================
// envelope
// ============================================================================

fn envelope_sign(args: EnvelopeSignArgs) -> Result<()> {
    let seed = read_seed(&args.side)?;
    let side = SideKey::from_seed(&seed, "(cli)");

    let recipient: Option<[u8; PUBLIC_KEY_LEN]> = match args.to {
        Some(s) => {
            let addr = Address::parse(&s).map_err(|e| anyhow!("--to: {e}"))?;
            if addr.kind() != AddressKind::Side {
                bail!(
                    "--to must be a side address (sv1q…), got kind {:?}",
                    addr.kind()
                );
            }
            Some(*addr.key_bytes())
        }
        None => None,
    };

    // Figure out message type + payload bytes.
    let (mt, payload_bytes_plain) = if let Some(text) = args.text {
        // Convenience path: text DirectMessage.
        let p = DirectMessagePayload {
            kind: DirectKind::Text,
            body: DirectBody::Text(text),
            reply_to: None,
            thread: None,
        };
        (MessageType::DIRECT_MESSAGE, p.encode())
    } else {
        let mt_byte = args
            .message_type
            .ok_or_else(|| anyhow!("either --text or --message-type must be supplied"))?;
        let payload_file = args
            .payload_file
            .ok_or_else(|| anyhow!("--message-type requires --payload-file"))?;
        let bytes = fs::read(&payload_file)
            .with_context(|| format!("reading payload file {}", payload_file.display()))?;
        (MessageType(mt_byte), bytes)
    };

    // Encrypt for unicast; leave plain for broadcast (spec §3.4). The
    // envelope nonce we use for signing is the same nonce HKDF-salts the
    // AEAD key — so the recipient derives the same key on decrypt.
    let envelope_nonce = sidevers_core::envelope::random_nonce()?;
    let ts = now_unix_seconds()?;
    let payload_for_wire = if let Some(to_bytes) = recipient.as_ref() {
        core_payload::seal(&payload_bytes_plain, &side, to_bytes, &envelope_nonce, b"")
            .map_err(|e| anyhow!("payload seal failed: {e}"))?
    } else {
        payload_bytes_plain
    };
    let env = Envelope::sign_with(mt, &side, recipient, payload_for_wire, ts, envelope_nonce)
        .map_err(|e| anyhow!("envelope sign failed: {e}"))?;

    fs::write(&args.out, env.to_wire_bytes())
        .with_context(|| format!("writing envelope to {}", args.out.display()))?;
    eprintln!(
        "wrote {} byte envelope (type 0x{:02X}{}) to {}",
        env.to_wire_bytes().len(),
        env.message_type.0,
        if recipient.is_some() {
            " unicast, encrypted"
        } else {
            " broadcast, plaintext"
        },
        args.out.display()
    );
    Ok(())
}

fn envelope_verify(file: &Path) -> Result<()> {
    let bytes =
        fs::read(file).with_context(|| format!("reading envelope from {}", file.display()))?;
    let env = Envelope::from_wire_bytes(&bytes).map_err(|e| anyhow!("verify failed: {e}"))?;
    let now = now_unix_seconds()?;
    let fresh = env
        .check_freshness(now, sidevers_core::envelope::DEFAULT_MAX_SKEW_SECS)
        .is_ok();
    println!("OK  envelope verified");
    println!("    type:      0x{:02X}", env.message_type.0);
    println!(
        "    from:      {}",
        Address::new(AddressKind::Side, env.from).encode()
    );
    if let Some(to) = env.to {
        println!(
            "    to:        {}",
            Address::new(AddressKind::Side, to).encode()
        );
    } else {
        println!("    to:        (broadcast)");
    }
    println!(
        "    timestamp: {} ({})",
        env.timestamp,
        if fresh { "fresh" } else { "STALE/SKEWED" }
    );
    println!("    payload:   {} bytes", env.payload.len());
    Ok(())
}

fn envelope_decode(file: &Path, side_path: Option<&Path>) -> Result<()> {
    let bytes =
        fs::read(file).with_context(|| format!("reading envelope from {}", file.display()))?;
    let env = Envelope::from_wire_bytes(&bytes).map_err(|e| anyhow!("verify failed: {e}"))?;
    println!("envelope (verified):");
    println!("  v:    {}", env.version);
    println!("  t:    0x{:02X}", env.message_type.0);
    println!(
        "  from: {}",
        Address::new(AddressKind::Side, env.from).encode()
    );
    match env.to {
        Some(to) => println!("  to:   {}", Address::new(AddressKind::Side, to).encode()),
        None => println!("  to:   (broadcast)"),
    }
    println!("  ts:   {}", env.timestamp);
    println!("  nonce:{}", hex::encode(env.nonce));
    println!("  sig:  {}", hex::encode(env.sig));
    println!("  payload ({} bytes):", env.payload.len());

    match (side_path, env.to) {
        (Some(sp), Some(to_bytes)) => {
            let seed = read_seed(sp)?;
            let side = SideKey::from_seed(&seed, "(cli)");
            if side.public_bytes() != to_bytes {
                println!("    (provided side is not the recipient; cannot decrypt)");
            } else {
                let plain = core_payload::open(&env.payload, &side, &env.from, &env.nonce, b"")
                    .map_err(|e| anyhow!("decrypt failed: {e}"))?;
                println!("    decrypted ({} bytes):", plain.len());
                try_pretty_direct_message(&plain);
            }
        }
        (Some(_), None) => {
            println!("    (broadcast payload, no decryption needed; raw bytes below)");
            print_payload_attempt(&env);
        }
        (None, None) => print_payload_attempt(&env),
        (None, Some(_)) => println!("    (unicast/encrypted; supply --side to decrypt)"),
    }

    Ok(())
}

fn print_payload_attempt(env: &Envelope) {
    if env.message_type == MessageType::DIRECT_MESSAGE {
        try_pretty_direct_message(&env.payload);
    } else {
        println!("    {}", hex::encode(&env.payload));
    }
}

fn try_pretty_direct_message(bytes: &[u8]) {
    match DirectMessagePayload::decode(bytes) {
        Ok(p) => {
            println!("    DirectMessage:");
            println!("      kind: {}", p.kind.as_str());
            match &p.body {
                DirectBody::Text(s) => println!("      body: {s:?}"),
                DirectBody::ReferenceBytes(_) => {
                    println!("      body: (Reference - decode in Month 3)")
                }
            }
            if let Some(rt) = p.reply_to {
                println!("      reply_to: {}", hex::encode(rt));
            }
            if let Some(t) = p.thread {
                println!("      thread:   {}", hex::encode(t));
            }
        }
        Err(_) => println!(
            "    (not a DirectMessage payload; raw hex follows)\n    {}",
            hex::encode(bytes)
        ),
    }
}

// ============================================================================
// linkage
// ============================================================================

fn linkage_sign(side_a: &Path, side_b: &Path, issued_at: Option<u64>, out: &Path) -> Result<()> {
    let seed_a = read_seed(side_a)?;
    let seed_b = read_seed(side_b)?;
    let a = SideKey::from_seed(&seed_a, "(cli a)");
    let b = SideKey::from_seed(&seed_b, "(cli b)");
    let ts = match issued_at {
        Some(t) => t,
        None => now_unix_seconds()?,
    };
    let proof = LinkageProof::sign(&a, &b, ts).map_err(|e| anyhow!("linkage sign: {e}"))?;
    fs::write(out, proof.to_wire_bytes())
        .with_context(|| format!("writing linkage proof to {}", out.display()))?;
    eprintln!("wrote linkage proof to {}", out.display());
    println!(
        "side_a: {}",
        Address::new(AddressKind::Side, proof.side_a).encode()
    );
    println!(
        "side_b: {}",
        Address::new(AddressKind::Side, proof.side_b).encode()
    );
    Ok(())
}

fn linkage_verify(file: &Path) -> Result<()> {
    let bytes =
        fs::read(file).with_context(|| format!("reading linkage proof from {}", file.display()))?;
    let proof = LinkageProof::from_wire_bytes(&bytes).map_err(|e| anyhow!("verify failed: {e}"))?;
    println!("OK  linkage proof verified");
    println!(
        "    side_a:    {}",
        Address::new(AddressKind::Side, proof.side_a).encode()
    );
    println!(
        "    side_b:    {}",
        Address::new(AddressKind::Side, proof.side_b).encode()
    );
    println!("    issued_at: {}", proof.issued_at);
    Ok(())
}

// ============================================================================
// helpers
// ============================================================================

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

fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    set_owner_read_write_only(path).ok();
    Ok(())
}

#[cfg(unix)]
fn set_owner_read_write_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(path)?;
    let mut perms = meta.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn set_owner_read_write_only(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn parse_message_type(s: &str) -> std::result::Result<u8, String> {
    let s = s.trim();
    let parsed = if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u8::from_str_radix(rest, 16)
    } else {
        s.parse::<u8>()
    };
    parsed.map_err(|e| format!("expected message type as 0xNN or NN, got {s}: {e}"))
}
