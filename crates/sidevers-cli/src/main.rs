//! Sidevers CLI entry point. Subcommands defined in the `cli` module.

mod cli;

fn main() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(cli::run())
}
