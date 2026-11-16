#![forbid(unsafe_code)]

//! CLI entry point for the Anvil local development orchestrator.

mod args;
mod commands;
mod terminal;

use args::Cli;
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    terminal::install_panic_hook();
    let cli = Cli::parse();
    commands::dispatch(cli).await
}
