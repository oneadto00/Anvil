//! Dispatches parsed CLI subcommands to their handlers.

use crate::args::{Cli, Command, GlobalOptions};

#[path = "../runtime_bridge.rs"]
pub mod runtime_bridge;
pub mod down;
pub mod doctor;
pub mod logs;
pub mod ps;
pub mod secret;
pub mod up;

/// Dispatches parsed CLI arguments to the selected subcommand implementation.
pub async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    let globals = GlobalOptions::from(&cli);

    match cli.command {
        Command::Up {
            detach,
            no_tui,
            daemon_child,
        } => up::execute(&globals, detach, no_tui, daemon_child).await,
        Command::Down { grace_ms } => down::execute(globals, grace_ms).await,
        Command::Ps { json } => ps::execute(globals, json).await,
        Command::Logs {
            service,
            follow,
            tail,
        } => logs::execute(globals, service, follow, tail).await,
        Command::Secret { action } => secret::run(&globals, action).await,
        Command::Doctor { reap } => doctor::run(&globals, reap).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[tokio::test]
    async fn dispatch_routes_all_implemented_subcommands() -> anyhow::Result<()> {
        let missing_cfg_cases = [
            vec!["anvil", "-c", "/nonexistent-anvil-config-path/anvil.yaml", "up"],
            vec!["anvil", "-c", "/nonexistent-anvil-config-path/anvil.yaml", "down"],
            vec!["anvil", "-c", "/nonexistent-anvil-config-path/anvil.yaml", "ps"],
            vec!["anvil", "-c", "/nonexistent-anvil-config-path/anvil.yaml", "logs"],
            vec!["anvil", "-c", "/nonexistent-anvil-config-path/anvil.yaml", "secret", "list"],
            vec!["anvil", "-c", "/nonexistent-anvil-config-path/anvil.yaml", "doctor"],
        ];

        for argv in missing_cfg_cases {
            let cli = Cli::try_parse_from(&argv)?;
            let err = dispatch(cli)
                .await
                .err()
                .ok_or_else(|| anyhow::anyhow!("expected error for missing config on {argv:?}"))?;
            assert!(
                !err.to_string().contains("not yet implemented"),
                "subcommand placeholder was not replaced for {argv:?}: {err}"
            );
        }
        Ok(())
    }
}
