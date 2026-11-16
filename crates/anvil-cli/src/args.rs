//! Command-line argument tree for the `anvil` binary.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Anvil local multi-service development orchestrator.
#[derive(Debug, Clone, PartialEq, Eq, Parser)]
#[command(
    name = "anvil",
    version,
    about = "Anvil local multi-service development orchestrator"
)]
pub struct Cli {
    /// Path to the anvil.yaml configuration file.
    #[arg(
        short = 'c',
        long = "config",
        global = true,
        value_name = "PATH",
        default_value = "./anvil.yaml"
    )]
    pub config: PathBuf,

    /// Override the Anvil data directory (defaults to ~/.anvil).
    #[arg(long = "data-dir", global = true, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,

    /// Override the project name defined in anvil.yaml.
    #[arg(short = 'p', long = "project", global = true, value_name = "NAME")]
    pub project: Option<String>,

    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Command,
}

/// Shared global options resolved from top-level CLI flags.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Fields are consumed by Phase 2 subcommand implementations.
pub struct GlobalOptions {
    /// Path to the `anvil.yaml` configuration file.
    pub config: PathBuf,
    /// Optional override for the Anvil data directory (`~/.anvil`).
    pub data_dir: Option<PathBuf>,
    /// Optional override for the project name defined in `anvil.yaml`.
    pub project: Option<String>,
}

impl From<&Cli> for GlobalOptions {
    fn from(cli: &Cli) -> Self {
        Self {
            config: cli.config.clone(),
            data_dir: cli.data_dir.clone(),
            project: cli.project.clone(),
        }
    }
}

/// Top-level `anvil` subcommands.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// Start services defined in anvil.yaml and attach the TUI or run detached.
    Up {
        /// Run orchestration in the background and detach from the terminal.
        #[arg(short, long)]
        detach: bool,
        /// Run in the foreground without attaching the interactive TUI.
        #[arg(long)]
        no_tui: bool,
        /// Internal flag indicating this process was spawned as a detached child.
        #[arg(long, hide = true)]
        daemon_child: bool,
    },

    /// Stop running services and clean up residual process trees.
    Down {
        /// Graceful shutdown timeout in milliseconds before sending SIGKILL.
        #[arg(long, default_value_t = 3000)]
        grace_ms: u64,
    },

    /// Display the current runtime state snapshot for project services.
    Ps {
        /// Output the runtime status snapshot as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Print or follow persisted service logs.
    Logs {
        /// Optional service name filter; prints all services if omitted.
        service: Option<String>,
        /// Follow new log lines as they are appended.
        #[arg(short, long)]
        follow: bool,
        /// Number of trailing lines to show initially.
        #[arg(short = 'n', long, default_value_t = 100)]
        tail: usize,
    },

    /// Manage project secrets in the OS keyring or encrypted fallback vault.
    Secret {
        /// Secret management operation to perform.
        #[command(subcommand)]
        action: SecretCommand,
    },

    /// Inspect runtime dependencies, ports, and orphaned process locks.
    Doctor {
        /// Automatically clean up verified orphaned process trees from stale locks.
        #[arg(long)]
        reap: bool,
    },
}

/// Subcommands under `anvil secret`.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
#[allow(dead_code)] // Fields are consumed by Phase 2 secret subcommand handler.
pub enum SecretCommand {
    /// Store or update a secret value for the specified key.
    Set {
        /// Secret key name (e.g. DB_PASSWORD).
        key: String,
        /// Force using the local encrypted fallback vault instead of the OS keyring.
        #[arg(long)]
        vault: bool,
        /// Read the secret value from standard input without an interactive prompt.
        #[arg(long)]
        stdin: bool,
    },

    /// Retrieve and print the secret value for the specified key.
    Get {
        /// Secret key name.
        key: String,
        /// Force using the local encrypted fallback vault instead of the OS keyring.
        #[arg(long)]
        vault: bool,
    },

    /// List stored secret keys.
    List {
        /// Force using the local encrypted fallback vault instead of the OS keyring.
        #[arg(long)]
        vault: bool,
    },

    /// Delete the stored secret for the specified key.
    Delete {
        /// Secret key name.
        key: String,
        /// Force using the local encrypted fallback vault instead of the OS keyring.
        #[arg(long)]
        vault: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_clap_command_tree() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_global_defaults_and_overrides() {
        let default_cli = Cli::try_parse_from(["anvil", "ps"]).unwrap();
        assert_eq!(default_cli.config, PathBuf::from("./anvil.yaml"));
        assert_eq!(default_cli.data_dir, None);
        assert_eq!(default_cli.project, None);

        let before = Cli::try_parse_from([
            "anvil",
            "-c",
            "infra/anvil.yaml",
            "--data-dir",
            "/tmp/anvil-data",
            "-p",
            "nebula",
            "ps",
        ])
        .unwrap();
        let after = Cli::try_parse_from([
            "anvil",
            "ps",
            "--config",
            "infra/anvil.yaml",
            "--data-dir",
            "/tmp/anvil-data",
            "--project",
            "nebula",
        ])
        .unwrap();

        assert_eq!(before, after);
        assert_eq!(before.config, PathBuf::from("infra/anvil.yaml"));
        assert_eq!(before.data_dir, Some(PathBuf::from("/tmp/anvil-data")));
        assert_eq!(before.project, Some("nebula".to_string()));
    }

    #[test]
    fn parses_up_subcommand() {
        let default_up = Cli::try_parse_from(["anvil", "up"]).unwrap();
        assert_eq!(
            default_up.command,
            Command::Up {
                detach: false,
                no_tui: false,
                daemon_child: false,
            }
        );

        let detached = Cli::try_parse_from(["anvil", "up", "-d"]).unwrap();
        assert_eq!(
            detached.command,
            Command::Up {
                detach: true,
                no_tui: false,
                daemon_child: false,
            }
        );

        let full = Cli::try_parse_from([
            "anvil",
            "up",
            "--detach",
            "--no-tui",
            "--daemon-child",
        ])
        .unwrap();
        assert_eq!(
            full.command,
            Command::Up {
                detach: true,
                no_tui: true,
                daemon_child: true,
            }
        );
    }

    #[test]
    fn parses_down_subcommand() {
        let default_down = Cli::try_parse_from(["anvil", "down"]).unwrap();
        assert_eq!(default_down.command, Command::Down { grace_ms: 3000 });

        let custom_down = Cli::try_parse_from(["anvil", "down", "--grace-ms", "5500"]).unwrap();
        assert_eq!(custom_down.command, Command::Down { grace_ms: 5500 });
    }

    #[test]
    fn parses_ps_subcommand() {
        let default_ps = Cli::try_parse_from(["anvil", "ps"]).unwrap();
        assert_eq!(default_ps.command, Command::Ps { json: false });

        let json_ps = Cli::try_parse_from(["anvil", "ps", "--json"]).unwrap();
        assert_eq!(json_ps.command, Command::Ps { json: true });
    }

    #[test]
    fn parses_logs_subcommand() {
        let default_logs = Cli::try_parse_from(["anvil", "logs"]).unwrap();
        assert_eq!(
            default_logs.command,
            Command::Logs {
                service: None,
                follow: false,
                tail: 100,
            }
        );

        let filtered = Cli::try_parse_from(["anvil", "logs", "api", "-f", "-n", "50"]).unwrap();
        assert_eq!(
            filtered.command,
            Command::Logs {
                service: Some("api".to_string()),
                follow: true,
                tail: 50,
            }
        );

        let long_flags =
            Cli::try_parse_from(["anvil", "logs", "--follow", "--tail", "25"]).unwrap();
        assert_eq!(
            long_flags.command,
            Command::Logs {
                service: None,
                follow: true,
                tail: 25,
            }
        );
    }

    #[test]
    fn parses_secret_subcommands() {
        let set_cmd =
            Cli::try_parse_from(["anvil", "secret", "set", "DB_PASSWORD", "--vault"]).unwrap();
        assert_eq!(
            set_cmd.command,
            Command::Secret {
                action: SecretCommand::Set {
                    key: "DB_PASSWORD".to_string(),
                    vault: true,
                    stdin: false,
                },
            }
        );

        let set_stdin =
            Cli::try_parse_from(["anvil", "secret", "set", "JWT_SECRET", "--stdin"]).unwrap();
        assert_eq!(
            set_stdin.command,
            Command::Secret {
                action: SecretCommand::Set {
                    key: "JWT_SECRET".to_string(),
                    vault: false,
                    stdin: true,
                },
            }
        );

        let get_cmd =
            Cli::try_parse_from(["anvil", "secret", "get", "DB_PASSWORD", "--vault"]).unwrap();
        assert_eq!(
            get_cmd.command,
            Command::Secret {
                action: SecretCommand::Get {
                    key: "DB_PASSWORD".to_string(),
                    vault: true,
                },
            }
        );

        let list_cmd = Cli::try_parse_from(["anvil", "secret", "list"]).unwrap();
        assert_eq!(
            list_cmd.command,
            Command::Secret {
                action: SecretCommand::List { vault: false },
            }
        );

        let delete_cmd =
            Cli::try_parse_from(["anvil", "secret", "delete", "DB_PASSWORD", "--vault"]).unwrap();
        assert_eq!(
            delete_cmd.command,
            Command::Secret {
                action: SecretCommand::Delete {
                    key: "DB_PASSWORD".to_string(),
                    vault: true,
                },
            }
        );
    }

    #[test]
    fn parses_doctor_subcommand() {
        let default_doc = Cli::try_parse_from(["anvil", "doctor"]).unwrap();
        assert_eq!(default_doc.command, Command::Doctor { reap: false });

        let reap_doc = Cli::try_parse_from(["anvil", "doctor", "--reap"]).unwrap();
        assert_eq!(reap_doc.command, Command::Doctor { reap: true });
    }
}
