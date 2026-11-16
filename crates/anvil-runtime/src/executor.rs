//! Common lifecycle interface for native and container services.

use anvil_core::{RuntimeIdentity, ServiceConfig};
use chrono::{DateTime, Local};
use std::{collections::HashMap, time::Duration};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

/// Origin of a service log record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamSource {
    /// Child standard output.
    Stdout,
    /// Child standard error.
    Stderr,
    /// Executor-generated message.
    System,
}

/// A single timestamped output line from a service.
#[derive(Clone, Debug)]
pub struct RawLogLine {
    /// Service identifier from the workspace configuration.
    pub service_id: String,
    /// Stream that produced the line.
    pub source: StreamSource,
    /// Line content without the trailing newline.
    pub content: String,
    /// Local time when the executor read the line.
    pub timestamp: DateTime<Local>,
}

/// Terminal event for a single service instance.
#[derive(Debug, PartialEq, Eq)]
pub enum ExitStatusEvent {
    /// A host process exited.
    Exited {
        code: Option<i32>,
        signal: Option<i32>,
    },
    /// The container engine reported a die event.
    DockerDie {
        container_id: String,
        exit_code: i64,
        oom_killed: bool,
    },
}

/// Starts, monitors, and stops instances managed by a runtime backend.
#[async_trait::async_trait]
pub trait RuntimeExecutor: Send + Sync {
    /// Starts a service with its resolved environment and returns its identity and exit receiver.
    async fn spawn(
        &self,
        service_id: &str,
        config: &ServiceConfig,
        decrypted_env: &HashMap<String, Zeroizing<String>>,
        log_tx: mpsc::Sender<RawLogLine>,
    ) -> anyhow::Result<(RuntimeIdentity, oneshot::Receiver<ExitStatusEvent>)>;

    /// Stops the instance and its descendants, allowing time for graceful shutdown.
    async fn stop(&self, identity: &RuntimeIdentity, grace_period: Duration) -> anyhow::Result<()>;

    /// Checks whether the identified instance is running.
    async fn is_alive(&self, identity: &RuntimeIdentity) -> bool;
}
