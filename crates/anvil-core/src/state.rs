//! Service lifecycle states, runtime identity, and immutable workspace snapshots.

use crate::config::{AnvilConfig, ServiceConfig};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

/// Unique identifier for a managed service in `anvil.yaml`.
pub type ServiceId = String;

/// Lifecycle state of an individual managed service in the orchestrator.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ServiceState {
    /// Initial state before scheduling has started.
    #[default]
    Idle,
    /// Waiting for one or more upstream DAG dependencies to become `Healthy`.
    WaitingDeps {
        /// Upstream service IDs that have not yet become `Healthy`.
        pending_deps: Vec<ServiceId>,
    },
    /// Checking whether the configured listening port is free prior to startup.
    PortCheck,
    /// Startup paused because the configured TCP port is occupied.
    PortConflict(PortOccupant),
    /// Spawning the OS process group or starting the Docker container.
    Starting,
    /// Process or container has been created and readiness probes are running.
    Probing {
        /// Timestamp when readiness probing started.
        started_at: SystemTime,
        /// Number of probe attempts executed so far.
        attempts: u32,
    },
    /// The service is ready and satisfies its downstream dependents' readiness checks.
    Healthy {
        /// Runtime handle identifying the running native process or Docker container.
        pid_or_cid: RuntimeIdentity,
        /// Timestamp when the service transitioned into `Healthy`.
        since: SystemTime,
    },
    /// Runtime health checks failed consecutively after reaching `Healthy`.
    Unhealthy {
        /// Human-readable description of the failed health check.
        reason: String,
    },
    /// Executing graceful shutdown (`SIGTERM` -> grace period -> `SIGKILL` or container stop).
    Stopping,
    /// Exited cleanly or stopped explicitly by user/system request.
    Stopped {
        /// Process or container exit code, if reported by the OS/runtime.
        exit_code: Option<i32>,
    },
    /// Exited unexpectedly or failed readiness probing before becoming healthy.
    Crashed {
        /// Process or container exit code, if available.
        exit_code: Option<i32>,
        /// Unix termination signal number, if terminated by signal.
        signal: Option<i32>,
        /// Human-readable crash summary.
        reason: String,
        /// Path to the persisted crash report, or an empty string if no report was saved.
        crash_log_path: String,
    },
}

impl ServiceState {
    /// Returns `true` if the service is currently in [`ServiceState::Healthy`].
    pub const fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy { .. })
    }

    /// Returns `true` if the service is actively progressing, running, or stopping.
    pub const fn is_active(&self) -> bool {
        !matches!(
            self,
            Self::Idle | Self::Stopped { .. } | Self::Crashed { .. }
        )
    }

    /// Returns `true` if the service has reached a stopped or crashed terminal state.
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Stopped { .. } | Self::Crashed { .. })
    }

    /// Returns the attached [`RuntimeIdentity`] when the service is [`ServiceState::Healthy`].
    pub const fn runtime_identity(&self) -> Option<&RuntimeIdentity> {
        match self {
            Self::Healthy { pid_or_cid, .. } => Some(pid_or_cid),
            _ => None,
        }
    }

    /// Returns a concise static label representing the current state variant.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::WaitingDeps { .. } => "WaitingDeps",
            Self::PortCheck => "PortCheck",
            Self::PortConflict(_) => "PortConflict",
            Self::Starting => "Starting",
            Self::Probing { .. } => "Probing",
            Self::Healthy { .. } => "Healthy",
            Self::Unhealthy { .. } => "Unhealthy",
            Self::Stopping => "Stopping",
            Self::Stopped { .. } => "Stopped",
            Self::Crashed { .. } => "Crashed",
        }
    }
}

/// Platform-agnostic identifier for a live service runtime instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeIdentity {
    /// Host operating system process managed via process groups or Windows Job Objects.
    NativeProcess {
        /// Operating system process ID.
        pid: u32,
        /// Operating system process group ID (`PGID` on Unix; `pid` fallback on Windows).
        pgid: u32,
        /// Process start timestamp in seconds since Unix epoch for PID-reuse validation.
        start_time_secs: u64,
    },
    /// Docker or Docker Compose container managed via the Docker Engine API.
    DockerContainer {
        /// Full or short Docker container ID.
        container_id: String,
        /// Human-readable Docker container name.
        container_name: String,
    },
}

/// Metadata describing an external process occupying a service's configured port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortOccupant {
    /// Conflicting TCP port.
    pub port: u16,
    /// Process ID holding the port, or `0` when attribution fails.
    pub pid: u32,
    /// Executable or process name reported by the OS.
    pub process_name: String,
    /// Command line of the occupying process. The orchestrator redacts it in snapshots.
    pub cmdline: String,
}

/// Immutable point-in-time snapshot of a single service's state and metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSnapshot {
    /// Unique service identifier.
    pub id: ServiceId,
    /// Current lifecycle state.
    pub state: ServiceState,
    /// Optional primary listening port from `anvil.yaml`.
    pub port: Option<u16>,
    /// Declared upstream dependency IDs.
    pub depends_on: Vec<ServiceId>,
    /// Number of automatic or manual restarts performed for this service.
    pub restart_count: u32,
}

impl ServiceSnapshot {
    /// Builds an initial [`ServiceSnapshot`] in [`ServiceState::Idle`] from configuration.
    pub fn from_service_config(id: ServiceId, config: &ServiceConfig) -> Self {
        Self {
            id,
            state: ServiceState::Idle,
            port: config.port,
            depends_on: config.depends_on.clone(),
            restart_count: 0,
        }
    }
}

/// Immutable workspace-wide snapshot broadcast by the orchestrator via `tokio::sync::watch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceSnapshot {
    /// Workspace project name from `anvil.yaml`.
    pub project_name: String,
    /// Deterministic map of service IDs to their latest snapshots.
    pub services: BTreeMap<ServiceId, ServiceSnapshot>,
    /// Topological startup waves computed from the dependency DAG.
    pub topology_layers: Vec<Vec<ServiceId>>,
    /// Timestamp when this snapshot was produced.
    pub updated_at: SystemTime,
}

impl WorkspaceSnapshot {
    /// Initializes a [`WorkspaceSnapshot`] from [`AnvilConfig`] and precomputed topology layers.
    pub fn from_config(config: &AnvilConfig, topology_layers: Vec<Vec<ServiceId>>) -> Self {
        let services = config
            .services
            .iter()
            .map(|(id, svc)| {
                (
                    id.clone(),
                    ServiceSnapshot::from_service_config(id.clone(), svc),
                )
            })
            .collect();

        Self {
            project_name: config.project.name.clone(),
            services,
            topology_layers,
            updated_at: SystemTime::now(),
        }
    }

    /// Wraps this snapshot in an [`Arc`] for sharing over `tokio::sync::watch`.
    pub fn into_shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;
    use tokio::sync::watch;

    #[test]
    fn service_state_predicates_and_labels_are_accurate() {
        let idle = ServiceState::default();
        assert_eq!(idle, ServiceState::Idle);
        assert!(!idle.is_healthy());
        assert!(!idle.is_active());
        assert!(!idle.is_terminal());
        assert_eq!(idle.runtime_identity(), None);
        assert_eq!(idle.label(), "Idle");

        let waiting = ServiceState::WaitingDeps {
            pending_deps: vec!["postgres".to_owned()],
        };
        assert!(waiting.is_active());
        assert!(!waiting.is_healthy());
        assert!(!waiting.is_terminal());
        assert_eq!(waiting.label(), "WaitingDeps");

        let conflict = ServiceState::PortConflict(PortOccupant {
            port: 5432,
            pid: 9001,
            process_name: "postgres".to_owned(),
            cmdline: "postgres -D /var/lib/pg".to_owned(),
        });
        assert!(conflict.is_active());
        assert_eq!(conflict.label(), "PortConflict");

        let identity = RuntimeIdentity::NativeProcess {
            pid: 1234,
            pgid: 1234,
            start_time_secs: 1_700_000_000,
        };
        let healthy = ServiceState::Healthy {
            pid_or_cid: identity.clone(),
            since: UNIX_EPOCH,
        };
        assert!(healthy.is_healthy());
        assert!(healthy.is_active());
        assert!(!healthy.is_terminal());
        assert_eq!(healthy.runtime_identity(), Some(&identity));
        assert_eq!(healthy.label(), "Healthy");

        let stopped = ServiceState::Stopped { exit_code: Some(0) };
        assert!(!stopped.is_active());
        assert!(stopped.is_terminal());
        assert_eq!(stopped.label(), "Stopped");

        let crashed = ServiceState::Crashed {
            exit_code: Some(1),
            signal: None,
            reason: "panic".to_owned(),
            crash_log_path: "/tmp/crash.log".to_owned(),
        };
        assert!(!crashed.is_active());
        assert!(crashed.is_terminal());
        assert_eq!(crashed.label(), "Crashed");
    }

    #[test]
    fn workspace_snapshot_shares_via_tokio_watch() {
        let yaml = r#"
version: "1"
project:
  name: "snapshot-demo"
services:
  db:
    runtime:
      type: native
      cmd: "echo db"
    port: 5432
  api:
    runtime:
      type: native
      cmd: "echo api"
    port: 8080
    depends_on:
      - db
"#;
        let cfg = AnvilConfig::from_yaml_str(yaml).unwrap();
        let initial = WorkspaceSnapshot::from_config(
            &cfg,
            vec![vec!["db".to_owned()], vec!["api".to_owned()]],
        )
        .into_shared();

        let (tx, rx) = watch::channel(Arc::clone(&initial));
        assert_eq!(rx.borrow().project_name, "snapshot-demo");
        assert_eq!(rx.borrow().services["db"].state, ServiceState::Idle);
        assert_eq!(rx.borrow().services["db"].port, Some(5432));
        assert_eq!(
            rx.borrow().services["api"].depends_on,
            vec!["db".to_owned()]
        );

        let mut next = (*initial).clone();
        if let Some(db) = next.services.get_mut("db") {
            db.state = ServiceState::Healthy {
                pid_or_cid: RuntimeIdentity::DockerContainer {
                    container_id: "abc123def456".to_owned(),
                    container_name: "anvil-snapshot-demo-db".to_owned(),
                },
                since: SystemTime::now(),
            };
        }
        tx.send(next.into_shared()).unwrap();

        let latest = rx.borrow();
        assert!(latest.services["db"].state.is_healthy());
        assert_eq!(latest.topology_layers.len(), 2);
    }
}
