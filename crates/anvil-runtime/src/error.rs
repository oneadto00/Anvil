//! Errors from service lifecycle operations.

use thiserror::Error;

/// Errors exposed by runtime executors at the orchestration boundary.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// A system process control operation failed.
    #[error(transparent)]
    Sys(#[from] anvil_sys::SysError),
    /// The core configuration or state model reported an error.
    #[error(transparent)]
    Core(#[from] anvil_core::CoreError),
    /// The executor does not manage this runtime type.
    #[error("the requested runtime is unsupported by this executor")]
    UnsupportedRuntime,
    /// A published port is malformed or outside the supported range.
    #[error("invalid Docker port binding: {0}")]
    InvalidPortBinding(String),
    /// Docker rejected a request. Daemon response bodies can contain environment values.
    #[error("Docker {operation} failed with HTTP {status}")]
    DockerResponse {
        operation: &'static str,
        status: u16,
    },
    /// The local Docker connection or response was unusable.
    #[error("Docker {operation} failed: {reason}")]
    DockerClient {
        operation: &'static str,
        reason: String,
    },
    /// Compose returned a nonzero exit status.
    #[error("docker compose {operation} failed ({status})")]
    ComposeFailed {
        operation: &'static str,
        status: std::process::ExitStatus,
    },
    /// The service did not resolve to one container identity.
    #[error("expected one container ID for {0}")]
    MissingContainerIdentity(String),
    /// The service could not be started or registered.
    #[error("failed to start service {service_id}: {source}")]
    SpawnFailed {
        /// Service requested by the caller.
        service_id: String,
        /// Underlying process or worker error.
        #[source]
        source: std::io::Error,
    },
    /// The worker responsible for stopping a process failed.
    #[error("failed to stop process {pid}: {source}")]
    StopFailed {
        /// Target root process ID.
        pid: u32,
        /// Blocking worker failure.
        #[source]
        source: tokio::task::JoinError,
    },
    /// A runtime I/O operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
