#![forbid(unsafe_code)]

//! Core orchestration engine, configuration parsing, semantic validation, DAG scheduler, and state model.

pub mod config;
pub mod dag;
pub mod error;
pub mod probe;
pub mod state;

pub use config::{
    AnvilConfig, ProjectMetadata, ReadinessProbeConfig, RestartPolicy, RuntimeConfig,
    ServiceConfig,
};
pub use dag::{DagCycleError, DagSchedulerState, DependencyGraph};
pub use error::{ConfigValidationError, CoreError};
pub use state::{
    PortOccupant, RuntimeIdentity, ServiceId, ServiceSnapshot, ServiceState, WorkspaceSnapshot,
};
