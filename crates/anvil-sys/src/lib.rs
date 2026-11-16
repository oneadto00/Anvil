//! Low-level cross-platform OS primitives for Anvil.
//!
//! This crate isolates platform-specific process group, Win32 Job Object,
//! port inspection, and PID-reuse-safe orphan reaping mechanics behind a
//! 100% safe public Rust interface.

pub mod error;
pub mod port;
pub mod process_tree;
pub mod reaper;

pub use error::SysError;
pub use port::{inspect_port, kill_port_occupant, PortCheckResult, PortOccupantInfo};
pub use process_tree::{
    DefaultProcessController, ManagedProcessHandle, ProcessController, ProcessSpawnIdentity,
};
pub use reaper::{LockRecord, LockfileStore, ReapReport, WorkspaceLockfile, LOCKFILE_VERSION};
