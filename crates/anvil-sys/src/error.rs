//! Structured system-level error definitions for `anvil-sys`.

use thiserror::Error;

/// Errors returned by cross-platform OS primitives in `anvil-sys`.
#[derive(Debug, Error)]
pub enum SysError {
    /// Failed to configure or attach a child process to an isolated process group.
    #[error("failed to configure process group: {0}")]
    ProcessGroupSetup(String),

    /// Failed to terminate a process or its entire process tree.
    #[error("failed to terminate process tree for pid {pid}: {reason}")]
    TerminationFailed {
        /// Primary process identifier targeted by the termination request.
        pid: u32,
        /// Underlying OS error or contextual failure reason.
        reason: String,
    },

    /// Failed to create, configure, assign, or terminate a Windows Job Object.
    #[error("Windows Job Object error: {0}")]
    JobObjectError(String),

    /// Failed to probe local port availability via bind check.
    #[error("port bind check failed on port {port}: {reason}")]
    PortBindCheck {
        /// TCP port that could not be probed.
        port: u16,
        /// Underlying OS bind error description.
        reason: String,
    },

    /// Failed to resolve the process occupying a conflicting listening port.
    #[error("failed to lookup occupant for port {port}: {reason}")]
    PortLookupFailed {
        /// Conflicting listening port number.
        port: u16,
        /// Reason the OS socket table lookup failed.
        reason: String,
    },

    /// A runtime lockfile, record, or project identifier was invalid.
    #[error("invalid runtime lockfile: {0}")]
    InvalidLockfile(String),

    /// Underlying standard I/O error from filesystem or process operations.
    #[error("system I/O error: {0}")]
    Io(#[from] std::io::Error),
}
