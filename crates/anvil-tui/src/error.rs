//! Structured failures at the terminal and engine channel boundaries.

use anvil_core::EngineCommand;
use thiserror::Error;
use tokio::sync::{mpsc, watch};

/// A terminal operation or one of the interface's input channels failed.
#[derive(Debug, Error)]
pub enum TuiError {
    /// Reading from or writing to the terminal failed.
    #[error("terminal I/O failed: {0}")]
    TerminalIo(#[from] std::io::Error),
    /// The terminal event stream ended unexpectedly.
    #[error("terminal event stream closed")]
    EventStreamClosed,
    /// The engine stopped receiving commands.
    #[error("engine command channel closed")]
    CommandChannelClosed(#[from] mpsc::error::SendError<EngineCommand>),
    /// The engine stopped publishing workspace snapshots.
    #[error("workspace snapshot channel closed")]
    SnapshotChannelClosed(#[from] watch::error::RecvError),
}
