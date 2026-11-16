#![forbid(unsafe_code)]

//! Service lifecycle executors and the events they deliver to the orchestrator.

pub mod docker;
pub mod error;
pub mod executor;
pub mod native;

pub use docker::DockerContainerExecutor;
pub use error::RuntimeError;
pub use executor::{ExitStatusEvent, RawLogLine, RuntimeExecutor, StreamSource};
pub use native::NativeProcessExecutor;
