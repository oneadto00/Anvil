#![forbid(unsafe_code)]

//! Terminal user interface workbench for Anvil.
//!
//! Snapshot-driven `ratatui` workbench, input routing, semantic styles, and 60FPS event loop.

pub mod app;
pub mod error;
pub mod event;
pub mod theme;
pub mod widgets;

pub use app::{run_tui, run_with_event_stream, TuiApp};
pub use error::TuiError;
pub use event::{map_key_event, FocusPane, InputMode, ModalKind, TuiAction};
pub use theme::Theme;
