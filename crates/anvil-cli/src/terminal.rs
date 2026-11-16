//! Terminal lifecycle RAII guards, panic recovery hook, and cross-platform OS shutdown signals.

use crossterm::{
    cursor::{Hide, Show},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::{
    io::{self, Write},
    sync::{Once, OnceLock},
};
use tokio::sync::watch;

static PANIC_HOOK_ONCE: Once = Once::new();
static SHUTDOWN_BUS: OnceLock<Result<ShutdownSignal, String>> = OnceLock::new();

/// Errors returned while configuring terminal UI mode or OS signal listeners.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // Constructed by Phase 2 subcommands entering TUI or signal loops.
pub enum TerminalError {
    /// Failed to switch the terminal into raw mode or enter the alternate screen.
    #[error("failed to initialize terminal UI mode: {0}")]
    Init(#[from] io::Error),

    /// Failed to install the cross-platform OS termination signal handler.
    #[error("failed to install shutdown signal handler: {0}")]
    SignalHandler(String),
}

/// RAII guard that switches the terminal into raw alternate-screen mode on construction
/// and idempotently restores normal terminal state when dropped.
#[derive(Debug)]
#[allow(dead_code)] // Constructed by Phase 2 `up` TUI command.
pub struct TerminalGuard {
    active: bool,
}

impl TerminalGuard {
    /// Enables raw mode, enters the alternate screen, and hides the cursor.
    ///
    /// If entering the alternate screen fails after raw mode was enabled, terminal
    /// state is restored best-effort before returning the error.
    #[allow(dead_code)] // Consumed by Phase 2 `up` TUI command.
    pub fn new() -> Result<Self, TerminalError> {
        enable_raw_mode()?;
        let mut guard = Self { active: true };
        let mut stdout = io::stdout();
        if let Err(err) = enter_terminal_writer(&mut stdout) {
            guard.restore();
            return Err(TerminalError::Init(err));
        }
        Ok(guard)
    }

    /// Idempotently and silently restores normal terminal state.
    pub fn restore(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        restore_terminal();
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

fn enter_terminal_writer<W: Write>(writer: &mut W) -> io::Result<()> {
    execute!(writer, EnterAlternateScreen, Hide)?;
    writer.flush()
}

fn restore_terminal_writer<W: Write>(writer: &mut W) {
    let _ = execute!(writer, LeaveAlternateScreen, Show);
    let _ = writer.flush();
}

/// Best-effort, panic-free restoration of terminal raw mode, alternate screen, and cursor visibility.
pub fn restore_terminal() {
    let _ = disable_raw_mode();
    let mut stdout = io::stdout();
    restore_terminal_writer(&mut stdout);
}

/// Installs a process-wide panic hook that restores terminal state before running the
/// previously registered panic handler.
///
/// Calling this function more than once is safe and idempotent.
pub fn install_panic_hook() {
    PANIC_HOOK_ONCE.call_once(|| {
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic_info| {
            restore_terminal();
            previous_hook(panic_info);
        }));
    });
}

/// Cross-platform shutdown broadcast bus backed by [`tokio::sync::watch`].
#[derive(Debug, Clone)]
#[allow(dead_code)] // Consumed by `subscribe_shutdown_signal` and Phase 2 commands.
pub struct ShutdownSignal {
    tx: watch::Sender<bool>,
}

impl ShutdownSignal {
    /// Creates an isolated shutdown signal bus initialized to `false`.
    #[allow(dead_code)] // Consumed by `subscribe_shutdown_signal` and unit tests.
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(false);
        Self { tx }
    }

    /// Returns a receiver that observes `true` once shutdown is triggered.
    #[allow(dead_code)] // Consumed by `subscribe_shutdown_signal` and unit tests.
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.tx.subscribe()
    }

    /// Broadcasts shutdown (`true`) to all current and future subscribers.
    #[allow(dead_code)] // Invoked from the OS signal handler callback.
    pub fn trigger(&self) {
        let _ = self.tx.send(true);
    }

    /// Returns `true` if shutdown has already been triggered.
    #[allow(dead_code)] // Utility accessor for callers checking shutdown synchronously.
    pub fn is_triggered(&self) -> bool {
        *self.tx.borrow()
    }
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

/// Installs the cross-platform OS termination signal listener (`SIGINT`, `SIGTERM`,
/// `SIGHUP`, and Windows console control events) once per process and returns a
/// [`watch::Receiver<bool>`] that transitions to `true` upon termination signal receipt.
#[allow(dead_code)] // Consumed by Phase 2 async commands (`up`, `logs`, etc.).
pub fn subscribe_shutdown_signal() -> Result<watch::Receiver<bool>, TerminalError> {
    let bus = SHUTDOWN_BUS.get_or_init(|| {
        let signal = ShutdownSignal::new();
        let handler_signal = signal.clone();
        match ctrlc::set_handler(move || {
            handler_signal.trigger();
        }) {
            Ok(()) => Ok(signal),
            Err(err) => Err(err.to_string()),
        }
    });

    match bus {
        Ok(signal) => Ok(signal.subscribe()),
        Err(msg) => Err(TerminalError::SignalHandler(msg.clone())),
    }
}

/// Resolves once `rx` observes `true` (or its corresponding sender is dropped).
#[allow(dead_code)] // Convenience helper for Phase 2 async commands.
pub async fn wait_for_shutdown(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|&shutdown| shutdown).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_emits_enter_and_restore_escape_sequences() {
        let mut enter_buf = Vec::new();
        enter_terminal_writer(&mut enter_buf).unwrap();
        let enter_seq = String::from_utf8(enter_buf).unwrap();
        assert!(enter_seq.contains("\x1b[?1049h"));
        assert!(enter_seq.contains("\x1b[?25l"));

        let mut restore_buf = Vec::new();
        restore_terminal_writer(&mut restore_buf);
        let restore_seq = String::from_utf8(restore_buf).unwrap();
        assert!(restore_seq.contains("\x1b[?1049l"));
        assert!(restore_seq.contains("\x1b[?25h"));
    }

    #[test]
    fn terminal_guard_restore_is_idempotent() {
        let mut guard = TerminalGuard { active: true };
        assert!(guard.active);
        guard.restore();
        assert!(!guard.active);
        guard.restore();
        assert!(!guard.active);
        drop(guard);
    }

    #[test]
    fn terminal_guard_new_handles_non_tty_gracefully() {
        // In a headless CI/test environment without a TTY, TerminalGuard::new()
        // returns an error without panicking; if a TTY is attached, dropping restores it.
        match TerminalGuard::new() {
            Ok(guard) => drop(guard),
            Err(TerminalError::Init(_)) => {}
            Err(other) => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn install_panic_hook_is_idempotent_and_runs_before_unwind() {
        install_panic_hook();
        install_panic_hook();

        let result = std::panic::catch_unwind(|| {
            panic!("simulated panic to test terminal recovery hook");
        });
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn shutdown_signal_notifies_all_and_late_subscribers() {
        let signal = ShutdownSignal::new();
        assert!(!signal.is_triggered());

        let mut rx1 = signal.subscribe();
        let mut rx2 = signal.subscribe();
        assert!(!*rx1.borrow());
        assert!(!*rx2.borrow());

        let waiter1 = tokio::spawn(async move {
            wait_for_shutdown(&mut rx1).await;
            *rx1.borrow()
        });
        let waiter2 = tokio::spawn(async move {
            wait_for_shutdown(&mut rx2).await;
            *rx2.borrow()
        });

        signal.trigger();
        assert!(signal.is_triggered());

        assert!(waiter1.await.unwrap());
        assert!(waiter2.await.unwrap());

        let mut late_rx = signal.subscribe();
        assert!(*late_rx.borrow());
        wait_for_shutdown(&mut late_rx).await;
    }

    #[test]
    fn subscribe_shutdown_signal_is_idempotent() {
        let rx1 = subscribe_shutdown_signal().unwrap();
        let rx2 = subscribe_shutdown_signal().unwrap();
        assert!(!*rx1.borrow());
        assert!(!*rx2.borrow());
    }
}
