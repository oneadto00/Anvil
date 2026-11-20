//! Terminal colors and styles for service states and workbench controls.

use anvil_core::ServiceState;
use ratatui::style::{Color, Modifier, Style};

/// Stateless terminal palette using named ANSI colors and readable state labels.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Theme;

impl Theme {
    /// Returns a nonempty badge label and its lifecycle-specific style.
    pub fn service_badge(&self, state: &ServiceState) -> (&'static str, Style) {
        let style = match state {
            ServiceState::Idle => Style::default().fg(Color::Gray),
            ServiceState::WaitingDeps { .. } => Style::default().fg(Color::Yellow),
            ServiceState::PortCheck => Style::default().fg(Color::Cyan),
            ServiceState::PortConflict(_) => self.warning_badge(),
            ServiceState::Starting => Style::default().fg(Color::Blue),
            ServiceState::Probing { .. } => Style::default().fg(Color::Cyan),
            ServiceState::Healthy { .. } => Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
            ServiceState::Unhealthy { .. } => self.warning_badge(),
            ServiceState::Stopping => Style::default().fg(Color::Yellow),
            ServiceState::Stopped { .. } => Style::default().fg(Color::DarkGray),
            ServiceState::Crashed { .. } => self.error_badge(),
        };
        (state.label(), style)
    }

    /// Distinguishes the pane receiving keyboard navigation from other panes.
    pub fn border(&self, focused: bool) -> Style {
        if focused {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        }
    }

    /// Highlights the selected service row with explicit foreground and background.
    pub fn selected_row(&self) -> Style {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    }

    /// Highlights only matching text within a log line.
    pub fn search_match(&self) -> Style {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    }

    /// Marks warnings and states that need user attention.
    pub fn warning_badge(&self) -> Style {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    }

    /// Marks errors and unexpected service exits.
    pub fn error_badge(&self) -> Style {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    }

    /// Separates an active modal from the underlying panes.
    pub fn modal_border(&self) -> Style {
        Style::default()
            .fg(Color::Magenta)
            .add_modifier(Modifier::BOLD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anvil_core::{PortOccupant, RuntimeIdentity};
    use std::time::UNIX_EPOCH;

    #[test]
    fn all_eleven_states_have_readable_semantic_badges() {
        let cases = [
            (ServiceState::Idle, Color::Gray),
            (
                ServiceState::WaitingDeps {
                    pending_deps: vec![],
                },
                Color::Yellow,
            ),
            (ServiceState::PortCheck, Color::Cyan),
            (
                ServiceState::PortConflict(PortOccupant {
                    port: 8080,
                    pid: 42,
                    process_name: "server".into(),
                    cmdline: "[REDACTED]".into(),
                }),
                Color::Yellow,
            ),
            (ServiceState::Starting, Color::Blue),
            (
                ServiceState::Probing {
                    started_at: UNIX_EPOCH,
                    attempts: 1,
                },
                Color::Cyan,
            ),
            (
                ServiceState::Healthy {
                    pid_or_cid: RuntimeIdentity::DockerContainer {
                        container_id: "abc".into(),
                        container_name: "api".into(),
                    },
                    since: UNIX_EPOCH,
                },
                Color::Green,
            ),
            (
                ServiceState::Unhealthy {
                    reason: "timeout".into(),
                },
                Color::Yellow,
            ),
            (ServiceState::Stopping, Color::Yellow),
            (
                ServiceState::Stopped { exit_code: Some(0) },
                Color::DarkGray,
            ),
            (
                ServiceState::Crashed {
                    exit_code: Some(1),
                    signal: None,
                    reason: "exit".into(),
                    crash_log_path: String::new(),
                },
                Color::Red,
            ),
        ];
        for (state, color) in cases {
            let (label, style) = Theme.service_badge(&state);
            assert!(!label.trim().is_empty());
            assert_eq!(label, state.label());
            assert_eq!(style.fg, Some(color), "{label}");
        }
    }

    #[test]
    fn interaction_styles_are_distinct_and_highlights_have_contrast() {
        assert_ne!(Theme.border(true), Theme.border(false));
        assert_ne!(Theme.modal_border(), Theme.border(true));
        assert_ne!(Theme.warning_badge(), Theme.error_badge());
        assert_ne!(Theme.selected_row(), Theme.search_match());
        for style in [Theme.selected_row(), Theme.search_match()] {
            assert!(style.fg.is_some());
            assert!(style.bg.is_some());
            assert_ne!(style.fg, style.bg);
        }
    }
}
