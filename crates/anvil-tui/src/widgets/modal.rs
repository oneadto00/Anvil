//! Centered snapshot-only detail overlays; interaction is handled by the caller.

use crate::Theme;
use anvil_core::{PortOccupant, ServiceState};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

/// Port conflict details copied from the engine snapshot.
pub struct PortConflictModal<'a> {
    /// Service blocked by the occupied port.
    pub service_name: &'a str,
    /// Occupant metadata; never a live process handle.
    pub occupant: &'a PortOccupant,
    /// Palette used to distinguish this overlay.
    pub theme: &'a Theme,
}

impl PortConflictModal<'_> {
    /// Clears the underlying pane content and draws a bounded conflict dialog.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect) {
        render_modal(
            frame,
            area,
            "Port Conflict",
            &[
                format!("Service: {}", self.service_name),
                format!("Port: {}", self.occupant.port),
                format!("PID: {}", self.occupant.pid),
                format!("Process: {}", self.occupant.process_name),
                format!("Command: {}", self.occupant.cmdline),
            ],
            "[k] Kill Occupant & Retry  [Esc] Dismiss",
            self.theme,
        );
    }
}

/// Crash metadata drawn from the latest state of the modal's service.
pub struct CrashDetailModal<'a> {
    /// Service whose crash is being inspected, independent of current selection.
    pub service_name: &'a str,
    /// Current state, or None when the service has disappeared from the snapshot.
    pub state: Option<&'a ServiceState>,
    /// Palette used to distinguish this overlay.
    pub theme: &'a Theme,
}

impl CrashDetailModal<'_> {
    /// Draws all crash fields, or an explicit stale-snapshot message.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect) {
        let mut fields = vec![format!("Service: {}", self.service_name)];
        match self.state {
            Some(ServiceState::Crashed {
                exit_code,
                signal,
                reason,
                crash_log_path,
            }) => {
                fields.extend([
                    format!(
                        "Exit code: {}",
                        exit_code.map_or_else(|| "unknown".into(), |code| code.to_string())
                    ),
                    format!(
                        "Signal: {}",
                        signal.map_or_else(|| "none".into(), |signal| signal.to_string())
                    ),
                    format!("Reason: {reason}"),
                    format!("Crash log: {crash_log_path}"),
                ]);
            }
            _ => fields.push("Crash details no longer available in this snapshot".into()),
        }
        render_modal(
            frame,
            area,
            "Crash Details",
            &fields,
            "[r] Restart Service  [Esc] Close",
            self.theme,
        );
    }
}

fn modal_area(area: Rect) -> Rect {
    let width = area
        .width
        .saturating_sub(if area.width > 4 { 4 } else { 0 })
        .min(76);
    let height = area
        .height
        .saturating_sub(if area.height > 2 { 2 } else { 0 })
        .min(18);
    Rect::new(
        area.x.saturating_add(area.width.saturating_sub(width) / 2),
        area.y
            .saturating_add(area.height.saturating_sub(height) / 2),
        width,
        height,
    )
}

fn render_modal(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    fields: &[String],
    hint: &str,
    theme: &Theme,
) {
    let area = modal_area(area);
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title.to_owned())
        .border_style(theme.modal_border());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let [body, footer] = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(2)])
        .areas(inner);
    // Clip each field to its own area so long details leave room for action hints.
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            fields
                .iter()
                .map(|_| Constraint::Ratio(1, fields.len() as u32)),
        )
        .split(body);
    for (field, row) in fields.iter().zip(rows.iter()) {
        frame.render_widget(
            Paragraph::new(field.as_str()).wrap(Wrap { trim: false }),
            *row,
        );
    }
    frame.render_widget(
        Paragraph::new(hint)
            .wrap(Wrap { trim: false })
            .style(theme.border(true)),
        footer,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::widgets::test_support::{ascii_frame, assert_border, SIZES};
    use ratatui::{backend::TestBackend, style::Color, Terminal};

    fn assert_overlay(terminal: &Terminal<TestBackend>, width: u16, height: u16) {
        let area = modal_area(Rect::new(0, 0, width, height));
        assert_border(terminal, area);
        let buffer = terminal.backend().buffer();
        assert_eq!(buffer[(area.x, area.y)].fg, Color::Magenta);
        for y in 0..height {
            for x in 0..width {
                if x < area.x || x >= area.right() || y < area.y || y >= area.bottom() {
                    assert_eq!(buffer[(x, y)].symbol(), "#");
                } else {
                    assert_ne!(
                        buffer[(x, y)].symbol(),
                        "#",
                        "Clear must erase all underlying content"
                    );
                }
            }
        }
    }

    fn background(frame: &mut Frame<'_>) {
        let area = frame.area();
        frame.render_widget(
            Paragraph::new(
                vec!["#".repeat(usize::from(area.width)); usize::from(area.height)].join("\n"),
            ),
            area,
        );
    }

    #[test]
    fn port_conflict_wraps_long_commands_and_keeps_actions_visible() {
        for (width, height) in SIZES {
            let occupant = PortOccupant {
                port: 8080,
                pid: 123,
                process_name: "node".into(),
                cmdline: format!("node server.js {}", "long-argument ".repeat(200)),
            };
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| {
                    background(frame);
                    PortConflictModal {
                        service_name: "api",
                        occupant: &occupant,
                        theme: &Theme,
                    }
                    .render(frame, frame.area());
                })
                .unwrap();
            let text = ascii_frame(&terminal);
            for expected in [
                "Port Conflict",
                "Service: api",
                "Port: 8080",
                "PID: 123",
                "Process: node",
                "Command: node server.js",
                "[k] Kill Occupant & Retry  [Esc] Dismiss",
            ] {
                assert!(text.contains(expected), "Missing {expected}:\n{text}");
            }
            assert_overlay(&terminal, width, height);
        }
    }

    #[test]
    fn crash_fields_and_actions_survive_long_reason_and_log_path() {
        for (width, height) in SIZES {
            let state = ServiceState::Crashed {
                exit_code: Some(1),
                signal: Some(9),
                reason: format!("probe timed out {}", "详细信息 ".repeat(200)),
                crash_log_path: format!("/tmp/crash.log/{}", "long-path/".repeat(200)),
            };
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| {
                    background(frame);
                    CrashDetailModal {
                        service_name: "api",
                        state: Some(&state),
                        theme: &Theme,
                    }
                    .render(frame, frame.area());
                })
                .unwrap();
            let text = ascii_frame(&terminal);
            for expected in [
                "Crash Details",
                "Service: api",
                "Exit code: 1",
                "Signal: 9",
                "Reason: probe timed out",
                "Crash log:",
                "/tmp/crash.log",
                "[r] Restart Service  [Esc] Close",
            ] {
                assert!(text.contains(expected), "Missing {expected}:\n{text}");
            }
            assert_overlay(&terminal, width, height);
            terminal
                .draw(|frame| {
                    CrashDetailModal {
                        service_name: "removed",
                        state: None,
                        theme: &Theme,
                    }
                    .render(frame, frame.area())
                })
                .unwrap();
            assert!(ascii_frame(&terminal).contains("no longer available"));
        }
    }
}
