//! Topological startup waves rendered from immutable service snapshots.

use crate::Theme;
use anvil_core::{RuntimeIdentity, WorkspaceSnapshot};
use ratatui::{
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

/// Layered service list with selection-driven viewport positioning.
pub struct Topology<'a> {
    /// Snapshot supplying DAG waves and service metadata.
    pub snapshot: &'a WorkspaceSnapshot,
    /// Selected service ID; all of its rows are kept visible when space permits.
    pub selected_service: Option<&'a str>,
    /// Whether keyboard navigation currently targets this pane.
    pub focused: bool,
    /// Semantic palette for badges and selection.
    pub theme: &'a Theme,
}

impl Topology<'_> {
    /// Renders service metadata on separate rows to fit compact split panes.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect) {
        let title = if self.focused {
            "Topology [FOCUS]"
        } else {
            "Topology"
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(self.theme.border(self.focused));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let mut lines = Vec::new();
        let mut selected_end = 0;
        for (index, layer) in self.snapshot.topology_layers.iter().enumerate() {
            lines.push(Line::raw(format!("[Layer {index}]")));
            for id in layer {
                let Some(service) = self.snapshot.services.get(id) else {
                    continue;
                };
                let selected = self.selected_service == Some(id.as_str());
                let name = Line::raw(format!(
                    "{} {}",
                    if selected { ">" } else { " " },
                    service.id
                ));
                lines.push(if selected {
                    name.style(self.theme.selected_row())
                } else {
                    name
                });
                let (badge, style) = self.theme.service_badge(&service.state);
                let mut metadata = vec![Span::raw("  "), Span::styled(badge, style)];
                if let Some(port) = service.port {
                    metadata.push(Span::raw(format!(" :{port}")));
                }
                if service.restart_count > 0 {
                    metadata.push(Span::raw(format!(" ↻{}", service.restart_count)));
                }
                lines.push(Line::from(metadata));
                if let Some(identity) = service.state.runtime_identity() {
                    let runtime = match identity {
                        RuntimeIdentity::NativeProcess { pid, .. } => format!("  PID:{pid}"),
                        RuntimeIdentity::DockerContainer { container_id, .. } => format!(
                            "  cid:{}",
                            container_id.chars().take(12).collect::<String>()
                        ),
                    };
                    lines.push(Line::raw(runtime));
                }
                if selected {
                    selected_end = lines.len();
                }
            }
        }
        if self.snapshot.services.is_empty() {
            lines.push(Line::raw("No services"));
        }
        let offset = selected_end.saturating_sub(usize::from(inner.height));
        frame.render_widget(
            Paragraph::new(
                lines
                    .into_iter()
                    .skip(offset)
                    .take(usize::from(inner.height))
                    .collect::<Vec<_>>(),
            ),
            inner,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::widgets::test_support::{ascii_frame, assert_border, snapshot, SIZES};
    use ratatui::{backend::TestBackend, style::Color, Terminal};

    #[test]
    fn layers_badges_runtime_ids_and_selection_fit_both_sizes() {
        for (width, height) in SIZES {
            let snapshot = snapshot();
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| {
                    Topology {
                        snapshot: &snapshot,
                        selected_service: Some("api"),
                        focused: true,
                        theme: &Theme,
                    }
                    .render(frame, frame.area())
                })
                .unwrap();
            let text = ascii_frame(&terminal);
            for expected in [
                "Topology [FOCUS]",
                "[Layer 0]",
                "[Layer 1]",
                "> api",
                "Healthy",
                ":8080",
                ":5432",
                "PID:42",
                "cid:abcdef123456",
                "↻2",
            ] {
                assert!(text.contains(expected), "Missing {expected}:\n{text}");
            }
            assert!(!text.contains("abcdef1234567890"));
            assert_border(&terminal, Rect::new(0, 0, width, height));
            let buffer = terminal.backend().buffer();
            assert_eq!(buffer[(3, 3)].fg, Color::Green);
            assert_eq!(buffer[(1, 6)].bg, Color::Cyan);
        }
    }

    #[test]
    fn selected_service_scrolls_into_view_even_after_many_waves() {
        for (width, height) in SIZES {
            let mut snapshot = snapshot();
            let template = snapshot.services["api"].clone();
            for index in 0..100 {
                let id = format!("worker-{index}");
                let mut service = template.clone();
                service.id = id.clone();
                snapshot.services.insert(id.clone(), service);
                snapshot.topology_layers.push(vec![id]);
            }
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| {
                    Topology {
                        snapshot: &snapshot,
                        selected_service: Some("worker-99"),
                        focused: false,
                        theme: &Theme,
                    }
                    .render(frame, frame.area())
                })
                .unwrap();
            let text = ascii_frame(&terminal);
            assert!(text.contains("> worker-99"));
            assert!(text.contains("[Layer 101]"));
            assert!(!text.contains("[Layer 0]"));
            assert!(!text.contains("[FOCUS]"));
            assert_border(&terminal, Rect::new(0, 0, width, height));
        }
    }
}
