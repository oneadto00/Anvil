//! Pure snapshot-driven workbench rendering and UI-owned log history.

pub mod log_pane;
pub mod modal;
pub mod topology;

use anvil_core::WorkspaceSnapshot;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    widgets::Paragraph,
    Frame,
};

use crate::{FocusPane, InputMode, ModalKind, Theme};
use log_pane::{LogPane, ServiceLogBuffer};
use modal::{CrashDetailModal, PortConflictModal};
use topology::Topology;

/// Borrowed presentation state; rendering never changes the engine or UI state.
pub struct WorkspaceView<'a> {
    /// Latest immutable engine snapshot.
    pub snapshot: &'a WorkspaceSnapshot,
    /// Service selected in topology order, if any.
    pub selected_service: Option<&'a str>,
    /// History belonging to the selected service, if it has received logs.
    pub logs: Option<&'a ServiceLogBuffer>,
    /// Pane currently receiving navigation input.
    pub focus: FocusPane,
    /// Whether the search input bar is being edited.
    pub input_mode: InputMode,
    /// Case-sensitive literal search over visible, ANSI-decoded text.
    pub search_query: &'a str,
    /// Snapshot-derived modal context from the input layer.
    pub modal: &'a ModalKind,
    /// Semantic palette shared by all components.
    pub theme: &'a Theme,
}

/// Draws the header, split panes, footer, and optional topmost modal.
pub fn render_workspace(frame: &mut Frame<'_>, view: &WorkspaceView<'_>) {
    let [header, body, footer] = workspace_areas(frame.area());
    let healthy = view
        .snapshot
        .services
        .values()
        .filter(|s| s.state.is_healthy())
        .count();
    frame.render_widget(
        Paragraph::new(format!(
            " Anvil | {} | Healthy {}/{}",
            view.snapshot.project_name,
            healthy,
            view.snapshot.services.len()
        )),
        header,
    );
    let [left, right] = pane_areas(body);
    Topology {
        snapshot: view.snapshot,
        selected_service: view.selected_service,
        focused: view.focus == FocusPane::Topology,
        theme: view.theme,
    }
    .render(frame, left);
    LogPane {
        service_name: view.selected_service,
        buffer: view.logs,
        query: view.search_query,
        search_active: view.input_mode == InputMode::SearchInput,
        focused: view.focus == FocusPane::Logs,
        theme: view.theme,
    }
    .render(frame, right);
    frame.render_widget(
        Paragraph::new(
            " j/k Navigate  Tab Focus  r Restart  / Search  s Follow  Enter Details  q Quit",
        ),
        footer,
    );
    match view.modal {
        ModalKind::None => {}
        ModalKind::PortConflict {
            service_id,
            occupant,
        } => {
            PortConflictModal {
                service_name: service_id,
                occupant,
                theme: view.theme,
            }
            .render(frame, frame.area());
        }
        ModalKind::CrashDetail { service_id } => {
            CrashDetailModal {
                service_name: service_id,
                state: view.snapshot.services.get(service_id).map(|s| &s.state),
                theme: view.theme,
            }
            .render(frame, frame.area());
        }
    }
}

fn workspace_areas(area: Rect) -> [Rect; 3] {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .areas(area)
}

fn pane_areas(area: Rect) -> [Rect; 2] {
    // Thirty columns keep badges, ports, and runtime IDs usable at 80 columns.
    let left = ((u32::from(area.width) * 35 / 100) as u16)
        .max(30)
        .min(area.width);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(left), Constraint::Min(0)])
        .areas(area)
}

#[cfg(test)]
pub(crate) mod test_support {
    use anvil_core::{RuntimeIdentity, ServiceSnapshot, ServiceState, WorkspaceSnapshot};
    use ratatui::{backend::TestBackend, layout::Rect, Terminal};
    use std::{collections::BTreeMap, time::UNIX_EPOCH};

    pub const SIZES: [(u16, u16); 2] = [(80, 24), (140, 40)];

    // Preserve every terminal cell and row, including trailing spaces and box glyphs.
    pub fn ascii_frame(terminal: &Terminal<TestBackend>) -> String {
        let buffer = terminal.backend().buffer();
        let mut output = String::new();
        for y in buffer.area.top()..buffer.area.bottom() {
            for x in buffer.area.left()..buffer.area.right() {
                output.push_str(buffer[(x, y)].symbol());
            }
            output.push('\n');
        }
        output
    }

    pub fn assert_border(terminal: &Terminal<TestBackend>, area: Rect) {
        let buffer = terminal.backend().buffer();
        let (left, right, top, bottom) = (area.x, area.right() - 1, area.y, area.bottom() - 1);
        for (x, y, symbol) in [
            (left, top, "┌"),
            (right, top, "┐"),
            (left, bottom, "└"),
            (right, bottom, "┘"),
        ] {
            assert_eq!(buffer[(x, y)].symbol(), symbol, "{}", ascii_frame(terminal));
        }
        for y in top + 1..bottom {
            assert_eq!(buffer[(left, y)].symbol(), "│");
            assert_eq!(buffer[(right, y)].symbol(), "│");
        }
        for x in left + 1..right {
            assert_eq!(buffer[(x, bottom)].symbol(), "─");
            assert!(!matches!(buffer[(x, top)].symbol(), "│" | "┌" | "┐"));
        }
        let border_start = (left + 1..right)
            .find(|x| buffer[(*x, top)].symbol() == "─")
            .unwrap();
        for x in border_start..right {
            assert_eq!(buffer[(x, top)].symbol(), "─");
        }
    }

    pub fn snapshot() -> WorkspaceSnapshot {
        let mut services = BTreeMap::new();
        for (id, identity, port) in [
            (
                "db",
                RuntimeIdentity::DockerContainer {
                    container_id: "abcdef1234567890".into(),
                    container_name: "db".into(),
                },
                5432,
            ),
            (
                "api",
                RuntimeIdentity::NativeProcess {
                    pid: 42,
                    pgid: 42,
                    start_time_secs: 1,
                },
                8080,
            ),
        ] {
            services.insert(
                id.into(),
                ServiceSnapshot {
                    id: id.into(),
                    state: ServiceState::Healthy {
                        pid_or_cid: identity,
                        since: UNIX_EPOCH,
                    },
                    port: Some(port),
                    depends_on: if id == "api" {
                        vec!["db".into()]
                    } else {
                        vec![]
                    },
                    restart_count: 2,
                },
            );
        }
        WorkspaceSnapshot {
            project_name: "anvil-demo".into(),
            services,
            topology_layers: vec![vec!["db".into()], vec!["api".into()]],
            updated_at: UNIX_EPOCH,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{ascii_frame, assert_border, snapshot, SIZES};
    use super::*;
    use anvil_core::PortOccupant;
    use ratatui::{backend::TestBackend, Terminal};

    #[test]
    fn workspace_renders_both_panes_header_footer_and_overlay() {
        for (width, height) in SIZES {
            let snapshot = snapshot();
            let mut logs = ServiceLogBuffer::default();
            logs.push("ready");
            let mut view = WorkspaceView {
                snapshot: &snapshot,
                selected_service: Some("api"),
                logs: Some(&logs),
                focus: FocusPane::Topology,
                input_mode: InputMode::Normal,
                search_query: "",
                modal: &ModalKind::None,
                theme: &Theme,
            };
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| render_workspace(frame, &view))
                .unwrap();
            let text = ascii_frame(&terminal);
            for expected in [
                "anvil-demo",
                "Healthy 2/2",
                "Topology",
                "Logs",
                "ready",
                "j/k Navigate",
                "q Quit",
                ":8080",
                "PID:42",
                "cid:abcdef123456",
                "↻2",
            ] {
                assert!(text.contains(expected), "Missing {expected}:\n{text}");
            }
            let [_, body, _] = workspace_areas(Rect::new(0, 0, width, height));
            for area in pane_areas(body) {
                assert_border(&terminal, area);
            }
            let modal = ModalKind::PortConflict {
                service_id: "api".into(),
                occupant: PortOccupant {
                    port: 8080,
                    pid: 99,
                    process_name: "node".into(),
                    cmdline: "node server.js".into(),
                },
            };
            view.modal = &modal;
            terminal
                .draw(|frame| render_workspace(frame, &view))
                .unwrap();
            let text = ascii_frame(&terminal);
            assert!(text.contains("Port Conflict"));
            assert!(text.contains("Kill Occupant & Retry"));
            assert!(text.contains("anvil-demo"));
            assert!(text.contains("q Quit"));
        }
    }

    #[test]
    fn empty_and_tiny_workspaces_render_without_panicking() {
        for (width, height) in SIZES.into_iter().chain([(0, 0), (1, 1), (2, 2), (12, 5)]) {
            let mut snapshot = snapshot();
            snapshot.services.clear();
            snapshot.topology_layers.clear();
            for modal in [
                ModalKind::None,
                ModalKind::CrashDetail {
                    service_id: "removed".into(),
                },
            ] {
                let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
                let view = WorkspaceView {
                    snapshot: &snapshot,
                    selected_service: None,
                    logs: None,
                    focus: FocusPane::Logs,
                    input_mode: InputMode::SearchInput,
                    search_query: "",
                    modal: &modal,
                    theme: &Theme,
                };
                terminal
                    .draw(|frame| render_workspace(frame, &view))
                    .unwrap();
                if width >= 80 && modal == ModalKind::None {
                    let text = ascii_frame(&terminal);
                    assert!(text.contains("Healthy 0/0"));
                    assert!(text.contains("No services"));
                    assert!(text.contains("No service selected"));
                }
            }
        }
    }
}
