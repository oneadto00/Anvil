//! Snapshot-driven TUI state container and 60FPS `tokio::select!` event loop.

use crate::{
    map_key_event,
    widgets::{log_pane::ServiceLogBuffer, render_workspace, WorkspaceView},
    FocusPane, InputMode, ModalKind, Theme, TuiAction, TuiError,
};
use ansi_to_tui::IntoText;
use anvil_core::{
    EngineChannels, EngineCommand, LogBatch, PortOccupant, ServiceId, ServiceState,
    WorkspaceSnapshot,
};
use crossterm::event::{Event, KeyEvent};
use futures_util::{Stream, StreamExt};
use ratatui::{backend::Backend, layout::Rect, Frame, Terminal};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::{sync::mpsc, time::MissedTickBehavior};

const FRAME_INTERVAL: Duration = Duration::from_nanos(16_666_667);
const MAX_LOG_DRAIN_BATCHES: usize = 64;

/// Lock-free snapshot-driven UI state for the terminal workbench.
pub struct TuiApp {
    snapshot: Arc<WorkspaceSnapshot>,
    ordered_services: Vec<ServiceId>,
    selected_service: Option<ServiceId>,
    logs: HashMap<ServiceId, ServiceLogBuffer>,
    focus: FocusPane,
    input_mode: InputMode,
    modal: ModalKind,
    search_query: String,
    seen_port_conflicts: HashMap<ServiceId, PortOccupant>,
    log_inner_height: usize,
    dirty: bool,
    should_quit: bool,
    theme: Theme,
}

impl TuiApp {
    /// Initializes UI state from the workspace's initial immutable snapshot.
    ///
    /// Starts with `dirty = true` so the first render tick always paints an initial frame.
    pub fn new(snapshot: Arc<WorkspaceSnapshot>) -> Self {
        let ordered_services = collect_ordered_services(&snapshot);
        let selected_service = ordered_services.first().cloned();
        let mut app = Self {
            snapshot,
            ordered_services,
            selected_service,
            logs: HashMap::new(),
            focus: FocusPane::Topology,
            input_mode: InputMode::Normal,
            modal: ModalKind::None,
            search_query: String::new(),
            seen_port_conflicts: HashMap::new(),
            log_inner_height: 0,
            dirty: true,
            should_quit: false,
            theme: Theme,
        };
        app.sync_port_conflicts();
        app
    }

    /// Returns the latest immutable workspace snapshot held by the UI.
    pub fn snapshot(&self) -> &Arc<WorkspaceSnapshot> {
        &self.snapshot
    }

    /// Returns the currently selected service ID in topology order, if any.
    pub fn selected_service(&self) -> Option<&str> {
        self.selected_service.as_deref()
    }

    /// Returns the pane currently receiving navigation keys.
    pub fn focus(&self) -> FocusPane {
        self.focus
    }

    /// Returns the active input mode (`Normal` or `SearchInput`).
    pub fn input_mode(&self) -> InputMode {
        self.input_mode
    }

    /// Returns the currently displayed modal overlay.
    pub fn modal(&self) -> &ModalKind {
        &self.modal
    }

    /// Returns the active literal search filter over decoded log lines.
    pub fn search_query(&self) -> &str {
        &self.search_query
    }

    /// Returns a service's bounded local log history, if any lines have arrived.
    pub fn logs_for(&self, service_id: &str) -> Option<&ServiceLogBuffer> {
        self.logs.get(service_id)
    }

    /// Returns `true` when UI state or logs changed since the last rendered frame.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Returns `true` once the user has requested graceful exit.
    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    /// Atomically replaces the active workspace snapshot and reconciles selection and conflict modals.
    pub fn apply_snapshot(&mut self, snapshot: Arc<WorkspaceSnapshot>) {
        self.snapshot = snapshot;
        self.ordered_services = collect_ordered_services(&self.snapshot);
        if !self
            .selected_service
            .as_ref()
            .is_some_and(|selected| self.ordered_services.contains(selected))
        {
            self.selected_service = self.ordered_services.first().cloned();
        }
        self.sync_port_conflicts();
        self.dirty = true;
    }

    /// Appends a batch of redacted log lines into the target service's bounded ring buffer.
    ///
    /// Returns `true` if any lines were appended and the screen was marked dirty.
    pub fn push_log_batch(&mut self, batch: LogBatch) -> bool {
        if batch.lines.is_empty() {
            return false;
        }
        let buffer = self.logs.entry(batch.service_id).or_default();
        for line in batch.lines {
            buffer.push(line);
        }
        self.dirty = true;
        true
    }

    /// Handles a terminal event (`Key` or `Resize`), returning any resulting engine command.
    pub fn handle_terminal_event(&mut self, event: Event) -> Option<EngineCommand> {
        match event {
            Event::Key(key) => self.handle_key_event(key),
            Event::Resize(_, height) => {
                self.set_viewport_height(height);
                self.dirty = true;
                None
            }
            _ => None,
        }
    }

    /// Translates a keyboard event via [`map_key_event`] and applies the resulting [`TuiAction`].
    pub fn handle_key_event(&mut self, key: KeyEvent) -> Option<EngineCommand> {
        let selected_state = self
            .selected_service
            .as_deref()
            .and_then(|id| self.snapshot.services.get(id))
            .map(|service| &service.state);
        let action = map_key_event(
            key,
            self.input_mode,
            &self.modal,
            self.focus,
            selected_state,
        );
        self.apply_action(action)
    }

    /// Reduces a [`TuiAction`] against local UI state and returns any outbound [`EngineCommand`].
    pub fn apply_action(&mut self, action: TuiAction) -> Option<EngineCommand> {
        match action {
            TuiAction::Noop => None,
            TuiAction::Quit => {
                self.should_quit = true;
                self.dirty = true;
                Some(EngineCommand::Shutdown)
            }
            TuiAction::SelectNext => {
                if self.step_selection(1) {
                    self.dirty = true;
                }
                None
            }
            TuiAction::SelectPrev => {
                if self.step_selection(-1) {
                    self.dirty = true;
                }
                None
            }
            TuiAction::ScrollUp(lines) => {
                self.scroll_logs_up(lines);
                self.dirty = true;
                None
            }
            TuiAction::ScrollDown(lines) => {
                self.scroll_logs_down(lines);
                self.dirty = true;
                None
            }
            TuiAction::ScrollTop => {
                self.scroll_logs_top();
                self.dirty = true;
                None
            }
            TuiAction::ScrollBottom => {
                self.scroll_logs_bottom();
                self.dirty = true;
                None
            }
            TuiAction::ToggleFocus => {
                self.focus = match self.focus {
                    FocusPane::Topology => FocusPane::Logs,
                    FocusPane::Logs => FocusPane::Topology,
                };
                self.dirty = true;
                None
            }
            TuiAction::RestartSelected => {
                let service_id = self.selected_service.clone()?;
                self.dirty = true;
                Some(EngineCommand::Restart(service_id))
            }
            TuiAction::KillPortConflict(service_id) => {
                self.modal = ModalKind::None;
                self.seen_port_conflicts.remove(&service_id);
                self.dirty = true;
                Some(EngineCommand::ResolvePortConflict(service_id))
            }
            TuiAction::DismissModal => {
                self.modal = ModalKind::None;
                self.sync_port_conflicts();
                self.dirty = true;
                None
            }
            TuiAction::OpenPortConflictModal => {
                let service_id = self.selected_service.clone()?;
                if let Some(ServiceState::PortConflict(occupant)) = self
                    .snapshot
                    .services
                    .get(&service_id)
                    .map(|service| &service.state)
                {
                    self.seen_port_conflicts
                        .insert(service_id.clone(), occupant.clone());
                    self.modal = ModalKind::PortConflict {
                        service_id,
                        occupant: occupant.clone(),
                    };
                    self.dirty = true;
                }
                None
            }
            TuiAction::OpenCrashModal => {
                let service_id = self.selected_service.clone()?;
                if matches!(
                    self.snapshot
                        .services
                        .get(&service_id)
                        .map(|service| &service.state),
                    Some(ServiceState::Crashed { .. })
                ) {
                    self.modal = ModalKind::CrashDetail { service_id };
                    self.dirty = true;
                }
                None
            }
            TuiAction::EnterSearchMode => {
                self.input_mode = InputMode::SearchInput;
                self.dirty = true;
                None
            }
            TuiAction::SearchPushChar(ch) => {
                self.search_query.push(ch);
                self.reset_log_scroll_offsets();
                self.dirty = true;
                None
            }
            TuiAction::SearchBackspace => {
                self.search_query.pop();
                self.reset_log_scroll_offsets();
                self.dirty = true;
                None
            }
            TuiAction::ConfirmSearch => {
                self.input_mode = InputMode::Normal;
                self.dirty = true;
                None
            }
            TuiAction::ClearSearch => {
                self.search_query.clear();
                self.reset_log_scroll_offsets();
                self.input_mode = InputMode::Normal;
                self.dirty = true;
                None
            }
            TuiAction::ToggleScrollLock => {
                self.toggle_scroll_lock();
                self.dirty = true;
                None
            }
        }
    }

    /// Renders the current workbench view into the given Ratatui frame.
    pub fn draw(&mut self, frame: &mut Frame<'_>) {
        self.set_viewport_height(frame.area().height);
        let logs = self
            .selected_service
            .as_deref()
            .and_then(|id| self.logs.get(id));
        let view = WorkspaceView {
            snapshot: &self.snapshot,
            selected_service: self.selected_service.as_deref(),
            logs,
            focus: self.focus,
            input_mode: self.input_mode,
            search_query: &self.search_query,
            modal: &self.modal,
            theme: &self.theme,
        };
        render_workspace(frame, &view);
    }

    fn set_viewport_height(&mut self, total_rows: u16) {
        // Header (1) + footer (1) + LogPane top/bottom borders (2) = 4 rows.
        self.log_inner_height = usize::from(total_rows.saturating_sub(4));
    }

    fn effective_log_viewport_height(&self) -> usize {
        if self.input_mode == InputMode::SearchInput {
            self.log_inner_height.saturating_sub(1)
        } else {
            self.log_inner_height
        }
    }

    fn sync_port_conflicts(&mut self) {
        // Keep dismissed conflicts suppressed only while the same occupant holds the port.
        self.seen_port_conflicts.retain(|id, seen_occupant| {
            matches!(
                self.snapshot.services.get(id).map(|service| &service.state),
                Some(ServiceState::PortConflict(current)) if current == seen_occupant
            )
        });

        if let ModalKind::PortConflict { service_id, .. } = &self.modal {
            match self
                .snapshot
                .services
                .get(service_id)
                .map(|service| &service.state)
            {
                Some(ServiceState::PortConflict(latest)) => {
                    self.modal = ModalKind::PortConflict {
                        service_id: service_id.clone(),
                        occupant: latest.clone(),
                    };
                }
                _ => {
                    self.modal = ModalKind::None;
                }
            }
        }

        if self.modal == ModalKind::None {
            for id in &self.ordered_services {
                let Some(ServiceState::PortConflict(occupant)) =
                    self.snapshot.services.get(id).map(|service| &service.state)
                else {
                    continue;
                };
                if self.seen_port_conflicts.get(id) != Some(occupant) {
                    self.seen_port_conflicts
                        .insert(id.clone(), occupant.clone());
                    self.modal = ModalKind::PortConflict {
                        service_id: id.clone(),
                        occupant: occupant.clone(),
                    };
                    break;
                }
            }
        }
    }

    fn step_selection(&mut self, delta: isize) -> bool {
        if self.ordered_services.is_empty() {
            return false;
        }
        let current = self
            .selected_service
            .as_ref()
            .and_then(|id| self.ordered_services.iter().position(|item| item == id))
            .unwrap_or(0);
        let next = if delta < 0 {
            current.saturating_sub(delta.unsigned_abs())
        } else {
            current
                .saturating_add(delta.unsigned_abs())
                .min(self.ordered_services.len().saturating_sub(1))
        };
        if next == current && self.selected_service.is_some() {
            return false;
        }
        self.selected_service = Some(self.ordered_services[next].clone());
        true
    }

    fn selected_log_max_start(&self) -> usize {
        let Some(id) = self.selected_service.as_deref() else {
            return 0;
        };
        let Some(buffer) = self.logs.get(id) else {
            return 0;
        };
        let matches = if self.search_query.is_empty() {
            buffer.len()
        } else {
            buffer
                .lines()
                .iter()
                .filter(|raw| decode_plain_text(raw).contains(&self.search_query))
                .count()
        };
        matches.saturating_sub(self.effective_log_viewport_height())
    }

    fn scroll_logs_up(&mut self, lines: usize) {
        let max_start = self.selected_log_max_start();
        let Some(id) = self.selected_service.clone() else {
            return;
        };
        let buffer = self.logs.entry(id).or_default();
        if buffer.scroll_locked {
            buffer.scroll_locked = false;
            buffer.scroll_offset = max_start.saturating_sub(lines);
        } else {
            buffer.scroll_offset = buffer.scroll_offset.min(max_start).saturating_sub(lines);
        }
    }

    fn scroll_logs_down(&mut self, lines: usize) {
        let max_start = self.selected_log_max_start();
        let Some(id) = self.selected_service.clone() else {
            return;
        };
        let buffer = self.logs.entry(id).or_default();
        if !buffer.scroll_locked {
            buffer.scroll_offset = buffer.scroll_offset.saturating_add(lines).min(max_start);
        }
    }

    fn scroll_logs_top(&mut self) {
        let Some(id) = self.selected_service.clone() else {
            return;
        };
        let buffer = self.logs.entry(id).or_default();
        buffer.scroll_locked = false;
        buffer.scroll_offset = 0;
    }

    fn scroll_logs_bottom(&mut self) {
        let max_start = self.selected_log_max_start();
        let Some(id) = self.selected_service.clone() else {
            return;
        };
        let buffer = self.logs.entry(id).or_default();
        buffer.scroll_locked = true;
        buffer.scroll_offset = max_start;
    }

    fn toggle_scroll_lock(&mut self) {
        let max_start = self.selected_log_max_start();
        let Some(id) = self.selected_service.clone() else {
            return;
        };
        let buffer = self.logs.entry(id).or_default();
        if buffer.scroll_locked {
            buffer.scroll_locked = false;
            buffer.scroll_offset = max_start;
        } else {
            buffer.scroll_locked = true;
        }
    }

    fn reset_log_scroll_offsets(&mut self) {
        for buffer in self.logs.values_mut() {
            buffer.scroll_offset = 0;
        }
    }
}

/// Runs the TUI event loop against a live terminal using [`crossterm::event::EventStream`].
pub async fn run_tui<B: Backend>(
    terminal: &mut Terminal<B>,
    channels: EngineChannels,
) -> Result<(), TuiError> {
    let events = crossterm::event::EventStream::new();
    run_with_event_stream(terminal, channels, events).await
}

/// Runs the 60FPS `dirty`-flag multiplexed loop against an arbitrary terminal event stream.
pub async fn run_with_event_stream<B, S>(
    terminal: &mut Terminal<B>,
    mut channels: EngineChannels,
    mut events: S,
) -> Result<(), TuiError>
where
    B: Backend,
    S: Stream<Item = Result<Event, std::io::Error>> + Unpin,
{
    let initial_snapshot = channels.snapshots.borrow_and_update().clone();
    let mut app = TuiApp::new(initial_snapshot);
    if let Ok(Rect { height, .. }) = terminal.size().map(|size| Rect::new(0, 0, size.width, size.height)) {
        app.set_viewport_height(height);
    }

    let mut tick = tokio::time::interval(FRAME_INTERVAL);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut logs_open = true;

    while !app.should_quit() {
        tokio::select! {
            changed = channels.snapshots.changed() => match changed {
                Ok(()) => {
                    let snapshot = channels.snapshots.borrow_and_update().clone();
                    app.apply_snapshot(snapshot);
                }
                Err(err) => return Err(TuiError::SnapshotChannelClosed(err)),
            },
            maybe_batch = channels.logs.recv(), if logs_open => match maybe_batch {
                Some(batch) => {
                    app.push_log_batch(batch);
                    for _ in 1..MAX_LOG_DRAIN_BATCHES {
                        match channels.logs.try_recv() {
                            Ok(batch) => {
                                app.push_log_batch(batch);
                            }
                            Err(mpsc::error::TryRecvError::Empty) => break,
                            Err(mpsc::error::TryRecvError::Disconnected) => {
                                logs_open = false;
                                break;
                            }
                        }
                    }
                }
                None => {
                    logs_open = false;
                }
            },
            maybe_event = events.next() => match maybe_event {
                Some(Ok(event)) => {
                    if let Some(command) = app.handle_terminal_event(event) {
                        channels.commands.send(command).await?;
                    }
                }
                Some(Err(err)) => return Err(TuiError::TerminalIo(err)),
                None => return Err(TuiError::EventStreamClosed),
            },
            _ = tick.tick() => {
                if app.is_dirty() {
                    terminal.draw(|frame| app.draw(frame))?;
                    app.dirty = false;
                }
            }
        }
    }

    Ok(())
}

fn collect_ordered_services(snapshot: &WorkspaceSnapshot) -> Vec<ServiceId> {
    let mut ordered = Vec::new();
    let mut seen = HashSet::new();
    for layer in &snapshot.topology_layers {
        for id in layer {
            if snapshot.services.contains_key(id) && seen.insert(id.clone()) {
                ordered.push(id.clone());
            }
        }
    }
    for id in snapshot.services.keys() {
        if seen.insert(id.clone()) {
            ordered.push(id.clone());
        }
    }
    ordered
}

fn decode_plain_text(raw: &str) -> String {
    match raw.into_text() {
        Ok(text) => text
            .lines
            .into_iter()
            .next()
            .unwrap_or_default()
            .spans
            .into_iter()
            .flat_map(|span| span.content.chars().filter(|ch| !ch.is_control()).collect::<Vec<_>>())
            .collect(),
        Err(_) => raw.chars().filter(|ch| !ch.is_control()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::widgets::test_support::{snapshot, SIZES};
    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
    use ratatui::{
        backend::{TestBackend, WindowSize},
        buffer::Cell,
        layout::{Position, Size},
    };
    use std::{
        pin::Pin,
        sync::Mutex,
        task::{Context, Poll},
    };
    use tokio::sync::watch;

    struct ReceiverEventStream {
        rx: mpsc::Receiver<Result<Event, std::io::Error>>,
    }

    impl Stream for ReceiverEventStream {
        type Item = Result<Event, std::io::Error>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.rx.poll_recv(cx)
        }
    }

    struct CountingBackend {
        inner: TestBackend,
        draws_tx: watch::Sender<usize>,
        frames: Arc<Mutex<Vec<String>>>,
    }

    impl CountingBackend {
        fn new(
            width: u16,
            height: u16,
        ) -> (Self, watch::Receiver<usize>, Arc<Mutex<Vec<String>>>) {
            let (draws_tx, draws_rx) = watch::channel(0usize);
            let frames = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    inner: TestBackend::new(width, height),
                    draws_tx,
                    frames: frames.clone(),
                },
                draws_rx,
                frames,
            )
        }

        fn capture_ascii(&self) -> String {
            let buffer = self.inner.buffer();
            let mut output = String::new();
            for y in buffer.area.top()..buffer.area.bottom() {
                for x in buffer.area.left()..buffer.area.right() {
                    output.push_str(buffer[(x, y)].symbol());
                }
                output.push('\n');
            }
            output
        }
    }

    impl Backend for CountingBackend {
        fn draw<'a, I>(&mut self, content: I) -> std::io::Result<()>
        where
            I: Iterator<Item = (u16, u16, &'a Cell)>,
        {
            self.inner.draw(content)
        }

        fn hide_cursor(&mut self) -> std::io::Result<()> {
            self.inner.hide_cursor()
        }

        fn show_cursor(&mut self) -> std::io::Result<()> {
            self.inner.show_cursor()
        }

        fn get_cursor_position(&mut self) -> std::io::Result<Position> {
            self.inner.get_cursor_position()
        }

        fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> std::io::Result<()> {
            self.inner.set_cursor_position(position)
        }

        fn clear(&mut self) -> std::io::Result<()> {
            self.inner.clear()
        }

        fn size(&self) -> std::io::Result<Size> {
            self.inner.size()
        }

        fn window_size(&mut self) -> std::io::Result<WindowSize> {
            self.inner.window_size()
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()?;
            self.frames.lock().unwrap().push(self.capture_ascii());
            let next = *self.draws_tx.borrow() + 1;
            let _ = self.draws_tx.send(next);
            Ok(())
        }
    }

    struct Harness {
        snap_tx: watch::Sender<Arc<WorkspaceSnapshot>>,
        log_tx: mpsc::Sender<LogBatch>,
        cmd_rx: mpsc::Receiver<EngineCommand>,
        event_tx: mpsc::Sender<Result<Event, std::io::Error>>,
        draws_rx: watch::Receiver<usize>,
        frames: Arc<Mutex<Vec<String>>>,
        task: tokio::task::JoinHandle<Result<(), TuiError>>,
    }

    impl Harness {
        fn spawn(width: u16, height: u16, initial: WorkspaceSnapshot) -> Self {
            let (snap_tx, snapshots) = watch::channel(Arc::new(initial));
            let (commands, cmd_rx) = mpsc::channel(64);
            let (log_tx, logs) = mpsc::channel(256);
            let (event_tx, event_rx) = mpsc::channel(128);
            let channels = EngineChannels {
                commands,
                snapshots,
                logs,
            };
            let (backend, draws_rx, frames) = CountingBackend::new(width, height);
            let mut terminal = Terminal::new(backend).unwrap();
            let task = tokio::spawn(async move {
                run_with_event_stream(
                    &mut terminal,
                    channels,
                    ReceiverEventStream { rx: event_rx },
                )
                .await
            });
            Self {
                snap_tx,
                log_tx,
                cmd_rx,
                event_tx,
                draws_rx,
                frames,
                task,
            }
        }

        async fn send_key(&self, code: KeyCode) {
            self.event_tx
                .send(Ok(Event::Key(KeyEvent::new(code, KeyModifiers::NONE))))
                .await
                .unwrap();
        }

        fn draw_count(&self) -> usize {
            *self.draws_rx.borrow()
        }

        async fn wait_for_draw_at_least(&mut self, min_draws: usize) -> String {
            tokio::time::timeout(
                Duration::from_secs(2),
                self.draws_rx.wait_for(|&count| count >= min_draws),
            )
            .await
            .expect("timed out waiting for frame render")
            .unwrap();
            self.latest_frame().unwrap()
        }

        async fn wait_for_frame<F>(&mut self, description: &str, predicate: F) -> String
        where
            F: Fn(&str) -> bool,
        {
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Some(frame) = self.latest_frame() {
                        if predicate(&frame) {
                            return frame;
                        }
                    }
                    self.draws_rx.changed().await.unwrap();
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "timed out waiting for frame ({description}); latest frame:\n{}",
                    self.latest_frame().unwrap_or_default()
                )
            })
        }

        fn latest_frame(&self) -> Option<String> {
            self.frames.lock().unwrap().last().cloned()
        }
    }

    fn occupant(port: u16, pid: u32) -> PortOccupant {
        PortOccupant {
            port,
            pid,
            process_name: "node".into(),
            cmdline: "node legacy.js".into(),
        }
    }

    #[tokio::test]
    async fn zero_idle_redraws_when_no_inputs_snapshots_or_logs_arrive() {
        let mut harness = Harness::spawn(80, 24, snapshot());

        let first = harness.wait_for_draw_at_least(1).await;
        assert!(first.contains("anvil-demo"));
        assert_eq!(harness.draw_count(), 1);

        // Wait across multiple 16.67ms frame intervals with zero updates.
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(
            harness.draw_count(),
            1,
            "idle ticks must not trigger redundant terminal.draw()"
        );

        // Key release (Noop) must not mark the UI dirty.
        harness
            .event_tx
            .send(Ok(Event::Key(KeyEvent::new_with_kind(
                KeyCode::Char('j'),
                KeyModifiers::NONE,
                KeyEventKind::Release,
            ))))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(harness.draw_count(), 1);

        // One real navigation event triggers exactly one additional frame.
        harness.send_key(KeyCode::Char('j')).await;
        let second = harness.wait_for_draw_at_least(2).await;
        assert!(second.contains("> api"));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(harness.draw_count(), 2);

        harness.send_key(KeyCode::Char('q')).await;
        harness.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn full_shortcut_loop_drives_ui_frames_and_exact_engine_command_sequence() {
        for (width, height) in SIZES {
            let mut harness = Harness::spawn(width, height, snapshot());

            let frame0 = harness.wait_for_draw_at_least(1).await;
            assert!(frame0.contains("Topology [FOCUS]"));
            assert!(frame0.contains("> db"));

            harness
                .log_tx
                .send(LogBatch {
                    service_id: "db".into(),
                    lines: vec![
                        "db booting".into(),
                        "\x1b[31mdb error line\x1b[0m".into(),
                        "db ready".into(),
                    ],
                })
                .await
                .unwrap();
            harness
                .log_tx
                .send(LogBatch {
                    service_id: "api".into(),
                    lines: vec!["api starting".into()],
                })
                .await
                .unwrap();
            harness
                .wait_for_frame("seeded db logs", |f| f.contains("Logs db [FOLLOW] 3/3"))
                .await;

            harness.send_key(KeyCode::Char('j')).await;
            let after_j = harness
                .wait_for_frame("select api", |f| {
                    f.contains("> api") && f.contains("Logs api [FOLLOW] 1/1")
                })
                .await;
            assert!(after_j.contains("api starting"), "{after_j}");

            harness.send_key(KeyCode::Char('k')).await;
            harness
                .wait_for_frame("select db", |f| {
                    f.contains("> db") && f.contains("Logs db [FOLLOW] 3/3")
                })
                .await;

            harness.send_key(KeyCode::Tab).await;
            harness
                .wait_for_frame("focus logs", |f| !f.contains("Topology [FOCUS]"))
                .await;

            harness.send_key(KeyCode::Char('/')).await;
            for ch in ['e', 'r', 'r', 'o', 'r'] {
                harness.send_key(KeyCode::Char(ch)).await;
            }
            let searching = harness
                .wait_for_frame("active search bar", |f| {
                    f.contains("/ error_") && f.contains("Logs db [FOLLOW] 1/3")
                })
                .await;
            assert!(searching.contains("db error line"), "{searching}");
            assert!(!searching.contains("db booting"), "{searching}");

            harness.send_key(KeyCode::Enter).await;
            let confirmed = harness
                .wait_for_frame("confirmed search", |f| {
                    !f.contains("/ error_") && f.contains("Logs db [FOLLOW] 1/3")
                })
                .await;
            assert!(confirmed.contains("db error line"), "{confirmed}");

            harness.send_key(KeyCode::Char('s')).await;
            harness
                .wait_for_frame("scroll locked", |f| f.contains("Logs db [LOCKED] 1/3"))
                .await;

            harness.send_key(KeyCode::Char('r')).await;
            let cmd1 = tokio::time::timeout(Duration::from_secs(1), harness.cmd_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(cmd1, EngineCommand::Restart("db".into()));

            let mut next_snap = snapshot();
            next_snap.services.get_mut("api").unwrap().state =
                ServiceState::PortConflict(occupant(8080, 999));
            harness.snap_tx.send(Arc::new(next_snap)).unwrap();
            let modal_frame = harness
                .wait_for_frame("port conflict modal", |f| {
                    f.contains("Port Conflict") && f.contains("PID: 999")
                })
                .await;
            assert!(modal_frame.contains("Service: api"), "{modal_frame}");
            assert!(
                modal_frame.contains("[k] Kill Occupant & Retry"),
                "{modal_frame}"
            );

            // The modal targets api even though db is selected.
            harness.send_key(KeyCode::Char('k')).await;
            let cmd2 = tokio::time::timeout(Duration::from_secs(1), harness.cmd_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(cmd2, EngineCommand::ResolvePortConflict("api".into()));
            harness
                .wait_for_frame("modal dismissed after resolve", |f| {
                    !f.contains("Port Conflict")
                })
                .await;

            harness.send_key(KeyCode::Char('q')).await;
            let cmd3 = tokio::time::timeout(Duration::from_secs(1), harness.cmd_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(cmd3, EngineCommand::Shutdown);
            assert!(harness.cmd_rx.try_recv().is_err());

            harness.task.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn dismissed_port_conflict_does_not_reopen_on_unrelated_snapshot_updates() {
        let mut harness = Harness::spawn(80, 24, snapshot());
        harness.wait_for_draw_at_least(1).await;

        let mut s1 = snapshot();
        s1.services.get_mut("api").unwrap().state =
            ServiceState::PortConflict(occupant(8080, 777));
        harness.snap_tx.send(Arc::new(s1.clone())).unwrap();
        harness
            .wait_for_frame("initial conflict modal", |f| f.contains("Port Conflict"))
            .await;

        harness.send_key(KeyCode::Esc).await;
        harness
            .wait_for_frame("modal dismissed", |f| !f.contains("Port Conflict"))
            .await;

        // Another service changes state while api remains in the same PortConflict.
        let mut s2 = s1.clone();
        s2.services.get_mut("db").unwrap().restart_count = 9;
        harness.snap_tx.send(Arc::new(s2)).unwrap();
        let refreshed = harness
            .wait_for_frame("unrelated snapshot refresh", |f| f.contains("↻9"))
            .await;
        assert!(
            !refreshed.contains("Port Conflict"),
            "dismissed conflict must not pop up again on unrelated snapshot refreshes"
        );

        // Once api leaves PortConflict and later enters a new conflict cycle, it opens again.
        let mut s3 = s1.clone();
        s3.services.get_mut("api").unwrap().state = ServiceState::PortCheck;
        harness.snap_tx.send(Arc::new(s3)).unwrap();
        harness
            .wait_for_frame("api PortCheck", |f| f.contains("PortCheck"))
            .await;

        harness.snap_tx.send(Arc::new(s1)).unwrap();
        harness
            .wait_for_frame("reopened conflict modal", |f| f.contains("Port Conflict"))
            .await;

        harness.send_key(KeyCode::Char('q')).await;
        harness.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn log_flood_bounds_buffer_at_5000_lines_and_keeps_quit_responsive() {
        let mut harness = Harness::spawn(140, 40, snapshot());
        harness.wait_for_draw_at_least(1).await;

        let log_tx = harness.log_tx.clone();
        let producer = tokio::spawn(async move {
            for index in 0..6_000 {
                log_tx
                    .send(LogBatch {
                        service_id: "db".into(),
                        lines: vec![format!("flood-{index:04}")],
                    })
                    .await
                    .unwrap();
            }
        });

        producer.await.unwrap();
        let final_frame = harness
            .wait_for_frame("6000 flood lines drained", |f| {
                f.contains("Received 6000 | Evicted 1000")
            })
            .await;

        assert!(final_frame.contains("5000/5000"), "{final_frame}");
        assert!(final_frame.contains("flood-5999"), "{final_frame}");
        assert!(!final_frame.contains("flood-0999"), "{final_frame}");

        harness.send_key(KeyCode::Char('q')).await;
        let cmd = tokio::time::timeout(Duration::from_secs(1), harness.cmd_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cmd, EngineCommand::Shutdown);
        harness.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn quit_interrupts_active_log_flood_without_starvation() {
        let mut harness = Harness::spawn(80, 24, snapshot());
        let log_tx = harness.log_tx.clone();
        let flooder = tokio::spawn(async move {
            for index in 0..10_000 {
                if log_tx
                    .send(LogBatch {
                        service_id: "db".into(),
                        lines: vec![format!("burst-{index}")],
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        // Send 'q' immediately while flood batches are actively saturating the channel.
        harness.send_key(KeyCode::Char('q')).await;
        let cmd = tokio::time::timeout(Duration::from_secs(2), harness.cmd_rx.recv())
            .await
            .expect("quit command must not starve under log flood")
            .unwrap();
        assert_eq!(cmd, EngineCommand::Shutdown);

        tokio::time::timeout(Duration::from_secs(2), harness.task)
            .await
            .expect("TUI loop must exit promptly after quit")
            .unwrap()
            .unwrap();
        drop(harness.log_tx);
        flooder.abort();
    }

    #[tokio::test]
    async fn log_scrolling_crash_modal_and_channel_closures_work_cleanly() {
        let mut app = TuiApp::new(Arc::new(snapshot()));
        app.set_viewport_height(24);
        app.push_log_batch(LogBatch {
            service_id: "db".into(),
            lines: (0..40).map(|i| format!("line-{i:02}")).collect(),
        });
        app.apply_action(TuiAction::ToggleFocus);
        app.apply_action(TuiAction::ScrollUp(5));
        let buf = app.logs_for("db").unwrap();
        assert!(!buf.scroll_locked);
        assert_eq!(buf.scroll_offset, 15);
        app.apply_action(TuiAction::ScrollDown(2));
        assert_eq!(app.logs_for("db").unwrap().scroll_offset, 17);
        app.apply_action(TuiAction::ScrollTop);
        assert_eq!(app.logs_for("db").unwrap().scroll_offset, 0);
        app.apply_action(TuiAction::ScrollBottom);
        assert!(app.logs_for("db").unwrap().scroll_locked);

        app.apply_action(TuiAction::ToggleFocus);
        app.apply_action(TuiAction::SelectNext);
        assert_eq!(app.selected_service(), Some("api"));
        let mut crashed = snapshot();
        crashed.services.remove("api");
        crashed.topology_layers = vec![vec!["db".into()]];
        crashed.services.get_mut("db").unwrap().state = ServiceState::Crashed {
            exit_code: Some(1),
            signal: None,
            reason: "boom".into(),
            crash_log_path: "/tmp/db.log".into(),
        };
        app.apply_snapshot(Arc::new(crashed));
        assert_eq!(app.selected_service(), Some("db"));
        app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(
            app.modal(),
            &ModalKind::CrashDetail {
                service_id: "db".into()
            }
        );
        app.handle_key_event(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.modal(), &ModalKind::None);

        let harness = Harness::spawn(80, 24, snapshot());
        drop(harness.snap_tx);
        let err = harness.task.await.unwrap().unwrap_err();
        assert!(matches!(err, TuiError::SnapshotChannelClosed(_)));

        let harness = Harness::spawn(80, 24, snapshot());
        drop(harness.event_tx);
        let err = harness.task.await.unwrap().unwrap_err();
        assert!(matches!(err, TuiError::EventStreamClosed));

        let harness = Harness::spawn(80, 24, snapshot());
        let event_tx = harness.event_tx.clone();
        drop(harness.cmd_rx);
        event_tx
            .send(Ok(Event::Key(KeyEvent::new(
                KeyCode::Char('r'),
                KeyModifiers::NONE,
            ))))
            .await
            .unwrap();
        let err = harness.task.await.unwrap().unwrap_err();
        assert!(matches!(err, TuiError::CommandChannelClosed(_)));

        let mut harness = Harness::spawn(80, 24, snapshot());
        let draws = harness.draw_count();
        harness
            .event_tx
            .send(Ok(Event::Resize(140, 40)))
            .await
            .unwrap();
        harness.wait_for_draw_at_least(draws + 1).await;
        harness
            .event_tx
            .send(Err(std::io::Error::other("stream failure")))
            .await
            .unwrap();
        let err = harness.task.await.unwrap().unwrap_err();
        assert!(matches!(err, TuiError::TerminalIo(_)));
    }
}
