//! Pure keyboard-to-intent routing; no terminal reads or engine commands occur here.

use anvil_core::{PortOccupant, ServiceId, ServiceState};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

/// Pane receiving navigation keys when no modal or text input is active.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FocusPane {
    /// Service topology and selection.
    #[default]
    Topology,
    /// Log history and scrolling.
    Logs,
}

/// Whether character keys represent shortcuts or search text.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum InputMode {
    /// Interpret keys as workbench shortcuts.
    #[default]
    Normal,
    /// Edit a search query without triggering workbench shortcuts.
    SearchInput,
}

/// Modal context copied from a workspace snapshot, without runtime handles.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ModalKind {
    /// No modal is open.
    #[default]
    None,
    /// Request a decision about the process occupying a service's port.
    PortConflict {
        /// Service whose startup is blocked.
        service_id: ServiceId,
        /// Occupant metadata from the snapshot.
        occupant: PortOccupant,
    },
    /// Show the selected service's crash details.
    CrashDetail {
        /// Service whose crash is being inspected.
        service_id: ServiceId,
    },
}

/// Intent for a future state reducer; mapping a key never performs this action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuiAction {
    /// Request graceful workspace shutdown.
    Quit,
    /// Select the next service in topology order.
    SelectNext,
    /// Select the previous service in topology order.
    SelectPrev,
    /// Scroll logs upward by this many lines.
    ScrollUp(usize),
    /// Scroll logs downward by this many lines.
    ScrollDown(usize),
    /// Move to the oldest available log line.
    ScrollTop,
    /// Move to the newest available log line.
    ScrollBottom,
    /// Switch between topology and logs.
    ToggleFocus,
    /// Request a restart of the selected service.
    RestartSelected,
    /// Request conflict resolution for the modal's service, not the current selection.
    KillPortConflict(ServiceId),
    /// Close the active modal.
    DismissModal,
    /// Open conflict details using the selected service's snapshot.
    OpenPortConflictModal,
    /// Open crash details using the selected service's snapshot.
    OpenCrashModal,
    /// Begin editing the log search query.
    EnterSearchMode,
    /// Append a character to the search query.
    SearchPushChar(char),
    /// Remove the last character from the search query.
    SearchBackspace,
    /// Return to normal mode while retaining the query as a filter.
    ConfirmSearch,
    /// Clear the query and return to normal mode.
    ClearSearch,
    /// Toggle automatic following of incoming logs.
    ToggleScrollLock,
    /// Ignore an unsupported key or a key-release event.
    Noop,
}

/// Maps press/repeat events with precedence: modal, search input, normal shortcuts.
///
/// Modals consume all keys, even if search mode is still set underneath them.
/// Search accepts unmodified/Shift characters (including `q/r/k/s`); modified
/// chords, including Ctrl+C, are ignored there. Ctrl+C quits in normal mode and
/// either modal. Release events and unsupported modified shortcuts are ignored.
/// Home/End scroll to log boundaries only when the logs pane has focus.
pub fn map_key_event(
    key: KeyEvent,
    mode: InputMode,
    modal: &ModalKind,
    focus: FocusPane,
    selected_state: Option<&ServiceState>,
) -> TuiAction {
    if key.kind == KeyEventKind::Release {
        return TuiAction::Noop;
    }
    let plain = (key.modifiers - KeyModifiers::SHIFT).is_empty();
    let quit = (key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL)
        || (plain && key.code == KeyCode::Char('q'));

    match modal {
        ModalKind::PortConflict { service_id, .. } => {
            return if quit {
                TuiAction::Quit
            } else if plain {
                match key.code {
                    KeyCode::Char('k' | 'y') | KeyCode::Enter => {
                        TuiAction::KillPortConflict(service_id.clone())
                    }
                    KeyCode::Esc | KeyCode::Char('n') => TuiAction::DismissModal,
                    _ => TuiAction::Noop,
                }
            } else {
                TuiAction::Noop
            };
        }
        ModalKind::CrashDetail { .. } => {
            return if quit {
                TuiAction::Quit
            } else if plain && matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
                TuiAction::DismissModal
            } else {
                TuiAction::Noop
            };
        }
        ModalKind::None => {}
    }

    if mode == InputMode::SearchInput {
        return if plain {
            match key.code {
                KeyCode::Char(ch) => TuiAction::SearchPushChar(ch),
                KeyCode::Backspace => TuiAction::SearchBackspace,
                KeyCode::Enter => TuiAction::ConfirmSearch,
                KeyCode::Esc => TuiAction::ClearSearch,
                _ => TuiAction::Noop,
            }
        } else {
            TuiAction::Noop
        };
    }

    if quit {
        return TuiAction::Quit;
    }
    if !plain {
        return TuiAction::Noop;
    }
    match key.code {
        KeyCode::Tab => TuiAction::ToggleFocus,
        KeyCode::Char('j') | KeyCode::Down => match focus {
            FocusPane::Topology => TuiAction::SelectNext,
            FocusPane::Logs => TuiAction::ScrollDown(1),
        },
        KeyCode::Char('k') | KeyCode::Up => match focus {
            FocusPane::Topology => TuiAction::SelectPrev,
            FocusPane::Logs => TuiAction::ScrollUp(1),
        },
        KeyCode::Home if focus == FocusPane::Logs => TuiAction::ScrollTop,
        KeyCode::End if focus == FocusPane::Logs => TuiAction::ScrollBottom,
        KeyCode::Char('r') => TuiAction::RestartSelected,
        KeyCode::Char('/') => TuiAction::EnterSearchMode,
        KeyCode::Char('s') => TuiAction::ToggleScrollLock,
        KeyCode::Enter => match selected_state {
            Some(ServiceState::PortConflict(_)) => TuiAction::OpenPortConflictModal,
            Some(ServiceState::Crashed { .. }) => TuiAction::OpenCrashModal,
            _ => TuiAction::Noop,
        },
        _ => TuiAction::Noop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn occupant() -> PortOccupant {
        PortOccupant {
            port: 8080,
            pid: 42,
            process_name: "server".into(),
            cmdline: "[REDACTED]".into(),
        }
    }

    fn conflict() -> ModalKind {
        ModalKind::PortConflict {
            service_id: "api".into(),
            occupant: occupant(),
        }
    }

    fn crash() -> ModalKind {
        ModalKind::CrashDetail {
            service_id: "api".into(),
        }
    }

    fn route(code: KeyCode, mode: InputMode, modal: &ModalKind, focus: FocusPane) -> TuiAction {
        map_key_event(
            KeyEvent::new(code, KeyModifiers::NONE),
            mode,
            modal,
            focus,
            None,
        )
    }

    #[test]
    fn normal_navigation_respects_pane_focus() {
        for (codes, topology, logs) in [
            (
                [KeyCode::Char('j'), KeyCode::Down],
                TuiAction::SelectNext,
                TuiAction::ScrollDown(1),
            ),
            (
                [KeyCode::Char('k'), KeyCode::Up],
                TuiAction::SelectPrev,
                TuiAction::ScrollUp(1),
            ),
        ] {
            for code in codes {
                assert_eq!(
                    route(
                        code,
                        InputMode::Normal,
                        &ModalKind::None,
                        FocusPane::Topology
                    ),
                    topology
                );
                assert_eq!(
                    route(code, InputMode::Normal, &ModalKind::None, FocusPane::Logs),
                    logs
                );
            }
        }
        for (code, action) in [
            (KeyCode::Home, TuiAction::ScrollTop),
            (KeyCode::End, TuiAction::ScrollBottom),
        ] {
            assert_eq!(
                route(code, InputMode::Normal, &ModalKind::None, FocusPane::Logs),
                action
            );
            assert_eq!(
                route(
                    code,
                    InputMode::Normal,
                    &ModalKind::None,
                    FocusPane::Topology
                ),
                TuiAction::Noop
            );
        }
    }

    #[test]
    fn normal_shortcuts_work_in_both_panes() {
        for focus in [FocusPane::Topology, FocusPane::Logs] {
            for (code, action) in [
                (KeyCode::Char('q'), TuiAction::Quit),
                (KeyCode::Tab, TuiAction::ToggleFocus),
                (KeyCode::Char('r'), TuiAction::RestartSelected),
                (KeyCode::Char('/'), TuiAction::EnterSearchMode),
                (KeyCode::Char('s'), TuiAction::ToggleScrollLock),
                (KeyCode::Esc, TuiAction::Noop),
                (KeyCode::F(1), TuiAction::Noop),
            ] {
                assert_eq!(
                    route(code, InputMode::Normal, &ModalKind::None, focus),
                    action
                );
            }
        }
    }

    #[test]
    fn search_consumes_shortcuts_and_accepts_unicode_and_shift() {
        for focus in [FocusPane::Topology, FocusPane::Logs] {
            for ch in ['q', 'r', 'k', 's', 'j', '/', ' ', '中', 'Q'] {
                for modifiers in [KeyModifiers::NONE, KeyModifiers::SHIFT] {
                    assert_eq!(
                        map_key_event(
                            KeyEvent::new(KeyCode::Char(ch), modifiers),
                            InputMode::SearchInput,
                            &ModalKind::None,
                            focus,
                            None
                        ),
                        TuiAction::SearchPushChar(ch)
                    );
                }
            }
            for (code, action) in [
                (KeyCode::Backspace, TuiAction::SearchBackspace),
                (KeyCode::Enter, TuiAction::ConfirmSearch),
                (KeyCode::Esc, TuiAction::ClearSearch),
                (KeyCode::Tab, TuiAction::Noop),
                (KeyCode::Up, TuiAction::Noop),
            ] {
                assert_eq!(
                    route(code, InputMode::SearchInput, &ModalKind::None, focus),
                    action
                );
            }
        }
    }

    #[test]
    fn conflict_modal_overrides_search_and_navigation() {
        for mode in [InputMode::Normal, InputMode::SearchInput] {
            for focus in [FocusPane::Topology, FocusPane::Logs] {
                for code in [KeyCode::Char('k'), KeyCode::Char('y'), KeyCode::Enter] {
                    assert_eq!(
                        route(code, mode, &conflict(), focus),
                        TuiAction::KillPortConflict("api".into())
                    );
                }
                for code in [KeyCode::Esc, KeyCode::Char('n')] {
                    assert_eq!(
                        route(code, mode, &conflict(), focus),
                        TuiAction::DismissModal
                    );
                }
                for code in [
                    KeyCode::Char('j'),
                    KeyCode::Up,
                    KeyCode::Char('r'),
                    KeyCode::Char('/'),
                    KeyCode::Char('s'),
                    KeyCode::Tab,
                ] {
                    assert_eq!(route(code, mode, &conflict(), focus), TuiAction::Noop);
                }
            }
        }
    }

    #[test]
    fn crash_modal_consumes_underlying_shortcuts() {
        for mode in [InputMode::Normal, InputMode::SearchInput] {
            for focus in [FocusPane::Topology, FocusPane::Logs] {
                for code in [KeyCode::Enter, KeyCode::Esc] {
                    assert_eq!(route(code, mode, &crash(), focus), TuiAction::DismissModal);
                }
                for code in [
                    KeyCode::Char('k'),
                    KeyCode::Char('r'),
                    KeyCode::Char('y'),
                    KeyCode::Char('n'),
                    KeyCode::Tab,
                    KeyCode::Char('/'),
                ] {
                    assert_eq!(route(code, mode, &crash(), focus), TuiAction::Noop);
                }
            }
        }
    }

    #[test]
    fn quit_is_available_in_normal_mode_and_both_modals() {
        for modal in [ModalKind::None, conflict(), crash()] {
            for mode in [InputMode::Normal, InputMode::SearchInput] {
                if modal == ModalKind::None && mode == InputMode::SearchInput {
                    continue;
                }
                for key in [
                    KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
                    KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
                ] {
                    assert_eq!(
                        map_key_event(key, mode, &modal, FocusPane::Topology, None),
                        TuiAction::Quit
                    );
                }
            }
        }
    }

    #[test]
    fn enter_opens_only_the_selected_states_details() {
        let conflict_state = ServiceState::PortConflict(occupant());
        let crashed = ServiceState::Crashed {
            exit_code: Some(1),
            signal: None,
            reason: "exit".into(),
            crash_log_path: String::new(),
        };
        for (state, action) in [
            (Some(&conflict_state), TuiAction::OpenPortConflictModal),
            (Some(&crashed), TuiAction::OpenCrashModal),
            (Some(&ServiceState::Idle), TuiAction::Noop),
            (None, TuiAction::Noop),
        ] {
            for focus in [FocusPane::Topology, FocusPane::Logs] {
                assert_eq!(
                    map_key_event(
                        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                        InputMode::Normal,
                        &ModalKind::None,
                        focus,
                        state
                    ),
                    action
                );
            }
        }
    }

    #[test]
    fn release_and_unsupported_modifier_chords_never_trigger_actions() {
        for modal in [ModalKind::None, conflict(), crash()] {
            for mode in [InputMode::Normal, InputMode::SearchInput] {
                for code in [KeyCode::Char('q'), KeyCode::Char('k'), KeyCode::Enter] {
                    let released =
                        KeyEvent::new_with_kind(code, KeyModifiers::NONE, KeyEventKind::Release);
                    assert_eq!(
                        map_key_event(released, mode, &modal, FocusPane::Topology, None),
                        TuiAction::Noop
                    );
                    for modifiers in [
                        KeyModifiers::CONTROL,
                        KeyModifiers::ALT,
                        KeyModifiers::SUPER,
                    ] {
                        assert_eq!(
                            map_key_event(
                                KeyEvent::new(code, modifiers),
                                mode,
                                &modal,
                                FocusPane::Topology,
                                None
                            ),
                            TuiAction::Noop
                        );
                    }
                }
            }
        }
        assert_eq!(
            map_key_event(
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
                InputMode::SearchInput,
                &ModalKind::None,
                FocusPane::Logs,
                None
            ),
            TuiAction::Noop
        );
    }

    #[test]
    fn repeats_support_navigation_and_search_editing() {
        let key =
            KeyEvent::new_with_kind(KeyCode::Char('k'), KeyModifiers::NONE, KeyEventKind::Repeat);
        assert_eq!(
            map_key_event(
                key,
                InputMode::Normal,
                &ModalKind::None,
                FocusPane::Topology,
                None
            ),
            TuiAction::SelectPrev
        );
        assert_eq!(
            map_key_event(
                key,
                InputMode::SearchInput,
                &ModalKind::None,
                FocusPane::Logs,
                None
            ),
            TuiAction::SearchPushChar('k')
        );
    }
}
