//! Bounded UI-owned log history and ANSI-aware search rendering.

use crate::Theme;
use ansi_to_tui::IntoText;
use ratatui::{
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};
use std::collections::VecDeque;

/// Maximum number of logical lines retained for each service in the TUI.
pub const LOG_CAPACITY: usize = 5_000;

/// Local log history; no runtime handles, files, or shared engine state are held.
pub struct ServiceLogBuffer {
    lines: VecDeque<String>,
    total_received: u64,
    /// True follows the newest lines; false keeps a manual history position.
    pub scroll_locked: bool,
    /// Zero-based top row in the retained (or search-filtered) history.
    /// Rendering clamps oversized offsets; callers should reset this on query changes.
    pub scroll_offset: usize,
}

impl Default for ServiceLogBuffer {
    fn default() -> Self {
        Self {
            lines: VecDeque::new(),
            total_received: 0,
            scroll_locked: true,
            scroll_offset: 0,
        }
    }
}

impl ServiceLogBuffer {
    /// Appends text, splitting embedded newlines into independently bounded rows.
    /// A trailing newline terminates a row without adding an extra empty row.
    /// Eviction shifts a manual unfiltered viewport to preserve its current content.
    pub fn push(&mut self, text: impl AsRef<str>) {
        let text = text.as_ref();
        if text.is_empty() {
            self.push_line(String::new());
        } else {
            for line in text.split_terminator('\n') {
                self.push_line(line.trim_end_matches('\r').to_owned());
            }
        }
    }

    fn push_line(&mut self, line: String) {
        if self.lines.len() == LOG_CAPACITY {
            self.lines.pop_front();
            if !self.scroll_locked {
                self.scroll_offset = self.scroll_offset.saturating_sub(1);
            }
        }
        self.lines.push_back(line);
        self.total_received = self.total_received.saturating_add(1);
    }

    /// Retained raw lines, ordered from oldest to newest, without mutable access.
    pub fn lines(&self) -> &VecDeque<String> {
        &self.lines
    }

    /// Number of rows currently retained, never exceeding [`LOG_CAPACITY`].
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// Whether this service has no retained log history.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Total logical rows received, including evicted rows (saturating at `u64::MAX`).
    pub fn total_received(&self) -> u64 {
        self.total_received
    }

    /// Number of old rows evicted from this local history.
    pub fn evicted_lines(&self) -> u64 {
        self.total_received.saturating_sub(self.lines.len() as u64)
    }

    /// Whether the retained history is incomplete because the ring has overflowed.
    pub fn overflowed(&self) -> bool {
        self.evicted_lines() > 0
    }
}

/// ANSI log viewer with literal search over decoded text and a separate input row.
pub struct LogPane<'a> {
    /// Selected service name, or no selection.
    pub service_name: Option<&'a str>,
    /// Selected service's local history, if available.
    pub buffer: Option<&'a ServiceLogBuffer>,
    /// Case-sensitive literal filter; empty means show all lines.
    pub query: &'a str,
    /// Shows `/ query_` when search input is active.
    pub search_active: bool,
    /// Whether log navigation currently has focus.
    pub focused: bool,
    /// Semantic palette for borders, warnings, and matches.
    pub theme: &'a Theme,
}

impl LogPane<'_> {
    /// Renders only visible history when not searching; search scans at most 5,000 rows.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect) {
        let follow = self.buffer.is_none_or(|buffer| buffer.scroll_locked);
        let count = self.buffer.map_or(0, ServiceLogBuffer::len);
        let filtered: Vec<_> = if self.query.is_empty() {
            Vec::new()
        } else {
            self.buffer
                .into_iter()
                .flat_map(|buffer| buffer.lines.iter())
                .map(|raw| decode_line(raw))
                .filter(|line| line.to_string().contains(self.query))
                .collect()
        };
        let matches = if self.query.is_empty() {
            count
        } else {
            filtered.len()
        };
        let title = format!(
            "Logs {} [{}] {matches}/{count}",
            self.service_name.unwrap_or("-"),
            if follow { "FOLLOW" } else { "LOCKED" }
        );
        let mut block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(self.theme.border(self.focused));
        if let Some(buffer) = self.buffer.filter(|buffer| buffer.overflowed()) {
            block = block.title_bottom(format!(
                "Received {} | Evicted {}",
                buffer.total_received(),
                buffer.evicted_lines()
            ));
        }
        let mut inner = block.inner(area);
        frame.render_widget(block, area);
        if self.search_active && inner.height > 0 {
            frame.render_widget(
                Paragraph::new(format!("/ {}_", self.query)).style(self.theme.border(true)),
                Rect::new(inner.x, inner.y, inner.width, 1),
            );
            inner.y = inner.y.saturating_add(1);
            inner.height = inner.height.saturating_sub(1);
        }
        if self.service_name.is_none() {
            frame.render_widget(Paragraph::new("No service selected"), inner);
            return;
        }
        let max_start = matches.saturating_sub(usize::from(inner.height));
        let start = if follow {
            max_start
        } else {
            self.buffer
                .map_or(0, |buffer| buffer.scroll_offset)
                .min(max_start)
        };
        let visible: Vec<_> = if self.query.is_empty() {
            self.buffer
                .into_iter()
                .flat_map(|buffer| buffer.lines.iter())
                .skip(start)
                .take(usize::from(inner.height))
                .map(|raw| self.decorate(decode_line(raw)))
                .collect()
        } else {
            filtered
                .into_iter()
                .skip(start)
                .take(usize::from(inner.height))
                .map(|line| self.decorate(line))
                .collect()
        };
        if visible.is_empty() {
            frame.render_widget(
                Paragraph::new(if self.query.is_empty() {
                    "No logs yet"
                } else {
                    "No matches"
                }),
                inner,
            );
        } else {
            frame.render_widget(Paragraph::new(visible), inner);
        }
    }

    fn decorate(&self, mut line: Line<'static>) -> Line<'static> {
        let plain = line.to_string();
        if plain.starts_with("[WARN:") && plain.contains("omitted in TUI") {
            for span in &mut line.spans {
                span.style = span.style.patch(self.theme.warning_badge());
            }
        }
        if self.query.is_empty() {
            return line;
        }
        // Byte ranges are derived from decoded UTF-8, so matches can cross ANSI spans.
        let hits: Vec<_> = plain
            .match_indices(self.query)
            .map(|(start, value)| start..start + value.len())
            .collect();
        let mut offset = 0;
        let mut spans = Vec::new();
        for span in line.spans {
            let end = offset + span.content.len();
            let mut cursor = 0;
            for hit in &hits {
                let start = hit.start.max(offset);
                let stop = hit.end.min(end);
                if start >= stop {
                    continue;
                }
                let (start, stop) = (start - offset, stop - offset);
                if cursor < start {
                    spans.push(Span::styled(
                        span.content[cursor..start].to_owned(),
                        span.style,
                    ));
                }
                spans.push(Span::styled(
                    span.content[start..stop].to_owned(),
                    span.style.patch(self.theme.search_match()),
                ));
                cursor = stop;
            }
            if cursor < span.content.len() {
                spans.push(Span::styled(span.content[cursor..].to_owned(), span.style));
            }
            offset = end;
        }
        line.spans = spans;
        line
    }
}

fn decode_line(raw: &str) -> Line<'static> {
    let mut line = match raw.into_text() {
        Ok(text) => text.lines.into_iter().next().unwrap_or_default(),
        Err(_) => Line::raw(raw.to_owned()),
    };
    // Unrecognized control bytes must never reach terminal cells, even on fallback.
    for span in &mut line.spans {
        if span.content.chars().any(char::is_control) {
            span.content = span
                .content
                .chars()
                .filter(|ch| !ch.is_control())
                .collect::<String>()
                .into();
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::widgets::test_support::{ascii_frame, SIZES};
    use ratatui::{backend::TestBackend, style::Color, Terminal};

    fn draw(
        terminal: &mut Terminal<TestBackend>,
        buffer: &ServiceLogBuffer,
        query: &str,
        active: bool,
    ) {
        terminal
            .draw(|frame| {
                LogPane {
                    service_name: Some("api"),
                    buffer: Some(buffer),
                    query,
                    search_active: active,
                    focused: true,
                    theme: &Theme,
                }
                .render(frame, frame.area())
            })
            .unwrap();
    }

    #[test]
    fn ansi_colors_search_across_spans_unicode_and_warning_styles() {
        for (width, height) in SIZES {
            let mut buffer = ServiceLogBuffer::default();
            buffer.push("\x1b[31mred\x1b[0m plain");
            buffer.push("\x1b[32mer\x1b[34mror\x1b[0m 中文 error");
            buffer.push("\x1b[31m[WARN: 20 lines omitted in TUI due to high output rate]\x1b[0m");
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            draw(&mut terminal, &buffer, "", false);
            let text = ascii_frame(&terminal);
            assert!(text.contains("red plain"));
            assert!(!text.contains('\x1b'));
            assert_eq!(terminal.backend().buffer()[(1, 1)].fg, Color::Red);
            assert_eq!(terminal.backend().buffer()[(5, 1)].fg, Color::Reset);
            assert_eq!(terminal.backend().buffer()[(1, 3)].fg, Color::Yellow);
            crate::widgets::test_support::assert_border(&terminal, Rect::new(0, 0, width, height));
            draw(&mut terminal, &buffer, "error", true);
            let text = ascii_frame(&terminal);
            assert!(text.contains("1/3"));
            assert!(text.contains("/ error_"));
            assert!(!text.contains("red plain"));
            for x in 1..=5 {
                assert_eq!(terminal.backend().buffer()[(x, 2)].bg, Color::Yellow);
            }
            assert_ne!(terminal.backend().buffer()[(6, 2)].bg, Color::Yellow);
            draw(&mut terminal, &buffer, "中文", true);
            assert_eq!(terminal.backend().buffer()[(7, 2)].bg, Color::Yellow);
            draw(&mut terminal, &buffer, "absent", true);
            let text = ascii_frame(&terminal);
            assert!(text.contains("0/3"));
            assert!(text.contains("No matches"));
        }
    }

    #[test]
    fn ring_is_bounded_and_follow_manual_scroll_and_eviction_are_visible() {
        for (width, height) in SIZES {
            let mut buffer = ServiceLogBuffer::default();
            assert!(buffer.is_empty());
            assert!(buffer.scroll_locked);
            for index in 0..5_100 {
                buffer.push(format!("row-{index:04}"));
            }
            assert_eq!(buffer.len(), 5_000);
            assert_eq!(buffer.total_received(), 5_100);
            assert_eq!(buffer.evicted_lines(), 100);
            assert!(buffer.overflowed());
            assert_eq!(buffer.lines().front().unwrap(), "row-0100");
            assert_eq!(buffer.lines().back().unwrap(), "row-5099");
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            draw(&mut terminal, &buffer, "", false);
            let text = ascii_frame(&terminal);
            assert!(text.contains("[FOLLOW] 5000/5000"));
            assert!(text.contains("row-5099"));
            assert!(!text.contains("row-0100"));
            assert!(text.contains("Received 5100 | Evicted 100"));
            buffer.scroll_locked = false;
            buffer.scroll_offset = 10;
            buffer.push("row-5100");
            assert_eq!(buffer.scroll_offset, 9);
            draw(&mut terminal, &buffer, "", false);
            let text = ascii_frame(&terminal);
            assert!(text.contains("[LOCKED]"));
            assert!(text.contains("row-0110"));
            assert!(!text.contains("row-5100"));
            buffer.scroll_offset = usize::MAX;
            draw(&mut terminal, &buffer, "", false);
            assert!(ascii_frame(&terminal).contains("row-5100"));
            // Filtered offsets are clamped against the filtered set, not raw history.
            draw(&mut terminal, &buffer, "row-0200", false);
            assert!(ascii_frame(&terminal).contains("row-0200"));
        }
    }

    #[test]
    fn empty_multiline_and_malformed_input_stays_inside_borders() {
        for (width, height) in SIZES {
            let mut buffer = ServiceLogBuffer::default();
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            draw(&mut terminal, &buffer, "", false);
            assert!(ascii_frame(&terminal).contains("No logs yet"));
            buffer.push("first\r\nsecond\n");
            buffer.push("");
            buffer.push("invalid\x1b[garbage\x07");
            assert_eq!(buffer.len(), 4);
            assert_eq!(buffer.lines()[0], "first");
            assert_eq!(buffer.lines()[1], "second");
            draw(&mut terminal, &buffer, "", false);
            let text = ascii_frame(&terminal);
            assert!(text.contains("first"));
            assert!(text.contains("second"));
            assert!(!text.contains('\x1b'));
            assert!(!text.contains('\x07'));
            crate::widgets::test_support::assert_border(&terminal, Rect::new(0, 0, width, height));
        }
    }
}
