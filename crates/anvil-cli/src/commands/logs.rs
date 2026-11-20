//! Tail and follow persisted per-service or aggregated workspace logs.

use super::ps::{resolve_data_dir, validate_name_component};
use crate::{
    args::GlobalOptions,
    terminal::{subscribe_shutdown_signal, wait_for_shutdown},
};
use anvil_core::AnvilConfig;
use std::{
    collections::HashSet,
    fs::{self, File},
    io::{self, BufRead, BufReader, BufWriter, ErrorKind, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::sync::watch;

const TAIL_CHUNK_SIZE: usize = 8192;
const FOLLOW_POLL_INTERVAL: Duration = Duration::from_millis(100);

pub(crate) trait LogSink {
    fn emit(&mut self, line: &str) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;
}

struct WriterSink<W: Write> {
    writer: BufWriter<W>,
}

impl<W: Write> WriterSink<W> {
    fn new(inner: W) -> Self {
        Self {
            writer: BufWriter::new(inner),
        }
    }
}

impl<W: Write> LogSink for WriterSink<W> {
    fn emit(&mut self, line: &str) -> io::Result<()> {
        writeln!(self.writer, "{line}")
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

struct TailRead {
    lines: Vec<String>,
    end_offset: u64,
}

struct TrackedLog {
    service: String,
    path: PathBuf,
    offset: u64,
    partial: Vec<u8>,
}

struct AggregatedLine {
    service: String,
    index: usize,
    timestamp_nanos: Option<i128>,
    text: String,
}

/// Executes the `anvil logs` subcommand.
pub async fn execute(
    globals: GlobalOptions,
    service: Option<String>,
    follow: bool,
    tail: usize,
) -> anyhow::Result<()> {
    let shutdown_rx = if follow {
        subscribe_shutdown_signal()?
    } else {
        let (_tx, rx) = watch::channel(true);
        rx
    };

    let mut sink = WriterSink::new(io::stdout());
    run_logs_with_sink(&globals, service, follow, tail, shutdown_rx, &mut sink).await
}

pub(crate) async fn run_logs_with_sink<S: LogSink>(
    globals: &GlobalOptions,
    service: Option<String>,
    follow: bool,
    tail: usize,
    mut shutdown_rx: watch::Receiver<bool>,
    sink: &mut S,
) -> anyhow::Result<()> {
    let data_dir = resolve_data_dir(globals.data_dir.as_deref())?;
    let (project, config) = resolve_logs_project(globals).await?;
    validate_name_component(&project, "project")?;

    if let Some(svc) = service.as_deref() {
        validate_name_component(svc, "service")?;
    }

    let log_dir = data_dir.join("logs").join(&project);
    let multi_service = service.is_none();
    let mut tracked = Vec::new();

    if let Some(svc) = service {
        let path = log_dir.join(format!("{svc}.log"));
        let exists = tokio::fs::try_exists(&path).await?;
        if !exists {
            if !follow {
                anyhow::bail!(
                    "log file not found for service '{svc}' at {}",
                    path.display()
                );
            }
            if let Some(cfg) = &config {
                if !cfg.services.contains_key(&svc) {
                    anyhow::bail!(
                        "unknown service '{svc}' and no log file exists at {}",
                        path.display()
                    );
                }
            }
            tracked.push(TrackedLog {
                service: svc,
                path,
                offset: 0,
                partial: Vec::new(),
            });
        } else {
            let path_for_read = path.clone();
            let tail_read = tokio::task::spawn_blocking(move || {
                read_tail_lines_blocking(&path_for_read, tail)
            })
            .await
            .map_err(|err| anyhow::anyhow!("log tail reader task failed: {err}"))??;

            for line in tail_read.lines {
                sink.emit(&line)?;
            }
            sink.flush()?;

            tracked.push(TrackedLog {
                service: svc,
                path,
                offset: tail_read.end_offset,
                partial: Vec::new(),
            });
        }
    } else {
        let dir_for_scan = log_dir.clone();
        let files = tokio::task::spawn_blocking(move || discover_log_files_blocking(&dir_for_scan))
            .await
            .map_err(|err| anyhow::anyhow!("log directory scan task failed: {err}"))??;

        let mut aggregated = Vec::new();
        for (svc, path) in files {
            let path_for_read = path.clone();
            let tail_read = tokio::task::spawn_blocking(move || {
                read_tail_lines_blocking(&path_for_read, tail)
            })
            .await
            .map_err(|err| anyhow::anyhow!("log tail reader task failed: {err}"))??;

            for (index, line) in tail_read.lines.into_iter().enumerate() {
                let timestamp_nanos = parse_anvil_timestamp_nanos(&line);
                aggregated.push(AggregatedLine {
                    service: svc.clone(),
                    index,
                    timestamp_nanos,
                    text: line,
                });
            }

            tracked.push(TrackedLog {
                service: svc,
                path,
                offset: tail_read.end_offset,
                partial: Vec::new(),
            });
        }

        if !aggregated.is_empty() && aggregated.iter().all(|item| item.timestamp_nanos.is_some()) {
            aggregated.sort_by(|a, b| {
                a.timestamp_nanos
                    .cmp(&b.timestamp_nanos)
                    .then_with(|| a.service.cmp(&b.service))
                    .then_with(|| a.index.cmp(&b.index))
            });
        }

        for item in aggregated {
            sink.emit(&format!("[{}] {}", item.service, item.text))?;
        }
        sink.flush()?;
    }

    if !follow {
        return Ok(());
    }

    let mut known_services: HashSet<String> = tracked.iter().map(|t| t.service.clone()).collect();
    let mut poll_tick = tokio::time::interval(FOLLOW_POLL_INTERVAL);
    poll_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if *shutdown_rx.borrow() {
            break;
        }
        tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown_rx) => break,
            _ = poll_tick.tick() => {
                if multi_service {
                    let dir_for_scan = log_dir.clone();
                    let discovered = tokio::task::spawn_blocking(move || {
                        discover_log_files_blocking(&dir_for_scan)
                    })
                    .await
                    .map_err(|err| anyhow::anyhow!("log directory scan task failed: {err}"))??;

                    for (svc, path) in discovered {
                        if known_services.insert(svc.clone()) {
                            tracked.push(TrackedLog {
                                service: svc,
                                path,
                                offset: 0,
                                partial: Vec::new(),
                            });
                        }
                    }
                }

                let mut emitted_any = false;
                for entry in &mut tracked {
                    let path_for_poll = entry.path.clone();
                    let offset = entry.offset;
                    let partial = std::mem::take(&mut entry.partial);

                    let (next_offset, next_partial, new_lines) = tokio::task::spawn_blocking(move || {
                        poll_log_delta_blocking(&path_for_poll, offset, partial)
                    })
                    .await
                    .map_err(|err| anyhow::anyhow!("log follow poll task failed: {err}"))??;

                    entry.offset = next_offset;
                    entry.partial = next_partial;

                    for line in new_lines {
                        if multi_service {
                            sink.emit(&format!("[{}] {line}", entry.service))?;
                        } else {
                            sink.emit(&line)?;
                        }
                        emitted_any = true;
                    }
                }

                if emitted_any {
                    sink.flush()?;
                }
            }
        }
    }

    Ok(())
}

async fn resolve_logs_project(
    globals: &GlobalOptions,
) -> anyhow::Result<(String, Option<AnvilConfig>)> {
    if let Some(proj) = &globals.project {
        return Ok((proj.clone(), None));
    }

    if !tokio::fs::try_exists(&globals.config).await? {
        anyhow::bail!(
            "configuration file '{}' not found and --project was not specified",
            globals.config.display()
        );
    }

    let raw = tokio::fs::read_to_string(&globals.config).await?;
    let cfg = AnvilConfig::from_yaml_str(&raw)?;
    Ok((cfg.project.name.clone(), Some(cfg)))
}

fn discover_log_files_blocking(log_dir: &Path) -> anyhow::Result<Vec<(String, PathBuf)>> {
    let entries = match fs::read_dir(log_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };

    let mut files = Vec::new();
    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("log") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if !stem.is_empty() {
            files.push((stem.to_owned(), path));
        }
    }

    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

/// Reads up to the last `tail` lines by scanning backwards in fixed chunks so huge logs
/// never get loaded completely into memory.
fn read_tail_lines_blocking(path: &Path, tail: usize) -> anyhow::Result<TailRead> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    if file_len == 0 {
        return Ok(TailRead {
            lines: Vec::new(),
            end_offset: 0,
        });
    }
    if tail == 0 {
        return Ok(TailRead {
            lines: Vec::new(),
            end_offset: file_len,
        });
    }

    let mut buf = [0u8; TAIL_CHUNK_SIZE];
    let mut pos = file_len;
    let mut newlines_found: usize = 0;
    let mut inspected_last_byte = false;
    let mut start_offset: u64 = 0;

    'scan: while pos > 0 {
        let chunk_len = usize::try_from(pos.min(TAIL_CHUNK_SIZE as u64)).unwrap_or(TAIL_CHUNK_SIZE);
        let chunk_start = pos - chunk_len as u64;
        file.seek(SeekFrom::Start(chunk_start))?;
        file.read_exact(&mut buf[..chunk_len])?;

        for idx in (0..chunk_len).rev() {
            let byte_pos = chunk_start + idx as u64;
            if byte_pos == file_len - 1 && !inspected_last_byte {
                inspected_last_byte = true;
                if buf[idx] == b'\n' {
                    continue;
                }
            }
            if buf[idx] == b'\n' {
                newlines_found += 1;
                if newlines_found == tail {
                    start_offset = byte_pos + 1;
                    break 'scan;
                }
            }
        }
        pos = chunk_start;
    }

    file.seek(SeekFrom::Start(start_offset))?;
    let mut reader = BufReader::new(file.take(file_len - start_offset));
    let mut lines = Vec::new();
    let mut raw_line = Vec::new();
    loop {
        raw_line.clear();
        let bytes = reader.read_until(b'\n', &mut raw_line)?;
        if bytes == 0 {
            break;
        }
        lines.push(decode_trimmed_line(&raw_line));
    }

    Ok(TailRead {
        lines,
        end_offset: file_len,
    })
}

fn poll_log_delta_blocking(
    path: &Path,
    mut offset: u64,
    mut partial: Vec<u8>,
) -> anyhow::Result<(u64, Vec<u8>, Vec<String>)> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok((0, Vec::new(), Vec::new())),
        Err(err) => return Err(err.into()),
    };

    let len = file.metadata()?.len();
    if len < offset {
        offset = 0;
        partial.clear();
    }
    if len == offset {
        return Ok((offset, partial, Vec::new()));
    }

    file.seek(SeekFrom::Start(offset))?;
    let to_read = len - offset;
    let mut limited = file.take(to_read);
    let mut chunk = [0u8; TAIL_CHUNK_SIZE];
    let mut lines = Vec::new();
    let mut total_read: u64 = 0;

    loop {
        let n = limited.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        total_read += n as u64;
        for segment in chunk[..n].split_inclusive(|&b| b == b'\n') {
            if let Some(without_nl) = segment.strip_suffix(b"\n") {
                partial.extend_from_slice(without_nl);
                let clean = partial.strip_suffix(b"\r").unwrap_or(&partial);
                lines.push(String::from_utf8_lossy(clean).into_owned());
                partial.clear();
            } else {
                partial.extend_from_slice(segment);
            }
        }
    }

    Ok((offset + total_read, partial, lines))
}

fn decode_trimmed_line(raw: &[u8]) -> String {
    let trimmed = raw.strip_suffix(b"\n").unwrap_or(raw);
    let trimmed = trimmed.strip_suffix(b"\r").unwrap_or(trimmed);
    String::from_utf8_lossy(trimmed).into_owned()
}

fn parse_anvil_timestamp_nanos(line: &str) -> Option<i128> {
    let rest = line.strip_prefix('[')?;
    let header_end = rest.find(']')?;
    let header = &rest[..header_end];
    let (nanos_str, source) = header.split_once(' ')?;
    if !matches!(source, "stdout" | "stderr" | "system") {
        return None;
    }
    nanos_str.parse::<i128>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal::ShutdownSignal;
    use tempfile::tempdir;
    use tokio::sync::mpsc;

    #[derive(Default)]
    struct CollectSink {
        lines: Vec<String>,
    }

    impl LogSink for CollectSink {
        fn emit(&mut self, line: &str) -> io::Result<()> {
            self.lines.push(line.to_owned());
            Ok(())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct ChannelSink {
        tx: mpsc::UnboundedSender<String>,
    }

    impl LogSink for ChannelSink {
        fn emit(&mut self, line: &str) -> io::Result<()> {
            let _ = self.tx.send(line.to_owned());
            Ok(())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn logs_reads_exact_tail_lines_for_single_and_multi_service_logs() -> anyhow::Result<()> {
        let data_dir = tempdir()?;
        let logs_dir = data_dir.path().join("logs").join("demo");
        tokio::fs::create_dir_all(logs_dir.join("crashes")).await?;

        // Build multi-chunk log file (>16KB) for api to exercise reverse chunked seeking.
        let mut api_content = String::new();
        for i in 1..=300 {
            let ts = i * 2;
            api_content.push_str(&format!(
                "[{ts} stdout] api-line-{i:03} padding-to-exceed-chunk-boundary-0123456789abcdef0123456789abcdef\n"
            ));
        }
        tokio::fs::write(logs_dir.join("api.log"), api_content).await?;

        let mut db_content = String::new();
        for i in 1..=20 {
            let ts = (280 + i) * 2 + 1;
            db_content.push_str(&format!("[{ts} stderr] db-line-{i:02}\n"));
        }
        tokio::fs::write(logs_dir.join("db.log"), db_content).await?;

        let globals = GlobalOptions {
            config: data_dir.path().join("nonexistent-anvil.yaml"),
            data_dir: Some(data_dir.path().to_path_buf()),
            project: Some("demo".to_owned()),
        };

        let (_tx, rx) = watch::channel(true);
        let mut single_sink = CollectSink::default();
        run_logs_with_sink(
            &globals,
            Some("api".to_owned()),
            false,
            3,
            rx,
            &mut single_sink,
        )
        .await?;
        assert_eq!(single_sink.lines.len(), 3);
        assert!(single_sink.lines[0].contains("api-line-298"));
        assert!(single_sink.lines[1].contains("api-line-299"));
        assert!(single_sink.lines[2].contains("api-line-300"));
        assert!(!single_sink.lines[0].starts_with("[api]"));

        let (_tx2, rx2) = watch::channel(true);
        let mut multi_sink = CollectSink::default();
        run_logs_with_sink(&globals, None, false, 2, rx2, &mut multi_sink).await?;
        assert_eq!(multi_sink.lines.len(), 4);
        assert!(multi_sink.lines[0].starts_with("[api] [598 stdout] api-line-299"));
        assert!(multi_sink.lines[1].starts_with("[db] [599 stderr] db-line-19"));
        assert!(multi_sink.lines[2].starts_with("[api] [600 stdout] api-line-300"));
        assert!(multi_sink.lines[3].starts_with("[db] [601 stderr] db-line-20"));

        Ok(())
    }

    #[tokio::test]
    async fn logs_follow_streams_appended_lines_and_stops_on_shutdown_signal() -> anyhow::Result<()>
    {
        let data_dir = tempdir()?;
        let logs_dir = data_dir.path().join("logs").join("follow-demo");
        tokio::fs::create_dir_all(&logs_dir).await?;
        let api_log = logs_dir.join("api.log");
        tokio::fs::write(&api_log, "initial-1\ninitial-2\n").await?;

        let globals = GlobalOptions {
            config: data_dir.path().join("missing.yaml"),
            data_dir: Some(data_dir.path().to_path_buf()),
            project: Some("follow-demo".to_owned()),
        };

        let signal = ShutdownSignal::new();
        let rx = signal.subscribe();
        let (tx, mut out_rx) = mpsc::unbounded_channel();

        let task = tokio::spawn(async move {
            let mut sink = ChannelSink { tx };
            run_logs_with_sink(&globals, Some("api".to_owned()), true, 1, rx, &mut sink).await
        });

        let first = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing initial tailed line"))?;
        assert_eq!(first, "initial-2");

        let path_append = api_log.clone();
        tokio::task::spawn_blocking(move || -> io::Result<()> {
            let mut file = fs::OpenOptions::new().append(true).open(path_append)?;
            writeln!(file, "appended-live-line")?;
            file.flush()?;
            Ok(())
        })
        .await??;

        let live = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing followed live line"))?;
        assert_eq!(live, "appended-live-line");

        signal.trigger();
        tokio::time::timeout(Duration::from_secs(2), task).await???;
        Ok(())
    }

    #[test]
    fn tail_reader_handles_empty_tail_zero_and_missing_trailing_newline() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let empty = dir.path().join("empty.log");
        fs::write(&empty, "")?;
        assert!(read_tail_lines_blocking(&empty, 10)?.lines.is_empty());

        let no_nl = dir.path().join("no_nl.log");
        fs::write(&no_nl, "first\nsecond\nthird")?;
        assert!(read_tail_lines_blocking(&no_nl, 0)?.lines.is_empty());
        assert_eq!(
            read_tail_lines_blocking(&no_nl, 2)?.lines,
            vec!["second".to_owned(), "third".to_owned()]
        );
        Ok(())
    }
}
