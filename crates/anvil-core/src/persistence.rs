//! Workspace-scoped service logs, immutable crash reports and native lock records.

use crate::log_ring::{LogEntry, LogSource};
use crate::{RuntimeIdentity, ServiceId};
use anvil_sys::{LockRecord, LockfileStore, SysError};
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, ErrorKind, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};
use thiserror::Error;
use tokio::{io::AsyncWriteExt, sync::mpsc, task::spawn_blocking};

/// Failures reported to the caller of a persistence operation.
#[derive(Debug, Error)]
pub enum PersistenceError {
    /// The default Anvil directory could not be resolved.
    #[error("could not determine the user's home directory")]
    HomeUnavailable,
    /// A project or service name cannot be used as a single path component.
    #[error("invalid {0} path component")]
    InvalidName(&'static str),
    /// A descendant of the configured root is a link or an unexpected file type.
    #[error("unexpected file type at {}", .0.display())]
    UnsafePath(PathBuf),
    /// A filesystem operation failed.
    #[error("persistence I/O failed: {0}")]
    Io(#[from] io::Error),
    /// The crash report could not be encoded.
    #[error("could not encode crash report: {0}")]
    Encoding(#[from] serde_yaml::Error),
    /// The native lockfile store rejected an operation.
    #[error(transparent)]
    Lockfile(#[from] SysError),
    /// A blocking filesystem worker did not finish.
    #[error("persistence worker did not finish")]
    Worker(#[source] tokio::task::JoinError),
}

/// Facts about one failed launch. The caller supplies a sanitized reason and the
/// ordered sample obtained from the service's M4 log collector separately.
#[derive(Serialize)]
pub struct CrashInfo {
    /// Configured service ID.
    pub service_id: ServiceId,
    /// Actor-assigned instance generation.
    pub generation: u64,
    /// Created instance, if startup reached that stage.
    pub identity: Option<RuntimeIdentity>,
    /// Time the failure was observed.
    pub occurred_at: SystemTime,
    /// Runtime exit status, when reported.
    pub exit_code: Option<i64>,
    /// Native termination signal, when reported.
    pub signal: Option<i32>,
    /// Sanitized, display-ready diagnostic.
    pub redacted_reason: String,
}

#[derive(Serialize)]
struct CrashFile<'a> {
    project: &'a str,
    #[serde(flatten)]
    info: &'a CrashInfo,
    tail: Vec<DiskEntry<'a>>,
}

#[derive(Serialize)]
struct DiskEntry<'a> {
    timestamp: SystemTime,
    source: &'static str,
    body: &'a str,
}

impl<'a> From<&'a LogEntry> for DiskEntry<'a> {
    fn from(entry: &'a LogEntry) -> Self {
        let source = match entry.source {
            LogSource::Stdout => "stdout",
            LogSource::Stderr => "stderr",
            LogSource::System => "system",
        };
        Self {
            timestamp: entry.timestamp,
            source,
            body: &entry.redacted_body,
        }
    }
}

/// Persistence for one project under a user-controlled Anvil data directory.
#[derive(Clone)]
pub struct WorkspacePersistence {
    root: PathBuf,
    project: String,
}

impl WorkspacePersistence {
    /// Select the default `~/.anvil` root. Directories are created on first write.
    pub fn new(project: &str) -> Result<Self, PersistenceError> {
        let home = std::env::home_dir().ok_or(PersistenceError::HomeUnavailable)?;
        Self::with_root(home.join(".anvil"), project)
    }

    /// Use an explicit Anvil data root (the parent of `logs` and `run`).
    pub fn with_root(root: impl Into<PathBuf>, project: &str) -> Result<Self, PersistenceError> {
        validate_name(project, "project")?;
        if project.chars().any(char::is_whitespace) {
            return Err(PersistenceError::InvalidName("project"));
        }
        Ok(Self {
            root: root.into(),
            project: project.to_owned(),
        })
    }

    /// Drain one service's complete M4.2 stream into its append-only log, with one
    /// timestamp (Unix nanoseconds), source and redacted body per line. Return the
    /// path after the stream closes and all writes have been flushed and synced.
    pub async fn write_service_log(
        &self,
        service: &str,
        mut input: mpsc::Receiver<LogEntry>,
    ) -> Result<PathBuf, PersistenceError> {
        validate_name(service, "service")?;
        let name = format!("{service}.log");
        let workspace = self.clone();
        let (path, file) = spawn_blocking(move || -> Result<_, PersistenceError> {
            let path = workspace
                .directory(&["logs", &workspace.project])?
                .join(name);
            check_regular_or_missing(&path)?;
            let file = OpenOptions::new().create(true).append(true).open(&path)?;
            Ok((path, file))
        })
        .await
        .map_err(PersistenceError::Worker)??;

        let mut file = tokio::fs::File::from_std(file);
        let mut entries = Vec::new();
        let mut bytes = Vec::new();
        while input.recv_many(&mut entries, 128).await > 0 {
            for entry in entries.drain(..) {
                let line = DiskEntry::from(&entry);
                let nanos = match line.timestamp.duration_since(SystemTime::UNIX_EPOCH) {
                    Ok(d) => d.as_nanos() as i128,
                    Err(e) => -(e.duration().as_nanos() as i128),
                };
                writeln!(bytes, "[{nanos} {}] {}", line.source, line.body)?;
            }
            file.write_all(&bytes).await?;
            bytes.clear();
        }
        file.flush().await?;
        file.sync_data().await?;
        Ok(path)
    }

    /// Atomically publish one YAML report with the supplied tail in ingestion order.
    /// Even concurrent reports with identical service, generation and time are retained.
    pub async fn write_crash(
        &self,
        info: CrashInfo,
        tail: Vec<LogEntry>,
    ) -> Result<PathBuf, PersistenceError> {
        validate_name(&info.service_id, "service")?;
        let workspace = self.clone();
        spawn_blocking(move || {
            let dir =
                workspace.directory(&["logs", &workspace.project, "crashes", &info.service_id])?;
            let mut tmp = tempfile::Builder::new()
                .prefix(&format!("instance-{}-", info.generation))
                .suffix(".tmp")
                .tempfile_in(dir)?;
            let report = CrashFile {
                project: &workspace.project,
                info: &info,
                tail: tail.iter().map(DiskEntry::from).collect(),
            };
            serde_yaml::to_writer(tmp.as_file_mut(), &report)?;
            tmp.as_file().sync_all()?;
            let mut path = tmp.path().with_extension("yaml");
            let mut collision = 0u64;
            loop {
                match tmp.persist_noclobber(&path) {
                    Ok(_) => return Ok(path),
                    Err(e) if e.error.kind() == ErrorKind::AlreadyExists => {
                        tmp = e.file;
                        collision += 1;
                        path = tmp.path().with_extension(format!("{collision}.yaml"));
                    }
                    Err(e) => return Err(e.error.into()),
                }
            }
        })
        .await
        .map_err(PersistenceError::Worker)?
    }

    /// Insert or replace a native process fingerprint using the sys lockfile schema.
    pub async fn record_native(&self, record: LockRecord) -> Result<(), PersistenceError> {
        validate_name(&record.service_id, "service")?;
        self.update_lockfile(move |store, project| store.record_process(project, record))
            .await
    }

    /// Remove only the recorded instance. A delayed exit for an older process
    /// leaves its replacement's fingerprint intact.
    pub async fn remove_native(&self, record: LockRecord) -> Result<(), PersistenceError> {
        self.remove_matching(record.service_id.clone(), move |item| item == &record)
            .await
    }

    /// Remove the registered process group for a confirmed runtime exit. The
    /// executor's executable label is not part of the process identity.
    pub(crate) async fn remove_native_instance(
        &self,
        service: &str,
        identity: &RuntimeIdentity,
    ) -> Result<(), PersistenceError> {
        let RuntimeIdentity::NativeProcess {
            pid,
            pgid,
            start_time_secs,
        } = *identity
        else {
            return Ok(());
        };
        validate_name(service, "service")?;
        let path = LockfileStore::with_dir(self.root.join("run")).lockfile_path(&self.project)?;
        match tokio::fs::symlink_metadata(path).await {
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err.into()),
            Ok(_) => {}
        }
        self.remove_matching(service.to_owned(), move |item| {
            item.pid == pid && item.pgid == pgid && item.start_time_secs == start_time_secs
        })
        .await
    }

    async fn remove_matching(
        &self,
        service: String,
        matches: impl Fn(&LockRecord) -> bool + Send + 'static,
    ) -> Result<(), PersistenceError> {
        validate_name(&service, "service")?;
        self.update_lockfile(move |store, project| {
            if store.load_workspace(project)?.is_some_and(|workspace| {
                workspace
                    .processes
                    .iter()
                    .any(|item| item.service_id == service && matches(item))
            }) {
                store.remove_service(project, &service)?;
            }
            Ok(())
        })
        .await
    }

    async fn update_lockfile(
        &self,
        update: impl FnOnce(&LockfileStore, &str) -> Result<(), SysError> + Send + 'static,
    ) -> Result<(), PersistenceError> {
        let workspace = self.clone();
        spawn_blocking(move || {
            let dir = workspace.directory(&["run"])?;
            // Lock a stable sibling because LockfileStore replaces the JSON inode.
            let guard_path = dir.join(format!("{}.guard", workspace.project));
            check_regular_or_missing(&guard_path)?;
            let guard = File::options()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(guard_path)?;
            guard.lock()?;
            let store = LockfileStore::with_dir(dir);
            check_regular_or_missing(&store.lockfile_path(&workspace.project)?)?;
            update(&store, &workspace.project)?;
            Ok(())
        })
        .await
        .map_err(PersistenceError::Worker)?
    }

    fn directory(&self, components: &[&str]) -> Result<PathBuf, PersistenceError> {
        fs::create_dir_all(&self.root)?;
        let mut path = self.root.clone();
        for component in components {
            path.push(component);
            match fs::create_dir(&path) {
                Ok(()) => (),
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    if !fs::symlink_metadata(&path)?.is_dir() {
                        return Err(PersistenceError::UnsafePath(path));
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(path)
    }
}

fn check_regular_or_missing(path: &Path) -> Result<(), PersistenceError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => Ok(()),
        Ok(_) => Err(PersistenceError::UnsafePath(path.to_owned())),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn validate_name(name: &str, field: &'static str) -> Result<(), PersistenceError> {
    // Apply portable component rules even when preparing paths on a Unix host.
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end()
        .to_ascii_uppercase();
    let device = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
        .is_some_and(|n| {
            matches!(
                n,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        });
    if name.is_empty()
        || name.ends_with(['.', ' '])
        || name.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|'])
        || name.chars().any(char::is_control)
        || device
    {
        return Err(PersistenceError::InvalidName(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_ring::{LogIngestor, LogInput};
    use anvil_secret::SecretValue;
    use std::{sync::Arc, time::Duration};
    use tempfile::tempdir;
    use tokio::{
        sync::{oneshot, Barrier},
        task::JoinSet,
    };

    fn info(service: &str) -> CrashInfo {
        CrashInfo {
            service_id: service.into(),
            generation: 7,
            identity: Some(RuntimeIdentity::NativeProcess {
                pid: 123,
                pgid: 120,
                start_time_secs: 10,
            }),
            occurred_at: SystemTime::UNIX_EPOCH + Duration::from_secs(20),
            exit_code: None,
            signal: Some(9),
            redacted_reason: "process terminated".into(),
        }
    }

    fn entry(i: u64, body: String) -> LogEntry {
        LogEntry {
            source: if i.is_multiple_of(2) {
                LogSource::Stderr
            } else {
                LogSource::Stdout
            },
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(i),
            redacted_body: body.into(),
        }
    }

    fn record(service: &str, pid: u32) -> LockRecord {
        LockRecord {
            service_id: service.into(),
            pid,
            pgid: pid,
            start_time_secs: 10,
            exe_name: "worker".into(),
        }
    }

    async fn append(
        workspace: &WorkspacePersistence,
        service: &str,
        body: &str,
    ) -> Result<PathBuf, PersistenceError> {
        let (tx, rx) = mpsc::channel(1);
        tx.send(entry(0, body.into())).await.unwrap();
        drop(tx);
        workspace.write_service_log(service, rx).await
    }

    #[tokio::test]
    async fn complete_log_and_crash_tail_round_trip_without_secret() {
        const N: usize = 3;
        let dir = tempdir().unwrap();
        let workspace = WorkspacePersistence::with_root(dir.path(), "demo").unwrap();
        let secret = SecretValue::new("TEST_ONLY_private_token_36da02");
        let (complete, rx) = mpsc::channel(1);
        let (ui, _batches) = mpsc::channel(1);
        let (input, messages) = mpsc::channel(2);
        let ingest = LogIngestor::new("api".into(), complete, ui);
        let collector = tokio::spawn(ingest.run(messages));
        let service_workspace = workspace.clone();
        let writer =
            tokio::spawn(async move { service_workspace.write_service_log("api", rx).await });

        for i in 0..N + 2 {
            input
                .send(LogInput::Line(entry(
                    i as u64,
                    format!("line {i}, token={secret}"),
                )))
                .await
                .unwrap();
        }
        let (reply, tail) = oneshot::channel();
        input
            .send(LogInput::Tail { count: N, reply })
            .await
            .unwrap();
        let mut crash = info("api");
        crash.redacted_reason = format!("process terminated, token={secret}");
        let path = workspace
            .write_crash(crash, tail.await.unwrap())
            .await
            .unwrap();
        drop(input);
        collector.await.unwrap().unwrap();
        let log = writer.await.unwrap().unwrap();
        assert_eq!(log, dir.path().join("logs/demo/api.log"));
        let text = fs::read_to_string(&log).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), N + 2);
        for (i, line) in lines.iter().enumerate() {
            let source = if i.is_multiple_of(2) {
                "stderr"
            } else {
                "stdout"
            };
            assert_eq!(
                *line,
                format!(
                    "[{} {source}] line {i}, token=[REDACTED]",
                    i * 1_000_000_000u64 as usize
                )
            );
        }

        let report: serde_yaml::Value =
            serde_yaml::from_reader(File::open(&path).unwrap()).unwrap();
        assert_eq!(report["service_id"], "api");
        assert_eq!(report["project"], "demo");
        assert_eq!(report["generation"], 7);
        assert_eq!(
            report["identity"],
            serde_yaml::to_value(info("api").identity).unwrap()
        );
        assert_eq!(
            report["occurred_at"],
            serde_yaml::to_value(info("api").occurred_at).unwrap()
        );
        assert!(report["exit_code"].is_null());
        assert_eq!(report["signal"], 9);
        assert_eq!(
            report["redacted_reason"],
            "process terminated, token=[REDACTED]"
        );
        let tail = report["tail"].as_sequence().unwrap();
        assert_eq!(tail.len(), N);
        for (i, item) in (2..N + 2).zip(tail) {
            assert_eq!(
                item["body"].as_str().unwrap(),
                format!("line {i}, token=[REDACTED]")
            );
            assert_eq!(
                item["source"],
                if i.is_multiple_of(2) {
                    "stderr"
                } else {
                    "stdout"
                }
            );
            assert_eq!(
                item["timestamp"]["secs_since_epoch"].as_u64(),
                Some(i as u64)
            );
        }

        workspace.record_native(record("api", 123)).await.unwrap();
        for artifact in [
            log,
            path,
            dir.path().join("run/demo.lock.json"),
            dir.path().join("run/demo.guard"),
        ] {
            assert!(!fs::read_to_string(artifact)
                .unwrap()
                .contains(secret.as_str()));
        }
    }

    #[tokio::test]
    async fn repeated_crashes_keep_each_report_even_at_the_same_instant() {
        let dir = tempdir().unwrap();
        let workspace = WorkspacePersistence::with_root(dir.path(), "demo").unwrap();
        let save = |code| {
            let mut crash = info("api");
            crash.signal = None;
            crash.exit_code = Some(code);
            workspace.write_crash(crash, vec![])
        };
        let (a, b) = tokio::join!(save(22), save(33));
        let paths = [a.unwrap(), b.unwrap(), save(44).await.unwrap()];
        assert_eq!(fs::read_dir(paths[0].parent().unwrap()).unwrap().count(), 3);
        for (code, path) in [22, 33, 44].into_iter().zip(paths) {
            let report: serde_yaml::Value =
                serde_yaml::from_reader(File::open(path).unwrap()).unwrap();
            assert_eq!(report["exit_code"], code);
            assert_eq!(report["tail"].as_sequence().unwrap().len(), 0);
        }
    }

    #[tokio::test]
    async fn append_preserves_previous_runs_and_isolates_project_and_service() {
        let dir = tempdir().unwrap();
        let a = WorkspacePersistence::with_root(dir.path(), "a").unwrap();
        let b = WorkspacePersistence::with_root(dir.path(), "b").unwrap();
        let log = append(&a, "api", "first").await.unwrap();
        assert_eq!(append(&a, "api", "second").await.unwrap(), log);
        let other_project = append(&b, "api", "third").await.unwrap();
        let other_service = append(&a, "db", "fourth").await.unwrap();
        assert_eq!(
            fs::read_to_string(log).unwrap(),
            "[0 stderr] first\n[0 stderr] second\n"
        );
        assert_eq!(
            fs::read_to_string(other_project).unwrap(),
            "[0 stderr] third\n"
        );
        assert_eq!(
            fs::read_to_string(other_service).unwrap(),
            "[0 stderr] fourth\n"
        );
    }

    #[tokio::test]
    async fn invalid_components_cannot_escape_the_root() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("data");
        let workspace = WorkspacePersistence::with_root(&root, "demo").unwrap();
        for name in [
            "",
            ".",
            "..",
            "../escape",
            "/escape",
            r"..\escape",
            r"C:\escape",
            "C:escape",
            "NUL.txt",
            ".. ",
        ] {
            assert!(matches!(
                WorkspacePersistence::with_root(&root, name),
                Err(PersistenceError::InvalidName("project"))
            ));
            assert!(matches!(
                append(&workspace, name, "log").await,
                Err(PersistenceError::InvalidName("service"))
            ));
            assert!(matches!(
                workspace.write_crash(info(name), vec![]).await,
                Err(PersistenceError::InvalidName("service"))
            ));
        }
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn failed_writes_return_typed_errors_and_clean_up_unpublished_reports() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("occupied");
        fs::write(&root, "existing").unwrap();
        let workspace = WorkspacePersistence::with_root(&root, "demo").unwrap();
        assert!(matches!(
            append(&workspace, "api", "line").await,
            Err(PersistenceError::Io(_))
        ));
        assert!(matches!(
            workspace.write_crash(info("api"), vec![]).await,
            Err(PersistenceError::Io(_))
        ));
        assert_eq!(fs::read_to_string(root).unwrap(), "existing");

        let workspace = WorkspacePersistence::with_root(dir.path(), "demo").unwrap();
        // Serde's SystemTime representation rejects pre-epoch timestamps during encoding.
        let mut bad = info("api");
        bad.occurred_at = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
        assert!(matches!(
            workspace.write_crash(bad, vec![]).await,
            Err(PersistenceError::Encoding(_))
        ));
        assert_eq!(
            fs::read_dir(dir.path().join("logs/demo/crashes/api"))
                .unwrap()
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn concurrent_lock_updates_preserve_peers_and_ignore_stale_exit() {
        let dir = tempdir().unwrap();
        let barrier = Arc::new(Barrier::new(8));
        let mut tasks = JoinSet::new();
        for i in 0..8 {
            let workspace = WorkspacePersistence::with_root(dir.path(), "demo").unwrap();
            let barrier = barrier.clone();
            tasks.spawn(async move {
                barrier.wait().await;
                workspace
                    .record_native(record(&format!("service-{i}"), 100 + i))
                    .await
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }
        let store = LockfileStore::with_dir(dir.path().join("run"));
        let lock = store.load_workspace("demo").unwrap().unwrap();
        assert_eq!(lock.processes.len(), 8);
        for i in 0..8 {
            assert!(lock
                .processes
                .contains(&record(&format!("service-{i}"), 100 + i)));
        }
        let workspace = WorkspacePersistence::with_root(dir.path(), "demo").unwrap();
        let replacement = record("service-0", 200);
        workspace.record_native(replacement.clone()).await.unwrap();
        workspace
            .remove_native(record("service-0", 100))
            .await
            .unwrap();
        assert!(store
            .load_workspace("demo")
            .unwrap()
            .unwrap()
            .processes
            .contains(&replacement));
        workspace.remove_native(replacement).await.unwrap();
        let remaining = store.load_workspace("demo").unwrap().unwrap().processes;
        assert_eq!(remaining.len(), 7);
        assert!(remaining.iter().all(|item| item.service_id != "service-0"));
    }
}
