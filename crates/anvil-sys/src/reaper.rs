//! Crash recovery lockfile persistence and PID-reuse-safe orphan process reaping.

use crate::error::SysError;
use crate::process_tree::ProcessController;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use sysinfo::{Pid, ProcessRefreshKind, ProcessStatus, System, UpdateKind};

/// Schema version written into [`WorkspaceLockfile::version`].
pub const LOCKFILE_VERSION: u8 = 1;

/// Recorded process identity and fingerprint for an active service instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockRecord {
    /// Service identifier within `anvil.yaml`.
    pub service_id: String,
    /// Operating system process ID.
    pub pid: u32,
    /// Operating system process group ID (`PGID` on Unix; `pid` fallback on Windows).
    pub pgid: u32,
    /// Process start timestamp in seconds since Unix epoch for PID-reuse verification.
    pub start_time_secs: u64,
    /// Executable file name (or process name fallback) captured at spawn time.
    pub exe_name: String,
}

/// Persisted runtime lockfile describing all processes tracked for a workspace project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceLockfile {
    /// Lockfile schema version (currently [`LOCKFILE_VERSION`]).
    pub version: u8,
    /// Workspace project name owning these process records.
    pub project_name: String,
    /// Active or stale recorded service processes.
    pub processes: Vec<LockRecord>,
}

/// Summary produced by [`LockfileStore::reap_orphans`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReapReport {
    /// Number of verified orphan process trees terminated.
    pub reaped: usize,
    /// Number of lock records skipped because the PID already exited or failed fingerprint matching.
    pub skipped_pid_reuse: usize,
    /// Records whose process trees matched the fingerprint and were terminated.
    pub reaped_records: Vec<LockRecord>,
    /// Records skipped due to PID exit or PID-reuse fingerprint mismatch.
    pub skipped_records: Vec<LockRecord>,
}

/// Atomic lockfile persistence and orphan recovery store under `~/.anvil/run` (or custom dir).
#[derive(Debug, Clone)]
pub struct LockfileStore {
    base_dir: PathBuf,
}

impl LockfileStore {
    /// Creates a [`LockfileStore`] rooted at the default `~/.anvil/run` directory.
    pub fn new() -> Result<Self, SysError> {
        let home = dirs::home_dir().ok_or_else(|| {
            SysError::Io(std::io::Error::new(
                ErrorKind::NotFound,
                "could not determine user home directory",
            ))
        })?;
        Ok(Self {
            base_dir: home.join(".anvil").join("run"),
        })
    }

    /// Creates a [`LockfileStore`] rooted at a custom `base_dir` (primarily for isolated tests).
    pub fn with_dir(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    /// Resolves and validates the lockfile path for `project`.
    pub fn lockfile_path(&self, project: &str) -> Result<PathBuf, SysError> {
        validate_project_name(project)?;
        Ok(self.base_dir.join(format!("{project}.lock.json")))
    }

    /// Loads the persisted [`WorkspaceLockfile`] for `project`, returning `Ok(None)` if absent.
    pub fn load_workspace(&self, project: &str) -> Result<Option<WorkspaceLockfile>, SysError> {
        let path = self.lockfile_path(project)?;
        let content = match fs::read_to_string(&path) {
            Ok(data) => data,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(SysError::Io(err)),
        };

        let lockfile: WorkspaceLockfile = serde_json::from_str(&content).map_err(|err| {
            SysError::InvalidLockfile(format!("failed to parse {}: {err}", path.display()))
        })?;

        if lockfile.version != LOCKFILE_VERSION {
            return Err(SysError::InvalidLockfile(format!(
                "unsupported lockfile version {} in {}",
                lockfile.version,
                path.display()
            )));
        }

        Ok(Some(lockfile))
    }

    /// Atomically inserts or replaces a [`LockRecord`] for `record.service_id` in `project`.
    pub fn record_process(&self, project: &str, record: LockRecord) -> Result<(), SysError> {
        if record.service_id.is_empty() {
            return Err(SysError::InvalidLockfile(
                "lock record service_id must not be empty".to_owned(),
            ));
        }

        let path = self.lockfile_path(project)?;
        let mut lockfile = match self.load_workspace(project)? {
            Some(existing) => existing,
            None => WorkspaceLockfile {
                version: LOCKFILE_VERSION,
                project_name: project.to_owned(),
                processes: Vec::new(),
            },
        };

        if let Some(slot) = lockfile
            .processes
            .iter_mut()
            .find(|entry| entry.service_id == record.service_id)
        {
            *slot = record;
        } else {
            lockfile.processes.push(record);
        }

        let serialized = serde_json::to_vec_pretty(&lockfile).map_err(|err| {
            SysError::InvalidLockfile(format!("failed to serialize lockfile: {err}"))
        })?;
        atomic_write(&path, &serialized)
    }

    /// Removes the [`LockRecord`] matching `service_id` from `project`'s lockfile.
    ///
    /// Deletes the lockfile completely if no records remain.
    pub fn remove_service(&self, project: &str, service_id: &str) -> Result<(), SysError> {
        let Some(mut lockfile) = self.load_workspace(project)? else {
            return Ok(());
        };

        let original_len = lockfile.processes.len();
        lockfile
            .processes
            .retain(|entry| entry.service_id != service_id);

        if lockfile.processes.is_empty() {
            return self.clear_workspace(project);
        }

        if lockfile.processes.len() != original_len {
            let path = self.lockfile_path(project)?;
            let serialized = serde_json::to_vec_pretty(&lockfile).map_err(|err| {
                SysError::InvalidLockfile(format!("failed to serialize lockfile: {err}"))
            })?;
            atomic_write(&path, &serialized)?;
        }

        Ok(())
    }

    /// Removes `project`'s lockfile from disk, succeeding cleanly if it does not exist.
    pub fn clear_workspace(&self, project: &str) -> Result<(), SysError> {
        let path = self.lockfile_path(project)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(SysError::Io(err)),
        }
    }

    /// Inspects all recorded processes for `project`, terminates verified orphans, skips stale or
    /// PID-reused entries, and removes the processed lockfile.
    pub fn reap_orphans<C: ProcessController>(
        &self,
        project: &str,
        controller: &C,
        grace_period: Duration,
    ) -> Result<ReapReport, SysError> {
        let Some(lockfile) = self.load_workspace(project)? else {
            return Ok(ReapReport::default());
        };

        let mut report = ReapReport::default();

        for record in lockfile.processes {
            if matches_process_fingerprint(controller, &record) {
                controller.terminate_process_tree(record.pid, record.pgid, grace_period)?;
                report.reaped += 1;
                report.reaped_records.push(record);
            } else {
                report.skipped_pid_reuse += 1;
                report.skipped_records.push(record);
            }
        }

        self.clear_workspace(project)?;
        Ok(report)
    }
}

fn matches_process_fingerprint<C: ProcessController>(controller: &C, record: &LockRecord) -> bool {
    if record.pid == 0 || !controller.is_process_alive(record.pid) {
        return false;
    }

    let mut sys = System::new();
    let sys_pid = Pid::from_u32(record.pid);
    let refresh_kind = ProcessRefreshKind::new().with_exe(UpdateKind::OnlyIfNotSet);
    if !sys.refresh_process_specifics(sys_pid, refresh_kind) {
        return false;
    }

    let Some(proc_info) = sys.process(sys_pid) else {
        return false;
    };

    if matches!(
        proc_info.status(),
        ProcessStatus::Zombie | ProcessStatus::Dead
    ) {
        return false;
    }

    if proc_info.start_time().abs_diff(record.start_time_secs) > 1 {
        return false;
    }

    let live_exe_name = extract_live_exe_name(proc_info);
    if !record.exe_name.is_empty()
        && record.exe_name != "unknown"
        && !live_exe_name.is_empty()
        && live_exe_name != "unknown"
        && !exe_names_match(&live_exe_name, &record.exe_name)
    {
        return false;
    }

    true
}

fn extract_live_exe_name(proc_info: &sysinfo::Process) -> String {
    proc_info
        .exe()
        .and_then(|path| path.file_name())
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            let name = proc_info.name();
            (!name.is_empty()).then(|| name.to_owned())
        })
        .unwrap_or_default()
}

fn exe_names_match(live: &str, recorded: &str) -> bool {
    #[cfg(windows)]
    {
        live.eq_ignore_ascii_case(recorded)
    }
    #[cfg(not(windows))]
    {
        live == recorded
    }
}

fn validate_project_name(project: &str) -> Result<(), SysError> {
    if project.is_empty()
        || project.contains('/')
        || project.contains('\\')
        || project.contains('\0')
        || project.chars().any(char::is_whitespace)
    {
        return Err(SysError::InvalidLockfile(format!(
            "invalid project name '{project}'"
        )));
    }
    let mut components = Path::new(project).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(SysError::InvalidLockfile(format!(
            "invalid project name '{project}'"
        ))),
    }
}

fn atomic_write(target: &Path, bytes: &[u8]) -> Result<(), SysError> {
    let parent = target.parent().ok_or_else(|| {
        SysError::Io(std::io::Error::new(
            ErrorKind::InvalidInput,
            "lockfile path has no parent directory",
        ))
    })?;
    fs::create_dir_all(parent)?;

    let mut suffix = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let tmp_name = format!(
        ".{}.tmp.{:016x}",
        target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("anvil"),
        u64::from_le_bytes(suffix)
    );
    let tmp_path = parent.join(tmp_name);

    let write_res = (|| -> Result<(), SysError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = fs::rename(&tmp_path, target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(SysError::Io(err));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_tree::DefaultProcessController;
    use tempfile::TempDir;

    #[test]
    fn lockfile_store_crud_and_project_validation() {
        let dir = TempDir::new().unwrap();
        let store = LockfileStore::with_dir(dir.path());

        assert!(store.lockfile_path("../escape").is_err());
        assert!(store.lockfile_path("").is_err());
        assert!(store.load_workspace("demo").unwrap().is_none());

        store
            .record_process(
                "demo",
                LockRecord {
                    service_id: "api".to_owned(),
                    pid: 1001,
                    pgid: 1001,
                    start_time_secs: 1_700_000_000,
                    exe_name: "node".to_owned(),
                },
            )
            .unwrap();
        store
            .record_process(
                "demo",
                LockRecord {
                    service_id: "db".to_owned(),
                    pid: 1002,
                    pgid: 1002,
                    start_time_secs: 1_700_000_005,
                    exe_name: "postgres".to_owned(),
                },
            )
            .unwrap();

        let loaded = store.load_workspace("demo").unwrap().unwrap();
        assert_eq!(loaded.version, LOCKFILE_VERSION);
        assert_eq!(loaded.processes.len(), 2);

        store.remove_service("demo", "api").unwrap();
        let after_remove = store.load_workspace("demo").unwrap().unwrap();
        assert_eq!(after_remove.processes.len(), 1);
        assert_eq!(after_remove.processes[0].service_id, "db");

        store.remove_service("demo", "db").unwrap();
        assert!(store.load_workspace("demo").unwrap().is_none());
    }

    #[test]
    fn reap_orphans_skips_mismatched_live_pid_across_platforms() {
        let dir = TempDir::new().unwrap();
        let store = LockfileStore::with_dir(dir.path());
        let controller = DefaultProcessController::new();
        let self_pid = std::process::id();

        store
            .record_process(
                "cross-platform-reuse",
                LockRecord {
                    service_id: "self".to_owned(),
                    pid: self_pid,
                    pgid: self_pid,
                    start_time_secs: 0,
                    exe_name: "not-anvil-test".to_owned(),
                },
            )
            .unwrap();

        let report = store
            .reap_orphans("cross-platform-reuse", &controller, Duration::from_millis(50))
            .unwrap();
        assert_eq!(report.reaped, 0);
        assert_eq!(report.skipped_pid_reuse, 1);
        assert!(controller.is_process_alive(self_pid));
        assert!(store.load_workspace("cross-platform-reuse").unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn reap_orphans_terminates_verified_child_process() {
        use std::process::Command;

        let dir = TempDir::new().unwrap();
        let store = LockfileStore::with_dir(dir.path());
        let controller = DefaultProcessController::new();

        let mut cmd = Command::new("sleep");
        cmd.arg("60");
        controller.prepare_command(&mut cmd).unwrap();
        let mut child = cmd.spawn().unwrap();
        let (_handle, identity) = controller.attach_child(&child).unwrap();

        store
            .record_process(
                "reap-test",
                LockRecord {
                    service_id: "sleeper".to_owned(),
                    pid: identity.pid,
                    pgid: identity.pgid,
                    start_time_secs: identity.start_time_secs,
                    exe_name: identity.exe_name.clone(),
                },
            )
            .unwrap();

        let report = store
            .reap_orphans("reap-test", &controller, Duration::from_millis(200))
            .unwrap();
        let _ = child.wait();

        assert_eq!(report.reaped, 1);
        assert_eq!(report.skipped_pid_reuse, 0);
        assert!(!controller.is_process_alive(identity.pid));
        assert!(store.load_workspace("reap-test").unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn reap_orphans_skips_process_when_start_time_fingerprint_mismatches() {
        use std::process::Command;

        let dir = TempDir::new().unwrap();
        let store = LockfileStore::with_dir(dir.path());
        let controller = DefaultProcessController::new();

        let mut cmd = Command::new("sleep");
        cmd.arg("60");
        controller.prepare_command(&mut cmd).unwrap();
        let mut child = cmd.spawn().unwrap();
        let (handle, identity) = controller.attach_child(&child).unwrap();

        // Forge start_time_secs off by 3600 seconds to simulate OS PID reuse.
        let forged_start_time = identity.start_time_secs.saturating_add(3600);
        store
            .record_process(
                "reuse-test",
                LockRecord {
                    service_id: "sleeper".to_owned(),
                    pid: identity.pid,
                    pgid: identity.pgid,
                    start_time_secs: forged_start_time,
                    exe_name: identity.exe_name.clone(),
                },
            )
            .unwrap();

        let report = store
            .reap_orphans("reuse-test", &controller, Duration::from_millis(200))
            .unwrap();

        assert_eq!(report.reaped, 0);
        assert_eq!(report.skipped_pid_reuse, 1);
        assert!(
            controller.is_process_alive(identity.pid),
            "process with mismatched start_time_secs must not be killed"
        );
        assert!(store.load_workspace("reuse-test").unwrap().is_none());

        controller
            .terminate_handle(&handle, Duration::from_millis(200))
            .unwrap();
        let _ = child.wait();
    }
}
