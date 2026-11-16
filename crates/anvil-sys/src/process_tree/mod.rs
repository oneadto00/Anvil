//! Cross-platform process tree isolation, identity fingerprinting, and termination.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use self::unix as imp;
#[cfg(windows)]
use self::windows as imp;

use crate::error::SysError;
use std::path::Path;
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::{Pid, ProcessRefreshKind, System, UpdateKind};

/// Kernel-level identity snapshot captured when a managed child process is attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSpawnIdentity {
    /// Operating system process ID.
    pub pid: u32,
    /// Process group ID (`PGID == PID` on Unix; `pid` fallback on Windows).
    pub pgid: u32,
    /// Process start timestamp in seconds since Unix epoch for PID-reuse validation.
    pub start_time_secs: u64,
    /// Executable file name (or process name fallback) reported by the OS.
    pub exe_name: String,
}

impl ProcessSpawnIdentity {
    /// Checks the live PID's kernel start timestamp before using a recorded identity.
    pub fn matches_start_time(pid: u32, expected: u64) -> bool {
        let mut system = System::new();
        let pid = Pid::from_u32(pid);
        system.refresh_process_specifics(pid, ProcessRefreshKind::new());
        system
            .process(pid)
            .is_some_and(|process| process.start_time() == expected)
    }
}

/// Safe RAII handle representing ownership over an isolated OS process tree.
///
/// On Unix this tracks the isolated process group ID (`pgid`); on Windows it holds
/// an owned Win32 Job Object handle configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
#[derive(Debug)]
pub struct ManagedProcessHandle {
    pub(crate) inner: imp::PlatformProcessHandle,
}

impl ManagedProcessHandle {
    /// Returns the root OS process ID associated with this managed handle.
    pub const fn pid(&self) -> u32 {
        self.inner.pid
    }

    /// Returns the process group ID associated with this managed handle.
    pub const fn pgid(&self) -> u32 {
        self.inner.pgid
    }
}

/// Builds a command line for the platform shell in an isolated process tree.
pub fn build_shell_command(cmd_line: &str, cwd: Option<&Path>) -> Command {
    let mut cmd = imp::shell_command(cmd_line);
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    imp::prepare_command(&mut cmd);
    cmd
}

/// Returns the exit code and, on Unix, the terminating signal.
pub fn extract_exit_status(status: &ExitStatus) -> (Option<i32>, Option<i32>) {
    (status.code(), imp::exit_signal(status))
}

/// Safe cross-platform abstraction for process-tree isolation and teardown.
pub trait ProcessController: Send + Sync {
    /// Configures `cmd` prior to spawning so the child executes in an isolated process tree.
    fn prepare_command(&self, cmd: &mut Command) -> Result<(), SysError>;

    /// Attaches a freshly spawned `child` to kernel-level process tree tracking and
    /// captures its [`ProcessSpawnIdentity`] fingerprint.
    fn attach_child(
        &self,
        child: &Child,
    ) -> Result<(ManagedProcessHandle, ProcessSpawnIdentity), SysError>;

    /// Attaches a freshly spawned, isolated child by PID while its owner retains the child.
    fn attach_pid(
        &self,
        pid: u32,
    ) -> Result<(ManagedProcessHandle, ProcessSpawnIdentity), SysError> {
        imp::attach_pid(pid)
    }

    /// Terminates the process tree owned by `handle` using a graceful-then-forceful strategy.
    fn terminate_handle(
        &self,
        handle: &ManagedProcessHandle,
        grace_period: Duration,
    ) -> Result<(), SysError>;

    /// Terminates a process tree identified by `(pid, pgid)` (for example during orphan recovery).
    fn terminate_process_tree(
        &self,
        pid: u32,
        pgid: u32,
        grace_period: Duration,
    ) -> Result<(), SysError>;

    /// Returns `true` if `pid` currently corresponds to a live, non-zombie OS process.
    fn is_process_alive(&self, pid: u32) -> bool;
}

/// Default OS-backed implementation of [`ProcessController`].
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultProcessController;

impl DefaultProcessController {
    /// Creates a new [`DefaultProcessController`].
    pub const fn new() -> Self {
        Self
    }
}

impl ProcessController for DefaultProcessController {
    fn prepare_command(&self, cmd: &mut Command) -> Result<(), SysError> {
        imp::prepare_command(cmd);
        Ok(())
    }

    fn attach_child(
        &self,
        child: &Child,
    ) -> Result<(ManagedProcessHandle, ProcessSpawnIdentity), SysError> {
        imp::attach_child(child)
    }

    fn terminate_handle(
        &self,
        handle: &ManagedProcessHandle,
        grace_period: Duration,
    ) -> Result<(), SysError> {
        imp::terminate_handle(handle, grace_period)
    }

    fn terminate_process_tree(
        &self,
        pid: u32,
        pgid: u32,
        grace_period: Duration,
    ) -> Result<(), SysError> {
        imp::terminate_process_tree(pid, pgid, grace_period)
    }

    fn is_process_alive(&self, pid: u32) -> bool {
        imp::is_process_alive(pid)
    }
}

/// Queries `(start_time_secs, exe_name)` for `pid` using `sysinfo`.
///
/// Falls back to the current Unix epoch timestamp and `"unknown"` if the process
/// exited before metadata could be inspected.
pub(crate) fn query_process_metadata(pid: u32) -> (u64, String) {
    let mut sys = System::new();
    let sys_pid = Pid::from_u32(pid);
    let refresh_kind = ProcessRefreshKind::new().with_exe(UpdateKind::OnlyIfNotSet);
    sys.refresh_process_specifics(sys_pid, refresh_kind);

    if let Some(proc_info) = sys.process(sys_pid) {
        let start_time_secs = proc_info.start_time();
        let exe_name = proc_info
            .exe()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .or_else(|| {
                let name = proc_info.name();
                (!name.is_empty()).then(|| name.to_owned())
            })
            .unwrap_or_else(|| "unknown".to_owned());
        (start_time_secs, exe_name)
    } else {
        let fallback_start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|dur| dur.as_secs())
            .unwrap_or(0);
        (fallback_start, "unknown".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_controller_reports_current_process_alive_and_prepares_command() {
        let controller = DefaultProcessController::new();
        assert!(controller.is_process_alive(std::process::id()));
        assert!(!controller.is_process_alive(0));

        let mut cmd = Command::new("echo");
        controller.prepare_command(&mut cmd).unwrap();
    }

    #[cfg(unix)]
    fn find_child_pids(parent_pid: u32) -> Vec<u32> {
        let mut sys = System::new();
        sys.refresh_processes();
        let target_parent = Pid::from_u32(parent_pid);
        sys.processes()
            .values()
            .filter(|proc_info| proc_info.parent() == Some(target_parent))
            .map(|proc_info| proc_info.pid().as_u32())
            .collect()
    }

    #[cfg(unix)]
    #[test]
    fn unix_terminates_nested_grandchild_process_tree() {
        use std::thread;

        let controller = DefaultProcessController::new();
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "sleep 60 & wait"]);
        controller.prepare_command(&mut cmd).unwrap();

        let mut child = cmd.spawn().unwrap();
        let (handle, identity) = controller.attach_child(&child).unwrap();
        let sh_pid = child.id();

        assert_eq!(handle.pid(), sh_pid);
        assert_eq!(handle.pgid(), sh_pid);
        assert_eq!(identity.pid, sh_pid);
        assert_eq!(identity.pgid, sh_pid);
        assert!(!identity.exe_name.is_empty());
        assert!(controller.is_process_alive(sh_pid));

        // Wait briefly for `sh` to fork the background `sleep 60` grandchild.
        let mut grandchild_pids = Vec::new();
        for _ in 0..40 {
            grandchild_pids = find_child_pids(sh_pid);
            if !grandchild_pids.is_empty() {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }

        assert!(
            !grandchild_pids.is_empty(),
            "expected shell process {sh_pid} to spawn grandchild sleep process"
        );
        let sleep_pid = grandchild_pids[0];
        assert!(controller.is_process_alive(sleep_pid));

        controller
            .terminate_handle(&handle, Duration::from_millis(200))
            .unwrap();
        let _ = child.wait();

        // Give the kernel/init a brief moment to finish reaping reparented grandchildren.
        let mut both_gone = false;
        for _ in 0..40 {
            if !controller.is_process_alive(sh_pid) && !controller.is_process_alive(sleep_pid) {
                both_gone = true;
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }

        assert!(
            both_gone,
            "expected both sh ({sh_pid}) and grandchild sleep ({sleep_pid}) to terminate"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_escalates_to_sigkill_when_sigterm_is_ignored() {
        use std::thread;

        let controller = DefaultProcessController::new();
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "trap '' TERM; sleep 60 & wait"]);
        controller.prepare_command(&mut cmd).unwrap();

        let mut child = cmd.spawn().unwrap();
        let (handle, _) = controller.attach_child(&child).unwrap();
        let sh_pid = child.id();

        let mut grandchild_pids = Vec::new();
        for _ in 0..40 {
            grandchild_pids = find_child_pids(sh_pid);
            if !grandchild_pids.is_empty() {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }

        assert!(
            !grandchild_pids.is_empty(),
            "expected shell process {sh_pid} to spawn grandchild sleep process"
        );
        let sleep_pid = grandchild_pids[0];

        controller
            .terminate_handle(&handle, Duration::from_millis(100))
            .unwrap();
        let _ = child.wait();

        let mut both_gone = false;
        for _ in 0..40 {
            if !controller.is_process_alive(sh_pid) && !controller.is_process_alive(sleep_pid) {
                both_gone = true;
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }

        assert!(
            both_gone,
            "expected SIGKILL escalation to terminate both sh ({sh_pid}) and grandchild ({sleep_pid})"
        );
    }
}
