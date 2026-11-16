//! Unix process group (`setpgid` / `killpg`) implementation.

use crate::error::SysError;
use crate::process_tree::{query_process_metadata, ManagedProcessHandle, ProcessSpawnIdentity};
use nix::errno::Errno;
use nix::sys::signal::{kill, killpg, Signal};
use nix::unistd::{getpgid, Pid};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::{Pid as SysPid, ProcessRefreshKind, ProcessStatus, System};

#[derive(Debug)]
pub(crate) struct PlatformProcessHandle {
    pub(crate) pid: u32,
    pub(crate) pgid: u32,
}

pub(crate) fn prepare_command(cmd: &mut Command) -> Result<(), SysError> {
    // Setting `process_group(0)` places the child in a new process group whose
    // PGID equals its PID without requiring an `unsafe` `pre_exec` hook.
    cmd.process_group(0);
    Ok(())
}

pub(crate) fn attach_child(
    child: &Child,
) -> Result<(ManagedProcessHandle, ProcessSpawnIdentity), SysError> {
    let pid = child.id();
    let raw_pid = i32::try_from(pid).map_err(|_| {
        SysError::ProcessGroupSetup(format!("spawned child PID {pid} overflows i32"))
    })?;
    if raw_pid <= 0 {
        return Err(SysError::ProcessGroupSetup(format!(
            "spawned child PID {pid} is not positive"
        )));
    }

    let (start_time_secs, exe_name) = query_process_metadata(pid);
    let handle = ManagedProcessHandle {
        inner: PlatformProcessHandle { pid, pgid: pid },
    };
    let identity = ProcessSpawnIdentity {
        pid,
        pgid: pid,
        start_time_secs,
        exe_name,
    };
    Ok((handle, identity))
}

pub(crate) fn terminate_handle(
    handle: &ManagedProcessHandle,
    grace_period: Duration,
) -> Result<(), SysError> {
    terminate_process_tree(handle.inner.pid, handle.inner.pgid, grace_period)
}

pub(crate) fn terminate_process_tree(
    pid: u32,
    pgid: u32,
    grace_period: Duration,
) -> Result<(), SysError> {
    let raw_target = if pgid > 0 { pgid } else { pid };
    let target_i32 = i32::try_from(raw_target).map_err(|_| SysError::TerminationFailed {
        pid,
        reason: format!("target PGID {raw_target} overflows i32"),
    })?;
    if target_i32 <= 0 {
        return Err(SysError::TerminationFailed {
            pid,
            reason: format!("target PGID {raw_target} must be positive"),
        });
    }

    let target_pgid = Pid::from_raw(target_i32);

    // Phase 1: Graceful shutdown via SIGTERM to the entire process group.
    match killpg(target_pgid, Signal::SIGTERM) {
        Ok(()) => {}
        Err(Errno::ESRCH) => return Ok(()),
        Err(Errno::EPERM) if !has_live_process_in_group(target_pgid, pid) => return Ok(()),
        Err(err) => {
            return Err(SysError::TerminationFailed {
                pid,
                reason: format!("SIGTERM to process group {raw_target} failed: {err}"),
            });
        }
    }

    let poll_interval = Duration::from_millis(30);
    let deadline = Instant::now() + grace_period;
    loop {
        match killpg(target_pgid, None) {
            Err(Errno::ESRCH) => return Ok(()),
            Ok(()) => {
                if !has_live_process_in_group(target_pgid, pid) {
                    return Ok(());
                }
            }
            Err(Errno::EPERM) => {
                // On macOS, signaling a process group containing only unreaped zombies
                // yields `EPERM`. Treat that as exited once no live member remains.
                if !has_live_process_in_group(target_pgid, pid) {
                    return Ok(());
                }
                return Err(SysError::TerminationFailed {
                    pid,
                    reason: format!("permission denied polling process group {raw_target}"),
                });
            }
            Err(err) => {
                return Err(SysError::TerminationFailed {
                    pid,
                    reason: format!("failed polling process group {raw_target}: {err}"),
                });
            }
        }

        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let sleep_for = deadline.saturating_duration_since(now).min(poll_interval);
        thread::sleep(sleep_for);
    }

    // Phase 2: Grace period expired; escalate to SIGKILL across the process group.
    match killpg(target_pgid, Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(Errno::EPERM) if !has_live_process_in_group(target_pgid, pid) => Ok(()),
        Err(err) => Err(SysError::TerminationFailed {
            pid,
            reason: format!("SIGKILL to process group {raw_target} failed: {err}"),
        }),
    }
}

pub(crate) fn is_process_alive(pid: u32) -> bool {
    let Ok(raw_pid) = i32::try_from(pid) else {
        return false;
    };
    if raw_pid <= 0 {
        return false;
    }

    let kill_res = kill(Pid::from_raw(raw_pid), None);
    match kill_res {
        Err(Errno::ESRCH) => return false,
        Ok(()) | Err(Errno::EPERM) => {}
        Err(_) => return false,
    }

    // Distinguish live processes from unreaped zombies still present in the process table.
    let mut sys = System::new();
    let sys_pid = SysPid::from_u32(pid);
    if sys.refresh_process_specifics(sys_pid, ProcessRefreshKind::new()) {
        if let Some(proc_info) = sys.process(sys_pid) {
            return !matches!(
                proc_info.status(),
                ProcessStatus::Zombie | ProcessStatus::Dead
            );
        }
    }

    // On macOS, `sysinfo` omits `SZOMB` zombies while `kill(pid, 0)` still returns `Ok(())`.
    // Only report alive on fallback when `EPERM` proves a live cross-user process exists.
    matches!(kill_res, Err(Errno::EPERM))
}

fn has_live_process_in_group(target_pgid: Pid, leader_pid: u32) -> bool {
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessRefreshKind::new());
    sys.processes().values().any(|proc_info| {
        if matches!(
            proc_info.status(),
            ProcessStatus::Zombie | ProcessStatus::Dead
        ) {
            return false;
        }
        let pid_u32 = proc_info.pid().as_u32();
        let Ok(raw_pid) = i32::try_from(pid_u32) else {
            return false;
        };
        if raw_pid <= 0 {
            return false;
        }
        pid_u32 == leader_pid
            || matches!(getpgid(Some(Pid::from_raw(raw_pid))), Ok(p) if p == target_pgid)
    })
}
