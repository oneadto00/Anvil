//! Two-stage cross-platform port conflict inspection and occupant attribution.

use crate::error::SysError;
use crate::process_tree::{DefaultProcessController, ProcessController};
use serde::{Deserialize, Serialize};
use std::io::ErrorKind;
use std::net::TcpListener;
use std::time::Duration;
use sysinfo::{Pid, ProcessRefreshKind, System, UpdateKind};

/// Metadata describing a live process holding a conflicting local TCP port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortOccupantInfo {
    /// Conflicting TCP port number.
    pub port: u16,
    /// Operating system process ID holding the listening socket.
    pub pid: u32,
    /// Process executable/display name reported by the OS.
    pub process_name: String,
    /// Full command line of the occupying process.
    pub cmdline: String,
}

/// Outcome of the two-stage port inspection performed by [`inspect_port`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortCheckResult {
    /// Both IPv4 and IPv6 loopback bind probes succeeded (or IPv6 is disabled on the host).
    Available,
    /// The port is already in use; `Some(info)` when attribution succeeded, or `None` when
    /// owned by a privileged/kernel socket whose PID cannot be inspected by the current user.
    Occupied(Option<PortOccupantInfo>),
}

/// Performs a two-stage check to determine whether `port` is available or occupied.
///
/// Stage 1 executes fast loopback bind probes (`127.0.0.1` and `::1`). Only when
/// `AddrInUse` is encountered does Stage 2 inspect OS socket tables and `sysinfo`
/// to attribute the owning process.
pub fn inspect_port(port: u16) -> Result<PortCheckResult, SysError> {
    if port == 0 {
        return Err(SysError::PortBindCheck {
            port,
            reason: "port 0 is not a valid service listening port".to_owned(),
        });
    }

    let mut in_use = false;

    match TcpListener::bind(("127.0.0.1", port)) {
        Ok(listener) => drop(listener),
        Err(err) if err.kind() == ErrorKind::AddrInUse => {
            in_use = true;
        }
        Err(err) if err.kind() == ErrorKind::AddrNotAvailable => {}
        Err(err) => {
            return Err(SysError::PortBindCheck {
                port,
                reason: format!("IPv4 loopback bind check failed: {err}"),
            });
        }
    }

    if !in_use {
        match TcpListener::bind(("::1", port)) {
            Ok(listener) => drop(listener),
            Err(err) if err.kind() == ErrorKind::AddrInUse => {
                in_use = true;
            }
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::AddrNotAvailable | ErrorKind::InvalidInput | ErrorKind::Unsupported
                ) => {}
            Err(err) => {
                return Err(SysError::PortBindCheck {
                    port,
                    reason: format!("IPv6 loopback bind check failed: {err}"),
                });
            }
        }
    }

    if !in_use {
        return Ok(PortCheckResult::Available);
    }

    let Some(pid) = find_listening_pid(port)? else {
        return Ok(PortCheckResult::Occupied(None));
    };

    let (process_name, cmdline) = query_occupant_process_details(pid);
    Ok(PortCheckResult::Occupied(Some(PortOccupantInfo {
        port,
        pid,
        process_name,
        cmdline,
    })))
}

/// Terminates the process occupying a port by `pid` (without signaling its entire process group).
///
/// Sends a graceful termination signal first, polls up to `grace_period`, and escalates to
/// forceful termination if the process has not exited.
pub fn kill_port_occupant(pid: u32, grace_period: Duration) -> Result<(), SysError> {
    platform::kill_port_occupant(pid, grace_period)
}

fn query_occupant_process_details(pid: u32) -> (String, String) {
    let mut sys = System::new();
    let sys_pid = Pid::from_u32(pid);
    let refresh_kind = ProcessRefreshKind::new()
        .with_exe(UpdateKind::OnlyIfNotSet)
        .with_cmd(UpdateKind::OnlyIfNotSet);
    sys.refresh_process_specifics(sys_pid, refresh_kind);

    if let Some(proc_info) = sys.process(sys_pid) {
        let process_name = if !proc_info.name().is_empty() {
            proc_info.name().to_owned()
        } else {
            proc_info
                .exe()
                .and_then(|path| path.file_name())
                .and_then(|name| name.to_str())
                .filter(|name| !name.is_empty())
                .unwrap_or("unknown")
                .to_owned()
        };

        let joined_cmd = proc_info.cmd().join(" ");
        let cmdline = if joined_cmd.is_empty() {
            process_name.clone()
        } else {
            joined_cmd
        };
        (process_name, cmdline)
    } else {
        ("unknown".to_owned(), String::new())
    }
}

fn find_listening_pid(port: u16) -> Result<Option<u32>, SysError> {
    platform::find_listening_pid(port)
}

#[cfg(unix)]
mod platform {
    use super::*;
    use nix::errno::Errno;
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid as NixPid;
    use std::collections::HashSet;
    use std::fs;
    use std::path::Path;
    use std::process::Command;
    use std::thread;
    use std::time::Instant;

    pub(super) fn find_listening_pid(port: u16) -> Result<Option<u32>, SysError> {
        let proc_tcp_available = Path::new("/proc/net/tcp").exists();
        if proc_tcp_available {
            if let Some(pid) = find_pid_via_proc_net(port) {
                return Ok(Some(pid));
            }
        }

        match find_pid_via_lsof(port) {
            Ok(Some(pid)) => Ok(Some(pid)),
            Ok(None) => Ok(None),
            Err(err) => {
                if proc_tcp_available {
                    Ok(None)
                } else {
                    Err(err)
                }
            }
        }
    }

    fn find_pid_via_proc_net(port: u16) -> Option<u32> {
        let mut inodes = HashSet::new();
        for table_path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            if let Ok(content) = fs::read_to_string(table_path) {
                collect_listening_inodes(&content, port, &mut inodes);
            }
        }
        if inodes.is_empty() {
            return None;
        }

        let proc_entries = fs::read_dir("/proc").ok()?;
        for entry in proc_entries.flatten() {
            let file_name = entry.file_name();
            let Some(pid_str) = file_name.to_str() else {
                continue;
            };
            let Ok(pid) = pid_str.parse::<u32>() else {
                continue;
            };
            if pid == 0 {
                continue;
            }

            let fd_dir = entry.path().join("fd");
            let Ok(fds) = fs::read_dir(fd_dir) else {
                continue;
            };
            for fd_entry in fds.flatten() {
                let Ok(link_target) = fs::read_link(fd_entry.path()) else {
                    continue;
                };
                let Some(target_str) = link_target.to_str() else {
                    continue;
                };
                if let Some(inode) = parse_socket_inode(target_str) {
                    if inodes.contains(&inode) {
                        return Some(pid);
                    }
                }
            }
        }

        None
    }

    fn collect_listening_inodes(content: &str, target_port: u16, out: &mut HashSet<u64>) {
        for line in content.lines().skip(1) {
            let mut cols = line.split_whitespace();
            let _sl = cols.next();
            let Some(local_addr) = cols.next() else {
                continue;
            };
            let _rem_addr = cols.next();
            let Some(state) = cols.next() else {
                continue;
            };
            if state != "0A" {
                continue;
            }
            let Some((_, port_hex)) = local_addr.rsplit_once(':') else {
                continue;
            };
            let Ok(parsed_port) = u16::from_str_radix(port_hex, 16) else {
                continue;
            };
            if parsed_port != target_port {
                continue;
            }
            // Columns 4..=8: tx_queue/rx_queue, tr/tm->when, retrnsmt, uid, timeout; col 9: inode.
            if let Some(inode_str) = cols.nth(5) {
                if let Ok(inode) = inode_str.parse::<u64>() {
                    if inode > 0 {
                        out.insert(inode);
                    }
                }
            }
        }
    }

    fn parse_socket_inode(link_target: &str) -> Option<u64> {
        link_target
            .strip_prefix("socket:[")
            .and_then(|rest| rest.strip_suffix(']'))
            .and_then(|inode_str| inode_str.parse::<u64>().ok())
    }

    fn find_pid_via_lsof(port: u16) -> Result<Option<u32>, SysError> {
        let port_filter = format!("-iTCP:{port}");
        let args = ["-nP", &port_filter, "-sTCP:LISTEN", "-Fp"];

        let output = match Command::new("lsof").args(args).output() {
            Ok(out) => out,
            Err(err) if err.kind() == ErrorKind::NotFound => Command::new("/usr/sbin/lsof")
                .args(args)
                .output()
                .map_err(|fallback_err| SysError::PortLookupFailed {
                    port,
                    reason: format!("failed to execute lsof: {fallback_err}"),
                })?,
            Err(err) => {
                return Err(SysError::PortLookupFailed {
                    port,
                    reason: format!("failed to execute lsof: {err}"),
                });
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some(pid_str) = line.strip_prefix('p') {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    if pid > 0 {
                        return Ok(Some(pid));
                    }
                }
            }
        }

        // `lsof` exits 1 when no matching listening socket is visible to the caller.
        Ok(None)
    }

    pub(super) fn kill_port_occupant(pid: u32, grace_period: Duration) -> Result<(), SysError> {
        let raw_pid = i32::try_from(pid).map_err(|_| SysError::TerminationFailed {
            pid,
            reason: format!("PID {pid} overflows i32"),
        })?;
        if raw_pid <= 0 {
            return Err(SysError::TerminationFailed {
                pid,
                reason: format!("PID {pid} must be positive"),
            });
        }

        let target_pid = NixPid::from_raw(raw_pid);
        let controller = DefaultProcessController::new();

        match kill(target_pid, Signal::SIGTERM) {
            Ok(()) => {}
            Err(Errno::ESRCH) => return Ok(()),
            Err(err) => {
                return Err(SysError::TerminationFailed {
                    pid,
                    reason: format!("SIGTERM to PID {pid} failed: {err}"),
                });
            }
        }

        let poll_interval = Duration::from_millis(30);
        let deadline = Instant::now() + grace_period;
        loop {
            if !controller.is_process_alive(pid) {
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            thread::sleep(deadline.saturating_duration_since(now).min(poll_interval));
        }

        match kill(target_pid, Signal::SIGKILL) {
            Ok(()) | Err(Errno::ESRCH) => {}
            Err(err) => {
                return Err(SysError::TerminationFailed {
                    pid,
                    reason: format!("SIGKILL to PID {pid} failed: {err}"),
                });
            }
        }

        let confirm_deadline = Instant::now() + Duration::from_millis(300);
        loop {
            if !controller.is_process_alive(pid) {
                return Ok(());
            }
            let now = Instant::now();
            if now >= confirm_deadline {
                break;
            }
            thread::sleep(
                confirm_deadline
                    .saturating_duration_since(now)
                    .min(Duration::from_millis(20)),
            );
        }

        Err(SysError::TerminationFailed {
            pid,
            reason: format!("process {pid} remained alive after SIGKILL"),
        })
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::c_void;
    use std::mem::{offset_of, size_of};
    use std::thread;
    use std::time::Instant;
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, FALSE, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
        MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    pub(super) fn find_listening_pid(port: u16) -> Result<Option<u32>, SysError> {
        if let Some(pid) = query_v4_listener_pid(port)? {
            return Ok(Some(pid));
        }
        query_v6_listener_pid(port)
    }

    fn fetch_tcp_table(port: u16, af: u32) -> Result<Vec<u8>, SysError> {
        let mut size: u32 = 0;
        // SAFETY: Passing a null buffer with `size = 0` queries the required buffer size.
        let initial_status = unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &raw mut size,
                FALSE,
                af,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if initial_status == NO_ERROR || size == 0 {
            return Ok(Vec::new());
        }
        if initial_status != ERROR_INSUFFICIENT_BUFFER {
            return Err(SysError::PortLookupFailed {
                port,
                reason: format!("GetExtendedTcpTable size query failed with code {initial_status}"),
            });
        }

        for _ in 0..4 {
            let mut buffer = vec![0u8; size as usize];
            // SAFETY: `buffer` has length `size` bytes, matching `*pdwsize` passed to
            // `GetExtendedTcpTable` for synchronous population.
            let status = unsafe {
                GetExtendedTcpTable(
                    buffer.as_mut_ptr().cast::<c_void>(),
                    &raw mut size,
                    FALSE,
                    af,
                    TCP_TABLE_OWNER_PID_LISTENER,
                    0,
                )
            };
            if status == NO_ERROR {
                return Ok(buffer);
            }
            if status != ERROR_INSUFFICIENT_BUFFER {
                return Err(SysError::PortLookupFailed {
                    port,
                    reason: format!("GetExtendedTcpTable query failed with code {status}"),
                });
            }
        }

        Err(SysError::PortLookupFailed {
            port,
            reason: "GetExtendedTcpTable kept growing past retry limit".to_owned(),
        })
    }

    fn query_v4_listener_pid(port: u16) -> Result<Option<u32>, SysError> {
        let buffer = fetch_tcp_table(port, u32::from(AF_INET))?;
        if buffer.len() < size_of::<u32>() {
            return Ok(None);
        }

        // SAFETY: `buffer.len() >= size_of::<u32>()`, and `read_unaligned` handles arbitrary alignment.
        let num_entries = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) } as usize;
        let table_offset = offset_of!(MIB_TCPTABLE_OWNER_PID, table);
        let row_size = size_of::<MIB_TCPROW_OWNER_PID>();

        for idx in 0..num_entries {
            let Some(row_offset) = idx
                .checked_mul(row_size)
                .and_then(|off| table_offset.checked_add(off))
            else {
                break;
            };
            let Some(end) = row_offset.checked_add(row_size) else {
                break;
            };
            if end > buffer.len() {
                break;
            }
            // SAFETY: `row_offset + row_size <= buffer.len()`, and `read_unaligned` safely reads
            // the `MIB_TCPROW_OWNER_PID` bytes without alignment assumptions.
            let row = unsafe {
                std::ptr::read_unaligned(buffer.as_ptr().add(row_offset).cast::<MIB_TCPROW_OWNER_PID>())
            };
            let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
            if local_port == port && row.dwOwningPid > 0 {
                return Ok(Some(row.dwOwningPid));
            }
        }

        Ok(None)
    }

    fn query_v6_listener_pid(port: u16) -> Result<Option<u32>, SysError> {
        let buffer = fetch_tcp_table(port, u32::from(AF_INET6))?;
        if buffer.len() < size_of::<u32>() {
            return Ok(None);
        }

        // SAFETY: `buffer.len() >= size_of::<u32>()`, and `read_unaligned` handles arbitrary alignment.
        let num_entries = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) } as usize;
        let table_offset = offset_of!(MIB_TCP6TABLE_OWNER_PID, table);
        let row_size = size_of::<MIB_TCP6ROW_OWNER_PID>();

        for idx in 0..num_entries {
            let Some(row_offset) = idx
                .checked_mul(row_size)
                .and_then(|off| table_offset.checked_add(off))
            else {
                break;
            };
            let Some(end) = row_offset.checked_add(row_size) else {
                break;
            };
            if end > buffer.len() {
                break;
            }
            // SAFETY: `row_offset + row_size <= buffer.len()`, and `read_unaligned` safely reads
            // the `MIB_TCP6ROW_OWNER_PID` bytes without alignment assumptions.
            let row = unsafe {
                std::ptr::read_unaligned(buffer.as_ptr().add(row_offset).cast::<MIB_TCP6ROW_OWNER_PID>())
            };
            let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
            if local_port == port && row.dwOwningPid > 0 {
                return Ok(Some(row.dwOwningPid));
            }
        }

        Ok(None)
    }

    pub(super) fn kill_port_occupant(pid: u32, grace_period: Duration) -> Result<(), SysError> {
        let controller = DefaultProcessController::new();
        controller.terminate_process_tree(pid, pid, grace_period)?;

        let confirm_deadline = Instant::now() + Duration::from_millis(300);
        loop {
            if !controller.is_process_alive(pid) {
                return Ok(());
            }
            let now = Instant::now();
            if now >= confirm_deadline {
                break;
            }
            thread::sleep(
                confirm_deadline
                    .saturating_duration_since(now)
                    .min(Duration::from_millis(20)),
            );
        }

        Err(SysError::TerminationFailed {
            pid,
            reason: format!("process {pid} remained alive after termination"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_port_detects_bound_listener_and_available_after_drop() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();

        let occupied = inspect_port(port).unwrap();
        match occupied {
            PortCheckResult::Occupied(Some(info)) => {
                assert_eq!(info.port, port);
                assert_eq!(info.pid, std::process::id());
                assert!(!info.process_name.is_empty());
            }
            other => panic!("expected Occupied(Some(info)) for port {port}, got {other:?}"),
        }

        drop(listener);

        let available = inspect_port(port).unwrap();
        assert_eq!(available, PortCheckResult::Available);
    }

    #[test]
    fn inspect_port_rejects_port_zero() {
        let err = inspect_port(0).unwrap_err();
        assert!(matches!(err, SysError::PortBindCheck { port: 0, .. }));
    }
}
