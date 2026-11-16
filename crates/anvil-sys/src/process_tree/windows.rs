//! Windows Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) implementation.

use crate::error::SysError;
use crate::process_tree::{query_process_metadata, ManagedProcessHandle, ProcessSpawnIdentity};
use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command};
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, FALSE, HANDLE,
    INVALID_HANDLE_VALUE, STILL_ACTIVE,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, TerminateProcess, CREATE_NEW_PROCESS_GROUP,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
};

/// RAII wrapper around an owned Win32 Job Object kernel `HANDLE`.
#[derive(Debug)]
pub(crate) struct JobObjectHandle(HANDLE);

// SAFETY: A Win32 Job Object `HANDLE` is an opaque kernel object reference that can
// be safely transferred across threads and queried/signaled concurrently by the OS kernel.
unsafe impl Send for JobObjectHandle {}

// SAFETY: Concurrent Win32 kernel calls against a valid Job Object `HANDLE` are thread-safe
// in the Windows kernel, and `Drop` runs exclusively when the final owner goes out of scope.
unsafe impl Sync for JobObjectHandle {}

impl JobObjectHandle {
    const fn as_raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for JobObjectHandle {
    fn drop(&mut self) {
        if self.0 != 0 && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: `self.0` is an owned, non-null, non-invalid Win32 kernel handle
            // returned by `CreateJobObjectW` and not closed elsewhere.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// RAII wrapper around a temporarily opened Win32 process `HANDLE`.
#[derive(Debug)]
struct OwnedProcessHandle(HANDLE);

impl OwnedProcessHandle {
    const fn as_raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedProcessHandle {
    fn drop(&mut self) {
        if self.0 != 0 && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: `self.0` is an owned Win32 process handle obtained from `OpenProcess`.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct PlatformProcessHandle {
    pub(crate) pid: u32,
    pub(crate) pgid: u32,
    pub(crate) job: JobObjectHandle,
}

pub(crate) fn prepare_command(cmd: &mut Command) -> Result<(), SysError> {
    cmd.creation_flags(CREATE_NEW_PROCESS_GROUP);
    Ok(())
}

pub(crate) fn attach_child(
    child: &Child,
) -> Result<(ManagedProcessHandle, ProcessSpawnIdentity), SysError> {
    let pid = child.id();

    // SAFETY: Passing null security attributes and null name creates a private anonymous
    // Win32 Job Object; the returned handle is checked before being wrapped in `JobObjectHandle`.
    let raw_job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if raw_job == 0 || raw_job == INVALID_HANDLE_VALUE {
        return Err(SysError::JobObjectError(format!(
            "CreateJobObjectW failed: {}",
            last_os_error()
        )));
    }
    let job = JobObjectHandle(raw_job);

    // SAFETY: `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` is a plain C-layout Win32 struct where
    // an all-zero bit pattern is valid prior to populating `LimitFlags`.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    let info_size = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
        .map_err(|_| SysError::JobObjectError("job limit struct size overflow".to_owned()))?;

    // SAFETY: `job.as_raw()` is a valid Job Object handle and `info` points to an initialized
    // `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` of `info_size` bytes.
    let set_ok = unsafe {
        SetInformationJobObject(
            job.as_raw(),
            JobObjectExtendedLimitInformation,
            (&raw const info).cast::<c_void>(),
            info_size,
        )
    };
    if set_ok == FALSE {
        return Err(SysError::JobObjectError(format!(
            "SetInformationJobObject failed: {}",
            last_os_error()
        )));
    }

    let child_handle = child.as_raw_handle() as HANDLE;
    // SAFETY: `job.as_raw()` is an active Job Object and `child_handle` is borrowed from
    // `child` for the duration of this synchronous call.
    let assign_ok = unsafe { AssignProcessToJobObject(job.as_raw(), child_handle) };
    if assign_ok == FALSE {
        return Err(SysError::JobObjectError(format!(
            "AssignProcessToJobObject failed for pid {pid}: {}",
            last_os_error()
        )));
    }

    let (start_time_secs, exe_name) = query_process_metadata(pid);
    let handle = ManagedProcessHandle {
        inner: PlatformProcessHandle {
            pid,
            pgid: pid,
            job,
        },
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
    _grace_period: Duration,
) -> Result<(), SysError> {
    // SAFETY: `handle.inner.job.as_raw()` is an owned, valid Win32 Job Object handle.
    let ok = unsafe { TerminateJobObject(handle.inner.job.as_raw(), 1) };
    if ok == FALSE {
        return Err(SysError::JobObjectError(format!(
            "TerminateJobObject failed for pid {}: {}",
            handle.inner.pid,
            last_os_error()
        )));
    }
    Ok(())
}

pub(crate) fn terminate_process_tree(
    pid: u32,
    _pgid: u32,
    _grace_period: Duration,
) -> Result<(), SysError> {
    if pid == 0 {
        return Err(SysError::TerminationFailed {
            pid,
            reason: "cannot terminate PID 0".to_owned(),
        });
    }

    // SAFETY: `OpenProcess` takes primitive access masks and PID; the returned handle is
    // checked for null before wrapping in `OwnedProcessHandle`.
    let raw_proc = unsafe {
        OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            pid,
        )
    };
    if raw_proc == 0 || raw_proc == INVALID_HANDLE_VALUE {
        // SAFETY: `GetLastError` reads the calling thread's last-error slot.
        let code = unsafe { GetLastError() };
        if code == ERROR_INVALID_PARAMETER {
            return Ok(());
        }
        return Err(SysError::TerminationFailed {
            pid,
            reason: format!("OpenProcess failed: {}", std::io::Error::from_raw_os_error(code as i32)),
        });
    }
    let proc_handle = OwnedProcessHandle(raw_proc);

    // SAFETY: `proc_handle.as_raw()` is a valid handle opened with `PROCESS_TERMINATE`.
    let ok = unsafe { TerminateProcess(proc_handle.as_raw(), 1) };
    if ok == FALSE {
        // SAFETY: `GetLastError` reads the calling thread's last-error slot.
        let code = unsafe { GetLastError() };
        if code == ERROR_ACCESS_DENIED && !is_process_alive(pid) {
            return Ok(());
        }
        return Err(SysError::TerminationFailed {
            pid,
            reason: format!(
                "TerminateProcess failed: {}",
                std::io::Error::from_raw_os_error(code as i32)
            ),
        });
    }

    Ok(())
}

pub(crate) fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }

    // SAFETY: `OpenProcess` takes primitive values and returns either 0 or an owned handle.
    let raw_proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) };
    if raw_proc == 0 || raw_proc == INVALID_HANDLE_VALUE {
        return false;
    }
    let proc_handle = OwnedProcessHandle(raw_proc);

    let mut exit_code: u32 = 0;
    // SAFETY: `proc_handle.as_raw()` is valid and `exit_code` is a valid mutable `u32` out-pointer.
    let ok = unsafe { GetExitCodeProcess(proc_handle.as_raw(), &raw mut exit_code) };
    ok != FALSE && exit_code == STILL_ACTIVE as u32
}

fn last_os_error() -> std::io::Error {
    std::io::Error::last_os_error()
}
