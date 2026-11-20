//! Native service execution using the platform shell and anvil-sys process isolation.

use crate::{ExitStatusEvent, RawLogLine, RuntimeError, RuntimeExecutor, StreamSource};
use anvil_core::{RuntimeConfig, RuntimeIdentity, ServiceConfig};
use anvil_sys::process_tree::{build_shell_command, extract_exit_status};
use anvil_sys::{
    DefaultProcessController, ManagedProcessHandle, ProcessController, ProcessSpawnIdentity,
};
use chrono::Local;
use std::{collections::HashMap, io, path::PathBuf, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    process::Command,
    sync::{mpsc, oneshot, Mutex},
    task::spawn_blocking,
};
use zeroize::{Zeroize, Zeroizing};

type Handles = Arc<Mutex<HashMap<u32, Arc<ManagedProcessHandle>>>>;

/// Executes native services in isolated process trees.
pub struct NativeProcessExecutor<C: ProcessController + 'static = DefaultProcessController> {
    controller: Arc<C>,
    workspace_root: Option<PathBuf>,
    handles: Handles,
}

impl Default for NativeProcessExecutor {
    fn default() -> Self {
        Self::new(None)
    }
}

impl NativeProcessExecutor {
    /// Creates a native executor with an optional base directory for service commands.
    pub fn new(workspace_root: Option<PathBuf>) -> Self {
        Self::with_controller(DefaultProcessController::new(), workspace_root)
    }
}

impl<C: ProcessController + 'static> NativeProcessExecutor<C> {
    /// Creates an executor using the supplied process controller.
    pub fn with_controller(controller: C, workspace_root: Option<PathBuf>) -> Self {
        Self {
            controller: Arc::new(controller),
            workspace_root,
            handles: Default::default(),
        }
    }
}

// A PID can be reused between child exit and registry cleanup. Only remove the
// entry if it still points to the same process handle.
async fn remove_handle(handles: &Handles, pid: u32, handle: &Arc<ManagedProcessHandle>) {
    let mut registry = handles.lock().await;
    if registry
        .get(&pid)
        .is_some_and(|entry| Arc::ptr_eq(entry, handle))
    {
        registry.remove(&pid);
    }
}

async fn forward_lines(
    pipe: impl AsyncRead + Unpin,
    service_id: String,
    source: StreamSource,
    log_tx: mpsc::Sender<RawLogLine>,
    sensitive: Arc<Vec<Zeroizing<String>>>,
) {
    let mut lines = BufReader::new(pipe).lines();
    loop {
        let mut content = match lines.next_line().await {
            Ok(Some(line)) => line,
            // A malformed line must not close the child's output pipe.
            Err(error) if error.kind() == io::ErrorKind::InvalidData => continue,
            Ok(None) | Err(_) => break,
        };
        if log_tx.is_closed() {
            // Continue draining so closing the log view cannot break a child's pipe.
            content.zeroize();
            continue;
        }
        if sensitive.iter().any(|value| {
            value
                .lines()
                .any(|part| !part.is_empty() && content.contains(part))
        }) {
            content.zeroize();
            content.push_str("[REDACTED]");
        }
        let line = RawLogLine {
            service_id: service_id.clone(),
            source,
            content,
            timestamp: Local::now(),
        };
        let _ = log_tx.send(line).await;
    }
}

#[async_trait::async_trait]
impl<C: ProcessController + 'static> RuntimeExecutor for NativeProcessExecutor<C> {
    async fn spawn(
        &self,
        service_id: &str,
        config: &ServiceConfig,
        decrypted_env: &HashMap<String, Zeroizing<String>>,
        log_tx: mpsc::Sender<RawLogLine>,
    ) -> anyhow::Result<(RuntimeIdentity, oneshot::Receiver<ExitStatusEvent>)> {
        let RuntimeConfig::Native { cmd, cwd, .. } = &config.runtime else {
            return Err(RuntimeError::UnsupportedRuntime.into());
        };
        let cwd = match (&self.workspace_root, cwd) {
            (Some(root), Some(path)) => Some(root.join(path)),
            (root, path) => path.as_ref().or(root.as_ref()).cloned(),
        };
        let spawn_error = |source| RuntimeError::SpawnFailed {
            service_id: service_id.to_owned(),
            source,
        };
        let mut command = Command::from(build_shell_command(cmd, cwd.as_deref()));
        command
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in decrypted_env {
            command.env(key, value.as_str());
        }
        let mut child = command.spawn().map_err(spawn_error)?;
        drop(command);
        let pid = child
            .id()
            .ok_or_else(|| spawn_error(io::Error::other("missing child PID")))?;
        let sensitive = Arc::new(
            decrypted_env
                .values()
                .filter(|v| !v.is_empty())
                .cloned()
                .collect(),
        );
        if let Some(pipe) = child.stdout.take() {
            tokio::spawn(forward_lines(
                pipe,
                service_id.to_owned(),
                StreamSource::Stdout,
                log_tx.clone(),
                Arc::clone(&sensitive),
            ));
        }
        if let Some(pipe) = child.stderr.take() {
            tokio::spawn(forward_lines(
                pipe,
                service_id.to_owned(),
                StreamSource::Stderr,
                log_tx,
                sensitive,
            ));
        }

        let controller = Arc::clone(&self.controller);
        let handles = Arc::clone(&self.handles);
        let (ready_tx, ready_rx) = oneshot::channel();
        let (accepted_tx, accepted_rx) = oneshot::channel::<()>();
        let (exit_tx, exit_rx) = oneshot::channel();
        // This task owns the child across attachment, even if the caller cancels spawn.
        tokio::spawn(async move {
            let attach = Arc::clone(&controller);
            let attached = spawn_blocking(move || attach.attach_pid(pid))
                .await
                .map_err(|e| RuntimeError::Io(io::Error::other(e)))
                .and_then(|result| result.map_err(RuntimeError::Sys));
            let (handle, identity) = match attached {
                Ok(pair) => pair,
                Err(error) => {
                    let _ = spawn_blocking(move || {
                        controller.terminate_process_tree(pid, pid, Duration::ZERO)
                    })
                    .await;
                    let _ = child.kill().await;
                    let _ = ready_tx.send(Err(error));
                    return;
                }
            };
            let handle = Arc::new(handle);
            handles.lock().await.insert(pid, Arc::clone(&handle));
            let identity = RuntimeIdentity::NativeProcess {
                pid: identity.pid,
                pgid: identity.pgid,
                start_time_secs: identity.start_time_secs,
            };
            let _ = ready_tx.send(Ok(identity));
            if accepted_rx.await.is_err() {
                let handle = Arc::clone(&handle);
                let _ =
                    spawn_blocking(move || controller.terminate_handle(&handle, Duration::ZERO))
                        .await;
            }
            let status = child.wait().await;
            remove_handle(&handles, pid, &handle).await;
            drop(handle);
            if let Ok(status) = status {
                let (code, signal) = extract_exit_status(&status);
                let _ = exit_tx.send(ExitStatusEvent::Exited { code, signal });
            }
        });
        let identity = ready_rx
            .await
            .map_err(|e| spawn_error(io::Error::other(e)))??;
        accepted_tx
            .send(())
            .map_err(|()| spawn_error(io::Error::other("process waiter closed")))?;
        Ok((identity, exit_rx))
    }

    async fn stop(&self, identity: &RuntimeIdentity, grace_period: Duration) -> anyhow::Result<()> {
        let RuntimeIdentity::NativeProcess {
            pid,
            pgid,
            start_time_secs,
        } = *identity
        else {
            return Err(RuntimeError::UnsupportedRuntime.into());
        };
        if pgid != pid || pid == 0 {
            return Err(RuntimeError::Sys(anvil_sys::SysError::TerminationFailed {
                pid,
                reason: "invalid isolated process group".to_owned(),
            })
            .into());
        }
        let handle = self.handles.lock().await.get(&pid).cloned();
        let target = handle.clone();
        let controller = Arc::clone(&self.controller);
        let stopped = spawn_blocking(move || {
            if controller.is_process_alive(pid)
                && !ProcessSpawnIdentity::matches_start_time(pid, start_time_secs)
            {
                return Ok(false);
            }
            match target {
                Some(handle) => controller.terminate_handle(&handle, grace_period),
                None => controller.terminate_process_tree(pid, pgid, grace_period),
            }?;
            Ok(true)
        })
        .await
        .map_err(|source| RuntimeError::StopFailed { pid, source })?
        .map_err(RuntimeError::Sys)?;
        if let Some(handle) = handle.filter(|_| stopped) {
            remove_handle(&self.handles, pid, &handle).await;
        }
        Ok(())
    }

    async fn is_alive(&self, identity: &RuntimeIdentity) -> bool {
        let RuntimeIdentity::NativeProcess {
            pid,
            start_time_secs,
            ..
        } = *identity
        else {
            return false;
        };
        let controller = Arc::clone(&self.controller);
        spawn_blocking(move || {
            controller.is_process_alive(pid)
                && ProcessSpawnIdentity::matches_start_time(pid, start_time_secs)
        })
        .await
        .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    const LIMIT: Duration = Duration::from_secs(10);

    fn service(cmd: &str, cwd: Option<PathBuf>) -> ServiceConfig {
        ServiceConfig {
            runtime: RuntimeConfig::Native {
                cmd: cmd.to_owned(),
                cwd,
                grace_period_ms: 100,
            },
            port: None,
            depends_on: Vec::new(),
            env: Default::default(),
            readiness_probe: None,
            restart_policy: Default::default(),
        }
    }

    #[tokio::test]
    async fn delivers_both_streams_and_exit_code_from_workspace_relative_cwd() {
        let root = tempfile::tempdir().unwrap();
        let subdir = root.path().join("service");
        std::fs::create_dir(&subdir).unwrap();
        std::fs::write(subdir.join("marker"), "stdout-ok\n").unwrap();
        let cmd = if std::env::consts::OS == "windows" {
            std::fs::write(
                subdir.join("fixture.cmd"),
                "@echo off\r\nif not \"%ANVIL_TOKEN%\"==\"test-only-token\" exit /b 1\r\ntype marker\r\necho %ANVIL_TOKEN%\r\n1>&2 echo stderr-ok\r\nexit /b 42\r\n",
            ).unwrap();
            "fixture.cmd"
        } else {
            r#"[ "$ANVIL_TOKEN" = test-only-token ] || exit 1; cat marker; echo "$ANVIL_TOKEN"; echo stderr-ok >&2; exit 42"#
        };
        let config = service(cmd, Some("service".into()));
        let env = HashMap::from([(
            "ANVIL_TOKEN".to_owned(),
            Zeroizing::new("test-only-token".to_owned()),
        )]);
        let executor = NativeProcessExecutor::new(Some(root.path().to_owned()));
        let (tx, mut rx) = mpsc::channel(1);
        let (identity, exit) = executor.spawn("api", &config, &env, tx).await.unwrap();
        // A full log queue must not delay delivery of the independent exit event.
        assert_eq!(
            timeout(LIMIT, exit).await.unwrap().unwrap(),
            ExitStatusEvent::Exited {
                code: Some(42),
                signal: None
            }
        );
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        while let Some(line) = timeout(LIMIT, rx.recv()).await.unwrap() {
            assert_eq!(line.service_id, "api");
            match line.source {
                StreamSource::Stdout => stdout.push(line.content),
                StreamSource::Stderr => stderr.push(line.content),
                StreamSource::System => panic!("unexpected system line"),
            }
        }
        assert_eq!(stdout, ["stdout-ok", "[REDACTED]"]);
        assert_eq!(stderr, ["stderr-ok"]);
        assert!(!executor.is_alive(&identity).await);
        assert!(executor.handles.lock().await.is_empty());
    }

    #[tokio::test]
    async fn closed_log_receiver_still_drains_child_output() {
        let cmd = if std::env::consts::OS == "windows" {
            "for /L %i in (1,1,20000) do @echo logging-to-closed-receiver"
        } else {
            "i=0; while [ $i -lt 20000 ]; do echo logging-to-closed-receiver; i=$((i+1)); done"
        };
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let (_, exit) = NativeProcessExecutor::default()
            .spawn("writer", &service(cmd, None), &HashMap::new(), tx)
            .await
            .unwrap();
        assert_eq!(
            timeout(LIMIT, exit).await.unwrap().unwrap(),
            ExitStatusEvent::Exited {
                code: Some(0),
                signal: None
            }
        );
    }

    #[tokio::test]
    async fn stops_nested_process_and_reaps_root() {
        let root = tempfile::tempdir().unwrap();
        let cmd = if std::env::consts::OS == "windows" {
            std::fs::write(root.path().join("worker.cmd"),
                "@echo off\r\n:wait\r\nif not exist attached goto wait\r\npowershell -NoProfile -NonInteractive -Command \"Write-Output $PID; Start-Sleep 60\"\r\n",
            ).unwrap();
            "worker.cmd"
        } else {
            "sleep 60 & echo $!; wait"
        };
        let executor = NativeProcessExecutor::new(Some(root.path().to_owned()));
        let (tx, mut rx) = mpsc::channel(1);
        let (identity, exit) = executor
            .spawn("worker", &service(cmd, None), &HashMap::new(), tx)
            .await
            .unwrap();
        std::fs::write(root.path().join("attached"), "").unwrap();
        let ready = timeout(LIMIT, rx.recv()).await.unwrap().unwrap();
        let descendant = ready.content.parse::<u32>().unwrap();
        let mut stale = identity.clone();
        if let RuntimeIdentity::NativeProcess {
            start_time_secs, ..
        } = &mut stale
        {
            *start_time_secs = 0;
        }
        assert!(!executor.is_alive(&stale).await);
        executor.stop(&stale, Duration::ZERO).await.unwrap();
        assert!(executor.is_alive(&identity).await);
        timeout(LIMIT, executor.stop(&identity, Duration::from_millis(100)))
            .await
            .unwrap()
            .unwrap();
        let status = timeout(LIMIT, exit).await.unwrap().unwrap();
        assert!(matches!(status, ExitStatusEvent::Exited { .. }));
        assert!(!executor.is_alive(&identity).await);
        assert!(executor.handles.lock().await.is_empty());
        // EOF also verifies that descendants holding inherited pipe ends have exited.
        assert!(timeout(LIMIT, rx.recv()).await.unwrap().is_none());
        assert!(!spawn_blocking(
            move || DefaultProcessController::new().is_process_alive(descendant)
        )
        .await
        .unwrap());
    }
}
