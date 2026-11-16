//! Inspect live service runtime state from workspace lockfiles and `anvil.yaml`.

use crate::args::GlobalOptions;
use anvil_core::{
    probe::{ContainerHealthInspector, ContainerHealthStatus},
    AnvilConfig, CoreError, RuntimeConfig, RuntimeIdentity,
};
use anvil_runtime::{DockerContainerExecutor, RuntimeExecutor};
use anvil_sys::{
    DefaultProcessController, LockRecord, LockfileStore, ProcessController, ProcessSpawnIdentity,
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fmt,
    path::{Component, Path, PathBuf},
    process::Stdio,
};
use sysinfo::{Pid, ProcessRefreshKind, ProcessStatus, System, UpdateKind};
use tokio::process::Command;

/// Resolved workspace paths, project name, and optional parsed configuration.
pub(super) struct WorkspaceContext {
    pub data_dir: PathBuf,
    pub project: String,
    pub config: Option<AnvilConfig>,
    pub workspace_root: Option<PathBuf>,
}

/// Live verification outcome for a persisted [`LockRecord`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RecordLiveness {
    Running,
    Dead,
    PidReused { reason: String },
}

/// Runtime status classification rendered by `anvil ps`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum ServicePsStatus {
    Running,
    Stale,
    PidReused,
    Stopped,
}

impl fmt::Display for ServicePsStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Running => f.write_str("Running"),
            Self::Stale => f.write_str("Stale"),
            Self::PidReused => f.write_str("PidReused"),
            Self::Stopped => f.write_str("Stopped"),
        }
    }
}

/// Structured status entry for a single service in `anvil ps`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PsServiceEntry {
    pub service: String,
    pub runtime: String,
    pub status: ServicePsStatus,
    pub pid: Option<u32>,
    pub pgid: Option<u32>,
    pub port: Option<u16>,
    pub container: Option<String>,
    pub detail: Option<String>,
}

/// Top-level JSON/table report returned by `anvil ps`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PsReport {
    pub project: String,
    pub services: Vec<PsServiceEntry>,
}

/// Executes the `anvil ps` subcommand.
pub async fn execute(globals: GlobalOptions, json: bool) -> anyhow::Result<()> {
    let report = build_ps_report(&globals).await?;
    if json {
        let encoded = serde_json::to_string_pretty(&report)?;
        println!("{encoded}");
    } else {
        println!("{}", format_ps_table(&report));
    }
    Ok(())
}

/// Resolves `--data-dir` (or defaults to `~/.anvil`).
pub(super) fn resolve_data_dir(override_dir: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(dir) = override_dir {
        return Ok(dir.to_path_buf());
    }
    let home = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("could not determine user home directory"))?;
    Ok(home.join(".anvil"))
}

/// Validates that a project or service identifier is a single normal path segment.
pub(super) fn validate_name_component(name: &str, kind: &str) -> anyhow::Result<()> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.chars().any(char::is_whitespace)
    {
        anyhow::bail!("invalid {kind} name '{name}'");
    }
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => anyhow::bail!("invalid {kind} name '{name}'"),
    }
}

/// Resolves the workspace context from `anvil.yaml` (if present) and global CLI flags.
pub(super) async fn resolve_workspace_context(
    globals: &GlobalOptions,
) -> anyhow::Result<WorkspaceContext> {
    let data_dir = resolve_data_dir(globals.data_dir.as_deref())?;
    let config_exists = tokio::fs::try_exists(&globals.config).await?;

    if config_exists {
        let raw = tokio::fs::read_to_string(&globals.config).await?;
        let cfg = AnvilConfig::from_yaml_str(&raw)?;
        let project = globals
            .project
            .clone()
            .unwrap_or_else(|| cfg.project.name.clone());
        validate_name_component(&project, "project")?;
        let workspace_root = globals
            .config
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf);

        return Ok(WorkspaceContext {
            data_dir,
            project,
            config: Some(cfg),
            workspace_root,
        });
    }

    if let Some(project) = globals.project.clone() {
        validate_name_component(&project, "project")?;
        return Ok(WorkspaceContext {
            data_dir,
            project,
            config: None,
            workspace_root: None,
        });
    }

    anyhow::bail!(
        "configuration file '{}' not found and --project was not specified",
        globals.config.display()
    )
}

/// Verifies liveness, start time, and executable name for a recorded native process.
///
/// Must only be invoked inside `tokio::task::spawn_blocking`.
pub(super) fn inspect_lock_record(
    controller: &dyn ProcessController,
    record: &LockRecord,
) -> RecordLiveness {
    if record.pid == 0 || !controller.is_process_alive(record.pid) {
        return RecordLiveness::Dead;
    }

    if !ProcessSpawnIdentity::matches_start_time(record.pid, record.start_time_secs) {
        if !controller.is_process_alive(record.pid) {
            return RecordLiveness::Dead;
        }
        return RecordLiveness::PidReused {
            reason: format!(
                "pid {} start time mismatch (expected {})",
                record.pid, record.start_time_secs
            ),
        };
    }

    let mut sys = System::new();
    let sys_pid = Pid::from_u32(record.pid);
    let refresh_kind = ProcessRefreshKind::new().with_exe(UpdateKind::OnlyIfNotSet);
    if !sys.refresh_process_specifics(sys_pid, refresh_kind) {
        return RecordLiveness::Dead;
    }

    let Some(proc_info) = sys.process(sys_pid) else {
        return RecordLiveness::Dead;
    };

    if matches!(
        proc_info.status(),
        ProcessStatus::Zombie | ProcessStatus::Dead
    ) {
        return RecordLiveness::Dead;
    }

    // `build_shell_command` spawns `sh -c <cmd>`, which on Unix commonly `execve`s a simple
    // target command in place while preserving the same PID and kernel `start_time`.
    let shell_wrapper_exec = record.exe_name == "sh";
    let live_exe = extract_live_exe_name(proc_info);
    if !shell_wrapper_exec
        && !record.exe_name.is_empty()
        && record.exe_name != "unknown"
        && !live_exe.is_empty()
        && live_exe != "unknown"
        && !exe_names_match(&live_exe, &record.exe_name)
    {
        return RecordLiveness::PidReused {
            reason: format!(
                "pid {} executable '{}' != recorded '{}'",
                record.pid, live_exe, record.exe_name
            ),
        };
    }

    RecordLiveness::Running
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
    if std::env::consts::OS == "windows" {
        live.eq_ignore_ascii_case(recorded)
    } else {
        live == recorded
    }
}

/// Computes the deterministic container name used by `DockerContainerExecutor`.
pub(super) fn standalone_container_name(
    project: &str,
    service_id: &str,
    explicit: Option<&str>,
) -> String {
    explicit
        .map(str::to_owned)
        .unwrap_or_else(|| format!("anvil-{project}-{service_id}"))
}

/// Resolves container IDs associated with a `docker compose` service.
pub(super) async fn find_compose_container_ids(
    compose_file: &Path,
    service_name: &str,
    workspace_root: Option<&Path>,
) -> Result<Vec<String>, String> {
    let mut cmd = Command::new("docker");
    cmd.args(["compose", "-f"])
        .arg(compose_file)
        .args(["ps", "-q", "--all", "--", service_name])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(root) = workspace_root {
        cmd.current_dir(root);
    }

    let output = cmd
        .output()
        .await
        .map_err(|err| format!("failed to run docker compose ps: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let msg = stderr.trim();
        return Err(if msg.is_empty() {
            format!("docker compose ps exited with {}", output.status)
        } else {
            msg.to_owned()
        });
    }

    let ids = std::str::from_utf8(&output.stdout)
        .unwrap_or_default()
        .split_whitespace()
        .filter(|tok| !tok.is_empty() && tok.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_owned)
        .collect();
    Ok(ids)
}

pub(crate) async fn build_ps_report(globals: &GlobalOptions) -> anyhow::Result<PsReport> {
    let ctx = resolve_workspace_context(globals).await?;
    let run_dir = ctx.data_dir.join("run");
    let project_for_lock = ctx.project.clone();

    let lock_results = tokio::task::spawn_blocking(
        move || -> anyhow::Result<Vec<(LockRecord, RecordLiveness)>> {
            let store = LockfileStore::with_dir(run_dir);
            let Some(lockfile) = store.load_workspace(&project_for_lock)? else {
                return Ok(Vec::new());
            };
            let controller = DefaultProcessController::new();
            Ok(lockfile
                .processes
                .into_iter()
                .map(|record| {
                    let liveness = inspect_lock_record(&controller, &record);
                    (record, liveness)
                })
                .collect())
        },
    )
    .await
    .map_err(|err| anyhow::anyhow!("lockfile inspection task failed: {err}"))??;

    let mut lock_map: BTreeMap<String, (LockRecord, RecordLiveness)> = lock_results
        .into_iter()
        .map(|(rec, liveness)| (rec.service_id.clone(), (rec, liveness)))
        .collect();

    let mut services = Vec::new();

    if let Some(cfg) = &ctx.config {
        let has_docker = cfg.services.values().any(|svc| {
            matches!(
                svc.runtime,
                RuntimeConfig::DockerContainer { .. } | RuntimeConfig::DockerCompose { .. }
            )
        });
        let docker_client = if has_docker {
            Some(DockerContainerExecutor::connect_local(
                &ctx.project,
                ctx.workspace_root.clone(),
            ))
        } else {
            None
        };

        for (service_id, svc_cfg) in &cfg.services {
            let entry = match &svc_cfg.runtime {
                RuntimeConfig::Native { .. } => {
                    native_ps_entry(service_id, svc_cfg.port, lock_map.remove(service_id))
                }
                RuntimeConfig::DockerContainer { container_name, .. } => {
                    let target = standalone_container_name(
                        &ctx.project,
                        service_id,
                        container_name.as_deref(),
                    );
                    docker_container_ps_entry(
                        service_id,
                        "docker_container",
                        svc_cfg.port,
                        &target,
                        &target,
                        docker_client.as_ref(),
                    )
                    .await
                }
                RuntimeConfig::DockerCompose {
                    compose_file,
                    service_name,
                } => {
                    docker_compose_ps_entry(
                        service_id,
                        svc_cfg.port,
                        compose_file,
                        service_name,
                        ctx.workspace_root.as_deref(),
                        docker_client.as_ref(),
                    )
                    .await
                }
            };
            services.push(entry);
        }
    }

    for (service_id, (record, liveness)) in lock_map {
        services.push(native_ps_entry(
            &service_id,
            None,
            Some((record, liveness)),
        ));
    }

    Ok(PsReport {
        project: ctx.project,
        services,
    })
}

fn native_ps_entry(
    service_id: &str,
    port: Option<u16>,
    record: Option<(LockRecord, RecordLiveness)>,
) -> PsServiceEntry {
    match record {
        Some((rec, RecordLiveness::Running)) => PsServiceEntry {
            service: service_id.to_owned(),
            runtime: "native".to_owned(),
            status: ServicePsStatus::Running,
            pid: Some(rec.pid),
            pgid: Some(rec.pgid),
            port,
            container: None,
            detail: Some(format!("exe={}", rec.exe_name)),
        },
        Some((rec, RecordLiveness::Dead)) => PsServiceEntry {
            service: service_id.to_owned(),
            runtime: "native".to_owned(),
            status: ServicePsStatus::Stale,
            pid: Some(rec.pid),
            pgid: Some(rec.pgid),
            port,
            container: None,
            detail: Some(format!("stale lock: pid {} is dead", rec.pid)),
        },
        Some((rec, RecordLiveness::PidReused { reason })) => PsServiceEntry {
            service: service_id.to_owned(),
            runtime: "native".to_owned(),
            status: ServicePsStatus::PidReused,
            pid: Some(rec.pid),
            pgid: Some(rec.pgid),
            port,
            container: None,
            detail: Some(reason),
        },
        None => PsServiceEntry {
            service: service_id.to_owned(),
            runtime: "native".to_owned(),
            status: ServicePsStatus::Stopped,
            pid: None,
            pgid: None,
            port,
            container: None,
            detail: None,
        },
    }
}

async fn docker_container_ps_entry(
    service_id: &str,
    runtime: &str,
    port: Option<u16>,
    container_ref: &str,
    display_name: &str,
    docker_client: Option<&Result<DockerContainerExecutor, anvil_runtime::RuntimeError>>,
) -> PsServiceEntry {
    let executor = match docker_client {
        Some(Ok(exec)) => exec,
        Some(Err(err)) => {
            return PsServiceEntry {
                service: service_id.to_owned(),
                runtime: runtime.to_owned(),
                status: ServicePsStatus::Stopped,
                pid: None,
                pgid: None,
                port,
                container: Some(display_name.to_owned()),
                detail: Some(format!("docker unavailable: {err}")),
            };
        }
        None => {
            return PsServiceEntry {
                service: service_id.to_owned(),
                runtime: runtime.to_owned(),
                status: ServicePsStatus::Stopped,
                pid: None,
                pgid: None,
                port,
                container: Some(display_name.to_owned()),
                detail: None,
            };
        }
    };

    let identity = RuntimeIdentity::DockerContainer {
        container_id: container_ref.to_owned(),
        container_name: display_name.to_owned(),
    };

    if executor.is_alive(&identity).await {
        let detail = match executor.inspect_health(container_ref).await {
            Ok(ContainerHealthStatus::Healthy) => "health: healthy".to_owned(),
            Ok(ContainerHealthStatus::Starting) => "health: starting".to_owned(),
            Ok(ContainerHealthStatus::Unhealthy(reason)) => {
                format!("health: unhealthy ({reason})")
            }
            Ok(ContainerHealthStatus::None) | Err(_) => "container running".to_owned(),
        };
        return PsServiceEntry {
            service: service_id.to_owned(),
            runtime: runtime.to_owned(),
            status: ServicePsStatus::Running,
            pid: None,
            pgid: None,
            port,
            container: Some(display_name.to_owned()),
            detail: Some(detail),
        };
    }

    let detail = match executor.inspect_health(container_ref).await {
        Err(CoreError::ProbeFailed { reason }) if !reason.contains("HTTP 404") => Some(reason),
        _ => None,
    };

    PsServiceEntry {
        service: service_id.to_owned(),
        runtime: runtime.to_owned(),
        status: ServicePsStatus::Stopped,
        pid: None,
        pgid: None,
        port,
        container: Some(display_name.to_owned()),
        detail,
    }
}

async fn docker_compose_ps_entry(
    service_id: &str,
    port: Option<u16>,
    compose_file: &Path,
    service_name: &str,
    workspace_root: Option<&Path>,
    docker_client: Option<&Result<DockerContainerExecutor, anvil_runtime::RuntimeError>>,
) -> PsServiceEntry {
    match find_compose_container_ids(compose_file, service_name, workspace_root).await {
        Ok(ids) if !ids.is_empty() => {
            for cid in &ids {
                let entry = docker_container_ps_entry(
                    service_id,
                    "docker_compose",
                    port,
                    cid,
                    service_name,
                    docker_client,
                )
                .await;
                if entry.status == ServicePsStatus::Running {
                    return entry;
                }
            }
            PsServiceEntry {
                service: service_id.to_owned(),
                runtime: "docker_compose".to_owned(),
                status: ServicePsStatus::Stopped,
                pid: None,
                pgid: None,
                port,
                container: Some(service_name.to_owned()),
                detail: None,
            }
        }
        Ok(_) => PsServiceEntry {
            service: service_id.to_owned(),
            runtime: "docker_compose".to_owned(),
            status: ServicePsStatus::Stopped,
            pid: None,
            pgid: None,
            port,
            container: Some(service_name.to_owned()),
            detail: None,
        },
        Err(reason) => PsServiceEntry {
            service: service_id.to_owned(),
            runtime: "docker_compose".to_owned(),
            status: ServicePsStatus::Stopped,
            pid: None,
            pgid: None,
            port,
            container: Some(service_name.to_owned()),
            detail: Some(reason),
        },
    }
}

pub(crate) fn format_ps_table(report: &PsReport) -> String {
    if report.services.is_empty() {
        return format!("No services found for project '{}'.", report.project);
    }

    let rows: Vec<[String; 6]> = report
        .services
        .iter()
        .map(|entry| {
            [
                entry.service.clone(),
                entry.runtime.clone(),
                entry.status.to_string(),
                entry
                    .pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_owned()),
                entry
                    .port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_owned()),
                entry
                    .detail
                    .clone()
                    .or_else(|| entry.container.clone())
                    .unwrap_or_else(|| "-".to_owned()),
            ]
        })
        .collect();

    let headers = ["SERVICE", "RUNTIME", "STATUS", "PID", "PORT", "DETAIL"];
    let mut widths = headers.map(str::len);
    for row in &rows {
        for (idx, col) in row.iter().enumerate() {
            widths[idx] = widths[idx].max(col.len());
        }
    }

    let format_row = |cols: &[String; 6]| -> String {
        format!(
            "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  {:<w4$}  {}",
            cols[0],
            cols[1],
            cols[2],
            cols[3],
            cols[4],
            cols[5],
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2],
            w3 = widths[3],
            w4 = widths[4],
        )
    };

    let header_cols = headers.map(str::to_owned);
    let mut lines = Vec::with_capacity(rows.len() + 2);
    lines.push(format!("Project: {}", report.project));
    lines.push(format_row(&header_cols));
    for row in &rows {
        lines.push(format_row(row));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use anvil_sys::process_tree::build_shell_command;
    use std::time::Duration;
    use tempfile::tempdir;

    fn long_sleep_cmd() -> &'static str {
        if std::env::consts::OS == "windows" {
            "ping -n 61 127.0.0.1 > nul"
        } else {
            "sleep 60"
        }
    }

    #[tokio::test]
    async fn ps_identifies_running_stale_pid_reused_and_stopped_services() -> anyhow::Result<()> {
        let data_dir = tempdir()?;
        let config_dir = tempdir()?;
        let config_path = config_dir.path().join("anvil.yaml");
        tokio::fs::write(
            &config_path,
            r#"
version: "1"
project:
  name: "ps-test"
services:
  live-svc:
    runtime:
      type: native
      cmd: "sleep 60"
    port: 8081
  dead-svc:
    runtime:
      type: native
      cmd: "echo dead"
    port: 8082
  reused-start-svc:
    runtime:
      type: native
      cmd: "echo reused"
  reused-exe-svc:
    runtime:
      type: native
      cmd: "echo exe-mismatch"
  idle-svc:
    runtime:
      type: native
      cmd: "echo idle"
    port: 8085
"#,
        )
        .await?;

        let controller = DefaultProcessController::new();

        // Spawn a real long-lived process for live-svc.
        let mut live_cmd = build_shell_command(long_sleep_cmd(), None);
        controller.prepare_command(&mut live_cmd)?;
        let mut live_child = live_cmd.spawn()?;
        let live_pid = live_child.id();
        let (live_handle, live_identity) =
            tokio::task::spawn_blocking(move || controller.attach_pid(live_pid)).await??;

        // Spawn and exit a short-lived process so we get a guaranteed dead PID.
        let dead_cmd_line = if std::env::consts::OS == "windows" {
            "exit /b 0"
        } else {
            "true"
        };
        let mut dead_cmd = build_shell_command(dead_cmd_line, None);
        controller.prepare_command(&mut dead_cmd)?;
        let mut dead_child = dead_cmd.spawn()?;
        let dead_pid = dead_child.id();
        let _ = dead_child.wait()?;

        // Capture real identity for current process to test both start_time and exe_name reuse guards.
        let self_pid = std::process::id();
        let self_start = tokio::task::spawn_blocking(move || {
            let mut sys = System::new();
            let p = Pid::from_u32(self_pid);
            sys.refresh_process_specifics(p, ProcessRefreshKind::new());
            sys.process(p).map(|proc_info| proc_info.start_time())
        })
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing current process metadata"))?;

        let run_dir = data_dir.path().join("run");
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let store = LockfileStore::with_dir(run_dir);
            store.record_process(
                "ps-test",
                LockRecord {
                    service_id: "live-svc".to_owned(),
                    pid: live_identity.pid,
                    pgid: live_identity.pgid,
                    start_time_secs: live_identity.start_time_secs,
                    exe_name: live_identity.exe_name,
                },
            )?;
            store.record_process(
                "ps-test",
                LockRecord {
                    service_id: "dead-svc".to_owned(),
                    pid: dead_pid,
                    pgid: dead_pid,
                    start_time_secs: 1,
                    exe_name: "true".to_owned(),
                },
            )?;
            store.record_process(
                "ps-test",
                LockRecord {
                    service_id: "reused-start-svc".to_owned(),
                    pid: self_pid,
                    pgid: self_pid,
                    start_time_secs: self_start.saturating_add(3600),
                    exe_name: "wrong-start".to_owned(),
                },
            )?;
            store.record_process(
                "ps-test",
                LockRecord {
                    service_id: "reused-exe-svc".to_owned(),
                    pid: self_pid,
                    pgid: self_pid,
                    start_time_secs: self_start,
                    exe_name: "definitely-not-this-test-binary".to_owned(),
                },
            )?;
            Ok(())
        })
        .await??;

        let globals = GlobalOptions {
            config: config_path,
            data_dir: Some(data_dir.path().to_path_buf()),
            project: None,
        };
        let report = build_ps_report(&globals).await?;

        let by_name: BTreeMap<&str, &PsServiceEntry> = report
            .services
            .iter()
            .map(|e| (e.service.as_str(), e))
            .collect();
        assert_eq!(
            by_name["live-svc"].status,
            ServicePsStatus::Running,
            "live-svc entry: {:?}",
            by_name["live-svc"]
        );
        assert_eq!(by_name["live-svc"].pid, Some(live_child.id()));
        assert_eq!(by_name["dead-svc"].status, ServicePsStatus::Stale);
        assert_eq!(by_name["reused-start-svc"].status, ServicePsStatus::PidReused);
        assert_eq!(by_name["reused-exe-svc"].status, ServicePsStatus::PidReused);
        assert_eq!(by_name["idle-svc"].status, ServicePsStatus::Stopped);

        // Verify JSON serialization round-trips cleanly.
        let encoded = serde_json::to_string(&report)?;
        let decoded: serde_json::Value = serde_json::from_str(&encoded)?;
        assert_eq!(decoded["project"], "ps-test");
        let json_services = decoded["services"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("expected services JSON array"))?;
        assert_eq!(json_services.len(), 5);

        let table = format_ps_table(&report);
        assert!(table.contains("live-svc"));
        assert!(table.contains("Running"));
        assert!(table.contains("Stale"));
        assert!(table.contains("PidReused"));
        assert!(table.contains("Stopped"));

        tokio::task::spawn_blocking(move || controller.terminate_handle(&live_handle, Duration::from_millis(200)))
            .await??;
        let _ = live_child.wait();
        Ok(())
    }

    #[tokio::test]
    async fn ps_supports_project_override_without_anvil_yaml() -> anyhow::Result<()> {
        let data_dir = tempdir()?;
        let run_dir = data_dir.path().join("run");
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            LockfileStore::with_dir(run_dir).record_process(
                "adhoc",
                LockRecord {
                    service_id: "worker".to_owned(),
                    pid: std::process::id(),
                    pgid: std::process::id(),
                    start_time_secs: 0,
                    exe_name: "wrong-exe".to_owned(),
                },
            )?;
            Ok(())
        })
        .await??;

        let globals = GlobalOptions {
            config: data_dir.path().join("missing-anvil.yaml"),
            data_dir: Some(data_dir.path().to_path_buf()),
            project: Some("adhoc".to_owned()),
        };
        let report = build_ps_report(&globals).await?;
        assert_eq!(report.project, "adhoc");
        assert_eq!(report.services.len(), 1);
        assert_eq!(report.services[0].service, "worker");
        assert_eq!(report.services[0].status, ServicePsStatus::PidReused);
        Ok(())
    }
}
