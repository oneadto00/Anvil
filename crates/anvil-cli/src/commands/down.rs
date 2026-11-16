//! Stop running services in reverse topological order and clean up workspace locks.

use super::ps::{
    find_compose_container_ids, inspect_lock_record, standalone_container_name, RecordLiveness,
};
use crate::args::GlobalOptions;
use anvil_core::{
    probe::ContainerHealthInspector, CoreError, DependencyGraph, RuntimeConfig, RuntimeIdentity,
};
use anvil_runtime::{DockerContainerExecutor, RuntimeExecutor};
use anvil_sys::{DefaultProcessController, LockRecord, LockfileStore, ProcessController};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};
use tokio::task::JoinSet;

/// Record of a service instance stopped during `anvil down`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoppedService {
    pub service_id: String,
    pub target: String,
}

/// Record of a lockfile entry skipped safely during `anvil down`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkippedRecord {
    pub service_id: String,
    pub pid: u32,
    pub reason: String,
}

/// Summary produced by `anvil down`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DownReport {
    pub project: String,
    pub stopped: Vec<StoppedService>,
    pub skipped: Vec<SkippedRecord>,
    pub warnings: Vec<String>,
}

#[derive(Default)]
struct ServiceStopOutcome {
    service_id: String,
    stopped: Vec<StoppedService>,
    skipped: Vec<SkippedRecord>,
    warnings: Vec<String>,
    errors: Vec<String>,
}

/// Executes the `anvil down` subcommand.
pub async fn execute(globals: GlobalOptions, grace_ms: u64) -> anyhow::Result<()> {
    let report = run_down(&globals, grace_ms).await?;
    println!("{}", format_down_summary(&report));
    Ok(())
}

pub(crate) async fn run_down(globals: &GlobalOptions, grace_ms: u64) -> anyhow::Result<DownReport> {
    let grace_period = Duration::from_millis(grace_ms);
    let ctx = super::ps::resolve_workspace_context(globals).await?;
    let run_dir = ctx.data_dir.join("run");
    let project_for_load = ctx.project.clone();

    let mut lock_records: BTreeMap<String, LockRecord> = tokio::task::spawn_blocking(move || {
        let store = LockfileStore::with_dir(run_dir);
        let Some(lockfile) = store.load_workspace(&project_for_load)? else {
            return Ok::<_, anvil_sys::SysError>(BTreeMap::new());
        };
        Ok(lockfile
            .processes
            .into_iter()
            .map(|rec| (rec.service_id.clone(), rec))
            .collect())
    })
    .await
    .map_err(|err| anyhow::anyhow!("lockfile load task failed: {err}"))??;

    let mut waves: Vec<Vec<String>> = if let Some(cfg) = &ctx.config {
        let graph = DependencyGraph::from_config(cfg)?;
        let mut shutdown_waves = graph.shutdown_layers();
        let residual: Vec<String> = lock_records
            .keys()
            .filter(|id| !cfg.services.contains_key(*id))
            .cloned()
            .collect();
        if !residual.is_empty() {
            shutdown_waves.push(residual);
        }
        shutdown_waves
    } else if !lock_records.is_empty() {
        vec![lock_records.keys().cloned().collect()]
    } else {
        Vec::new()
    };

    let mut report = DownReport {
        project: ctx.project.clone(),
        ..DownReport::default()
    };

    let has_docker = ctx.config.as_ref().is_some_and(|cfg| {
        cfg.services.values().any(|svc| {
            matches!(
                svc.runtime,
                RuntimeConfig::DockerContainer { .. } | RuntimeConfig::DockerCompose { .. }
            )
        })
    });

    let docker_exec = if has_docker {
        match DockerContainerExecutor::connect_local(&ctx.project, ctx.workspace_root.clone()) {
            Ok(exec) => Some(Arc::new(exec)),
            Err(err) => {
                report
                    .warnings
                    .push(format!("could not connect to local Docker daemon: {err}"));
                None
            }
        }
    } else {
        None
    };

    let mut failures = Vec::new();
    for wave in waves.drain(..) {
        let mut join_set = JoinSet::new();
        for service_id in wave {
            let lock_record = lock_records.remove(&service_id);
            let runtime_cfg = ctx
                .config
                .as_ref()
                .and_then(|cfg| cfg.services.get(&service_id))
                .map(|svc| svc.runtime.clone());
            let docker = docker_exec.clone();
            let project = ctx.project.clone();
            let workspace_root = ctx.workspace_root.clone();

            join_set.spawn(async move {
                stop_service_in_wave(
                    service_id,
                    lock_record,
                    runtime_cfg,
                    docker,
                    project,
                    workspace_root,
                    grace_period,
                )
                .await
            });
        }

        let mut layer_outcomes = Vec::new();
        while let Some(joined) = join_set.join_next().await {
            match joined {
                Ok(outcome) => layer_outcomes.push(outcome),
                Err(err) => failures.push(format!("shutdown worker panicked or cancelled: {err}")),
            }
        }
        layer_outcomes.sort_by(|a, b| a.service_id.cmp(&b.service_id));

        for outcome in layer_outcomes {
            report.stopped.extend(outcome.stopped);
            report.skipped.extend(outcome.skipped);
            report.warnings.extend(outcome.warnings);
            failures.extend(outcome.errors);
        }
    }

    if !failures.is_empty() {
        anyhow::bail!("failed to stop all services:\n{}", failures.join("\n"));
    }

    let run_dir = ctx.data_dir.join("run");
    let project_for_clear = ctx.project;
    tokio::task::spawn_blocking(move || LockfileStore::with_dir(run_dir).clear_workspace(&project_for_clear))
        .await
        .map_err(|err| anyhow::anyhow!("lockfile cleanup task failed: {err}"))??;

    Ok(report)
}

async fn stop_service_in_wave(
    service_id: String,
    lock_record: Option<LockRecord>,
    runtime_cfg: Option<RuntimeConfig>,
    docker_exec: Option<Arc<DockerContainerExecutor>>,
    project: String,
    workspace_root: Option<PathBuf>,
    grace_period: Duration,
) -> ServiceStopOutcome {
    let mut outcome = ServiceStopOutcome {
        service_id: service_id.clone(),
        ..ServiceStopOutcome::default()
    };

    if let Some(record) = lock_record {
        let blocking_res = tokio::task::spawn_blocking(move || {
            let controller = DefaultProcessController::new();
            match inspect_lock_record(&controller, &record) {
                RecordLiveness::Running => {
                    controller.terminate_process_tree(record.pid, record.pgid, grace_period)?;
                    Ok::<_, anyhow::Error>(Ok(StoppedService {
                        service_id: record.service_id,
                        target: format!("pid {}", record.pid),
                    }))
                }
                RecordLiveness::Dead => Ok(Err(SkippedRecord {
                    service_id: record.service_id,
                    pid: record.pid,
                    reason: "process is dead (stale lock)".to_owned(),
                })),
                RecordLiveness::PidReused { reason } => Ok(Err(SkippedRecord {
                    service_id: record.service_id,
                    pid: record.pid,
                    reason: format!("PID reuse guard skipped termination: {reason}"),
                })),
            }
        })
        .await;

        match blocking_res {
            Ok(Ok(Ok(stopped))) => outcome.stopped.push(stopped),
            Ok(Ok(Err(skipped))) => outcome.skipped.push(skipped),
            Ok(Err(err)) => outcome
                .errors
                .push(format!("failed to stop native service '{service_id}': {err}")),
            Err(err) => outcome
                .errors
                .push(format!("native stop task failed for '{service_id}': {err}")),
        }
    }

    match runtime_cfg {
        Some(RuntimeConfig::DockerContainer { container_name, .. }) => {
            if let Some(exec) = docker_exec {
                let target =
                    standalone_container_name(&project, &service_id, container_name.as_deref());
                stop_docker_target(&exec, &service_id, &target, &target, grace_period, &mut outcome)
                    .await;
            }
        }
        Some(RuntimeConfig::DockerCompose {
            compose_file,
            service_name,
        }) => {
            if let Some(exec) = docker_exec {
                match find_compose_container_ids(
                    &compose_file,
                    &service_name,
                    workspace_root.as_deref(),
                )
                .await
                {
                    Ok(ids) => {
                        for cid in ids {
                            stop_docker_target(
                                &exec,
                                &service_id,
                                &cid,
                                &service_name,
                                grace_period,
                                &mut outcome,
                            )
                            .await;
                        }
                    }
                    Err(reason) => outcome
                        .warnings
                        .push(format!("compose service '{service_id}': {reason}")),
                }
            }
        }
        Some(RuntimeConfig::Native { .. }) | None => {}
    }

    outcome
}

async fn stop_docker_target(
    exec: &DockerContainerExecutor,
    service_id: &str,
    container_ref: &str,
    display_name: &str,
    grace_period: Duration,
    outcome: &mut ServiceStopOutcome,
) {
    let identity = RuntimeIdentity::DockerContainer {
        container_id: container_ref.to_owned(),
        container_name: display_name.to_owned(),
    };
    if exec.is_alive(&identity).await {
        match exec.stop(&identity, grace_period).await {
            Ok(()) => outcome.stopped.push(StoppedService {
                service_id: service_id.to_owned(),
                target: format!("container {container_ref}"),
            }),
            Err(err) => outcome.errors.push(format!(
                "failed to stop container '{container_ref}' for '{service_id}': {err}"
            )),
        }
    } else if let Err(CoreError::ProbeFailed { reason }) = exec.inspect_health(container_ref).await
    {
        if !reason.contains("HTTP 404") {
            outcome
                .warnings
                .push(format!("docker service '{service_id}': {reason}"));
        }
    }
}

pub(crate) fn format_down_summary(report: &DownReport) -> String {
    if report.stopped.is_empty() && report.skipped.is_empty() && report.warnings.is_empty() {
        return format!(
            "No running services or stale locks found for project '{}'.",
            report.project
        );
    }

    let mut lines = vec![format!("Shutdown summary for project '{}':", report.project)];
    lines.push(format!("  Stopped: {}", report.stopped.len()));
    for entry in &report.stopped {
        lines.push(format!("    - {} ({})", entry.service_id, entry.target));
    }
    lines.push(format!("  Skipped stale/reused: {}", report.skipped.len()));
    for entry in &report.skipped {
        lines.push(format!(
            "    - {} (pid {}): {}",
            entry.service_id, entry.pid, entry.reason
        ));
    }
    for warning in &report.warnings {
        lines.push(format!("  Warning: {warning}"));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use anvil_sys::process_tree::build_shell_command;
    use std::path::Path;
    use tempfile::tempdir;

    fn trap_or_sleep_cmd(service: &str, order_file: &Path) -> String {
        if std::env::consts::OS == "windows" {
            "ping -n 61 127.0.0.1 > nul".to_owned()
        } else {
            format!(
                "trap 'printf \"{service}\\n\" >> \"{}\"; exit 0' TERM; sleep 60 & wait",
                order_file.display()
            )
        }
    }

    #[tokio::test]
    async fn down_stops_children_in_reverse_dag_order_and_skips_mismatched_pid() -> anyhow::Result<()>
    {
        let data_dir = tempdir()?;
        let config_dir = tempdir()?;
        let order_file = config_dir.path().join("stop_order.txt");
        let config_path = config_dir.path().join("anvil.yaml");

        tokio::fs::write(
            &config_path,
            r#"
version: "1"
project:
  name: "down-test"
services:
  db:
    runtime:
      type: native
      cmd: "sleep 60"
  api:
    runtime:
      type: native
      cmd: "sleep 60"
    depends_on:
      - db
  forged:
    runtime:
      type: native
      cmd: "sleep 60"
  dead:
    runtime:
      type: native
      cmd: "true"
"#,
        )
        .await?;

        let controller = DefaultProcessController::new();
        let mut db_cmd = build_shell_command(&trap_or_sleep_cmd("db", &order_file), None);
        controller.prepare_command(&mut db_cmd)?;
        let mut db_child = db_cmd.spawn()?;

        let mut api_cmd = build_shell_command(&trap_or_sleep_cmd("api", &order_file), None);
        controller.prepare_command(&mut api_cmd)?;
        let mut api_child = api_cmd.spawn()?;

        let mut dead_cmd = build_shell_command(
            if std::env::consts::OS == "windows" {
                "exit /b 0"
            } else {
                "true"
            },
            None,
        );
        controller.prepare_command(&mut dead_cmd)?;
        let mut dead_child = dead_cmd.spawn()?;
        let dead_pid = dead_child.id();
        let _ = dead_child.wait()?;

        let db_pid = db_child.id();
        let api_pid = api_child.id();
        let self_pid = std::process::id();
        let run_dir = data_dir.path().join("run");

        let (_db_handle, db_identity) =
            tokio::task::spawn_blocking(move || controller.attach_pid(db_pid)).await??;
        let (_api_handle, api_identity) =
            tokio::task::spawn_blocking(move || controller.attach_pid(api_pid)).await??;

        let run_dir_write = run_dir.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let store = LockfileStore::with_dir(run_dir_write);
            store.record_process(
                "down-test",
                LockRecord {
                    service_id: "db".to_owned(),
                    pid: db_identity.pid,
                    pgid: db_identity.pgid,
                    start_time_secs: db_identity.start_time_secs,
                    exe_name: db_identity.exe_name,
                },
            )?;
            store.record_process(
                "down-test",
                LockRecord {
                    service_id: "api".to_owned(),
                    pid: api_identity.pid,
                    pgid: api_identity.pgid,
                    start_time_secs: api_identity.start_time_secs,
                    exe_name: api_identity.exe_name,
                },
            )?;
            // Record current test PID with forged start time and exe name: must NOT be killed.
            store.record_process(
                "down-test",
                LockRecord {
                    service_id: "forged".to_owned(),
                    pid: self_pid,
                    pgid: self_pid,
                    start_time_secs: 0,
                    exe_name: "forged-proc".to_owned(),
                },
            )?;
            store.record_process(
                "down-test",
                LockRecord {
                    service_id: "dead".to_owned(),
                    pid: dead_pid,
                    pgid: dead_pid,
                    start_time_secs: 1,
                    exe_name: "true".to_owned(),
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
        let report = run_down(&globals, 1500).await?;

        let _ = api_child.wait();
        let _ = db_child.wait();

        let stopped_ids: Vec<&str> = report
            .stopped
            .iter()
            .map(|s| s.service_id.as_str())
            .collect();
        assert_eq!(stopped_ids, vec!["api", "db"]);

        if std::env::consts::OS != "windows" {
            let order_text = tokio::fs::read_to_string(&order_file).await?;
            assert_eq!(order_text, "api\ndb\n");
        }

        let skipped_ids: Vec<&str> = report
            .skipped
            .iter()
            .map(|s| s.service_id.as_str())
            .collect();
        assert!(skipped_ids.contains(&"forged"));
        assert!(skipped_ids.contains(&"dead"));

        let (api_alive, db_alive, self_alive, lock_after) =
            tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                let ctrl = DefaultProcessController::new();
                let store = LockfileStore::with_dir(run_dir);
                Ok((
                    ctrl.is_process_alive(api_pid),
                    ctrl.is_process_alive(db_pid),
                    ctrl.is_process_alive(self_pid),
                    store.load_workspace("down-test")?,
                ))
            })
            .await??;

        assert!(!api_alive);
        assert!(!db_alive);
        assert!(self_alive);
        assert!(lock_after.is_none());

        let summary = format_down_summary(&report);
        assert!(summary.contains("Stopped: 2"));
        assert!(summary.contains("Skipped stale/reused: 2"));
        Ok(())
    }

    #[tokio::test]
    async fn down_cleans_up_by_project_without_anvil_yaml() -> anyhow::Result<()> {
        let data_dir = tempdir()?;
        let missing_dir = tempdir()?;
        let missing_config = missing_dir.path().join("missing-anvil.yaml");

        let controller = DefaultProcessController::new();
        let sleep_cmd = if std::env::consts::OS == "windows" {
            "ping -n 61 127.0.0.1 > nul"
        } else {
            "sleep 60"
        };
        let mut cmd = build_shell_command(sleep_cmd, None);
        controller.prepare_command(&mut cmd)?;
        let mut child = cmd.spawn()?;
        let child_pid = child.id();

        let run_dir = data_dir.path().join("run");
        let run_dir_write = run_dir.clone();
        let (_handle, identity) =
            tokio::task::spawn_blocking(move || controller.attach_pid(child_pid)).await??;
        let self_pid = std::process::id();

        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let store = LockfileStore::with_dir(run_dir_write);
            store.record_process(
                "adhoc-proj",
                LockRecord {
                    service_id: "worker".to_owned(),
                    pid: identity.pid,
                    pgid: identity.pgid,
                    start_time_secs: identity.start_time_secs,
                    exe_name: identity.exe_name,
                },
            )?;
            store.record_process(
                "adhoc-proj",
                LockRecord {
                    service_id: "forged".to_owned(),
                    pid: self_pid,
                    pgid: self_pid,
                    start_time_secs: 0,
                    exe_name: "fake".to_owned(),
                },
            )?;
            Ok(())
        })
        .await??;

        let globals = GlobalOptions {
            config: missing_config,
            data_dir: Some(data_dir.path().to_path_buf()),
            project: Some("adhoc-proj".to_owned()),
        };
        let report = run_down(&globals, 1000).await?;
        let _ = child.wait();

        assert_eq!(report.stopped.len(), 1);
        assert_eq!(report.stopped[0].service_id, "worker");
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].service_id, "forged");

        let (child_alive, lock_after) =
            tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                let ctrl = DefaultProcessController::new();
                let store = LockfileStore::with_dir(run_dir);
                Ok((
                    ctrl.is_process_alive(child_pid),
                    store.load_workspace("adhoc-proj")?,
                ))
            })
            .await??;

        assert!(!child_alive);
        assert!(lock_after.is_none());
        Ok(())
    }
}
