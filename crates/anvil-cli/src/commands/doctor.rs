//! `anvil doctor` 5-point environment diagnostic and orphan lockfile reaper.

use crate::args::GlobalOptions;
use crate::commands::secret;
use anvil_core::{AnvilConfig, CoreError, DependencyGraph, RuntimeConfig, ServiceConfig};
use anvil_runtime::DockerContainerExecutor;
use anvil_sys::{
    inspect_port, DefaultProcessController, LockRecord, LockfileStore, PortCheckResult,
    ProcessController, ProcessSpawnIdentity, ReapReport,
};
use anyhow::Context;
use bollard::Docker;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;
use tokio::task::spawn_blocking;
use zeroize::Zeroizing;

const REAP_GRACE_PERIOD: Duration = Duration::from_secs(3);
const DOCKER_PING_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

impl CheckStatus {
    const fn tag(self) -> &'static str {
        match self {
            Self::Pass => "[PASS]",
            Self::Warn => "[WARN]",
            Self::Fail => "[FAIL]",
        }
    }
}

#[derive(Debug)]
struct CheckOutcome {
    status: CheckStatus,
    lines: Vec<String>,
}

impl CheckOutcome {
    fn single(status: CheckStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            lines: vec![format!("{} {}", status.tag(), message.into())],
        }
    }
}

enum LockInspection {
    Empty,
    Entries {
        live_orphans: Vec<LockRecord>,
        stale_pids: Vec<LockRecord>,
    },
    Reaped(ReapReport),
}

enum DockerCheckMode {
    Live,
    #[cfg(test)]
    Client(Docker),
    #[cfg(test)]
    PingOutcome(Result<(), String>),
}

enum ConfigLoadOutcome {
    Valid(Box<AnvilConfig>, DependencyGraph),
    Failed(Box<Option<AnvilConfig>>, CoreError),
}

/// Executes all 5 `anvil doctor` checks and returns an error if any check reports `[FAIL]`.
pub async fn run(globals: &GlobalOptions, reap: bool) -> anyhow::Result<()> {
    let mut stdout = io::stdout().lock();
    run_with(globals, reap, None, DockerCheckMode::Live, &mut stdout).await
}

async fn run_with(
    globals: &GlobalOptions,
    reap: bool,
    passphrase_override: Option<Zeroizing<String>>,
    docker_mode: DockerCheckMode,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let mut outcomes = Vec::with_capacity(5);

    // 1. Config & DAG cycle validation
    let (config_outcome, config) = check_config_and_dag(&globals.config).await?;
    outcomes.push(config_outcome);

    let project = globals
        .project
        .clone()
        .or_else(|| config.as_ref().map(|c| c.project.name.clone()));

    let data_dir = secret::resolve_data_dir(globals).await?;
    let vault_dir = secret::vault_dir_for(&data_dir);
    let run_dir = data_dir.join("run");

    // 2. Declared secret completeness check
    let secrets_outcome = match (&config, &project) {
        (Some(cfg), Some(proj)) => {
            check_secrets(proj, &cfg.secrets, &vault_dir, passphrase_override).await
        }
        _ => CheckOutcome::single(
            CheckStatus::Warn,
            "Secrets: skipped because configuration could not be loaded.",
        ),
    };
    outcomes.push(secrets_outcome);

    // 3. Orphan lockfile & process fingerprint check
    let lock_outcome = match &project {
        Some(proj) => check_lockfile(proj, &run_dir, reap).await,
        None => CheckOutcome::single(
            CheckStatus::Warn,
            "Lockfile: skipped because project name could not be determined.",
        ),
    };
    outcomes.push(lock_outcome);

    // 4. Service listening port conflict preflight
    let ports_outcome = match &config {
        Some(cfg) => check_ports(&cfg.services).await,
        None => CheckOutcome::single(
            CheckStatus::Warn,
            "Ports: skipped because configuration could not be loaded.",
        ),
    };
    outcomes.push(ports_outcome);

    // 5. Docker Daemon connectivity check
    let uses_docker = config.as_ref().is_some_and(|cfg| {
        cfg.services.values().any(|svc| {
            matches!(
                svc.runtime,
                RuntimeConfig::DockerContainer { .. } | RuntimeConfig::DockerCompose { .. }
            )
        })
    });
    let workspace_root = globals
        .config
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf);
    let docker_outcome = check_docker_daemon(
        project.as_deref().unwrap_or("anvil"),
        workspace_root.as_deref(),
        uses_docker,
        docker_mode,
    )
    .await;
    outcomes.push(docker_outcome);

    let mut has_fail = false;
    for outcome in &outcomes {
        if outcome.status == CheckStatus::Fail {
            has_fail = true;
        }
        for line in &outcome.lines {
            writeln!(out, "{line}")?;
        }
    }
    out.flush()?;

    if has_fail {
        anyhow::bail!("anvil doctor found one or more failing checks");
    }
    Ok(())
}

async fn check_config_and_dag(config_path: &Path) -> anyhow::Result<(CheckOutcome, Option<AnvilConfig>)> {
    let path = config_path.to_path_buf();
    let result = spawn_blocking(move || match AnvilConfig::from_file(&path) {
        Ok(cfg) => match DependencyGraph::from_config(&cfg) {
            Ok(graph) => ConfigLoadOutcome::Valid(Box::new(cfg), graph),
            Err(err) => ConfigLoadOutcome::Failed(Box::new(Some(cfg)), err),
        },
        Err(err) => ConfigLoadOutcome::Failed(Box::new(None), err),
    })
    .await
    .context("config validation task failed")?;

    match result {
        ConfigLoadOutcome::Valid(cfg, graph) => {
            let layers = graph.execution_layers().len();
            let outcome = CheckOutcome::single(
                CheckStatus::Pass,
                format!(
                    "Config & DAG: valid (project '{}', {} service(s), {} wave(s)).",
                    cfg.project.name,
                    cfg.services.len(),
                    layers
                ),
            );
            Ok((outcome, Some(*cfg)))
        }
        ConfigLoadOutcome::Failed(maybe_cfg, CoreError::ValidationErrors(errors)) => {
            let mut lines = vec![format!(
                "{} Config & DAG: configuration validation failed ({} error(s)):",
                CheckStatus::Fail.tag(),
                errors.len()
            )];
            for (idx, err) in errors.iter().enumerate() {
                lines.push(format!("  {}. {err}", idx + 1));
            }
            Ok((
                CheckOutcome {
                    status: CheckStatus::Fail,
                    lines,
                },
                *maybe_cfg,
            ))
        }
        ConfigLoadOutcome::Failed(maybe_cfg, CoreError::DagCycle(cycle)) => {
            let outcome = CheckOutcome::single(
                CheckStatus::Fail,
                format!(
                    "Config & DAG: dependency cycle detected: {}",
                    cycle.cycle_path.join(" -> ")
                ),
            );
            Ok((outcome, *maybe_cfg))
        }
        ConfigLoadOutcome::Failed(maybe_cfg, err) => {
            let outcome = CheckOutcome::single(
                CheckStatus::Fail,
                format!(
                    "Config & DAG: failed to load {}: {err}",
                    config_path.display()
                ),
            );
            Ok((outcome, *maybe_cfg))
        }
    }
}

async fn check_secrets(
    project: &str,
    declared: &[String],
    vault_dir: &Path,
    passphrase_override: Option<Zeroizing<String>>,
) -> CheckOutcome {
    if declared.is_empty() {
        return CheckOutcome::single(
            CheckStatus::Pass,
            "Secrets: no secrets declared in anvil.yaml.",
        );
    }

    match secret::check_declared_secrets(project, declared, vault_dir, passphrase_override).await {
        Ok(audit) => {
            let missing: Vec<&str> = audit
                .statuses
                .iter()
                .filter_map(|(key, present)| (!*present).then_some(key.as_str()))
                .collect();
            if missing.is_empty() {
                CheckOutcome::single(
                    CheckStatus::Pass,
                    format!(
                        "Secrets: all {} declared secret(s) are configured for project '{project}'.",
                        declared.len()
                    ),
                )
            } else {
                let mut lines = vec![format!(
                    "{} Secrets: missing {} declared secret(s) for project '{project}': {}",
                    CheckStatus::Fail.tag(),
                    missing.len(),
                    missing.join(", ")
                )];
                for key in missing {
                    lines.push(format!("  - run 'anvil secret set {key}' to configure"));
                }
                CheckOutcome {
                    status: CheckStatus::Fail,
                    lines,
                }
            }
        }
        Err(err) => CheckOutcome::single(
            CheckStatus::Fail,
            format!("Secrets: verification failed for project '{project}': {err}"),
        ),
    }
}

async fn check_lockfile(project: &str, run_dir: &Path, reap: bool) -> CheckOutcome {
    let project_owned = project.to_owned();
    let run_dir_owned = run_dir.to_path_buf();

    let task_res = spawn_blocking(move || -> anyhow::Result<LockInspection> {
        let store = LockfileStore::with_dir(&run_dir_owned);
        let controller = DefaultProcessController::new();

        if reap {
            if store.load_workspace(&project_owned)?.is_none() {
                return Ok(LockInspection::Empty);
            }
            let report =
                store.reap_orphans(&project_owned, &controller, REAP_GRACE_PERIOD)?;
            return Ok(LockInspection::Reaped(report));
        }

        let Some(lockfile) = store.load_workspace(&project_owned)? else {
            return Ok(LockInspection::Empty);
        };
        if lockfile.processes.is_empty() {
            return Ok(LockInspection::Empty);
        }

        let mut live_orphans = Vec::new();
        let mut stale_pids = Vec::new();
        for record in lockfile.processes {
            let is_live_orphan = record.pid > 0
                && controller.is_process_alive(record.pid)
                && ProcessSpawnIdentity::matches_start_time(record.pid, record.start_time_secs);
            if is_live_orphan {
                live_orphans.push(record);
            } else {
                stale_pids.push(record);
            }
        }
        Ok(LockInspection::Entries {
            live_orphans,
            stale_pids,
        })
    })
    .await;

    match task_res {
        Ok(Ok(LockInspection::Empty)) => CheckOutcome::single(
            CheckStatus::Pass,
            format!("Lockfile: no residual process locks for project '{project}'."),
        ),
        Ok(Ok(LockInspection::Entries {
            live_orphans,
            stale_pids,
        })) => {
            if live_orphans.is_empty() && stale_pids.is_empty() {
                return CheckOutcome::single(
                    CheckStatus::Pass,
                    format!("Lockfile: no residual process locks for project '{project}'."),
                );
            }
            let mut lines = vec![format!(
                "{} Lockfile: found {} live orphan process(es) and {} stale/reused PID(s) for '{project}' (run 'anvil doctor --reap' to clean up).",
                CheckStatus::Warn.tag(),
                live_orphans.len(),
                stale_pids.len()
            )];
            for rec in &live_orphans {
                lines.push(format!(
                    "  - live orphan: service='{}' pid={} pgid={} exe='{}'",
                    rec.service_id, rec.pid, rec.pgid, rec.exe_name
                ));
            }
            for rec in &stale_pids {
                lines.push(format!(
                    "  - stale/reused PID: service='{}' pid={} exe='{}'",
                    rec.service_id, rec.pid, rec.exe_name
                ));
            }
            CheckOutcome {
                status: CheckStatus::Warn,
                lines,
            }
        }
        Ok(Ok(LockInspection::Reaped(report))) => {
            let mut lines = vec![format!(
                "{} Lockfile (--reap): ReapReport {{ reaped: {}, skipped_pid_reuse: {} }}",
                CheckStatus::Pass.tag(),
                report.reaped,
                report.skipped_pid_reuse
            )];
            for rec in &report.reaped_records {
                lines.push(format!(
                    "  - reaped orphan: service='{}' pid={} pgid={} exe='{}'",
                    rec.service_id, rec.pid, rec.pgid, rec.exe_name
                ));
            }
            for rec in &report.skipped_records {
                lines.push(format!(
                    "  - skipped stale/reused PID: service='{}' pid={} exe='{}'",
                    rec.service_id, rec.pid, rec.exe_name
                ));
            }
            CheckOutcome {
                status: CheckStatus::Pass,
                lines,
            }
        }
        Ok(Err(err)) => CheckOutcome::single(
            CheckStatus::Fail,
            format!("Lockfile: failed to inspect workspace locks for '{project}': {err}"),
        ),
        Err(join_err) => CheckOutcome::single(
            CheckStatus::Fail,
            format!("Lockfile: inspection task panicked: {join_err}"),
        ),
    }
}

async fn check_ports(services: &BTreeMap<String, ServiceConfig>) -> CheckOutcome {
    let port_targets: Vec<(String, u16)> = services
        .iter()
        .filter_map(|(id, svc)| svc.port.map(|port| (id.clone(), port)))
        .collect();

    if port_targets.is_empty() {
        return CheckOutcome::single(
            CheckStatus::Pass,
            "Ports: no listening ports declared in anvil.yaml.",
        );
    }

    let results = spawn_blocking(move || {
        port_targets
            .into_iter()
            .map(|(service_id, port)| {
                let res = inspect_port(port);
                (service_id, port, res)
            })
            .collect::<Vec<_>>()
    })
    .await;

    let Ok(results) = results else {
        return CheckOutcome::single(
            CheckStatus::Fail,
            "Ports: port inspection worker task failed.",
        );
    };

    let mut any_fail = false;
    let mut lines = Vec::with_capacity(results.len());
    for (service_id, port, res) in results {
        match res {
            Ok(PortCheckResult::Available) => {
                lines.push(format!(
                    "{} Port {port} (service '{service_id}'): available.",
                    CheckStatus::Pass.tag()
                ));
            }
            Ok(PortCheckResult::Occupied(Some(info))) => {
                any_fail = true;
                lines.push(format!(
                    "{} Port {} (service '{}'): conflict detected (pid={}, process_name='{}', cmdline='{}').",
                    CheckStatus::Fail.tag(),
                    info.port,
                    service_id,
                    info.pid,
                    info.process_name,
                    info.cmdline
                ));
            }
            Ok(PortCheckResult::Occupied(None)) => {
                any_fail = true;
                lines.push(format!(
                    "{} Port {port} (service '{service_id}'): conflict detected (occupant PID unavailable).",
                    CheckStatus::Fail.tag()
                ));
            }
            Err(err) => {
                any_fail = true;
                lines.push(format!(
                    "{} Port {port} (service '{service_id}'): inspection error: {err}",
                    CheckStatus::Fail.tag()
                ));
            }
        }
    }

    CheckOutcome {
        status: if any_fail {
            CheckStatus::Fail
        } else {
            CheckStatus::Pass
        },
        lines,
    }
}

async fn check_docker_daemon(
    project: &str,
    workspace_root: Option<&Path>,
    uses_docker: bool,
    docker_mode: DockerCheckMode,
) -> CheckOutcome {
    let ping_res: Result<(), String> = match docker_mode {
        #[cfg(test)]
        DockerCheckMode::Client(client) => ping_docker_client(&client).await,
        #[cfg(test)]
        DockerCheckMode::PingOutcome(outcome) => outcome,
        DockerCheckMode::Live => {
            if let Err(err) = DockerContainerExecutor::connect_local(
                project,
                workspace_root.map(Path::to_path_buf),
            ) {
                Err(err.to_string())
            } else {
                match Docker::connect_with_local_defaults() {
                    Ok(client) => ping_docker_client(&client).await,
                    Err(err) => Err(err.to_string()),
                }
            }
        }
    };

    match ping_res {
        Ok(()) => CheckOutcome::single(
            CheckStatus::Pass,
            "Docker Daemon: reachable and responding to ping.",
        ),
        Err(reason) => {
            if uses_docker {
                CheckOutcome::single(
                    CheckStatus::Fail,
                    format!(
                        "Docker Daemon: unreachable ({reason}); required by docker_container/docker_compose services."
                    ),
                )
            } else {
                CheckOutcome::single(
                    CheckStatus::Warn,
                    format!(
                        "Docker Daemon: unreachable ({reason}); only native services are configured."
                    ),
                )
            }
        }
    }
}

async fn ping_docker_client(client: &Docker) -> Result<(), String> {
    match tokio::time::timeout(DOCKER_PING_TIMEOUT, client.ping()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(err)) => Err(err.to_string()),
        Err(_) => Err("ping timed out".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anvil_secret::SecretBackend;
    use bollard::API_DEFAULT_VERSION;
    use std::fs;
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::process::{Child, Command};
    use tempfile::TempDir;

    struct ChildCleanupGuard(Option<Child>);

    impl Drop for ChildCleanupGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn unreachable_docker_client() -> anyhow::Result<Docker> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let addr = listener.local_addr()?;
        drop(listener);
        Ok(Docker::connect_with_http(
            &format!("http://{addr}"),
            1,
            API_DEFAULT_VERSION,
        )?)
    }

    fn write_yaml(dir: &Path, yaml: &str) -> anyhow::Result<PathBuf> {
        let path = dir.join("anvil.yaml");
        fs::write(&path, yaml)?;
        Ok(path)
    }

    #[tokio::test]
    async fn doctor_detects_port_conflict_with_pid_and_missing_secret() -> anyhow::Result<()> {
        let tmp = TempDir::new()?;
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        let data_dir = tmp.path().join("data");
        let passphrase = Zeroizing::new("doctor-pass-1".to_owned());

        let yaml = format!(
            "version: \"1\"\nproject:\n  name: \"doc-port-test\"\nsecrets:\n  - DB_PASSWORD\n  - MISSING_SECRET\nservices:\n  api:\n    runtime:\n      type: native\n      cmd: \"echo ok\"\n    port: {port}\n"
        );
        let config_path = write_yaml(tmp.path(), &yaml)?;

        let vault = anvil_secret::LocalEncryptedVault::with_dir(
            secret::vault_dir_for(&data_dir),
            passphrase.clone(),
        );
        vault.set(
            "doc-port-test",
            "DB_PASSWORD",
            Zeroizing::new("ultra_secret_never_print".to_owned()),
        )?;

        let globals = GlobalOptions {
            config: config_path,
            data_dir: Some(data_dir),
            project: None,
        };

        let mut out = Vec::new();
        let err = run_with(
            &globals,
            false,
            Some(passphrase.clone()),
            DockerCheckMode::Client(unreachable_docker_client()?),
            &mut out,
        )
        .await;
        assert!(err.is_err());

        let report = String::from_utf8(out)?;
        assert!(report.contains("[PASS] Config & DAG"));
        assert!(report.contains("[FAIL] Secrets: missing 1 declared secret(s)"));
        assert!(report.contains("MISSING_SECRET"));
        assert!(!report.contains("ultra_secret_never_print"));
        assert!(report.contains("[PASS] Lockfile"));
        assert!(report.contains(&format!("[FAIL] Port {port} (service 'api')")));
        assert!(report.contains(&format!("pid={}", std::process::id())));
        assert!(report.contains("process_name="));
        assert!(report.contains("cmdline="));
        assert!(report.contains("[WARN] Docker Daemon"));

        // Release port and populate missing secret -> all checks pass (Docker is non-blocking WARN).
        drop(listener);
        vault.set(
            "doc-port-test",
            "MISSING_SECRET",
            Zeroizing::new("now_present".to_owned()),
        )?;

        let mut ok_out = Vec::new();
        run_with(
            &globals,
            false,
            Some(passphrase),
            DockerCheckMode::Client(unreachable_docker_client()?),
            &mut ok_out,
        )
        .await?;
        let ok_report = String::from_utf8(ok_out)?;
        assert!(ok_report.contains("[PASS] Secrets: all 2 declared secret(s)"));
        assert!(ok_report.contains(&format!("[PASS] Port {port} (service 'api'): available")));
        assert!(!ok_report.contains("[FAIL]"));
        Ok(())
    }

    #[tokio::test]
    async fn doctor_detects_dag_cycle_and_docker_requirement() -> anyhow::Result<()> {
        let tmp = TempDir::new()?;
        let data_dir = tmp.path().join("data");
        let yaml = r#"
version: "1"
project:
  name: "doc-cycle-test"
services:
  a:
    runtime:
      type: docker_container
      image: "alpine:3"
    depends_on: [b]
  b:
    runtime:
      type: native
      cmd: "echo b"
    depends_on: [a]
"#;
        let config_path = write_yaml(tmp.path(), yaml)?;
        let globals = GlobalOptions {
            config: config_path,
            data_dir: Some(data_dir),
            project: None,
        };

        let mut out = Vec::new();
        let err = run_with(
            &globals,
            false,
            None,
            DockerCheckMode::Client(unreachable_docker_client()?),
            &mut out,
        )
        .await;
        assert!(err.is_err());

        let report = String::from_utf8(out)?;
        assert!(report.contains("[FAIL] Config & DAG: dependency cycle detected: a -> b -> a"));
        assert!(report.contains("[FAIL] Docker Daemon: unreachable"));

        let docker_outcome = check_docker_daemon(
            "doc-cycle-test",
            None,
            true,
            DockerCheckMode::PingOutcome(Ok(())),
        )
        .await;
        assert_eq!(docker_outcome.status, CheckStatus::Pass);
        Ok(())
    }

    #[tokio::test]
    async fn doctor_reports_and_reaps_orphans_safely() -> anyhow::Result<()> {
        let tmp = TempDir::new()?;
        let data_dir = tmp.path().join("data");
        let yaml = r#"
version: "1"
project:
  name: "doc-reap-test"
services:
  worker:
    runtime:
      type: native
      cmd: "echo worker"
"#;
        let config_path = write_yaml(tmp.path(), yaml)?;
        let controller = DefaultProcessController::new();

        let mut cmd = if std::env::consts::OS == "windows" {
            let mut c = Command::new("cmd");
            c.args(["/C", "ping -n 60 127.0.0.1 > nul"]);
            c
        } else {
            let mut c = Command::new("sleep");
            c.arg("60");
            c
        };
        controller.prepare_command(&mut cmd)?;
        let child = cmd.spawn()?;
        let (_handle, identity) = controller.attach_child(&child)?;
        let mut child_guard = ChildCleanupGuard(Some(child));

        let store = LockfileStore::with_dir(data_dir.join("run"));
        store.record_process(
            "doc-reap-test",
            LockRecord {
                service_id: "orphan-svc".to_owned(),
                pid: identity.pid,
                pgid: identity.pgid,
                start_time_secs: identity.start_time_secs,
                exe_name: identity.exe_name.clone(),
            },
        )?;
        // Record with forged start_time_secs=0 to simulate PID reuse (must never kill self).
        let self_pid = std::process::id();
        store.record_process(
            "doc-reap-test",
            LockRecord {
                service_id: "reused-svc".to_owned(),
                pid: self_pid,
                pgid: self_pid,
                start_time_secs: 0,
                exe_name: "not-anvil-test".to_owned(),
            },
        )?;

        let globals = GlobalOptions {
            config: config_path,
            data_dir: Some(data_dir.clone()),
            project: None,
        };

        let mut inspect_out = Vec::new();
        run_with(
            &globals,
            false,
            None,
            DockerCheckMode::Client(unreachable_docker_client()?),
            &mut inspect_out,
        )
        .await?;
        let inspect_report = String::from_utf8(inspect_out)?;
        assert!(inspect_report.contains("[WARN] Lockfile: found 1 live orphan process(es) and 1 stale/reused PID(s)"));
        assert!(inspect_report.contains("orphan-svc"));
        assert!(inspect_report.contains("reused-svc"));

        let mut reap_out = Vec::new();
        run_with(
            &globals,
            true,
            None,
            DockerCheckMode::Client(unreachable_docker_client()?),
            &mut reap_out,
        )
        .await?;
        if let Some(mut c) = child_guard.0.take() {
            let _ = c.wait();
        }
        let reap_report = String::from_utf8(reap_out)?;
        assert!(reap_report.contains("[PASS] Lockfile (--reap): ReapReport { reaped: 1, skipped_pid_reuse: 1 }"));
        assert!(!controller.is_process_alive(identity.pid));
        assert!(controller.is_process_alive(self_pid));
        assert!(store.load_workspace("doc-reap-test")?.is_none());
        Ok(())
    }
}
