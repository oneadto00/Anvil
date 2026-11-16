//! Implementation of `anvil up`: config loading, orphan reaping, TUI/foreground/detach modes.

use crate::{
    args::GlobalOptions,
    commands::runtime_bridge::{CompositeSecretBackend, HybridEngineExecutor},
    terminal::{self, TerminalGuard},
};
use anyhow::{bail, Context, Result};
use anvil_core::{
    persistence::WorkspacePersistence, AnvilConfig, DependencyGraph, EngineChannels, EngineCommand,
    Orchestrator, PortOccupant, RuntimeConfig, ServiceId, ServiceState, WorkspaceSnapshot,
};
use anvil_secret::{extract_secret_refs, KeyringStore, LocalEncryptedVault, SecretBackend};
use anvil_sys::{DefaultProcessController, LockfileStore, ProcessController};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

const REAP_GRACE_PERIOD: Duration = Duration::from_secs(3);
const CRASH_TAIL_LINES: usize = 200;
const DETACH_POLL_INTERVAL: Duration = Duration::from_millis(50);
const DETACH_NATIVE_POLL_TIMEOUT: Duration = Duration::from_millis(1500);
const DETACH_MIN_ALIVE_WINDOW: Duration = Duration::from_millis(250);

/// Executes the `anvil up` subcommand in TUI, foreground (`--no-tui`), or background (`--detach`) mode.
pub async fn execute(
    globals: &GlobalOptions,
    detach: bool,
    no_tui: bool,
    daemon_child: bool,
) -> Result<()> {
    let config = Arc::new(load_and_validate_config(globals)?);
    let graph = DependencyGraph::from_config(&config).context("invalid service dependency graph")?;
    let data_root = resolve_data_root(globals.data_dir.as_deref())?;

    reap_stale_locks(&data_root, &config.project.name).await?;

    if detach && !daemon_child {
        return run_detached(globals, &config, &data_root).await;
    }

    let shutdown_rx = terminal::subscribe_shutdown_signal()
        .context("failed to install OS termination signal handler")?;

    run_foreground(
        globals,
        config,
        graph,
        &data_root,
        no_tui || daemon_child,
        daemon_child,
        shutdown_rx,
    )
    .await
}

fn load_and_validate_config(globals: &GlobalOptions) -> Result<AnvilConfig> {
    let mut config = AnvilConfig::from_file(&globals.config)
        .with_context(|| format!("failed to load config from {}", globals.config.display()))?;
    if let Some(project_override) = &globals.project {
        config.project.name = project_override.clone();
        config
            .validate()
            .map_err(anvil_core::CoreError::ValidationErrors)
            .context("invalid workspace configuration after applying --project override")?;
    }
    Ok(config)
}

fn resolve_data_root(data_dir: Option<&Path>) -> Result<PathBuf> {
    if let Some(dir) = data_dir {
        return Ok(dir.to_path_buf());
    }
    let home = dirs::home_dir().context("could not determine user home directory")?;
    Ok(home.join(".anvil"))
}

fn resolve_workspace_root(config_path: &Path) -> Option<PathBuf> {
    let abs = std::path::absolute(config_path).ok()?;
    abs.parent().map(Path::to_path_buf)
}

async fn reap_stale_locks(data_root: &Path, project_name: &str) -> Result<anvil_sys::ReapReport> {
    let run_dir = data_root.join("run");
    let project = project_name.to_owned();
    let report = tokio::task::spawn_blocking(move || {
        let store = LockfileStore::with_dir(run_dir);
        let controller = DefaultProcessController::new();
        store.reap_orphans(&project, &controller, REAP_GRACE_PERIOD)
    })
    .await
    .context("orphan reaper task failed")?
    .context("failed to reap stale workspace locks")?;
    Ok(report)
}

async fn prepare_secret_backend(
    config: &AnvilConfig,
    data_root: &Path,
    interactive_prompt: bool,
) -> Result<Arc<dyn SecretBackend>> {
    let vault_dir = data_root.join("vault");
    let keyring = KeyringStore::with_index_dir(&vault_dir);
    let vault = Arc::new(LocalEncryptedVault::locked_with_dir(&vault_dir));
    let project = config.project.name.clone();

    let referenced_keys = collect_referenced_secret_keys(config);
    if referenced_keys.is_empty() {
        return Ok(Arc::new(CompositeSecretBackend::new(keyring, vault)));
    }

    let vault_path = vault
        .vault_path(&project)
        .context("failed to resolve vault path")?;
    if !vault_path.is_file() {
        return Ok(Arc::new(CompositeSecretBackend::new(keyring, vault)));
    }

    let probe_keyring = KeyringStore::with_index_dir(&vault_dir);
    let keys_for_probe = referenced_keys.clone();
    let project_for_probe = project.clone();
    let first_missing = tokio::task::spawn_blocking(move || {
        for key in keys_for_probe {
            match probe_keyring.get(&project_for_probe, &key) {
                Ok(Some(_)) => {}
                Ok(None) | Err(anvil_secret::SecretError::KeyringUnavailable(_)) => {
                    return Ok(Some(key));
                }
                Err(err) => return Err(err),
            }
        }
        Ok(None)
    })
    .await
    .context("secret backend check task failed")?
    .context("failed to query OS keyring")?;

    let Some(verify_key) = first_missing else {
        return Ok(Arc::new(CompositeSecretBackend::new(keyring, vault)));
    };

    if let Ok(passphrase) = std::env::var("ANVIL_VAULT_PASSPHRASE") {
        if !passphrase.is_empty() {
            vault
                .unlock(Zeroizing::new(passphrase))
                .context("failed to unlock encrypted vault")?;
        }
    } else if interactive_prompt && io::stdin().is_terminal() {
        let prompt = format!("Enter vault passphrase for project '{project}': ");
        let passphrase = tokio::task::spawn_blocking(move || rpassword::prompt_password(prompt))
            .await
            .context("vault passphrase prompt task failed")?
            .context("failed to read vault passphrase")?;
        vault
            .unlock(Zeroizing::new(passphrase))
            .context("failed to unlock encrypted vault")?;

        let verify_vault = Arc::clone(&vault);
        let verify_project = project.clone();
        tokio::task::spawn_blocking(move || verify_vault.get(&verify_project, &verify_key))
            .await
            .context("vault verification task failed")?
            .context("failed to decrypt local secret vault")?;
    }

    Ok(Arc::new(CompositeSecretBackend::new(keyring, vault)))
}

fn collect_referenced_secret_keys(config: &AnvilConfig) -> Vec<String> {
    let mut keys = BTreeSet::new();
    for val in config.env.values() {
        keys.extend(extract_secret_refs(val));
    }
    for svc in config.services.values() {
        for val in svc.env.values() {
            keys.extend(extract_secret_refs(val));
        }
    }
    keys.into_iter().collect()
}

async fn run_detached(
    globals: &GlobalOptions,
    config: &AnvilConfig,
    data_root: &Path,
) -> Result<()> {
    let exe = std::env::current_exe().context("failed to resolve current anvil binary path")?;
    let abs_config = std::path::absolute(&globals.config)
        .with_context(|| format!("failed to resolve path {}", globals.config.display()))?;
    let abs_data_dir = match &globals.data_dir {
        Some(dir) => Some(
            std::path::absolute(dir)
                .with_context(|| format!("failed to resolve path {}", dir.display()))?,
        ),
        None => None,
    };

    let mut cmd = build_detached_command(
        &exe,
        &abs_config,
        abs_data_dir.as_deref(),
        globals.project.as_deref(),
    )?;
    let mut child = cmd
        .spawn()
        .context("failed to spawn detached anvil daemon")?;
    let child_pid = child.id();

    let has_native = config
        .services
        .values()
        .any(|svc| matches!(svc.runtime, RuntimeConfig::Native { .. }));
    let run_dir = data_root.join("run");
    let project = config.project.name.clone();
    let deadline = Instant::now()
        + if has_native {
            DETACH_NATIVE_POLL_TIMEOUT
        } else {
            DETACH_MIN_ALIVE_WINDOW
        };
    let min_alive_at = Instant::now() + DETACH_MIN_ALIVE_WINDOW;

    loop {
        if let Some(status) = child
            .try_wait()
            .context("failed to poll detached daemon status")?
        {
            if !status.success() {
                bail!("detached anvil daemon exited early with status {status}");
            }
            let _ = writeln!(
                io::stdout(),
                "Anvil workspace '{}' finished cleanly in background (pid {child_pid}).",
                config.project.name
            );
            return Ok(());
        }

        if has_native {
            let poll_dir = run_dir.clone();
            let poll_project = project.clone();
            let lock_ready = tokio::task::spawn_blocking(move || {
                LockfileStore::with_dir(poll_dir)
                    .load_workspace(&poll_project)
                    .map(|opt| opt.is_some_and(|lock| !lock.processes.is_empty()))
            })
            .await
            .context("lockfile poll task failed")?
            .context("failed to inspect workspace lockfile")?;

            if lock_ready {
                break;
            }
        } else if Instant::now() >= min_alive_at {
            break;
        }

        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(DETACH_POLL_INTERVAL).await;
    }

    let _ = writeln!(
        io::stdout(),
        "Anvil workspace '{}' started in background (pid {child_pid}).",
        config.project.name
    );
    Ok(())
}

fn build_detached_command(
    exe: &Path,
    config_path: &Path,
    data_dir: Option<&Path>,
    project: Option<&str>,
) -> Result<Command> {
    let mut cmd = Command::new(exe);
    cmd.arg("--config").arg(config_path);
    if let Some(dir) = data_dir {
        cmd.arg("--data-dir").arg(dir);
    }
    if let Some(name) = project {
        cmd.arg("--project").arg(name);
    }
    cmd.args(["up", "--daemon-child", "--no-tui"]);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    DefaultProcessController::new()
        .prepare_command(&mut cmd)
        .context("failed to isolate detached child process group")?;
    Ok(cmd)
}

async fn run_foreground(
    globals: &GlobalOptions,
    config: Arc<AnvilConfig>,
    graph: DependencyGraph,
    data_root: &Path,
    no_tui: bool,
    daemon_child: bool,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let persistence = WorkspacePersistence::with_root(data_root, &config.project.name)
        .context("failed to initialize workspace persistence")?;
    let secret_backend = prepare_secret_backend(&config, data_root, !daemon_child).await?;
    let workspace_root = resolve_workspace_root(&globals.config);

    let executor = Arc::new(HybridEngineExecutor::new(
        Arc::clone(&config),
        persistence.clone(),
        secret_backend,
        workspace_root,
    ));

    if no_tui {
        run_no_tui_mode(
            config,
            graph,
            persistence,
            executor,
            shutdown_rx,
            daemon_child,
        )
        .await
    } else {
        run_tui_mode(config, graph, persistence, executor, shutdown_rx).await
    }
}

async fn run_tui_mode(
    config: Arc<AnvilConfig>,
    graph: DependencyGraph,
    persistence: WorkspacePersistence,
    executor: Arc<HybridEngineExecutor>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let mut terminal_guard = TerminalGuard::new().context("failed to enter terminal UI mode")?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).context("failed to initialize ratatui terminal")?;
    let _ = terminal.clear();

    let (actor, channels) = Orchestrator::new(Arc::clone(&config), &graph, executor.clone());
    executor.bind_orchestrator(&actor);
    drop(executor);

    let actor_handle = tokio::spawn(
        actor
            .with_crash_persistence(persistence, CRASH_TAIL_LINES)
            .run(),
    );

    let cmd_tx = channels.commands.clone();
    cmd_tx
        .send(EngineCommand::StartWorkspace)
        .await
        .context("failed to start workspace orchestration")?;

    let mut tui_result: Option<Result<(), anvil_tui::TuiError>> = None;
    tokio::select! {
        res = anvil_tui::run_tui(&mut terminal, channels) => {
            tui_result = Some(res);
        }
        _ = terminal::wait_for_shutdown(&mut shutdown_rx) => {}
    }

    let _ = cmd_tx.send(EngineCommand::Shutdown).await;
    drop(cmd_tx);

    let actor_result = actor_handle
        .await
        .context("orchestrator actor task panicked during shutdown")?;

    drop(terminal);
    terminal_guard.restore();

    if let Some(Err(err)) = tui_result {
        actor_result.context("orchestrator failed during shutdown")?;
        return Err(err).context("TUI loop exited with error");
    }
    actor_result.context("orchestrator exited with error")?;
    Ok(())
}

async fn run_no_tui_mode(
    config: Arc<AnvilConfig>,
    graph: DependencyGraph,
    persistence: WorkspacePersistence,
    executor: Arc<HybridEngineExecutor>,
    shutdown_rx: watch::Receiver<bool>,
    silent_output: bool,
) -> Result<()> {
    let (actor, channels) = Orchestrator::new(Arc::clone(&config), &graph, executor.clone());
    executor.bind_orchestrator(&actor);
    drop(executor);

    let actor_handle = tokio::spawn(
        actor
            .with_crash_persistence(persistence, CRASH_TAIL_LINES)
            .run(),
    );

    channels
        .commands
        .send(EngineCommand::StartWorkspace)
        .await
        .context("failed to start workspace orchestration")?;

    pump_no_tui_events(channels, shutdown_rx, silent_output).await;

    let actor_result = actor_handle
        .await
        .context("orchestrator actor task panicked during shutdown")?;
    actor_result.context("orchestrator exited with error")?;
    Ok(())
}

async fn pump_no_tui_events(
    mut channels: EngineChannels,
    mut shutdown_rx: watch::Receiver<bool>,
    silent_output: bool,
) {
    let mut cmd_tx: Option<mpsc::Sender<EngineCommand>> = Some(channels.commands);
    let mut prev_states: BTreeMap<ServiceId, ServiceState> = channels
        .snapshots
        .borrow_and_update()
        .services
        .keys()
        .map(|id| (id.clone(), ServiceState::Idle))
        .collect();
    report_state_changes(
        &mut prev_states,
        &channels.snapshots.borrow().clone(),
        silent_output,
    );

    let mut shutdown_sent = false;
    let mut snapshots_open = true;
    let mut logs_open = true;

    while snapshots_open || logs_open {
        tokio::select! {
            _ = terminal::wait_for_shutdown(&mut shutdown_rx), if !shutdown_sent => {
                shutdown_sent = true;
                if !silent_output {
                    let _ = writeln!(io::stderr(), "[anvil] shutdown signal received, stopping services...");
                }
                if let Some(tx) = cmd_tx.take() {
                    let _ = tx.send(EngineCommand::Shutdown).await;
                }
            }
            changed = channels.snapshots.changed(), if snapshots_open => {
                match changed {
                    Ok(()) => {
                        let snap = channels.snapshots.borrow_and_update().clone();
                        report_state_changes(&mut prev_states, &snap, silent_output);
                    }
                    Err(_) => {
                        snapshots_open = false;
                    }
                }
            }
            maybe_batch = channels.logs.recv(), if logs_open => {
                match maybe_batch {
                    Some(batch) => {
                        if !silent_output {
                            let mut stdout = io::stdout();
                            for line in batch.lines {
                                let _ = writeln!(stdout, "[{}] {}", batch.service_id, line);
                            }
                        }
                    }
                    None => {
                        logs_open = false;
                    }
                }
            }
        }
    }
}

fn report_state_changes(
    prev_states: &mut BTreeMap<ServiceId, ServiceState>,
    snapshot: &WorkspaceSnapshot,
    silent_output: bool,
) {
    for (id, svc) in &snapshot.services {
        let changed = prev_states.get(id) != Some(&svc.state);
        if !changed {
            continue;
        }
        prev_states.insert(id.clone(), svc.state.clone());
        if silent_output {
            continue;
        }
        let summary = format_state_summary(&svc.state);
        let _ = writeln!(io::stderr(), "[anvil] {id}: {summary}");
    }
}

fn format_state_summary(state: &ServiceState) -> String {
    match state {
        ServiceState::Idle => "idle".to_owned(),
        ServiceState::WaitingDeps { pending_deps } => {
            format!("waiting for dependencies ({})", pending_deps.join(", "))
        }
        ServiceState::PortCheck => "checking port availability".to_owned(),
        ServiceState::PortConflict(PortOccupant {
            port,
            pid,
            process_name,
            ..
        }) => format!("port {port} conflict (pid {pid}, process {process_name})"),
        ServiceState::Starting => "starting".to_owned(),
        ServiceState::Probing { .. } => "running readiness probe".to_owned(),
        ServiceState::Healthy { .. } => "healthy".to_owned(),
        ServiceState::Unhealthy { reason } => format!("unhealthy ({reason})"),
        ServiceState::Stopping => "stopping".to_owned(),
        ServiceState::Stopped { exit_code } => match exit_code {
            Some(code) => format!("stopped (exit code {code})"),
            None => "stopped".to_owned(),
        },
        ServiceState::Crashed {
            exit_code,
            signal,
            reason,
            crash_log_path,
        } => {
            let mut msg = format!("crashed ({reason}");
            if let Some(code) = exit_code {
                msg.push_str(&format!(", exit code {code}"));
            }
            if let Some(sig) = signal {
                msg.push_str(&format!(", signal {sig}"));
            }
            if !crash_log_path.is_empty() {
                msg.push_str(&format!(", crash log: {crash_log_path}"));
            }
            msg.push(')');
            msg
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal::ShutdownSignal;
    use anvil_secret::LocalEncryptedVault;
    use tempfile::TempDir;

    #[test]
    fn build_detached_command_forwards_flags_and_isolates_stdio() -> Result<()> {
        let cmd = build_detached_command(
            Path::new("/usr/local/bin/anvil"),
            Path::new("/tmp/proj/anvil.yaml"),
            Some(Path::new("/tmp/proj/data")),
            Some("custom-proj"),
        )?;
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "--config",
                "/tmp/proj/anvil.yaml",
                "--data-dir",
                "/tmp/proj/data",
                "--project",
                "custom-proj",
                "up",
                "--daemon-child",
                "--no-tui",
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn foreground_no_tui_mode_reaps_orphans_runs_with_vault_and_shuts_down_cleanly(
    ) -> Result<()> {
        let dir = TempDir::new()?;
        let data_dir = dir.path().join("anvil-data");
        let vault_dir = data_dir.join("vault");
        let pid_file = dir.path().join("service.pid");
        let secret_val = "vault_only_secret_token_42";

        let vault = LocalEncryptedVault::with_dir(&vault_dir, Zeroizing::new("vault-pass".into()));
        vault.set("up-e2e", "API_KEY", Zeroizing::new(secret_val.to_owned()))?;

        // Record a non-existent / mismatched stale lock entry to verify reap_stale_locks skips PID reuse.
        let lock_store = LockfileStore::with_dir(data_dir.join("run"));
        lock_store.record_process(
            "up-e2e",
            anvil_sys::LockRecord {
                service_id: "stale".to_owned(),
                pid: std::process::id(),
                pgid: std::process::id(),
                start_time_secs: 0,
                exe_name: "not-anvil".to_owned(),
            },
        )?;

        let cmd = if std::env::consts::OS == "windows" {
            let script = dir.path().join("run.cmd");
            std::fs::write(
                &script,
                format!(
                    "@echo off\r\necho READY\r\necho token=%API_KEY%\r\npowershell -NoProfile -NonInteractive -Command \"$PID | Out-File -Encoding ascii '{}'; Start-Sleep 30\"\r\n",
                    pid_file.display()
                ),
            )?;
            format!("\"{}\"", script.display())
        } else {
            format!(
                r#"echo "READY"; echo "token=$API_KEY"; sleep 30 & child=$!; echo "$child" > "{}"; wait "$child""#,
                pid_file.display()
            )
        };

        let config_path = dir.path().join("anvil.yaml");
        let yaml = format!(
            "version: \"1\"\nproject:\n  name: \"up-e2e\"\nsecrets:\n  - API_KEY\nservices:\n  api:\n    runtime:\n      type: native\n      cmd: '{}'\n      grace_period_ms: 150\n    env:\n      API_KEY: \"${{SECRET:API_KEY}}\"\n    readiness_probe:\n      type: log_regex\n      pattern: \"^READY$\"\n      timeout_ms: 5000\n",
            cmd.replace('\'', "''")
        );
        std::fs::write(&config_path, yaml)?;

        let globals = GlobalOptions {
            config: config_path,
            data_dir: Some(data_dir.clone()),
            project: None,
        };
        let config = Arc::new(load_and_validate_config(&globals)?);
        let graph = DependencyGraph::from_config(&config)?;

        let reap_report = reap_stale_locks(&data_dir, &config.project.name).await?;
        assert_eq!(reap_report.reaped, 0);
        assert_eq!(reap_report.skipped_pid_reuse, 1);

        let persistence = WorkspacePersistence::with_root(&data_dir, &config.project.name)?;
        let secret_backend = Arc::new(CompositeSecretBackend::new(
            KeyringStore::with_index_dir(&vault_dir),
            Arc::new(vault),
        ));
        let executor = Arc::new(HybridEngineExecutor::new(
            Arc::clone(&config),
            persistence.clone(),
            secret_backend,
            Some(dir.path().to_path_buf()),
        ));

        let shutdown = ShutdownSignal::new();
        let shutdown_rx = shutdown.subscribe();
        let task = tokio::spawn(run_no_tui_mode(
            config,
            graph,
            persistence,
            executor,
            shutdown_rx,
            true,
        ));

        let mut child_pid = None;
        for _ in 0..80 {
            if let Ok(raw) = std::fs::read_to_string(&pid_file) {
                if let Ok(pid) = raw.trim().parse::<u32>() {
                    child_pid = Some(pid);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let child_pid = child_pid.context("service did not write pid file")?;

        // Give lockfile registration a brief moment if needed, then verify lock exists.
        let mut lock_recorded = false;
        for _ in 0..40 {
            if lock_store
                .load_workspace("up-e2e")?
                .is_some_and(|w| !w.processes.is_empty())
            {
                lock_recorded = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(lock_recorded);

        shutdown.trigger();
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .context("foreground mode did not shut down in time")???;

        assert!(lock_store.load_workspace("up-e2e")?.is_none());
        let alive = tokio::task::spawn_blocking(move || {
            DefaultProcessController::new().is_process_alive(child_pid)
        })
        .await?;
        assert!(!alive);

        let log_text = std::fs::read_to_string(data_dir.join("logs/up-e2e/api.log"))?;
        assert!(log_text.contains("[REDACTED]"));
        assert!(!log_text.contains(secret_val));
        Ok(())
    }
}
