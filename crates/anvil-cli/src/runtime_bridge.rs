//! Connects the orchestrator to runtime executors, secret resolution, and log routing.

use anvil_core::{
    log_ring::{LogEntry, LogError, LogIngestor, LogInput, LogRing, LogSource},
    persistence::WorkspacePersistence,
    probe::{ContainerHealthInspector, ContainerHealthStatus},
    AnvilConfig, CoreError, EngineExecutor, ExecutionError, InstanceExit, LogBatch, Orchestrator,
    RuntimeConfig, RuntimeIdentity, ServiceConfig, ServiceId, StartedInstance,
};
use anvil_runtime::{
    DockerContainerExecutor, ExitStatusEvent, NativeProcessExecutor, RawLogLine, RuntimeExecutor,
    StreamSource,
};
use anvil_secret::{
    extract_secret_refs, resolve_env_map, KeyringStore, LocalEncryptedVault, SecretBackend,
    SecretError,
};
use anvil_sys::LockRecord;
use std::{
    collections::{BTreeSet, HashMap},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tokio::sync::{broadcast, mpsc, oneshot};
use zeroize::{Zeroize, Zeroizing};

const LOG_CHANNEL_CAPACITY: usize = 256;

/// Composite secret backend prioritizing [`KeyringStore`] with fallback to
/// [`LocalEncryptedVault`] when the keyring lacks an entry or is unavailable.
pub struct CompositeSecretBackend {
    keyring: KeyringStore,
    vault: Arc<LocalEncryptedVault>,
}

impl CompositeSecretBackend {
    /// Creates a composite backend using the supplied keyring and fallback vault.
    pub fn new(keyring: KeyringStore, vault: Arc<LocalEncryptedVault>) -> Self {
        Self { keyring, vault }
    }

    fn vault_exists(&self, project: &str) -> Result<bool, SecretError> {
        Ok(self.vault.vault_path(project)?.is_file())
    }
}

impl SecretBackend for CompositeSecretBackend {
    fn get(&self, project: &str, key: &str) -> Result<Option<Zeroizing<String>>, SecretError> {
        match self.keyring.get(project, key) {
            Ok(Some(value)) => Ok(Some(value)),
            Ok(None) => {
                if self.vault_exists(project)? {
                    self.vault.get(project, key)
                } else {
                    Ok(None)
                }
            }
            Err(SecretError::KeyringUnavailable(reason)) => {
                if self.vault_exists(project)? {
                    self.vault.get(project, key)
                } else {
                    Err(SecretError::KeyringUnavailable(reason))
                }
            }
            Err(err) => Err(err),
        }
    }

    fn set(&self, project: &str, key: &str, value: Zeroizing<String>) -> Result<(), SecretError> {
        match self.keyring.set(project, key, value.clone()) {
            Ok(()) => Ok(()),
            Err(SecretError::KeyringUnavailable(_)) => self.vault.set(project, key, value),
            Err(err) => Err(err),
        }
    }

    fn delete(&self, project: &str, key: &str) -> Result<(), SecretError> {
        let keyring_res = self.keyring.delete(project, key);
        if self.vault_exists(project)? {
            let vault_res = self.vault.delete(project, key);
            if matches!(keyring_res, Ok(()) | Err(SecretError::KeyringUnavailable(_))) {
                return vault_res;
            }
        }
        keyring_res
    }

    fn list_keys(&self, project: &str) -> Result<Vec<String>, SecretError> {
        let mut keys = BTreeSet::new();
        let keyring_err = match self.keyring.list_keys(project) {
            Ok(list) => {
                keys.extend(list);
                None
            }
            Err(err) => Some(err),
        };
        if self.vault_exists(project)? {
            match self.vault.list_keys(project) {
                Ok(list) => keys.extend(list),
                Err(err) if keys.is_empty() => return Err(err),
                Err(_) => {}
            }
        }
        if keys.is_empty() {
            if let Some(err) = keyring_err {
                if !matches!(err, SecretError::KeyringUnavailable(_)) {
                    return Err(err);
                }
            }
        }
        Ok(keys.into_iter().collect())
    }
}

/// Hybrid runtime adapter connecting `Orchestrator` to native process-tree and lazy Docker executors.
pub struct HybridEngineExecutor {
    project_name: String,
    workspace_config: Arc<AnvilConfig>,
    persistence: WorkspacePersistence,
    secret_backend: Arc<dyn SecretBackend>,
    workspace_root: Option<PathBuf>,
    native: NativeProcessExecutor,
    docker: Arc<Mutex<Option<Arc<DockerContainerExecutor>>>>,
    has_docker_services: bool,
    ui_log_pipes: Mutex<HashMap<ServiceId, mpsc::Sender<LogInput>>>,
}

impl HybridEngineExecutor {
    /// Builds a hybrid executor from validated workspace configuration and runtime dependencies.
    ///
    /// Docker Engine connections are deferred until a Docker or Compose service actually starts
    /// or is inspected, so pure-native workspaces never require a running Docker daemon.
    pub fn new(
        workspace_config: Arc<AnvilConfig>,
        persistence: WorkspacePersistence,
        secret_backend: Arc<dyn SecretBackend>,
        workspace_root: Option<PathBuf>,
    ) -> Self {
        let project_name = workspace_config.project.name.clone();
        let has_docker_services = workspace_config.services.values().any(|svc| {
            matches!(
                svc.runtime,
                RuntimeConfig::DockerContainer { .. } | RuntimeConfig::DockerCompose { .. }
            )
        });
        let native = NativeProcessExecutor::new(workspace_root.clone());
        Self {
            project_name,
            workspace_config,
            persistence,
            secret_backend,
            workspace_root,
            native,
            docker: Arc::new(Mutex::new(None)),
            has_docker_services,
            ui_log_pipes: Mutex::new(HashMap::new()),
        }
    }

    /// Connects per-service UI batching ingestors obtained from [`Orchestrator::service_log_ingestor`].
    ///
    /// Must be called while a Tokio runtime is active before spawning `actor.run()`.
    pub fn bind_orchestrator(&self, actor: &Orchestrator) {
        let mut pipes = lock_unpoisoned(&self.ui_log_pipes);
        for service_id in self.workspace_config.services.keys() {
            if pipes.contains_key(service_id) {
                continue;
            }
            let (complete_tx, mut complete_rx) = mpsc::channel::<LogEntry>(LOG_CHANNEL_CAPACITY);
            let ingestor = actor.service_log_ingestor(service_id.clone(), complete_tx);
            let (input_tx, input_rx) = mpsc::channel::<LogInput>(LOG_CHANNEL_CAPACITY);
            tokio::spawn(async move {
                while complete_rx.recv().await.is_some() {}
            });
            tokio::spawn(async move {
                let _ = ingestor.run(input_rx).await;
            });
            pipes.insert(service_id.clone(), input_tx);
        }
    }

    fn ui_pipe_for(&self, service_id: &str) -> Option<mpsc::Sender<LogInput>> {
        lock_unpoisoned(&self.ui_log_pipes).get(service_id).cloned()
    }

    fn get_or_connect_docker(&self) -> Result<Arc<DockerContainerExecutor>, ExecutionError> {
        connect_docker_lazy(&self.docker, &self.project_name, &self.workspace_root)
    }
}

struct LazyDockerHealthInspector {
    project_name: String,
    workspace_root: Option<PathBuf>,
    docker: Arc<Mutex<Option<Arc<DockerContainerExecutor>>>>,
}

#[async_trait::async_trait]
impl ContainerHealthInspector for LazyDockerHealthInspector {
    async fn inspect_health(
        &self,
        container_ref: &str,
    ) -> Result<ContainerHealthStatus, CoreError> {
        let exec = connect_docker_lazy(&self.docker, &self.project_name, &self.workspace_root)
            .map_err(|_| CoreError::ProbeFailed {
                reason: "failed to connect to local Docker daemon".to_owned(),
            })?;
        exec.inspect_health(container_ref).await
    }
}

fn connect_docker_lazy(
    slot: &Mutex<Option<Arc<DockerContainerExecutor>>>,
    project_name: &str,
    workspace_root: &Option<PathBuf>,
) -> Result<Arc<DockerContainerExecutor>, ExecutionError> {
    let mut guard = slot.lock().map_err(|_| ExecutionError::Task)?;
    if let Some(exec) = guard.as_ref() {
        return Ok(Arc::clone(exec));
    }
    let exec = Arc::new(
        DockerContainerExecutor::connect_local(project_name.to_owned(), workspace_root.clone())
            .map_err(|_| ExecutionError::Start)?,
    );
    *guard = Some(Arc::clone(&exec));
    Ok(exec)
}

#[async_trait::async_trait]
impl EngineExecutor for HybridEngineExecutor {
    async fn start(
        &self,
        id: &str,
        config: &ServiceConfig,
        probe_logs: Option<broadcast::Sender<String>>,
    ) -> Result<StartedInstance, ExecutionError> {
        let workspace_config = Arc::clone(&self.workspace_config);
        let backend = Arc::clone(&self.secret_backend);
        let service_id = id.to_owned();
        let fallback_service_env = config.env.clone();

        // Keyring IPC and Argon2id derivation can block the async executor.
        let resolved = tokio::task::spawn_blocking(move || {
            resolve_service_secrets(
                &workspace_config,
                &service_id,
                &fallback_service_env,
                backend.as_ref(),
            )
        })
        .await
        .map_err(|_| ExecutionError::Task)?
        .map_err(|_| ExecutionError::Start)?;

        let ui_pipe = self.ui_pipe_for(id);
        let pipeline = spawn_log_pipeline(
            id.to_owned(),
            self.persistence.clone(),
            resolved.secrets,
            probe_logs,
            ui_pipe,
        );

        let spawn_result = match &config.runtime {
            RuntimeConfig::Native { .. } => {
                self.native
                    .spawn(id, config, &resolved.env, pipeline.raw_tx)
                    .await
            }
            RuntimeConfig::DockerContainer { .. } | RuntimeConfig::DockerCompose { .. } => {
                let docker = self.get_or_connect_docker()?;
                docker
                    .spawn(id, config, &resolved.env, pipeline.raw_tx)
                    .await
            }
        };

        // Zeroize resolved environment values immediately after spawning.
        drop(resolved.env);

        let (identity, raw_exit_rx) = spawn_result.map_err(|_| ExecutionError::Start)?;

        let lock_record = match &identity {
            RuntimeIdentity::NativeProcess {
                pid,
                pgid,
                start_time_secs,
            } => {
                let record = LockRecord {
                    service_id: id.to_owned(),
                    pid: *pid,
                    pgid: *pgid,
                    start_time_secs: *start_time_secs,
                    exe_name: "unknown".to_owned(),
                };
                if self.persistence.record_native(record.clone()).await.is_err() {
                    let _ = self.native.stop(&identity, Duration::ZERO).await;
                    return Err(ExecutionError::Start);
                }
                Some(record)
            }
            RuntimeIdentity::DockerContainer { .. } => None,
        };

        let exit = spawn_exit_bridge(raw_exit_rx, self.persistence.clone(), lock_record);

        Ok(StartedInstance {
            identity,
            exit,
            drained: pipeline.drained,
            log_written: pipeline.log_written,
        })
    }

    fn health_inspector(&self) -> Option<Arc<dyn ContainerHealthInspector>> {
        if let Some(exec) = lock_unpoisoned(&self.docker).as_ref() {
            return Some(Arc::clone(exec) as Arc<dyn ContainerHealthInspector>);
        }
        if self.has_docker_services {
            return Some(Arc::new(LazyDockerHealthInspector {
                project_name: self.project_name.clone(),
                workspace_root: self.workspace_root.clone(),
                docker: Arc::clone(&self.docker),
            }));
        }
        None
    }

    async fn stop(
        &self,
        identity: &RuntimeIdentity,
        grace: Duration,
    ) -> Result<(), ExecutionError> {
        match identity {
            RuntimeIdentity::NativeProcess { .. } => self
                .native
                .stop(identity, grace)
                .await
                .map_err(|_| ExecutionError::Stop),
            RuntimeIdentity::DockerContainer { .. } => {
                let docker = self
                    .get_or_connect_docker()
                    .map_err(|_| ExecutionError::Stop)?;
                docker
                    .stop(identity, grace)
                    .await
                    .map_err(|_| ExecutionError::Stop)
            }
        }
    }
}

/// Converts runtime exit details to the actor's per-instance event.
pub fn map_exit_status(event: ExitStatusEvent) -> InstanceExit {
    match event {
        ExitStatusEvent::Exited { code, signal } => InstanceExit::Process { code, signal },
        ExitStatusEvent::DockerDie {
            container_id: _,
            exit_code,
            oom_killed,
        } => InstanceExit::Container {
            exit_code,
            oom_killed,
        },
    }
}

struct ResolvedServiceEnv {
    env: HashMap<String, Zeroizing<String>>,
    secrets: Arc<Vec<Zeroizing<String>>>,
}

struct LogPipelineHandles {
    raw_tx: mpsc::Sender<RawLogLine>,
    drained: oneshot::Receiver<Result<LogRing, LogError>>,
    log_written: oneshot::Receiver<Result<(), ExecutionError>>,
}

fn resolve_service_secrets(
    workspace_config: &AnvilConfig,
    service_id: &str,
    fallback_service_env: &std::collections::BTreeMap<String, String>,
    backend: &dyn SecretBackend,
) -> Result<ResolvedServiceEnv, SecretError> {
    let raw_env = workspace_config
        .merged_env_for_service(service_id)
        .unwrap_or_else(|| {
            let mut merged = workspace_config.env.clone();
            for (k, v) in fallback_service_env {
                merged.insert(k.clone(), v.clone());
            }
            merged
        });

    let project = &workspace_config.project.name;
    let decrypted_env = resolve_env_map(project, &raw_env, backend)?;

    let mut sensitive = Vec::new();
    for (env_key, raw_val) in &raw_env {
        let refs = extract_secret_refs(raw_val);
        if refs.is_empty() {
            continue;
        }
        for secret_key in refs {
            if let Some(secret_val) = backend.get(project, &secret_key)? {
                if !secret_val.is_empty() {
                    sensitive.push(secret_val);
                }
            }
        }
        if let Some(resolved_val) = decrypted_env.get(env_key) {
            if !resolved_val.is_empty() {
                sensitive.push(resolved_val.clone());
            }
        }
    }

    // Redact longer values first so overlapping fragments leave less context visible.
    sensitive.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
    Ok(ResolvedServiceEnv {
        env: decrypted_env,
        secrets: Arc::new(sensitive),
    })
}

fn spawn_log_pipeline(
    service_id: ServiceId,
    persistence: WorkspacePersistence,
    sensitive_secrets: Arc<Vec<Zeroizing<String>>>,
    probe_logs: Option<broadcast::Sender<String>>,
    ui_pipe: Option<mpsc::Sender<LogInput>>,
) -> LogPipelineHandles {
    let (raw_tx, mut raw_rx) = mpsc::channel::<RawLogLine>(LOG_CHANNEL_CAPACITY);
    let (launch_input_tx, launch_input_rx) = mpsc::channel::<LogInput>(LOG_CHANNEL_CAPACITY);
    let (complete_tx, complete_rx) = mpsc::channel::<LogEntry>(LOG_CHANNEL_CAPACITY);
    let (dummy_ui_tx, mut dummy_ui_rx) = mpsc::channel::<LogBatch>(64);
    let (drained_tx, drained_rx) = oneshot::channel();
    let (written_tx, written_rx) = oneshot::channel();

    // The per-launch collector supplies persistence. The shared pipe handles UI delivery.
    tokio::spawn(async move {
        while dummy_ui_rx.recv().await.is_some() {}
    });

    let ingestor = LogIngestor::new(service_id.clone(), complete_tx, dummy_ui_tx);
    tokio::spawn(async move {
        let res = ingestor.run(launch_input_rx).await;
        let _ = drained_tx.send(res);
    });

    let writer_service = service_id.clone();
    tokio::spawn(async move {
        let res = persistence
            .write_service_log(&writer_service, complete_rx)
            .await
            .map(|_| ())
            .map_err(|_| ExecutionError::LogWrite);
        let _ = written_tx.send(res);
    });

    tokio::spawn(async move {
        while let Some(mut raw) = raw_rx.recv().await {
            let content = std::mem::take(&mut raw.content);
            let redacted = redact_text(content, &sensitive_secrets);
            let entry = LogEntry {
                source: map_stream_source(raw.source),
                timestamp: SystemTime::from(raw.timestamp),
                redacted_body: Arc::from(redacted),
            };

            if let Some(ref probe_tx) = probe_logs {
                let _ = probe_tx.send(entry.redacted_body.to_string());
            }
            if let Some(ref ui_tx) = ui_pipe {
                let _ = ui_tx.send(LogInput::Line(entry.clone())).await;
            }
            if launch_input_tx.send(LogInput::Line(entry)).await.is_err() {
                break;
            }
        }
        drop(launch_input_tx);
        drop(probe_logs);
        drop(ui_pipe);
    });

    LogPipelineHandles {
        raw_tx,
        drained: drained_rx,
        log_written: written_rx,
    }
}

fn spawn_exit_bridge(
    raw_exit_rx: oneshot::Receiver<ExitStatusEvent>,
    persistence: WorkspacePersistence,
    lock_record: Option<LockRecord>,
) -> oneshot::Receiver<InstanceExit> {
    let (exit_tx, exit_rx) = oneshot::channel();
    tokio::spawn(async move {
        let event = raw_exit_rx.await;
        if let Some(record) = lock_record {
            let _ = persistence.remove_native(record).await;
        }
        if let Ok(status) = event {
            let _ = exit_tx.send(map_exit_status(status));
        }
    });
    exit_rx
}

fn redact_text(mut text: String, secrets: &[Zeroizing<String>]) -> String {
    for secret in secrets {
        for part in secret.lines() {
            if !part.is_empty() && text.contains(part) {
                let replaced = text.replace(part, "[REDACTED]");
                text.zeroize();
                text = replaced;
            }
        }
    }
    text
}

const fn map_stream_source(source: StreamSource) -> LogSource {
    match source {
        StreamSource::Stdout => LogSource::Stdout,
        StreamSource::Stderr => LogSource::Stderr,
        StreamSource::System => LogSource::System,
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result};
    use anvil_core::{DependencyGraph, EngineCommand, ServiceState};
    use anvil_secret::InMemorySecretStore;
    use anvil_sys::{DefaultProcessController, LockfileStore, ProcessController};
    use tempfile::TempDir;

    #[test]
    fn maps_exit_status_events_losslessly() {
        assert!(matches!(
            map_exit_status(ExitStatusEvent::Exited {
                code: Some(7),
                signal: Some(15),
            }),
            InstanceExit::Process {
                code: Some(7),
                signal: Some(15),
            }
        ));
        assert!(matches!(
            map_exit_status(ExitStatusEvent::DockerDie {
                container_id: "cid".to_owned(),
                exit_code: 137,
                oom_killed: true,
            }),
            InstanceExit::Container {
                exit_code: 137,
                oom_killed: true,
            }
        ));
    }

    #[test]
    fn redact_text_scrubs_secrets_and_preserves_context() {
        let secrets = vec![Zeroizing::new("super_secret_api_key".to_owned())];
        let cleaned = redact_text("auth token=super_secret_api_key ok".to_owned(), &secrets);
        assert_eq!(cleaned, "auth token=[REDACTED] ok");
        assert!(!cleaned.contains("super_secret_api_key"));
    }

    #[tokio::test]
    async fn hybrid_executor_resolves_secrets_redacts_logs_and_cleans_locks_on_shutdown(
    ) -> Result<()> {
        let dir = TempDir::new()?;
        let pid_file = dir.path().join("child.pid");
        let env_file = dir.path().join("seen_env.txt");
        let secret_val = "sk_test_only_987654321_secret";

        let cmd = if std::env::consts::OS == "windows" {
            let script = dir.path().join("svc.cmd");
            std::fs::write(
                &script,
                format!(
                    "@echo off\r\n> \"{}\" echo %API_KEY%\r\necho READY\r\necho token=%API_KEY%\r\n1>&2 echo err=%API_KEY%\r\npowershell -NoProfile -NonInteractive -Command \"$PID | Out-File -Encoding ascii '{}'; Start-Sleep 30\"\r\n",
                    env_file.display(),
                    pid_file.display()
                ),
            )?;
            format!("\"{}\"", script.display())
        } else {
            format!(
                r#"printf '%s' "$API_KEY" > "{}"; echo "READY"; echo "token=$API_KEY"; echo "err=$API_KEY" >&2; sleep 30 & child=$!; echo "$child" > "{}"; wait "$child""#,
                env_file.display(),
                pid_file.display()
            )
        };

        let yaml = format!(
            "version: \"1\"\nproject:\n  name: \"bridge-test\"\nsecrets:\n  - API_KEY\nservices:\n  api:\n    runtime:\n      type: native\n      cmd: '{}'\n      grace_period_ms: 150\n    env:\n      API_KEY: \"${{SECRET:API_KEY}}\"\n      API_DSN: \"https://user:${{SECRET:API_KEY}}@example.local\"\n    readiness_probe:\n      type: log_regex\n      pattern: \"^READY$\"\n      timeout_ms: 5000\n",
            cmd.replace('\'', "''")
        );

        let config = Arc::new(AnvilConfig::from_yaml_str(&yaml)?);
        let graph = DependencyGraph::from_config(&config)?;
        let persistence = WorkspacePersistence::with_root(dir.path(), "bridge-test")?;

        let store = Arc::new(InMemorySecretStore::new());
        store.set(
            "bridge-test",
            "API_KEY",
            Zeroizing::new(secret_val.to_owned()),
        )?;

        let executor = Arc::new(HybridEngineExecutor::new(
            Arc::clone(&config),
            persistence.clone(),
            store,
            Some(dir.path().to_path_buf()),
        ));
        let (actor, mut channels) =
            Orchestrator::new(Arc::clone(&config), &graph, executor.clone());
        executor.bind_orchestrator(&actor);
        drop(executor);

        let actor_task = tokio::spawn(actor.with_crash_persistence(persistence, 50).run());
        channels.commands.send(EngineCommand::StartWorkspace).await?;

        tokio::time::timeout(
            Duration::from_secs(10),
            channels
                .snapshots
                .wait_for(|snap| snap.services["api"].state.is_healthy()),
        )
        .await
        .context("timed out waiting for api service to become healthy")??;

        assert_eq!(std::fs::read_to_string(&env_file)?.trim(), secret_val);

        let lock_store = LockfileStore::with_dir(dir.path().join("run"));
        let lockfile = lock_store
            .load_workspace("bridge-test")?
            .context("lockfile should exist while native service is running")?;
        assert_eq!(lockfile.processes.len(), 1);
        assert_eq!(lockfile.processes[0].service_id, "api");

        let mut descendant_pid = None;
        for _ in 0..40 {
            if let Ok(raw) = std::fs::read_to_string(&pid_file) {
                if let Ok(pid) = raw.trim().parse::<u32>() {
                    descendant_pid = Some(pid);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let child_pid = descendant_pid.context("child pid file was not written")?;

        channels.commands.send(EngineCommand::Shutdown).await?;
        drop(channels.commands);
        tokio::time::timeout(Duration::from_secs(10), actor_task)
            .await
            .context("timed out waiting for orchestrator shutdown")???;

        assert!(matches!(
            channels.snapshots.borrow().services["api"].state,
            ServiceState::Stopped { .. }
        ));
        assert!(lock_store.load_workspace("bridge-test")?.is_none());

        let alive = tokio::task::spawn_blocking(move || {
            DefaultProcessController::new().is_process_alive(child_pid)
        })
        .await?;
        assert!(!alive, "descendant process {child_pid} must be terminated");

        let log_path = dir.path().join("logs/bridge-test/api.log");
        let log_text = std::fs::read_to_string(&log_path)?;
        assert!(log_text.contains("stdout] [REDACTED]") || log_text.contains("stdout] token=[REDACTED]"));
        assert!(log_text.contains("stderr] [REDACTED]") || log_text.contains("stderr] err=[REDACTED]"));
        assert!(!log_text.contains(secret_val));

        let mut saw_redacted_batch = false;
        while let Some(batch) = channels.logs.recv().await {
            for line in batch.lines {
                assert!(!line.contains(secret_val));
                if line.contains("[REDACTED]") {
                    saw_redacted_batch = true;
                }
            }
        }
        assert!(saw_redacted_batch);
        Ok(())
    }

    #[tokio::test]
    async fn crash_report_and_missing_secret_never_leak_secrets() -> Result<()> {
        let dir = TempDir::new()?;
        let secret_val = "sk_crash_secret_do_not_leak";
        let cmd = if std::env::consts::OS == "windows" {
            "@echo off\r\n1>&2 echo boom %API_KEY%\r\nexit /b 9\r\n"
        } else {
            r#"echo "boom $API_KEY" >&2; exit 9"#
        };
        let yaml = format!(
            "version: \"1\"\nproject:\n  name: \"crash-redact\"\nsecrets:\n  - API_KEY\nservices:\n  api:\n    runtime:\n      type: native\n      cmd: '{cmd}'\n    env:\n      API_KEY: \"${{SECRET:API_KEY}}\"\n"
        );
        let config = Arc::new(AnvilConfig::from_yaml_str(&yaml)?);
        let graph = DependencyGraph::from_config(&config)?;
        let persistence = WorkspacePersistence::with_root(dir.path(), "crash-redact")?;
        let store = Arc::new(InMemorySecretStore::new());
        store.set(
            "crash-redact",
            "API_KEY",
            Zeroizing::new(secret_val.to_owned()),
        )?;

        let executor = Arc::new(HybridEngineExecutor::new(
            Arc::clone(&config),
            persistence.clone(),
            store,
            Some(dir.path().to_path_buf()),
        ));
        let (actor, mut channels) =
            Orchestrator::new(Arc::clone(&config), &graph, executor.clone());
        executor.bind_orchestrator(&actor);
        drop(executor);

        let actor_task = tokio::spawn(actor.with_crash_persistence(persistence, 20).run());
        channels.commands.send(EngineCommand::StartWorkspace).await?;

        tokio::time::timeout(
            Duration::from_secs(10),
            channels
                .snapshots
                .wait_for(|snap| matches!(snap.services["api"].state, ServiceState::Crashed { .. })),
        )
        .await
        .context("timed out waiting for crash state")??;

        let ServiceState::Crashed {
            reason,
            crash_log_path,
            ..
        } = channels.snapshots.borrow().services["api"].state.clone()
        else {
            anyhow::bail!("expected Crashed state");
        };
        assert!(!reason.contains(secret_val));
        let crash_yaml = std::fs::read_to_string(&crash_log_path)?;
        assert!(crash_yaml.contains("[REDACTED]"));
        assert!(!crash_yaml.contains(secret_val));

        channels.commands.send(EngineCommand::Shutdown).await?;
        drop(channels.commands);
        tokio::time::timeout(Duration::from_secs(5), actor_task).await???;
        Ok(())
    }
}
