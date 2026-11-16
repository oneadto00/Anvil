//! Single-writer workspace actor and its runtime adapter boundary.

use crate::{
    log_ring::{LogEntry, LogError, LogIngestor, LogRing},
    persistence::{CrashInfo, WorkspacePersistence},
    probe::{run_readiness_probe, ContainerHealthInspector, ProbeOutcome},
    AnvilConfig, DagSchedulerState, DependencyGraph, PortOccupant, ReadinessProbeConfig,
    RuntimeConfig, RuntimeIdentity, ServiceConfig, ServiceId, ServiceState, WorkspaceSnapshot,
};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    time::{Duration, SystemTime},
};
use thiserror::Error;
use tokio::{
    sync::{broadcast, mpsc, oneshot, watch},
    task::JoinSet,
};

/// Downstream control messages for a workspace.
#[derive(Debug)]
pub enum EngineCommand {
    /// Schedule all services, beginning with the independent roots.
    StartWorkspace,
    /// Request startup of a service or recheck its conflicting port. Duplicate requests for an active launch are idempotent.
    Start(ServiceId),
    /// Stop this service and cancel any pending automatic retry.
    Stop(ServiceId),
    /// Replace only this service, coalescing requests until its replacement is ready.
    Restart(ServiceId),
    /// Close admission and stop any instances created by this actor.
    Shutdown,
}

/// Redacted output lines from a single service in arrival order.
pub struct LogBatch {
    /// Configured service ID.
    pub service_id: ServiceId,
    /// Display-ready lines.
    pub lines: Vec<String>,
}

/// The three endpoints handed to workspace clients.
pub struct EngineChannels {
    /// Bounded control queue (64 commands).
    pub commands: mpsc::Sender<EngineCommand>,
    /// Latest immutable workspace view.
    pub snapshots: watch::Receiver<Arc<WorkspaceSnapshot>>,
    /// Bounded display queue (256 batches).
    pub logs: mpsc::Receiver<LogBatch>,
}

/// Exit information carried across the runtime boundary without executor diagnostics.
#[derive(Debug)]
pub enum InstanceExit {
    /// Native process exit code or terminating signal.
    Process {
        code: Option<i32>,
        signal: Option<i32>,
    },
    /// Docker exit code and out-of-memory flag for this launch.
    Container { exit_code: i64, oom_killed: bool },
}

/// A created instance and its one-shot termination notification.
pub struct StartedInstance {
    /// Identity used to stop this exact instance.
    pub identity: RuntimeIdentity,
    /// Terminal notification subscribed during spawn.
    pub exit: oneshot::Receiver<InstanceExit>,
    /// Final result of this launch's `LogIngestor::run`. The adapter closes the
    /// collector input after both output streams reach EOF, then forwards the
    /// result here. The exit notification can arrive before this receipt.
    pub drained: oneshot::Receiver<Result<LogRing, LogError>>,
    /// Completion of this launch's full log writer, after flush and sync. The
    /// adapter maps writer failures to the sanitized `ExecutionError::LogWrite`.
    pub log_written: oneshot::Receiver<Result<(), ExecutionError>>,
}

/// Sanitized lifecycle failure. Adapter errors can contain resolved environment values.
#[derive(Debug, Error)]
pub enum ExecutionError {
    /// Preflight could not determine whether the configured port is free.
    #[error("port inspection failed")]
    PortCheck,
    /// The runtime could not create an instance.
    #[error("runtime start failed")]
    Start,
    /// The runtime could not confirm termination.
    #[error("runtime stop failed")]
    Stop,
    /// The collector could not deliver the final batch.
    #[error("log drain failed")]
    LogDrain,
    /// The complete service log could not be flushed to disk.
    #[error("service log write failed")]
    LogWrite,
    /// A confirmed native process's lock record could not be cleaned up.
    #[error("native lock cleanup failed")]
    LockCleanup,
    /// An internal lifecycle task failed to complete.
    #[error("lifecycle task failed")]
    Task,
}

/// Lifecycle operations supplied by the outer assembly. The adapter owns environment
/// resolution and runtime log routing. Config passed here still contains placeholders.
#[async_trait::async_trait]
pub trait EngineExecutor: Send + Sync {
    /// Create an instance and subscribe to its exit before returning. For a log
    /// probe, forward this launch's redacted output to the supplied sender from
    /// the first line onward, alongside the normal complete log stream.
    async fn start(
        &self,
        id: &str,
        config: &ServiceConfig,
        probe_logs: Option<broadcast::Sender<String>>,
    ) -> Result<StartedInstance, ExecutionError>;
    /// Provide the runtime inspector for Docker health probes.
    fn health_inspector(&self) -> Option<Arc<dyn ContainerHealthInspector>> {
        None
    }

    /// Stop the identified instance within the configured graceful shutdown window.
    async fn stop(&self, identity: &RuntimeIdentity, grace: Duration)
        -> Result<(), ExecutionError>;
}

#[derive(Clone)]
struct Launch {
    id: ServiceId,
    generation: u64,
}

enum InstanceEvent {
    Started(Launch, RuntimeIdentity),
    Ready(Launch),
    Terminated(Launch),
}

enum Completion {
    Retry(Launch),
    TimerCancelled,
    PortChecked(Launch, Result<Option<PortOccupant>, ExecutionError>),
    Exited(Launch, Result<ServiceState, ExecutionError>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ManualAction {
    Stop,
    Restart,
}

struct ActiveInstance {
    identity: Option<RuntimeIdentity>,
    cancel: watch::Sender<bool>,
    after_exit: Option<ManualAction>,
    terminated: bool,
    task: tokio::task::Id,
}

#[derive(Default)]
struct ServiceControl {
    generation: u64,
    spawned_before: bool,
    active: Option<ActiveInstance>,
    replacing: bool,
    retries_used: u32,
    retry_cancel: Option<oneshot::Sender<()>>,
}

struct Cancellation {
    service: watch::Receiver<bool>,
    shutdown: watch::Receiver<bool>,
}

/// Owns workspace state and all lifecycle tasks. Run with `tokio::spawn(actor.run())`.
pub struct Orchestrator {
    config: Arc<AnvilConfig>,
    scheduler: DagSchedulerState,
    executor: Arc<dyn EngineExecutor>,
    commands: mpsc::Receiver<EngineCommand>,
    snapshots: watch::Sender<Arc<WorkspaceSnapshot>>,
    logs: mpsc::Sender<LogBatch>,
    services: BTreeMap<ServiceId, ServiceControl>,
    shutdown_layers: VecDeque<Vec<ServiceId>>,
    tasks: JoinSet<Completion>,
    crash_store: Option<WorkspacePersistence>,
    crash_tail_lines: usize,
    shutdown: watch::Sender<bool>,
    events: mpsc::Sender<InstanceEvent>,
    event_rx: mpsc::Receiver<InstanceEvent>,
}

impl Orchestrator {
    /// Build an idle actor from validated configuration and the graph built from it.
    /// The initial snapshot is available even before the actor is polled.
    pub fn new(
        config: Arc<AnvilConfig>,
        graph: &DependencyGraph,
        executor: Arc<dyn EngineExecutor>,
    ) -> (Self, EngineChannels) {
        let (events, event_rx) = mpsc::channel(64);
        let services = config
            .services
            .keys()
            .map(|id| (id.clone(), ServiceControl::default()))
            .collect();
        let crash_store = WorkspacePersistence::new(&config.project.name).ok();
        let initial = WorkspaceSnapshot::from_config(&config, graph.execution_layers());
        let (snapshots, snapshot_rx) = watch::channel(initial.into_shared());
        let (commands, command_rx) = mpsc::channel(64);
        let (logs, log_rx) = mpsc::channel(256);
        (
            Self {
                config,
                scheduler: graph.scheduler_state(),
                executor,
                commands: command_rx,
                snapshots,
                logs,
                services,
                shutdown_layers: graph.shutdown_layers().into(),
                tasks: JoinSet::new(),
                crash_store,
                crash_tail_lines: 200,
                shutdown: watch::channel(false).0,
                events,
                event_rx,
            },
            EngineChannels {
                commands,
                snapshots: snapshot_rx,
                logs: log_rx,
            },
        )
    }

    /// Select the workspace store used for crash reports and native lock cleanup,
    /// and the maximum crash tail length. Defaults to `~/.anvil` and 200 lines.
    pub fn with_crash_persistence(
        mut self,
        store: WorkspacePersistence,
        tail_lines: usize,
    ) -> Self {
        self.crash_store = Some(store);
        self.crash_tail_lines = tail_lines;
        self
    }

    /// Build a service's collector during assembly, routing UI batches to this
    /// workspace and complete records to that service's persistence consumer.
    pub fn service_log_ingestor(
        &self,
        service_id: ServiceId,
        complete: mpsc::Sender<LogEntry>,
    ) -> LogIngestor {
        LogIngestor::new(service_id, complete, self.logs.clone())
    }

    /// Consume commands until shutdown or the last command sender drops, then join all
    /// launches, including instances whose start acknowledgement is still outstanding.
    pub async fn run(mut self) -> Result<(), ExecutionError> {
        let mut closing = false;
        let mut failure = None;
        let mut commands_open = true;
        while !closing || !self.tasks.is_empty() {
            tokio::select! {
                command = self.commands.recv(), if commands_open => match command {
                    command if closing => commands_open = command.is_some(),
                    Some(EngineCommand::StartWorkspace) => self.start_workspace(),
                    Some(EngineCommand::Start(id)) => self.start(id),
                    Some(EngineCommand::Restart(id)) => self.manual(id, ManualAction::Restart),
                    Some(EngineCommand::Stop(id)) => self.manual(id, ManualAction::Stop),
                    Some(EngineCommand::Shutdown) | None => {
                        commands_open = command.is_some();
                        closing = true;
                        self.close();
                    }
                },
                Some(event) = self.event_rx.recv() => {
                    match event {
                        InstanceEvent::Terminated(launch) => {
                            self.terminated(&launch);
                            if closing { self.advance_shutdown(); }
                        }
                        event if !closing => self.on_event(event),
                        _ => {}
                    }
                }
                Some(result) = self.tasks.join_next(), if !self.tasks.is_empty() => match result {
                    Ok(Completion::PortChecked(launch, result)) if !closing => self.port_checked(launch, result),
                    Ok(Completion::PortChecked(_, _)) => {}
                    Ok(Completion::Retry(launch)) if !closing && self.is_current(&launch) => {
                        if self.services.get_mut(&launch.id).and_then(|s| s.retry_cancel.take()).is_some() {
                            self.admit(launch.id);
                        }
                    }
                    Ok(Completion::Retry(_) | Completion::TimerCancelled) => {}
                    Ok(Completion::Exited(launch, result)) if self.is_current(&launch) => {
                        if let Err(err) = self.exited(launch, result, closing) {
                            failure = Some(err);
                        }
                        if closing { self.advance_shutdown(); }
                    }
                    Ok(Completion::Exited(_, _)) => {}
                    Err(err) => {
                        if let Some((id, control)) = self.services.iter_mut().find(|(_, s)|
                            s.active.as_ref().is_some_and(|active| active.task == err.id())) {
                            control.active = None;
                            let id = id.clone();
                            self.transition(&id, ServiceState::Unhealthy { reason: "lifecycle task failed".into() });
                        }
                        if closing { self.advance_shutdown(); } else {
                            closing = true;
                            self.close();
                        }
                        failure = Some(ExecutionError::Task);
                    }
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }

    fn close(&mut self) {
        self.shutdown.send_replace(true);
        let mut cancelled = Vec::new();
        for (id, service) in &mut self.services {
            let retrying = service.retry_cancel.take().is_some();
            if service.active.is_none()
                && (retrying
                    || matches!(
                        self.snapshots.borrow().services[id].state,
                        ServiceState::WaitingDeps { .. }
                            | ServiceState::PortCheck
                            | ServiceState::PortConflict(_)
                    ))
            {
                cancelled.push(id.clone());
            }
        }
        for id in cancelled {
            self.transition(&id, ServiceState::Stopped { exit_code: None });
        }
        self.advance_shutdown();
    }

    fn advance_shutdown(&mut self) {
        while let Some(layer) = self.shutdown_layers.front() {
            let mut waiting = false;
            for id in layer {
                if let Some(active) = &self.services[id].active {
                    if !active.terminated {
                        waiting = true;
                        if !*active.cancel.borrow() {
                            active.cancel.send_replace(true);
                        }
                        self.transition(id, ServiceState::Stopping);
                    }
                }
            }
            if waiting {
                break;
            }
            self.shutdown_layers.pop_front();
        }
    }

    fn terminated(&mut self, launch: &Launch) {
        if !self.is_current(launch) {
            return;
        }
        if let Some(active) = self
            .services
            .get_mut(&launch.id)
            .and_then(|s| s.active.as_mut())
        {
            active.terminated = true;
            self.scheduler.mark_exited(&launch.id);
            self.transition(&launch.id, ServiceState::Stopping);
            self.refresh_waiting(&launch.id);
        }
    }

    fn start(&mut self, id: ServiceId) {
        if self.state(&id).is_some_and(|s| s.is_terminal()) {
            if let Some(control) = self.services.get_mut(&id) {
                if control.retry_cancel.is_none() {
                    control.retries_used = 0;
                }
            }
        }
        self.admit(id);
    }

    fn manual(&mut self, id: ServiceId, action: ManualAction) {
        let Some(state) = self.state(&id) else { return };
        let Some(control) = self.services.get_mut(&id) else {
            return;
        };
        if action == ManualAction::Restart && control.replacing {
            return;
        }
        control.retry_cancel.take();
        control.retries_used = 0;
        control.replacing = action == ManualAction::Restart;
        if let Some(active) = &mut control.active {
            active.after_exit = Some(action);
            active.cancel.send_replace(true);
            self.scheduler.mark_exited(&id);
            self.transition(&id, ServiceState::Stopping);
            self.refresh_waiting(&id);
        } else if !matches!(state, ServiceState::Unhealthy { .. }) {
            // An in-flight preflight is superseded by the fresh admission generation.
            self.transition(&id, ServiceState::Stopped { exit_code: None });
            if action == ManualAction::Restart {
                self.admit(id);
            }
        }
    }

    fn exited(
        &mut self,
        launch: Launch,
        result: Result<ServiceState, ExecutionError>,
        closing: bool,
    ) -> Result<(), ExecutionError> {
        let id = launch.id.as_str();
        let Some(control) = self.services.get_mut(id) else {
            return Ok(());
        };
        let Some(active) = control.active.take() else {
            return Ok(());
        };
        self.scheduler.mark_exited(id);
        self.refresh_waiting(id);
        let mut state = match result {
            Ok(state) => state,
            Err(err) => {
                self.transition(
                    id,
                    ServiceState::Unhealthy {
                        reason: err.to_string(),
                    },
                );
                return Err(err);
            }
        };
        if active.after_exit.is_some() && !matches!(state, ServiceState::Stopped { .. }) {
            state = ServiceState::Stopped { exit_code: None };
        }
        let failed = matches!(state, ServiceState::Crashed { .. });
        self.transition(id, state);
        if closing {
            return Ok(());
        }
        if active.after_exit == Some(ManualAction::Restart) {
            self.admit(launch.id);
        } else {
            if let Some(control) = self.services.get_mut(id) {
                control.replacing = false;
                if !failed {
                    control.retries_used = 0;
                }
            }
            if failed {
                self.schedule_retry(launch);
            }
        }
        Ok(())
    }

    fn schedule_retry(&mut self, launch: Launch) {
        let policy = &self.config.services[&launch.id].restart_policy;
        let Some(control) = self.services.get_mut(&launch.id) else {
            return;
        };
        control.replacing = false;
        if !policy.on_failure || control.retries_used >= policy.max_retries {
            return;
        }
        control.retries_used += 1;
        let delay = tokio::time::sleep(Duration::from_millis(policy.backoff_ms));
        let (cancel, cancelled) = oneshot::channel();
        control.retry_cancel = Some(cancel);
        self.tasks.spawn(async move {
            tokio::select! {
                _ = cancelled => Completion::TimerCancelled,
                _ = delay => Completion::Retry(launch),
            }
        });
    }

    fn start_workspace(&mut self) {
        let roots = self.scheduler.initial_ready_services();
        let dependents: Vec<_> = self
            .config
            .services
            .iter()
            .filter(|(_, service)| !service.depends_on.is_empty())
            .map(|(id, _)| id.clone())
            .collect();
        for id in roots.into_iter().chain(dependents) {
            self.start(id);
        }
    }

    fn is_current(&self, launch: &Launch) -> bool {
        self.services
            .get(&launch.id)
            .is_some_and(|s| s.generation == launch.generation)
    }

    fn state(&self, id: &str) -> Option<ServiceState> {
        self.snapshots
            .borrow()
            .services
            .get(id)
            .map(|s| s.state.clone())
    }

    fn wait_for_dependencies(&self, id: &str) -> bool {
        let pending_deps = self.scheduler.pending_dependencies(id);
        if pending_deps.is_empty() {
            return false;
        }
        self.transition(id, ServiceState::WaitingDeps { pending_deps });
        true
    }

    fn refresh_waiting(&self, id: &str) {
        for child in self.scheduler.dependents_of(id) {
            if matches!(self.state(child), Some(ServiceState::WaitingDeps { .. })) {
                self.wait_for_dependencies(child);
            }
        }
    }

    fn admit(&mut self, id: ServiceId) {
        let Some(state) = self.state(&id) else { return };
        if self.services[&id].retry_cancel.is_some() {
            return;
        }
        if state.is_active()
            && !matches!(
                state,
                ServiceState::WaitingDeps { .. } | ServiceState::PortConflict(_)
            )
        {
            return;
        }
        if self.wait_for_dependencies(&id) {
            return;
        }
        let Some(control) = self.services.get_mut(&id) else {
            return;
        };
        let Some(generation) = control.generation.checked_add(1) else {
            return;
        };
        control.generation = generation;
        let port = self.config.services[&id].port;
        let launch = Launch { id, generation };
        if let Some(port) = port {
            self.transition(&launch.id, ServiceState::PortCheck);
            self.tasks.spawn(async move {
                let result = tokio::task::spawn_blocking(move || check_port(port))
                    .await
                    .map_err(|_| ExecutionError::Task)
                    .and_then(|result| result);
                Completion::PortChecked(launch, result)
            });
        } else {
            self.start_instance(launch);
        }
    }

    fn port_checked(
        &mut self,
        launch: Launch,
        result: Result<Option<PortOccupant>, ExecutionError>,
    ) {
        if !self.is_current(&launch)
            || self.state(&launch.id) != Some(ServiceState::PortCheck)
            || self.wait_for_dependencies(&launch.id)
        {
            return;
        }
        match result {
            Ok(None) => self.start_instance(launch),
            Ok(Some(occupant)) => {
                if let Some(control) = self.services.get_mut(&launch.id) {
                    control.replacing = false;
                }
                self.transition(&launch.id, ServiceState::PortConflict(occupant));
            }
            Err(_) => {
                self.transition(&launch.id, crashed(None, None, "port inspection failed"));
                self.schedule_retry(launch);
            }
        }
    }

    fn start_instance(&mut self, launch: Launch) {
        let Some(control) = self.services.get_mut(&launch.id) else {
            return;
        };
        let (cancel, service) = watch::channel(false);
        let restarting = std::mem::replace(&mut control.spawned_before, true);
        let task = self.tasks.spawn(run_instance(
            launch.clone(),
            self.config.clone(),
            self.executor.clone(),
            self.events.clone(),
            Cancellation {
                service,
                shutdown: self.shutdown.subscribe(),
            },
            self.crash_store.clone(),
            self.crash_tail_lines,
        ));
        control.active = Some(ActiveInstance {
            identity: None,
            cancel,
            after_exit: None,
            terminated: false,
            task: task.id(),
        });
        self.publish(&launch.id, ServiceState::Starting, restarting);
    }

    fn on_event(&mut self, event: InstanceEvent) {
        match event {
            InstanceEvent::Started(launch, identity)
                if self.is_current(&launch)
                    && self.state(&launch.id) == Some(ServiceState::Starting) =>
            {
                let Some(active) = self
                    .services
                    .get_mut(&launch.id)
                    .and_then(|s| s.active.as_mut())
                else {
                    return;
                };
                active.identity = Some(identity);
                if self.config.services[&launch.id].readiness_probe.is_some() {
                    self.transition(
                        &launch.id,
                        ServiceState::Probing {
                            started_at: SystemTime::now(),
                            attempts: 0,
                        },
                    );
                } else {
                    self.healthy(&launch.id);
                }
            }
            InstanceEvent::Ready(launch)
                if self.is_current(&launch)
                    && matches!(self.state(&launch.id), Some(ServiceState::Probing { .. })) =>
            {
                self.healthy(&launch.id)
            }
            _ => {}
        }
    }

    fn healthy(&mut self, id: &str) {
        let Some(control) = self.services.get_mut(id) else {
            return;
        };
        control.replacing = false;
        let Some(identity) = control.active.as_ref().and_then(|a| a.identity.clone()) else {
            return;
        };
        self.transition(
            id,
            ServiceState::Healthy {
                pid_or_cid: identity,
                since: SystemTime::now(),
            },
        );
        for child in self.scheduler.mark_healthy(id) {
            if matches!(self.state(&child), Some(ServiceState::WaitingDeps { .. })) {
                self.admit(child);
            }
        }
        self.refresh_waiting(id);
    }

    fn transition(&self, id: &str, state: ServiceState) {
        self.publish(id, state, false);
    }

    fn publish(&self, id: &str, state: ServiceState, restarting: bool) {
        self.snapshots.send_if_modified(|current| {
            if current
                .services
                .get(id)
                .is_none_or(|svc| svc.state == state)
            {
                return false;
            }
            let snapshot = Arc::make_mut(current);
            if let Some(service) = snapshot.services.get_mut(id) {
                if restarting {
                    service.restart_count = service.restart_count.saturating_add(1);
                }
                service.state = state;
                snapshot.updated_at = SystemTime::now();
            }
            true
        });
    }
}

fn check_port(port: u16) -> Result<Option<PortOccupant>, ExecutionError> {
    use anvil_sys::PortCheckResult;
    match anvil_sys::inspect_port(port).map_err(|_| ExecutionError::PortCheck)? {
        PortCheckResult::Available => Ok(None),
        PortCheckResult::Occupied(info) => {
            let (pid, process_name) = info
                .map(|i| (i.pid, i.process_name))
                .unwrap_or_else(|| (0, "unknown".into()));
            Ok(Some(PortOccupant {
                port,
                pid,
                process_name,
                cmdline: "[REDACTED]".into(),
            }))
        }
    }
}

async fn run_instance(
    launch: Launch,
    config: Arc<AnvilConfig>,
    executor: Arc<dyn EngineExecutor>,
    events: mpsc::Sender<InstanceEvent>,
    cancellation: Cancellation,
    store: Option<WorkspacePersistence>,
    tail_lines: usize,
) -> Completion {
    let service = &config.services[&launch.id];
    let (sender, logs) = if matches!(
        service.readiness_probe,
        Some(ReadinessProbeConfig::LogRegex { .. })
    ) {
        let (tx, rx) = broadcast::channel(256);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    if *cancellation.shutdown.borrow() {
        return Completion::Exited(launch, Ok(ServiceState::Stopped { exit_code: None }));
    }
    let result = match executor.start(&launch.id, service, sender).await {
        Err(_) => Ok(crashed(None, None, "runtime start failed")),
        Ok(mut instance) => {
            let _ = events
                .send(InstanceEvent::Started(
                    launch.clone(),
                    instance.identity.clone(),
                ))
                .await;
            let outcome = supervise(
                &launch,
                service,
                executor.as_ref(),
                &mut instance,
                logs,
                events.clone(),
                cancellation,
            )
            .await;
            let ended_at = SystemTime::now();
            let end = match outcome {
                Ok(end) => end,
                Err(err) => return Completion::Exited(launch, Err(err)),
            };
            let _ = events.send(InstanceEvent::Terminated(launch.clone())).await;
            let cleanup = async {
                if matches!(instance.identity, RuntimeIdentity::NativeProcess { .. }) {
                    store
                        .as_ref()
                        .ok_or(ExecutionError::LockCleanup)?
                        .remove_native_instance(&launch.id, &instance.identity)
                        .await
                        .map_err(|_| ExecutionError::LockCleanup)?;
                }
                Ok(())
            };
            // Receipt order is independent. A blocked disk writer for this service
            // must not hold another layer's stop gate or a UI queue slot.
            let (unlocked, drained, written) =
                tokio::join!(cleanup, instance.drained, instance.log_written);
            let saved = unlocked.and(written.unwrap_or(Err(ExecutionError::LogWrite)));
            let ring = drained.ok().and_then(Result::ok);
            match end {
                End::Crash {
                    code,
                    signal,
                    reason,
                } => {
                    let info = CrashInfo {
                        service_id: launch.id.clone(),
                        generation: launch.generation,
                        identity: Some(instance.identity),
                        occurred_at: ended_at,
                        exit_code: code,
                        signal,
                        redacted_reason: reason.to_owned(),
                    };
                    let mut state = persist_crash(info, ring, store, tail_lines).await;
                    if let (Err(err), ServiceState::Crashed { reason, .. }) = (saved, &mut state) {
                        reason.push_str("; ");
                        reason.push_str(&err.to_string());
                    }
                    Ok(state)
                }
                End::Stopped(exit_code) => saved
                    .and(ring.ok_or(ExecutionError::LogDrain))
                    .map(|_| ServiceState::Stopped { exit_code }),
            }
        }
    };
    Completion::Exited(launch, result)
}

async fn supervise(
    launch: &Launch,
    service: &ServiceConfig,
    executor: &dyn EngineExecutor,
    instance: &mut StartedInstance,
    logs: Option<broadcast::Receiver<String>>,
    events: mpsc::Sender<InstanceEvent>,
    mut cancellation: Cancellation,
) -> Result<End, ExecutionError> {
    let identity = &instance.identity;
    let stop_requested = cancellation.service.clone();
    let monitor = async {
        if let Some(probe) = &service.readiness_probe {
            let container_ref = match identity {
                RuntimeIdentity::DockerContainer { container_id, .. } => {
                    Some(container_id.as_str())
                }
                _ => None,
            };
            match run_readiness_probe(
                probe,
                cancellation.service.clone(),
                logs,
                executor.health_inspector(),
                container_ref,
            )
            .await
            {
                Ok(ProbeOutcome::Ready { .. }) => {
                    let _ = events.send(InstanceEvent::Ready(launch.clone())).await;
                }
                Ok(ProbeOutcome::TimedOut { .. }) => {
                    return End::failed("readiness probe timed out")
                }
                Ok(ProbeOutcome::Cancelled) => return End::Stopped(None),
                Err(_) => return End::failed("readiness probe failed"),
            }
        }
        let _ = cancellation.service.wait_for(|stop| *stop).await;
        End::Stopped(None)
    };
    let workspace_closing = cancellation.shutdown.clone();
    let readiness = async {
        tokio::select! {
            biased;
            _ = cancellation.shutdown.wait_for(|closing| *closing) => {}
            end = monitor => return end,
        }
        let mut gate = stop_requested.clone();
        let _ = gate.wait_for(|stop| *stop).await;
        End::Stopped(None)
    };
    let mut exit_lost = false;
    let state = tokio::select! {
        biased;
        result = &mut instance.exit => match result {
            Ok(status) => return Ok(exit_state(status, *stop_requested.borrow() || *workspace_closing.borrow())),
            Err(_) => {
                exit_lost = true;
                End::failed("runtime exit notification lost")
            }
        },
        state = readiness => state,
    };
    let grace = match service.runtime {
        RuntimeConfig::Native {
            grace_period_ms, ..
        } => Duration::from_millis(grace_period_ms),
        _ => Duration::from_secs(3),
    };
    executor.stop(identity, grace).await?;
    if *stop_requested.borrow() {
        if exit_lost {
            return Err(ExecutionError::Stop);
        }
        return (&mut instance.exit)
            .await
            .map(|status| exit_state(status, true))
            .map_err(|_| ExecutionError::Stop);
    }
    Ok(state)
}

enum End {
    Stopped(Option<i32>),
    Crash {
        code: Option<i64>,
        signal: Option<i32>,
        reason: &'static str,
    },
}

impl End {
    fn failed(reason: &'static str) -> Self {
        Self::Crash {
            code: None,
            signal: None,
            reason,
        }
    }
}

fn exit_state(status: InstanceExit, stopping: bool) -> End {
    let (code, signal, oom) = match status {
        InstanceExit::Process { code, signal } => (code.map(i64::from), signal, false),
        InstanceExit::Container {
            exit_code,
            oom_killed,
        } => (Some(exit_code), None, oom_killed),
    };
    if stopping || (code == Some(0) && signal.is_none() && !oom) {
        End::Stopped(code.and_then(|c| i32::try_from(c).ok()))
    } else {
        End::Crash {
            code,
            signal,
            reason: if oom {
                "container out of memory"
            } else {
                "unexpected runtime exit"
            },
        }
    }
}

async fn persist_crash(
    info: CrashInfo,
    ring: Option<LogRing>,
    store: Option<WorkspacePersistence>,
    tail_lines: usize,
) -> ServiceState {
    let exit_code = info.exit_code.and_then(|c| i32::try_from(c).ok());
    let signal = info.signal;
    let mut reason = info.redacted_reason.clone();
    let result = async {
        let ring = ring.ok_or("log drain failed")?;
        let path = store
            .ok_or("crash storage unavailable")?
            .write_crash(info, ring.tail(tail_lines))
            .await
            .map_err(|_| "crash report write failed")?;
        path.into_os_string()
            .into_string()
            .map_err(|_| "crash report path is not UTF-8")
    }
    .await;
    let crash_log_path = result.unwrap_or_else(|error| {
        reason.push_str("; ");
        reason.push_str(error);
        String::new()
    });
    ServiceState::Crashed {
        exit_code,
        signal,
        reason,
        crash_log_path,
    }
}

fn crashed(exit_code: Option<i32>, signal: Option<i32>, reason: &str) -> ServiceState {
    ServiceState::Crashed {
        exit_code,
        signal,
        reason: reason.into(),
        crash_log_path: String::new(),
    }
}

#[cfg(test)]
mod tests;
