#![forbid(unsafe_code)]
#![cfg(test)]

//! Milestone 4 acceptance through the public actor and real log persistence.
//! The runtime controls process events and redacts its synthetic credential at
//! the adapter boundary. No native process or Docker daemon is used here.

use anvil_core::{
    log_ring::{LogEntry, LogIngestor, LogInput, LogSource},
    persistence::WorkspacePersistence,
    AnvilConfig, DependencyGraph, EngineChannels, EngineCommand, EngineExecutor, ExecutionError,
    InstanceExit, Orchestrator, RuntimeIdentity, ServiceConfig, ServiceState, StartedInstance,
};
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tokio::{
    sync::{broadcast, mpsc, oneshot},
    task::JoinHandle,
};

const CONFIG: &str = r#"
version: "1"
project: {name: acceptance}
services:
  db:
    runtime: {type: native, cmd: db, grace_period_ms: 101}
    readiness_probe: {type: log_regex, pattern: '^READY$', timeout_ms: 60000}
  api:
    depends_on: [db]
    runtime: {type: native, cmd: api, grace_period_ms: 202}
    readiness_probe: {type: log_regex, pattern: '^READY$', timeout_ms: 60000}
  web:
    depends_on: [api]
    runtime: {type: native, cmd: web, grace_period_ms: 303}
    readiness_probe: {type: log_regex, pattern: '^READY$', timeout_ms: 60000}
"#;
const TAIL: usize = 5;
const SYNTHETIC_CREDENTIAL: &str = "fixture-only-credential";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Spawn(String),
    Ready(String),
    Stop(RuntimeIdentity, Duration),
    Released(RuntimeIdentity),
}

enum Request {
    Spawn {
        id: String,
        probe: broadcast::Sender<String>,
        reply: oneshot::Sender<StartedInstance>,
    },
    Stop {
        identity: RuntimeIdentity,
        reply: oneshot::Sender<()>,
    },
}

struct TestExecutor {
    requests: mpsc::Sender<Request>,
    calls: Arc<Mutex<Vec<Call>>>,
}

#[async_trait::async_trait]
impl EngineExecutor for TestExecutor {
    async fn start(
        &self,
        id: &str,
        _: &ServiceConfig,
        probe_logs: Option<broadcast::Sender<String>>,
    ) -> Result<StartedInstance, ExecutionError> {
        self.calls.lock().unwrap().push(Call::Spawn(id.into()));
        let (reply, result) = oneshot::channel();
        self.requests
            .send(Request::Spawn {
                id: id.into(),
                probe: probe_logs.unwrap(),
                reply,
            })
            .await
            .unwrap();
        Ok(result.await.unwrap())
    }

    async fn stop(
        &self,
        identity: &RuntimeIdentity,
        grace: Duration,
    ) -> Result<(), ExecutionError> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::Stop(identity.clone(), grace));
        let (reply, result) = oneshot::channel();
        self.requests
            .send(Request::Stop {
                identity: identity.clone(),
                reply,
            })
            .await
            .unwrap();
        result.await.unwrap();
        Ok(())
    }
}

struct PreparedLogs {
    collector: LogIngestor,
    complete: mpsc::Receiver<LogEntry>,
}

struct LiveInstance {
    identity: RuntimeIdentity,
    probe: broadcast::Sender<String>,
    input: mpsc::Sender<LogInput>,
    exit: Option<oneshot::Sender<InstanceExit>>,
}

struct Workspace {
    channels: EngineChannels,
    requests: mpsc::Receiver<Request>,
    calls: Arc<Mutex<Vec<Call>>>,
    live: BTreeMap<String, LiveInstance>,
    prepared: BTreeMap<String, VecDeque<PreparedLogs>>,
    actor: JoinHandle<Result<(), ExecutionError>>,
    log_tasks: Vec<JoinHandle<()>>,
    store: WorkspacePersistence,
    directory: tempfile::TempDir,
    next_pid: u32,
}

impl Workspace {
    fn new() -> Self {
        let config = AnvilConfig::from_yaml_str(CONFIG).unwrap();
        let graph = DependencyGraph::from_config(&config).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let store =
            WorkspacePersistence::with_root(directory.path(), &config.project.name).unwrap();
        let (requests, receiver) = mpsc::channel(16);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let executor = Arc::new(TestExecutor {
            requests,
            calls: calls.clone(),
        });
        let (actor, channels) = Orchestrator::new(Arc::new(config), &graph, executor);
        let mut prepared = BTreeMap::new();
        for (id, launches) in [("db", 1), ("api", 2), ("web", 1)] {
            let mut queue = VecDeque::new();
            for _ in 0..launches {
                let (complete, receiver) = mpsc::channel(128);
                queue.push_back(PreparedLogs {
                    collector: actor.service_log_ingestor(id.into(), complete),
                    complete: receiver,
                });
            }
            prepared.insert(id.into(), queue);
        }
        Self {
            channels,
            requests: receiver,
            calls,
            prepared,
            live: BTreeMap::new(),
            actor: tokio::spawn(actor.with_crash_persistence(store.clone(), TAIL).run()),
            log_tasks: Vec::new(),
            store,
            directory,
            next_pid: 100,
        }
    }

    async fn command(&self, command: EngineCommand) {
        self.channels.commands.send(command).await.unwrap();
    }

    async fn state(&mut self, id: &str, label: &str) -> ServiceState {
        self.channels
            .snapshots
            .wait_for(|s| s.services[id].state.label() == label)
            .await
            .unwrap()
            .services[id]
            .state
            .clone()
    }

    async fn spawn(&mut self, expected: &str) {
        let Some(Request::Spawn { id, probe, reply }) = self.requests.recv().await else {
            panic!("expected spawn of {expected}");
        };
        assert_eq!(id, expected);
        assert!(
            !self.live.contains_key(&id),
            "overlapping instance for {id}"
        );
        let PreparedLogs {
            collector,
            complete,
        } = self.prepared.get_mut(&id).unwrap().pop_front().unwrap();
        let (input, receiver) = mpsc::channel(128);
        let (done, drained) = oneshot::channel();
        self.log_tasks.push(tokio::spawn(async move {
            assert!(done.send(collector.run(receiver).await).is_ok());
        }));
        let store = self.store.clone();
        let service = id.clone();
        let (saved, log_written) = oneshot::channel();
        self.log_tasks.push(tokio::spawn(async move {
            let result = store
                .write_service_log(&service, complete)
                .await
                .map(|_| ())
                .map_err(|_| ExecutionError::LogWrite);
            saved.send(result).unwrap();
        }));
        self.next_pid += 1;
        let identity = RuntimeIdentity::NativeProcess {
            pid: self.next_pid,
            pgid: self.next_pid,
            start_time_secs: self.next_pid.into(),
        };
        let (exit_tx, exit) = oneshot::channel();
        self.live.insert(
            id,
            LiveInstance {
                identity: identity.clone(),
                probe,
                input,
                exit: Some(exit_tx),
            },
        );
        assert!(reply
            .send(StartedInstance {
                identity,
                exit,
                drained,
                log_written
            })
            .is_ok());
    }

    async fn line(&self, id: &str, raw: &str) {
        let redacted = raw.replace(SYNTHETIC_CREDENTIAL, "[REDACTED]");
        self.live[id]
            .input
            .send(LogInput::Line(LogEntry {
                source: LogSource::Stdout,
                timestamp: SystemTime::now(),
                redacted_body: redacted.into(),
            }))
            .await
            .unwrap();
    }

    async fn ready(&mut self, id: &str) {
        self.state(id, "Probing").await;
        self.line(id, "READY").await;
        // Record before releasing the probe so a downstream spawn cannot overtake
        // this marker, even if the snapshot watch coalesces intermediate updates.
        self.calls.lock().unwrap().push(Call::Ready(id.into()));
        self.live[id].probe.send("READY".into()).unwrap();
    }

    async fn start_chain(&mut self) {
        self.command(EngineCommand::StartWorkspace).await;
        for id in ["db", "api", "web"] {
            self.spawn(id).await;
            self.ready(id).await;
        }
        self.state("web", "Healthy").await;
    }

    fn trace(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn spawn_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for call in self.trace() {
            if let Call::Spawn(id) = call {
                *counts.entry(id).or_default() += 1;
            }
        }
        counts
    }

    async fn stop(&mut self, id: &str) {
        let Some(Request::Stop { identity, reply }) = self.requests.recv().await else {
            panic!("expected stop of {id}");
        };
        assert_eq!(identity, self.live[id].identity);
        self.release(id, 0);
        reply.send(()).unwrap();
    }

    fn release(&mut self, id: &str, code: i32) {
        let mut instance = self.live.remove(id).unwrap();
        if let Some(exit) = instance.exit.take() {
            exit.send(InstanceExit::Process {
                code: Some(code),
                signal: None,
            })
            .unwrap();
        }
        self.calls
            .lock()
            .unwrap()
            .push(Call::Released(instance.identity));
        // Dropping both output senders allows the collector to flush its final batch.
    }

    async fn shutdown(mut self) {
        self.command(EngineCommand::Shutdown).await;
        for id in ["web", "api", "db"] {
            if self.live.contains_key(id) {
                self.stop(id).await;
            }
        }
        assert!(self.live.is_empty());
        self.prepared.clear();
        self.actor.await.unwrap().unwrap();
        for task in self.log_tasks {
            task.await.unwrap();
        }
        assert!(self.requests.recv().await.is_none());
        assert!(self.channels.commands.is_closed());
        assert!(self.channels.logs.is_closed());
        assert!(self.channels.snapshots.has_changed().is_err());
        let calls = self.calls.lock().unwrap();
        let spawned = calls
            .iter()
            .filter(|call| matches!(call, Call::Spawn(_)))
            .count();
        let released = calls
            .iter()
            .filter(|call| matches!(call, Call::Released(_)))
            .count();
        assert_eq!(spawned, released);
    }
}

// Watchdog only: all ordering below is established by calls, channels and receipts.
async fn bounded(test: impl Future<Output = ()>) {
    tokio::time::timeout(Duration::from_secs(30), test)
        .await
        .expect("acceptance test stalled");
}

#[tokio::test]
async fn readiness_gates_three_layer_spawn_order() {
    bounded(async {
        let mut workspace = Workspace::new();
        workspace.start_chain().await;
        assert_eq!(
            workspace.trace(),
            [
                Call::Spawn("db".into()),
                Call::Ready("db".into()),
                Call::Spawn("api".into()),
                Call::Ready("api".into()),
                Call::Spawn("web".into()),
                Call::Ready("web".into()),
            ]
        );
        workspace.shutdown().await;
    })
    .await;
}

async fn crash_tail(ui_backpressure: bool) {
    let mut workspace = Workspace::new();
    workspace.start_chain().await;
    if ui_backpressure {
        // Fill the actual 256-batch UI queue via real ingestion without consuming
        // it. Tail's FIFO receipt proves every preceding batch attempt completed.
        for _ in 0..workspace.channels.logs.max_capacity() * 100 {
            workspace.line("db", "UI pressure").await;
        }
        let (reply, receipt) = oneshot::channel();
        workspace.live["db"]
            .input
            .send(LogInput::Tail { count: 0, reply })
            .await
            .unwrap();
        receipt.await.unwrap();
        assert_eq!(
            workspace.channels.logs.len(),
            workspace.channels.logs.max_capacity()
        );
    }
    let count = TAIL + 7;
    for index in 0..count - 2 {
        workspace
            .line(
                "api",
                &format!("line-{index:03} token={SYNTHETIC_CREDENTIAL}"),
            )
            .await;
    }
    workspace
        .live
        .get_mut("api")
        .unwrap()
        .exit
        .take()
        .unwrap()
        .send(InstanceExit::Process {
            code: Some(17),
            signal: None,
        })
        .unwrap();
    workspace.state("api", "Stopping").await;
    for index in count - 2..count {
        workspace
            .line(
                "api",
                &format!("line-{index:03} token={SYNTHETIC_CREDENTIAL}"),
            )
            .await;
    }
    workspace.release("api", 17);
    let ServiceState::Crashed {
        exit_code,
        crash_log_path,
        ..
    } = workspace.state("api", "Crashed").await
    else {
        unreachable!();
    };
    assert_eq!(exit_code, Some(17));
    assert!(std::path::Path::new(&crash_log_path).starts_with(workspace.directory.path()));
    let crash_text = tokio::fs::read_to_string(crash_log_path).await.unwrap();
    assert!(!crash_text.contains(SYNTHETIC_CREDENTIAL));
    let report: serde_yaml::Value = serde_yaml::from_str(&crash_text).unwrap();
    assert_eq!(report["generation"].as_u64(), Some(1));
    let tail = report["tail"].as_sequence().unwrap();
    let actual: Vec<_> = tail
        .iter()
        .map(|entry| entry["body"].as_str().unwrap())
        .collect();
    let expected: Vec<_> = (count - TAIL..count)
        .map(|index| format!("line-{index:03} token=[REDACTED]"))
        .collect();
    assert_eq!(actual, expected);
    let full =
        tokio::fs::read_to_string(workspace.directory.path().join("logs/acceptance/api.log"))
            .await
            .unwrap();
    assert!(!full.contains(SYNTHETIC_CREDENTIAL));
    let numbered: Vec<_> = full
        .lines()
        .filter_map(|line| line.split_once("] line-").map(|(_, body)| body))
        .collect();
    assert_eq!(
        numbered,
        (0..count)
            .map(|index| format!("{index:03} token=[REDACTED]"))
            .collect::<Vec<_>>()
    );
    if ui_backpressure {
        assert_eq!(
            workspace.channels.logs.len(),
            workspace.channels.logs.max_capacity()
        );
    }
    workspace.shutdown().await;
}

#[tokio::test]
async fn crash_keeps_exact_redacted_tail_after_exit() {
    bounded(crash_tail(false)).await;
}

#[tokio::test]
async fn crash_keeps_exact_redacted_tail_with_full_ui_queue() {
    bounded(crash_tail(true)).await;
}

#[tokio::test]
async fn hot_restart_changes_only_api_and_releases_all_instances() {
    bounded(async {
        let mut workspace = Workspace::new();
        workspace.start_chain().await;
        let before = workspace.channels.snapshots.borrow().clone();
        assert_eq!(
            workspace.spawn_counts(),
            BTreeMap::from([("db".into(), 1), ("api".into(), 1), ("web".into(), 1),])
        );
        workspace
            .command(EngineCommand::Restart("api".into()))
            .await;
        workspace.stop("api").await;
        workspace.spawn("api").await;
        workspace.ready("api").await;
        workspace.state("api", "Healthy").await;
        let after = workspace.channels.snapshots.borrow().clone();
        for id in ["db", "web"] {
            assert_eq!(before.services[id], after.services[id]);
        }
        assert_ne!(
            before.services["api"].state.runtime_identity(),
            after.services["api"].state.runtime_identity()
        );
        assert_eq!(after.services["api"].restart_count, 1);
        assert_eq!(
            workspace.spawn_counts(),
            BTreeMap::from([("db".into(), 1), ("api".into(), 2), ("web".into(), 1),])
        );
        let stops: Vec<_> = workspace
            .trace()
            .into_iter()
            .filter(|call| matches!(call, Call::Stop(..)))
            .collect();
        assert_eq!(
            stops,
            [Call::Stop(
                before.services["api"]
                    .state
                    .runtime_identity()
                    .unwrap()
                    .clone(),
                Duration::from_millis(202)
            )]
        );
        workspace.shutdown().await;
    })
    .await;
}
