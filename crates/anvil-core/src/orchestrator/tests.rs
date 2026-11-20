use super::*;
use crate::probe::ContainerHealthStatus;
use tokio::task::JoinHandle;

enum Request {
    Start(
        ServiceId,
        Option<broadcast::Sender<String>>,
        oneshot::Sender<Result<StartedInstance, ExecutionError>>,
    ),
    Health(String, oneshot::Sender<ContainerHealthStatus>),
    Stop(
        RuntimeIdentity,
        Duration,
        oneshot::Sender<Result<(), ExecutionError>>,
    ),
}

#[derive(Clone)]
struct Controlled {
    requests: mpsc::Sender<Request>,
    data: Arc<tempfile::TempDir>,
}

fn test_actor(
    config: AnvilConfig,
    requests: mpsc::Sender<Request>,
) -> (Orchestrator, EngineChannels) {
    let graph = DependencyGraph::from_config(&config).unwrap();
    let executor = Controlled {
        requests,
        data: Arc::new(tempfile::tempdir().unwrap()),
    };
    let store =
        WorkspacePersistence::with_root(executor.data.path(), &config.project.name).unwrap();
    let (actor, channels) = Orchestrator::new(Arc::new(config), &graph, Arc::new(executor));
    (actor.with_crash_persistence(store, 200), channels)
}

#[async_trait::async_trait]
impl ContainerHealthInspector for Controlled {
    async fn inspect_health(
        &self,
        target: &str,
    ) -> Result<ContainerHealthStatus, crate::CoreError> {
        let (reply, rx) = oneshot::channel();
        self.requests
            .send(Request::Health(target.into(), reply))
            .await
            .unwrap();
        Ok(rx.await.unwrap())
    }
}

#[async_trait::async_trait]
impl EngineExecutor for Controlled {
    async fn start(
        &self,
        id: &str,
        _: &ServiceConfig,
        logs: Option<broadcast::Sender<String>>,
    ) -> Result<StartedInstance, ExecutionError> {
        let (tx, rx) = oneshot::channel();
        self.requests
            .send(Request::Start(id.into(), logs, tx))
            .await
            .unwrap();
        rx.await.unwrap()
    }
    fn health_inspector(&self) -> Option<Arc<dyn ContainerHealthInspector>> {
        Some(Arc::new(self.clone()))
    }
    async fn stop(
        &self,
        identity: &RuntimeIdentity,
        grace: Duration,
    ) -> Result<(), ExecutionError> {
        let (tx, rx) = oneshot::channel();
        self.requests
            .send(Request::Stop(identity.clone(), grace, tx))
            .await
            .unwrap();
        rx.await.unwrap()
    }
}

fn workspace() -> (
    EngineChannels,
    mpsc::Receiver<Request>,
    JoinHandle<Result<(), ExecutionError>>,
) {
    let config = AnvilConfig::from_yaml_str(
        r#"
version: "1"
project: {name: sample}
services:
  db:
    runtime: {type: native, cmd: database, grace_period_ms: 175}
  api:
    depends_on: [db]
    port: 8080
    runtime: {type: native, cmd: api}
"#,
    )
    .unwrap();
    let (tx, rx) = mpsc::channel(4);
    let (actor, channels) = test_actor(config, tx);
    (channels, rx, tokio::spawn(actor.run()))
}

async fn start_request(
    ch: &EngineChannels,
    requests: &mut mpsc::Receiver<Request>,
) -> oneshot::Sender<Result<StartedInstance, ExecutionError>> {
    ch.commands
        .send(EngineCommand::Start("db".into()))
        .await
        .unwrap();
    let Request::Start(id, _, reply) = requests.recv().await.unwrap() else {
        panic!("expected start request")
    };
    assert_eq!(id, "db");
    reply
}

fn instance() -> (StartedInstance, oneshot::Sender<InstanceExit>) {
    let (tx, exit) = oneshot::channel();
    let identity = RuntimeIdentity::NativeProcess {
        pid: 42,
        pgid: 42,
        start_time_secs: 1,
    };
    let (done, drained) = oneshot::channel();
    assert!(done.send(Ok(LogRing::default())).is_ok());
    let (saved, log_written) = oneshot::channel();
    saved.send(Ok(())).unwrap();
    (
        StartedInstance {
            identity,
            exit,
            drained,
            log_written,
        },
        tx,
    )
}

#[tokio::test]
async fn idle_workspace_closes_and_joins() {
    let (mut ch, mut requests, task) = workspace();
    assert_eq!(ch.commands.max_capacity(), 64);
    assert_eq!(ch.logs.max_capacity(), 256);
    let initial = ch.snapshots.borrow().clone();
    assert_eq!(initial.project_name, "sample");
    assert_eq!(initial.topology_layers, [vec!["db"], vec!["api"]]);
    assert_eq!(initial.services["api"].port, Some(8080));
    assert!(initial
        .services
        .values()
        .all(|svc| svc.state == ServiceState::Idle));
    ch.commands.send(EngineCommand::Shutdown).await.unwrap();
    task.await.unwrap().unwrap();
    assert!(ch.commands.is_closed());
    assert!(ch.snapshots.changed().await.is_err());
    assert!(ch.logs.recv().await.is_none());
    assert!(requests.recv().await.is_none());
}

#[tokio::test]
async fn start_and_exit_publish_new_snapshots_preserving_old_arcs() {
    let (mut ch, mut requests, task) = workspace();
    let initial = ch.snapshots.borrow_and_update().clone();
    let reply = start_request(&ch, &mut requests).await;
    ch.snapshots.changed().await.unwrap();
    let starting = ch.snapshots.borrow_and_update().clone();
    assert_eq!(starting.services["db"].state, ServiceState::Starting);
    let (created, exit) = instance();
    let identity = created.identity.clone();
    assert!(reply.send(Ok(created)).is_ok());
    ch.snapshots.changed().await.unwrap();
    let healthy = ch.snapshots.borrow_and_update().clone();
    assert_eq!(
        healthy.services["db"].state.runtime_identity(),
        Some(&identity)
    );
    exit.send(InstanceExit::Process {
        code: Some(0),
        signal: None,
    })
    .unwrap();
    assert_eq!(
        state(&mut ch, "db", "Stopped").await,
        ServiceState::Stopped { exit_code: Some(0) }
    );
    assert_eq!(initial.services["db"].state, ServiceState::Idle);
    assert_eq!(starting.services["db"].state, ServiceState::Starting);
    drop(ch.commands);
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn noop_commands_preserve_watch_version_and_arc() {
    let (mut ch, mut requests, task) = workspace();
    ch.commands
        .send(EngineCommand::Start("api".into()))
        .await
        .unwrap();
    ch.snapshots.changed().await.unwrap();
    let waiting = ch.snapshots.borrow_and_update().clone();
    assert_eq!(
        waiting.services["api"].state,
        ServiceState::WaitingDeps {
            pending_deps: vec!["db".into()]
        }
    );
    ch.commands
        .send(EngineCommand::Start("api".into()))
        .await
        .unwrap();
    ch.commands
        .send(EngineCommand::Start("missing".into()))
        .await
        .unwrap();
    drop(
        ch.commands
            .reserve_many(ch.commands.max_capacity())
            .await
            .unwrap(),
    );
    assert!(!ch.snapshots.has_changed().unwrap());
    assert!(Arc::ptr_eq(&waiting, &ch.snapshots.borrow()));
    drop(ch.commands);
    task.await.unwrap().unwrap();
    assert_eq!(
        ch.snapshots.borrow().services["api"].state,
        ServiceState::Stopped { exit_code: None }
    );
    assert!(requests.recv().await.is_none());
}

#[tokio::test]
async fn shutdown_during_spawn_waits_for_identity_and_stop_ack() {
    let (mut ch, mut requests, task) = workspace();
    let reply = start_request(&ch, &mut requests).await;
    ch.commands.send(EngineCommand::Shutdown).await.unwrap();
    state(&mut ch, "db", "Stopping").await;
    let (created, exit) = instance();
    let expected = created.identity.clone();
    assert!(reply.send(Ok(created)).is_ok());
    let Request::Stop(identity, grace, stopped) = requests.recv().await.unwrap() else {
        panic!("expected stop request")
    };
    assert_eq!(identity, expected);
    assert_eq!(grace, Duration::from_millis(175));
    assert!(!task.is_finished());
    stopped.send(Ok(())).unwrap();
    exit.send(InstanceExit::Process {
        code: None,
        signal: Some(15),
    })
    .unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(
        ch.snapshots.borrow().services["db"].state,
        ServiceState::Stopped { exit_code: None }
    );
}

fn configured(services: &str) -> (Orchestrator, EngineChannels, mpsc::Receiver<Request>) {
    let cfg = AnvilConfig::from_yaml_str(&format!(
        "version: '1'\nproject: {{ name: test }}\nservices:\n{services}"
    ))
    .unwrap();
    let (tx, rx) = mpsc::channel(16);
    let (actor, ch) = test_actor(cfg, tx);
    (actor, ch, rx)
}

async fn state(ch: &mut EngineChannels, id: &str, label: &str) -> ServiceState {
    ch.snapshots
        .wait_for(|s| s.services[id].state.label() == label)
        .await
        .unwrap()
        .services[id]
        .state
        .clone()
}

struct Spawn {
    id: String,
    logs: Option<broadcast::Sender<String>>,
    reply: oneshot::Sender<Result<StartedInstance, ExecutionError>>,
}

impl Spawn {
    async fn next(rx: &mut mpsc::Receiver<Request>) -> Self {
        let Some(Request::Start(id, logs, reply)) = rx.recv().await else {
            panic!("expected spawn")
        };
        Self { id, logs, reply }
    }

    fn created(self) -> oneshot::Sender<InstanceExit> {
        let (mut started, exit) = instance();
        started.identity = RuntimeIdentity::DockerContainer {
            container_id: format!("cid-{}", self.id),
            container_name: self.id,
        };
        assert!(self.reply.send(Ok(started)).is_ok());
        exit
    }
}

fn finished(exit: oneshot::Sender<InstanceExit>) {
    exit.send(InstanceExit::Process {
        code: Some(0),
        signal: None,
    })
    .unwrap();
}

#[tokio::test]
async fn workspace_chain_waits_for_each_probe_and_starts_once() {
    let (actor, mut ch, mut rx) = configured(
        r#"
  db:
    runtime: {type: docker_container, image: postgres}
    readiness_probe: {type: docker_health}
  api:
    depends_on: [db]
    runtime: {type: native, cmd: api}
    readiness_probe: {type: log_regex, pattern: '^ready$'}
  web:
    depends_on: [api]
    runtime: {type: native, cmd: web}
"#,
    );
    let events = actor.events.clone();
    let task = tokio::spawn(actor.run());
    ch.commands
        .send(EngineCommand::StartWorkspace)
        .await
        .unwrap();
    let db = Spawn::next(&mut rx).await;
    assert_eq!(db.id, "db");
    let db_exit = db.created();
    let Some(Request::Health(target, ready)) = rx.recv().await else {
        panic!("expected Docker inspector")
    };
    assert_eq!(target, "cid-db");
    state(&mut ch, "db", "Probing").await;
    assert_eq!(
        ch.snapshots.borrow().services["api"].state,
        ServiceState::WaitingDeps {
            pending_deps: vec!["db".into()]
        }
    );
    assert!(rx.try_recv().is_err());
    ready.send(ContainerHealthStatus::Healthy).unwrap();
    let api = Spawn::next(&mut rx).await;
    assert_eq!(api.id, "api");
    let logs = api.logs.clone().unwrap();
    let api_exit = api.created();
    state(&mut ch, "api", "Probing").await;
    assert_eq!(
        ch.snapshots.borrow().services["web"].state,
        ServiceState::WaitingDeps {
            pending_deps: vec!["api".into()]
        }
    );
    assert!(rx.try_recv().is_err());
    logs.send("ready".into()).unwrap();
    let web = Spawn::next(&mut rx).await;
    assert_eq!(web.id, "web");
    // Deliver a duplicate completion through the same internal channel as the probe.
    events
        .send(InstanceEvent::Ready(Launch {
            id: "api".into(),
            generation: 1,
        }))
        .await
        .unwrap();
    ch.commands
        .send(EngineCommand::StartWorkspace)
        .await
        .unwrap();
    let web_exit = web.created();
    state(&mut ch, "web", "Healthy").await;
    for exit in [web_exit, api_exit, db_exit] {
        finished(exit);
    }
    for id in ["web", "api", "db"] {
        state(&mut ch, id, "Stopped").await;
    }
    drop(ch.commands);
    task.await.unwrap().unwrap();
    assert!(rx.recv().await.is_none());
}

#[tokio::test]
async fn diamond_waits_for_both_branches_and_captures_spawn_time_logs() {
    let (actor, mut ch, mut rx) = configured(
        r#"
  db:
    runtime: {type: native, cmd: db}
    readiness_probe: {type: log_regex, pattern: booted}
  left:
    depends_on: [db]
    runtime: {type: native, cmd: left}
  right:
    depends_on: [db]
    runtime: {type: native, cmd: right}
  web:
    depends_on: [left, right]
    runtime: {type: native, cmd: web}
"#,
    );
    let task = tokio::spawn(actor.run());
    ch.commands
        .send(EngineCommand::StartWorkspace)
        .await
        .unwrap();
    let db = Spawn::next(&mut rx).await;
    assert_eq!(db.id, "db");
    // The only matching line is emitted before the spawn acknowledgement.
    db.logs.as_ref().unwrap().send("booted".into()).unwrap();
    let db_exit = db.created();
    let first = Spawn::next(&mut rx).await;
    let second = Spawn::next(&mut rx).await;
    let (left, right) = if first.id == "left" {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!((&*left.id, &*right.id), ("left", "right"));
    let left_exit = left.created();
    ch.snapshots.wait_for(|s| matches!(&s.services["web"].state, ServiceState::WaitingDeps { pending_deps } if pending_deps == &["right"])).await.unwrap();
    assert!(rx.try_recv().is_err());
    let right_exit = right.created();
    let web = Spawn::next(&mut rx).await;
    assert_eq!(web.id, "web");
    let web_exit = web.created();
    state(&mut ch, "web", "Healthy").await;
    for exit in [web_exit, left_exit, right_exit, db_exit] {
        finished(exit);
    }
    drop(ch.commands);
    task.await.unwrap().unwrap();
    assert!(rx.recv().await.is_none());
}

#[tokio::test]
async fn occupied_port_is_rechecked_before_spawn() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (actor, mut ch, mut rx) = configured(&format!(
        "  db:\n    runtime: {{type: native, cmd: db}}\n    port: {port}"
    ));
    let task = tokio::spawn(actor.run());
    ch.commands
        .send(EngineCommand::StartWorkspace)
        .await
        .unwrap();
    let ServiceState::PortConflict(occupant) = state(&mut ch, "db", "PortConflict").await else {
        unreachable!()
    };
    assert_eq!(occupant.port, port);
    assert_eq!(occupant.cmdline, "[REDACTED]");
    assert!(rx.try_recv().is_err());
    ch.commands
        .send(EngineCommand::Start("db".into()))
        .await
        .unwrap();
    // Wait for a new watch version after retry, even if PortCheck was coalesced.
    ch.snapshots.changed().await.unwrap();
    state(&mut ch, "db", "PortConflict").await;
    assert!(rx.try_recv().is_err());
    drop(listener);
    ch.commands
        .send(EngineCommand::Start("db".into()))
        .await
        .unwrap();
    let db = Spawn::next(&mut rx).await;
    assert_eq!(db.id, "db");
    let exit = db.created();
    state(&mut ch, "db", "Healthy").await;
    assert_eq!(ch.snapshots.borrow().services["db"].restart_count, 0);
    finished(exit);
    drop(ch.commands);
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn independent_roots_can_spawn_before_either_acknowledgement() {
    let (actor, ch, mut rx) = configured(
        r#"
  db:
    runtime: {type: native, cmd: db}
  cache:
    runtime: {type: native, cmd: cache}
"#,
    );
    let task = tokio::spawn(actor.run());
    ch.commands
        .send(EngineCommand::StartWorkspace)
        .await
        .unwrap();
    let a = Spawn::next(&mut rx).await;
    let b = Spawn::next(&mut rx).await;
    let mut ids = [a.id.as_str(), b.id.as_str()];
    ids.sort();
    assert_eq!(ids, ["cache", "db"]);
    finished(a.created());
    finished(b.created());
    drop(ch.commands);
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn probe_timeout_error_and_shutdown_stop_the_instance_without_unlocking() {
    enum End {
        Timeout,
        ClosedStream,
        Shutdown,
    }
    for end in [End::Timeout, End::ClosedStream, End::Shutdown] {
        let (actor, mut ch, mut rx) = configured(
            r#"
  db:
    runtime: {type: native, cmd: db}
    readiness_probe: {type: log_regex, pattern: ready, timeout_ms: 1500}
  api:
    depends_on: [db]
    runtime: {type: native, cmd: api}
"#,
        );
        let dir = tempfile::tempdir().unwrap();
        let store = WorkspacePersistence::with_root(dir.path(), "test").unwrap();
        let task = tokio::spawn(actor.with_crash_persistence(store, 2).run());
        ch.commands
            .send(EngineCommand::StartWorkspace)
            .await
            .unwrap();
        let mut db = Spawn::next(&mut rx).await;
        let logs = db.logs.take().unwrap();
        let exit = db.created();
        state(&mut ch, "db", "Probing").await;
        let reason = match end {
            End::Timeout => {
                tokio::time::advance(Duration::from_millis(1500)).await;
                Some("readiness probe timed out")
            }
            End::ClosedStream => {
                drop(logs);
                Some("readiness probe failed")
            }
            End::Shutdown => {
                ch.commands.send(EngineCommand::Shutdown).await.unwrap();
                None
            }
        };
        let Some(Request::Stop(RuntimeIdentity::DockerContainer { container_id, .. }, _, ack)) =
            rx.recv().await
        else {
            panic!("expected stop for probing instance")
        };
        assert_eq!(container_id, "cid-db");
        ack.send(Ok(())).unwrap();
        if let Some(expected) = reason {
            let ServiceState::Crashed {
                reason,
                crash_log_path,
                ..
            } = state(&mut ch, "db", "Crashed").await
            else {
                unreachable!()
            };
            assert_eq!(reason, expected);
            assert!(tokio::fs::metadata(crash_log_path).await.unwrap().is_file());
            assert!(matches!(
                ch.snapshots.borrow().services["api"].state,
                ServiceState::WaitingDeps { .. }
            ));
        } else {
            finished(exit);
            state(&mut ch, "db", "Stopped").await;
            assert_eq!(
                ch.snapshots.borrow().services["api"].state,
                ServiceState::Stopped { exit_code: None }
            );
        }
        drop(ch.commands);
        task.await.unwrap().unwrap();
        assert!(rx.recv().await.is_none());
    }
}

#[tokio::test]
async fn exited_branch_blocks_join_until_current_generation_is_ready() {
    let (actor, mut ch, mut rx) = configured(
        r#"
  a:
    runtime: {type: native, cmd: a}
    readiness_probe: {type: log_regex, pattern: ready}
  b:
    runtime: {type: native, cmd: b}
  marker:
    runtime: {type: native, cmd: marker}
  web:
    depends_on: [a, b]
    runtime: {type: native, cmd: web}
"#,
    );
    let events = actor.events.clone();
    let task = tokio::spawn(actor.run());
    ch.commands
        .send(EngineCommand::StartWorkspace)
        .await
        .unwrap();
    let mut roots = BTreeMap::new();
    for _ in 0..3 {
        let root = Spawn::next(&mut rx).await;
        roots.insert(root.id.clone(), root);
    }
    let a = roots.remove("a").unwrap();
    let b = roots.remove("b").unwrap();
    let marker = roots.remove("marker").unwrap();
    a.logs.as_ref().unwrap().send("ready".into()).unwrap();
    let exit = a.created();
    state(&mut ch, "a", "Healthy").await;
    finished(exit);
    state(&mut ch, "a", "Stopped").await;
    let b_exit = b.created();
    state(&mut ch, "b", "Healthy").await;
    ch.commands
        .send(EngineCommand::Start("a".into()))
        .await
        .unwrap();
    let next = Spawn::next(&mut rx).await;
    assert_eq!(next.id, "a");
    let logs = next.logs.as_ref().unwrap().clone();
    let a_exit = next.created();
    state(&mut ch, "a", "Probing").await;
    events
        .send(InstanceEvent::Ready(Launch {
            id: "a".into(),
            generation: 1,
        }))
        .await
        .unwrap();
    // The marker's Started event follows the obsolete Ready on the same FIFO.
    let marker_exit = marker.created();
    state(&mut ch, "marker", "Healthy").await;
    assert!(matches!(
        ch.snapshots.borrow().services["a"].state,
        ServiceState::Probing { .. }
    ));
    assert_eq!(
        ch.snapshots.borrow().services["web"].state,
        ServiceState::WaitingDeps {
            pending_deps: vec!["a".into()]
        }
    );
    assert!(rx.try_recv().is_err());
    logs.send("ready".into()).unwrap();
    let web = Spawn::next(&mut rx).await;
    assert_eq!(web.id, "web");
    let web_exit = web.created();
    state(&mut ch, "web", "Healthy").await;
    for exit in [web_exit, a_exit, b_exit, marker_exit] {
        finished(exit);
    }
    drop(ch.commands);
    task.await.unwrap().unwrap();
    assert!(rx.recv().await.is_none());
}

const DB_AND_WORKER: &str = "
  db:
    runtime: {type: native, cmd: db}
  worker:
    runtime: {type: native, cmd: worker}";

async fn start_named(ch: &EngineChannels, rx: &mut mpsc::Receiver<Request>, id: &str) -> Spawn {
    ch.commands
        .send(EngineCommand::Start(id.into()))
        .await
        .unwrap();
    let spawn = Spawn::next(rx).await;
    assert_eq!(spawn.id, id);
    spawn
}

async fn send_record(input: &mpsc::Sender<crate::log_ring::LogInput>, body: &'static str) {
    input
        .send(crate::log_ring::LogInput::Line(LogEntry {
            source: crate::log_ring::LogSource::Stderr,
            timestamp: SystemTime::now(),
            redacted_body: body.into(),
        }))
        .await
        .unwrap();
}

async fn crash_report(ch: &mut EngineChannels) -> (String, serde_yaml::Value) {
    let ServiceState::Crashed { crash_log_path, .. } = state(ch, "db", "Crashed").await else {
        unreachable!()
    };
    let bytes = tokio::fs::read(&crash_log_path).await.unwrap();
    (crash_log_path, serde_yaml::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn exit_before_final_lines_persists_the_drained_generation_tail() {
    let dir = tempfile::tempdir().unwrap();
    let store = WorkspacePersistence::with_root(dir.path(), "test").unwrap();
    let (actor, mut ch, mut rx) = configured(DB_AND_WORKER);
    let (input, logs) = mpsc::channel(4);
    let (complete, full) = mpsc::channel(4);
    let collector = actor.service_log_ingestor("db".into(), complete);
    let (done, drained) = oneshot::channel();
    let collector = tokio::spawn(async move {
        assert!(done.send(collector.run(logs).await).is_ok());
    });
    let writer_store = store.clone();
    let (saved, written) = oneshot::channel();
    let writer = tokio::spawn(async move {
        let result = writer_store.write_service_log("db", full).await;
        saved
            .send(
                result
                    .as_ref()
                    .map(|_| ())
                    .map_err(|_| ExecutionError::LogWrite),
            )
            .unwrap();
        result
    });
    let task = tokio::spawn(actor.with_crash_persistence(store, 2).run());
    let db = start_named(&ch, &mut rx, "db").await;
    let (mut started, exit) = instance();
    let identity = started.identity.clone();
    started.drained = drained;
    started.log_written = written;
    assert!(db.reply.send(Ok(started)).is_ok());
    state(&mut ch, "db", "Healthy").await;
    send_record(&input, "earlier line").await;
    exit.send(InstanceExit::Process {
        code: Some(23),
        signal: None,
    })
    .unwrap();
    state(&mut ch, "db", "Stopping").await;

    // A different service starts while db's collector is held open.
    let worker = start_named(&ch, &mut rx, "worker").await.created();
    state(&mut ch, "worker", "Healthy").await;
    send_record(&input, "last stderr [REDACTED]").await;
    send_record(&input, "final shutdown line").await;
    drop(input);
    let (_, report) = crash_report(&mut ch).await;
    assert_eq!(report["generation"].as_u64(), Some(1));
    assert_eq!(report["exit_code"].as_i64(), Some(23));
    assert_eq!(
        serde_yaml::from_value::<RuntimeIdentity>(report["identity"].clone()).unwrap(),
        identity
    );
    let tail = report["tail"].as_sequence().unwrap();
    assert_eq!(tail.len(), 2);
    assert_eq!(tail[0]["body"], "last stderr [REDACTED]");
    assert_eq!(tail[1]["body"], "final shutdown line");
    collector.await.unwrap();
    assert!(tokio::fs::read_to_string(writer.await.unwrap().unwrap())
        .await
        .unwrap()
        .contains("earlier line"));
    finished(worker);
    state(&mut ch, "worker", "Stopped").await;
    drop(ch.commands);
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn simultaneous_probe_deadline_and_oom_write_one_crash() {
    let dir = tempfile::tempdir().unwrap();
    let store = WorkspacePersistence::with_root(dir.path(), "test").unwrap();
    let (actor, mut ch, mut rx) = configured(
        "
  db:
    runtime: {type: docker_container, image: db}
    readiness_probe: {type: docker_health, timeout_ms: 1500}",
    );
    let task = tokio::spawn(actor.with_crash_persistence(store, 2).run());
    let exit = start_named(&ch, &mut rx, "db").await.created();
    let Some(Request::Health(_, _pending)) = rx.recv().await else {
        panic!("expected probe")
    };
    // Both become ready in the same poll on this single-thread runtime.
    tokio::join!(biased;
        tokio::time::advance(Duration::from_millis(1500)),
        async { exit.send(InstanceExit::Container { exit_code: 137, oom_killed: true }).unwrap(); }
    );
    let (path, report) = crash_report(&mut ch).await;
    assert_eq!(report["redacted_reason"], "container out of memory");
    assert_eq!(report["exit_code"].as_i64(), Some(137));
    drop(ch.commands);
    task.await.unwrap().unwrap();
    assert!(rx.recv().await.is_none());
    let mut files = tokio::fs::read_dir(std::path::Path::new(&path).parent().unwrap())
        .await
        .unwrap();
    assert_eq!(
        files.next_entry().await.unwrap().unwrap().path(),
        std::path::Path::new(&path)
    );
    assert!(files.next_entry().await.unwrap().is_none());
}

#[tokio::test(start_paused = true)]
async fn late_exit_after_probe_cleanup_cannot_crash_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let store = WorkspacePersistence::with_root(dir.path(), "test").unwrap();
    let (actor, mut ch, mut rx) = configured(
        "
  db:
    runtime: {type: native, cmd: db}
    readiness_probe: {type: log_regex, pattern: ready, timeout_ms: 1500}",
    );
    let task = tokio::spawn(actor.with_crash_persistence(store, 2).run());
    let first = start_named(&ch, &mut rx, "db").await;
    let _probe_open = first.logs.clone();
    let old_exit = first.created();
    state(&mut ch, "db", "Probing").await;
    tokio::time::advance(Duration::from_millis(1500)).await;
    let Some(Request::Stop(_, _, ack)) = rx.recv().await else {
        panic!("expected cleanup")
    };
    ack.send(Ok(())).unwrap();
    let (path, report) = crash_report(&mut ch).await;
    assert_eq!(report["redacted_reason"], "readiness probe timed out");
    let next = start_named(&ch, &mut rx, "db").await;
    next.logs.as_ref().unwrap().send("ready".into()).unwrap();
    let new_exit = next.created();
    state(&mut ch, "db", "Healthy").await;
    assert!(old_exit
        .send(InstanceExit::Process {
            code: Some(19),
            signal: None
        })
        .is_err());
    assert_eq!(ch.snapshots.borrow().services["db"].restart_count, 1);
    finished(new_exit);
    assert_eq!(
        state(&mut ch, "db", "Stopped").await,
        ServiceState::Stopped { exit_code: Some(0) }
    );
    drop(ch.commands);
    task.await.unwrap().unwrap();
    let files = std::fs::read_dir(std::path::Path::new(&path).parent().unwrap()).unwrap();
    assert_eq!(files.count(), 1);
}

#[tokio::test]
async fn graceful_stop_and_clean_exit_leave_no_crash_reports() {
    let dir = tempfile::tempdir().unwrap();
    let store = WorkspacePersistence::with_root(dir.path(), "test").unwrap();
    let (actor, mut ch, mut rx) = configured(DB_AND_WORKER);
    let task = tokio::spawn(actor.with_crash_persistence(store, 2).run());
    let db = start_named(&ch, &mut rx, "db").await.created();
    let worker = start_named(&ch, &mut rx, "worker").await.created();
    finished(worker);
    state(&mut ch, "worker", "Stopped").await;
    ch.commands.send(EngineCommand::Shutdown).await.unwrap();
    let Some(Request::Stop(_, _, ack)) = rx.recv().await else {
        panic!("expected stop")
    };
    db.send(InstanceExit::Process {
        code: None,
        signal: Some(15),
    })
    .unwrap();
    ack.send(Ok(())).unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(
        ch.snapshots.borrow().services["db"].state,
        ServiceState::Stopped { exit_code: None }
    );
    assert!(!dir.path().join("logs/test/crashes").exists());
}

#[tokio::test]
async fn failed_crash_write_has_no_path_and_other_services_continue() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("not-a-directory");
    tokio::fs::write(&file, b"").await.unwrap();
    let store = WorkspacePersistence::with_root(file, "test").unwrap();
    let (actor, mut ch, mut rx) = configured(DB_AND_WORKER);
    let task = tokio::spawn(actor.with_crash_persistence(store, 2).run());
    let db = start_named(&ch, &mut rx, "db").await.created();
    db.send(InstanceExit::Process {
        code: None,
        signal: Some(9),
    })
    .unwrap();
    let ServiceState::Crashed {
        reason,
        crash_log_path,
        signal,
        ..
    } = state(&mut ch, "db", "Crashed").await
    else {
        unreachable!()
    };
    assert_eq!(signal, Some(9));
    assert!(reason.contains("crash report write failed"));
    assert!(crash_log_path.is_empty());
    let worker = start_named(&ch, &mut rx, "worker").await.created();
    state(&mut ch, "worker", "Healthy").await;
    finished(worker);
    drop(ch.commands);
    task.await.unwrap().unwrap();
}

impl Spawn {
    fn created_as(self, pid: u32) -> oneshot::Sender<InstanceExit> {
        let (mut started, exit) = instance();
        started.identity = RuntimeIdentity::NativeProcess {
            pid,
            pgid: pid,
            start_time_secs: u64::from(pid),
        };
        assert!(self.reply.send(Ok(started)).is_ok());
        exit
    }

    fn failed(self) {
        assert!(self.reply.send(Err(ExecutionError::Start)).is_ok());
    }
}

async fn command(ch: &EngineChannels, cmd: EngineCommand) {
    ch.commands.send(cmd).await.unwrap();
}

async fn stop_request(
    rx: &mut mpsc::Receiver<Request>,
) -> (RuntimeIdentity, oneshot::Sender<Result<(), ExecutionError>>) {
    let Some(Request::Stop(identity, _, ack)) = rx.recv().await else {
        panic!("expected stop")
    };
    (identity, ack)
}

#[tokio::test(start_paused = true)]
async fn hot_restart_replaces_only_api_and_coalesces_duplicate_requests() {
    let (mut actor, mut ch, mut rx) = configured(
        "
  db:
    runtime: {type: native, cmd: db}
  api:
    depends_on: [db]
    runtime: {type: native, cmd: api}
    readiness_probe: {type: log_regex, pattern: ready}
  web:
    depends_on: [api]
    runtime: {type: native, cmd: web}
  cache:
    runtime: {type: native, cmd: cache}
  join:
    depends_on: [api, cache]
    runtime: {type: native, cmd: join}",
    );
    let events = actor.events.clone();
    // Hold a duplicate old exit at the same JoinSet boundary as runtime completion.
    let (release, delayed) = oneshot::channel();
    actor.tasks.spawn(async move {
        delayed.await.unwrap();
        Completion::Exited(
            Launch {
                id: "api".into(),
                generation: 1,
            },
            Ok(ServiceState::Stopped {
                exit_code: Some(47),
            }),
        )
    });
    let task = tokio::spawn(actor.run());
    let db = start_named(&ch, &mut rx, "db").await.created_as(10);
    state(&mut ch, "db", "Healthy").await;
    let api = start_named(&ch, &mut rx, "api").await;
    api.logs.as_ref().unwrap().send("ready".into()).unwrap();
    let old = api.created_as(20);
    state(&mut ch, "api", "Healthy").await;
    let web = start_named(&ch, &mut rx, "web").await.created_as(30);
    state(&mut ch, "web", "Healthy").await;
    let before = ch.snapshots.borrow().clone();

    for _ in 0..3 {
        command(&ch, EngineCommand::Restart("api".into())).await;
    }
    let (identity, ack) = stop_request(&mut rx).await;
    assert_eq!(
        Some(&identity),
        before.services["api"].state.runtime_identity()
    );
    ack.send(Ok(())).unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(1), rx.recv())
        .await
        .is_err());
    assert_eq!(
        ch.snapshots.borrow().services["api"].state,
        ServiceState::Stopping
    );
    finished(old);
    let api = Spawn::next(&mut rx).await;
    assert_eq!(api.id, "api");
    let probe = api.logs.clone().unwrap();
    let new = api.created_as(21);
    state(&mut ch, "api", "Probing").await;
    command(&ch, EngineCommand::Restart("api".into())).await;
    command(&ch, EngineCommand::Start("join".into())).await;
    state(&mut ch, "join", "WaitingDeps").await;
    release.send(()).unwrap();
    events
        .send(InstanceEvent::Ready(Launch {
            id: "api".into(),
            generation: 1,
        }))
        .await
        .unwrap();
    let cache = start_named(&ch, &mut rx, "cache").await.created_as(40);
    state(&mut ch, "cache", "Healthy").await;
    assert!(matches!(
        ch.snapshots.borrow().services["api"].state,
        ServiceState::Probing { .. }
    ));
    assert_eq!(
        ch.snapshots.borrow().services["join"].state,
        ServiceState::WaitingDeps {
            pending_deps: vec!["api".into()]
        }
    );
    probe.send("ready".into()).unwrap();
    let join = Spawn::next(&mut rx).await;
    assert_eq!(join.id, "join");
    let join = join.created_as(50);
    state(&mut ch, "join", "Healthy").await;
    let after = ch.snapshots.borrow().clone();
    for id in ["db", "web"] {
        assert_eq!(before.services[id], after.services[id]);
    }
    assert_ne!(
        after.services["api"].state.runtime_identity(),
        Some(&identity)
    );
    assert_eq!(after.services["api"].restart_count, 1);
    for exit in [db, new, web, cache, join] {
        finished(exit);
    }
    drop(ch.commands);
    task.await.unwrap().unwrap();
    assert!(rx.recv().await.is_none());
    assert_eq!(
        ch.snapshots.borrow().services["api"].state,
        ServiceState::Stopped { exit_code: Some(0) }
    );
}

// A real port may still be reported occupied just after releasing the listener.
// Drive the same explicit recheck a client would issue on a fresh conflict snapshot.
async fn start_after_port_release(
    ch: &mut EngineChannels,
    rx: &mut mpsc::Receiver<Request>,
) -> Spawn {
    ch.snapshots.borrow_and_update();
    command(ch, EngineCommand::Start("api".into())).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                spawn = Spawn::next(rx) => return spawn,
                changed = ch.snapshots.changed() => {
                    changed.unwrap();
                    let conflict = matches!(ch.snapshots.borrow_and_update().services["api"].state, ServiceState::PortConflict(_));
                    if conflict { command(ch, EngineCommand::Start("api".into())).await; }
                }
            }
        }
    }).await.unwrap_or_else(|_| panic!("port recheck stalled: {:?}", ch.snapshots.borrow().services["api"].state))
}

#[tokio::test]
async fn restart_cancels_pending_probe_and_rechecks_dependencies_and_port() {
    // Reserve both address families outside the ephemeral pool used by parallel
    // networking tests. The preflight checks both IPv4 and IPv6.
    let (port, reservation, reservation_v6) = (12_000..13_000)
        .find_map(|port| {
            let v4 = std::net::TcpListener::bind(("127.0.0.1", port)).ok()?;
            let v6 = std::net::TcpListener::bind(("::1", port)).ok()?;
            Some((port, v4, v6))
        })
        .unwrap();
    let (actor, mut ch, mut rx) = configured(&format!(
        "
  db:
    runtime: {{type: native, cmd: db}}
  api:
    depends_on: [db]
    port: {port}
    runtime: {{type: docker_container, image: api}}
    readiness_probe: {{type: docker_health}}"
    ));
    let task = tokio::spawn(actor.run());
    let db = start_named(&ch, &mut rx, "db").await.created();
    state(&mut ch, "db", "Healthy").await;
    drop(reservation);
    drop(reservation_v6);
    let api = start_after_port_release(&mut ch, &mut rx).await.created();
    let Some(Request::Health(_, pending)) = rx.recv().await else {
        panic!("expected probe")
    };
    command(&ch, EngineCommand::Restart("api".into())).await;
    let (_, ack) = stop_request(&mut rx).await;
    assert!(pending.send(ContainerHealthStatus::Healthy).is_err());
    finished(db);
    state(&mut ch, "db", "Stopped").await;
    let occupied = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    finished(api);
    ack.send(Ok(())).unwrap();
    assert_eq!(
        state(&mut ch, "api", "WaitingDeps").await,
        ServiceState::WaitingDeps {
            pending_deps: vec!["db".into()]
        }
    );
    let db = start_named(&ch, &mut rx, "db").await.created();
    state(&mut ch, "api", "PortConflict").await;
    assert_eq!(ch.snapshots.borrow().services["api"].restart_count, 0);
    drop(occupied);
    let api = start_after_port_release(&mut ch, &mut rx).await.created();
    let Some(Request::Health(_, ready)) = rx.recv().await else {
        panic!("expected new probe")
    };
    ready.send(ContainerHealthStatus::Healthy).unwrap();
    state(&mut ch, "api", "Healthy").await;
    assert_eq!(ch.snapshots.borrow().services["api"].restart_count, 1);
    finished(api);
    finished(db);
    drop(ch.commands);
    task.await.unwrap().unwrap();
}

const RETRY_CONFIG: &str = "
  db:
    runtime: {type: native, cmd: db}
    restart_policy: {on_failure: true, max_retries: 2, backoff_ms: 100}";

async fn fixed_backoff_spawn(rx: &mut mpsc::Receiver<Request>) -> Spawn {
    let start = tokio::time::Instant::now();
    assert!(tokio::time::timeout(Duration::from_millis(99), rx.recv())
        .await
        .is_err());
    let spawn = Spawn::next(rx).await;
    assert_eq!(start.elapsed(), Duration::from_millis(100));
    spawn
}

#[tokio::test(start_paused = true)]
async fn fixed_backoff_caps_consecutive_failures_and_manual_restart_resets_budget() {
    let dir = tempfile::tempdir().unwrap();
    let store = WorkspacePersistence::with_root(dir.path(), "test").unwrap();
    let (actor, mut ch, mut rx) = configured(RETRY_CONFIG);
    let task = tokio::spawn(actor.with_crash_persistence(store, 2).run());
    start_named(&ch, &mut rx, "db").await.failed();
    state(&mut ch, "db", "Crashed").await;
    let retry = fixed_backoff_spawn(&mut rx).await.created();
    state(&mut ch, "db", "Healthy").await;
    // Momentary readiness alone does not replenish a crash-loop budget.
    retry
        .send(InstanceExit::Process {
            code: Some(1),
            signal: None,
        })
        .unwrap();
    state(&mut ch, "db", "Crashed").await;
    fixed_backoff_spawn(&mut rx).await.failed();
    state(&mut ch, "db", "Crashed").await;
    assert!(tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .is_err());
    assert_eq!(ch.snapshots.borrow().services["db"].restart_count, 2);

    command(&ch, EngineCommand::Restart("db".into())).await;
    Spawn::next(&mut rx).await.failed();
    state(&mut ch, "db", "Crashed").await;
    let retry = fixed_backoff_spawn(&mut rx).await.created();
    finished(retry);
    state(&mut ch, "db", "Stopped").await;
    assert_eq!(ch.snapshots.borrow().services["db"].restart_count, 4);
    assert!(tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .is_err());
    drop(ch.commands);
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn default_policy_leaves_failed_service_crashed() {
    let (actor, mut ch, mut rx) = configured(DB_AND_WORKER);
    let task = tokio::spawn(actor.run());
    start_named(&ch, &mut rx, "db").await.failed();
    state(&mut ch, "db", "Crashed").await;
    assert!(tokio::time::timeout(Duration::from_secs(60), rx.recv())
        .await
        .is_err());
    assert_eq!(ch.snapshots.borrow().services["db"].restart_count, 0);
    drop(ch.commands);
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn backoff_can_be_stopped_replaced_or_shut_down_before_deadline() {
    for action in [
        EngineCommand::Stop("db".into()),
        EngineCommand::Restart("db".into()),
        EngineCommand::Shutdown,
    ] {
        let (actor, mut ch, mut rx) = configured(RETRY_CONFIG);
        let task = tokio::spawn(actor.run());
        start_named(&ch, &mut rx, "db").await.failed();
        state(&mut ch, "db", "Crashed").await;
        let now = tokio::time::Instant::now();
        match action {
            EngineCommand::Stop(_) => {
                command(&ch, action).await;
                state(&mut ch, "db", "Stopped").await;
                assert_eq!(now.elapsed(), Duration::ZERO);
                assert!(tokio::time::timeout(Duration::from_secs(1), rx.recv())
                    .await
                    .is_err());
                assert_eq!(ch.snapshots.borrow().services["db"].restart_count, 0);
            }
            EngineCommand::Restart(_) => {
                command(&ch, action).await;
                let exit = Spawn::next(&mut rx).await.created();
                assert_eq!(now.elapsed(), Duration::ZERO);
                finished(exit);
                state(&mut ch, "db", "Stopped").await;
                assert!(tokio::time::timeout(Duration::from_secs(1), rx.recv())
                    .await
                    .is_err());
                assert_eq!(ch.snapshots.borrow().services["db"].restart_count, 1);
            }
            _ => {
                command(&ch, action).await;
                task.await.unwrap().unwrap();
                assert_eq!(now.elapsed(), Duration::ZERO);
                assert!(rx.recv().await.is_none());
                continue;
            }
        }
        drop(ch.commands);
        task.await.unwrap().unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn expired_old_timer_cannot_consume_the_replacements_retry() {
    let (mut actor, mut ch, mut rx) = configured(RETRY_CONFIG);
    let (release, delayed) = oneshot::channel();
    actor.tasks.spawn(async move {
        delayed.await.unwrap();
        Completion::Retry(Launch {
            id: "db".into(),
            generation: 1,
        })
    });
    let task = tokio::spawn(actor.run());
    start_named(&ch, &mut rx, "db").await.failed();
    state(&mut ch, "db", "Crashed").await;
    command(&ch, EngineCommand::Restart("db".into())).await;
    Spawn::next(&mut rx).await.failed();
    state(&mut ch, "db", "Crashed").await;

    // Generation two has its own pending timer when generation one's completion arrives.
    release.send(()).unwrap();
    let retry = fixed_backoff_spawn(&mut rx).await.created();
    finished(retry);
    state(&mut ch, "db", "Stopped").await;
    assert_eq!(ch.snapshots.borrow().services["db"].restart_count, 2);
    drop(ch.commands);
    task.await.unwrap().unwrap();
    assert!(rx.recv().await.is_none());
}

fn fingerprint(id: &str, pid: u32) -> anvil_sys::LockRecord {
    anvil_sys::LockRecord {
        service_id: id.into(),
        pid,
        pgid: pid,
        start_time_secs: pid.into(),
        exe_name: "worker".into(),
    }
}

#[tokio::test(start_paused = true)]
async fn shutdown_waits_for_each_reverse_layer_and_coalesces_duplicate_commands() {
    let (actor, mut ch, mut rx) = configured(
        "
  db:
    runtime: {type: native, cmd: db, grace_period_ms: 111}
  api:
    depends_on: [db]
    runtime: {type: native, cmd: api, grace_period_ms: 222}
  web:
    depends_on: [api]
    runtime: {type: native, cmd: web, grace_period_ms: 333}",
    );
    let dir = tempfile::tempdir().unwrap();
    let store = WorkspacePersistence::with_root(dir.path(), "test").unwrap();
    let locks = anvil_sys::LockfileStore::with_dir(dir.path().join("run"));
    let task = tokio::spawn(actor.with_crash_persistence(store.clone(), 2).run());
    command(&ch, EngineCommand::StartWorkspace).await;
    let mut exits = BTreeMap::new();
    for (id, pid) in [("db", 11), ("api", 22), ("web", 33)] {
        let spawn = Spawn::next(&mut rx).await;
        assert_eq!(spawn.id, id);
        store.record_native(fingerprint(id, pid)).await.unwrap();
        exits.insert(id, spawn.created_as(pid));
    }
    state(&mut ch, "web", "Healthy").await;
    command(&ch, EngineCommand::Shutdown).await;
    command(&ch, EngineCommand::Shutdown).await;
    command(&ch, EngineCommand::Restart("api".into())).await;
    for (id, pid, grace) in [("web", 33, 333), ("api", 22, 222), ("db", 11, 111)] {
        let Some(Request::Stop(RuntimeIdentity::NativeProcess { pid: actual, .. }, period, ack)) =
            rx.recv().await
        else {
            panic!("expected stop for {id}");
        };
        assert_eq!((actual, period), (pid, Duration::from_millis(grace)));
        ack.send(Ok(())).unwrap();
        // Stop returned, but this instance has not delivered its exit yet.
        assert!(tokio::time::timeout(Duration::from_millis(1), rx.recv())
            .await
            .is_err());
        assert!(locks
            .load_workspace("test")
            .unwrap()
            .unwrap()
            .processes
            .contains(&fingerprint(id, pid)));
        finished(exits.remove(id).unwrap());
    }
    task.await.unwrap().unwrap();
    assert!(rx.recv().await.is_none());
    assert!(locks.load_workspace("test").unwrap().is_none());
    assert!(ch
        .snapshots
        .borrow()
        .services
        .values()
        .all(|s| matches!(s.state, ServiceState::Stopped { .. })));
}

#[tokio::test]
async fn shutdown_flushes_full_log_before_closing_channels_under_ui_backpressure() {
    let dir = tempfile::tempdir().unwrap();
    let store = WorkspacePersistence::with_root(dir.path(), "test").unwrap();
    let (actor, mut ch, mut rx) = configured(DB_AND_WORKER);
    for _ in 0..ch.logs.max_capacity() {
        actor
            .logs
            .try_send(LogBatch {
                service_id: "worker".into(),
                lines: vec!["busy".into()],
            })
            .unwrap();
    }
    let (input, logs) = mpsc::channel(4);
    let (complete, full) = mpsc::channel(4);
    let collector = actor.service_log_ingestor("db".into(), complete);
    let (done, drained) = oneshot::channel();
    let collecting = tokio::spawn(async move {
        assert!(done.send(collector.run(logs).await).is_ok());
    });
    let (release, gate) = oneshot::channel();
    let (saved, log_written) = oneshot::channel();
    let disk = store.clone();
    let writer = tokio::spawn(async move {
        gate.await.unwrap();
        let result = disk
            .write_service_log("db", full)
            .await
            .map_err(|_| ExecutionError::LogWrite);
        saved
            .send(
                result
                    .as_ref()
                    .map(|_| ())
                    .map_err(|_| ExecutionError::LogWrite),
            )
            .unwrap();
        result.unwrap()
    });
    let task = tokio::spawn(actor.with_crash_persistence(store, 2).run());
    let spawn = start_named(&ch, &mut rx, "db").await;
    let (mut started, exit) = instance();
    started.drained = drained;
    started.log_written = log_written;
    assert!(spawn.reply.send(Ok(started)).is_ok());
    state(&mut ch, "db", "Healthy").await;
    command(&ch, EngineCommand::Shutdown).await;
    let (_, ack) = stop_request(&mut rx).await;
    ack.send(Ok(())).unwrap();
    finished(exit);
    send_record(&input, "penultimate [REDACTED]").await;
    send_record(&input, "final output").await;
    drop(input);
    collecting.await.unwrap();
    assert!(!task.is_finished());
    assert!(!ch.commands.is_closed());
    assert!(!ch.logs.is_closed());
    assert!(ch.snapshots.has_changed().is_ok());
    release.send(()).unwrap();
    task.await.unwrap().unwrap();
    assert!(ch.commands.is_closed());
    assert!(ch.logs.is_closed());
    assert!(ch.snapshots.has_changed().is_err());
    assert_eq!(ch.logs.len(), ch.logs.max_capacity());
    let content = tokio::fs::read_to_string(writer.await.unwrap())
        .await
        .unwrap();
    let rows: Vec<_> = content.lines().collect();
    assert_eq!(rows.len(), 2);
    assert!(rows[0].ends_with("penultimate [REDACTED]"));
    assert!(rows[1].ends_with("final output"));
}

#[tokio::test]
async fn shutdown_preserves_replacement_lock_and_reports_lost_writer() {
    let dir = tempfile::tempdir().unwrap();
    let store = WorkspacePersistence::with_root(dir.path(), "test").unwrap();
    let (actor, mut ch, mut rx) = configured(DB_AND_WORKER);
    let task = tokio::spawn(actor.with_crash_persistence(store.clone(), 2).run());
    let db = start_named(&ch, &mut rx, "db").await;
    let (mut started, exit) = instance();
    let (saved, log_written) = oneshot::channel();
    started.log_written = log_written;
    assert!(db.reply.send(Ok(started)).is_ok());
    state(&mut ch, "db", "Healthy").await;
    command(&ch, EngineCommand::Shutdown).await;
    let (_, ack) = stop_request(&mut rx).await;
    let replacement = fingerprint("db", 42); // Same PID/PGID, different start time.
    store.record_native(replacement.clone()).await.unwrap();
    finished(exit);
    ack.send(Ok(())).unwrap();
    drop(saved);
    assert!(matches!(task.await.unwrap(), Err(ExecutionError::LogWrite)));
    let locks = anvil_sys::LockfileStore::with_dir(dir.path().join("run"));
    assert_eq!(
        locks.load_workspace("test").unwrap().unwrap().processes,
        [replacement]
    );
}

#[tokio::test]
async fn shutdown_cancels_pending_probe_before_its_stop_layer() {
    let (actor, mut ch, mut rx) = configured(
        "
  db:
    runtime: {type: native, cmd: db}
  web:
    depends_on: [db]
    runtime: {type: native, cmd: web}
  monitor:
    runtime: {type: docker_container, image: monitor}
    readiness_probe: {type: docker_health}
  waiting:
    depends_on: [monitor]
    runtime: {type: native, cmd: waiting}",
    );
    let task = tokio::spawn(actor.run());
    let db = start_named(&ch, &mut rx, "db").await.created();
    state(&mut ch, "db", "Healthy").await;
    let web = start_named(&ch, &mut rx, "web").await.created();
    state(&mut ch, "web", "Healthy").await;
    let monitor = start_named(&ch, &mut rx, "monitor").await.created();
    let Some(Request::Health(_, mut in_flight)) = rx.recv().await else {
        panic!("expected probe")
    };
    command(&ch, EngineCommand::Start("waiting".into())).await;
    state(&mut ch, "waiting", "WaitingDeps").await;
    command(&ch, EngineCommand::Shutdown).await;
    in_flight.closed().await;
    assert_eq!(
        state(&mut ch, "waiting", "Stopped").await,
        ServiceState::Stopped { exit_code: None }
    );
    let (identity, ack) = stop_request(&mut rx).await;
    assert!(
        matches!(identity, RuntimeIdentity::DockerContainer { container_name, .. } if container_name == "web")
    );
    assert!(rx.try_recv().is_err());
    ack.send(Ok(())).unwrap();
    finished(web);
    // Both roots can receive stop before either acknowledges.
    let mut roots = BTreeMap::from([("db".to_string(), db), ("monitor".to_string(), monitor)]);
    let a = stop_request(&mut rx).await;
    let b = stop_request(&mut rx).await;
    for (identity, ack) in [a, b] {
        let RuntimeIdentity::DockerContainer { container_name, .. } = identity else {
            panic!("expected container")
        };
        ack.send(Ok(())).unwrap();
        finished(roots.remove(&container_name).unwrap());
    }
    task.await.unwrap().unwrap();
    assert!(rx.recv().await.is_none());
}

#[tokio::test]
async fn resolve_port_conflict_ignores_non_conflicting_services_and_retries_conflict() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (actor, mut ch, mut rx) = configured(&format!(
        "  db:\n    runtime: {{type: native, cmd: db}}\n    port: {port}"
    ));
    let task = tokio::spawn(actor.run());

    ch.snapshots.borrow_and_update();
    command(&ch, EngineCommand::ResolvePortConflict("db".into())).await;
    drop(
        ch.commands
            .reserve_many(ch.commands.max_capacity())
            .await
            .unwrap(),
    );
    assert!(!ch.snapshots.has_changed().unwrap());

    command(&ch, EngineCommand::StartWorkspace).await;
    state(&mut ch, "db", "PortConflict").await;
    assert!(rx.try_recv().is_err());

    // Safe self-PID guard keeps the test runner alive and re-reports the conflict.
    command(&ch, EngineCommand::ResolvePortConflict("db".into())).await;
    ch.snapshots.changed().await.unwrap();
    state(&mut ch, "db", "PortConflict").await;
    assert!(rx.try_recv().is_err());

    drop(listener);
    let mut spawn = None;
    for _ in 0..10 {
        command(&ch, EngineCommand::ResolvePortConflict("db".into())).await;
        tokio::select! {
            next = Spawn::next(&mut rx) => {
                spawn = Some(next);
                break;
            }
            changed = ch.snapshots.changed() => {
                changed.unwrap();
                let _ = ch.snapshots.borrow_and_update();
            }
        }
    }
    let exit = spawn.expect("service should start once port is free").created();
    state(&mut ch, "db", "Healthy").await;
    finished(exit);
    drop(ch.commands);
    task.await.unwrap().unwrap();
}
