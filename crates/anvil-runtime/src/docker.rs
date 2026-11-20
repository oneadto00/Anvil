//! Docker Engine lifecycle operations and the Compose CLI bridge.

use crate::{ExitStatusEvent, RawLogLine, RuntimeError, RuntimeExecutor, StreamSource};
use anvil_core::{
    probe::{ContainerHealthInspector, ContainerHealthStatus},
    CoreError, RuntimeConfig, RuntimeIdentity, ServiceConfig,
};
use bollard::{
    container::{
        Config, CreateContainerOptions, LogOutput, LogsOptions, StartContainerOptions,
        StopContainerOptions, WaitContainerOptions,
    },
    errors::Error as DockerError,
    models::{
        ContainerInspectResponse, Health, HealthStatusEnum, HostConfig, PortBinding, PortMap,
    },
    Docker,
};
use chrono::Local;
use futures_util::{Stream, StreamExt};
use std::{
    borrow::Cow,
    collections::HashMap,
    fmt,
    net::IpAddr,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    process::Command,
    sync::{mpsc, oneshot},
};
use zeroize::{Zeroize, Zeroizing};

type Environment = HashMap<String, Zeroizing<String>>;

/// Executes standalone and Compose services on a local Docker engine.
#[derive(Clone)]
pub struct DockerContainerExecutor {
    docker: Docker,
    project: String,
    workspace_root: Option<PathBuf>,
}

impl fmt::Debug for DockerContainerExecutor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DockerContainerExecutor")
            .field("project", &self.project)
            .field("workspace_root", &self.workspace_root)
            .finish_non_exhaustive()
    }
}

impl DockerContainerExecutor {
    /// Opens the default local Docker socket or named pipe.
    pub fn connect_local(
        project_name: impl Into<String>,
        workspace_root: Option<PathBuf>,
    ) -> Result<Self, RuntimeError> {
        let docker =
            Docker::connect_with_local_defaults().map_err(|e| docker_error("connect", e))?;
        Ok(Self::with_client(docker, project_name, workspace_root))
    }

    /// Uses an existing Engine client. Compose's CLI must address the same engine.
    pub fn with_client(
        docker: Docker,
        project_name: impl Into<String>,
        workspace_root: Option<PathBuf>,
    ) -> Self {
        Self {
            docker,
            project: project_name.into(),
            workspace_root,
        }
    }

    fn container_name(&self, service_id: &str, name: Option<&str>) -> String {
        name.map(str::to_owned)
            .unwrap_or_else(|| format!("anvil-{}-{service_id}", self.project))
    }

    async fn start_standalone(
        &self,
        name: &str,
        config: Config<Cow<'_, str>>,
        sensitive: &mut Vec<Zeroizing<String>>,
    ) -> Result<String, RuntimeError> {
        match self.docker.inspect_container(name, None).await {
            Ok(mut existing) => {
                let id = existing
                    .id
                    .take()
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| RuntimeError::MissingContainerIdentity(name.to_owned()))?;
                if existing.state.as_ref().and_then(|s| s.running) == Some(true) {
                    sensitive.extend(inspected_values(&mut existing));
                    return Ok(id);
                }
                // Use the inspected ID and a non-forced removal in case another caller restarted it.
                match self.docker.remove_container(&id, None).await {
                    Ok(())
                    | Err(DockerError::DockerResponseServerError {
                        status_code: 404, ..
                    }) => {}
                    Err(e) => return Err(docker_error("remove stale container", e)),
                }
            }
            Err(DockerError::DockerResponseServerError {
                status_code: 404, ..
            }) => {}
            Err(e) => return Err(docker_error("inspect container", e)),
        }
        let options = CreateContainerOptions {
            name,
            platform: None,
        };
        let id = self
            .docker
            .create_container(Some(options), config)
            .await
            .map_err(|e| docker_error("create container", e))?
            .id;
        if let Err(e) = self
            .docker
            .start_container(&id, None::<StartContainerOptions<String>>)
            .await
        {
            let _ = self.docker.remove_container(&id, None).await;
            return Err(docker_error("start container", e));
        }
        Ok(id)
    }

    fn compose(&self, file: &Path, env: &Environment) -> Command {
        let mut cmd = Command::new("docker");
        cmd.args(["compose", "-f"])
            .arg(file)
            .envs(env.iter().map(|(key, value)| (key, value.as_str())))
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stderr(Stdio::null());
        if let Some(root) = &self.workspace_root {
            cmd.current_dir(root);
        }
        cmd
    }

    async fn start_compose(
        &self,
        file: &Path,
        service: &str,
        env: &Environment,
        sensitive: &mut Vec<Zeroizing<String>>,
    ) -> Result<(String, String), RuntimeError> {
        let status = self
            .compose(file, env)
            .args(["up", "-d", "--", service])
            .stdout(Stdio::null())
            .status()
            .await?;
        if !status.success() {
            return Err(RuntimeError::ComposeFailed {
                operation: "up",
                status,
            });
        }
        // Include exited containers so even a short-lived service gets an exit watcher.
        let output = self
            .compose(file, env)
            .args(["ps", "-q", "--all", "--", service])
            .output()
            .await?;
        if !output.status.success() {
            return Err(RuntimeError::ComposeFailed {
                operation: "ps",
                status: output.status,
            });
        }
        let id = compose_id(&output.stdout, service)?;
        let mut container = self
            .docker
            .inspect_container(id, None)
            .await
            .map_err(|e| docker_error("inspect Compose container", e))?;
        sensitive.extend(inspected_values(&mut container));
        let name = container
            .name
            .as_deref()
            .unwrap_or(service)
            .trim_start_matches('/');
        Ok((
            container.id.unwrap_or_else(|| id.to_owned()),
            name.to_owned(),
        ))
    }
}

fn compose_id<'a>(stdout: &'a [u8], service: &str) -> Result<&'a str, RuntimeError> {
    let mut ids = std::str::from_utf8(stdout)
        .unwrap_or_default()
        .split_whitespace();
    match (ids.next(), ids.next()) {
        (Some(id), None) if id.bytes().all(|b| b.is_ascii_hexdigit()) => Ok(id),
        _ => Err(RuntimeError::MissingContainerIdentity(service.to_owned())),
    }
}

fn docker_error(operation: &'static str, error: DockerError) -> RuntimeError {
    // Do not propagate untrusted daemon response bodies or JSON fragments to crash logs.
    let reason = match error {
        DockerError::DockerResponseServerError { status_code, .. } => {
            return RuntimeError::DockerResponse {
                operation,
                status: status_code,
            }
        }
        DockerError::JsonDataError { .. } | DockerError::JsonSerdeError { .. } => {
            "invalid Engine response".to_owned()
        }
        DockerError::DockerStreamError { .. } => "Engine stream failed".to_owned(),
        other => other.to_string(),
    };
    RuntimeError::DockerClient { operation, reason }
}

// The exposed-port key uses the container port and protocol. The binding uses the host port and IP.
fn parse_port_binding(spec: &str) -> Result<(String, PortBinding), RuntimeError> {
    let invalid = || RuntimeError::InvalidPortBinding(spec.to_owned());
    let (mapping, protocol) = spec.split_once('/').unwrap_or((spec, "tcp"));
    if !matches!(protocol, "tcp" | "udp" | "sctp") {
        return Err(invalid());
    }
    let (host, target) = mapping.rsplit_once(':').ok_or_else(invalid)?;
    let (host_ip, port) = match host.rsplit_once(':') {
        Some((ip, port)) => {
            let ip = ip
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(ip);
            (
                Some(ip.parse::<IpAddr>().map_err(|_| invalid())?.to_string()),
                port,
            )
        }
        None => (None, host),
    };
    let parse_port = |s: &str| {
        s.parse::<u16>()
            .ok()
            .filter(|&p| p != 0 && s.bytes().all(|b| b.is_ascii_digit()))
            .ok_or_else(invalid)
    };
    Ok((
        format!("{}/{protocol}", parse_port(target)?),
        PortBinding {
            host_ip,
            host_port: Some(parse_port(port)?.to_string()),
        },
    ))
}

fn bind_spec(spec: &str, root: Option<&Path>) -> Result<String, RuntimeError> {
    if let Some((source, target)) = spec.split_once(':') {
        let source = Path::new(source);
        if source.starts_with(".") || source.starts_with("..") {
            let path = std::path::absolute(root.unwrap_or(Path::new(".")).join(source))?;
            return Ok(format!("{}:{target}", path.display()));
        }
    }
    Ok(spec.to_owned())
}

fn build_config<'a>(
    image: &'a str,
    command: Option<&'a [String]>,
    volumes: &[String],
    ports: &[String],
    env: &'a [String],
    root: Option<&Path>,
) -> Result<Config<Cow<'a, str>>, RuntimeError> {
    let mut exposed = HashMap::new();
    let mut bindings = PortMap::new();
    for spec in ports {
        let (port, binding) = parse_port_binding(spec)?;
        exposed.insert(Cow::Owned(port.clone()), HashMap::new());
        bindings
            .entry(port)
            .or_default()
            .get_or_insert_with(Vec::new)
            .push(binding);
    }
    let binds = volumes
        .iter()
        .map(|v| bind_spec(v, root))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Config {
        image: Some(Cow::Borrowed(image)),
        cmd: command.map(|args| args.iter().map(|s| Cow::Borrowed(s.as_str())).collect()),
        env: Some(env.iter().map(|s| Cow::Borrowed(s.as_str())).collect()),
        exposed_ports: Some(exposed),
        host_config: Some(HostConfig {
            binds: Some(binds),
            port_bindings: Some(bindings),
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn formatted_env(env: &Environment) -> Zeroizing<Vec<String>> {
    Zeroizing::new(
        env.iter()
            .map(|(k, v)| format!("{k}={}", v.as_str()))
            .collect(),
    )
}

fn inspected_values(container: &mut ContainerInspectResponse) -> Vec<Zeroizing<String>> {
    let vars = container
        .config
        .as_mut()
        .and_then(|c| c.env.take())
        .unwrap_or_default();
    let vars = Zeroizing::new(vars);
    vars.iter()
        .filter_map(|entry| entry.split_once('='))
        .filter(|(_, v)| !v.is_empty())
        .map(|(_, v)| Zeroizing::new(v.to_owned()))
        .collect()
}

fn contains_secret(text: &str, values: &[Zeroizing<String>]) -> bool {
    values.iter().any(|v| {
        v.lines()
            .any(|part| !part.is_empty() && text.contains(part))
    })
}

fn map_docker_health_status(
    health: Option<&Health>,
    sensitive: &[Zeroizing<String>],
) -> ContainerHealthStatus {
    match health.and_then(|h| h.status) {
        Some(HealthStatusEnum::HEALTHY) => ContainerHealthStatus::Healthy,
        Some(HealthStatusEnum::STARTING) => ContainerHealthStatus::Starting,
        Some(HealthStatusEnum::UNHEALTHY) => {
            let output = health
                .and_then(|h| h.log.as_ref())
                .and_then(|log| {
                    log.iter()
                        .rev()
                        .filter(|r| r.exit_code != Some(0))
                        .find_map(|r| r.output.as_deref().filter(|s| !s.trim().is_empty()))
                })
                .unwrap_or("container health check failed")
                .trim();
            ContainerHealthStatus::Unhealthy(if contains_secret(output, sensitive) {
                "[REDACTED]".into()
            } else {
                output.to_owned()
            })
        }
        _ => ContainerHealthStatus::None,
    }
}

#[async_trait::async_trait]
impl ContainerHealthInspector for DockerContainerExecutor {
    async fn inspect_health(
        &self,
        container_ref: &str,
    ) -> Result<ContainerHealthStatus, CoreError> {
        let mut container = self
            .docker
            .inspect_container(container_ref, None)
            .await
            .map_err(|e| CoreError::ProbeFailed {
                reason: docker_error("inspect health", e).to_string(),
            })?;
        let sensitive = inspected_values(&mut container);
        Ok(map_docker_health_status(
            container.state.as_ref().and_then(|s| s.health.as_ref()),
            &sensitive,
        ))
    }
}

#[async_trait::async_trait]
impl RuntimeExecutor for DockerContainerExecutor {
    async fn spawn(
        &self,
        service_id: &str,
        config: &ServiceConfig,
        env: &Environment,
        log_tx: mpsc::Sender<RawLogLine>,
    ) -> anyhow::Result<(RuntimeIdentity, oneshot::Receiver<ExitStatusEvent>)> {
        let mut sensitive: Vec<_> = env.values().filter(|v| !v.is_empty()).cloned().collect();
        let (id, name) = match &config.runtime {
            RuntimeConfig::DockerContainer {
                image,
                container_name,
                command,
                volumes,
                ports,
            } => {
                let name = self.container_name(service_id, container_name.as_deref());
                let entries = formatted_env(env);
                let config = build_config(
                    image,
                    command.as_deref(),
                    volumes,
                    ports,
                    &entries,
                    self.workspace_root.as_deref(),
                )?;
                (
                    self.start_standalone(&name, config, &mut sensitive).await?,
                    name,
                )
            }
            RuntimeConfig::DockerCompose {
                compose_file,
                service_name,
            } => {
                self.start_compose(compose_file, service_name, env, &mut sensitive)
                    .await?
            }
            RuntimeConfig::Native { .. } => return Err(RuntimeError::UnsupportedRuntime.into()),
        };

        let docker = self.docker.clone();
        let log_id = id.clone();
        let service = service_id.to_owned();
        tokio::spawn(async move {
            let options = LogsOptions {
                follow: true,
                stdout: true,
                stderr: true,
                tail: "all",
                ..Default::default()
            };
            let logs = docker.logs(&log_id, Some(options));
            tokio::select! {
                _ = log_tx.closed() => {},
                _ = forward_logs(logs, &service, &log_tx, &sensitive) => {},
            }
        });
        let (mut exit_tx, exit_rx) = oneshot::channel();
        let docker = self.docker.clone();
        let wait_id = id.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = exit_tx.closed() => {},
                event = wait_for_exit(&docker, &wait_id) => {
                    if let Some(event) = event { let _ = exit_tx.send(event); }
                }
            }
        });
        Ok((
            RuntimeIdentity::DockerContainer {
                container_id: id,
                container_name: name,
            },
            exit_rx,
        ))
    }

    async fn stop(&self, identity: &RuntimeIdentity, grace: Duration) -> anyhow::Result<()> {
        let RuntimeIdentity::DockerContainer { container_id, .. } = identity else {
            return Err(RuntimeError::UnsupportedRuntime.into());
        };
        let seconds = grace
            .as_secs()
            .saturating_add(u64::from(grace.subsec_nanos() != 0));
        let options = StopContainerOptions {
            t: i64::try_from(seconds).unwrap_or(i64::MAX),
        };
        let docker = self
            .docker
            .clone()
            .with_timeout(self.docker.timeout().saturating_add(grace));
        match docker.stop_container(container_id, Some(options)).await {
            Ok(())
            | Err(DockerError::DockerResponseServerError {
                status_code: 304 | 404,
                ..
            }) => Ok(()),
            Err(e) => Err(docker_error("stop container", e).into()),
        }
    }

    async fn is_alive(&self, identity: &RuntimeIdentity) -> bool {
        let RuntimeIdentity::DockerContainer { container_id, .. } = identity else {
            return false;
        };
        self.docker
            .inspect_container(container_id, None)
            .await
            .ok()
            .and_then(|c| c.state?.running)
            == Some(true)
    }
}

/// Reconcile a wait timeout or dropped connection with the current state before retrying.
async fn wait_for_exit(docker: &Docker, id: &str) -> Option<ExitStatusEvent> {
    loop {
        let waited = docker
            .wait_container(id, None::<WaitContainerOptions<String>>)
            .next()
            .await;
        let code = match waited {
            Some(Ok(result)) => Some(result.status_code),
            Some(Err(DockerError::DockerContainerWaitError { code, .. })) => Some(code),
            _ => None,
        };
        let state = match docker.inspect_container(id, None).await {
            Ok(c) => c.state,
            Err(DockerError::DockerResponseServerError {
                status_code: 404, ..
            }) if code.is_none() => return None,
            Err(_) => None,
        };
        let stopped = state.as_ref().filter(|s| s.running == Some(false));
        if let Some(exit_code) = code.or_else(|| stopped.and_then(|s| s.exit_code)) {
            return Some(ExitStatusEvent::DockerDie {
                container_id: id.to_owned(),
                exit_code,
                oom_killed: state.and_then(|s| s.oom_killed).unwrap_or(false),
            });
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn forward_logs(
    mut logs: impl Stream<Item = Result<LogOutput, DockerError>> + Unpin,
    service: &str,
    tx: &mpsc::Sender<RawLogLine>,
    sensitive: &[Zeroizing<String>],
) {
    let mut stdout = Zeroizing::new(Vec::new());
    let mut stderr = Zeroizing::new(Vec::new());
    while let Some(Ok(frame)) = logs.next().await {
        let (pending, source, message) = match frame {
            LogOutput::StdOut { message } | LogOutput::Console { message } => {
                (&mut stdout, StreamSource::Stdout, message)
            }
            LogOutput::StdErr { message } => (&mut stderr, StreamSource::Stderr, message),
            LogOutput::StdIn { .. } => continue,
        };
        for chunk in message.split_inclusive(|&b| b == b'\n') {
            if let Some(line) = chunk.strip_suffix(b"\n") {
                pending.extend_from_slice(line);
                if !send_line(
                    pending.strip_suffix(b"\r").unwrap_or(pending),
                    source,
                    service,
                    tx,
                    sensitive,
                )
                .await
                {
                    return;
                }
                pending.zeroize();
            } else {
                pending.extend_from_slice(chunk);
            }
        }
    }
    for (pending, source) in [
        (stdout, StreamSource::Stdout),
        (stderr, StreamSource::Stderr),
    ] {
        if !pending.is_empty() {
            send_line(&pending, source, service, tx, sensitive).await;
        }
    }
}

async fn send_line(
    bytes: &[u8],
    source: StreamSource,
    service: &str,
    tx: &mpsc::Sender<RawLogLine>,
    sensitive: &[Zeroizing<String>],
) -> bool {
    let text = String::from_utf8_lossy(bytes);
    let content = if contains_secret(&text, sensitive) {
        "[REDACTED]".to_owned()
    } else {
        text.into_owned()
    };
    tx.send(RawLogLine {
        service_id: service.to_owned(),
        source,
        content,
        timestamp: Local::now(),
    })
    .await
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::{models::HealthcheckResult, API_DEFAULT_VERSION};

    fn executor(address: &str) -> DockerContainerExecutor {
        let client = Docker::connect_with_http(address, 2, API_DEFAULT_VERSION).unwrap();
        DockerContainerExecutor::with_client(client, "demo", Some("workspace".into()))
    }

    #[test]
    fn port_bindings_validate_host_target_and_protocol() {
        for (spec, key, ip, port) in [
            ("5432:5432", "5432/tcp", None, "5432"),
            ("127.0.0.1:8080:80/udp", "80/udp", Some("127.0.0.1"), "8080"),
            ("8080:80/tcp", "80/tcp", None, "8080"),
            ("[::1]:9000:80", "80/tcp", Some("::1"), "9000"),
        ] {
            let (exposed, binding) = parse_port_binding(spec).unwrap();
            assert_eq!(exposed, key);
            assert_eq!(binding.host_ip.as_deref(), ip);
            assert_eq!(binding.host_port.as_deref(), Some(port));
        }
        for spec in [
            "",
            "80",
            ":80",
            "80:",
            "0:80",
            "80:65536",
            "bad:80:80",
            "80:80/http",
            "80:80/udp/udp",
        ] {
            assert!(
                matches!(
                    parse_port_binding(spec),
                    Err(RuntimeError::InvalidPortBinding(_))
                ),
                "{spec}"
            );
        }
    }

    #[test]
    fn builds_container_config_and_resolves_names() {
        let executor = executor("http://127.0.0.1:1");
        assert_eq!(executor.container_name("db", None), "anvil-demo-db");
        assert_eq!(executor.container_name("db", Some("custom")), "custom");

        let env = HashMap::from([("TOKEN".into(), Zeroizing::new("test=secret".into()))]);
        let entries = formatted_env(&env);
        let root = tempfile::tempdir().unwrap();
        let config = build_config(
            "db:1",
            Some(&["serve".to_owned()]),
            &["data:/data".into(), "./cache:/cache:ro".into()],
            &["8080:80".into(), "127.0.0.1:8081:80/tcp".into()],
            &entries,
            Some(root.path()),
        )
        .map(|c| {
            assert_eq!(c.image.as_deref(), Some("db:1"));
            assert_eq!(c.cmd.unwrap(), ["serve"]);
            assert_eq!(c.env.unwrap(), ["TOKEN=test=secret"]);
            assert!(c.exposed_ports.unwrap()["80/tcp"].is_empty());
            c.host_config.unwrap()
        })
        .unwrap();
        let binds = config.binds.unwrap();
        assert_eq!(binds[0], "data:/data");
        let (src, dest) = binds[1].rsplit_once(":/cache").unwrap();
        assert_eq!(Path::new(src), root.path().join("cache"));
        assert_eq!(dest, ":ro");
        let ports = config.port_bindings.unwrap();
        let bindings = ports["80/tcp"].as_ref().unwrap();
        assert_eq!(bindings.len(), 2);
        assert_eq!(bindings[0].host_port.as_deref(), Some("8080"));
        assert_eq!(bindings[1].host_ip.as_deref(), Some("127.0.0.1"));
        assert!(!format!("{executor:?}").contains("test=secret"));
    }

    #[test]
    fn maps_health_and_protects_failure_output() {
        use HealthStatusEnum::*;
        let log = vec![
            HealthcheckResult {
                exit_code: Some(1),
                output: Some("first".into()),
                ..Default::default()
            },
            HealthcheckResult {
                exit_code: Some(2),
                output: Some(" latest failure\n".into()),
                ..Default::default()
            },
        ];
        let mut health = Health {
            log: Some(log),
            ..Default::default()
        };
        for (status, expected) in [
            (None, ContainerHealthStatus::None),
            (Some(NONE), ContainerHealthStatus::None),
            (Some(EMPTY), ContainerHealthStatus::None),
            (Some(HEALTHY), ContainerHealthStatus::Healthy),
            (Some(STARTING), ContainerHealthStatus::Starting),
            (
                Some(UNHEALTHY),
                ContainerHealthStatus::Unhealthy("latest failure".into()),
            ),
        ] {
            health.status = status;
            assert_eq!(map_docker_health_status(Some(&health), &[]), expected);
        }
        assert_eq!(
            map_docker_health_status(None, &[]),
            ContainerHealthStatus::None
        );
        assert_eq!(
            map_docker_health_status(Some(&health), &[Zeroizing::new("failure".into())]),
            ContainerHealthStatus::Unhealthy("[REDACTED]".into())
        );
    }

    #[test]
    fn compose_uses_workspace_environment_and_one_id() {
        let executor = executor("http://127.0.0.1:1");
        let env = HashMap::from([("TOKEN".into(), Zeroizing::new("secret".into()))]);
        let command = executor.compose(Path::new("infra/compose file.yml"), &env);
        let cmd = command.as_std();
        assert_eq!(cmd.get_program(), "docker");
        assert_eq!(
            cmd.get_args().collect::<Vec<_>>(),
            ["compose", "-f", "infra/compose file.yml"]
        );
        assert_eq!(cmd.get_current_dir(), Some(Path::new("workspace")));
        assert!(cmd
            .get_envs()
            .any(|(k, v)| k == "TOKEN" && v == Some("secret".as_ref())));
        assert_eq!(compose_id(b" abc123\r\n", "db").unwrap(), "abc123");
        for output in [b"".as_slice(), b"abc123\ndef456", b"not-an-id"] {
            assert!(compose_id(output, "db").is_err());
        }
    }

    #[tokio::test]
    async fn logs_join_fragmented_lines_before_redacting_each_stream() {
        let frames = [
            LogOutput::StdOut {
                message: "ready\r\npass".into(),
            },
            LogOutput::StdErr {
                message: "warn\nlast".into(),
            },
            LogOutput::StdOut {
                message: "word\n\n".into(),
            },
        ];
        let (tx, mut rx) = mpsc::channel(8);
        forward_logs(
            futures_util::stream::iter(frames.map(Ok)),
            "db",
            &tx,
            &[Zeroizing::new("password".into())],
        )
        .await;
        drop(tx);
        let mut lines = Vec::new();
        while let Some(line) = rx.recv().await {
            assert_eq!(line.service_id, "db");
            lines.push((line.source, line.content));
        }
        use StreamSource::*;
        assert_eq!(
            lines,
            [
                (Stdout, "ready".into()),
                (Stderr, "warn".into()),
                (Stdout, "[REDACTED]".into()),
                (Stdout, "".into()),
                (Stderr, "last".into())
            ]
        );
    }

    #[tokio::test]
    async fn recreates_stale_container_and_reports_nonzero_oom_exit() {
        use tokio::{
            io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
            net::TcpListener,
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let executor = executor(&format!("http://{}", listener.local_addr().unwrap()));
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for _ in 0..9 {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                let request = line.trim_end().to_owned();
                let mut len = 0;
                loop {
                    line.clear();
                    stream.read_line(&mut line).await.unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(n) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = n.trim().parse().unwrap();
                    }
                }
                stream.read_exact(&mut vec![0; len]).await.unwrap();
                let (status, body) = if request.contains("/anvil-demo-db/json") {
                    (200, r#"{"Id":"old","State":{"Running":false}}"#)
                } else if request.starts_with("DELETE") && request.contains("/containers/old ") {
                    (204, "")
                } else if request.contains("/containers/create?name=anvil-demo-db") {
                    (201, r#"{"Id":"new","Warnings":[]}"#)
                } else if request.contains("/new/start") || request.contains("/new/stop?t=1") {
                    (204, "")
                } else if request.contains("/new/logs?") {
                    (200, "")
                } else if request.contains("/new/wait") {
                    (200, "{\"StatusCode\":137}\n")
                } else if request.contains("/new/json") {
                    (
                        200,
                        r#"{"State":{"Running":false,"ExitCode":137,"OOMKilled":true}}"#,
                    )
                } else {
                    panic!("unexpected request {request}");
                };
                let response = format!("HTTP/1.1 {status} mock\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                stream
                    .get_mut()
                    .write_all(response.as_bytes())
                    .await
                    .unwrap();
                requests.push(request);
            }
            requests
        });
        let config = ServiceConfig {
            runtime: RuntimeConfig::DockerContainer {
                image: "fixture".into(),
                container_name: None,
                ports: vec![],
                volumes: vec![],
                command: None,
            },
            port: None,
            depends_on: vec![],
            env: Default::default(),
            readiness_probe: None,
            restart_policy: Default::default(),
        };
        let (tx, mut rx) = mpsc::channel(1);
        tokio::time::timeout(Duration::from_secs(10), async {
            let (identity, exited) = executor
                .spawn("db", &config, &Environment::new(), tx)
                .await
                .unwrap();
            assert_eq!(
                exited.await.unwrap(),
                ExitStatusEvent::DockerDie {
                    container_id: "new".into(),
                    exit_code: 137,
                    oom_killed: true
                }
            );
            assert!(rx.recv().await.is_none());
            assert!(!executor.is_alive(&identity).await);
            executor
                .stop(&identity, Duration::from_millis(100))
                .await
                .unwrap();
            let requests = server.await.unwrap();
            assert!(requests[1].starts_with("DELETE"));
            assert!(requests[2].contains("/create?"));
            assert!(requests[3].contains("/new/start"));
        })
        .await
        .unwrap();
    }
}
