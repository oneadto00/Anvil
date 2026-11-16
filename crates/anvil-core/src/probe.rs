//! Cancellable readiness checks for services during startup.

use crate::{CoreError, ReadinessProbeConfig};
use regex::Regex;
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{
    net::TcpStream,
    sync::{broadcast, watch},
    time::{self, Instant},
};

const NETWORK_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);
const DOCKER_INTERVAL: Duration = Duration::from_millis(500);

/// Health reported by the runtime for a single container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerHealthStatus {
    Healthy,
    Starting,
    Unhealthy(String),
    /// The container has no health check.
    None,
}

/// Runtime interface for inspecting a container by name or ID.
#[async_trait::async_trait]
pub trait ContainerHealthInspector: Send + Sync {
    /// Returns the latest health observation for the given container.
    async fn inspect_health(&self, container_ref: &str)
        -> Result<ContainerHealthStatus, CoreError>;
}

/// Terminal result of a readiness check. Attempts count polls started or log lines examined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    Ready { attempts: u32, elapsed: Duration },
    TimedOut { attempts: u32, last_error: String },
    Cancelled,
}

/// Runs a configured probe until ready, its overall deadline, or cancellation.
///
/// Supply a log subscription made before service startup for a log probe, or an inspector
/// and container name/ID for a Docker probe. Missing inputs, setup failures and a closed
/// log stream are terminal errors. Sending `true` or dropping the cancellation sender
/// interrupts both active attempts and waits between them.
pub async fn run_readiness_probe(
    config: &ReadinessProbeConfig,
    mut cancel: watch::Receiver<bool>,
    logs: Option<broadcast::Receiver<String>>,
    inspector: Option<Arc<dyn ContainerHealthInspector>>,
    container_ref: Option<&str>,
) -> Result<ProbeOutcome, CoreError> {
    let started = Instant::now();
    let timeout_ms = match config {
        ReadinessProbeConfig::Tcp { timeout_ms, .. }
        | ReadinessProbeConfig::Http { timeout_ms, .. }
        | ReadinessProbeConfig::LogRegex { timeout_ms, .. }
        | ReadinessProbeConfig::DockerHealth { timeout_ms } => *timeout_ms,
    };
    let mut attempts = 0;
    let mut last_error = "no probe attempt completed before the deadline".to_owned();

    let probe = async {
        match config {
            ReadinessProbeConfig::Tcp {
                host,
                port,
                interval_ms,
                ..
            } => {
                poll_until_ready(
                    Duration::from_millis(*interval_ms),
                    &mut attempts,
                    &mut last_error,
                    || async {
                        time::timeout(
                            NETWORK_ATTEMPT_TIMEOUT,
                            TcpStream::connect((host.as_str(), *port)),
                        )
                        .await
                        .map_err(|_| "TCP connection attempt timed out".to_owned())?
                        .map(|_| ())
                        .map_err(|err| format!("TCP connection failed: {err}"))
                    },
                )
                .await;
            }
            ReadinessProbeConfig::Http {
                url,
                expected_status,
                interval_ms,
                ..
            } => {
                let client = reqwest::Client::builder()
                    .timeout(NETWORK_ATTEMPT_TIMEOUT)
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .map_err(|err| probe_error(format!("could not build HTTP client: {err}")))?;
                poll_until_ready(
                    Duration::from_millis(*interval_ms),
                    &mut attempts,
                    &mut last_error,
                    || async {
                        let response =
                            client.get(url).send().await.map_err(|err| {
                                format!("HTTP request failed: {}", err.without_url())
                            })?;
                        let status = response.status().as_u16();
                        if status == *expected_status {
                            Ok(())
                        } else {
                            Err(format!(
                                "received HTTP {status}, expected {expected_status}"
                            ))
                        }
                    },
                )
                .await;
            }
            ReadinessProbeConfig::LogRegex { pattern, .. } => {
                let mut logs = logs.ok_or_else(|| probe_error("missing log subscription"))?;
                let regex = Regex::new(pattern)
                    .map_err(|err| probe_error(format!("invalid log pattern: {err}")))?;
                last_error = "no matching log line received".to_owned();
                loop {
                    match logs.recv().await {
                        Ok(line) => {
                            attempts = attempts.saturating_add(1);
                            if regex.is_match(&line) {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => {
                            return Err(probe_error("log stream closed before a match"));
                        }
                    }
                }
            }
            ReadinessProbeConfig::DockerHealth { .. } => {
                let inspector =
                    inspector.ok_or_else(|| probe_error("missing container health inspector"))?;
                let target = container_ref
                    .filter(|name| !name.trim().is_empty())
                    .ok_or_else(|| probe_error("missing container name or ID"))?;
                poll_until_ready(DOCKER_INTERVAL, &mut attempts, &mut last_error, || async {
                    match inspector.inspect_health(target).await {
                        Ok(ContainerHealthStatus::Healthy) => Ok(()),
                        Ok(ContainerHealthStatus::Starting) => {
                            Err("container is still starting".to_owned())
                        }
                        Ok(ContainerHealthStatus::Unhealthy(reason)) => {
                            Err(format!("container is unhealthy: {reason}"))
                        }
                        Ok(ContainerHealthStatus::None) => {
                            Err("container has no health check".to_owned())
                        }
                        Err(err) => Err(format!("container health inspection failed: {err}")),
                    }
                })
                .await;
            }
        }
        Ok(())
    };

    tokio::select! {
        biased;
        _ = cancel.wait_for(|flag| *flag) => Ok(ProbeOutcome::Cancelled),
        _ = time::sleep(Duration::from_millis(timeout_ms)) => Ok(ProbeOutcome::TimedOut { attempts, last_error }),
        result = probe => result.map(|()| ProbeOutcome::Ready { attempts, elapsed: started.elapsed() }),
    }
}

fn probe_error(reason: impl Into<String>) -> CoreError {
    CoreError::ProbeFailed {
        reason: reason.into(),
    }
}

async fn poll_until_ready<F: Future<Output = Result<(), String>>>(
    interval: Duration,
    attempts: &mut u32,
    last_error: &mut String,
    mut check: impl FnMut() -> F,
) {
    loop {
        let started = Instant::now();
        *attempts = attempts.saturating_add(1);
        match check().await {
            Ok(()) => return,
            Err(reason) => *last_error = reason,
        }
        time::sleep(interval.saturating_sub(started.elapsed())).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::{TcpListener, TcpSocket},
        sync::Notify,
    };

    fn reserved_socket() -> TcpSocket {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        socket
    }

    fn tcp_config(socket: &TcpSocket, timeout_ms: u64) -> ReadinessProbeConfig {
        ReadinessProbeConfig::Tcp {
            host: "127.0.0.1".to_owned(),
            port: socket.local_addr().unwrap().port(),
            interval_ms: 20,
            timeout_ms,
        }
    }

    #[tokio::test]
    async fn tcp_retries_until_listener_starts() {
        // Reserve the ephemeral port throughout the delay so parallel tests cannot claim it.
        let socket = reserved_socket();
        let config = tcp_config(&socket, 3000);
        let (_tx, cancel) = watch::channel(false);
        let (outcome, _listener) = tokio::join!(
            run_readiness_probe(&config, cancel, None, None, None),
            async move {
                time::sleep(Duration::from_millis(100)).await;
                socket.listen(1).unwrap()
            }
        );
        let outcome = outcome.unwrap();
        assert!(
            matches!(outcome, ProbeOutcome::Ready { attempts, elapsed }
                if attempts >= 1 && elapsed >= Duration::from_millis(100)),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn tcp_times_out_on_closed_port() {
        let socket = reserved_socket();
        let config = tcp_config(&socket, 100);
        drop(socket);
        let (_tx, cancel) = watch::channel(false);
        let outcome = run_readiness_probe(&config, cancel, None, None, None)
            .await
            .unwrap();
        assert!(
            matches!(outcome, ProbeOutcome::TimedOut { attempts, last_error }
            if attempts >= 1 && last_error.contains("TCP connection failed"))
        );
    }

    #[tokio::test]
    async fn http_retries_503_then_accepts_200() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = ReadinessProbeConfig::Http {
            url: format!("http://{}/health", listener.local_addr().unwrap()),
            expected_status: 200,
            interval_ms: 20,
            timeout_ms: 3000,
        };
        let server = tokio::spawn(async move {
            for response in [
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            ] {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut header = String::new();
                loop {
                    header.clear();
                    assert!(stream.read_line(&mut header).await.unwrap() > 0);
                    if header == "\r\n" {
                        break;
                    }
                }
                stream
                    .get_mut()
                    .write_all(response.as_bytes())
                    .await
                    .unwrap();
            }
        });
        let (_tx, cancel) = watch::channel(false);
        let outcome = run_readiness_probe(&config, cancel, None, None, None)
            .await
            .unwrap();
        assert!(
            matches!(outcome, ProbeOutcome::Ready { attempts: 2, .. }),
            "{outcome:?}"
        );
        server.await.unwrap();
    }

    fn log_config(timeout_ms: u64) -> ReadinessProbeConfig {
        ReadinessProbeConfig::LogRegex {
            pattern: r"Local:\s+http://localhost:3000".to_owned(),
            timeout_ms,
        }
    }

    #[tokio::test]
    async fn log_regex_matches_buffered_lines_after_lag() {
        let (tx, logs) = broadcast::channel(2);
        for line in ["starting", "compiling", "Local: http://localhost:3000"] {
            tx.send(line.to_owned()).unwrap();
        }
        let (_tx, cancel) = watch::channel(false);
        let outcome = run_readiness_probe(&log_config(1000), cancel, Some(logs), None, None)
            .await
            .unwrap();
        assert!(matches!(outcome, ProbeOutcome::Ready { attempts: 2, .. }));
    }

    #[tokio::test]
    async fn log_regex_times_out_without_a_match() {
        let (tx, logs) = broadcast::channel(2);
        tx.send("compiling".to_owned()).unwrap();
        let (_tx, cancel) = watch::channel(false);
        let outcome = run_readiness_probe(&log_config(50), cancel, Some(logs), None, None)
            .await
            .unwrap();
        assert!(
            matches!(outcome, ProbeOutcome::TimedOut { attempts: 1, last_error }
            if last_error.contains("no matching log line"))
        );
    }

    #[tokio::test]
    async fn closed_log_stream_reports_terminal_error() {
        let (tx, logs) = broadcast::channel(1);
        drop(tx);
        let (_tx, cancel) = watch::channel(false);
        let result = run_readiness_probe(&log_config(1000), cancel, Some(logs), None, None).await;
        assert!(
            matches!(result, Err(CoreError::ProbeFailed { reason }) if reason.contains("closed"))
        );
    }

    struct MockHealth {
        starting_polls: AtomicU32,
        final_status: ContainerHealthStatus,
    }

    #[async_trait::async_trait]
    impl ContainerHealthInspector for MockHealth {
        async fn inspect_health(&self, target: &str) -> Result<ContainerHealthStatus, CoreError> {
            assert_eq!(target, "db");
            let starting =
                self.starting_polls
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1));
            Ok(if starting.is_ok() {
                ContainerHealthStatus::Starting
            } else {
                self.final_status.clone()
            })
        }
    }

    async fn run_mock_health(
        starting_polls: u32,
        final_status: ContainerHealthStatus,
        timeout_ms: u64,
    ) -> ProbeOutcome {
        let inspector = Arc::new(MockHealth {
            starting_polls: AtomicU32::new(starting_polls),
            final_status,
        });
        let (_tx, cancel) = watch::channel(false);
        run_readiness_probe(
            &ReadinessProbeConfig::DockerHealth { timeout_ms },
            cancel,
            None,
            Some(inspector),
            Some("db"),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn docker_waits_for_healthy() {
        let outcome = run_mock_health(2, ContainerHealthStatus::Healthy, 3000).await;
        assert!(
            matches!(outcome, ProbeOutcome::Ready { attempts: 3, elapsed } if elapsed >= 2 * DOCKER_INTERVAL)
        );
    }

    #[tokio::test]
    async fn docker_timeout_preserves_last_observation() {
        for (status, reason) in [
            (
                ContainerHealthStatus::Unhealthy("exit code 1".into()),
                "exit code 1",
            ),
            (ContainerHealthStatus::Starting, "starting"),
            (ContainerHealthStatus::None, "no health check"),
        ] {
            let outcome = run_mock_health(0, status, 50).await;
            assert!(
                matches!(outcome, ProbeOutcome::TimedOut { attempts: 1, last_error } if last_error.contains(reason))
            );
        }
    }

    #[derive(Default)]
    struct StalledInspection(Notify);

    #[async_trait::async_trait]
    impl ContainerHealthInspector for StalledInspection {
        async fn inspect_health(&self, _: &str) -> Result<ContainerHealthStatus, CoreError> {
            self.0.notify_one();
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn cancellation_interrupts_in_flight_inspection() {
        for drop_sender in [false, true] {
            let inspector = Arc::new(StalledInspection::default());
            let (tx, cancel) = watch::channel(false);
            let config = ReadinessProbeConfig::DockerHealth { timeout_ms: 3000 };
            let (outcome, ()) = tokio::join!(
                run_readiness_probe(&config, cancel, None, Some(inspector.clone()), Some("db")),
                async {
                    inspector.0.notified().await;
                    if drop_sender {
                        drop(tx);
                    } else {
                        tx.send(true).unwrap();
                        // Keep the sender alive until the probe returns.
                        tx.closed().await;
                    }
                }
            );
            assert_eq!(outcome.unwrap(), ProbeOutcome::Cancelled);
        }
    }

    #[tokio::test]
    async fn deadline_interrupts_in_flight_inspection() {
        let (_tx, cancel) = watch::channel(false);
        let outcome = run_readiness_probe(
            &ReadinessProbeConfig::DockerHealth { timeout_ms: 50 },
            cancel,
            None,
            Some(Arc::new(StalledInspection::default())),
            Some("db"),
        )
        .await
        .unwrap();
        assert!(matches!(
            outcome,
            ProbeOutcome::TimedOut { attempts: 1, .. }
        ));
    }
}
