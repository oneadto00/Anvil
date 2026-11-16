#![forbid(unsafe_code)]

//! End-to-end CLI lifecycle integration tests for the compiled `anvil` binary.

use anyhow::Result;
use anvil_sys::{DefaultProcessController, LockfileStore, ProcessController};
use serde_json::Value;
use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const VAULT_PASSPHRASE: &str = "e2e-anvil-test-passphrase";

fn reserve_ephemeral_port() -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

fn python_exe() -> &'static str {
    if std::env::consts::OS == "windows" {
        "python"
    } else {
        "python3"
    }
}

fn build_db_script(port: u16, events_file: &Path, pid_file: &Path) -> String {
    let py = format!(
        r#"import os, pathlib, socket
pathlib.Path({events:?}).open('a').write('db_start\n')
pathlib.Path({pid_file:?}).write_text(str(os.getpid()))
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', {port}))
srv.listen(16)
print('DB_LISTENING', flush=True)
while True:
    conn, _ = srv.accept()
    conn.close()
"#,
        events = events_file.to_string_lossy(),
        pid_file = pid_file.to_string_lossy(),
        port = port,
    );
    let encoded = base64_encode(py.as_bytes());
    format!(
        "{} -c \"import base64; exec(base64.b64decode('{encoded}').decode())\"",
        python_exe()
    )
}

fn build_api_script(
    port: u16,
    events_file: &Path,
    env_file: &Path,
    pid_file: &Path,
) -> String {
    let py = format!(
        r#"import http.server, os, pathlib, sys
secret = os.environ.get('DB_PASS', '')
pathlib.Path({env_file:?}).write_text(secret)
pathlib.Path({events:?}).open('a').write('api_start\n')
pathlib.Path({pid_file:?}).write_text(str(os.getpid()))
print('API_BOOT token=' + secret, flush=True)
print('API_ERR secret=' + secret, file=sys.stderr, flush=True)
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ok')
    def log_message(self, *args):
        pass
http.server.HTTPServer(('127.0.0.1', {port}), H).serve_forever()
"#,
        env_file = env_file.to_string_lossy(),
        events = events_file.to_string_lossy(),
        pid_file = pid_file.to_string_lossy(),
        port = port,
    );
    let encoded = base64_encode(py.as_bytes());
    format!(
        "{} -c \"import base64; exec(base64.b64decode('{encoded}').decode())\"",
        python_exe()
    )
}

fn build_web_script(events_file: &Path, pid_file: &Path) -> String {
    let py = format!(
        r#"import os, pathlib, time
pathlib.Path({events:?}).open('a').write('web_start\n')
pathlib.Path({pid_file:?}).write_text(str(os.getpid()))
print('WEB_BOOT_OK', flush=True)
time.sleep(60)
"#,
        events = events_file.to_string_lossy(),
        pid_file = pid_file.to_string_lossy(),
    );
    let encoded = base64_encode(py.as_bytes());
    format!(
        "{} -c \"import base64; exec(base64.b64decode('{encoded}').decode())\"",
        python_exe()
    )
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((triple >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(triple & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn wait_for_pid_file(path: &Path, timeout: Duration) -> Result<u32> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(raw) = fs::read_to_string(path) {
            if let Ok(pid) = raw.trim().parse::<u32>() {
                return Ok(pid);
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    anyhow::bail!("timed out waiting for pid file {}", path.display())
}

fn wait_for_process_exit(pid: u32, timeout: Duration) -> bool {
    let controller = DefaultProcessController::new();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !controller.is_process_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    !controller.is_process_alive(pid)
}

struct PidTreeGuard {
    pid_pgid: Option<(u32, u32)>,
}

impl Drop for PidTreeGuard {
    fn drop(&mut self) {
        if let Some((pid, pgid)) = self.pid_pgid.take() {
            let _ = DefaultProcessController::new().terminate_process_tree(
                pid,
                pgid,
                Duration::from_millis(500),
            );
        }
    }
}

fn anvil_cmd(config_path: &Path, data_dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_anvil"));
    cmd.arg("--config")
        .arg(config_path)
        .arg("--data-dir")
        .arg(data_dir)
        .env("ANVIL_VAULT_PASSPHRASE", VAULT_PASSPHRASE);
    cmd
}

#[test]
fn e2e_secret_doctor_up_no_tui_ps_logs_and_signal_shutdown() -> Result<()> {
    let tmp = TempDir::new()?;
    let data_dir = tmp.path().join("anvil-data");
    let config_path = tmp.path().join("anvil.yaml");
    let events_file = tmp.path().join("events.log");
    let api_env_file = tmp.path().join("api_env.txt");
    let db_pid_file = tmp.path().join("db.pid");
    let api_pid_file = tmp.path().join("api.pid");
    let web_pid_file = tmp.path().join("web.pid");

    let db_port = reserve_ephemeral_port()?;
    let api_port = reserve_ephemeral_port()?;

    let db_cmd = build_db_script(db_port, &events_file, &db_pid_file);
    let api_cmd = build_api_script(api_port, &events_file, &api_env_file, &api_pid_file);
    let web_cmd = build_web_script(&events_file, &web_pid_file);

    let yaml = format!(
        r#"version: "1"
project:
  name: "e2e-lifecycle"
secrets:
  - DB_PASS
services:
  db:
    runtime:
      type: native
      cmd: {db_cmd:?}
      grace_period_ms: 300
    port: {db_port}
    readiness_probe:
      type: tcp
      host: "127.0.0.1"
      port: {db_port}
      interval_ms: 50
      timeout_ms: 8000
  api:
    depends_on: [db]
    runtime:
      type: native
      cmd: {api_cmd:?}
      grace_period_ms: 300
    port: {api_port}
    env:
      DB_PASS: "${{SECRET:DB_PASS}}"
    readiness_probe:
      type: http
      url: "http://127.0.0.1:{api_port}/health"
      expected_status: 200
      interval_ms: 50
      timeout_ms: 8000
  web:
    depends_on: [api]
    runtime:
      type: native
      cmd: {web_cmd:?}
      grace_period_ms: 300
    readiness_probe:
      type: log_regex
      pattern: "^WEB_BOOT_OK$"
      timeout_ms: 8000
"#
    );
    fs::write(&config_path, yaml)?;

    // 1. Write DB_PASS via `anvil secret set --vault --stdin`.
    let secret_value = "s3cr3t_e2e_db_password_987";
    let mut set_child = anvil_cmd(&config_path, &data_dir)
        .args(["secret", "set", "DB_PASS", "--vault", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = set_child.stdin.take() {
        use std::io::Write;
        writeln!(stdin, "{secret_value}")?;
    }
    let set_out = set_child.wait_with_output()?;
    assert!(
        set_out.status.success(),
        "secret set failed: {}",
        String::from_utf8_lossy(&set_out.stderr)
    );
    let set_stdout = String::from_utf8_lossy(&set_out.stdout);
    assert!(!set_stdout.contains(secret_value));

    // 2. Run `anvil doctor` and verify all non-Docker checks [PASS] without [FAIL].
    let doctor_out = anvil_cmd(&config_path, &data_dir).arg("doctor").output()?;
    let doctor_stdout = String::from_utf8_lossy(&doctor_out.stdout);
    assert!(
        doctor_out.status.success(),
        "doctor failed:\nstdout: {doctor_stdout}\nstderr: {}",
        String::from_utf8_lossy(&doctor_out.stderr)
    );
    assert!(doctor_stdout.contains("[PASS] Config & DAG"));
    assert!(doctor_stdout.contains("[PASS] Secrets"));
    assert!(doctor_stdout.contains("[PASS] Lockfile"));
    assert!(doctor_stdout.contains(&format!("[PASS] Port {db_port}")));
    assert!(doctor_stdout.contains(&format!("[PASS] Port {api_port}")));
    assert!(!doctor_stdout.contains("[FAIL]"));
    assert!(!doctor_stdout.contains(secret_value));

    // 3. Launch `anvil up --no-tui` in an isolated process group.
    let controller = DefaultProcessController::new();
    let mut up_cmd = anvil_cmd(&config_path, &data_dir);
    up_cmd
        .args(["up", "--no-tui"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    controller.prepare_command(&mut up_cmd)?;
    let mut up_child = up_cmd.spawn()?;
    let up_pid = up_child.id();
    let (_up_handle, up_identity) = controller.attach_pid(up_pid)?;
    let mut up_guard = PidTreeGuard {
        pid_pgid: Some((up_identity.pid, up_identity.pgid)),
    };

    // Wait for all 3 topological waves to launch and reach the leaf (`web`).
    let db_pid = wait_for_pid_file(&db_pid_file, Duration::from_secs(12))?;
    let api_pid = wait_for_pid_file(&api_pid_file, Duration::from_secs(12))?;
    let web_pid = wait_for_pid_file(&web_pid_file, Duration::from_secs(12))?;

    // Wait briefly until `web` is healthy in `anvil ps --json`.
    let ps_deadline = Instant::now() + Duration::from_secs(10);
    let mut all_running = false;
    let mut last_ps = String::new();
    while Instant::now() < ps_deadline {
        let ps_out = anvil_cmd(&config_path, &data_dir)
            .args(["ps", "--json"])
            .output()?;
        if ps_out.status.success() {
            last_ps = String::from_utf8_lossy(&ps_out.stdout).into_owned();
            if let Ok(json) = serde_json::from_str::<Value>(&last_ps) {
                if let Some(arr) = json["services"].as_array() {
                    let running_count = arr
                        .iter()
                        .filter(|entry| entry["status"] == "Running")
                        .count();
                    if running_count == 3 {
                        all_running = true;
                        break;
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        all_running,
        "expected all 3 services Running in `ps --json`, got:\n{last_ps}"
    );

    // Verify strict topological startup order: db -> api -> web.
    let events: Vec<String> = fs::read_to_string(&events_file)?
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(events, vec!["db_start", "api_start", "web_start"]);

    // Verify real secret injection in child environment.
    assert_eq!(fs::read_to_string(&api_env_file)?.trim(), secret_value);

    // Verify persisted log file + `anvil logs api` redact the secret cleanly.
    let api_log_path = data_dir.join("logs/e2e-lifecycle/api.log");
    let log_deadline = Instant::now() + Duration::from_secs(5);
    let mut api_log = String::new();
    while Instant::now() < log_deadline {
        if let Ok(content) = fs::read_to_string(&api_log_path) {
            if content.contains("[REDACTED]") {
                api_log = content;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        api_log.contains("stdout] [REDACTED]") || api_log.contains("API_BOOT token=[REDACTED]"),
        "expected redacted stdout in api.log, got:\n{api_log}"
    );
    assert!(
        api_log.contains("stderr] [REDACTED]") || api_log.contains("API_ERR secret=[REDACTED]"),
        "expected redacted stderr in api.log, got:\n{api_log}"
    );
    assert!(!api_log.contains(secret_value));

    let logs_out = anvil_cmd(&config_path, &data_dir)
        .args(["logs", "api", "-n", "20"])
        .output()?;
    assert!(logs_out.status.success());
    let logs_stdout = String::from_utf8_lossy(&logs_out.stdout);
    assert!(logs_stdout.contains("[REDACTED]"));
    assert!(!logs_stdout.contains(secret_value));

    // 4. Send graceful termination signal to `anvil up --no-tui` process group and verify clean teardown.
    controller.terminate_process_tree(up_identity.pid, up_identity.pgid, Duration::from_secs(5))?;
    up_guard.pid_pgid = None;
    let status = up_child.wait()?;
    let _ = status;

    assert!(
        wait_for_process_exit(db_pid, Duration::from_secs(5)),
        "db descendant pid {db_pid} remained alive"
    );
    assert!(
        wait_for_process_exit(api_pid, Duration::from_secs(5)),
        "api descendant pid {api_pid} remained alive"
    );
    assert!(
        wait_for_process_exit(web_pid, Duration::from_secs(5)),
        "web descendant pid {web_pid} remained alive"
    );

    let lock_store = LockfileStore::with_dir(data_dir.join("run"));
    assert!(
        lock_store.load_workspace("e2e-lifecycle")?.is_none(),
        "lockfile should be cleaned up after shutdown"
    );
    Ok(())
}

#[test]
fn e2e_up_detach_and_down_reverse_order_cleanup() -> Result<()> {
    let tmp = TempDir::new()?;
    let data_dir = tmp.path().join("anvil-data");
    let config_path = tmp.path().join("anvil.yaml");
    let events_file = tmp.path().join("events.log");
    let db_pid_file = tmp.path().join("db.pid");
    let web_pid_file = tmp.path().join("web.pid");

    let db_port = reserve_ephemeral_port()?;
    let db_cmd = build_db_script(db_port, &events_file, &db_pid_file);
    let web_cmd = build_web_script(&events_file, &web_pid_file);

    let yaml = format!(
        r#"version: "1"
project:
  name: "e2e-detach"
services:
  db:
    runtime:
      type: native
      cmd: {db_cmd:?}
      grace_period_ms: 250
    port: {db_port}
    readiness_probe:
      type: tcp
      host: "127.0.0.1"
      port: {db_port}
      interval_ms: 50
      timeout_ms: 8000
  web:
    depends_on: [db]
    runtime:
      type: native
      cmd: {web_cmd:?}
      grace_period_ms: 250
    readiness_probe:
      type: log_regex
      pattern: "^WEB_BOOT_OK$"
      timeout_ms: 8000
"#
    );
    fs::write(&config_path, yaml)?;

    let detach_out = anvil_cmd(&config_path, &data_dir)
        .args(["up", "--detach"])
        .output()?;
    assert!(
        detach_out.status.success(),
        "up --detach failed: {}",
        String::from_utf8_lossy(&detach_out.stderr)
    );
    let detach_stdout = String::from_utf8_lossy(&detach_out.stdout);
    let daemon_pid: Option<u32> = detach_stdout
        .split("(pid ")
        .nth(1)
        .and_then(|rest| rest.split(')').next())
        .and_then(|s| s.trim().parse::<u32>().ok());
    let mut daemon_guard = PidTreeGuard {
        pid_pgid: daemon_pid.map(|p| (p, p)),
    };

    let db_pid = wait_for_pid_file(&db_pid_file, Duration::from_secs(12))?;
    let web_pid = wait_for_pid_file(&web_pid_file, Duration::from_secs(12))?;

    let lock_store = LockfileStore::with_dir(data_dir.join("run"));
    let lock_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < lock_deadline {
        if lock_store
            .load_workspace("e2e-detach")?
            .is_some_and(|w| w.processes.len() >= 2)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let down_out = anvil_cmd(&config_path, &data_dir)
        .args(["down", "--grace-ms", "1500"])
        .output()?;
    let down_stdout = String::from_utf8_lossy(&down_out.stdout);
    assert!(
        down_out.status.success(),
        "anvil down failed: {}",
        String::from_utf8_lossy(&down_out.stderr)
    );
    assert!(down_stdout.contains("Stopped: 2"));

    assert!(wait_for_process_exit(db_pid, Duration::from_secs(5)));
    assert!(wait_for_process_exit(web_pid, Duration::from_secs(5)));
    assert!(lock_store.load_workspace("e2e-detach")?.is_none());

    if let Some((pid, pgid)) = daemon_guard.pid_pgid.take() {
        let _ = DefaultProcessController::new().terminate_process_tree(
            pid,
            pgid,
            Duration::from_secs(2),
        );
    }
    Ok(())
}
