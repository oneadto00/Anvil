//! Declarative `anvil.yaml` (v1) schema types, loading, and semantic validation.

use crate::error::{ConfigValidationError, CoreError};
use anvil_secret::validate_secret_refs;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Unique identifier for a service in `anvil.yaml`.
pub type ServiceId = String;

const SUPPORTED_VERSION: &str = "1";

/// Root configuration structure parsed from `anvil.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnvilConfig {
    /// Protocol schema version (must be `"1"`).
    pub version: String,
    /// Project metadata used for isolating logs, vaults, and lockfiles.
    pub project: ProjectMetadata,
    /// Global environment variables injected into every service (overridable per service).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Explicitly declared `${SECRET:<KEY>}` names required by this workspace.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// Map of service identifiers to service definitions.
    pub services: BTreeMap<ServiceId, ServiceConfig>,
}

/// Project-level metadata under `project` in `anvil.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectMetadata {
    /// Project name (non-empty, free of path separators and whitespace).
    pub name: String,
    /// Optional human-readable project description.
    #[serde(default)]
    pub description: Option<String>,
}

/// Configuration for an individual managed service under `services.<id>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Runtime backend specification (`native`, `docker_container`, or `docker_compose`).
    pub runtime: RuntimeConfig,
    /// Optional primary listening port checked for conflicts prior to startup.
    #[serde(default)]
    pub port: Option<u16>,
    /// Upstream service IDs that must become `Healthy` before starting this service.
    #[serde(default)]
    pub depends_on: Vec<ServiceId>,
    /// Service-specific environment variables overriding global `env`.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Optional readiness probe gating downstream dependency unlocking.
    #[serde(default)]
    pub readiness_probe: Option<ReadinessProbeConfig>,
    /// Automatic restart policy applied after unexpected non-zero exits.
    #[serde(default)]
    pub restart_policy: RestartPolicy,
}

/// Runtime execution configuration for a service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuntimeConfig {
    /// Native host child process managed via process groups / Job Objects.
    Native {
        /// Command line to execute (must be non-empty after trimming).
        cmd: String,
        /// Optional working directory relative to `anvil.yaml` or absolute.
        #[serde(default)]
        cwd: Option<PathBuf>,
        /// Graceful shutdown window between `SIGTERM` and `SIGKILL`, in milliseconds.
        #[serde(default = "default_grace_period_ms")]
        grace_period_ms: u64,
    },
    /// Standalone Docker container managed directly via the Docker Engine API.
    DockerContainer {
        /// Container image reference and tag (e.g. `postgres:16-alpine`).
        image: String,
        /// Optional explicit container name (defaults to `anvil-<project>-<service>`).
        #[serde(default)]
        container_name: Option<String>,
        /// Port bindings in `HOST:CONTAINER` format.
        #[serde(default)]
        ports: Vec<String>,
        /// Volume mount specifications.
        #[serde(default)]
        volumes: Vec<String>,
        /// Optional command override replacing image `CMD`.
        #[serde(default)]
        command: Option<Vec<String>>,
    },
    /// Service bridged from an existing Docker Compose manifest.
    DockerCompose {
        /// Path to the `docker-compose.yml` file.
        compose_file: PathBuf,
        /// Target service name inside the Compose file.
        service_name: String,
    },
}

/// Multi-modal readiness probe configuration under `services.<id>.readiness_probe`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReadinessProbeConfig {
    /// Probes TCP connection acceptance on `host:port`.
    Tcp {
        /// Target host address (defaults to `"127.0.0.1"`).
        #[serde(default = "default_probe_host")]
        host: String,
        /// Target TCP port.
        port: u16,
        /// Polling interval in milliseconds (defaults to `500`).
        #[serde(default = "default_probe_interval_ms")]
        interval_ms: u64,
        /// Overall readiness timeout in milliseconds (defaults to `15000`).
        #[serde(default = "default_tcp_timeout_ms")]
        timeout_ms: u64,
    },
    /// Probes an HTTP(S) endpoint expecting a specific status code.
    Http {
        /// Target `http://` or `https://` healthcheck URL.
        url: String,
        /// Expected HTTP response status code (defaults to `200`).
        #[serde(default = "default_http_status")]
        expected_status: u16,
        /// Polling interval in milliseconds (defaults to `500`).
        #[serde(default = "default_probe_interval_ms")]
        interval_ms: u64,
        /// Overall readiness timeout in milliseconds (defaults to `30000`).
        #[serde(default = "default_http_timeout_ms")]
        timeout_ms: u64,
    },
    /// Watches stdout/stderr lines for a regular expression match.
    LogRegex {
        /// Regular expression pattern matched against service output lines.
        pattern: String,
        /// Overall readiness timeout in milliseconds (defaults to `20000`).
        #[serde(default = "default_log_regex_timeout_ms")]
        timeout_ms: u64,
    },
    /// Polls Docker container `HEALTHCHECK` state until healthy.
    DockerHealth {
        /// Overall readiness timeout in milliseconds (defaults to `15000`).
        #[serde(default = "default_docker_health_timeout_ms")]
        timeout_ms: u64,
    },
}

/// Automatic crash-recovery policy for a service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestartPolicy {
    /// Whether to automatically restart after an unexpected crash (defaults to `false`).
    #[serde(default)]
    pub on_failure: bool,
    /// Maximum consecutive restart attempts (defaults to `3`).
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    /// Base backoff delay in milliseconds between restarts (defaults to `1000`).
    #[serde(default = "default_backoff_ms")]
    pub backoff_ms: u64,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            on_failure: false,
            max_retries: default_max_retries(),
            backoff_ms: default_backoff_ms(),
        }
    }
}

impl AnvilConfig {
    /// Parses and semantically validates an [`AnvilConfig`] from a YAML string.
    pub fn from_yaml_str(raw: &str) -> Result<Self, CoreError> {
        let config: Self = serde_yaml::from_str(raw)?;
        if let Err(errors) = config.validate() {
            return Err(CoreError::ValidationErrors(errors));
        }
        Ok(config)
    }

    /// Reads, parses, and semantically validates an [`AnvilConfig`] from a file on disk.
    pub fn from_file(path: &Path) -> Result<Self, CoreError> {
        let raw = fs::read_to_string(path)?;
        Self::from_yaml_str(&raw)
    }

    /// Validates all semantic rules from `PROTOCOL_ANVIL_YAML.md`, collecting all violations.
    pub fn validate(&self) -> Result<(), Vec<ConfigValidationError>> {
        let mut errors = Vec::new();

        // 1. Protocol version check
        if self.version != SUPPORTED_VERSION {
            errors.push(ConfigValidationError::UnsupportedVersion(
                self.version.clone(),
            ));
        }

        // 2. Project name check
        if !is_valid_project_name(&self.project.name) {
            errors.push(ConfigValidationError::InvalidProjectName(
                self.project.name.clone(),
            ));
        }

        // 3. Non-empty services check
        if self.services.is_empty() {
            errors.push(ConfigValidationError::EmptyServices);
        }

        let declared_secrets: BTreeSet<&str> = self.secrets.iter().map(String::as_str).collect();
        let mut seen_ports: BTreeMap<u16, String> = BTreeMap::new();

        // 7 (global): Validate global env secret placeholders & declarations
        validate_env_secrets(None, &self.env, &declared_secrets, &mut errors);

        for (service_id, svc) in &self.services {
            // 4. Port validity & uniqueness
            if let Some(port) = svc.port {
                if port == 0 {
                    errors.push(ConfigValidationError::InvalidPort {
                        service: service_id.clone(),
                    });
                } else if let Some(first_service) = seen_ports.get(&port) {
                    errors.push(ConfigValidationError::DuplicatePort {
                        port,
                        first_service: first_service.clone(),
                        second_service: service_id.clone(),
                    });
                } else {
                    seen_ports.insert(port, service_id.clone());
                }
            }

            // 5. Dependency integrity
            for dep in &svc.depends_on {
                if dep == service_id {
                    errors.push(ConfigValidationError::SelfDependency {
                        service: service_id.clone(),
                    });
                } else if !self.services.contains_key(dep) {
                    errors.push(ConfigValidationError::UndefinedDependency {
                        service: service_id.clone(),
                        missing_dep: dep.clone(),
                    });
                }
            }

            // 6. Command & probe validity
            if let RuntimeConfig::Native { cmd, .. } = &svc.runtime {
                if cmd.trim().is_empty() {
                    errors.push(ConfigValidationError::EmptyCommand {
                        service: service_id.clone(),
                    });
                }
            }

            if let Some(probe) = &svc.readiness_probe {
                validate_probe(service_id, probe, &mut errors);
            }

            // 7 (service): Validate per-service env secret placeholders & declarations
            validate_env_secrets(
                Some(service_id.as_str()),
                &svc.env,
                &declared_secrets,
                &mut errors,
            );
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Returns merged environment variables (`global env` overridden by `service env`) for `service_id`.
    pub fn merged_env_for_service(&self, service_id: &str) -> Option<BTreeMap<String, String>> {
        let svc = self.services.get(service_id)?;
        let mut merged = self.env.clone();
        for (k, v) in &svc.env {
            merged.insert(k.clone(), v.clone());
        }
        Some(merged)
    }
}

fn is_valid_project_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
        && !name.chars().any(char::is_whitespace)
}

fn validate_probe(
    service_id: &str,
    probe: &ReadinessProbeConfig,
    errors: &mut Vec<ConfigValidationError>,
) {
    match probe {
        ReadinessProbeConfig::Tcp {
            host,
            port,
            interval_ms,
            timeout_ms,
        } => {
            if host.trim().is_empty() {
                errors.push(ConfigValidationError::InvalidProbe {
                    service: service_id.to_owned(),
                    reason: "tcp probe 'host' cannot be empty".to_owned(),
                });
            }
            if *port == 0 {
                errors.push(ConfigValidationError::InvalidProbe {
                    service: service_id.to_owned(),
                    reason: "tcp probe 'port' cannot be 0".to_owned(),
                });
            }
            if *interval_ms == 0 {
                errors.push(ConfigValidationError::InvalidProbe {
                    service: service_id.to_owned(),
                    reason: "tcp probe 'interval_ms' must be greater than 0".to_owned(),
                });
            }
            if *timeout_ms == 0 {
                errors.push(ConfigValidationError::InvalidProbe {
                    service: service_id.to_owned(),
                    reason: "tcp probe 'timeout_ms' must be greater than 0".to_owned(),
                });
            }
        }
        ReadinessProbeConfig::Http {
            url,
            expected_status,
            interval_ms,
            timeout_ms,
        } => {
            if let Err(reason) = validate_http_url(url) {
                errors.push(ConfigValidationError::InvalidProbe {
                    service: service_id.to_owned(),
                    reason,
                });
            }
            if !(100..600).contains(expected_status) {
                errors.push(ConfigValidationError::InvalidProbe {
                    service: service_id.to_owned(),
                    reason: format!(
                        "http probe 'expected_status' must be between 100 and 599, got {expected_status}"
                    ),
                });
            }
            if *interval_ms == 0 {
                errors.push(ConfigValidationError::InvalidProbe {
                    service: service_id.to_owned(),
                    reason: "http probe 'interval_ms' must be greater than 0".to_owned(),
                });
            }
            if *timeout_ms == 0 {
                errors.push(ConfigValidationError::InvalidProbe {
                    service: service_id.to_owned(),
                    reason: "http probe 'timeout_ms' must be greater than 0".to_owned(),
                });
            }
        }
        ReadinessProbeConfig::LogRegex {
            pattern,
            timeout_ms,
        } => {
            if pattern.trim().is_empty() {
                errors.push(ConfigValidationError::InvalidProbe {
                    service: service_id.to_owned(),
                    reason: "log_regex probe 'pattern' cannot be empty".to_owned(),
                });
            } else if let Err(err) = Regex::new(pattern) {
                errors.push(ConfigValidationError::InvalidProbe {
                    service: service_id.to_owned(),
                    reason: format!("invalid log_regex pattern '{pattern}': {err}"),
                });
            }
            if *timeout_ms == 0 {
                errors.push(ConfigValidationError::InvalidProbe {
                    service: service_id.to_owned(),
                    reason: "log_regex probe 'timeout_ms' must be greater than 0".to_owned(),
                });
            }
        }
        ReadinessProbeConfig::DockerHealth { timeout_ms } => {
            if *timeout_ms == 0 {
                errors.push(ConfigValidationError::InvalidProbe {
                    service: service_id.to_owned(),
                    reason: "docker_health probe 'timeout_ms' must be greater than 0".to_owned(),
                });
            }
        }
    }
}

fn validate_http_url(url: &str) -> Result<(), String> {
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("http probe 'url' must not contain whitespace or control characters".to_owned());
    }

    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .ok_or_else(|| "http probe 'url' must start with 'http://' or 'https://'".to_owned())?;

    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err("http probe 'url' must include a valid host".to_owned());
    }

    if let Some(after_open) = authority.strip_prefix('[') {
        let Some(close_idx) = after_open.find(']') else {
            return Err("http probe 'url' has unclosed IPv6 host bracket".to_owned());
        };
        let host = &after_open[..close_idx];
        if host.is_empty() {
            return Err("http probe 'url' has empty IPv6 host".to_owned());
        }
        let remainder = &after_open[close_idx + 1..];
        if !remainder.is_empty() {
            let Some(port_str) = remainder.strip_prefix(':') else {
                return Err("http probe 'url' has invalid authority suffix after ']'".to_owned());
            };
            validate_url_port(port_str)?;
        }
    } else if let Some((host, port_str)) = authority.split_once(':') {
        if host.is_empty() {
            return Err("http probe 'url' must include a non-empty host".to_owned());
        }
        validate_url_port(port_str)?;
    }

    Ok(())
}

fn validate_url_port(port_str: &str) -> Result<(), String> {
    if port_str.is_empty() {
        return Err("http probe 'url' has empty port after ':'".to_owned());
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("http probe 'url' has invalid port '{port_str}'"))?;
    if port == 0 {
        return Err("http probe 'url' port cannot be 0".to_owned());
    }
    Ok(())
}

fn validate_env_secrets(
    service: Option<&str>,
    env: &BTreeMap<String, String>,
    declared_secrets: &BTreeSet<&str>,
    errors: &mut Vec<ConfigValidationError>,
) {
    for (env_key, env_val) in env {
        match validate_secret_refs(env_val) {
            Ok(secret_keys) => {
                for secret_key in secret_keys {
                    if !declared_secrets.contains(secret_key.as_str()) {
                        errors.push(ConfigValidationError::UndeclaredSecretReference {
                            service: service.map(str::to_owned),
                            env_key: env_key.clone(),
                            secret_key,
                        });
                    }
                }
            }
            Err(err) => {
                errors.push(ConfigValidationError::InvalidSecretPlaceholder {
                    service: service.map(str::to_owned),
                    env_key: env_key.clone(),
                    reason: err.to_string(),
                });
            }
        }
    }
}

const fn default_grace_period_ms() -> u64 {
    3_000
}

fn default_probe_host() -> String {
    "127.0.0.1".to_owned()
}

const fn default_probe_interval_ms() -> u64 {
    500
}

const fn default_tcp_timeout_ms() -> u64 {
    15_000
}

const fn default_http_status() -> u16 {
    200
}

const fn default_http_timeout_ms() -> u64 {
    30_000
}

const fn default_log_regex_timeout_ms() -> u64 {
    20_000
}

const fn default_docker_health_timeout_ms() -> u64 {
    15_000
}

const fn default_max_retries() -> u32 {
    3
}

const fn default_backoff_ms() -> u64 {
    1_000
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const NEBULA_YAML: &str = r#"
version: "1"

project:
  name: "nebula-commerce"
  description: "本地微服务全栈开发环境"

env:
  RUST_LOG: "info,nebula=debug"
  NODE_ENV: "development"

secrets:
  - DB_PASSWORD
  - JWT_PRIVATE_KEY
  - STRIPE_API_SECRET

services:
  postgres:
    runtime:
      type: docker_container
      image: "postgres:16-alpine"
      container_name: "anvil-nebula-pg"
      volumes:
        - "./.anvil-data/pg:/var/lib/postgresql/data"
      ports:
        - "5432:5432"
    port: 5432
    env:
      POSTGRES_USER: "nebula"
      POSTGRES_PASSWORD: "${SECRET:DB_PASSWORD}"
      POSTGRES_DB: "nebula_dev"
    readiness_probe:
      type: tcp
      host: "127.0.0.1"
      port: 5432
      interval_ms: 500
      timeout_ms: 15000

  redis:
    runtime:
      type: docker_compose
      compose_file: "./infra/docker-compose.yml"
      service_name: "redis-cache"
    port: 6379
    readiness_probe:
      type: docker_health
      timeout_ms: 10000

  api-gateway:
    runtime:
      type: native
      cmd: "cargo run -p nebula-api"
      cwd: "./backend"
      grace_period_ms: 3000
    port: 8080
    depends_on:
      - postgres
      - redis
    env:
      DATABASE_URL: "postgres://nebula:${SECRET:DB_PASSWORD}@127.0.0.1:5432/nebula_dev"
      JWT_SECRET: "${SECRET:JWT_PRIVATE_KEY}"
    readiness_probe:
      type: http
      url: "http://127.0.0.1:8080/healthz"
      expected_status: 200
      interval_ms: 500
      timeout_ms: 30000
    restart_policy:
      on_failure: true
      max_retries: 3
      backoff_ms: 1000

  web-console:
    runtime:
      type: native
      cmd: "pnpm run dev --port 3000"
      cwd: "./frontend"
    port: 3000
    depends_on:
      - api-gateway
    readiness_probe:
      type: log_regex
      pattern: "Local:\\s+http://localhost:3000"
      timeout_ms: 20000
"#;

    fn base_valid_yaml() -> &'static str {
        r#"
version: "1"
project:
  name: "sample-app"
services:
  api:
    runtime:
      type: native
      cmd: "cargo run"
    port: 8080
"#
    }

    fn validation_errors(yaml: &str) -> Vec<ConfigValidationError> {
        match AnvilConfig::from_yaml_str(yaml) {
            Err(CoreError::ValidationErrors(errs)) => errs,
            other => panic!("expected ValidationErrors, got: {other:?}"),
        }
    }

    #[test]
    fn parses_full_nebula_commerce_config_and_defaults() {
        let cfg = AnvilConfig::from_yaml_str(NEBULA_YAML).unwrap();
        assert_eq!(cfg.version, "1");
        assert_eq!(cfg.project.name, "nebula-commerce");
        assert_eq!(cfg.secrets.len(), 3);
        assert_eq!(cfg.services.len(), 4);

        let web = &cfg.services["web-console"];
        assert_eq!(web.restart_policy, RestartPolicy::default());
        assert!(!web.restart_policy.on_failure);
        assert_eq!(web.restart_policy.max_retries, 3);
        assert_eq!(web.restart_policy.backoff_ms, 1000);
        match &web.runtime {
            RuntimeConfig::Native {
                grace_period_ms, ..
            } => assert_eq!(*grace_period_ms, 3000),
            other => panic!("unexpected runtime: {other:?}"),
        }

        let merged = cfg.merged_env_for_service("api-gateway").unwrap();
        assert_eq!(merged.get("RUST_LOG").map(String::as_str), Some("info,nebula=debug"));
        assert_eq!(
            merged.get("JWT_SECRET").map(String::as_str),
            Some("${SECRET:JWT_PRIVATE_KEY}")
        );
    }

    #[test]
    fn loads_config_from_file() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(base_valid_yaml().as_bytes()).unwrap();
        let cfg = AnvilConfig::from_file(tmp.path()).unwrap();
        assert_eq!(cfg.project.name, "sample-app");
    }

    #[test]
    fn rejects_wrong_version() {
        let yaml = r#"
version: "2"
project:
  name: "sample"
services:
  api:
    runtime:
      type: native
      cmd: "echo ok"
"#;
        let errs = validation_errors(yaml);
        assert_eq!(
            errs,
            vec![ConfigValidationError::UnsupportedVersion("2".to_owned())]
        );
    }

    #[test]
    fn rejects_invalid_project_names() {
        for bad_name in ["", "bad/name", r"bad\name", "has space", "..", "."] {
            let yaml = format!(
                r#"
version: "1"
project:
  name: '{bad_name}'
services:
  api:
    runtime:
      type: native
      cmd: "echo ok"
"#
            );
            let errs = validation_errors(&yaml);
            assert!(
                errs.contains(&ConfigValidationError::InvalidProjectName(
                    bad_name.to_owned()
                )),
                "missing InvalidProjectName for {bad_name:?}: {errs:?}"
            );
        }
    }

    #[test]
    fn rejects_empty_services() {
        let yaml = r#"
version: "1"
project:
  name: "sample"
services: {}
"#;
        let errs = validation_errors(yaml);
        assert_eq!(errs, vec![ConfigValidationError::EmptyServices]);
    }

    #[test]
    fn rejects_duplicate_ports_and_port_zero() {
        let yaml = r#"
version: "1"
project:
  name: "sample"
services:
  alpha:
    runtime:
      type: native
      cmd: "echo a"
    port: 8080
  beta:
    runtime:
      type: native
      cmd: "echo b"
    port: 8080
  gamma:
    runtime:
      type: native
      cmd: "echo c"
    port: 0
"#;
        let errs = validation_errors(yaml);
        assert!(errs.contains(&ConfigValidationError::DuplicatePort {
            port: 8080,
            first_service: "alpha".to_owned(),
            second_service: "beta".to_owned(),
        }));
        assert!(errs.contains(&ConfigValidationError::InvalidPort {
            service: "gamma".to_owned(),
        }));
    }

    #[test]
    fn rejects_undefined_and_self_dependencies() {
        let yaml = r#"
version: "1"
project:
  name: "sample"
services:
  api:
    runtime:
      type: native
      cmd: "echo api"
    depends_on:
      - api
      - missing-db
"#;
        let errs = validation_errors(yaml);
        assert!(errs.contains(&ConfigValidationError::SelfDependency {
            service: "api".to_owned(),
        }));
        assert!(errs.contains(&ConfigValidationError::UndefinedDependency {
            service: "api".to_owned(),
            missing_dep: "missing-db".to_owned(),
        }));
    }

    #[test]
    fn rejects_blank_native_command() {
        let yaml = r#"
version: "1"
project:
  name: "sample"
services:
  api:
    runtime:
      type: native
      cmd: "   \t  "
"#;
        let errs = validation_errors(yaml);
        assert_eq!(
            errs,
            vec![ConfigValidationError::EmptyCommand {
                service: "api".to_owned(),
            }]
        );
    }

    #[test]
    fn rejects_invalid_probes() {
        let yaml = r#"
version: "1"
project:
  name: "sample"
services:
  bad-regex:
    runtime:
      type: native
      cmd: "echo 1"
    readiness_probe:
      type: log_regex
      pattern: "[unclosed"
      timeout_ms: 0
  bad-http:
    runtime:
      type: native
      cmd: "echo 2"
    readiness_probe:
      type: http
      url: "ftp://127.0.0.1/health"
      interval_ms: 0
      timeout_ms: 0
  bad-tcp:
    runtime:
      type: native
      cmd: "echo 3"
    readiness_probe:
      type: tcp
      host: "   "
      port: 0
      interval_ms: 0
      timeout_ms: 0
  bad-docker:
    runtime:
      type: docker_container
      image: "redis:7"
    readiness_probe:
      type: docker_health
      timeout_ms: 0
"#;
        let errs = validation_errors(yaml);
        assert!(errs.iter().any(|e| matches!(
            e,
            ConfigValidationError::InvalidProbe { service, reason }
                if service == "bad-regex" && reason.contains("invalid log_regex pattern")
        )));
        assert!(errs.iter().any(|e| matches!(
            e,
            ConfigValidationError::InvalidProbe { service, reason }
                if service == "bad-regex" && reason.contains("timeout_ms")
        )));
        assert!(errs.iter().any(|e| matches!(
            e,
            ConfigValidationError::InvalidProbe { service, reason }
                if service == "bad-http" && reason.contains("http://")
        )));
        assert!(errs.iter().any(|e| matches!(
            e,
            ConfigValidationError::InvalidProbe { service, reason }
                if service == "bad-http" && reason.contains("interval_ms")
        )));
        assert!(errs.iter().any(|e| matches!(
            e,
            ConfigValidationError::InvalidProbe { service, reason }
                if service == "bad-tcp" && reason.contains("port")
        )));
        assert!(errs.iter().any(|e| matches!(
            e,
            ConfigValidationError::InvalidProbe { service, reason }
                if service == "bad-docker" && reason.contains("docker_health")
        )));
    }

    #[test]
    fn rejects_malformed_and_undeclared_secret_references_and_collects_all_errors() {
        let yaml = r#"
version: "2"
project:
  name: "sample"
env:
  GLOBAL_BAD: "${SECRET:lowercase}"
  GLOBAL_UNDECLARED: "${SECRET:GLOBAL_MISSING}"
secrets:
  - DECLARED_ONLY
services:
  api:
    runtime:
      type: native
      cmd: "   "
    env:
      SVC_UNCLOSED: "postgres://u:${SECRET:UNCLOSED"
      SVC_UNDECLARED: "${SECRET:SVC_MISSING}"
      SVC_OK: "${SECRET:DECLARED_ONLY}"
"#;
        let errs = validation_errors(yaml);
        assert!(errs.contains(&ConfigValidationError::UnsupportedVersion("2".to_owned())));
        assert!(errs.contains(&ConfigValidationError::EmptyCommand {
            service: "api".to_owned()
        }));
        assert!(errs.iter().any(|e| matches!(
            e,
            ConfigValidationError::InvalidSecretPlaceholder {
                service: None,
                env_key,
                ..
            } if env_key == "GLOBAL_BAD"
        )));
        assert!(errs.contains(&ConfigValidationError::UndeclaredSecretReference {
            service: None,
            env_key: "GLOBAL_UNDECLARED".to_owned(),
            secret_key: "GLOBAL_MISSING".to_owned(),
        }));
        assert!(errs.iter().any(|e| matches!(
            e,
            ConfigValidationError::InvalidSecretPlaceholder {
                service: Some(svc),
                env_key,
                ..
            } if svc == "api" && env_key == "SVC_UNCLOSED"
        )));
        assert!(errs.contains(&ConfigValidationError::UndeclaredSecretReference {
            service: Some("api".to_owned()),
            env_key: "SVC_UNDECLARED".to_owned(),
            secret_key: "SVC_MISSING".to_owned(),
        }));
    }
}
