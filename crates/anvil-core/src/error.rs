//! Structured domain and configuration validation errors for `anvil-core`.

use crate::state::ServiceId;
use thiserror::Error;

/// Top-level errors returned by `anvil-core` operations.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Failed to read a configuration or runtime file from disk.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Failed to deserialize `anvil.yaml` syntax or types.
    #[error("failed to parse anvil.yaml: {0}")]
    YamlParse(#[from] serde_yaml::Error),

    /// One or more semantic validation rules failed after parsing `anvil.yaml`.
    #[error("configuration validation failed:\n{}", format_validation_errors(.0))]
    ValidationErrors(Vec<ConfigValidationError>),

    /// Circular service dependency detected while building the topological graph.
    #[error(transparent)]
    DagCycle(#[from] DagCycleError),

    /// A readiness probe could not run or lost its required input.
    #[error("readiness probe failed: {reason}")]
    ProbeFailed { reason: String },

    /// Underlying secret backend or placeholder resolution error.
    #[error("secret error: {0}")]
    Secret(#[from] anvil_secret::SecretError),
}

/// Error returned when a circular service dependency is detected in the DAG.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("dependency cycle detected: {}", .cycle_path.join(" -> "))]
pub struct DagCycleError {
    /// Closed cycle path starting and ending with the same service ID
    /// (e.g. `["api", "worker", "cache", "api"]`).
    pub cycle_path: Vec<ServiceId>,
}

/// Semantic validation errors produced by [`crate::AnvilConfig::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigValidationError {
    /// `version` is not `"1"`.
    #[error("unsupported anvil.yaml version '{0}'; expected \"1\"")]
    UnsupportedVersion(String),

    /// `project.name` is empty, contains path separators, whitespace, or path traversal tokens.
    #[error("invalid project name '{0}'; must be non-empty without '/', '\\\\', whitespace, or '.'/'..'")]
    InvalidProjectName(String),

    /// `services` map is empty.
    #[error("at least one service must be defined under 'services'")]
    EmptyServices,

    /// Two services declared the same non-zero `port`.
    #[error("port {port} is declared by both '{first_service}' and '{second_service}'")]
    DuplicatePort {
        /// The conflicting TCP/UDP port number.
        port: u16,
        /// The first service that claimed the port.
        first_service: String,
        /// The second service that also claimed the port.
        second_service: String,
    },

    /// A service declared `port: 0`.
    #[error("service '{service}' declared invalid port 0")]
    InvalidPort {
        /// Service identifier with invalid port `0`.
        service: String,
    },

    /// A service's `depends_on` references a service ID that does not exist in `services`.
    #[error("service '{service}' depends on undefined service '{missing_dep}'")]
    UndefinedDependency {
        /// Service declaring the invalid dependency.
        service: String,
        /// Missing dependency identifier.
        missing_dep: String,
    },

    /// A service lists itself in `depends_on`.
    #[error("service '{service}' cannot depend on itself")]
    SelfDependency {
        /// Service identifier that depends on itself.
        service: String,
    },

    /// A `native` runtime service has an empty or whitespace-only `cmd`.
    #[error("native service '{service}' has an empty command")]
    EmptyCommand {
        /// Service identifier with a blank command.
        service: String,
    },

    /// A service's `readiness_probe` configuration is invalid.
    #[error("service '{service}' has an invalid readiness probe: {reason}")]
    InvalidProbe {
        /// Service identifier with an invalid probe.
        service: String,
        /// Human-readable reason explaining the probe error.
        reason: String,
    },

    /// An environment value contains a syntactically malformed `${SECRET:...}` placeholder.
    #[error("{}", format_invalid_placeholder(.service.as_deref(), .env_key, .reason))]
    InvalidSecretPlaceholder {
        /// Owning service ID, or `None` for global `env`.
        service: Option<String>,
        /// Environment variable name whose value failed placeholder validation.
        env_key: String,
        /// Detailed syntax error from `anvil-secret`.
        reason: String,
    },

    /// An environment value references `${SECRET:<KEY>}` without declaring `<KEY>` in top-level `secrets`.
    #[error("{}", format_undeclared_secret(.service.as_deref(), .env_key, .secret_key))]
    UndeclaredSecretReference {
        /// Owning service ID, or `None` for global `env`.
        service: Option<String>,
        /// Environment variable name containing the reference.
        env_key: String,
        /// Secret key missing from top-level `secrets`.
        secret_key: String,
    },
}

fn format_validation_errors(errors: &[ConfigValidationError]) -> String {
    errors
        .iter()
        .enumerate()
        .map(|(idx, err)| format!("  {}. {err}", idx + 1))
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_invalid_placeholder(service: Option<&str>, env_key: &str, reason: &str) -> String {
    match service {
        Some(svc) => format!("service '{svc}' env '{env_key}' has invalid secret placeholder: {reason}"),
        None => format!("global env '{env_key}' has invalid secret placeholder: {reason}"),
    }
}

fn format_undeclared_secret(service: Option<&str>, env_key: &str, secret_key: &str) -> String {
    match service {
        Some(svc) => format!(
            "service '{svc}' env '{env_key}' references undeclared secret '{secret_key}'; add it to top-level 'secrets'"
        ),
        None => format!(
            "global env '{env_key}' references undeclared secret '{secret_key}'; add it to top-level 'secrets'"
        ),
    }
}
