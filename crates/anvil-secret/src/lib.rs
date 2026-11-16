#![forbid(unsafe_code)]

//! Sensitive credential storage and memory-safe placeholder resolution for Anvil.
//!
//! This crate isolates secrets using:
//! - [`KeyringStore`]: OS native keychain integration (`keyring`) with a key-only sidecar index.
//! - [`LocalEncryptedVault`]: Argon2id + AES-256-GCM encrypted file fallback for headless hosts.
//! - [`resolver`]: Single-pass `${SECRET:<KEY>}` placeholder extraction and resolution wrapped in
//!   `zeroize::Zeroizing<String>`.

pub mod error;
pub mod keyring_store;
pub mod resolver;
pub mod vault_fallback;

pub use error::SecretError;
pub use keyring_store::KeyringStore;
pub use resolver::{
    extract_secret_refs, resolve_env_map, resolve_value, validate_secret_refs, ResolvedEnvMap,
};
pub use vault_fallback::LocalEncryptedVault;

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::{Component, Path};
use std::sync::RwLock;
use zeroize::Zeroizing;

/// Abstraction over secret persistence backends (OS keyring, local encrypted vault, or mocks).
pub trait SecretBackend: Send + Sync {
    /// Retrieves a secret value for `(project, key)`, returning `Ok(None)` if absent.
    fn get(&self, project: &str, key: &str) -> Result<Option<Zeroizing<String>>, SecretError>;

    /// Stores or overwrites a secret value for `(project, key)`.
    fn set(&self, project: &str, key: &str, value: Zeroizing<String>) -> Result<(), SecretError>;

    /// Deletes the secret value for `(project, key)`. Deleting an absent key succeeds cleanly.
    fn delete(&self, project: &str, key: &str) -> Result<(), SecretError>;

    /// Lists all stored secret key names for `project` without returning any secret values.
    fn list_keys(&self, project: &str) -> Result<Vec<String>, SecretError>;
}

/// A memory-protected secret string whose `Debug` and `Display` implementations redact its value.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(Zeroizing<String>);

impl SecretValue {
    /// Wraps a string in a zeroizing, redacting [`SecretValue`].
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Wraps an existing `Zeroizing<String>` in a [`SecretValue`].
    pub fn from_zeroizing(value: Zeroizing<String>) -> Self {
        Self(value)
    }

    /// Exposes the secret as a string slice for immediate injection into a consumer.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Consumes this wrapper and returns the inner `Zeroizing<String>`.
    pub fn into_zeroizing(self) -> Zeroizing<String> {
        self.0
    }
}

impl From<String> for SecretValue {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<Zeroizing<String>> for SecretValue {
    fn from(value: Zeroizing<String>) -> Self {
        Self::from_zeroizing(value)
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue([REDACTED])")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Thread-safe in-memory [`SecretBackend`] suitable for isolated tests and dry runs.
#[derive(Default)]
pub struct InMemorySecretStore {
    entries: RwLock<HashMap<String, BTreeMap<String, Zeroizing<String>>>>,
}

impl InMemorySecretStore {
    /// Creates an empty in-memory secret store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl fmt::Debug for InMemorySecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg = f.debug_struct("InMemorySecretStore");
        match self.entries.read() {
            Ok(guard) => {
                let redacted: BTreeMap<&str, BTreeMap<&str, &str>> = guard
                    .iter()
                    .map(|(proj, keys)| {
                        let inner = keys.keys().map(|k| (k.as_str(), "[REDACTED]")).collect();
                        (proj.as_str(), inner)
                    })
                    .collect();
                dbg.field("projects", &redacted).finish()
            }
            Err(_) => dbg.field("projects", &"<poisoned>").finish(),
        }
    }
}

impl SecretBackend for InMemorySecretStore {
    fn get(&self, project: &str, key: &str) -> Result<Option<Zeroizing<String>>, SecretError> {
        validate_project_name(project)?;
        validate_secret_key_name(key)?;
        let guard = self
            .entries
            .read()
            .map_err(|_| SecretError::VaultLocked("in-memory secret store lock poisoned".into()))?;
        Ok(guard
            .get(project)
            .and_then(|proj_map| proj_map.get(key))
            .cloned())
    }

    fn set(&self, project: &str, key: &str, value: Zeroizing<String>) -> Result<(), SecretError> {
        validate_project_name(project)?;
        validate_secret_key_name(key)?;
        let mut guard = self
            .entries
            .write()
            .map_err(|_| SecretError::VaultLocked("in-memory secret store lock poisoned".into()))?;
        guard
            .entry(project.to_owned())
            .or_default()
            .insert(key.to_owned(), value);
        Ok(())
    }

    fn delete(&self, project: &str, key: &str) -> Result<(), SecretError> {
        validate_project_name(project)?;
        validate_secret_key_name(key)?;
        let mut guard = self
            .entries
            .write()
            .map_err(|_| SecretError::VaultLocked("in-memory secret store lock poisoned".into()))?;
        if let Some(proj_map) = guard.get_mut(project) {
            proj_map.remove(key);
        }
        Ok(())
    }

    fn list_keys(&self, project: &str) -> Result<Vec<String>, SecretError> {
        validate_project_name(project)?;
        let guard = self
            .entries
            .read()
            .map_err(|_| SecretError::VaultLocked("in-memory secret store lock poisoned".into()))?;
        Ok(guard
            .get(project)
            .map(|proj_map| proj_map.keys().cloned().collect())
            .unwrap_or_default())
    }
}

/// Validates that a project name is non-empty and safe to use in file paths (single normal segment).
pub(crate) fn validate_project_name(project: &str) -> Result<(), SecretError> {
    if project.is_empty()
        || project.contains('/')
        || project.contains('\\')
        || project.contains('\0')
        || project.chars().any(char::is_whitespace)
    {
        return Err(SecretError::InvalidPlaceholder(format!(
            "invalid project name '{project}'"
        )));
    }
    let mut components = Path::new(project).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(SecretError::InvalidPlaceholder(format!(
            "invalid project name '{project}'"
        ))),
    }
}

/// Validates that a secret key name matches `[A-Z0-9_]+`.
pub(crate) fn validate_secret_key_name(key: &str) -> Result<(), SecretError> {
    if key.is_empty()
        || !key
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(SecretError::InvalidPlaceholder(format!(
            "invalid secret key '{key}'; expected [A-Z0-9_]+"
        )));
    }
    Ok(())
}

/// Resolves the default `~/.anvil/vault` directory using `dirs::home_dir()`.
pub(crate) fn default_vault_dir() -> Result<std::path::PathBuf, SecretError> {
    let home = dirs::home_dir().ok_or_else(|| {
        SecretError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "could not determine user home directory",
        ))
    })?;
    Ok(home.join(".anvil").join("vault"))
}

/// Atomically writes `bytes` to `target` via a sibling temporary file with `0600` Unix permissions.
pub(crate) fn atomic_write_restricted(target: &Path, bytes: &[u8]) -> Result<(), SecretError> {
    use rand::RngCore;
    use std::fs::{self, OpenOptions};
    use std::io::Write;

    let parent = target.parent().ok_or_else(|| {
        SecretError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "target path has no parent directory",
        ))
    })?;
    fs::create_dir_all(parent)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }

    let mut suffix = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let tmp_name = format!(
        ".{}.tmp.{:016x}",
        target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("anvil"),
        u64::from_le_bytes(suffix)
    );
    let tmp_path = parent.join(tmp_name);

    let write_result = (|| -> Result<(), SecretError> {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    })();

    if let Err(err) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = fs::rename(&tmp_path, target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(SecretError::Io(err));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_value_redacts_debug_and_display() {
        let secret = SecretValue::new("super_secret_token_123");
        assert_eq!(secret.as_str(), "super_secret_token_123");
        assert_eq!(format!("{secret:?}"), "SecretValue([REDACTED])");
        assert_eq!(format!("{secret}"), "[REDACTED]");
        assert!(!format!("{secret:?}").contains("super_secret_token_123"));
        assert!(!format!("{secret}").contains("super_secret_token_123"));
    }

    #[test]
    fn in_memory_store_round_trip_and_redacted_debug() {
        let store = InMemorySecretStore::new();
        store
            .set("demo", "DB_PASSWORD", Zeroizing::new("hunter2".into()))
            .unwrap();
        store
            .set("demo", "API_KEY", Zeroizing::new("tok_live_999".into()))
            .unwrap();

        let dbg = format!("{store:?}");
        assert!(dbg.contains("DB_PASSWORD"));
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("hunter2"));
        assert!(!dbg.contains("tok_live_999"));

        assert_eq!(
            store.get("demo", "DB_PASSWORD").unwrap().as_deref().map(String::as_str),
            Some("hunter2")
        );
        assert_eq!(
            store.list_keys("demo").unwrap(),
            vec!["API_KEY".to_string(), "DB_PASSWORD".to_string()]
        );

        store.delete("demo", "DB_PASSWORD").unwrap();
        assert!(store.get("demo", "DB_PASSWORD").unwrap().is_none());
        assert_eq!(store.list_keys("demo").unwrap(), vec!["API_KEY".to_string()]);
    }
}
