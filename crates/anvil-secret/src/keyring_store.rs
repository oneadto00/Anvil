//! OS native keyring integration (`KeyringStore`) with a key-only sidecar index.

use crate::error::SecretError;
use crate::{
    atomic_write_restricted, default_vault_dir, validate_project_name, validate_secret_key_name,
    SecretBackend,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use zeroize::Zeroizing;

/// Sidecar index storing only key names (never secret values) for [`KeyringStore::list_keys`].
#[derive(Debug, Default, Serialize, Deserialize)]
struct KeyIndexFile {
    version: u8,
    keys: BTreeSet<String>,
}

/// Secret backend backed by the operating system's native credential store via `keyring`.
///
/// Because `keyring` does not natively support enumerating keys under a service name across all
/// platforms, `KeyringStore` maintains a small key-name-only sidecar JSON index at
/// `<index_dir>/<project>.keys.json` (defaulting to `~/.anvil/vault/<project>.keys.json`).
/// Secret values themselves are never written to the sidecar file.
pub struct KeyringStore {
    index_dir: PathBuf,
    index_lock: Mutex<()>,
}

impl KeyringStore {
    /// Creates a [`KeyringStore`] storing its key-name index under `~/.anvil/vault`.
    pub fn new() -> Result<Self, SecretError> {
        let dir = default_vault_dir()?;
        Ok(Self::with_index_dir(dir))
    }

    /// Creates a [`KeyringStore`] with an explicit directory for the key-name sidecar index.
    pub fn with_index_dir(index_dir: impl Into<PathBuf>) -> Self {
        Self {
            index_dir: index_dir.into(),
            index_lock: Mutex::new(()),
        }
    }

    /// Returns the path to the key-name sidecar index file for `project`.
    pub fn index_path(&self, project: &str) -> Result<PathBuf, SecretError> {
        validate_project_name(project)?;
        Ok(self.index_dir.join(format!("{project}.keys.json")))
    }

    /// Returns the `keyring` service name used for `project`.
    fn service_name(project: &str) -> String {
        format!("anvil:{project}")
    }

    fn build_entry(project: &str, key: &str) -> Result<keyring::Entry, SecretError> {
        validate_project_name(project)?;
        validate_secret_key_name(key)?;
        keyring::Entry::new(&Self::service_name(project), key).map_err(map_keyring_error)
    }

    fn update_index(&self, project: &str, key: &str, insert: bool) -> Result<(), SecretError> {
        let _guard = self
            .index_lock
            .lock()
            .map_err(|_| SecretError::KeyringUnavailable("keyring index lock poisoned".into()))?;
        let path = self.index_path(project)?;
        let mut index = read_index(&path)?;
        index.version = 1;
        if insert {
            index.keys.insert(key.to_owned());
        } else {
            index.keys.remove(key);
        }
        let encoded = serde_json::to_vec_pretty(&index).map_err(|err| {
            SecretError::CryptoError(format!("failed to serialize keyring key index: {err}"))
        })?;
        atomic_write_restricted(&path, &encoded)
    }
}

impl fmt::Debug for KeyringStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyringStore")
            .field("index_dir", &self.index_dir)
            .finish()
    }
}

impl SecretBackend for KeyringStore {
    fn get(&self, project: &str, key: &str) -> Result<Option<Zeroizing<String>>, SecretError> {
        let entry = Self::build_entry(project, key)?;
        match entry.get_password() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(map_keyring_error(err)),
        }
    }

    fn set(&self, project: &str, key: &str, value: Zeroizing<String>) -> Result<(), SecretError> {
        let entry = Self::build_entry(project, key)?;
        entry
            .set_password(value.as_str())
            .map_err(map_keyring_error)?;
        self.update_index(project, key, true)
    }

    fn delete(&self, project: &str, key: &str) -> Result<(), SecretError> {
        let entry = Self::build_entry(project, key)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => self.update_index(project, key, false),
            Err(err) => Err(map_keyring_error(err)),
        }
    }

    fn list_keys(&self, project: &str) -> Result<Vec<String>, SecretError> {
        let _guard = self
            .index_lock
            .lock()
            .map_err(|_| SecretError::KeyringUnavailable("keyring index lock poisoned".into()))?;
        let path = self.index_path(project)?;
        let index = read_index(&path)?;
        Ok(index.keys.into_iter().collect())
    }
}

fn read_index(path: &Path) -> Result<KeyIndexFile, SecretError> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<KeyIndexFile>(&bytes).map_err(|err| {
            SecretError::CryptoError(format!("failed to parse keyring key index: {err}"))
        }),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(KeyIndexFile {
            version: 1,
            keys: BTreeSet::new(),
        }),
        Err(err) => Err(SecretError::Io(err)),
    }
}

fn map_keyring_error(err: keyring::Error) -> SecretError {
    match err {
        keyring::Error::BadEncoding(_) => SecretError::KeyringUnavailable(
            "keyring entry contains invalid UTF-8 bytes".to_string(),
        ),
        keyring::Error::NoStorageAccess(inner) => {
            SecretError::KeyringUnavailable(format!("no keyring storage access: {inner}"))
        }
        keyring::Error::PlatformFailure(inner) => {
            SecretError::KeyringUnavailable(format!("platform keyring failure: {inner}"))
        }
        other => SecretError::KeyringUnavailable(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn sidecar_index_tracks_keys_without_writing_secrets() {
        let dir = TempDir::new().unwrap();
        let store = KeyringStore::with_index_dir(dir.path());
        store.update_index("proj-a", "DB_PASS", true).unwrap();
        store.update_index("proj-a", "API_KEY", true).unwrap();
        assert_eq!(
            store.list_keys("proj-a").unwrap(),
            vec!["API_KEY".to_string(), "DB_PASS".to_string()]
        );

        let raw_index = fs::read_to_string(store.index_path("proj-a").unwrap()).unwrap();
        assert!(raw_index.contains("DB_PASS"));
        assert!(raw_index.contains("API_KEY"));

        store.update_index("proj-a", "DB_PASS", false).unwrap();
        assert_eq!(
            store.list_keys("proj-a").unwrap(),
            vec!["API_KEY".to_string()]
        );
    }

    #[test]
    fn keyring_store_debug_is_safe_and_handles_missing_index() {
        let dir = TempDir::new().unwrap();
        let store = KeyringStore::with_index_dir(dir.path());
        assert!(store.list_keys("empty-proj").unwrap().is_empty());
        let dbg = format!("{store:?}");
        assert!(dbg.contains("KeyringStore"));
    }

    #[test]
    fn keyring_store_rejects_invalid_identifiers() {
        let dir = TempDir::new().unwrap();
        let store = KeyringStore::with_index_dir(dir.path());
        assert!(matches!(
            store.get("../escape", "KEY"),
            Err(SecretError::InvalidPlaceholder(_))
        ));
        assert!(matches!(
            store.set("valid", "lowercase", Zeroizing::new("x".into())),
            Err(SecretError::InvalidPlaceholder(_))
        ));
    }
}
