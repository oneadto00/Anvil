//! Local AES-256-GCM + Argon2id encrypted vault fallback for headless environments.

use crate::error::SecretError;
use crate::{
    atomic_write_restricted, default_vault_dir, validate_project_name, validate_secret_key_name,
    SecretBackend,
};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use zeroize::Zeroizing;

const ENVELOPE_VERSION: u8 = 1;
const KDF_NAME: &str = "argon2id";
const CIPHER_NAME: &str = "aes-256-gcm";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// On-disk encrypted envelope stored at `~/.anvil/vault/<project>.vault.enc`.
#[derive(Debug, Serialize, Deserialize)]
struct VaultEnvelope {
    version: u8,
    kdf: String,
    cipher: String,
    salt_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
}

/// Decrypted secret map serialized inside the authenticated ciphertext.
#[derive(Default, Serialize, Deserialize)]
struct VaultPayload {
    secrets: BTreeMap<String, Zeroizing<String>>,
}

/// Local encrypted vault storing per-project secrets at `~/.anvil/vault/<project>.vault.enc`.
///
/// Uses Argon2id with a random 16-byte salt to derive a 256-bit key from the user passphrase,
/// and AES-256-GCM with a fresh random 12-byte nonce per write. Writes are atomic and restricted
/// to `0600` permissions on Unix systems.
pub struct LocalEncryptedVault {
    vault_dir: PathBuf,
    passphrase: Mutex<Option<Zeroizing<String>>>,
    io_lock: Mutex<()>,
}

impl LocalEncryptedVault {
    /// Creates an unlocked [`LocalEncryptedVault`] backed by `~/.anvil/vault`.
    pub fn new(passphrase: Zeroizing<String>) -> Result<Self, SecretError> {
        let dir = default_vault_dir()?;
        Ok(Self::with_dir(dir, passphrase))
    }

    /// Creates a locked [`LocalEncryptedVault`] backed by `~/.anvil/vault`.
    pub fn locked() -> Result<Self, SecretError> {
        let dir = default_vault_dir()?;
        Ok(Self::locked_with_dir(dir))
    }

    /// Creates an unlocked [`LocalEncryptedVault`] backed by a custom directory.
    pub fn with_dir(vault_dir: impl Into<PathBuf>, passphrase: Zeroizing<String>) -> Self {
        Self {
            vault_dir: vault_dir.into(),
            passphrase: Mutex::new(Some(passphrase)),
            io_lock: Mutex::new(()),
        }
    }

    /// Creates a locked [`LocalEncryptedVault`] backed by a custom directory.
    pub fn locked_with_dir(vault_dir: impl Into<PathBuf>) -> Self {
        Self {
            vault_dir: vault_dir.into(),
            passphrase: Mutex::new(None),
            io_lock: Mutex::new(()),
        }
    }

    /// Unlocks this vault instance in memory with the supplied passphrase.
    pub fn unlock(&self, passphrase: Zeroizing<String>) -> Result<(), SecretError> {
        let mut guard = self
            .passphrase
            .lock()
            .map_err(|_| SecretError::VaultLocked("vault passphrase lock poisoned".into()))?;
        *guard = Some(passphrase);
        Ok(())
    }

    /// Clears and zeroizes the in-memory passphrase, returning the vault to the locked state.
    pub fn lock(&self) -> Result<(), SecretError> {
        let mut guard = self
            .passphrase
            .lock()
            .map_err(|_| SecretError::VaultLocked("vault passphrase lock poisoned".into()))?;
        *guard = None;
        Ok(())
    }

    /// Returns the vault file path `<vault_dir>/<project>.vault.enc` for `project`.
    pub fn vault_path(&self, project: &str) -> Result<PathBuf, SecretError> {
        validate_project_name(project)?;
        Ok(self.vault_dir.join(format!("{project}.vault.enc")))
    }

    fn active_passphrase(&self) -> Result<Zeroizing<String>, SecretError> {
        let guard = self
            .passphrase
            .lock()
            .map_err(|_| SecretError::VaultLocked("vault passphrase lock poisoned".into()))?;
        guard.clone().ok_or_else(|| {
            SecretError::VaultLocked("vault passphrase is required to unlock vault".to_string())
        })
    }

    fn load_payload(
        path: &Path,
        passphrase: &Zeroizing<String>,
    ) -> Result<Option<VaultPayload>, SecretError> {
        let raw = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(SecretError::Io(err)),
        };

        let envelope: VaultEnvelope = serde_json::from_slice(&raw)
            .map_err(|err| SecretError::CryptoError(format!("malformed vault envelope: {err}")))?;

        if envelope.version != ENVELOPE_VERSION
            || envelope.kdf != KDF_NAME
            || envelope.cipher != CIPHER_NAME
        {
            return Err(SecretError::CryptoError(
                "unsupported vault version or cryptographic parameters".to_string(),
            ));
        }

        let salt_bytes = BASE64
            .decode(envelope.salt_b64.as_bytes())
            .map_err(|err| SecretError::CryptoError(format!("invalid vault salt: {err}")))?;
        if salt_bytes.len() != SALT_LEN {
            return Err(SecretError::CryptoError(format!(
                "invalid vault salt length: expected {SALT_LEN}, got {}",
                salt_bytes.len()
            )));
        }

        let nonce_bytes = BASE64
            .decode(envelope.nonce_b64.as_bytes())
            .map_err(|err| SecretError::CryptoError(format!("invalid vault nonce: {err}")))?;
        if nonce_bytes.len() != NONCE_LEN {
            return Err(SecretError::CryptoError(format!(
                "invalid vault nonce length: expected {NONCE_LEN}, got {}",
                nonce_bytes.len()
            )));
        }

        let ciphertext = BASE64
            .decode(envelope.ciphertext_b64.as_bytes())
            .map_err(|err| SecretError::CryptoError(format!("invalid vault ciphertext: {err}")))?;

        let key = derive_key(passphrase, &salt_bytes)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|err| SecretError::CryptoError(format!("failed to init AES-GCM: {err}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = Zeroizing::new(cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| {
            SecretError::VaultLocked(
                "failed to decrypt vault (wrong passphrase or corrupted ciphertext)".to_string(),
            )
        })?);

        let payload: VaultPayload = serde_json::from_slice(plaintext.as_ref()).map_err(|err| {
            SecretError::CryptoError(format!("corrupted decrypted vault payload: {err}"))
        })?;

        Ok(Some(payload))
    }

    fn save_payload(
        path: &Path,
        passphrase: &Zeroizing<String>,
        payload: &VaultPayload,
    ) -> Result<(), SecretError> {
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);

        let key = derive_key(passphrase, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|err| SecretError::CryptoError(format!("failed to init AES-GCM: {err}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = Zeroizing::new(serde_json::to_vec(payload).map_err(|err| {
            SecretError::CryptoError(format!("failed to serialize vault payload: {err}"))
        })?);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|err| SecretError::CryptoError(format!("failed to encrypt vault: {err}")))?;

        let envelope = VaultEnvelope {
            version: ENVELOPE_VERSION,
            kdf: KDF_NAME.to_string(),
            cipher: CIPHER_NAME.to_string(),
            salt_b64: BASE64.encode(salt),
            nonce_b64: BASE64.encode(nonce_bytes),
            ciphertext_b64: BASE64.encode(ciphertext),
        };

        let encoded = serde_json::to_vec_pretty(&envelope).map_err(|err| {
            SecretError::CryptoError(format!("failed to encode vault envelope: {err}"))
        })?;

        atomic_write_restricted(path, &encoded)
    }
}

impl fmt::Debug for LocalEncryptedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = match self.passphrase.lock() {
            Ok(guard) if guard.is_some() => "[REDACTED]",
            Ok(_) => "<locked>",
            Err(_) => "<poisoned>",
        };
        f.debug_struct("LocalEncryptedVault")
            .field("vault_dir", &self.vault_dir)
            .field("passphrase", &status)
            .finish()
    }
}

impl SecretBackend for LocalEncryptedVault {
    fn get(&self, project: &str, key: &str) -> Result<Option<Zeroizing<String>>, SecretError> {
        validate_secret_key_name(key)?;
        let path = self.vault_path(project)?;
        let passphrase = self.active_passphrase()?;
        let _guard = self
            .io_lock
            .lock()
            .map_err(|_| SecretError::VaultLocked("vault I/O lock poisoned".into()))?;
        let Some(payload) = Self::load_payload(&path, &passphrase)? else {
            return Ok(None);
        };
        Ok(payload.secrets.get(key).cloned())
    }

    fn set(&self, project: &str, key: &str, value: Zeroizing<String>) -> Result<(), SecretError> {
        validate_secret_key_name(key)?;
        let path = self.vault_path(project)?;
        let passphrase = self.active_passphrase()?;
        let _guard = self
            .io_lock
            .lock()
            .map_err(|_| SecretError::VaultLocked("vault I/O lock poisoned".into()))?;
        let mut payload = Self::load_payload(&path, &passphrase)?.unwrap_or_default();
        payload.secrets.insert(key.to_owned(), value);
        Self::save_payload(&path, &passphrase, &payload)
    }

    fn delete(&self, project: &str, key: &str) -> Result<(), SecretError> {
        validate_secret_key_name(key)?;
        let path = self.vault_path(project)?;
        let passphrase = self.active_passphrase()?;
        let _guard = self
            .io_lock
            .lock()
            .map_err(|_| SecretError::VaultLocked("vault I/O lock poisoned".into()))?;
        let Some(mut payload) = Self::load_payload(&path, &passphrase)? else {
            return Ok(());
        };
        if payload.secrets.remove(key).is_some() {
            Self::save_payload(&path, &passphrase, &payload)?;
        }
        Ok(())
    }

    fn list_keys(&self, project: &str) -> Result<Vec<String>, SecretError> {
        let path = self.vault_path(project)?;
        let passphrase = self.active_passphrase()?;
        let _guard = self
            .io_lock
            .lock()
            .map_err(|_| SecretError::VaultLocked("vault I/O lock poisoned".into()))?;
        let Some(payload) = Self::load_payload(&path, &passphrase)? else {
            return Ok(Vec::new());
        };
        Ok(payload.secrets.keys().cloned().collect())
    }
}

fn derive_key(
    passphrase: &Zeroizing<String>,
    salt: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, SecretError> {
    let params = Params::new(19_456, 2, 1, Some(KEY_LEN))
        .map_err(|err| SecretError::CryptoError(format!("invalid argon2 params: {err}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|err| SecretError::CryptoError(format!("argon2id derivation failed: {err}")))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn vault_round_trip_fresh_nonce_and_no_plaintext_on_disk() {
        let dir = TempDir::new().unwrap();
        let passphrase = Zeroizing::new("correct-horse-battery-staple".to_string());
        let vault = LocalEncryptedVault::with_dir(dir.path(), passphrase.clone());

        let secret_val = Zeroizing::new("pg_super_secret_pw_42".to_string());
        vault.set("nebula", "DB_PASSWORD", secret_val).unwrap();

        let vault_file = vault.vault_path("nebula").unwrap();
        assert!(vault_file.exists());
        let on_disk_1 = fs::read_to_string(&vault_file).unwrap();
        assert!(!on_disk_1.contains("pg_super_secret_pw_42"));
        assert!(!on_disk_1.contains("correct-horse-battery-staple"));

        let env_1: VaultEnvelope = serde_json::from_str(&on_disk_1).unwrap();

        vault
            .set("nebula", "JWT_KEY", Zeroizing::new("jwt_999".to_string()))
            .unwrap();
        let on_disk_2 = fs::read_to_string(&vault_file).unwrap();
        let env_2: VaultEnvelope = serde_json::from_str(&on_disk_2).unwrap();
        assert_ne!(env_1.nonce_b64, env_2.nonce_b64);
        assert_ne!(env_1.salt_b64, env_2.salt_b64);

        let reopened = LocalEncryptedVault::with_dir(dir.path(), passphrase);
        assert_eq!(
            reopened
                .get("nebula", "DB_PASSWORD")
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("pg_super_secret_pw_42")
        );
        assert_eq!(
            reopened.list_keys("nebula").unwrap(),
            vec!["DB_PASSWORD".to_string(), "JWT_KEY".to_string()]
        );

        reopened.delete("nebula", "DB_PASSWORD").unwrap();
        assert!(reopened.get("nebula", "DB_PASSWORD").unwrap().is_none());
        assert_eq!(
            reopened.list_keys("nebula").unwrap(),
            vec!["JWT_KEY".to_string()]
        );
    }

    #[test]
    fn wrong_passphrase_and_locked_vault_return_vault_locked() {
        let dir = TempDir::new().unwrap();
        let vault =
            LocalEncryptedVault::with_dir(dir.path(), Zeroizing::new("right-pass".to_string()));
        vault
            .set("proj", "API_KEY", Zeroizing::new("secret_val".to_string()))
            .unwrap();

        let wrong =
            LocalEncryptedVault::with_dir(dir.path(), Zeroizing::new("wrong-pass".to_string()));
        assert!(matches!(
            wrong.get("proj", "API_KEY"),
            Err(SecretError::VaultLocked(_))
        ));

        let locked = LocalEncryptedVault::locked_with_dir(dir.path());
        assert!(matches!(
            locked.get("proj", "API_KEY"),
            Err(SecretError::VaultLocked(_))
        ));

        locked
            .unlock(Zeroizing::new("right-pass".to_string()))
            .unwrap();
        assert_eq!(
            locked
                .get("proj", "API_KEY")
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("secret_val")
        );
        locked.lock().unwrap();
        assert!(matches!(
            locked.list_keys("proj"),
            Err(SecretError::VaultLocked(_))
        ));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let dir = TempDir::new().unwrap();
        let vault = LocalEncryptedVault::with_dir(dir.path(), Zeroizing::new("pass".to_string()));
        vault
            .set("proj", "TOKEN", Zeroizing::new("val".to_string()))
            .unwrap();

        let path = vault.vault_path("proj").unwrap();
        let mut envelope: VaultEnvelope =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let mut ct = BASE64.decode(envelope.ciphertext_b64.as_bytes()).unwrap();
        ct[0] ^= 0xff;
        envelope.ciphertext_b64 = BASE64.encode(ct);
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

        assert!(matches!(
            vault.get("proj", "TOKEN"),
            Err(SecretError::VaultLocked(_))
        ));
    }

    #[test]
    fn vault_debug_redacts_passphrase() {
        let dir = TempDir::new().unwrap();
        let vault = LocalEncryptedVault::with_dir(
            dir.path(),
            Zeroizing::new("super-secret-passphrase".to_string()),
        );
        let dbg = format!("{vault:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("super-secret-passphrase"));
    }

    #[cfg(unix)]
    #[test]
    fn vault_file_permissions_are_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let vault = LocalEncryptedVault::with_dir(dir.path(), Zeroizing::new("pass".to_string()));
        vault
            .set("proj", "KEY_A", Zeroizing::new("secret".to_string()))
            .unwrap();

        let mode = fs::metadata(vault.vault_path("proj").unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
