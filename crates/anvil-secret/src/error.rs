//! Structured error definitions for `anvil-secret`.

use thiserror::Error;

/// Errors returned by secret storage backends and placeholder resolution.
#[derive(Debug, Error)]
pub enum SecretError {
    /// The operating system keyring / keychain service is unavailable or failed.
    #[error("OS keyring is unavailable: {0}")]
    KeyringUnavailable(String),

    /// The local encrypted fallback vault is locked, missing a passphrase, or failed authentication.
    #[error("encrypted vault is locked or passphrase is invalid: {0}")]
    VaultLocked(String),

    /// A cryptographic, encoding, or envelope format error occurred.
    #[error("cryptographic or vault format error: {0}")]
    CryptoError(String),

    /// A referenced secret key could not be found in the active backend.
    #[error("secret '{key}' was not found")]
    SecretNotFound {
        /// The missing secret key name.
        key: String,
    },

    /// A `${SECRET:...}` placeholder or project/key identifier is syntactically invalid.
    #[error("invalid secret placeholder or identifier: {0}")]
    InvalidPlaceholder(String),

    /// An underlying filesystem I/O error occurred while reading or persisting vault metadata.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
