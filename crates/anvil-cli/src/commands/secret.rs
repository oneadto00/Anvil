//! `anvil secret` subcommand implementation with OS keyring and Argon2id/AES-GCM fallback.

use crate::args::{GlobalOptions, SecretCommand};
use anvil_core::AnvilConfig;
use anvil_secret::{KeyringStore, LocalEncryptedVault, SecretBackend, SecretError};
use anyhow::Context;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Component, Path, PathBuf};
use tokio::task::spawn_blocking;
use zeroize::Zeroizing;

const PASSPHRASE_ENV: &str = "ANVIL_VAULT_PASSPHRASE";

/// Outcome of inspecting declared secrets for `anvil doctor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecretPresenceAudit {
    pub(crate) statuses: Vec<(String, bool)>,
    pub(crate) backend_notice: Option<String>,
}

/// Executes the `anvil secret` subcommand using standard terminal/pipe I/O.
pub async fn run(globals: &GlobalOptions, action: SecretCommand) -> anyhow::Result<()> {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    run_with_io(globals, action, None, None, &mut stdout, &mut stderr).await
}

pub(crate) async fn resolve_data_dir(globals: &GlobalOptions) -> anyhow::Result<PathBuf> {
    if let Some(dir) = &globals.data_dir {
        return Ok(dir.clone());
    }
    let home = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("could not determine user home directory"))?;
    Ok(home.join(".anvil"))
}

pub(crate) fn vault_dir_for(data_dir: &Path) -> PathBuf {
    data_dir.join("vault")
}

pub(crate) async fn resolve_project_name(globals: &GlobalOptions) -> anyhow::Result<String> {
    if let Some(project) = &globals.project {
        validate_project_identifier(project)?;
        return Ok(project.clone());
    }

    let config_path = globals.config.clone();
    let config = spawn_blocking(move || AnvilConfig::from_file(&config_path))
        .await
        .context("configuration loader task failed")?
        .with_context(|| {
            format!(
                "failed to resolve project name from {} (or specify --project)",
                globals.config.display()
            )
        })?;
    Ok(config.project.name)
}

pub(crate) async fn check_declared_secrets(
    project: &str,
    keys: &[String],
    vault_dir: &Path,
    passphrase_override: Option<Zeroizing<String>>,
) -> anyhow::Result<SecretPresenceAudit> {
    validate_project_identifier(project)?;
    for key in keys {
        validate_secret_key(key)?;
    }
    if keys.is_empty() {
        return Ok(SecretPresenceAudit {
            statuses: Vec::new(),
            backend_notice: None,
        });
    }

    let project_owned = project.to_owned();
    let keys_owned = keys.to_vec();
    let vault_dir_owned = vault_dir.to_path_buf();

    let (statuses, fallback_reason) = spawn_blocking(move || -> anyhow::Result<_> {
        let keyring = KeyringStore::with_index_dir(&vault_dir_owned);
        let index_path = keyring.index_path(&project_owned)?;
        let vault_path = vault_dir_owned.join(format!("{project_owned}.vault.enc"));

        if !index_path.exists() && vault_path.exists() {
            return Ok((
                Vec::new(),
                Some("using local encrypted vault for project".to_owned()),
            ));
        }

        let mut results = Vec::with_capacity(keys_owned.len());
        for key in &keys_owned {
            match keyring.get(&project_owned, key) {
                Ok(found) => {
                    // Drop Zeroizing<String> immediately; only presence boolean escapes.
                    let exists = found.is_some();
                    drop(found);
                    results.push((key.clone(), exists));
                }
                Err(SecretError::KeyringUnavailable(reason)) => {
                    return Ok((Vec::new(), Some(reason)));
                }
                Err(err) => return Err(err.into()),
            }
        }

        if results.iter().any(|(_, exists)| !*exists) && vault_path.exists() {
            return Ok((results, Some("checking fallback encrypted vault".to_owned())));
        }

        Ok((results, None))
    })
    .await
    .context("secret inspection task failed")??;

    let Some(reason) = fallback_reason else {
        return Ok(SecretPresenceAudit {
            statuses,
            backend_notice: None,
        });
    };

    let vault_path = vault_dir.join(format!("{project}.vault.enc"));
    if !vault_path.exists() {
        let missing_statuses = keys.iter().map(|k| (k.clone(), false)).collect();
        return Ok(SecretPresenceAudit {
            statuses: missing_statuses,
            backend_notice: Some(format!(
                "OS keyring unavailable ({reason}); no fallback vault found at {}",
                vault_path.display()
            )),
        });
    }

    let passphrase = acquire_passphrase(passphrase_override).await?;
    let project_owned = project.to_owned();
    let keys_owned = keys.to_vec();
    let vault_dir_owned = vault_dir.to_path_buf();

    let merged = spawn_blocking(move || -> anyhow::Result<Vec<(String, bool)>> {
        let vault = LocalEncryptedVault::with_dir(&vault_dir_owned, passphrase);
        if statuses.is_empty() {
            let mut out = Vec::with_capacity(keys_owned.len());
            for key in &keys_owned {
                let exists = {
                    let found = vault.get(&project_owned, key)?;
                    found.is_some()
                };
                out.push((key.clone(), exists));
            }
            Ok(out)
        } else {
            let mut out = Vec::with_capacity(statuses.len());
            for (key, in_keyring) in statuses {
                if in_keyring {
                    out.push((key, true));
                } else {
                    let exists = {
                        let found = vault.get(&project_owned, &key)?;
                        found.is_some()
                    };
                    out.push((key, exists));
                }
            }
            Ok(out)
        }
    })
    .await
    .context("vault inspection task failed")??;

    Ok(SecretPresenceAudit {
        statuses: merged,
        backend_notice: Some(reason),
    })
}

async fn run_with_io(
    globals: &GlobalOptions,
    action: SecretCommand,
    secret_input_override: Option<Zeroizing<Vec<u8>>>,
    passphrase_override: Option<Zeroizing<String>>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> anyhow::Result<()> {
    match action {
        SecretCommand::Set { key, vault, stdin } => {
            validate_secret_key(&key)?;
            let project = resolve_project_name(globals).await?;
            let data_dir = resolve_data_dir(globals).await?;
            let vault_dir = vault_dir_for(&data_dir);
            let value = read_secret_input(&key, stdin, secret_input_override).await?;

            let backend_used = set_secret(
                &project,
                &key,
                value,
                &vault_dir,
                vault,
                passphrase_override,
                stderr,
            )
            .await?;

            writeln!(
                stdout,
                "Stored secret '{key}' for project '{project}' ({backend_used})."
            )?;
            stdout.flush()?;
            Ok(())
        }
        SecretCommand::Get { key, vault } => {
            validate_secret_key(&key)?;
            let project = resolve_project_name(globals).await?;
            let data_dir = resolve_data_dir(globals).await?;
            let vault_dir = vault_dir_for(&data_dir);

            let maybe_secret =
                get_secret(&project, &key, &vault_dir, vault, passphrase_override, stderr).await?;

            match maybe_secret {
                Some(secret) => {
                    writeln!(stdout, "{}", secret.as_str())?;
                    stdout.flush()?;
                    Ok(())
                }
                None => anyhow::bail!("secret '{key}' was not found for project '{project}'"),
            }
        }
        SecretCommand::List { vault } => {
            let project = resolve_project_name(globals).await?;
            let data_dir = resolve_data_dir(globals).await?;
            let vault_dir = vault_dir_for(&data_dir);

            let mut keys =
                list_secret_keys(&project, &vault_dir, vault, passphrase_override, stderr).await?;
            keys.sort();
            keys.dedup();

            for key in &keys {
                writeln!(stdout, "{key}")?;
            }
            if keys.is_empty() {
                writeln!(stderr, "No secrets stored for project '{project}'.")?;
            }
            stdout.flush()?;
            stderr.flush()?;
            Ok(())
        }
        SecretCommand::Delete { key, vault } => {
            validate_secret_key(&key)?;
            let project = resolve_project_name(globals).await?;
            let data_dir = resolve_data_dir(globals).await?;
            let vault_dir = vault_dir_for(&data_dir);

            let backend_used = delete_secret(
                &project,
                &key,
                &vault_dir,
                vault,
                passphrase_override,
                stderr,
            )
            .await?;

            writeln!(
                stdout,
                "Deleted secret '{key}' for project '{project}' ({backend_used})."
            )?;
            stdout.flush()?;
            Ok(())
        }
    }
}

async fn set_secret(
    project: &str,
    key: &str,
    value: Zeroizing<String>,
    vault_dir: &Path,
    force_vault: bool,
    passphrase_override: Option<Zeroizing<String>>,
    stderr: &mut dyn Write,
) -> anyhow::Result<&'static str> {
    if !force_vault {
        let project_owned = project.to_owned();
        let key_owned = key.to_owned();
        let vault_dir_owned = vault_dir.to_path_buf();
        let keyring_value = value.clone();

        let keyring_res = spawn_blocking(move || {
            let store = KeyringStore::with_index_dir(&vault_dir_owned);
            store.set(&project_owned, &key_owned, keyring_value)
        })
        .await
        .context("keyring set task failed")?;

        match keyring_res {
            Ok(()) => return Ok("OS keyring"),
            Err(SecretError::KeyringUnavailable(reason)) => {
                writeln!(
                    stderr,
                    "OS keyring unavailable ({reason}); falling back to encrypted vault."
                )?;
                stderr.flush()?;
            }
            Err(err) => return Err(err.into()),
        }
    }

    let passphrase = acquire_passphrase(passphrase_override).await?;
    let project_owned = project.to_owned();
    let key_owned = key.to_owned();
    let vault_dir_owned = vault_dir.to_path_buf();

    spawn_blocking(move || {
        let vault = LocalEncryptedVault::with_dir(&vault_dir_owned, passphrase);
        vault.set(&project_owned, &key_owned, value)
    })
    .await
    .context("vault set task failed")??;

    Ok("encrypted vault")
}

async fn get_secret(
    project: &str,
    key: &str,
    vault_dir: &Path,
    force_vault: bool,
    passphrase_override: Option<Zeroizing<String>>,
    stderr: &mut dyn Write,
) -> anyhow::Result<Option<Zeroizing<String>>> {
    let vault_file = vault_dir.join(format!("{project}.vault.enc"));

    if !force_vault {
        let project_owned = project.to_owned();
        let key_owned = key.to_owned();
        let vault_dir_owned = vault_dir.to_path_buf();

        let (result, has_index) = spawn_blocking(move || {
            let store = KeyringStore::with_index_dir(&vault_dir_owned);
            let has_index = store
                .index_path(&project_owned)
                .map(|p| p.exists())
                .unwrap_or(false);
            (store.get(&project_owned, &key_owned), has_index)
        })
        .await
        .context("keyring get task failed")?;

        match result {
            Ok(Some(secret)) => return Ok(Some(secret)),
            Ok(None) => {
                if has_index || !vault_file.exists() {
                    return Ok(None);
                }
            }
            Err(SecretError::KeyringUnavailable(reason)) => {
                writeln!(
                    stderr,
                    "OS keyring unavailable ({reason}); falling back to encrypted vault."
                )?;
                stderr.flush()?;
            }
            Err(err) => return Err(err.into()),
        }
    }

    if !vault_file.exists() {
        return Ok(None);
    }

    let passphrase = acquire_passphrase(passphrase_override).await?;
    let project_owned = project.to_owned();
    let key_owned = key.to_owned();
    let vault_dir_owned = vault_dir.to_path_buf();

    let secret = spawn_blocking(move || {
        let vault = LocalEncryptedVault::with_dir(&vault_dir_owned, passphrase);
        vault.get(&project_owned, &key_owned)
    })
    .await
    .context("vault get task failed")??;

    Ok(secret)
}

async fn list_secret_keys(
    project: &str,
    vault_dir: &Path,
    force_vault: bool,
    passphrase_override: Option<Zeroizing<String>>,
    stderr: &mut dyn Write,
) -> anyhow::Result<Vec<String>> {
    let vault_file = vault_dir.join(format!("{project}.vault.enc"));

    if !force_vault {
        let project_owned = project.to_owned();
        let vault_dir_owned = vault_dir.to_path_buf();

        let (result, has_index) = spawn_blocking(move || {
            let store = KeyringStore::with_index_dir(&vault_dir_owned);
            let has_index = store
                .index_path(&project_owned)
                .map(|p| p.exists())
                .unwrap_or(false);
            (store.list_keys(&project_owned), has_index)
        })
        .await
        .context("keyring list task failed")?;

        match result {
            Ok(keys) if !keys.is_empty() || has_index || !vault_file.exists() => return Ok(keys),
            Ok(_) => {}
            Err(SecretError::KeyringUnavailable(reason)) => {
                writeln!(
                    stderr,
                    "OS keyring unavailable ({reason}); falling back to encrypted vault."
                )?;
                stderr.flush()?;
            }
            Err(err) => return Err(err.into()),
        }
    }

    if !vault_file.exists() {
        return Ok(Vec::new());
    }

    let passphrase = acquire_passphrase(passphrase_override).await?;
    let project_owned = project.to_owned();
    let vault_dir_owned = vault_dir.to_path_buf();

    let keys = spawn_blocking(move || {
        let vault = LocalEncryptedVault::with_dir(&vault_dir_owned, passphrase);
        vault.list_keys(&project_owned)
    })
    .await
    .context("vault list task failed")??;

    Ok(keys)
}

async fn delete_secret(
    project: &str,
    key: &str,
    vault_dir: &Path,
    force_vault: bool,
    passphrase_override: Option<Zeroizing<String>>,
    stderr: &mut dyn Write,
) -> anyhow::Result<&'static str> {
    let vault_file = vault_dir.join(format!("{project}.vault.enc"));

    if !force_vault {
        let project_owned = project.to_owned();
        let key_owned = key.to_owned();
        let vault_dir_owned = vault_dir.to_path_buf();
        let vault_exists = vault_file.exists();

        let outcome = spawn_blocking(move || {
            let store = KeyringStore::with_index_dir(&vault_dir_owned);
            let has_index = store
                .index_path(&project_owned)
                .map(|p| p.exists())
                .unwrap_or(false);
            if !has_index && vault_exists {
                return Ok(None);
            }
            store.delete(&project_owned, &key_owned).map(Some)
        })
        .await
        .context("keyring delete task failed")?;

        match outcome {
            Ok(Some(())) => return Ok("OS keyring"),
            Ok(None) => {}
            Err(SecretError::KeyringUnavailable(reason)) => {
                writeln!(
                    stderr,
                    "OS keyring unavailable ({reason}); falling back to encrypted vault."
                )?;
                stderr.flush()?;
            }
            Err(err) => return Err(err.into()),
        }
    }

    if !vault_file.exists() {
        return Ok("encrypted vault");
    }

    let passphrase = acquire_passphrase(passphrase_override).await?;
    let project_owned = project.to_owned();
    let key_owned = key.to_owned();
    let vault_dir_owned = vault_dir.to_path_buf();

    spawn_blocking(move || {
        let vault = LocalEncryptedVault::with_dir(&vault_dir_owned, passphrase);
        vault.delete(&project_owned, &key_owned)
    })
    .await
    .context("vault delete task failed")??;

    Ok("encrypted vault")
}

async fn acquire_passphrase(
    passphrase_override: Option<Zeroizing<String>>,
) -> anyhow::Result<Zeroizing<String>> {
    if let Some(passphrase) = passphrase_override {
        if passphrase.is_empty() {
            anyhow::bail!("vault passphrase cannot be empty");
        }
        return Ok(passphrase);
    }

    match std::env::var(PASSPHRASE_ENV) {
        Ok(val) => {
            let pass = Zeroizing::new(val);
            if pass.is_empty() {
                anyhow::bail!("{PASSPHRASE_ENV} must not be empty");
            }
            return Ok(pass);
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("{PASSPHRASE_ENV} contains invalid UTF-8");
        }
        Err(std::env::VarError::NotPresent) => {}
    }

    spawn_blocking(|| -> anyhow::Result<Zeroizing<String>> {
        let pass = Zeroizing::new(
            rpassword::prompt_password("Enter vault passphrase: ")
                .context("failed to read vault passphrase from terminal")?,
        );
        if pass.is_empty() {
            anyhow::bail!("vault passphrase cannot be empty");
        }
        Ok(pass)
    })
    .await
    .context("passphrase prompt task failed")?
}

async fn read_secret_input(
    key: &str,
    force_stdin: bool,
    secret_input_override: Option<Zeroizing<Vec<u8>>>,
) -> anyhow::Result<Zeroizing<String>> {
    if let Some(bytes) = secret_input_override {
        let mut cursor = io::Cursor::new(bytes.as_slice());
        return read_secret_from_reader(&mut cursor);
    }

    let key_owned = key.to_owned();
    spawn_blocking(move || -> anyhow::Result<Zeroizing<String>> {
        if force_stdin || !io::stdin().is_terminal() {
            let mut stdin = io::stdin().lock();
            read_secret_from_reader(&mut stdin)
        } else {
            let prompt = format!("Enter secret value for '{key_owned}': ");
            let value = Zeroizing::new(
                rpassword::prompt_password(prompt)
                    .context("failed to read secret value from terminal")?,
            );
            Ok(value)
        }
    })
    .await
    .context("secret input task failed")?
}

fn read_secret_from_reader<R: Read>(reader: &mut R) -> anyhow::Result<Zeroizing<String>> {
    let mut value = Zeroizing::new(String::new());
    reader
        .read_to_string(&mut value)
        .context("failed to read secret value from standard input")?;
    while value.ends_with(['\r', '\n']) {
        value.pop();
    }
    Ok(value)
}

fn validate_project_identifier(project: &str) -> anyhow::Result<()> {
    if project.is_empty()
        || project.contains('/')
        || project.contains('\\')
        || project.contains('\0')
        || project.chars().any(char::is_whitespace)
    {
        anyhow::bail!("invalid project name '{project}'");
    }
    let mut components = Path::new(project).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => anyhow::bail!("invalid project name '{project}'"),
    }
}

fn validate_secret_key(key: &str) -> anyhow::Result<()> {
    if key.is_empty()
        || !key
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        anyhow::bail!("invalid secret key '{key}'; expected [A-Z0-9_]+");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_sample_config(dir: &Path, project: &str) -> anyhow::Result<PathBuf> {
        let path = dir.join("anvil.yaml");
        let yaml = format!(
            "version: \"1\"\nproject:\n  name: \"{project}\"\nservices:\n  api:\n    runtime:\n      type: native\n      cmd: \"echo ok\"\n"
        );
        fs::write(&path, yaml)?;
        Ok(path)
    }

    #[tokio::test]
    async fn secret_set_list_get_delete_vault_roundtrip_and_no_plaintext() -> anyhow::Result<()> {
        let tmp = TempDir::new()?;
        let config_path = write_sample_config(tmp.path(), "vault-proj")?;
        let data_dir = tmp.path().join("data");
        let globals = GlobalOptions {
            config: config_path,
            data_dir: Some(data_dir.clone()),
            project: None,
        };
        let passphrase = Zeroizing::new("test-vault-passphrase-42".to_owned());

        let mut out = Vec::new();
        let mut err = Vec::new();
        run_with_io(
            &globals,
            SecretCommand::Set {
                key: "DB_PASSWORD".to_owned(),
                vault: true,
                stdin: true,
            },
            Some(Zeroizing::new(b"super_secret_pw_999\n".to_vec())),
            Some(passphrase.clone()),
            &mut out,
            &mut err,
        )
        .await?;
        let set_out = String::from_utf8(out)?;
        assert!(!set_out.contains("super_secret_pw_999"));
        assert!(!set_out.contains("19"));

        let mut out = Vec::new();
        let mut err = Vec::new();
        run_with_io(
            &globals,
            SecretCommand::Set {
                key: "API_KEY".to_owned(),
                vault: true,
                stdin: true,
            },
            Some(Zeroizing::new(b"api_token_abc\r\n".to_vec())),
            Some(passphrase.clone()),
            &mut out,
            &mut err,
        )
        .await?;

        let vault_file = vault_dir_for(&data_dir).join("vault-proj.vault.enc");
        assert!(vault_file.exists());
        let raw_vault = fs::read_to_string(&vault_file)?;
        assert!(!raw_vault.contains("super_secret_pw_999"));
        assert!(!raw_vault.contains("api_token_abc"));
        assert!(!raw_vault.contains(passphrase.as_str()));

        let mut out = Vec::new();
        let mut err = Vec::new();
        run_with_io(
            &globals,
            SecretCommand::List { vault: true },
            None,
            Some(passphrase.clone()),
            &mut out,
            &mut err,
        )
        .await?;
        let listed = String::from_utf8(out)?;
        assert_eq!(listed, "API_KEY\nDB_PASSWORD\n");
        assert!(!listed.contains("super_secret_pw_999"));

        let mut out = Vec::new();
        let mut err = Vec::new();
        run_with_io(
            &globals,
            SecretCommand::Get {
                key: "DB_PASSWORD".to_owned(),
                vault: true,
            },
            None,
            Some(passphrase.clone()),
            &mut out,
            &mut err,
        )
        .await?;
        assert_eq!(String::from_utf8(out)?, "super_secret_pw_999\n");

        let mut out = Vec::new();
        let mut err = Vec::new();
        run_with_io(
            &globals,
            SecretCommand::Delete {
                key: "DB_PASSWORD".to_owned(),
                vault: true,
            },
            None,
            Some(passphrase.clone()),
            &mut out,
            &mut err,
        )
        .await?;
        assert!(String::from_utf8(out)?.contains("Deleted secret 'DB_PASSWORD'"));

        let mut out = Vec::new();
        let mut err = Vec::new();
        run_with_io(
            &globals,
            SecretCommand::List { vault: true },
            None,
            Some(passphrase.clone()),
            &mut out,
            &mut err,
        )
        .await?;
        assert_eq!(String::from_utf8(out)?, "API_KEY\n");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let missing_err = run_with_io(
            &globals,
            SecretCommand::Get {
                key: "DB_PASSWORD".to_owned(),
                vault: true,
            },
            None,
            Some(passphrase),
            &mut out,
            &mut err,
        )
        .await;
        assert!(missing_err.is_err());
        assert!(out.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn project_override_beats_config_and_rejects_bad_keys() -> anyhow::Result<()> {
        let tmp = TempDir::new()?;
        let data_dir = tmp.path().join("data");
        let globals = GlobalOptions {
            config: tmp.path().join("nonexistent-anvil.yaml"),
            data_dir: Some(data_dir.clone()),
            project: Some("explicit-proj".to_owned()),
        };
        assert_eq!(resolve_project_name(&globals).await?, "explicit-proj");

        let passphrase = Zeroizing::new("pass-123".to_owned());
        let mut out = Vec::new();
        let mut err = Vec::new();
        let bad_key = run_with_io(
            &globals,
            SecretCommand::Set {
                key: "bad-lower".to_owned(),
                vault: true,
                stdin: true,
            },
            Some(Zeroizing::new(b"secret\n".to_vec())),
            Some(passphrase.clone()),
            &mut out,
            &mut err,
        )
        .await;
        assert!(bad_key.is_err());

        run_with_io(
            &globals,
            SecretCommand::Set {
                key: "JWT_SECRET".to_owned(),
                vault: true,
                stdin: true,
            },
            Some(Zeroizing::new(b"jwt_val\n".to_vec())),
            Some(passphrase),
            &mut out,
            &mut err,
        )
        .await?;
        assert!(vault_dir_for(&data_dir)
            .join("explicit-proj.vault.enc")
            .exists());
        Ok(())
    }
}
