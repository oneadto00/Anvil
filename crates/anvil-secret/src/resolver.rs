//! `${SECRET:<KEY_NAME>}` placeholder parsing and memory-safe environment resolution.

use crate::error::SecretError;
use crate::{validate_project_name, SecretBackend};
use regex::Regex;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::LazyLock;
use zeroize::Zeroizing;

const PLACEHOLDER_PREFIX: &str = "${SECRET:";

static SECRET_REF_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // SAFETY: compile-time constant regex
    Regex::new(r"\$\{SECRET:([A-Z0-9_]+)\}").expect("compile-time constant secret ref regex")
});

/// Wrapper around resolved environment variables whose `Debug` output redacts all values.
#[derive(Clone, Default)]
pub struct ResolvedEnvMap(HashMap<String, Zeroizing<String>>);

impl ResolvedEnvMap {
    /// Wraps a map of resolved environment variables.
    pub fn new(inner: HashMap<String, Zeroizing<String>>) -> Self {
        Self(inner)
    }

    /// Borrows the underlying map of environment keys to zeroizing secret strings.
    pub fn as_map(&self) -> &HashMap<String, Zeroizing<String>> {
        &self.0
    }

    /// Consumes the wrapper and returns the underlying map.
    pub fn into_inner(self) -> HashMap<String, Zeroizing<String>> {
        self.0
    }
}

impl From<HashMap<String, Zeroizing<String>>> for ResolvedEnvMap {
    fn from(value: HashMap<String, Zeroizing<String>>) -> Self {
        Self(value)
    }
}

impl fmt::Debug for ResolvedEnvMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted: BTreeMap<&str, &str> = self
            .0
            .keys()
            .map(|k| (k.as_str(), "[REDACTED]"))
            .collect();
        f.debug_tuple("ResolvedEnvMap").field(&redacted).finish()
    }
}

/// Extracts all unique `<KEY_NAME>` references matching `${SECRET:<KEY_NAME>}` (`[A-Z0-9_]+`)
/// in order of first appearance.
pub fn extract_secret_refs(value: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut refs = Vec::new();
    for caps in SECRET_REF_REGEX.captures_iter(value) {
        if let Some(m) = caps.get(1) {
            let key = m.as_str();
            if seen.insert(key.to_owned()) {
                refs.push(key.to_owned());
            }
        }
    }
    refs
}

/// Strictly validates all `${SECRET:...}` placeholders in `value` and returns unique referenced keys.
///
/// Any unclosed `${SECRET:` sequence or key name outside `[A-Z0-9_]+` returns
/// [`SecretError::InvalidPlaceholder`].
pub fn validate_secret_refs(value: &str) -> Result<Vec<String>, SecretError> {
    let mut seen = HashSet::new();
    let mut refs = Vec::new();
    let mut cursor = 0;

    while let Some(rel_start) = value[cursor..].find(PLACEHOLDER_PREFIX) {
        let prefix_start = cursor + rel_start;
        let key_start = prefix_start + PLACEHOLDER_PREFIX.len();
        let Some(rel_end) = value[key_start..].find('}') else {
            return Err(SecretError::InvalidPlaceholder(
                "unclosed '${SECRET:' placeholder".to_string(),
            ));
        };
        let key_end = key_start + rel_end;
        let key = &value[key_start..key_end];
        if !is_valid_key_name(key) {
            return Err(SecretError::InvalidPlaceholder(format!(
                "invalid secret placeholder key '{key}'; expected [A-Z0-9_]+"
            )));
        }
        if seen.insert(key.to_owned()) {
            refs.push(key.to_owned());
        }
        cursor = key_end + 1;
    }

    Ok(refs)
}

/// Resolves all `${SECRET:<KEY_NAME>}` placeholders in a single environment value using `backend`.
///
/// Resolution expands only placeholders in the input. Secret values are inserted literally.
pub fn resolve_value<S: SecretBackend + ?Sized>(
    project: &str,
    raw_value: &str,
    backend: &S,
) -> Result<Zeroizing<String>, SecretError> {
    let mut cache = HashMap::new();
    resolve_value_with_cache(project, raw_value, backend, &mut cache)
}

/// Resolves all `${SECRET:<KEY_NAME>}` placeholders across an environment map using `backend`.
///
/// Distinct secret keys referenced multiple times are fetched at most once per call.
pub fn resolve_env_map<S, I, K, V>(
    project: &str,
    raw_env: I,
    backend: &S,
) -> Result<HashMap<String, Zeroizing<String>>, SecretError>
where
    S: SecretBackend + ?Sized,
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    validate_project_name(project)?;
    let mut cache: HashMap<String, Zeroizing<String>> = HashMap::new();
    let mut resolved = HashMap::new();

    for (env_key, env_val) in raw_env {
        let value = resolve_value_with_cache(project, env_val.as_ref(), backend, &mut cache)?;
        resolved.insert(env_key.as_ref().to_owned(), value);
    }

    Ok(resolved)
}

fn resolve_value_with_cache<S: SecretBackend + ?Sized>(
    project: &str,
    raw_value: &str,
    backend: &S,
    cache: &mut HashMap<String, Zeroizing<String>>,
) -> Result<Zeroizing<String>, SecretError> {
    validate_project_name(project)?;
    validate_secret_refs(raw_value)?;

    if !raw_value.contains(PLACEHOLDER_PREFIX) {
        return Ok(Zeroizing::new(raw_value.to_owned()));
    }

    let mut out = Zeroizing::new(String::with_capacity(raw_value.len()));
    let mut cursor = 0;

    while let Some(rel_start) = raw_value[cursor..].find(PLACEHOLDER_PREFIX) {
        let prefix_start = cursor + rel_start;
        out.push_str(&raw_value[cursor..prefix_start]);

        let key_start = prefix_start + PLACEHOLDER_PREFIX.len();
        let Some(rel_end) = raw_value[key_start..].find('}') else {
            return Err(SecretError::InvalidPlaceholder(
                "unclosed '${SECRET:' placeholder".to_string(),
            ));
        };
        let key_end = key_start + rel_end;
        let key = &raw_value[key_start..key_end];

        if let Some(cached) = cache.get(key) {
            out.push_str(cached.as_str());
        } else {
            let fetched = backend
                .get(project, key)?
                .ok_or_else(|| SecretError::SecretNotFound {
                    key: key.to_owned(),
                })?;
            out.push_str(fetched.as_str());
            cache.insert(key.to_owned(), fetched);
        }

        cursor = key_end + 1;
    }

    out.push_str(&raw_value[cursor..]);
    Ok(out)
}

fn is_valid_key_name(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemorySecretStore;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingBackend {
        inner: InMemorySecretStore,
        get_calls: AtomicUsize,
    }

    impl CountingBackend {
        fn new(inner: InMemorySecretStore) -> Self {
            Self {
                inner,
                get_calls: AtomicUsize::new(0),
            }
        }
    }

    impl SecretBackend for CountingBackend {
        fn get(&self, project: &str, key: &str) -> Result<Option<Zeroizing<String>>, SecretError> {
            self.get_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.get(project, key)
        }

        fn set(
            &self,
            project: &str,
            key: &str,
            value: Zeroizing<String>,
        ) -> Result<(), SecretError> {
            self.inner.set(project, key, value)
        }

        fn delete(&self, project: &str, key: &str) -> Result<(), SecretError> {
            self.inner.delete(project, key)
        }

        fn list_keys(&self, project: &str) -> Result<Vec<String>, SecretError> {
            self.inner.list_keys(project)
        }
    }

    #[test]
    fn extract_secret_refs_deduplicates_in_order() {
        let input = "postgres://u:${SECRET:DB_PASS}@localhost/${SECRET:DB_NAME}?p=${SECRET:DB_PASS}&k=${SECRET:API_V2_KEY}";
        assert_eq!(
            extract_secret_refs(input),
            vec![
                "DB_PASS".to_string(),
                "DB_NAME".to_string(),
                "API_V2_KEY".to_string()
            ]
        );
    }

    #[test]
    fn extract_secret_refs_ignores_non_matching_or_other_placeholders() {
        let input = "${HOME}/app ${SECRET:bad_lower} ${SECRET:NO-DASH} ${SECRET:} ${SECRET:GOOD_1}";
        assert_eq!(extract_secret_refs(input), vec!["GOOD_1".to_string()]);
    }

    #[test]
    fn validate_secret_refs_rejects_malformed_placeholders() {
        assert!(matches!(
            validate_secret_refs("${SECRET:lowercase}"),
            Err(SecretError::InvalidPlaceholder(_))
        ));
        assert!(matches!(
            validate_secret_refs("${SECRET:BAD-KEY}"),
            Err(SecretError::InvalidPlaceholder(_))
        ));
        assert!(matches!(
            validate_secret_refs("${SECRET:}"),
            Err(SecretError::InvalidPlaceholder(_))
        ));
        assert!(matches!(
            validate_secret_refs("prefix ${SECRET:UNCLOSED"),
            Err(SecretError::InvalidPlaceholder(_))
        ));
        assert_eq!(
            validate_secret_refs("${OTHER_VAR} ${SECRET:VALID_01}").unwrap(),
            vec!["VALID_01".to_string()]
        );
    }

    #[test]
    fn resolve_env_map_interpolates_and_caches_lookups() {
        let store = InMemorySecretStore::new();
        store
            .set(
                "nebula",
                "DB_PASSWORD",
                Zeroizing::new("pw_12345".to_string()),
            )
            .unwrap();
        store
            .set(
                "nebula",
                "JWT_PRIVATE_KEY",
                Zeroizing::new("jwt_abc".to_string()),
            )
            .unwrap();
        let backend = CountingBackend::new(store);

        let mut raw = BTreeMap::new();
        raw.insert("RUST_LOG".to_string(), "info".to_string());
        raw.insert(
            "POSTGRES_PASSWORD".to_string(),
            "${SECRET:DB_PASSWORD}".to_string(),
        );
        raw.insert(
            "DATABASE_URL".to_string(),
            "postgres://nebula:${SECRET:DB_PASSWORD}@127.0.0.1:5432/dev".to_string(),
        );
        raw.insert(
            "JWT_SECRET".to_string(),
            "${SECRET:JWT_PRIVATE_KEY}".to_string(),
        );

        let resolved = resolve_env_map("nebula", &raw, &backend).unwrap();
        assert_eq!(resolved["RUST_LOG"].as_str(), "info");
        assert_eq!(resolved["POSTGRES_PASSWORD"].as_str(), "pw_12345");
        assert_eq!(
            resolved["DATABASE_URL"].as_str(),
            "postgres://nebula:pw_12345@127.0.0.1:5432/dev"
        );
        assert_eq!(resolved["JWT_SECRET"].as_str(), "jwt_abc");
        assert_eq!(backend.get_calls.load(Ordering::SeqCst), 2);

        let wrapper = ResolvedEnvMap::from(resolved);
        let dbg = format!("{wrapper:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("pw_12345"));
        assert!(!dbg.contains("jwt_abc"));
    }

    #[test]
    fn resolve_value_is_single_pass_and_fails_when_missing() {
        let store = InMemorySecretStore::new();
        store
            .set(
                "proj",
                "OUTER",
                Zeroizing::new("literal_${SECRET:INNER}".to_string()),
            )
            .unwrap();
        store
            .set("proj", "INNER", Zeroizing::new("should_not_expand".into()))
            .unwrap();

        let val = resolve_value("proj", "${SECRET:OUTER}", &store).unwrap();
        assert_eq!(val.as_str(), "literal_${SECRET:INNER}");

        let err = resolve_value("proj", "${SECRET:MISSING_KEY}", &store).unwrap_err();
        assert!(matches!(
            err,
            SecretError::SecretNotFound { ref key } if key == "MISSING_KEY"
        ));
    }
}
