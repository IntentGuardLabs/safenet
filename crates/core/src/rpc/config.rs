//! RPC endpoint configuration: an ordered list of endpoints whose credential
//! bearing URLs live in secret files, never in the TOML.

use serde::{Deserialize, Deserializer, de};
use std::{
    collections::HashSet,
    fmt::{self, Debug, Display, Formatter},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use url::Url;

/// The maximum size of a URL secret file.
const MAX_URL_FILE_LEN: u64 = 4096;

/// A URL that may carry credentials. Its `Debug` and `Display` never show it.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretUrl(Url);

impl SecretUrl {
    pub fn new(url: Url) -> Self {
        Self(url)
    }

    /// The real URL. Only for connecting; never log or format it.
    pub fn expose(&self) -> &Url {
        &self.0
    }
}

impl Debug for SecretUrl {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str("SecretUrl(<redacted>)")
    }
}

impl Display for SecretUrl {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<'de> Deserialize<'de> for SecretUrl {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Do not echo the value in the error: it may contain credentials.
        let raw = String::deserialize(deserializer)?;
        Url::parse(&raw)
            .map(Self)
            .map_err(|_| de::Error::custom("invalid RPC URL (value not shown)"))
    }
}

/// A resolved, named endpoint.
#[derive(Clone, Debug)]
pub struct Endpoint {
    pub name: Arc<str>,
    pub url: SecretUrl,
}

/// Errors in the RPC configuration. Messages never contain URL contents.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("`rpc.endpoints` must list at least one endpoint")]
    NoEndpoints,
    #[error("RPC endpoint {0:?} must set exactly one of `url` or `url_file`")]
    UrlSource(String),
    #[error("invalid RPC endpoint name {0:?}: use 1-32 characters from [A-Za-z0-9_-]")]
    InvalidName(String),
    #[error("duplicate RPC endpoint name {0:?}")]
    DuplicateName(String),
    #[error("`rpc.failure_threshold` must be at least 1")]
    ZeroThreshold,
    #[error("`rpc.request_timeout` must be greater than zero")]
    ZeroTimeout,
    #[error("cannot read URL file {} for RPC endpoint {name:?}: {kind}", path.display())]
    UrlFile {
        name: String,
        path: PathBuf,
        kind: std::io::ErrorKind,
    },
    #[error("URL file {} for RPC endpoint {name:?} is empty, too large or not UTF-8", path.display())]
    UrlFileContents { name: String, path: PathBuf },
    #[error("URL file {} for RPC endpoint {name:?} does not contain a valid http(s) URL (value not shown)", path.display())]
    InvalidUrl { name: String, path: PathBuf },
}

/// One `[[rpc.endpoints]]` entry.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EndpointConfig {
    /// The endpoint's name: the only way it is identified in logs and metrics.
    pub name: String,
    /// The endpoint URL, inline. It may contain credentials, which then sit in
    /// the configuration file; prefer `url_file` for such URLs. Exactly one of
    /// `url` and `url_file` must be set.
    #[serde(default)]
    pub url: Option<SecretUrl>,
    /// File holding the endpoint URL. Leading/trailing whitespace (such as a
    /// trailing newline) is trimmed; the URL may contain credentials.
    #[serde(default)]
    pub url_file: Option<PathBuf>,
}

/// The `[rpc]` table.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Every endpoint must report this chain ID.
    pub expected_chain_id: u64,
    /// Per-request timeout, e.g. `"10s"`.
    #[serde(default = "default_request_timeout", with = "duration")]
    pub request_timeout: Duration,
    /// Consecutive retryable failures before an endpoint's circuit opens.
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    /// How long an opened circuit stays open before a half-open probe.
    #[serde(default = "default_cooldown", with = "duration")]
    pub cooldown: Duration,
    /// Endpoints in priority order: the first healthy one is the primary.
    pub endpoints: Vec<EndpointConfig>,
}

fn default_request_timeout() -> Duration {
    Duration::from_secs(10)
}
fn default_failure_threshold() -> u32 {
    3
}
fn default_cooldown() -> Duration {
    Duration::from_secs(30)
}

impl Config {
    /// Checks names, counts and limits (not the files).
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.endpoints.is_empty() {
            return Err(ConfigError::NoEndpoints);
        }
        if self.failure_threshold == 0 {
            return Err(ConfigError::ZeroThreshold);
        }
        if self.request_timeout.is_zero() {
            return Err(ConfigError::ZeroTimeout);
        }
        let mut seen = HashSet::new();
        for endpoint in &self.endpoints {
            let valid = (1..=32).contains(&endpoint.name.len())
                && endpoint
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
            if !valid {
                return Err(ConfigError::InvalidName(endpoint.name.clone()));
            }
            if !seen.insert(endpoint.name.as_str()) {
                return Err(ConfigError::DuplicateName(endpoint.name.clone()));
            }
            if endpoint.url.is_some() == endpoint.url_file.is_some() {
                return Err(ConfigError::UrlSource(endpoint.name.clone()));
            }
        }
        Ok(())
    }

    /// Resolves relative `url_file` paths against `base` (the directory of the
    /// configuration file).
    pub fn resolve_paths(&mut self, base: &Path) {
        for endpoint in &mut self.endpoints {
            if let Some(file) = &mut endpoint.url_file {
                *file = base.join(&*file);
            }
        }
    }

    /// Validates the configuration and reads every endpoint's URL, preserving
    /// order.
    pub fn load_endpoints(&self) -> Result<Vec<Endpoint>, ConfigError> {
        self.validate()?;
        self.endpoints.iter().map(load_endpoint).collect()
    }
}

fn load_endpoint(config: &EndpointConfig) -> Result<Endpoint, ConfigError> {
    use std::io::Read as _;
    let name = config.name.clone();
    let url_file = match (&config.url, &config.url_file) {
        (Some(url), None) => {
            if !matches!(url.expose().scheme(), "http" | "https") {
                return Err(ConfigError::InvalidUrl {
                    name,
                    path: PathBuf::new(),
                });
            }
            return Ok(Endpoint {
                name: Arc::from(config.name.as_str()),
                url: url.clone(),
            });
        }
        (None, Some(file)) => file,
        _ => return Err(ConfigError::UrlSource(name)),
    };
    let io_err = |err: std::io::Error| ConfigError::UrlFile {
        name: name.clone(),
        path: url_file.clone(),
        kind: err.kind(),
    };
    let mut raw = String::new();
    fs::File::open(url_file)
        .map_err(io_err)?
        .take(MAX_URL_FILE_LEN + 1)
        .read_to_string(&mut raw)
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::InvalidData {
                ConfigError::UrlFileContents {
                    name: name.clone(),
                    path: url_file.clone(),
                }
            } else {
                io_err(err)
            }
        })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() || raw.len() as u64 > MAX_URL_FILE_LEN {
        return Err(ConfigError::UrlFileContents {
            name,
            path: url_file.clone(),
        });
    }
    let invalid = || ConfigError::InvalidUrl {
        name: config.name.clone(),
        path: url_file.clone(),
    };
    let url = Url::parse(trimmed).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(invalid());
    }
    Ok(Endpoint {
        name: Arc::from(config.name.as_str()),
        url: SecretUrl(url),
    })
}

/// Serde support for durations written as `"250ms"`, `"10s"`, `"2m"`.
pub mod duration {
    use serde::{Deserialize, Deserializer, de};
    use std::time::Duration;

    pub fn parse(text: &str) -> Option<Duration> {
        let text = text.trim();
        let (digits, unit) = text.split_at(text.find(|c: char| !c.is_ascii_digit())?);
        let value: u64 = digits.parse().ok()?;
        match unit {
            "ms" => Some(Duration::from_millis(value)),
            "s" => Some(Duration::from_secs(value)),
            "m" => value.checked_mul(60).map(Duration::from_secs),
            _ => None,
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        let text = String::deserialize(deserializer)?;
        parse(&text).ok_or_else(|| {
            de::Error::custom("expected a duration like \"250ms\", \"10s\" or \"2m\"")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(toml: &str) -> Config {
        toml::from_str(toml).unwrap()
    }

    const TWO: &str = r#"
        expected_chain_id = 100
        request_timeout = "10s"
        failure_threshold = 3
        cooldown = "30s"
        [[endpoints]]
        name = "primary"
        url_file = "/run/secrets/rpc-primary-url"
        [[endpoints]]
        name = "secondary"
        url_file = "/run/secrets/rpc-secondary-url"
    "#;

    #[test]
    fn parses_and_preserves_order() {
        let config = config(TWO);
        config.validate().unwrap();
        assert_eq!(config.expected_chain_id, 100);
        assert_eq!(config.request_timeout, Duration::from_secs(10));
        assert_eq!(config.cooldown, Duration::from_secs(30));
        let names: Vec<_> = config.endpoints.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["primary", "secondary"]);
    }

    #[test]
    fn rejects_duplicate_names_bad_names_and_empty_lists() {
        let mut c = config(TWO);
        c.endpoints[1].name = "primary".into();
        assert!(matches!(c.validate(), Err(ConfigError::DuplicateName(_))));
        c.endpoints[1].name = "https://user:pw@host".into();
        assert!(matches!(c.validate(), Err(ConfigError::InvalidName(_))));
        c.endpoints.clear();
        assert!(matches!(c.validate(), Err(ConfigError::NoEndpoints)));
    }

    #[test]
    fn rejects_unknown_fields_and_requires_exactly_one_url_source() {
        assert!(toml::from_str::<Config>(&format!("{TWO}\nbogus = 1")).is_err());

        // Both `url` and `url_file`, or neither, is an error.
        let mut c = config(TWO);
        c.endpoints[0].url = Some(SecretUrl::new(Url::parse("http://127.0.0.1:8545").unwrap()));
        assert!(matches!(c.validate(), Err(ConfigError::UrlSource(_))));
        c.endpoints[0].url_file = None;
        c.validate().unwrap();
        c.endpoints[0].url = None;
        assert!(matches!(c.validate(), Err(ConfigError::UrlSource(_))));
    }

    #[test]
    fn loads_inline_urls_and_redacts_them() {
        let inline = TWO.replace(
            "url_file = \"/run/secrets/rpc-primary-url\"",
            "url = \"https://user:hunter2@rpc.example/v1/KEY\"",
        );
        let c = config(&inline);
        let endpoints = c.load_endpoints().unwrap_err();
        // The secondary's file does not exist; only the primary is inline.
        assert!(matches!(endpoints, ConfigError::UrlFile { .. }));
        assert!(!format!("{c:?}").contains("hunter2"));

        let bad = TWO.replace(
            "url_file = \"/run/secrets/rpc-primary-url\"",
            "url = \"ftp://user:hunter2@host\"",
        );
        let err = config(&bad).load_endpoints().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidUrl { .. }));
        assert!(!format!("{err} {err:?}").contains("hunter2"));
    }

    #[test]
    fn loads_urls_from_files_trimming_whitespace_and_redacts() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, "https://user:hunter2@rpc.example/v1/KEY\n").unwrap();
        std::fs::write(&b, "http://127.0.0.1:8545").unwrap();
        let mut c = config(TWO);
        c.endpoints[0].url_file = Some(a);
        c.endpoints[1].url_file = Some(b);

        let endpoints = c.load_endpoints().unwrap();
        assert_eq!(&*endpoints[0].name, "primary");
        assert_eq!(endpoints[0].url.expose().username(), "user");
        let shown = format!(
            "{:?} {} {:?}",
            endpoints[0].url, endpoints[0].url, endpoints[0]
        );
        assert!(
            !shown.contains("hunter2") && !shown.contains("KEY") && !shown.contains("rpc.example")
        );
    }

    #[test]
    fn url_file_errors_never_contain_the_url() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("bad");
        std::fs::write(&bad, "ftp://user:hunter2@host/secret").unwrap();
        let mut c = config(TWO);
        c.endpoints[0].url_file = Some(bad);
        let err = c.load_endpoints().unwrap_err();
        assert!(!format!("{err} {err:?}").contains("hunter2"));

        c.endpoints[0].url_file = Some(dir.path().join("missing"));
        assert!(matches!(
            c.load_endpoints(),
            Err(ConfigError::UrlFile { .. })
        ));
        let empty = dir.path().join("empty");
        std::fs::write(&empty, "  \n").unwrap();
        c.endpoints[0].url_file = Some(empty);
        assert!(matches!(
            c.load_endpoints(),
            Err(ConfigError::UrlFileContents { .. })
        ));
    }

    #[test]
    fn parses_durations() {
        assert_eq!(duration::parse("250ms"), Some(Duration::from_millis(250)));
        assert_eq!(duration::parse("2m"), Some(Duration::from_secs(120)));
        assert_eq!(duration::parse("10"), None);
        assert_eq!(duration::parse("1h"), None);
    }
}
