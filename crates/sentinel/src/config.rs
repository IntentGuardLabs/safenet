use alloy::primitives::Address;
use safenet_core::{
    driver, observability, rpc,
    tx::{KeystoreError, Signer},
};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Visitor},
};
use sqlx::sqlite::SqliteConnectOptions;
use std::{
    fmt,
    path::{Path, PathBuf},
};
use tokio::{fs, io};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    /// A TOML error, reduced to its message and location. `toml`'s own
    /// `Display` quotes the offending source line, which for a legacy inline
    /// `signer = "0x..."` would print the private key.
    #[error("invalid configuration {}: {message} (line {line}, column {column})", file.display())]
    Parse {
        file: PathBuf,
        message: String,
        line: usize,
        column: usize,
    },
}

/// The RPC section: an ordered list of endpoints with sticky-primary failover
/// (`[rpc]` + `[[rpc.endpoints]]`), or the deprecated single `rpc = "<url>"`.
#[derive(Debug)]
pub enum RpcConfig {
    /// `[rpc]` table; endpoint URLs live in secret files.
    Endpoints(rpc::Config),
    /// Deprecated: `rpc = "https://..."`. The URL may contain credentials.
    Legacy(rpc::SecretUrl),
}

impl RpcConfig {
    fn resolve_paths(&mut self, base: &Path) {
        if let Self::Endpoints(config) = self {
            config.resolve_paths(base);
        }
    }

    /// Validates every endpoint and connects the provider.
    pub async fn connect(
        &self,
    ) -> Result<safenet_core::provider::Provider, Box<dyn std::error::Error>> {
        use safenet_core::provider::Provider;
        match self {
            Self::Endpoints(config) => {
                let endpoints = config.load_endpoints()?;
                tracing::info!(
                    endpoints = ?endpoints.iter().map(|e| e.name.to_string()).collect::<Vec<_>>(),
                    expected_chain_id = config.expected_chain_id,
                    "validating RPC endpoints"
                );
                Ok(Provider::connect_rpc(config, endpoints).await?)
            }
            Self::Legacy(url) => {
                tracing::warn!(
                    "DEPRECATED: a single `rpc = \"<url>\"` has no failover and puts a possibly credential-bearing URL in the configuration file; migrate to `[rpc]` with `[[rpc.endpoints]]` and `url_file`"
                );
                Ok(Provider::connect(url.expose()).await?)
            }
        }
    }
}

impl<'de> Deserialize<'de> for RpcConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RpcVisitor;

        impl<'de> Visitor<'de> for RpcVisitor {
            type Value = RpcConfig;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(
                    "an `[rpc]` table with `[[rpc.endpoints]]` (or a deprecated URL string)",
                )
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                rpc::SecretUrl::deserialize(de::value::StrDeserializer::new(v))
                    .map(RpcConfig::Legacy)
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                let config = rpc::Config::deserialize(de::value::MapAccessDeserializer::new(map))?;
                config.validate().map_err(de::Error::custom)?;
                Ok(RpcConfig::Endpoints(config))
            }
        }

        deserializer.deserialize_any(RpcVisitor)
    }
}

/// The signer section of the configuration: either a reference to an
/// encrypted keystore (preferred), or the deprecated inline private key.
///
/// Configuration only ever holds *references* to secrets; the password is read
/// and decrypted by [`SignerConfig::load`] and never stored.
#[derive(Debug)]
pub enum SignerConfig {
    /// `[signer] type = "keystore"`: a Web3 Secret Storage v3 keystore.
    Keystore(KeystoreConfig),
    /// Deprecated: `signer = "0x<hex private key>"`.
    Legacy(Signer),
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum TaggedSignerConfig {
    Keystore(KeystoreConfig),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeystoreConfig {
    /// The encrypted keystore. Relative paths are resolved against the
    /// directory containing the configuration file.
    pub path: PathBuf,
    /// File containing the keystore password, verbatim (no trimming).
    /// Relative paths are resolved like `path`.
    pub password_file: PathBuf,
    /// The address the keystore must decrypt to. Mandatory, so that mounting
    /// the wrong keystore fails startup instead of silently changing identity.
    pub expected_address: Address,
}

impl SignerConfig {
    /// Loads the signer, decrypting the keystore if configured.
    ///
    /// Fails closed: a keystore configuration never falls back to anything else.
    pub fn load(self) -> Result<Signer, KeystoreError> {
        match self {
            Self::Keystore(config) => {
                let signer = Signer::from_keystore(
                    &config.path,
                    &config.password_file,
                    config.expected_address,
                )?;
                tracing::info!(address = %signer.address(), "loaded signer from keystore");
                Ok(signer)
            }
            Self::Legacy(signer) => {
                tracing::warn!(
                    address = %signer.address(),
                    "DEPRECATED: inline `signer = \"0x...\"` private keys in the configuration file are insecure and will be removed; migrate to an encrypted `[signer] type = \"keystore\"`"
                );
                Ok(signer)
            }
        }
    }

    fn resolve_paths(&mut self, base: &Path) {
        if let Self::Keystore(config) = self {
            config.path = base.join(&config.path);
            config.password_file = base.join(&config.password_file);
        }
    }
}

impl<'de> Deserialize<'de> for SignerConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SignerVisitor;

        impl<'de> Visitor<'de> for SignerVisitor {
            type Value = SignerConfig;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a `[signer]` table with `type = \"keystore\"` (or a deprecated hex private key string)")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Signer::deserialize(de::value::StrDeserializer::new(v)).map(SignerConfig::Legacy)
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                let TaggedSignerConfig::Keystore(config) =
                    TaggedSignerConfig::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(SignerConfig::Keystore(config))
            }
        }

        deserializer.deserialize_any(SignerVisitor)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The RPC endpoint(s) used to initialize the chain provider.
    pub rpc: RpcConfig,
    /// How to obtain the signer used to sign and submit transactions onchain.
    pub signer: SignerConfig,
    /// The database URL backing persistent state and transaction storage.
    #[serde(with = "safenet_core::serialization::from_str")]
    pub database: SqliteConnectOptions,
    /// The `SentinelOracle` contract watched and voted/committed on.
    pub oracle: Address,
    /// The `Consensus` contract whose proposals are hashed into request ids.
    pub consensus: Address,
    /// Configuration for the sentinel's own detection and voting logic.
    pub sentinel: SentinelConfig,
    /// Observability (logging and metrics) configuration.
    #[serde(default)]
    pub observability: observability::Config,
    /// Configuration for the service driver and its components.
    #[serde(flatten)]
    pub driver: driver::Config,
}

/// Configuration specific to the sentinel's request handling, as opposed to
/// the infrastructure it shares with other Safenet services.
//
// TODO(epic Phase E2, follow-up): pick and document a sensible default for
// `voting_window` (`fee_token`/`oracle`/`consensus` are deployment-specific and
// should stay required) once the sentinel's config shape has settled; for now
// it is mandatory so a missing value fails loudly rather than silently using
// the wrong window.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SentinelConfig {
    /// The ERC-20 fee token approved for bonds.
    pub fee_token: Address,
    /// The number of blocks a `Preparing` request is kept alive for before
    /// being cleaned up.
    pub voting_window: u64,
    /// Base URL of the transaction-verification engine used by this sentinel.
    pub engine: Url,
}

impl Config {
    pub async fn load(file: &Path) -> Result<Self, Error> {
        let contents = fs::read_to_string(file).await?;
        let mut config = toml::from_str::<Self>(&contents).map_err(|err| {
            let (line, column) = err.span().map_or((0, 0), |span| {
                let before = &contents[..span.start];
                let line = before.matches('\n').count() + 1;
                (line, before.rsplit('\n').next().map_or(0, str::len) + 1)
            });
            Error::Parse {
                file: file.to_owned(),
                message: err.message().to_owned(),
                line,
                column,
            }
        })?;
        // Secret paths are relative to the configuration file, not the
        // process's working directory. Nothing is canonicalized: that would
        // need the files to exist, and the files are only ever read.
        let base = file.parent().unwrap_or_else(|| Path::new(""));
        config.signer.resolve_paths(base);
        config.rpc.resolve_paths(base);
        // Sentinel indexing is strict: sequential per-block catch-up, a
        // required `start_block` on a fresh database, and log integrity checks.
        config.driver.index.blocks.strict = true;
        config.driver.index.events.verify_integrity = true;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use std::path::PathBuf;

    const TOML: &str = r#"
        rpc = "https://eth.llamarpc.com"
        signer = "0x0000000000000000000000000000000000000000000000000000000000000001"
        database = "sqlite:sentinel.db"
        oracle = "0x0101010101010101010101010101010101010101"
        consensus = "0x0202020202020202020202020202020202020202"

        [sentinel]
        fee_token = "0x0303030303030303030303030303030303030303"
        voting_window = 100
        engine = "http://localhost:5473"
    "#;

    #[test]
    fn deserializes_required_fields_and_defaults_the_rest() {
        // Observability and the flattened driver config are both omitted and
        // fall back to their own defaults, matching the `validator` crate's
        // config convention.
        let config = toml::from_str::<Config>(TOML).unwrap();

        assert!(matches!(config.rpc, RpcConfig::Legacy(_)));
        assert!(!format!("{:?}", config.rpc).contains("llamarpc"));
        assert_eq!(config.database.get_filename(), "sentinel.db");
        assert_eq!(
            config.oracle,
            address!("0x0101010101010101010101010101010101010101")
        );
        assert_eq!(
            config.consensus,
            address!("0x0202020202020202020202020202020202020202")
        );
        assert_eq!(
            config.sentinel.fee_token,
            address!("0x0303030303030303030303030303030303030303")
        );
        assert_eq!(config.sentinel.voting_window, 100);
        assert_eq!(config.sentinel.engine.as_str(), "http://localhost:5473/");
        assert_eq!(
            config.observability.log_filter.to_string(),
            observability::Config::default().log_filter.to_string()
        );
        assert_eq!(config.driver, driver::Config::default());
    }

    #[test]
    fn rejects_config_missing_a_deployment_specific_field() {
        // `oracle`, `consensus` and the `[sentinel]` block have no sensible
        // default and must fail loudly rather than silently defaulting to the
        // zero address (see the `SentinelConfig` TODO above).
        let without_oracle = TOML.replacen(
            r#"oracle = "0x0101010101010101010101010101010101010101""#,
            "",
            1,
        );
        assert!(toml::from_str::<Config>(&without_oracle).is_err());
    }

    #[test]
    fn rejects_config_missing_the_engine_url() {
        let without_engine = TOML.replacen("engine = \"http://localhost:5473\"", "", 1);
        assert!(toml::from_str::<Config>(&without_engine).is_err());
    }

    const KEYSTORE_TOML: &str = r#"
        rpc = "https://eth.llamarpc.com"
        database = "sqlite:sentinel.db"
        oracle = "0x0101010101010101010101010101010101010101"
        consensus = "0x0202020202020202020202020202020202020202"

        [signer]
        type = "keystore"
        path = "secrets/keystore.json"
        password_file = "/run/secrets/password"
        expected_address = "0x0404040404040404040404040404040404040404"

        [sentinel]
        fee_token = "0x0303030303030303030303030303030303030303"
        voting_window = 100
        engine = "http://localhost:5473"
    "#;

    fn with_signer(signer_table: &str) -> String {
        KEYSTORE_TOML.replace(
            &KEYSTORE_TOML[KEYSTORE_TOML.find("[signer]").unwrap()
                ..KEYSTORE_TOML.find("[sentinel]").unwrap()],
            signer_table,
        )
    }

    #[test]
    fn parses_keystore_signer() {
        let config = toml::from_str::<Config>(KEYSTORE_TOML).unwrap();
        let SignerConfig::Keystore(keystore) = config.signer else {
            panic!("expected keystore signer");
        };
        assert_eq!(keystore.path, Path::new("secrets/keystore.json"));
        assert_eq!(keystore.password_file, Path::new("/run/secrets/password"));
        assert_eq!(
            keystore.expected_address,
            address!("0x0404040404040404040404040404040404040404")
        );
    }

    #[test]
    fn parses_legacy_inline_signer() {
        let config = toml::from_str::<Config>(TOML).unwrap();
        assert!(matches!(config.signer, SignerConfig::Legacy(_)));
        // Debug shows the address only.
        let debug = format!("{:?}", config.signer);
        assert!(
            !debug.contains("0000000000000000000000000000000000000000000000000000000000000001")
        );
    }

    #[test]
    fn rejects_unknown_signer_type() {
        let toml = with_signer("[signer]\ntype = \"kms\"\n");
        assert!(toml::from_str::<Config>(&toml).is_err());
    }

    #[test]
    fn rejects_unknown_and_missing_signer_fields() {
        let unknown =
            KEYSTORE_TOML.replace("[signer]\n", "[signer]\n        password = \"hunter2\"\n");
        assert!(toml::from_str::<Config>(&unknown).is_err());

        for field in ["path", "password_file", "expected_address"] {
            let missing = KEYSTORE_TOML
                .lines()
                .filter(|l| !l.trim_start().starts_with(field))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(toml::from_str::<Config>(&missing).is_err(), "{field}");
        }
    }

    #[test]
    fn rejects_invalid_expected_address() {
        let bad = KEYSTORE_TOML.replace("0x0404040404040404040404040404040404040404", "0x1234");
        assert!(toml::from_str::<Config>(&bad).is_err());
    }

    #[test]
    fn keystore_type_does_not_fall_back_to_inline_key() {
        // A keystore table with a mistyped tag must not parse as anything else.
        let toml = with_signer("[signer]\ntype = \"Keystore\"\n");
        assert!(toml::from_str::<Config>(&toml).is_err());
    }

    fn write_keystore(dir: &Path, password: &[u8]) -> Address {
        let (signer, _) = alloy::signers::local::PrivateKeySigner::encrypt_keystore(
            dir,
            &mut rand::thread_rng(),
            [0x42u8; 32],
            password,
            Some("keystore.json"),
        )
        .unwrap();
        signer.address()
    }

    fn write_config(dir: &Path, signer_table: &str) -> PathBuf {
        let file = dir.join("sentinel.toml");
        std::fs::write(&file, with_signer(signer_table)).unwrap();
        file
    }

    #[tokio::test]
    async fn resolves_relative_paths_against_config_file_not_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        std::fs::create_dir(&secrets).unwrap();
        let address = write_keystore(&secrets, b"pw");
        std::fs::write(secrets.join("password"), b"pw").unwrap();
        let file = write_config(
            dir.path(),
            &format!(
                "[signer]\ntype = \"keystore\"\npath = \"secrets/keystore.json\"\npassword_file = \"secrets/password\"\nexpected_address = \"{address}\"\n"
            ),
        );

        // The test process's cwd is the crate directory, which has no `secrets/`.
        let signer = Config::load(&file).await.unwrap().signer.load().unwrap();
        assert_eq!(signer.address(), address);
    }

    #[tokio::test]
    async fn absolute_paths_are_used_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = tempfile::tempdir().unwrap();
        let address = write_keystore(secrets.path(), b"pw");
        std::fs::write(secrets.path().join("password"), b"pw").unwrap();
        let file = write_config(
            dir.path(),
            &format!(
                "[signer]\ntype = \"keystore\"\npath = \"{0}/keystore.json\"\npassword_file = \"{0}/password\"\nexpected_address = \"{address}\"\n",
                secrets.path().display()
            ),
        );
        let signer = Config::load(&file).await.unwrap().signer.load().unwrap();
        assert_eq!(signer.address(), address);
    }

    #[tokio::test]
    async fn keystore_failures_are_fatal_and_leak_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let address = write_keystore(dir.path(), b"correct-horse");
        std::fs::write(dir.path().join("password"), b"wrong-battery").unwrap();
        let file = write_config(
            dir.path(),
            &format!(
                "[signer]\ntype = \"keystore\"\npath = \"keystore.json\"\npassword_file = \"password\"\nexpected_address = \"{address}\"\n"
            ),
        );
        let err = Config::load(&file)
            .await
            .unwrap()
            .signer
            .load()
            .unwrap_err();
        let text = format!("{err} {err:?}");
        assert!(!text.contains("correct-horse") && !text.contains("wrong-battery"));
    }

    #[tokio::test]
    async fn parse_errors_do_not_echo_the_inline_key() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sentinel.toml");
        // Valid hex, wrong length: the value must not appear in the error.
        let secret = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef00";
        std::fs::write(
            &file,
            TOML.replace(
                "0x0000000000000000000000000000000000000000000000000000000000000001",
                secret,
            ),
        )
        .unwrap();
        let err = Config::load(&file).await.unwrap_err();
        let text = format!("{err} {err:?}");
        assert!(!text.contains("deadbeef"), "{text}");
        assert!(text.contains("line"));
    }

    #[test]
    fn parses_sample_config() {
        // The sample linked from the sentinel handbook must stay a valid,
        // loadable example of the schema above.
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("sentinel.sample.toml");
        let contents = std::fs::read_to_string(path).unwrap();
        toml::from_str::<Config>(&contents).unwrap();
    }
}
