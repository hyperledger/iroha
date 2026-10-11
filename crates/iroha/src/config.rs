//! Module for client-related configuration and structs
use crate::{
    crypto::KeyPair,
    data_model::{NetworkId, prelude::*},
};
use core::str::FromStr;
use derive_more::Display;
use error_stack::{AttachmentKind, FrameKind, Report, ResultExt};
use eyre::Result;
use iroha_config_base::{env::ReadEnv, read::ConfigReader, toml::TomlSource};
use iroha_model_base::chain::ChainId;
use iroha_primitives::small::SmallStr;
use iroha_service_model::soranet::AnonymityPolicy;
use iroha_service_model::soranet::RolloutPhase;
use norito::json::{self, JsonDeserialize, JsonSerialize};
use std::{fmt, path::Path, time::Duration};
use url::Url;
mod private_key_file;
mod user;
use crate::secrecy::SecretString;
pub use user::{
    AliasCache, MusubiFetch as MusubiFetchConfig,
    MusubiFetchProviderGateway as MusubiFetchProviderGatewayConfig,
    MusubiPublication as MusubiPublicationConfig,
    MusubiPublicationProviderGateway as MusubiPublicationProviderGatewayConfig, ParseError,
    Root as UserConfig,
};
type ReportResult<T, E> = core::result::Result<T, Report<[E]>>;
/// Resolve exactly one explicit public network identity source without loading a signer.
///
/// Callers resolve file paths relative to their configuration source before calling this
/// function. Identity files use the same bounded, canonical LF-terminated record as
/// [`Config::load_file`]. No process environment is consulted.
///
/// # Errors
/// Rejects missing or competing sources and malformed or unreadable identity files.
pub fn resolve_network_identity(
    inline: Option<NetworkId>,
    file: Option<&Path>,
) -> ReportResult<NetworkId, ParseError> {
    let mut emitter = iroha_config_base::util::Emitter::new();
    let identity = user::resolve_network_id_source(
        inline,
        file.map(|path| iroha_config_base::WithOrigin::inline(path.to_path_buf())),
        &mut emitter,
        &user::NativeConfigFiles,
    );
    emitter.into_result()?;
    identity.ok_or_else(|| Report::new(ParseError::InvalidNetworkIdentity).expand())
}

/// Treat a Torii API URL as a directory, as route joins require.
///
/// `https://host/peer-1` and `https://host/peer-1/` both address routes below
/// `/peer-1/`. Configuration files and [`crate::client::ClientBuilder::build`]
/// apply the same rule.
pub(crate) fn normalize_torii_api_url(mut url: Url) -> Url {
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    url
}

/// Default time-to-live for transactions submitted via the client API.
pub const DEFAULT_TRANSACTION_TIME_TO_LIVE: Duration = Duration::from_secs(100);
/// Mandatory lifetime of one signed query request.
///
/// Query requests are one-shot and are never automatically re-signed on retry. The node rejects
/// requests whose lifetime exceeds its configured replay-retention window.
pub const DEFAULT_QUERY_TIME_TO_LIVE: Duration = Duration::from_secs(100);
/// Default timeout for waiting on transaction status updates.
pub const DEFAULT_TRANSACTION_STATUS_TIMEOUT: Duration = Duration::from_secs(15);
/// Default timeout for Torii HTTP requests issued by the client.
///
/// This must remain above the Nexus routed/fanout HTTP budget so clients do
/// not abandon a request while Torii is still within its allowed route window.
pub const DEFAULT_TORII_REQUEST_TIMEOUT: Duration = Duration::from_secs(70);
/// Whether to add a random transaction nonce by default.
pub const DEFAULT_TRANSACTION_NONCE: bool = false;
/// Valid web auth login string. See [`WebLogin::from_str`]
#[derive(Debug, Display, Clone, PartialEq, Eq)]
pub struct WebLogin(SmallStr);
impl FromStr for WebLogin {
    type Err = eyre::ErrReport;
    /// Validates that the string is a valid web login
    ///
    /// # Errors
    /// Fails if `login` contains `:` character, which is the binary representation of the '\0'.
    fn from_str(login: &str) -> Result<Self> {
        if login.contains(':') {
            eyre::bail!("The `:` character, in `{login}` is not allowed");
        }
        Ok(Self(SmallStr::from_str(login)))
    }
}
impl WebLogin {
    /// Return the underlying login as a string slice.
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}
impl JsonSerialize for WebLogin {
    fn json_serialize(&self, out: &mut String) {
        self.as_str().json_serialize(out);
    }
}
impl JsonDeserialize for WebLogin {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let raw = parser.parse_string()?;
        Self::from_str(&raw).map_err(|err| json::Error::Message(err.to_string()))
    }
}
/// Basic Authentication credentials
#[derive(Clone, Debug)]
pub struct BasicAuth {
    /// Login for Basic Authentication
    pub web_login: WebLogin,
    /// Password for Basic Authentication
    pub password: SecretString,
}
impl JsonSerialize for BasicAuth {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        out.push_str("\"web_login\":");
        self.web_login.json_serialize(out);
        out.push(',');
        out.push_str("\"password\":");
        self.password.json_serialize(out);
        out.push('}');
    }
}
impl JsonDeserialize for BasicAuth {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let mut map = json::MapVisitor::new(parser)?;
        let mut web_login: Option<WebLogin> = None;
        let mut password: Option<SecretString> = None;
        while let Some(key) = map.next_key()? {
            match key.as_str() {
                "web_login" => {
                    if web_login.is_some() {
                        return Err(json::Error::duplicate_field("web_login"));
                    }
                    web_login = Some(map.parse_value::<WebLogin>()?);
                }
                "password" => {
                    if password.is_some() {
                        return Err(json::Error::duplicate_field("password"));
                    }
                    password = Some(map.parse_value::<SecretString>()?);
                }
                _ => map.skip_value()?,
            }
        }
        map.finish()?;
        Ok(Self {
            web_login: web_login.ok_or_else(|| json::Error::missing_field("web_login"))?,
            password: password.ok_or_else(|| json::Error::missing_field("password"))?,
        })
    }
}
/// Complete client configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// Unique chain identifier the client connects to.
    pub chain: ChainId,
    /// Exact genesis-lineage identity the client signs into query requests.
    pub network_id: NetworkId,
    /// Account ID used for signing and submitting transactions.
    pub account: AccountId,
    /// I105 chain discriminant used when parsing and rendering account literals.
    pub account_chain_discriminant: u16,
    /// Key pair corresponding to the account.
    pub key_pair: KeyPair,
    /// Optional Basic Auth credentials for HTTP.
    pub basic_auth: Option<BasicAuth>,
    /// Owner-held Torii listener credential, sent as `X-API-Token`.
    pub api_token: Option<SecretString>,
    /// Torii API base URL.
    pub torii_api_url: Url,
    /// Timeout for Torii HTTP requests.
    pub torii_request_timeout: Duration,
    /// Transaction time-to-live.
    pub transaction_ttl: Duration,
    /// Timeout for waiting on transaction status.
    pub transaction_status_timeout: Duration,
    /// Whether to add a random nonce to transactions.
    pub transaction_add_nonce: bool,
    /// Alias cache policy applied when validating `SoraFS` proofs.
    pub sorafs_alias_cache: sorafs_manifest::alias_cache::AliasCachePolicy,
    /// Default `SoraNet` anonymity policy stage for gateway fetches.
    pub sorafs_anonymity_policy: AnonymityPolicy,
    /// Configured rollout phase for staged PQ activation.
    pub sorafs_rollout_phase: RolloutPhase,
}
/// Context of every [`ConfigLoadError`].
#[derive(thiserror::Error, Debug, Copy, Clone)]
#[error("Failed to load configuration")]
pub struct LoadError;

/// Failure to load a client configuration, with every reported cause.
///
/// `Display` renders the failed contexts followed by their fix hints on one
/// line, so `?` into `eyre`, `anyhow` or `Box<dyn Error>` keeps the actionable
/// message. [`Self::report`] exposes the complete `error_stack` report.
pub struct ConfigLoadError(Report<[LoadError]>);

impl ConfigLoadError {
    /// The complete report, including parameter origins and fix hints.
    pub const fn report(&self) -> &Report<[LoadError]> {
        &self.0
    }

    /// Take the complete report.
    pub fn into_report(self) -> Report<[LoadError]> {
        self.0
    }
}

impl From<Report<LoadError>> for ConfigLoadError {
    fn from(report: Report<LoadError>) -> Self {
        Self(report.into())
    }
}

impl From<Report<[LoadError]>> for ConfigLoadError {
    fn from(report: Report<[LoadError]>) -> Self {
        Self(report)
    }
}

impl fmt::Debug for ConfigLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, formatter)
    }
}

impl fmt::Display for ConfigLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:#}", self.0)?;
        let mut separator = ": ";
        for frame in self.0.frames() {
            if let FrameKind::Attachment(AttachmentKind::Printable(hint)) = frame.kind() {
                write!(formatter, "{separator}{hint}")?;
                separator = "; ";
            }
        }
        Ok(())
    }
}

impl std::error::Error for ConfigLoadError {}
/// Invalid signer-free account network context from a client configuration.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum AccountChainDiscriminantError {
    /// Neither a public network profile nor an explicit discriminant was configured.
    #[error("account network context is missing: set a public profile or a chain discriminant")]
    Missing,
    /// The configured public network profile is unknown.
    #[error("unknown account network profile `{profile}`")]
    UnknownProfile {
        /// Supplied profile label.
        profile: String,
    },
    /// An explicit discriminant disagrees with the selected public profile.
    #[error(
        "account network profile `{profile}` expects chain discriminant {expected}, but {actual} was configured"
    )]
    ProfileMismatch {
        /// Canonical name of the selected public profile.
        profile: &'static str,
        /// I105 chain discriminant assigned to the profile.
        expected: u16,
        /// Explicitly configured I105 chain discriminant.
        actual: u16,
    },
    /// Zero is not a valid account chain discriminant.
    #[error("account chain discriminant must be nonzero")]
    Zero,
}
impl From<AccountChainDiscriminantError> for ParseError {
    fn from(error: AccountChainDiscriminantError) -> Self {
        match error {
            AccountChainDiscriminantError::Missing => Self::MissingAccountNetworkContext,
            AccountChainDiscriminantError::UnknownProfile { profile } => {
                Self::InvalidAccountProfile { profile }
            }
            AccountChainDiscriminantError::ProfileMismatch {
                profile,
                expected,
                actual,
            } => Self::AccountProfileDiscriminantMismatch {
                profile: profile.to_owned(),
                expected,
                actual,
            },
            AccountChainDiscriminantError::Zero => Self::ZeroAccountChainDiscriminant,
        }
    }
}
/// Resolve a client account network context to its I105 chain discriminant.
///
/// A known public `profile` (`taira`, `minamoto`; blank counts as absent) determines the
/// discriminant. An `explicit` discriminant selects any other network and must agree with a
/// profile when both are present. There is no default network: with neither input the context
/// is missing. [`Config::load`] applies exactly this rule to `account.profile` and
/// `account.chain_discriminant`; this helper constructs no account or key pair, so signer-free
/// clients validate the same public network context.
///
/// # Errors
/// Returns an error when both inputs are absent, for an unknown profile, for a
/// profile/discriminant mismatch, or for zero.
pub fn resolve_account_chain_discriminant(
    profile: Option<&str>,
    explicit: Option<u16>,
) -> Result<u16, AccountChainDiscriminantError> {
    let profile = profile.map(str::trim).filter(|profile| !profile.is_empty());
    let discriminant = match (profile, explicit) {
        (Some(name), explicit) => {
            let profile = iroha_torii_shared::network_profile(name).ok_or_else(|| {
                AccountChainDiscriminantError::UnknownProfile {
                    profile: name.to_owned(),
                }
            })?;
            if let Some(actual) = explicit.filter(|value| *value != profile.chain_discriminant) {
                return Err(AccountChainDiscriminantError::ProfileMismatch {
                    profile: profile.name,
                    expected: profile.chain_discriminant,
                    actual,
                });
            }
            profile.chain_discriminant
        }
        (None, Some(explicit)) => explicit,
        (None, None) => return Err(AccountChainDiscriminantError::Missing),
    };
    if discriminant == 0 {
        return Err(AccountChainDiscriminantError::Zero);
    }
    Ok(discriminant)
}
/// Where to load configuration from
pub enum LoadPath<P> {
    /// Path specified explicitly, therefore, loading will fail if the file is not found
    Explicit(P),
    /// Using the default path, therefore, loading will not fail if the file is not found
    Default(P),
}
impl Config {
    /// Load an already-read TOML table using its original source path.
    ///
    /// Applications can use this entry point after removing and validating their own top-level
    /// sections. The source path remains the provenance and relative-path base for SDK-owned
    /// parameters, and standard client environment overrides are applied.
    ///
    /// # Errors
    /// Returns an error when the table contains unknown or invalid SDK parameters, environment
    /// overrides are invalid, or completed client configuration validation fails.
    pub fn load_table(path: impl AsRef<Path>, table: toml::Table) -> Result<Self, ConfigLoadError> {
        Ok(ConfigReader::new()
            .with_toml_source(TomlSource::new(path.as_ref().to_path_buf(), table))
            .with_env(Box::new(iroha_config_base::env::std_env))
            .read_and_complete::<user::Root>()
            .change_context(LoadError)?
            .parse()
            .change_context(LoadError)?)
    }

    /// Load one required client configuration file without consulting process environment.
    ///
    /// This is intended for security-sensitive tools whose credential provenance must be the
    /// explicitly selected configuration file. Unlike [`Self::load`], no environment fallback
    /// or override is applied.
    ///
    /// # Errors
    /// Returns an error when the file cannot be read, its TOML is invalid, or the completed
    /// client configuration fails validation.
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self, ConfigLoadError> {
        let toml_source = TomlSource::from_file(path).change_context(LoadError)?;
        let config = ConfigReader::new()
            .with_toml_source(toml_source)
            .with_env(|_: &str| None::<std::borrow::Cow<'static, str>>)
            .read_and_complete::<user::Root>()
            .change_context(LoadError)?
            .parse()
            .change_context(LoadError)?;
        Ok(config)
    }
    /// Load a required platform client file and return its typed Musubi publication subtree.
    ///
    /// This path does not consult environment variables. Service URLs remain encapsulated in the
    /// returned redacting configuration and are never copied into the generic [`Client`](crate::client::Client).
    ///
    /// # Errors
    /// Returns an error when the selected file cannot be read, contains unknown or invalid
    /// parameters, or fails client configuration validation.
    pub fn load_file_with_musubi_publication(
        path: impl AsRef<Path>,
    ) -> Result<(Self, MusubiPublicationConfig), ConfigLoadError> {
        let toml_source = TomlSource::from_file(path).change_context(LoadError)?;
        Self::load_source_with_musubi_publication(toml_source)
    }
    /// Parse an already-read client TOML source and return its Musubi publication subtree.
    ///
    /// Security-sensitive callers use this entry point after opening a configuration file with
    /// no-follow semantics and reading it from one stable descriptor. The supplied `path` is
    /// retained as configuration provenance and as the base for relative public-proof paths;
    /// this function never reopens it.
    ///
    /// # Errors
    /// Returns an error when `bytes` are not UTF-8 TOML, contain unknown or invalid parameters,
    /// or fail client configuration validation.
    pub fn load_bytes_with_musubi_publication(
        path: impl AsRef<Path>,
        bytes: &[u8],
    ) -> Result<(Self, MusubiPublicationConfig), ConfigLoadError> {
        Self::load_bytes_with_musubi_publication_and_file_source(
            path,
            bytes,
            &user::NativeConfigFiles,
        )
    }
    /// Parse already-read client bytes using one explicit source for every referenced file.
    ///
    /// The source receives paths resolved against the original configuration provenance. Its
    /// errors are final; this parser never falls back to the filesystem for missing source bytes.
    /// The same canonical record and configuration validators handle both source kinds.
    ///
    /// # Errors
    /// Refuses invalid configuration, referenced file custody, oversized inputs or invalid records.
    pub fn load_bytes_with_musubi_publication_and_file_source(
        path: impl AsRef<Path>,
        bytes: &[u8],
        files: &dyn iroha_config_base::file_source::ConfigFileSource,
    ) -> Result<(Self, MusubiPublicationConfig), ConfigLoadError> {
        let source = core::str::from_utf8(bytes).change_context(LoadError)?;
        let table = source.parse::<toml::Table>().change_context(LoadError)?;
        Self::load_source_with_musubi_publication_and_file_source(
            TomlSource::new(path.as_ref().to_path_buf(), table),
            files,
        )
    }
    fn load_source_with_musubi_publication(
        toml_source: TomlSource,
    ) -> Result<(Self, MusubiPublicationConfig), ConfigLoadError> {
        Self::load_source_with_musubi_publication_and_file_source(
            toml_source,
            &user::NativeConfigFiles,
        )
    }
    fn load_source_with_musubi_publication_and_file_source(
        toml_source: TomlSource,
        files: &dyn iroha_config_base::file_source::ConfigFileSource,
    ) -> Result<(Self, MusubiPublicationConfig), ConfigLoadError> {
        Ok(ConfigReader::new()
            .with_toml_source(toml_source)
            .with_env(|_: &str| None::<std::borrow::Cow<'static, str>>)
            .read_and_complete::<user::Root>()
            .change_context(LoadError)?
            .parse_with_musubi_file_source(files)
            .change_context(LoadError)?)
    }
    /// Loads configuration from a file
    ///
    /// # Errors
    /// - unable to load config from a TOML file
    /// - the config is invalid
    pub fn load(path: LoadPath<impl AsRef<Path>>) -> Result<Self, ConfigLoadError> {
        Self::load_with_env(path, Box::new(iroha_config_base::env::std_env))
    }
    fn load_with_env(
        path: LoadPath<impl AsRef<Path>>,
        env: impl ReadEnv + 'static,
    ) -> Result<Self, ConfigLoadError> {
        let toml_source = match path {
            LoadPath::Explicit(path) => {
                Some(TomlSource::from_file(path).change_context(LoadError)?)
            }
            LoadPath::Default(path) => match TomlSource::from_file(path) {
                Ok(x) => Some(x),
                Err(err)
                    if matches!(
                        err.current_context(),
                        iroha_config_base::toml::FromFileError::Read
                    ) =>
                {
                    None
                }
                Err(err) => Err(err).change_context(LoadError)?,
            },
        };
        let config = toml_source
            .map_or_else(ConfigReader::new, |x| {
                ConfigReader::new().with_toml_source(x)
            })
            .with_env(env)
            .read_and_complete::<user::Root>()
            .change_context(LoadError)?
            .parse()
            .change_context(LoadError)?;
        Ok(config)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signer_free_network_identity_uses_exactly_one_canonical_source() {
        let expected: NetworkId =
            "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
                .parse()
                .unwrap();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), format!("{expected}\n")).unwrap();
        assert_eq!(
            resolve_network_identity(None, Some(file.path())).unwrap(),
            expected
        );
        assert_eq!(
            resolve_network_identity(Some(expected), None).unwrap(),
            expected
        );
        assert!(resolve_network_identity(None, None).is_err());
        assert!(resolve_network_identity(Some(expected), Some(file.path())).is_err());
        std::fs::write(file.path(), expected.to_string()).unwrap();
        assert!(resolve_network_identity(None, Some(file.path())).is_err());
    }

    use assertables::assert_contains;
    use iroha_config_base::env::MockEnv;
    use iroha_crypto::ExposedPrivateKey;
    use std::{collections::HashSet, io::Write};
    fn checked_random_keypair() -> KeyPair {
        KeyPair::try_random().expect("generate checked config fixture keypair")
    }

    #[test]
    fn web_login_string_boundaries_preserve_text_json_and_colon_rejection() {
        for sample in [
            String::new(),
            "a".repeat(15),
            "a".repeat(16),
            "a".repeat(32),
            "a".repeat(33),
            "Δ🔥\\\n".repeat(32),
        ] {
            let login: WebLogin = sample.parse().expect("login without a colon");
            assert_eq!(login.as_str(), sample);
            let encoded = json::to_json(&login).expect("login JSON");
            assert_eq!(encoded, json::to_json(&sample).expect("string JSON"));
            let decoded: WebLogin = json::from_json(&encoded).expect("login decode");
            assert_eq!(decoded, login);
            let invalid = format!("{sample}:suffix");
            assert!(invalid.parse::<WebLogin>().is_err());
            let invalid_json = json::to_json(&invalid).expect("invalid login JSON");
            assert!(json::from_json::<WebLogin>(&invalid_json).is_err());
        }
    }

    #[test]
    fn web_login_ok() {
        let _ok: WebLogin = "alice".parse().expect("input is valid");
    }
    #[test]
    fn web_login_bad() {
        let _err = "alice:wonderland"
            .parse::<WebLogin>()
            .expect_err("input has `:`");
    }
    fn config_sample() -> toml::Table {
        toml::toml! {
            chain = "00000000-0000-0000-0000-000000000000"
            network_id = "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
            torii_url = "http://127.0.0.1:8080/"
            [basic_auth]
            web_login = "mad_hatter"
            password = "ilovetea"
            [account]
            chain_discriminant = 753
            public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            private_key = "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
            [transaction]
            time_to_live_ms = 100_000
            status_timeout_ms = 100_000
            nonce = false
        }
    }
    #[test]
    fn parse_full_toml_config() {
        ConfigReader::new()
            .with_toml_source(TomlSource::inline(config_sample()))
            .read_and_complete::<user::Root>()
            .unwrap();
    }
    #[test]
    fn owner_api_token_loads_without_exposure_in_debug() {
        let token = "owner-only-listener-token-for-config-test";
        let mut table = config_sample();
        table.insert("api_token".into(), toml::Value::String(token.into()));
        let config = ConfigReader::new()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<user::Root>()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(config.api_token.as_ref().unwrap().expose_secret(), token);
        assert!(!format!("{config:?}").contains(token));
    }
    #[test]
    fn sdk_config_rejects_cli_owned_filesystem_sections() {
        for (section, value) in [
            (
                "connect",
                toml::Value::Table(toml::toml! { queue_root = "/tmp/connect" }),
            ),
            (
                "soracloud",
                toml::Value::Table(toml::toml! { http_witness_file = "/tmp/witness.json" }),
            ),
        ] {
            let mut table = config_sample();
            table.insert(section.to_owned(), value);
            let error = ConfigReader::new()
                .with_toml_source(TomlSource::inline(table))
                .read_and_complete::<user::Root>()
                .expect_err("CLI-owned sections must not be accepted by SDK configuration");
            assert_contains!(format!("{error:?}"), section);
        }
    }
    #[test]
    fn account_private_key_file_populates_signer() {
        let mut table = config_sample();
        let account = table
            .get_mut("account")
            .and_then(toml::Value::as_table_mut)
            .expect("client account table");
        let private_key = account
            .remove("private_key")
            .and_then(|value| value.as_str().map(str::to_owned))
            .expect("inline client private key");
        let mut key_file = tempfile::NamedTempFile::new().expect("client private-key file");
        writeln!(key_file, "{private_key}").expect("write client private-key file");
        key_file.flush().expect("flush client private-key file");
        account.insert(
            "private_key_file".into(),
            toml::Value::String(key_file.path().to_string_lossy().into_owned()),
        );
        let config = ConfigReader::new()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<user::Root>()
            .expect("file-backed client config should complete")
            .parse()
            .expect("file-backed client config should parse");
        assert_eq!(
            ExposedPrivateKey(config.key_pair.private_key().clone()).to_string(),
            private_key
        );
    }
    #[test]
    fn load_table_preserves_source_path_for_relative_key_files() {
        let mut table = config_sample();
        let account = table
            .get_mut("account")
            .and_then(toml::Value::as_table_mut)
            .expect("client account table");
        let private_key = account
            .remove("private_key")
            .and_then(|value| value.as_str().map(str::to_owned))
            .expect("inline client private key");
        let directory = tempfile::tempdir().expect("client configuration directory");
        let key_path = directory.path().join("account.key");
        std::fs::write(&key_path, format!("{private_key}\n"))
            .expect("write relative client private-key file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .expect("restrict client private-key permissions");
        }
        account.insert(
            "private_key_file".into(),
            toml::Value::String("account.key".to_owned()),
        );
        let config = Config::load_table(directory.path().join("client.toml"), table)
            .expect("relative key path should resolve from supplied source path");
        assert_eq!(
            ExposedPrivateKey(config.key_pair.private_key().clone()).to_string(),
            private_key
        );
    }
    #[test]
    fn account_private_key_sources_are_mutually_exclusive() {
        let mut table = config_sample();
        let account = table
            .get_mut("account")
            .and_then(toml::Value::as_table_mut)
            .expect("client account table");
        let key_file = tempfile::NamedTempFile::new().expect("client private-key file");
        account.insert(
            "private_key_file".into(),
            toml::Value::String(key_file.path().to_string_lossy().into_owned()),
        );
        let error = ConfigReader::new()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<user::Root>()
            .expect("duplicate private sources remain structurally readable")
            .parse()
            .expect_err("duplicate client private sources must fail");
        assert_contains!(
            format!("{error:#?}"),
            "account.private_key and account.private_key_file are mutually exclusive"
        );
    }
    #[test]
    fn load_errors_are_std_errors_with_actionable_messages() {
        #[derive(Debug, thiserror::Error)]
        #[error("outer context")]
        struct Outer;
        fn assert_std_error<E: std::error::Error + Send + Sync + 'static>(_: &E) {}

        let mut table = config_sample();
        table
            .get_mut("account")
            .and_then(toml::Value::as_table_mut)
            .expect("client account table")
            .remove("private_key");
        let error = Config::load_table("client.toml", table).expect_err("missing signer");
        assert_std_error(&error);
        let message = error.to_string();
        assert!(
            message.starts_with("Failed to load configuration: "),
            "{message}"
        );
        assert_contains!(message, "missing account private-key source");
        assert_contains!(format!("{error:?}"), "missing account private-key source");
        let report: eyre::Report = error.into();
        assert_contains!(report.to_string(), "missing account private-key source");

        let missing = tempfile::tempdir()
            .expect("directory")
            .path()
            .join("client.toml");
        let error = Config::load_file(&missing).expect_err("missing file");
        assert_contains!(
            format!("{:?}", error.report()),
            "Failed to load configuration"
        );
        // `error_stack` callers keep composing contexts on the typed error.
        let wrapped = Config::load_file(&missing).change_context(Outer);
        assert_eq!(
            wrapped
                .expect_err("missing file")
                .current_context()
                .to_string(),
            "outer context"
        );
    }
    #[test]
    fn builder_and_loader_share_trailing_slash_normalization() {
        for (raw, expected) in [
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080/"),
            ("http://127.0.0.1/peer-1", "http://127.0.0.1/peer-1/"),
            ("http://127.0.0.1/peer-1/", "http://127.0.0.1/peer-1/"),
        ] {
            let url = Url::parse(raw).expect("URL");
            assert_eq!(normalize_torii_api_url(url).as_str(), expected);
        }
    }
    #[test]
    fn torii_url_scheme_support() {
        fn with_scheme(scheme: &str) -> ReportResult<Config, user::ParseError> {
            ConfigReader::new()
                .with_toml_source(TomlSource::inline(config_sample()))
                .with_env(MockEnv::from([(
                    "TORII_URL",
                    format!("{scheme}://127.0.0.1:8080"),
                )]))
                .read_and_complete::<user::Root>()
                .unwrap()
                .parse()
        }
        let _ = with_scheme("http").expect("should be fine");
        let _ = with_scheme("https").expect("should be fine");
        let _ = with_scheme("ws").expect_err("not supported");
    }
    #[test]
    fn torii_url_ensure_trailing_slash() {
        let config = ConfigReader::new()
            .with_toml_source(TomlSource::inline(config_sample()))
            .with_env(MockEnv::from([("TORII_URL", "http://127.0.0.1/peer-1")]))
            .read_and_complete::<user::Root>()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(config.torii_api_url.as_str(), "http://127.0.0.1/peer-1/");
    }
    #[test]
    fn invalid_toml_file_is_handled_properly() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"not a valid toml").unwrap();
        let err =
            Config::load(LoadPath::Explicit(file.path())).expect_err("should fail on toml parsing");
        assert_contains!(
            format!("{err:#?}"),
            "Error while deserializing file contents as TOML"
        );
    }
    #[test]
    fn reads_default_path() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(toml::to_string(&config_sample()).unwrap().as_bytes())
            .unwrap();
        let config = Config::load(LoadPath::Default(file.path())).unwrap();
        assert_eq!(
            config.account.expect_single_signatory().to_string(),
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
        );
    }
    #[test]
    fn load_file_requires_and_parses_the_selected_file() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(toml::to_string(&config_sample()).unwrap().as_bytes())
            .unwrap();
        let config = Config::load_file(file.path()).expect("load explicit file without fallback");
        assert_eq!(config.torii_api_url.as_str(), "http://127.0.0.1:8080/");
        assert!(
            Config::load_file(file.path().with_extension("missing")).is_err(),
            "the selected file is mandatory"
        );
    }
    #[test]
    fn load_bytes_with_musubi_publication_never_reopens_path() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("already-read-client.toml");
        let bytes = toml::to_string(&config_sample()).expect("serialize client fixture");
        let (config, publication) =
            Config::load_bytes_with_musubi_publication(&path, bytes.as_bytes())
                .expect("parse supplied client bytes");
        assert_eq!(config.torii_api_url.as_str(), "http://127.0.0.1:8080/");
        assert!(publication.seed_ingress_url.is_none());
        assert!(
            !path.exists(),
            "parsing an already-read source must not create or reopen its provenance path"
        );
    }
    struct CapturedConfigFiles {
        values: std::collections::BTreeMap<
            std::path::PathBuf,
            (iroha_config_base::file_source::ConfigFileAccess, Vec<u8>),
        >,
        reads: std::cell::RefCell<Vec<std::path::PathBuf>>,
    }
    impl iroha_config_base::file_source::ConfigFileSource for CapturedConfigFiles {
        fn read(
            &self,
            path: &Path,
            request: iroha_config_base::file_source::ConfigFileRequest,
        ) -> std::io::Result<zeroize::Zeroizing<Vec<u8>>> {
            self.reads.borrow_mut().push(path.to_path_buf());
            let (access, bytes) = self.values.get(path).ok_or(std::io::ErrorKind::NotFound)?;
            if *access != request.access {
                return Err(std::io::ErrorKind::PermissionDenied.into());
            }
            // Deliberately leave the size check to the canonical parser boundary.
            Ok(zeroize::Zeroizing::new(bytes.clone()))
        }
    }

    fn referenced_client_fixture(path: &Path) -> (String, CapturedConfigFiles) {
        use iroha_config_base::file_source::ConfigFileAccess;
        let mut table = config_sample();
        let identity = table
            .remove("network_id")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        table.insert(
            "network_id_file".into(),
            toml::Value::String("network.identity".into()),
        );
        let account = table.get_mut("account").unwrap().as_table_mut().unwrap();
        let key = account
            .remove("private_key")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        account.insert(
            "private_key_file".into(),
            toml::Value::String("account.key".into()),
        );
        let root = path.parent().unwrap();
        let files = CapturedConfigFiles {
            values: [
                (
                    root.join("network.identity"),
                    (
                        ConfigFileAccess::Public,
                        format!("{identity}\n").into_bytes(),
                    ),
                ),
                (
                    root.join("account.key"),
                    (ConfigFileAccess::Private, format!("{key}\n").into_bytes()),
                ),
            ]
            .into_iter()
            .collect(),
            reads: std::cell::RefCell::new(Vec::new()),
        };
        (toml::to_string(&table).unwrap(), files)
    }

    #[test]
    fn supplied_client_files_preserve_origins_and_use_the_canonical_parser_without_disk() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("absent/client.toml");
        let (source, files) = referenced_client_fixture(&path);
        let (actual, _) = Config::load_bytes_with_musubi_publication_and_file_source(
            &path,
            source.as_bytes(),
            &files,
        )
        .unwrap();
        let ordinary_source = toml::to_string(&config_sample()).unwrap();
        let (expected, _) =
            Config::load_bytes_with_musubi_publication(&path, ordinary_source.as_bytes()).unwrap();
        assert_eq!(actual.account, expected.account);
        assert_eq!(actual.network_id, expected.network_id);
        assert_eq!(actual.chain, expected.chain);
        assert_eq!(actual.torii_api_url, expected.torii_api_url);
        assert!(actual.key_pair == expected.key_pair);
        assert_eq!(
            files.reads.borrow().as_slice(),
            &[
                path.with_file_name("network.identity"),
                path.with_file_name("account.key")
            ]
        );
        assert!(!path.parent().unwrap().exists());
    }

    #[test]
    fn supplied_client_files_refuse_missing_oversized_and_malformed_inputs_without_fallback() {
        let temporary = tempfile::tempdir().unwrap();
        let directory =
            iroha_fs::PrivateDirectory::open_or_create(temporary.path().join("client")).unwrap();
        let path = directory.path().join("client.toml");
        let (source, mut files) = referenced_client_fixture(&path);
        for (file, (_, bytes)) in &files.values {
            directory
                .write_atomic(
                    file.file_name().unwrap(),
                    bytes,
                    iroha_fs::PublishMode::CreateNew,
                )
                .unwrap();
        }
        let (native, _) =
            Config::load_bytes_with_musubi_publication(&path, source.as_bytes()).unwrap();
        let (captured, _) = Config::load_bytes_with_musubi_publication_and_file_source(
            &path,
            source.as_bytes(),
            &files,
        )
        .unwrap();
        assert_eq!(native.account, captured.account);
        assert_eq!(native.network_id, captured.network_id);
        for (name, replacement) in [
            ("network.identity", Vec::new()),
            ("network.identity", vec![b'x'; 513]),
            ("account.key", vec![b'x'; 4097]),
            ("account.key", b"not a canonical key\n".to_vec()),
        ] {
            let key = path.with_file_name(name);
            let prior = files.values.get_mut(&key).unwrap();
            let original = std::mem::replace(&mut prior.1, replacement);
            assert!(
                Config::load_bytes_with_musubi_publication_and_file_source(
                    &path,
                    source.as_bytes(),
                    &files
                )
                .is_err()
            );
            files.values.get_mut(&key).unwrap().1 = original;
        }
        let mut conflicting = source.parse::<toml::Table>().unwrap();
        let inline = config_sample()["account"]["private_key"].clone();
        conflicting
            .get_mut("account")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .insert("private_key".into(), inline);
        let error = Config::load_bytes_with_musubi_publication_and_file_source(
            &path,
            toml::to_string(&conflicting).unwrap().as_bytes(),
            &files,
        )
        .unwrap_err();
        assert!(format!("{error:?}").contains("mutually exclusive"));
        let identity_path = path.with_file_name("network.identity");
        let private_key_path = path.with_file_name("account.key");
        let original_identity = std::mem::replace(
            &mut files.values.get_mut(&identity_path).unwrap().1,
            b"invalid-network".to_vec(),
        );
        let original_private_key = std::mem::replace(
            &mut files.values.get_mut(&private_key_path).unwrap().1,
            b"private-sentinel".to_vec(),
        );
        let error = Config::load_bytes_with_musubi_publication_and_file_source(
            &path,
            source.as_bytes(),
            &files,
        )
        .unwrap_err();
        let diagnostic = format!("{error:?}");
        assert!(diagnostic.contains("network_id_file"));
        assert!(diagnostic.contains("account.private_key_file"));
        assert!(!diagnostic.contains("private-sentinel"));
        files.values.get_mut(&identity_path).unwrap().1 = original_identity;
        files.values.get_mut(&private_key_path).unwrap().1 = original_private_key;
        Config::load_bytes_with_musubi_publication(&path, source.as_bytes())
            .expect("all disk inputs remain valid before one-at-a-time source refusals");
        let references: Vec<_> = files.values.keys().cloned().collect();
        assert_eq!(references.len(), 2);
        for missing in references {
            Config::load_bytes_with_musubi_publication_and_file_source(
                &path,
                source.as_bytes(),
                &files,
            )
            .expect("every supplied input is valid immediately before removing one");
            let input = files.values.remove(&missing).unwrap();
            files.reads.borrow_mut().clear();
            let error = Config::load_bytes_with_musubi_publication_and_file_source(
                &path,
                source.as_bytes(),
                &files,
            )
            .expect_err("valid disk bytes must not replace one absent supplied input");
            assert!(files.reads.borrow().contains(&missing));
            assert!(format!("{error:?}").contains(missing.file_name().unwrap().to_str().unwrap()));
            files.values.insert(missing, input);
        }
    }

    #[test]
    fn signer_free_chain_discriminant_resolution_matches_profiles() {
        assert_eq!(
            resolve_account_chain_discriminant(Some("taira"), None).expect("known profile"),
            iroha_torii_shared::TAIRA_CHAIN_DISCRIMINANT
        );
        assert_eq!(
            resolve_account_chain_discriminant(Some(" Minamoto "), None).expect("known profile"),
            iroha_torii_shared::MINAMOTO_CHAIN_DISCRIMINANT
        );
        assert_eq!(
            resolve_account_chain_discriminant(None, Some(777)).expect("explicit discriminant"),
            777
        );
        assert_eq!(
            resolve_account_chain_discriminant(Some("taira"), Some(369)).expect("matching pair"),
            369
        );
        assert_eq!(
            resolve_account_chain_discriminant(Some("taira"), Some(753)),
            Err(AccountChainDiscriminantError::ProfileMismatch {
                profile: iroha_torii_shared::NETWORK_PROFILE_TAIRA,
                expected: iroha_torii_shared::TAIRA_CHAIN_DISCRIMINANT,
                actual: 753,
            })
        );
        assert_eq!(
            resolve_account_chain_discriminant(Some("unknownnet"), Some(777)),
            Err(AccountChainDiscriminantError::UnknownProfile {
                profile: "unknownnet".to_owned(),
            })
        );
        assert_eq!(
            resolve_account_chain_discriminant(None, Some(0)),
            Err(AccountChainDiscriminantError::Zero)
        );
        for profile in [None, Some(""), Some(" ")] {
            assert_eq!(
                resolve_account_chain_discriminant(profile, None),
                Err(AccountChainDiscriminantError::Missing),
                "{profile:?} must not select a default network"
            );
        }
    }
    #[test]
    fn signer_free_resolution_errors_map_onto_parse_errors() {
        assert_eq!(
            ParseError::from(AccountChainDiscriminantError::Missing),
            ParseError::MissingAccountNetworkContext
        );
        assert_eq!(
            ParseError::from(AccountChainDiscriminantError::UnknownProfile {
                profile: "unknownnet".to_owned(),
            }),
            ParseError::InvalidAccountProfile {
                profile: "unknownnet".to_owned(),
            }
        );
        assert_eq!(
            ParseError::from(AccountChainDiscriminantError::ProfileMismatch {
                profile: iroha_torii_shared::NETWORK_PROFILE_TAIRA,
                expected: iroha_torii_shared::TAIRA_CHAIN_DISCRIMINANT,
                actual: 753,
            }),
            ParseError::AccountProfileDiscriminantMismatch {
                profile: iroha_torii_shared::NETWORK_PROFILE_TAIRA.to_owned(),
                expected: iroha_torii_shared::TAIRA_CHAIN_DISCRIMINANT,
                actual: 753,
            }
        );
        assert_eq!(
            ParseError::from(AccountChainDiscriminantError::Zero),
            ParseError::ZeroAccountChainDiscriminant
        );
    }
    fn account_table(table: &mut toml::Table) -> &mut toml::Table {
        table
            .get_mut("account")
            .and_then(toml::Value::as_table_mut)
            .expect("client account table")
    }
    fn load_without_env(table: toml::Table) -> Result<Config, ConfigLoadError> {
        Ok(ConfigReader::new()
            .without_env()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<user::Root>()
            .change_context(LoadError)?
            .parse()
            .change_context(LoadError)?)
    }
    #[test]
    fn loader_requires_explicit_account_network_context() {
        let mut table = config_sample();
        account_table(&mut table).remove("chain_discriminant");
        let error = load_without_env(table.clone())
            .expect_err("a client config without network context must not default to mainnet");
        assert!(
            error
                .report()
                .frames()
                .filter_map(|frame| frame.downcast_ref::<ParseError>())
                .any(|error| *error == ParseError::MissingAccountNetworkContext),
            "{error:?}"
        );
        assert_contains!(error.to_string(), "account.profile");

        account_table(&mut table).insert("profile".into(), toml::Value::String("taira".into()));
        let config = load_without_env(table.clone()).expect("profile context");
        assert_eq!(
            config.account_chain_discriminant,
            iroha_torii_shared::TAIRA_CHAIN_DISCRIMINANT
        );

        account_table(&mut table).insert("chain_discriminant".into(), toml::Value::Integer(753));
        let error = load_without_env(table)
            .expect_err("an explicit discriminant must agree with the profile");
        assert!(
            error
                .report()
                .frames()
                .filter_map(|frame| frame.downcast_ref::<ParseError>())
                .any(|error| matches!(
                    error,
                    ParseError::AccountProfileDiscriminantMismatch { actual: 753, .. }
                )),
            "{error:?}"
        );
    }
    #[test]
    fn loader_rejects_retired_account_domain() {
        let mut table = config_sample();
        account_table(&mut table).insert(
            "domain".into(),
            toml::Value::String("wonderland.universal".into()),
        );
        let error = ConfigReader::new()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<user::Root>()
            .expect_err("`account.domain` is not a client configuration parameter");
        let unknown: Vec<String> = error
            .frames()
            .filter_map(|frame| frame.downcast_ref::<iroha_config_base::attach::UnknownParameter>())
            .map(ToString::to_string)
            .collect();
        assert_eq!(unknown, ["unknown parameter: `account.domain`"]);
    }
    #[test]
    fn env_account_domain_is_not_read() {
        let key = checked_random_keypair();
        let env = MockEnv::new()
            .set("CHAIN", "wonder")
            .set(
                "NETWORK_ID",
                "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0",
            )
            .set("TORII_URL", "http://localhost:8080")
            .set("ACCOUNT_CHAIN_DISCRIMINANT", "777")
            .set("ACCOUNT_DOMAIN", "land.universal")
            .set(
                "ACCOUNT_PRIVATE_KEY",
                ExposedPrivateKey(key.private_key().clone()).to_string(),
            )
            .set("ACCOUNT_PUBLIC_KEY", key.public_key().to_string());
        let config =
            Config::load_with_env(LoadPath::Default("non_existing_path"), env.clone()).unwrap();
        assert_eq!(config.account_chain_discriminant, 777);
        assert_eq!(
            env.unvisited(),
            HashSet::from(["ACCOUNT_DOMAIN".to_owned()]),
            "the retired account scope must not be an environment parameter"
        );
    }
    #[test]
    fn full_env_fallback() {
        let key = checked_random_keypair();
        let env = MockEnv::new()
            .set("CHAIN", "wonder")
            .set(
                "NETWORK_ID",
                "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0",
            )
            .set("TORII_URL", "http://localhost:8080")
            .set("ACCOUNT_PROFILE", iroha_torii_shared::NETWORK_PROFILE_TAIRA)
            .set(
                "ACCOUNT_CHAIN_DISCRIMINANT",
                iroha_torii_shared::TAIRA_CHAIN_DISCRIMINANT.to_string(),
            )
            .set(
                "ACCOUNT_PRIVATE_KEY",
                ExposedPrivateKey(key.private_key().clone()).to_string(),
            )
            .set("ACCOUNT_PUBLIC_KEY", key.public_key().to_string());
        let _config =
            Config::load_with_env(LoadPath::Default("non_existing_path"), env.clone()).unwrap();
        assert_eq!(env.unvisited(), HashSet::new());
        assert_eq!(
            env.unknown(),
            HashSet::from(["ACCOUNT_PRIVATE_KEY_FILE".to_owned()]),
            "the mutually exclusive file-backed private-key source must still be inspected"
        );
    }
}
