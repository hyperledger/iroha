//! Utility crate for standardized and random signatories.

/// Deterministic private-settlement protocol and custody fixtures.
pub mod private_settlement;
use iroha_crypto::KeyPair;
#[cfg(feature = "rand")]
use iroha_crypto::{Algorithm, Error as CryptoError, Hash};
use iroha_data_model::prelude::{AccountId, IvmBytecode};
use iroha_model_base::domain::DomainId;
#[cfg(all(test, feature = "rand"))]
use std::cell::RefCell;
#[cfg(feature = "rand")]
use std::sync::Once;
#[cfg(feature = "rand")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
    sync::LazyLock,
};
/// Generate a domainless [`AccountId`] using the given `domain` label as seed scope.
///
/// # Panics
///
/// Panics if the given `domain` is invalid as a [`DomainId`] label.
#[cfg(feature = "rand")]
pub fn gen_account_in(domain: impl core::fmt::Display) -> (AccountId, KeyPair) {
    try_gen_account_in(domain).expect("test sample account key generation should succeed")
}
/// Fallibly generate a domainless [`AccountId`] using the given `domain` label as seed scope.
///
/// # Errors
///
/// Returns a crypto error if OS-backed random key generation fails or if seeded
/// calibration key derivation fails.
///
/// # Panics
///
/// Panics if the given `domain` is invalid as a [`DomainId`] label.
#[cfg(feature = "rand")]
pub fn try_gen_account_in(
    domain: impl core::fmt::Display,
) -> Result<(AccountId, KeyPair), CryptoError> {
    let domain_str = domain.to_string();
    let key_pair = match calibration_base_seed() {
        Some(base_seed) => {
            log_active_seed_once(&base_seed);
            let seed_bytes = next_calibration_seed(&base_seed, &domain_str);
            KeyPair::try_from_seed(seed_bytes, Algorithm::default())?
        }
        None => KeyPair::try_random()?,
    };
    let _: DomainId =
        DomainId::try_new(domain_str.as_str(), "universal").expect("domain name should be valid");
    let account_id = AccountId::new(key_pair.public_key().clone());
    Ok((account_id, key_pair))
}
#[cfg(feature = "rand")]
static CALIBRATION_COUNTER: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "rand")]
static CALIBRATION_LOG_ONCE: Once = Once::new();
#[cfg(feature = "rand")]
fn calibration_base_seed() -> Option<String> {
    #[cfg(all(test, feature = "rand"))]
    {
        let override_value = CALIBRATION_SEED_OVERRIDE
            .with(|state| state.borrow().as_ref().map(|state| state.base_seed.clone()));
        if override_value.is_some() {
            return override_value;
        }
    }
    std::env::var("IROHA_CONF_GAS_SEED").ok()
}
#[cfg(feature = "rand")]
fn next_calibration_seed(base_seed: &str, domain: &str) -> Vec<u8> {
    #[cfg(test)]
    let fixture_ordinal = CALIBRATION_SEED_OVERRIDE.with(|state| {
        state.borrow_mut().as_mut().map(|state| {
            let ordinal = state.next_ordinal;
            state.next_ordinal = state.next_ordinal.wrapping_add(1);
            ordinal
        })
    });
    #[cfg(test)]
    let ordinal =
        fixture_ordinal.unwrap_or_else(|| CALIBRATION_COUNTER.fetch_add(1, Ordering::Relaxed));
    #[cfg(not(test))]
    let ordinal = CALIBRATION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let material = format!("{base_seed}:{domain}:{ordinal}");
    let hash_bytes: [u8; Hash::LENGTH] = Hash::new(material).into();
    hash_bytes.to_vec()
}
#[cfg(feature = "rand")]
fn log_active_seed_once(base_seed: &str) {
    CALIBRATION_LOG_ONCE.call_once(|| {
        println!("IROHA_CONF_GAS_SEED_ACTIVE={base_seed}");
    });
}
#[cfg(all(test, feature = "rand"))]
struct CalibrationSeedState {
    base_seed: String,
    next_ordinal: u64,
}
#[cfg(all(test, feature = "rand"))]
thread_local! {
    // Each synchronous sample test owns its seed and ordinal on its test thread.
    static CALIBRATION_SEED_OVERRIDE: RefCell<Option<CalibrationSeedState>> = const { RefCell::new(None) };
}
#[cfg(all(test, feature = "rand"))]
struct CalibrationSeedFixture {
    previous: Option<CalibrationSeedState>,
    // A scoped override must be restored on the thread that installed it.
    thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
#[cfg(all(test, feature = "rand"))]
impl CalibrationSeedFixture {
    fn new(base_seed: &str) -> Self {
        let previous = CALIBRATION_SEED_OVERRIDE.with(|state| {
            state.replace(Some(CalibrationSeedState {
                base_seed: base_seed.to_owned(),
                next_ordinal: 0,
            }))
        });
        Self {
            previous,
            thread: std::marker::PhantomData,
        }
    }
}
#[cfg(all(test, feature = "rand"))]
impl Drop for CalibrationSeedFixture {
    fn drop(&mut self) {
        let _ = CALIBRATION_SEED_OVERRIDE.with(|state| state.replace(self.previous.take()));
    }
}
#[cfg(all(test, feature = "rand"))]
mod calibration_tests {
    use super::*;
    use iroha_data_model::prelude::AccountId;
    #[test]
    fn gen_account_in_uses_seed_when_present() {
        let seed_value = "test-seed";
        let _fixture = CalibrationSeedFixture::new(seed_value);
        let (account, key_pair) = super::gen_account_in("wonderland");
        let material = format!("{seed_value}:wonderland:0");
        let hash_bytes: [u8; Hash::LENGTH] = Hash::new(material).into();
        let expected_key = KeyPair::try_from_seed(hash_bytes.to_vec(), Algorithm::default())
            .expect("fixed calibration seed must derive");
        let expected_account = AccountId::new(expected_key.public_key().clone());
        assert_eq!(account, expected_account);
        assert_eq!(key_pair.public_key(), expected_key.public_key());
    }
    #[test]
    fn try_gen_account_in_uses_checked_seed_derivation() {
        let seed_value = "checked-test-seed";
        let _fixture = CalibrationSeedFixture::new(seed_value);
        let (account, key_pair) =
            super::try_gen_account_in("wonderland").expect("checked sample account");
        let material = format!("{seed_value}:wonderland:0");
        let hash_bytes: [u8; Hash::LENGTH] = Hash::new(material).into();
        let expected_key = KeyPair::try_from_seed(hash_bytes.to_vec(), Algorithm::default())
            .expect("fixed calibration seed must derive");
        assert_eq!(account, AccountId::new(expected_key.public_key().clone()));
        assert_eq!(
            key_pair
                .public_key()
                .try_algorithm()
                .expect("sample account public-key algorithm"),
            Algorithm::default()
        );
        assert_eq!(key_pair.public_key(), expected_key.public_key());
    }
    #[test]
    fn calibration_seed_fixtures_are_parallel_and_restore_nested_sequences() {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let workers = ["parallel-seed-one", "parallel-seed-two"].map(|seed| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let fixture = CalibrationSeedFixture::new(seed);
                barrier.wait();
                for ordinal in 0..2 {
                    if ordinal == 1 {
                        let unwound = std::panic::catch_unwind(|| {
                            let _nested = CalibrationSeedFixture::new("unwinding-seed");
                            let (account, key_pair) = try_gen_account_in("wonderland")
                                .expect("unwinding calibration account");
                            assert_derived_account(&account, &key_pair, "unwinding-seed", 0);
                            panic!("nested calibration fixture unwind");
                        });
                        let payload = unwound.expect_err("nested fixture must unwind");
                        assert_eq!(
                            payload.downcast_ref::<&str>(),
                            Some(&"nested calibration fixture unwind")
                        );
                        let _nested = CalibrationSeedFixture::new("nested-seed");
                        let (account, key_pair) =
                            try_gen_account_in("wonderland").expect("nested calibration account");
                        assert_derived_account(&account, &key_pair, "nested-seed", 0);
                    }
                    let (account, key_pair) =
                        try_gen_account_in("wonderland").expect("parallel calibration account");
                    assert_derived_account(&account, &key_pair, seed, ordinal);
                }
                drop(fixture);
                assert!(CALIBRATION_SEED_OVERRIDE.with(|state| state.borrow().is_none()));
            })
        });
        for worker in workers {
            worker.join().expect("parallel seed fixture assertions");
        }
    }
    fn assert_derived_account(account: &AccountId, key_pair: &KeyPair, seed: &str, ordinal: u64) {
        let hash_bytes: [u8; Hash::LENGTH] =
            Hash::new(format!("{seed}:wonderland:{ordinal}")).into();
        let expected_key = KeyPair::try_from_seed(hash_bytes.to_vec(), Algorithm::default())
            .expect("fixed calibration seed must derive");
        assert_eq!(account, &AccountId::new(expected_key.public_key().clone()));
        assert_eq!(key_pair.public_key(), expected_key.public_key());
    }
    #[test]
    fn toml_profile_key_parses() {
        let value: toml::Value =
            toml::from_str("profile = \"Debug\"").expect("toml document with profile key");
        assert_eq!(
            value.get("profile").and_then(toml::Value::as_str),
            Some("Debug")
        );
    }
}
macro_rules! declare_keypair {
    ( $key_pair:ident, $public_key:expr, $private_key:expr ) => {
        /// A standardized [`KeyPair`].
        pub static $key_pair: LazyLock<KeyPair> = LazyLock::new(|| {
            KeyPair::new(
                $public_key
                    .parse()
                    .expect(r#"public_key should be valid multihash e.g. "ed0120...""#),
                $private_key
                    .parse()
                    .expect(r#"private_key should be valid multihash e.g. "802620...""#),
            )
            .expect("public_key and private_key should be valid as a pair")
        });
    };
}
macro_rules! declare_account_with_keypair {
    ( $account_id:ident, $domain:literal, $key_pair:ident, $public_key:literal, $private_key:literal ) => {
        /// A standardized [`AccountId`].
        pub static $account_id: LazyLock<AccountId> = LazyLock::new(|| {
            let _: DomainId =
                DomainId::try_new($domain, "universal").expect("domain should be a valid Name");
            AccountId::new($key_pair.public_key().clone())
        });
        declare_keypair!($key_pair, $public_key, $private_key);
    };
}
declare_keypair!(
    PEER_KEYPAIR,
    "ed01207233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C0",
    "8026209AC47ABF59B356E0BD7DCBBBB4DEC080E302156A48CA907E47CB6AEA1D32719E"
);
declare_account_with_keypair!(
    ALICE_ID,
    "wonderland",
    ALICE_KEYPAIR,
    "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
    "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
);
declare_account_with_keypair!(
    BOB_ID,
    "wonderland",
    BOB_KEYPAIR,
    "ed012004FF5B81046DDCCF19E2E451C45DFB6F53759D4EB30FA2EFA807284D1CC33016",
    "802620AF3F96DEEF44348FEB516C057558972CEC4C75C4DB9C5B3AAC843668854BF828"
);
declare_account_with_keypair!(
    CARPENTER_ID,
    "garden_of_live_flowers",
    CARPENTER_KEYPAIR,
    "ed0120E9F632D3034BAB6BB26D92AC8FD93EF878D9C5E69E01B61B4C47101884EE2F99",
    "802620B5DD003D106B273F3628A29E6087C31CE12C9F32223BE26DD1ADB85CEBB48E1D"
);
declare_account_with_keypair!(
    SAMPLE_GENESIS_ACCOUNT_ID,
    "genesis",
    SAMPLE_GENESIS_ACCOUNT_KEYPAIR,
    "ed01204164BF554923ECE1FD412D241036D863A6AE430476C898248B8237D77534CFC4",
    "80262082B3BDE54AEBECA4146257DA0DE8D59D8E46D5FE34887DCD8072866792FCB3AD"
);
// Deterministic “real” genesis keys (seed: genesis-real). These match the localnet
// fixture keys used in /private/tmp/i2-localnet and are available for integration
// tests that want to mirror production-style key material.
declare_account_with_keypair!(
    REAL_GENESIS_ACCOUNT_ID,
    "genesis",
    REAL_GENESIS_ACCOUNT_KEYPAIR,
    "ed0120EEF765223920C4D7D7ED4E204DCBDF3DAFE37F53B11F155D78206F24BC232646",
    "802620AF458918974764C8ECB6AEB4F0AB18DC4EAD18DB597F22D5D2B31E68537817D7"
);
fn read_file(path: impl AsRef<Path>) -> std::io::Result<Vec<u8>> {
    let mut blob = vec![];
    std::fs::File::open(path.as_ref())?.read_to_end(&mut blob)?;
    Ok(blob)
}
/// Resolve a canonical IVM sample in this crate's Cargo-owned fixture output.
pub fn sample_ivm_path(name: impl AsRef<str>) -> PathBuf {
    PathBuf::from(env!("OUT_DIR"))
        .join("ivm/samples")
        .join(name.as_ref())
        .with_extension("to")
}
/// Resolve the build profile staged alongside this crate's IVM samples.
#[must_use]
pub fn ivm_build_profile_path() -> PathBuf {
    PathBuf::from(env!("OUT_DIR")).join("ivm/build_config.toml")
}
/// Load canonical IVM bytecode staged automatically by this crate's build script.
///
/// Sample names are listed in `crates/ivm/prebuilt_samples.txt`.
pub fn load_sample_ivm(name: impl AsRef<str>) -> IvmBytecode {
    let path = sample_ivm_path(name.as_ref());
    match read_file(&path) {
        Err(err) => {
            panic!(
                "could not load Cargo-staged IVM sample `{}` from `{}`: {err}; \
                 use a canonical sample name and preserve the build's Cargo output",
                name.as_ref(),
                path.display(),
            );
        }
        Ok(blob) => IvmBytecode::from_compiled(blob),
    }
}
/// Load IVM smart contract build profile.
///
/// Returns `None` if the build configuration cannot be found.
pub fn load_ivm_build_profile() -> Option<Profile> {
    load_ivm_build_profile_from(&ivm_build_profile_path())
}
fn load_ivm_build_profile_from(path: &Path) -> Option<Profile> {
    match fs::read_to_string(path) {
        Err(err) => {
            eprintln!(
                "WARN: Could not load build configuration file from `{}`: {err}\n\
                 Preserve the Cargo output containing this test build's staged IVM samples.",
                path.display(),
            );
            None
        }
        Ok(content) => {
            let value: toml::Value = toml::from_str(&content)
                .expect("a valid config must be written during the IVM build process");
            let profile_raw = value
                .get("profile")
                .and_then(toml::Value::as_str)
                .expect("`profile` key must be present in the build configuration");
            let profile = profile_raw
                .parse::<Profile>()
                .unwrap_or_else(|err| panic!("invalid profile `{profile_raw}`: {err}"));
            Some(profile)
        }
    }
}
/// Build profile used for pre-built IVM samples
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// Unoptimized build
    Debug,
    /// Optimized build
    Release,
}
impl Profile {
    /// Whether the profile is optimized
    #[must_use]
    pub const fn is_optimized(self) -> bool {
        matches!(self, Self::Release)
    }
}
impl FromStr for Profile {
    type Err = &'static str;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "debug" | "Debug" => Ok(Self::Debug),
            "release" | "Release" => Ok(Self::Release),
            _ => Err("expected `debug` or `release`"),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sample_ivm_path_has_to_extension() {
        let path = sample_ivm_path("dummy");
        assert_eq!(path.extension().and_then(|e| e.to_str()), Some("to"));
        assert_eq!(
            path.parent().unwrap(),
            Path::new(env!("OUT_DIR")).join("ivm/samples")
        );
    }
    #[test]
    fn staged_ivm_profile_and_samples_share_the_cargo_output() {
        let profile = ivm_build_profile_path();
        assert_eq!(
            profile,
            Path::new(env!("OUT_DIR")).join("ivm/build_config.toml")
        );
        assert!(load_ivm_build_profile().is_some());
        let sample = sample_ivm_path("mint_rose_trigger");
        assert!(sample.is_file());
        assert!(
            !read_file(sample)
                .expect("Cargo-staged canonical sample")
                .is_empty()
        );
    }
    #[test]
    fn load_ivm_build_profile_defaults_to_release_when_missing() {
        let path = std::env::temp_dir().join(format!(
            "missing_ivm_build_profile_{}.toml",
            std::process::id()
        ));
        assert_eq!(super::load_ivm_build_profile_from(&path), None);
    }
    #[test]
    fn load_ivm_build_profile_reads_existing_file() {
        let path =
            std::env::temp_dir().join(format!("ivm_build_profile_{}.toml", std::process::id()));
        std::fs::write(&path, "profile = \"Debug\"").unwrap();
        assert_eq!(
            super::load_ivm_build_profile_from(&path),
            Some(Profile::Debug)
        );
        std::fs::remove_file(&path).unwrap();
    }
}
