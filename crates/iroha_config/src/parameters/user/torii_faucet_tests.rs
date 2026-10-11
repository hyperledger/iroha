//! Faucet configuration parsing tests.
use super::*;
use iroha_crypto::PublicKey;
use iroha_model_base::domain::DomainId;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT_KEY_FILE: AtomicU64 = AtomicU64::new(0);
struct TestKeyFile(PathBuf);
impl TestKeyFile {
    fn create(contents: &str) -> Self {
        let sequence = NEXT_KEY_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "iroha-config-faucet-{}-{sequence}.key",
            std::process::id()
        ));
        use std::io::Write as _;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        options
            .open(&path)
            .expect("create private faucet key file")
            .write_all(contents.as_bytes())
            .expect("write faucet key file");
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TestKeyFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn sample_faucet() -> (ToriiFaucet, TestKeyFile) {
    let public_key: PublicKey =
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .expect("public key");
    let key_file = TestKeyFile::create(
        "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53\n",
    );
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("sora", "universal").expect("domain"),
        "xor".parse().expect("name"),
    )
    .to_string();
    (
        ToriiFaucet {
            enabled: true,
            authority: AccountId::new(public_key).to_string(),
            private_key_file: key_file.path().to_path_buf(),
            asset_definition_id,
            amount: Quantity::from(25_000_u64),
            pow_difficulty_bits: 18,
            pow_scrypt_log_n: 13,
            pow_scrypt_r: 8,
            pow_scrypt_p: 1,
            pow_max_anchor_age_blocks: 4,
            pow_adaptive_lookback_blocks: 32,
            pow_adaptive_claims_per_extra_bit: 3,
            pow_adaptive_max_extra_bits: 5,
            pow_beacon_seed_enabled: true,
        },
        key_file,
    )
}
#[test]
fn torii_faucet_parse_maps_enabled_config() {
    let (faucet, _key_file) = sample_faucet();
    let expected_authority = faucet.authority.clone();
    let expected_asset = faucet.asset_definition_id.clone();
    let mut emitter = Emitter::new();
    let parsed = faucet.parse(&mut emitter).expect("enabled faucet");
    assert!(emitter.into_result().is_ok());
    assert_eq!(parsed.authority.to_string(), expected_authority);
    assert_eq!(parsed.asset_definition_id, expected_asset);
    assert_eq!(parsed.amount.to_string(), "25000");
    assert_eq!(parsed.pow_difficulty_bits.get(), 18);
    assert_eq!(parsed.pow_scrypt_log_n, 13);
    assert_eq!(parsed.pow_scrypt_r, 8);
    assert_eq!(parsed.pow_scrypt_p, 1);
    assert_eq!(parsed.pow_max_anchor_age_blocks.get(), 4);
    assert_eq!(parsed.pow_adaptive_lookback_blocks, 32);
    assert_eq!(parsed.pow_adaptive_claims_per_extra_bit, 3);
    assert_eq!(parsed.pow_adaptive_max_extra_bits, 5);
    assert!(parsed.pow_beacon_seed_enabled);
}
#[test]
fn torii_faucet_parse_returns_none_when_disabled() {
    let (mut faucet, _key_file) = sample_faucet();
    faucet.enabled = false;
    let mut emitter = Emitter::new();
    assert!(faucet.parse(&mut emitter).is_none());
    assert!(emitter.into_result().is_ok());
}
#[test]
fn torii_faucet_parse_rejects_zero_amount() {
    let (mut faucet, _key_file) = sample_faucet();
    faucet.amount = Quantity::zero();
    let mut emitter = Emitter::new();
    assert!(faucet.parse(&mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn torii_faucet_parse_rejects_zero_pow_difficulty_when_enabled() {
    let (mut faucet, _key_file) = sample_faucet();
    faucet.pow_difficulty_bits = 0;
    let mut emitter = Emitter::new();
    assert!(faucet.parse(&mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn torii_faucet_parse_accepts_asset_alias_selector() {
    let (mut faucet, _key_file) = sample_faucet();
    faucet.asset_definition_id = "xor#universal".to_owned();
    let mut emitter = Emitter::new();
    let parsed = faucet
        .parse(&mut emitter)
        .expect("alias selector should parse");
    assert!(emitter.into_result().is_ok());
    assert_eq!(parsed.asset_definition_id, "xor#universal");
}
#[test]
fn torii_faucet_parse_rejects_invalid_asset_selector() {
    let (mut faucet, _key_file) = sample_faucet();
    faucet.asset_definition_id = "not a selector".to_owned();
    let mut emitter = Emitter::new();
    assert!(faucet.parse(&mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn torii_faucet_parse_rejects_non_positive_pow_anchor_age() {
    let (mut faucet, _key_file) = sample_faucet();
    faucet.pow_max_anchor_age_blocks = 0;
    let mut emitter = Emitter::new();
    assert!(faucet.parse(&mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn torii_faucet_parse_rejects_non_positive_scrypt_log_n() {
    let (mut faucet, _key_file) = sample_faucet();
    faucet.pow_scrypt_log_n = 0;
    let mut emitter = Emitter::new();
    assert!(faucet.parse(&mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn torii_faucet_parse_rejects_signer_authority_mismatch_without_panicking() {
    let (mut faucet, _key_file) = sample_faucet();
    faucet.authority = AccountId::new(
        KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .expect("different authority")
            .public_key()
            .clone(),
    )
    .to_string();
    let mut emitter = Emitter::new();
    assert!(faucet.parse(&mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
