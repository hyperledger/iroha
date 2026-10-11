//! Development-only fixed-witness IPA membership fixtures; never admitted ballot or tally proofs.
use blake2::{
    Blake2bVar,
    digest::{Update as _, VariableOutput as _},
};
use norito::json::{self, Value};
use std::{convert::TryInto, error::Error, fs, path::Path};
/// Canonical file names within the development membership bundle directory.
pub fn bundle_file_names() -> &'static [&'static str] {
    &[
        "dev_vote_membership_meta.json",
        "dev_vote_membership_proof.norito",
        "dev_vote_membership_vk.norito",
    ]
}
/// Human-readable summary derived from the development membership bundle artifacts.
#[derive(Debug)]
pub struct BundleSummary {
    pub backend: String,
    pub circuit_id: String,
    pub commit_hex: String,
    pub root_hex: String,
    pub public_inputs_hash_hex: String,
    pub vk_commit_hex: String,
    pub vk_len: usize,
    pub proof_len: usize,
}
impl std::fmt::Display for BundleSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "development membership summary:")?;
        writeln!(f, "  backend: {}", self.backend)?;
        writeln!(f, "  circuit_id: {}", self.circuit_id)?;
        writeln!(f, "  commit: {}", self.commit_hex)?;
        writeln!(f, "  root: {}", self.root_hex)?;
        writeln!(f, "  public_inputs_hash: {}", self.public_inputs_hash_hex)?;
        writeln!(f, "  production_admissible: false")?;
        writeln!(f, "  vk_commitment: {}", self.vk_commit_hex)?;
        writeln!(f, "  vk_len: {}", self.vk_len)?;
        writeln!(f, "  proof_len: {}", self.proof_len)
    }
}
/// Generate the native PIPA-R development membership bundle and write it to `out_dir`.
#[cfg(feature = "dev-vote-fixture")]
pub fn write_bundle(out_dir: &Path) -> Result<BundleSummary, Box<dyn Error>> {
    vote_tally_backend::write_bundle(out_dir)
}
#[cfg(not(feature = "dev-vote-fixture"))]
pub fn write_bundle(_out_dir: &Path) -> Result<BundleSummary, Box<dyn Error>> {
    Err("xtask compiled without the `dev-vote-fixture` feature; re-run with `--features dev-vote-fixture` to generate bundles".into())
}
/// Read an on-disk development membership bundle summary back from `dir`.
pub fn read_summary(dir: &Path) -> Result<BundleSummary, Box<dyn Error>> {
    let meta_path = dir.join("dev_vote_membership_meta.json");
    let meta_text = fs::read_to_string(&meta_path)?;
    let meta: Value = json::from_str(&meta_text)?;
    if meta["production_admissible"] != Value::from(false)
        || meta["purpose"] != Value::from("development-only fixed-witness membership")
    {
        return Err("bundle must explicitly identify an inadmissible development fixture".into());
    }
    let backend = meta["backend"].as_str().unwrap_or_default().to_string();
    let circuit_id = meta["circuit_id"].as_str().unwrap_or_default().to_string();
    let commit_hex = meta["commit_hex"].as_str().unwrap_or_default().to_string();
    let root_hex = meta["root_hex"].as_str().unwrap_or_default().to_string();
    let public_inputs_hash_hex = meta["public_inputs_hash_hex"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let vk_commit_hex = meta["vk_commitment_hex"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let vk_len = fs::metadata(dir.join("dev_vote_membership_vk.norito"))?.len() as usize;
    let proof_len = fs::metadata(dir.join("dev_vote_membership_proof.norito"))?.len() as usize;
    Ok(BundleSummary {
        backend,
        circuit_id,
        commit_hex,
        root_hex,
        public_inputs_hash_hex,
        vk_commit_hex,
        vk_len,
        proof_len,
    })
}
/// Convert a summary into a JSON representation used for the `--summary-json` flag.
pub fn summary_to_json(summary: &BundleSummary) -> Value {
    let mut map = norito::json::Map::new();
    map.insert(
        "purpose".into(),
        Value::from("development-only fixed-witness membership"),
    );
    map.insert("production_admissible".into(), Value::from(false));
    map.insert("backend".into(), Value::from(summary.backend.clone()));
    map.insert("circuit_id".into(), Value::from(summary.circuit_id.clone()));
    map.insert("commit_hex".into(), Value::from(summary.commit_hex.clone()));
    map.insert("root_hex".into(), Value::from(summary.root_hex.clone()));
    map.insert(
        "public_inputs_hash_hex".into(),
        Value::from(summary.public_inputs_hash_hex.clone()),
    );
    map.insert(
        "vk_commitment_hex".into(),
        Value::from(summary.vk_commit_hex.clone()),
    );
    map.insert("vk_len".into(), Value::from(summary.vk_len as u64));
    map.insert("proof_len".into(), Value::from(summary.proof_len as u64));
    Value::Object(map)
}
/// Build an attestation manifest describing the bundle summary and artifact hashes.
pub fn attestation_manifest(summary: &BundleSummary, dir: &Path) -> Result<Value, Box<dyn Error>> {
    let mut artifacts = Vec::new();
    for name in bundle_file_names() {
        let path = dir.join(name);
        let bytes = fs::read(&path)?;
        let digest = iroha_hash(&bytes);
        let mut entry = norito::json::Map::new();
        entry.insert("file".into(), Value::from(*name));
        entry.insert("len".into(), Value::from(bytes.len() as u64));
        entry.insert("blake2b_256".into(), Value::from(hex::encode(digest)));
        artifacts.push(Value::Object(entry));
    }
    let fixture_id = deterministic_fixture_id(summary);
    let mut manifest = norito::json::Map::new();
    manifest.insert("fixture_id".into(), Value::from(fixture_id));
    manifest.insert("hash_algorithm".into(), Value::from("blake2b-256"));
    manifest.insert("bundle".into(), summary_to_json(summary));
    manifest.insert("artifacts".into(), Value::Array(artifacts));
    Ok(Value::Object(manifest))
}
fn deterministic_fixture_id(summary: &BundleSummary) -> u64 {
    let mut combined = summary.commit_hex.clone();
    combined.push('@');
    combined.push_str(&summary.vk_commit_hex);
    let hash = iroha_hash(combined.as_bytes());
    u64::from_be_bytes(hash[..8].try_into().expect("slice length"))
}
#[cfg(feature = "dev-vote-fixture")]
#[path = "vote_tally/native.rs"]
mod vote_tally_backend;

pub fn iroha_hash(bytes: &[u8]) -> [u8; 32] {
    let vec_hash = Blake2bVar::new(32)
        .expect("failed to construct blake2b-256 hasher")
        .chain(bytes)
        .finalize_boxed();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&vec_hash);
    hash[31] |= 1;
    hash
}
