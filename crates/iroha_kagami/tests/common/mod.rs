//! Shared fixtures for Kagami integration tests.
use color_eyre::eyre::{Result, WrapErr, ensure};
use iroha_model_base::peer::PeerId;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
/// Proof-of-possession fields from an owner-only `kagami keys --pop` bundle.
#[derive(Clone, Debug)]
pub struct PopFixture {
    pub peer_id: PeerId,
    pub pop_hex: String,
}
/// Run `kagami keys --pop --out-dir` with the provided 32-byte hexadecimal seed.
pub fn generate_pop(seed: &str) -> Result<PopFixture> {
    let directory = tempfile::tempdir().wrap_err("create PoP custody parent")?;
    let custody = directory.path().join("custody");
    let output = Command::new(env!("CARGO_BIN_EXE_kagami"))
        .args([
            "keys",
            "--algorithm",
            "bls_normal",
            "--seed-hex",
            seed,
            "--pop",
            "--out-dir",
        ])
        .arg(&custody)
        .output()
        .wrap_err_with(|| format!("failed to run `kagami keys --pop` for seed `{seed}`"))?;
    ensure!(
        output.status.success(),
        "kagami keys --pop for seed `{seed}` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let public_key =
        fs::read_to_string(custody.join("public.key")).wrap_err("read generated public key")?;
    let pop_hex = fs::read_to_string(custody.join("pop.hex"))
        .wrap_err("read generated proof of possession")?;
    let peer_id: PeerId = public_key
        .trim_end()
        .parse()
        .wrap_err("failed to parse peer public key into PeerId")?;
    Ok(PopFixture {
        peer_id,
        pop_hex: pop_hex.trim_end().to_owned(),
    })
}
/// Build a minimal raw genesis manifest with the provided topology.
pub fn minimal_manifest_with_topology(
    chain: &str,
    ivm_dir: impl Into<PathBuf>,
    topology: &[PeerId],
) -> norito::json::Value {
    let mut tx_map = norito::json::Map::new();
    let topo_entries = topology
        .iter()
        .map(|peer| {
            let mut entry = norito::json::Map::new();
            entry.insert(
                "peer".to_string(),
                norito::json::value::to_value(peer).expect("serialize peer id"),
            );
            norito::json::Value::Object(entry)
        })
        .collect();
    tx_map.insert(
        "topology".to_string(),
        norito::json::Value::Array(topo_entries),
    );
    let mut root = norito::json::Map::new();
    root.insert(
        "crypto_admission_policy".to_string(),
        norito::json::value::to_value(
            &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
                iroha_crypto::Algorithm::Ed25519,
                iroha_crypto::Algorithm::Secp256k1,
                iroha_crypto::Algorithm::BlsNormal,
            ])
            .expect("explicit fixture policy"),
        )
        .expect("encode explicit fixture policy"),
    );
    root.insert(
        "chain".to_string(),
        norito::json::Value::String(chain.to_owned()),
    );
    root.insert("executor".to_string(), norito::json::Value::Null);
    root.insert(
        "ivm_dir".to_string(),
        norito::json::Value::String(ivm_dir.into().display().to_string()),
    );
    root.insert(
        "consensus_mode".to_string(),
        norito::json::Value::String("Permissioned".to_string()),
    );
    root.insert(
        "transactions".to_string(),
        norito::json::Value::Array(vec![norito::json::Value::Object(tx_map)]),
    );
    norito::json::Value::Object(root)
}
/// Serialize a raw genesis manifest to JSON and write it to `path`.
pub fn write_raw_genesis_to(path: &Path, manifest: &norito::json::Value) -> Result<()> {
    let bytes = norito::json::to_vec(manifest).wrap_err("serialize genesis manifest to JSON")?;
    fs::write(path, bytes)
        .wrap_err_with(|| format!("write genesis manifest to {}", path.display()))?;
    Ok(())
}
