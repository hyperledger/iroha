//! Ensures the published curve registry matches the runtime identifiers.
use iroha_crypto::Algorithm;
use iroha_data_model::account::curve::CurveId;
use norito::json::{self, JsonDeserialize};
use std::{collections::BTreeSet, path::Path};
#[derive(Debug, JsonDeserialize)]
struct Registry {
    version: u32,
    entries: Vec<Entry>,
}
#[derive(Debug, JsonDeserialize)]
struct Entry {
    id: u8,
    hex: String,
    algorithm: String,
    feature: Option<String>,
    validation: Option<EntryValidation>,
}
#[derive(Debug, JsonDeserialize)]
struct EntryValidation {
    public_key_bytes: Option<u16>,
    signature_bytes: Option<u16>,
    checks: Vec<String>,
}
#[test]
fn curve_registry_aligns_with_runtime() {
    let registry_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("specs/references/address_curve_registry.json");
    let payload = std::fs::read_to_string(&registry_path)
        .unwrap_or_else(|err| panic!("failed to read {registry_path:?}: {err}"));
    let registry: Registry =
        json::from_str(&payload).expect("curve registry JSON must be well-formed");
    assert!(registry.version >= 1, "unexpected registry version");
    assert_eq!(registry.entries.len(), Algorithm::ALL.len());
    let mut seen_ids = BTreeSet::new();
    for entry in registry.entries {
        assert!(
            seen_ids.insert(entry.id),
            "duplicate curve identifier {}",
            entry.id
        );
        let expected_hex = format!("0x{:02X}", entry.id);
        assert_eq!(
            expected_hex.to_lowercase(),
            entry.hex.to_lowercase(),
            "hex rendering mismatch for curve id {}",
            entry.id
        );
        if let Some(feature) = entry.feature.as_deref() {
            match feature {
                "pqc" | "gost" | "sm" | "bls" => {}
                other => panic!("unknown feature gate '{other}' in curve registry"),
            }
        }
        let curve_id =
            CurveId::try_from(entry.id).expect("every registered identity is unconditional");
        let algorithm = curve_id.algorithm();
        assert_eq!(
            algorithm_name(algorithm),
            entry.algorithm,
            "algorithm label mismatch for curve id {}",
            entry.id
        );
        assert_eq!(CurveId::from_algorithm(algorithm), curve_id);
        if let Some(validation) = entry.validation.as_ref() {
            if let Some(bytes) = validation.public_key_bytes {
                assert!(
                    bytes > 0,
                    "validation entry for {} must set public_key_bytes > 0",
                    entry.algorithm
                );
            }
            if let Some(bytes) = validation.signature_bytes {
                assert!(
                    bytes > 0,
                    "validation entry for {} must set signature_bytes > 0 when present",
                    entry.algorithm
                );
            }
            assert!(
                !validation.checks.is_empty(),
                "validation entry for {} must describe at least one check",
                entry.algorithm
            );
        }
    }
}
fn algorithm_name(algorithm: Algorithm) -> &'static str {
    algorithm.as_static_str()
}
