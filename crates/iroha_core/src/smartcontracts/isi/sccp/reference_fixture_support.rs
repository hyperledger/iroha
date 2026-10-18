//! Test-only canonical JSON and public deterministic committee for the shared SCCP fixtures.
#![allow(
    dead_code,
    reason = "each independent fixture generator uses its own subset"
)]

use iroha_crypto::{Algorithm, KeyPair, PrivateKey};
use iroha_data_model::{
    account::AccountId,
    sccp::generation::{
        SccpCommitteeGenerationV1, SccpGenerationCauseV1, SccpGenerationEndV1,
        SccpGenerationMemberV1,
    },
};
use iroha_model_base::topology::LaneId;
use norito::json::Value;

#[path = "../../../../../iroha_sccp/tests/reference_support/python_json.rs"]
pub mod python_json;

/// Captured generation creation time and liability clock.
pub const START: u64 = 1_000;
/// Captured destination trust window.
pub const VALIDITY: u64 = 1_209_600_000;
/// Captured evidence grace period.
pub const GRACE: u64 = 604_800_000;
/// Captured maximum destination-progress extension.
pub const CAP: u64 = 2_592_000_000;
/// Inclusive time-leg liability boundary.
pub const UNTIL: u64 = START + VALIDITY + GRACE;
/// Generation heartbeat interval.
pub const HEARTBEAT: u64 = 86_400_000;

/// Lowercase prefixed hex for shared JSON byte strings.
pub fn hx(bytes: &[u8]) -> String {
    format!("0x{}", iroha_sccp::v1::hashes::to_hex(bytes))
}
/// Sorted BLS keys from public test scalars one through four.
pub fn keys() -> Vec<KeyPair> {
    let mut keys = (1..=4)
        .map(|scalar| {
            let mut bytes = [0; 32];
            bytes[0] = scalar;
            KeyPair::from_private_key(PrivateKey::from_bytes(Algorithm::BlsNormal, &bytes).unwrap())
                .unwrap()
        })
        .collect::<Vec<_>>();
    keys.sort_by_key(raw_key);
    keys
}
/// Canonical compressed G1 bytes of a fixture key.
pub fn raw_key(key: &KeyPair) -> [u8; 48] {
    key.public_key()
        .try_to_bytes()
        .unwrap()
        .1
        .try_into()
        .unwrap()
}
/// Fully bound structural generation DATA with deterministic original registrations.
pub fn generation(id: u64, start_height: u64) -> SccpCommitteeGenerationV1 {
    let keys = keys();
    let raw = keys.iter().map(raw_key).collect::<Vec<_>>();
    SccpCommitteeGenerationV1 {
        generation: id,
        committee_root: iroha_data_model::sumeragi_finality::certified_result::committee_root(&raw)
            .unwrap(),
        keys: raw,
        members: keys
            .iter()
            .map(|key| {
                Some(SccpGenerationMemberV1 {
                    lane_id: LaneId::SINGLE,
                    validator: AccountId::new(key.public_key().clone()),
                    activation_height: 1,
                })
            })
            .collect(),
        cause: if id == 1 {
            SccpGenerationCauseV1::Genesis
        } else {
            SccpGenerationCauseV1::Heartbeat
        },
        start_height,
        start_timestamp_ms: START,
        start_lc: START,
        validity_ms: VALIDITY,
        deadline_ms: START + VALIDITY,
        grace_ms: GRACE,
        progress_cap_ms: CAP,
        liable_until_lc: UNTIL,
        dest_cleared_lc: None,
        end: None,
    }
}
/// Structural generation DATA with a captured genuine-handoff-shaped end.
pub fn ended(id: u64, height: u64) -> SccpCommitteeGenerationV1 {
    let mut record = generation(id, height);
    record.end = Some(SccpGenerationEndV1 {
        end_height: height + 1,
        end_timestamp_ms: START,
        next_committee_root: record.committee_root,
        successor_validity_ms: record.validity_ms,
    });
    record
}
/// Repository fixture path, independent of the process working directory.
pub fn path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/sccp")
        .join(name)
}
/// Compare generated canonical JSON byte for byte with the committed fixture.
pub fn assert_fixture(name: &str, value: &Value) {
    let generated = python_json::render(value);
    let committed = std::fs::read_to_string(path(name)).unwrap();
    if generated != committed {
        let old: Value = norito::json::from_str(&committed).unwrap();
        panic!(
            "{name}: {}",
            python_json::first_difference(&old, value)
                .unwrap_or_else(|| "text formatting differs".into())
        );
    }
}
/// Rewrite one shared fixture only from an explicitly ignored regeneration test.
pub fn write_fixture(name: &str, value: &Value) {
    std::fs::write(path(name), python_json::render(value)).unwrap();
}
