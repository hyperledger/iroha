//! Unqualified key and retained-election adversaries for the closed registry.
//! No fixture represents an admitted election or a valid proof.
use iroha_core::state::ElectionState;
use iroha_core_zk::{hash_vk, native_pipa_r::BACKEND as NATIVE_BACKEND};
use iroha_data_model::{
    confidential::ConfidentialStatus,
    proof::{VerifyingKeyBox, VerifyingKeyId, VerifyingKeyRecord},
    zk::BackendTag,
};

pub(super) fn unqualified_key(circuit_id: &str) -> (VerifyingKeyId, VerifyingKeyRecord) {
    let id = VerifyingKeyId::new(NATIVE_BACKEND, "unqualified");
    // Deliberately opaque rejected input. The role gate must reject before key decode.
    let key = VerifyingKeyBox::new(NATIVE_BACKEND.to_owned(), vec![1, 2, 3, 4]);
    let mut record = VerifyingKeyRecord::new(
        1,
        circuit_id,
        BackendTag::NativePipaRPasta,
        "vesta",
        [0x11; 32],
        hash_vk(&key),
    );
    record.status = ConfidentialStatus::Active;
    record.vk_len = u32::try_from(key.bytes.len()).expect("key extent");
    record.key = Some(key);
    record.max_proof_bytes = 1024;
    record.gas_schedule_id = Some("native_pipa_r_default".to_owned());
    (id, record)
}

pub(super) fn retained_election(id: &VerifyingKeyId, record: &VerifyingKeyRecord) -> ElectionState {
    // Test-only retained-state adversary: this record was NOT created by a valid proof.
    ElectionState {
        options: 2,
        tally: vec![0, 0],
        eligible_root: [0x22; 32],
        vk_ballot: Some(id.clone()),
        vk_ballot_commitment: Some(record.commitment),
        vk_tally: Some(id.clone()),
        vk_tally_commitment: Some(record.commitment),
        domain_tag: "gov:ballot:v1".to_owned(),
        ..ElectionState::default()
    }
}
