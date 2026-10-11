//! Genuine native transfer proofs relabelled as explicitly unadmitted governance inputs.
//! No helper proves ballot authorization or election tally correctness.
#![cfg(feature = "zk-tests")]
#![allow(dead_code)]
use base64::Engine as _;
use iroha_core_zk as zk;
use iroha_data_model::{
    confidential::ConfidentialStatus,
    proof::{ProofBox, VerifyingKeyId, VerifyingKeyRecord},
    zk::{BackendTag, NativePipaRProofV1, OpenVerifyEnvelope},
};

/// An actual transfer transcript and a deliberately rejected ballot-labelled carrier.
pub struct UnqualifiedNativeBallotBundle {
    original: OpenVerifyEnvelope,
    transcript: Vec<u8>,
    /// Admitted native family; the ballot relation below is not admitted.
    pub backend: &'static str,
    /// Explicit unadmitted ballot identity used only for role rejection.
    pub circuit_id: &'static str,
    /// Registry identifier of the rejected test input.
    pub vk_id: VerifyingKeyId,
    /// Actual compiled key with deliberately substituted, unadmitted relation metadata.
    pub vk_record: VerifyingKeyRecord,
    /// Canonical envelope with the unadmitted relation label.
    pub proof_bytes: Vec<u8>,
    /// Actual first input commitment of the original transfer statement.
    pub commit: [u8; 32],
    /// Actual authenticated root of the original transfer statement.
    pub root: [u8; 32],
}
impl UnqualifiedNativeBallotBundle {
    /// Verify the original transfer relation against supplied transcript and public values.
    pub fn verify_native(&self, proof: &[u8], commit: [u8; 32], root: [u8; 32]) -> bool {
        let mut envelope = self.original.clone();
        let mut inner: NativePipaRProofV1 =
            norito::decode_canonical(&envelope.proof_bytes).expect("original native proof framing");
        inner.proof = proof.to_vec();
        inner.public_inputs[0] = commit;
        inner.public_inputs[6] = root;
        envelope.proof_bytes = norito::encode_canonical(&inner).expect("native proof framing");
        zk::verify_backend(
            self.backend,
            &ProofBox::new(
                self.backend.into(),
                norito::encode_canonical(&envelope).expect("native envelope"),
            ),
            self.vk_record.key.as_ref(),
        )
    }
    /// Actual native transcript, without the outer unadmitted relation label.
    pub fn native_transcript(&self) -> &[u8] {
        &self.transcript
    }
    /// Actual first input commitment, used as hostile ballot data by rejection tests.
    pub fn commit_bytes(&self) -> [u8; 32] {
        self.commit
    }
    /// Actual root, used as hostile election context by rejection tests.
    pub fn root_bytes(&self) -> [u8; 32] {
        self.root
    }
    /// Encode the rejected carrier for JSON-facing governance tests.
    pub fn proof_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(&self.proof_bytes)
    }
}
/// Retain a genuine compiled native proof while rejecting a substituted ballot relation.
pub fn unqualified_native_ballot_bundle() -> UnqualifiedNativeBallotBundle {
    let fixture = zk::test_utils::native_confidential_fixture_envelope();
    let backend = "pipa-r/pasta";
    let circuit_id = "pipa-r/pasta/vote-bool-commit-merkle8-v1";
    let key = fixture.vk_box(backend).expect("actual compiled native key");
    let original: OpenVerifyEnvelope =
        norito::decode_canonical(&fixture.proof_bytes).expect("actual native envelope");
    let inner: NativePipaRProofV1 =
        norito::decode_canonical(&original.proof_bytes).expect("actual single-column native proof");
    let mut record = VerifyingKeyRecord::new(
        1,
        circuit_id,
        BackendTag::NativePipaRPasta,
        "vesta",
        fixture.schema_hash,
        zk::hash_vk(&key),
    );
    record.vk_len = u32::try_from(key.bytes.len()).expect("bounded compiled key");
    record.status = ConfidentialStatus::Active;
    record.gas_schedule_id = Some("native_pipa_r_default".into());
    record.key = Some(key);
    let mut rejected = original.clone();
    rejected.circuit_id = circuit_id.into();
    let proof_bytes = norito::encode_canonical(&rejected).expect("relabelled native envelope");
    record.max_proof_bytes = u32::try_from(proof_bytes.len()).expect("bounded native envelope");
    assert!(!zk::verify_backend(
        backend,
        &ProofBox::new(backend.into(), proof_bytes.clone()),
        record.key.as_ref()
    ));
    UnqualifiedNativeBallotBundle {
        original,
        transcript: inner.proof,
        backend,
        circuit_id,
        vk_id: VerifyingKeyId::new(backend, "unqualified-native-ballot"),
        vk_record: record,
        proof_bytes,
        commit: inner.public_inputs[0],
        root: inner.public_inputs[6],
    }
}
#[test]
fn native_fixture_satisfies_only_its_compiled_transfer_relation() {
    let bundle = unqualified_native_ballot_bundle();
    assert!(bundle.verify_native(bundle.native_transcript(), bundle.commit, bundle.root));
    assert!(!zk::pipa_r_open_verify_circuit_id_matches_backend(
        bundle.backend,
        bundle.circuit_id
    ));
}
