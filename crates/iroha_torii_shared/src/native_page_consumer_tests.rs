//! Application consumers verify real native proof pages before promoting state or checking witnesses.
//! Fixture result values are synthetic; these controls do not execute World or qualify monetary policy.

use iroha_crypto::Hash;
use iroha_data_model::{
    sumeragi_finality::{
        SumeragiFinalityCheckpoint, SumeragiFinalityVerifier, VerifiedSumeragiBlock,
        test_fixtures::NativeFinalityFixture,
    },
    validation_fee::{
        VALIDATION_FEE_POLICY_WITNESS_KEY_V1, VALIDATION_FEE_POLICY_WITNESS_SIBLINGS_V1,
        ValidationFeePolicySnapshotCommitmentV1, ValidationFeePolicyWitnessProofV1,
    },
};

use crate::validation_fee_api::{
    VALIDATION_FEE_POLICY_PROOF_VERSION_V1, ValidationFeeCurrentPolicyProofV1,
};

fn native_page_inputs() -> (
    NativeFinalityFixture,
    SumeragiFinalityCheckpoint,
    VerifiedSumeragiBlock,
) {
    let fixture = NativeFinalityFixture::new();
    // Select genesis and committee independently, then authenticate the complete
    // prefix through the production verifier. No decoded object grants trust.
    let mut verifier = SumeragiFinalityVerifier::new(
        fixture.genesis(),
        fixture.chain_id(),
        fixture.genesis_proof().committee.clone(),
    )
    .unwrap();
    verifier.verify(fixture.genesis_proof()).unwrap();
    let checkpoint = verifier.export_checkpoint(fixture.genesis_proof()).unwrap();
    let evaluated = verifier.verify(fixture.latest()).unwrap();
    assert_eq!(checkpoint.height(), 1);
    assert_eq!(evaluated.height(), 2);
    (fixture, checkpoint, evaluated)
}

#[test]
fn validation_fee_native_page_rejects_unbound_witness_without_promotion() {
    let (fixture, checkpoint, evaluated) = native_page_inputs();
    let original_checkpoint = checkpoint.encode_canonical().unwrap();
    let evaluated_timestamp_ms = u64::try_from(evaluated.header().creation_time().as_millis())
        .expect("fixture timestamp fits u64");
    let commitment =
        ValidationFeePolicySnapshotCommitmentV1::from_registry(2, evaluated_timestamp_ms, None);
    let policy_witness = ValidationFeePolicyWitnessProofV1 {
        key: VALIDATION_FEE_POLICY_WITNESS_KEY_V1.to_vec(),
        value: norito::encode_canonical(&commitment).unwrap(),
        siblings: vec![Hash::new(b"unbound sibling"); VALIDATION_FEE_POLICY_WITNESS_SIBLINGS_V1],
    };
    assert_eq!(policy_witness.commitment().unwrap(), commitment);
    assert!(!policy_witness.verify(evaluated.execution().ordinary_writes_root));
    let response = ValidationFeeCurrentPolicyProofV1 {
        version: VALIDATION_FEE_POLICY_PROOF_VERSION_V1,
        registry: None,
        policy_witness,
        finality_chain: vec![fixture.genesis_proof().clone(), fixture.latest().clone()],
        evaluated_context_id: evaluated.context_id(),
        evaluated_block_height: evaluated.height(),
        evaluated_block_hash: hex::encode(evaluated.header().hash().as_ref()),
        observed_ledger_tip_height: 2,
        more_available: false,
    };
    // This exact error occurs only after the whole native page and tip binding
    // succeed. A canonical policy value alone cannot authorize state promotion.
    assert_eq!(
        response
            .verify_against(fixture.network_id(), &checkpoint)
            .unwrap_err(),
        "validation-fee synthetic write proof is invalid"
    );
    assert_eq!(checkpoint.encode_canonical().unwrap(), original_checkpoint);
    let mut wrong_context = response.clone();
    wrong_context.evaluated_context_id = Hash::new(b"wrong policy context");
    assert_eq!(
        wrong_context
            .verify_against(fixture.network_id(), &checkpoint)
            .unwrap_err(),
        "native finality page tip does not match the evaluated application block"
    );
    let mut bad_native = response;
    bad_native.finality_chain[1].committee[0].proof_of_possession[0] ^= 1;
    assert!(
        bad_native
            .verify_against(fixture.network_id(), &checkpoint)
            .unwrap_err()
            .starts_with("native finality page failed:")
    );
    assert_eq!(checkpoint.encode_canonical().unwrap(), original_checkpoint);
}
