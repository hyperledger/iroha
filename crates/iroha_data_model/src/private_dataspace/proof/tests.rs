//! Parent receipt inclusion is authenticated by an independent native finality capability.

use super::*;
use crate::{
    account::AccountId,
    block::consensus::{ExecKv, ExecWitness},
    sumeragi_finality::{
        SUMERAGI_LANE_STATE_WITNESS_KEY, SumeragiLaneStateCommitment, authenticated_genesis,
        test_fixtures::NativeFinalityFixture,
    },
    sumeragi_lanes::SumeragiLaneState,
};
use iroha_crypto::{Algorithm, KeyPair};

#[test]
fn private_record_proof_binds_independent_parent_decision_and_exact_public_record() {
    let mut parent = NativeFinalityFixture::start("public-parent");
    let dataspace_id = DataSpaceId::new(u64::MAX);
    let scope = SumeragiRootScope::Dataspace {
        parent_network_id: parent.network_id(),
        dataspace_id,
    };
    let child = NativeFinalityFixture::start_with_scope("private-child", scope);
    let child_result = child
        .verifier()
        .verify_retained_decision(child.genesis_proof())
        .unwrap()
        .result()
        .0;
    let registration = PrivateDataspaceRegistration::new(
        scope,
        child.chain_id().parse().unwrap(),
        child.network_id(),
        child_result,
        authenticated_genesis(child.genesis())
            .map(|genesis| genesis.into_parts().0)
            .unwrap(),
    )
    .unwrap();
    let owner = AccountId::new(
        KeyPair::from_seed(vec![21; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let record = PrivateDataspaceRecord {
        dataspace_id,
        alias: "acme".into(),
        owner,
        ownership_generation: 1,
        anchor: PrivateDataspaceAnchorState::from_authorized_registration(registration).unwrap(),
    };
    let height = parent.next_header().height().get();
    let lanes = SumeragiLaneStateCommitment::from_state(
        parent.network_id(),
        height,
        &SumeragiLaneState::default(),
    )
    .unwrap();
    let writes = vec![
        ExecKv {
            key: SUMERAGI_LANE_STATE_WITNESS_KEY.to_vec(),
            value: norito::encode_canonical(&lanes).unwrap(),
        },
        ExecKv {
            key: record.witness_key(),
            value: norito::encode_canonical(&record).unwrap(),
        },
    ];
    let block = parent.block_with_submitted_work(parent.next_header());
    let finality = parent.certify_with_witness(
        block,
        &ExecWitness {
            writes: writes.clone(),
            ..ExecWitness::default()
        },
    );
    let verified = parent
        .verifier()
        .verify_retained_decision(&finality)
        .unwrap();
    let proof = PrivateDataspaceRecordProof::from_writes(
        parent.network_id(),
        height,
        verified.result().0,
        writes
            .iter()
            .map(|write| (write.key.as_slice(), write.value.as_slice())),
        record.clone(),
    )
    .unwrap();
    proof.verify(dataspace_id, &verified).unwrap();
    let wire = norito::encode_canonical(&proof).unwrap();
    assert!(wire.len() < MAX_PRIVATE_DATASPACE_RECORD_PROOF_BYTES);
    assert_eq!(PrivateDataspaceRecordProof::decode(&wire).unwrap(), proof);
    assert_eq!(
        norito::json::from_str::<PrivateDataspaceRecordProof>(
            &norito::json::to_json(&proof).unwrap()
        )
        .unwrap(),
        proof
    );
    assert!(
        PrivateDataspaceRecordProof::decode(&vec![0; MAX_PRIVATE_DATASPACE_RECORD_PROOF_BYTES + 1])
            .is_err()
    );
    assert!(proof.verify(DataSpaceId::new(1), &verified).is_err());
    let mut mutated = proof.clone();
    mutated.record.ownership_generation = 2;
    assert!(mutated.verify(dataspace_id, &verified).is_err());
    mutated = proof.clone();
    mutated.parent_height += 1;
    assert!(mutated.verify(dataspace_id, &verified).is_err());
    mutated = proof.clone();
    mutated.parent_result[0] ^= 1;
    assert!(mutated.verify(dataspace_id, &verified).is_err());
    mutated = proof.clone();
    mutated.inclusion.present[0] ^= 1;
    assert!(mutated.verify(dataspace_id, &verified).is_err());
    let stranger = NativeFinalityFixture::new();
    let stranger_verified = stranger
        .verifier()
        .verify_retained_decision(stranger.latest())
        .unwrap();
    assert!(proof.verify(dataspace_id, &stranger_verified).is_err());
    let mut wrong_record = record;
    wrong_record.ownership_generation += 1;
    assert!(
        PrivateDataspaceRecordProof::from_writes(
            parent.network_id(),
            height,
            verified.result().0,
            writes
                .iter()
                .map(|write| (write.key.as_slice(), write.value.as_slice())),
            wrong_record
        )
        .is_err()
    );
}
