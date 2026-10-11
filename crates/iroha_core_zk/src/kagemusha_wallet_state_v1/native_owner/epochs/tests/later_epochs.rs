//! Delayed non-genesis authority after a later durable selection and restart.
//! The added boundary has real fixture BLS signatures over synthetic execution data.

use super::*;
use iroha_data_model::sumeragi_finality::{
    ExecutionResultCommitment, NativeLaneStateProof, ScheduledConfig, ScheduledSlot, core_epoch,
    result_of_preimage,
};
use iroha_sumeragi::{
    message::{BlockHeader, Qc},
    types::{AggregateSignature, Bitmap, Hash32},
};

fn second_boundary(
    native: &NativeFinalityFixture,
    first: &SumeragiCommitCertificateV1,
    checkpoint: &SumeragiCommitCheckpointV1,
) -> SumeragiCommitCertificateV1 {
    let current = checkpoint.selected_epoch();
    assert_eq!(current.authorization.epoch, 1);
    let height = current.authorization.last_height;
    let mut next = current.clone();
    next.authorization.epoch += 1;
    next.authorization.first_height = height + 1;
    next.authorization.last_height = height + 3;
    next.authorization.previous_authorization_id =
        current.authorization.authorization_id().unwrap();
    next.leader_seed = [2; 32];
    next.validate_successor(current).unwrap();
    let mut result = ExecutionResultCommitment::decode(&first.result_preimage).unwrap();
    result.height = height;
    result.schedule.height = height;
    result.schedule.current = current.clone();
    let boundary = result.schedule.boundary.as_mut().unwrap();
    boundary.height = height;
    boundary.predecessor_context_id = current.context_id().unwrap();
    boundary.next = next.clone();
    let params = *result.schedule.next.params();
    result.schedule.next = ScheduledSlot::Ready(ScheduledConfig {
        height: height + 1,
        epoch: next.clone(),
        params,
    });
    result.schedule.after_next = ScheduledSlot::Ready(ScheduledConfig {
        height: height + 2,
        epoch: next,
        params,
    });
    let (lanes, writes_root) = NativeLaneStateProof::empty_for_testing(native.network_id(), height);
    result.native_lanes = lanes;
    result.execution.ordinary_writes_root = writes_root;
    result.validate().unwrap();

    let mut header: BlockHeader = norito::decode_canonical(&first.consensus_header).unwrap();
    header.height = height;
    header.epoch = core_epoch(current).unwrap().id;
    let result_preimage = result.preimage().unwrap();
    let mut qc: Qc = norito::decode_canonical(&first.commit_qc).unwrap();
    qc.height = height;
    qc.epoch = header.epoch;
    qc.block_hash = Hash32(
        iroha_crypto::Hash::new(iroha_sumeragi::preimage::block_hash_preimage(&header)).into(),
    );
    qc.result = result_of_preimage(&result_preimage);
    let mut keys: Vec<_> = (1..=4)
        .map(|seed| {
            iroha_crypto::KeyPair::from_seed(vec![seed; 32], iroha_crypto::Algorithm::BlsNormal)
        })
        .collect();
    keys.sort_by_key(|key| key.public_key().try_to_bytes().unwrap().1.to_vec());
    qc.signers = Bitmap::from_indices(4, [0, 1, 2]).unwrap();
    let shares: Vec<_> = keys[..3]
        .iter()
        .map(|key| iroha_crypto::Signature::try_new(key.private_key(), &qc.preimage()).unwrap())
        .collect();
    let references: Vec<_> = shares
        .iter()
        .map(iroha_crypto::Signature::payload)
        .collect();
    qc.agg_sig = AggregateSignature(
        iroha_crypto::bls_normal_aggregate_signatures(&references)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    SumeragiCommitCertificateV1 {
        consensus_header: norito::encode_canonical(&header).unwrap(),
        commit_qc: norito::encode_canonical(&qc).unwrap(),
        result_preimage,
    }
}

#[test]
fn later_epoch_publication_retains_prior_nonzero_authority_across_restart() {
    let (native, chain, genesis) = chain();
    let first_bytes = certificate(&native, &chain[2]);
    let first = SumeragiCommitCertificateV1::decode_canonical(&first_bytes).unwrap();
    let mut w = wallet(&native);
    w.ingest_epoch_original(&genesis, 0, &first_bytes).unwrap();
    let (_, before) = w.manifest().unwrap();
    let (_, checkpoint) = w.selected_commit_epoch(&before, &genesis, 1).unwrap();
    let original_address = w.epoch_entry(&before, 1).unwrap().checkpoint;
    let second = second_boundary(&native, &first, &checkpoint)
        .to_canonical_bytes()
        .unwrap();
    assert_eq!(
        w.ingest_epoch_original(&genesis, 1, &second).unwrap().epoch,
        2
    );

    let mut w = restart(w);
    assert_eq!(w.epoch_progress_selected(&genesis).unwrap().epoch, 2);
    let (_, selected) = w.manifest().unwrap();
    assert_eq!(
        w.epoch_entry(&selected, 1).unwrap().checkpoint,
        original_address
    );
    let delayed =
        SumeragiCommitCertificateV1::decode_canonical(&certificate(&native, &chain[3])).unwrap();
    let (mut current, _) = w.selected_commit_epoch(&selected, &genesis, 2).unwrap();
    assert!(current.verify(&delayed).is_err());
    let (mut old, retained) = w.selected_commit_epoch(&selected, &genesis, 1).unwrap();
    assert_eq!(retained, checkpoint);
    assert_eq!(old.verify(&delayed).unwrap().height(), 4);
    let root = w.manifest().unwrap().0;
    // An older exact boundary retry neither regresses the tip nor rewrites history.
    assert_eq!(
        w.ingest_epoch_original(&genesis, 0, &first_bytes)
            .unwrap()
            .epoch,
        2
    );
    assert_eq!(
        w.ingest_epoch_original(&genesis, 1, &second).unwrap().epoch,
        2
    );
    assert_eq!(w.manifest().unwrap().0, root);
}
