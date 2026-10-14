//! Verify that `ProofEvent::{Verified,Rejected}` carry the transaction `call_hash`.

#![cfg(feature = "zk-tests")]
use iroha_core::{
    block::{BlockBuilder, ValidBlock},
    governance::manifest::LaneManifestRegistry,
};
use iroha_data_model::{
    events::{
        EventBox,
        data::{prelude::*, proof::ProofEvent},
    },
    prelude::*,
};
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use std::{borrow::Cow, sync::Arc};
#[test]
fn proof_event_includes_call_hash() {
    // Minimal world
    let (authority_id, kp) = iroha_test_samples::gen_account_in("zkd");
    let domain_id: DomainId = DomainId::try_new("zkd", "universal").unwrap();
    let domain: Domain = Domain::new(domain_id.clone()).build(&authority_id);
    let acc = Account::new(authority_id.clone()).build(&authority_id);
    let world = iroha_core::state::World::with([domain], [acc], []);
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let query = iroha_core::query::store::LiveQueryStore::start_test();
    let chain_id = ChainId::from("chain");
    let state =
        iroha_core::state::State::new_with_chain_for_testing(world, kura, query, chain_id.clone());
    let network_id = *state.network_id_ref();
    let nexus = state.nexus_snapshot();
    state.install_lane_manifests_for_testing(&Arc::new(
        LaneManifestRegistry::empty().rebind(&nexus.lane_catalog, &nexus.governance),
    ));
    // Build a tx with a VerifyProof instruction for an unsupported real backend.
    let pr = iroha_data_model::proof::ProofBox::new("groth16/bn254".into(), vec![1, 2, 3]);
    let attach = iroha_data_model::proof::ProofAttachment::new_ref(
        "groth16/bn254".into(),
        pr.clone(),
        iroha_data_model::proof::VerifyingKeyId::new("groth16/bn254", "proof_event_vk"),
    );
    let verify = iroha_data_model::isi::zk::VerifyProof::new(attach);
    let tx = TransactionBuilder::new(
        network_id,
        authority_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([InstructionBox::from(verify)])
    .sign(kp.private_key());
    let tx_call_hash = tx.hash_as_entrypoint();
    // Build/commit block and collect events
    let acc_tx = iroha_core::tx::AcceptedTransaction::new_unchecked(Cow::Owned(tx));
    let new_block = BlockBuilder::new(vec![acc_tx])
        .chain(0, None)
        .sign(kp.private_key())
        .unpack(|_| {});
    let (mut sb, sb_recorder) =
        iroha_core::block::ValidBlock::start_component_execution(&new_block.clone().into(), &state)
            .expect("original writer-first component execution");
    let vb = ValidBlock::validate_unchecked(new_block.into(), &mut sb, sb_recorder).unpack(|_| {});
    let cb = vb
        .commit_unchecked(iroha_core::block::reserve_block_for_tests())
        .unpack(|_| {});
    let events = sb.apply_without_execution(&cb, Vec::new());
    // Find a Proof::Rejected event and assert call_hash was set
    let mut found = None;
    for ev in events {
        if let EventBox::Data(data) = ev
            && let DataEvent::Proof(ProofEvent::Rejected(r)) = data.as_ref()
        {
            found = Some(r.clone());
            break;
        }
    }
    let r = found.expect("proof rejected event present");
    let ch = r.call_hash.expect("call_hash present in proof event");
    assert_eq!(
        hex::encode(ch),
        hex::encode(iroha_crypto::Hash::from(tx_call_hash).as_ref())
    );
}
