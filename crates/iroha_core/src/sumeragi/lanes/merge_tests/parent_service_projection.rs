//! Original parent-service identity across genuine certified lane execution expansion.

use super::*;
use crate::sumeragi::certified_chain::{
    ParentServiceError, ParentServicePreparation, admit_parent_service_fixture,
};
use iroha_allocation::ChargedShared;

#[test]
fn parent_service_original_proposal_survives_actual_nonempty_lane_expansion() {
    let _epoch = crossbeam_epoch::pin();
    let mut fixture = Fixture::start();
    fixture.chain.commit(Vec::new());
    fixture.chain.commit(Vec::new());
    let routed = fixture.log(&lane_user(), "original lane work", GENESIS_MS - 10);
    let lane_tip = fixture.certify(1, 3, vec![routed.clone()]);
    let mut proposal = fixture.chain.proposal(
        None,
        vec![fixture.log(&other_user(), "original global work", GENESIS_MS - 9)],
    );
    assert_eq!(proposal.lane_merge().unwrap().merges.len(), 1);
    assert_eq!(proposal.merged_entrypoint_count(), 0);
    let state = Arc::clone(fixture.chain.state());
    let pool = state.ivm_execution_budget();
    admit_parent_service_fixture(&mut proposal, &pool).unwrap();
    let original_hash = proposal.hash();
    let original = proposal.clone();
    let source = proposal
        .npos_consensus_effects()
        .unwrap()
        .parent_service_commit_qc
        .as_ref()
        .unwrap()
        .admitted_source()
        .unwrap()
        .clone();
    {
        let view = state.view();
        let mut prepared = ParentServicePreparation::default();
        prepared.prepare(&view, 3).unwrap();
        prepared.prepare_proposal_qc(&view, &proposal).unwrap();
        let before = prepared.authenticate(&view, &proposal).unwrap().unwrap();
        let expected_signers = before.signer_keys().cloned().collect::<Vec<_>>();
        let qc_pointers = prepared.qc_pointers();
        let signer_pointers = prepared.signer_pointers();
        let original_pointers = prepared.original_pointers();
        let expansion = expand(
            &state,
            &proposal,
            &*fixture.stores,
            Duration::ZERO,
            &mut crate::sumeragi::lanes::ProposalReadScope::new(),
        )
        .unwrap();
        let (expanded, step) = expansion
            .apply(proposal, &state, state.state_view_generation())
            .unwrap();
        assert_eq!(expanded.merged_entrypoint_count(), 1);
        assert_eq!(step.merges.len(), 1);
        assert_ne!(expanded.hash(), original_hash);
        assert_eq!(
            expanded.canonical_resultless_header().unwrap().hash(),
            original_hash
        );
        assert!(ChargedShared::ptr_eq(
            &source,
            expanded
                .npos_consensus_effects()
                .unwrap()
                .parent_service_commit_qc
                .as_ref()
                .unwrap()
                .admitted_source()
                .unwrap()
        ));
        let authenticated = prepared.authenticate(&view, &expanded);
        assert!(
            authenticated.is_ok(),
            "parent service must retain the original signed proposal through nonempty lane expansion"
        );
        let after = authenticated.unwrap().unwrap();
        before.require_proposal(&expanded).unwrap();
        after.require_proposal(&original).unwrap();
        after.require_proposal(&expanded).unwrap();
        assert_eq!(
            after.signer_keys().cloned().collect::<Vec<_>>(),
            expected_signers
        );
        prepared.prepare_proposal_qc(&view, &expanded).unwrap();
        assert_eq!(prepared.qc_pointers(), qc_pointers);
        assert_eq!(prepared.signer_pointers(), signer_pointers);
        assert_eq!(prepared.original_pointers(), original_pointers);

        // The same QC source cannot authorize a changed original merge declaration.
        let mut changed = expanded.clone();
        let mut context = changed.execution_context().unwrap().clone();
        context.lane_merge.as_mut().unwrap().time_floor_ms += 1;
        changed.set_execution_context(Some(context));
        assert_ne!(
            changed.canonical_resultless_header().unwrap().hash(),
            original_hash
        );
        assert!(matches!(
            prepared.authenticate(&view, &changed),
            Err(ParentServiceError::Source(_))
        ));
        assert!(matches!(
            after.require_proposal(&changed),
            Err(ParentServiceError::Invalid(_))
        ));

        // Equal canonical bytes in another admitted QC allocation are not this source.
        let mut replacement = expanded.clone();
        let mut effects = replacement.npos_consensus_effects().unwrap().clone();
        effects.parent_service_commit_qc = Some(
            iroha_data_model::consensus::NposParentServiceCommitQc::from_untrusted(
                source.as_slice().to_vec(),
            ),
        );
        replacement.set_npos_consensus_effects(Some(effects));
        admit_parent_service_fixture(&mut replacement, &pool).unwrap();
        assert_eq!(
            replacement.encode_wire().unwrap(),
            expanded.encode_wire().unwrap()
        );
        assert!(!ChargedShared::ptr_eq(
            &source,
            replacement
                .npos_consensus_effects()
                .unwrap()
                .parent_service_commit_qc
                .as_ref()
                .unwrap()
                .admitted_source()
                .unwrap()
        ));
        let reserved = pool.reserved_bytes();
        assert!(matches!(
            prepared.authenticate(&view, &replacement),
            Err(ParentServiceError::Source(_))
        ));
        assert_eq!(pool.reserved_bytes(), reserved);
        assert_eq!(prepared.qc_pointers(), qc_pointers);
        assert_eq!(prepared.signer_pointers(), signer_pointers);
        prepared.authenticate(&view, &expanded).unwrap().unwrap();
    }

    // Exercise the actual worker, rewards participation consumer and native publication too.
    let executed = fixture
        .chain
        .begin_proposal(original, iroha_sumeragi::types::ControlWitness::default());
    assert!(
        executed.is_ok(),
        "original expanded lane work must execute: {:?}",
        executed.as_ref().err()
    );
    let committed = executed
        .unwrap()
        .publish(crate::sumeragi::test_chain::Signers::Quorum)
        .unwrap();
    assert_eq!(committed.height(), 4);
    assert_eq!(committed.block().merged_entrypoint_count(), 1);
    assert_eq!(
        committed
            .block()
            .canonical_resultless_header()
            .unwrap()
            .hash(),
        original_hash
    );
    assert!(fixture.committed(&routed));
    assert_eq!(fixture.record().merged.block_hash, lane_tip.0);
    let index = committed
        .block()
        .external_entrypoints_slice()
        .iter()
        .position(|input| input.hash() == routed.hash_as_entrypoint())
        .unwrap();
    assert!(
        committed
            .block()
            .network_output_at(u32::try_from(index).unwrap())
            .unwrap()
            .1
            .result
            .is_ok()
    );
}
