//! Genuine owner grants, borrowed certified World publication and independent private verification.

use super::*;
use iroha_allocation::AllocationBudget;
use iroha_data_model::{
    isi::Revoke,
    sumeragi_amx::{AmxDebitApprovalProofRefV1, AmxDebitApprovalProofV1, AmxDebitApprovalV1},
    sumeragi_finality::{FinalityValidator, SumeragiFinalityVerifier, VerifiedSumeragiBlock},
};

fn verified_tip(chain: &CertifiedTestChain) -> VerifiedSumeragiBlock {
    let validators = chain
        .validators()
        .iter()
        .map(|(peer, pop)| FinalityValidator {
            public_key: peer.public_key().clone(),
            proof_of_possession: pop.clone(),
        })
        .collect();
    let mut verifier = SumeragiFinalityVerifier::new(
        chain.genesis(),
        chain.state().chain_id_ref().as_str(),
        validators,
    )
    .unwrap();
    let view = chain.state().view();
    let mut last = None;
    for height in 1..=chain.height() {
        last = Some(
            verifier
                .verify(&crate::sumeragi::finality::build_proof(&view, height).unwrap())
                .unwrap(),
        );
    }
    last.unwrap()
}

fn publish(
    chain: &CertifiedTestChain,
    approval: &AmxDebitApprovalV1,
    relay: &AccountId,
    bytes: usize,
) -> Result<AmxDebitApprovalProofV1, crate::state::WorldStateSnapshotError> {
    let budget = AllocationBudget::new(bytes);
    let tip = chain.committed(chain.height());
    let encoded = chain.state().with_native_amx_debit_approval_snapshot_v1(
        &tip,
        approval,
        relay,
        &budget,
        |world, permissions| {
            assert!(permissions.contains(&approval.permission().unwrap()));
            assert_eq!(
                world.root().unwrap(),
                tip.commitment().execution.world_state_root
            );
            let borrowed = AmxDebitApprovalProofRefV1::new(world, permissions);
            let size = norito::canonical_frame_len(&borrowed).map_err(|error| error.to_string())?;
            let charge = budget
                .try_reserve_bytes(size)
                .map_err(|error| error.to_string())?;
            Ok((
                norito::encode_canonical(&borrowed).map_err(|error| error.to_string())?,
                charge,
            ))
        },
    );
    let result = encoded.map(|(frame, charge)| {
        let proof = AmxDebitApprovalProofV1::decode_frame(&frame).unwrap();
        drop(frame);
        drop(charge);
        proof
    });
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "original publisher pool is completely refunded"
    );
    result
}

#[test]
fn native_amx_approval_proof_requires_owner_grant_and_rechecks_exact_private_cut() {
    const BUDGET: usize = 32 * 1024 * 1024;
    let mut roots = paid_roots();
    let transaction = roots.transaction(100, 0xA7);
    let approval = roots.approval(0, &transaction);
    let relay = account(&receiver());
    assert_ne!(relay, *approval.debited_asset.account());
    assert!(publish(&roots.participants[0], &approval, &relay, BUDGET).is_err());
    roots.approve(0, &transaction, relay.clone(), 2_500);
    let chain = &roots.participants[0];
    let proof = publish(chain, &approval, &relay, BUDGET).unwrap();
    let block = verified_tip(chain);
    let schema = crate::state::State::native_world_schema_hash_v1().unwrap();
    let verified = proof.verify(&approval, &relay, schema, &block).unwrap();
    assert_eq!(verified.approval(), &approval);
    assert_eq!(verified.relay(), &relay);
    assert_eq!(verified.height(), chain.height());
    assert_eq!(verified.context_id(), block.context_id());
    assert!(publish(chain, &approval, &relay, 0).is_err());
    let mut changed = approval.clone();
    changed.transaction_id[0] ^= 1;
    assert!(publish(chain, &changed, &relay, BUDGET).is_err());
    assert!(proof.verify(&changed, &relay, schema, &block).is_err());
    assert!(publish(&roots.participants[1], &approval, &relay, BUDGET).is_err());
    assert!(publish(&roots.global, &approval, &relay, BUDGET).is_err());
    assert!(publish(chain, &approval, &account(&payer()), BUDGET).is_err());
    assert!(native(chain).escrows.is_empty());
    assert_eq!(
        balance(chain, FIRST, principal(), account(&payer())),
        Quantity::from(1_000_u32)
    );
}

#[test]
fn native_amx_approval_proof_is_historical_and_cannot_replace_revoked_current_consent() {
    const BUDGET: usize = 32 * 1024 * 1024;
    let mut roots = paid_roots();
    let transaction = roots.transaction(100, 0xA8);
    let approval = roots.approval(0, &transaction);
    let relay = account(&receiver());
    roots.approve(0, &transaction, relay.clone(), 2_500);
    let chain = &mut roots.participants[0];
    let old = publish(chain, &approval, &relay, BUDGET).unwrap();
    let old_tip = chain.committed(chain.height());
    let old_block = verified_tip(chain);
    let revoke = chain.sign(
        &payer(),
        [Revoke::account_permission(approval.permission().unwrap(), relay.clone()).into()],
        2_999,
    );
    assert_eq!(chain.commit_at(3_000, vec![revoke]), vec![true]);
    let current_block = verified_tip(chain);
    let schema = crate::state::State::native_world_schema_hash_v1().unwrap();
    assert!(old.verify(&approval, &relay, schema, &old_block).is_ok());
    assert!(
        old.verify(&approval, &relay, schema, &current_block)
            .is_err()
    );
    assert!(publish(chain, &approval, &relay, BUDGET).is_err());
    let budget = AllocationBudget::new(BUDGET);
    let mut called = false;
    assert!(
        chain
            .state()
            .with_native_amx_debit_approval_snapshot_v1(
                &old_tip,
                &approval,
                &relay,
                &budget,
                |_, _| {
                    called = true;
                    Ok(())
                }
            )
            .is_err()
    );
    assert!(
        !called,
        "old cut cannot expose substituted current permission originals"
    );
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(native(chain).escrows.is_empty());
}
