//! Canonical row and lifecycle boundaries for scoped fee evidence readers.
use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{Registrable, account::Account, block::BlockHeader};
use iroha_model_base::chain::ChainId;
use std::num::{NonZeroU16, NonZeroU64};

fn with_fixture(test: impl FnOnce(&mut StateTransaction<'_, '_>, &MultisigAccountState)) {
    let key = KeyPair::from_seed(vec![73; 32], Algorithm::Ed25519);
    let owner = AccountId::new(key.public_key().clone());
    let spec = MultisigSpec::new(
        BTreeMap::from([(owner.clone(), 1)]),
        NonZeroU16::new(1).unwrap(),
        NonZeroU64::new(1_000).unwrap(),
    );
    let account = AccountId::new_multisig(multisig_policy_from_spec(&spec).unwrap());
    let native = MultisigAccountState::new(account.clone(), None, spec);
    let world = World::with([], [Account::new(account).build(&owner)], []);
    let state = State::new_with_chain(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        ChainId::from("scoped-multisig-fee-evidence"),
    );
    let mut block = state.block(BlockHeader::new(
        NonZeroU64::new(1).unwrap(),
        None,
        None,
        500,
        0,
    ));
    let mut tx = block.transaction_for_callback_testing();
    // Component fixture uses the actual canonical writer; no alias/metadata-only registration.
    persist_multisig_account_state(&mut tx, None, &native).unwrap();
    test(&mut tx, &native);
}
fn proposal(account: &AccountId) -> MultisigProposalState {
    let instructions = vec![Log::new(Level::INFO, "exact proposed body".into()).into()];
    MultisigProposalState::new(
        account.clone(),
        HashOf::new(&instructions),
        instructions,
        100,
        1_000,
        BTreeSet::new(),
        None,
    )
}
fn terminal(proposal: &MultisigProposalState) -> MultisigProposalTerminalState {
    MultisigProposalTerminalState::new(
        proposal.multisig_account_id.clone(),
        proposal.instructions_hash,
        proposal_state_value(proposal),
        MultisigProposalTerminalStatus::Finalized,
        500,
    )
}
fn install_terminal(
    tx: &mut StateTransaction<'_, '_>,
    terminal: &MultisigProposalTerminalState,
    hash: [u8; 32],
) {
    install_executed_fee_proposal_fixture(tx, terminal, hash).unwrap();
}
fn limited<T>(read: impl FnOnce() -> T) -> T {
    norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        read,
    )
}

#[test]
fn fee_registered_controller_requires_canonical_state_and_exact_policy() {
    with_fixture(|tx, native| {
        let account = &native.account_id;
        let key = multisig_account_state_key(account);
        let original = tx.world.smart_contract_state.get(&key).unwrap().clone();
        assert_eq!(
            read_registered_account_state(&tx.world, account).unwrap(),
            Some(native.clone())
        );
        tx.world.smart_contract_state.remove(key.clone());
        // Matching metadata is still present but is not authoritative registration.
        assert!(
            read_registered_account_state(&tx.world, account)
                .unwrap()
                .is_none()
        );
        tx.world
            .smart_contract_state
            .insert(key.clone(), original.clone());
        let mut wrong = native.clone();
        wrong.spec.quorum = NonZeroU16::new(2).unwrap();
        tx.world
            .smart_contract_state
            .insert(key.clone(), norito::to_bytes(&wrong).unwrap());
        assert!(matches!(
            read_registered_account_state(&tx.world, account),
            Err(Attempt::Rejected(_))
        ));
        let mut wrong = native.clone();
        wrong.account_id = native.spec.signatories.keys().next().unwrap().clone();
        tx.world
            .smart_contract_state
            .insert(key.clone(), norito::to_bytes(&wrong).unwrap());
        assert!(matches!(
            read_registered_account_state(&tx.world, account),
            Err(Attempt::Rejected(_))
        ));
        let mut wrong = native.clone();
        *wrong.spec.signatories.values_mut().next().unwrap() = 2;
        tx.world
            .smart_contract_state
            .insert(key.clone(), norito::to_bytes(&wrong).unwrap());
        assert!(matches!(
            read_registered_account_state(&tx.world, account),
            Err(Attempt::Rejected(_))
        ));
        tx.world.smart_contract_state.insert(key, original);
        let mut wrong_metadata = native.spec.clone();
        wrong_metadata.transaction_ttl_ms = NonZeroU64::new(999).unwrap();
        tx.world
            .accounts
            .get_mut(account)
            .unwrap()
            .metadata
            .insert(spec_key(), Json::new(wrong_metadata));
        assert!(matches!(
            read_registered_account_state(&tx.world, account),
            Err(Attempt::Rejected(_))
        ));
    });
}

#[test]
fn fee_registered_home_domain_uses_canonical_json_and_preserves_refusal() {
    with_fixture(|tx, native| {
        let mut with_domain = native.clone();
        with_domain.home_domain =
            Some(iroha_model_base::domain::DomainId::try_new("bsp", "cbsi").unwrap());
        persist_multisig_account_state(tx, Some(native), &with_domain).unwrap();
        assert_eq!(
            read_registered_account_state(&tx.world, &native.account_id).unwrap(),
            Some(with_domain.clone())
        );
        // Isolate the optional domain decoder so refusal cannot come from spec.
        tx.world
            .accounts
            .get_mut(&native.account_id)
            .unwrap()
            .metadata
            .remove(&spec_key());
        assert!(matches!(
            limited(|| validate_registered_account_state(
                &tx.world,
                native.account_id.clone(),
                with_domain.clone(),
            )),
            Err(Attempt::Deferred(_))
        ));
        assert_eq!(
            read_registered_account_state(&tx.world, &native.account_id).unwrap(),
            Some(with_domain.clone())
        );
        for invalid in [
            Json::new(Some(
                iroha_model_base::domain::DomainId::try_new("other", "cbsi").unwrap(),
            )),
            Json::new(Option::<iroha_model_base::domain::DomainId>::None),
            Json::new(17_u64),
        ] {
            tx.world
                .accounts
                .get_mut(&native.account_id)
                .unwrap()
                .metadata
                .insert(home_domain_key(), invalid);
            assert!(matches!(
                read_registered_account_state(&tx.world, &native.account_id),
                Err(Attempt::Rejected(_))
            ));
        }
        persist_multisig_account_state(tx, Some(&with_domain), native).unwrap();
        assert_eq!(
            read_registered_account_state(&tx.world, &native.account_id).unwrap(),
            Some(native.clone())
        );
    });
}

#[test]
fn fee_pending_proposal_is_exact_live_nonrelayed_and_never_terminal() {
    with_fixture(|tx, native| {
        let p = proposal(&native.account_id);
        let h = &p.instructions_hash;
        assert!(
            read_pending_fee_proposal(&tx.world, &native.account_id, h, 500)
                .unwrap()
                .is_none()
        );
        store_multisig_proposal_state(tx, &p).unwrap();
        assert_eq!(
            read_pending_fee_proposal(&tx.world, &native.account_id, h, 100).unwrap(),
            Some(p.instructions.clone())
        );
        for time in [99, 1_000, u64::MAX] {
            assert!(
                read_pending_fee_proposal(&tx.world, &native.account_id, h, time)
                    .unwrap()
                    .is_none()
            );
        }
        for relayed in [Some(false), Some(true)] {
            let mut changed = p.clone();
            changed.is_relayed = relayed;
            store_multisig_proposal_state(tx, &changed).unwrap();
            assert!(
                read_pending_fee_proposal(&tx.world, &native.account_id, h, 500)
                    .unwrap()
                    .is_none()
            );
        }
        store_multisig_proposal_state(tx, &p).unwrap();
        store_multisig_proposal_terminal_state(tx, &terminal(&p)).unwrap();
        assert!(matches!(
            read_pending_fee_proposal(&tx.world, &native.account_id, h, 500),
            Err(Attempt::Rejected(_))
        ));
        tx.world
            .smart_contract_state
            .remove(multisig_proposal_state_key(&native.account_id, h));
        assert!(
            read_pending_fee_proposal(&tx.world, &native.account_id, h, 500)
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn fee_pending_proposal_rejects_rehashed_key_and_body_substitution() {
    with_fixture(|tx, native| {
        let p = proposal(&native.account_id);
        let key = multisig_proposal_state_key(&native.account_id, &p.instructions_hash);
        for recompute in [false, true] {
            let mut wrong = p.clone();
            wrong.instructions =
                vec![Log::new(Level::INFO, "different unapproved body".into()).into()];
            if recompute {
                wrong.instructions_hash = HashOf::new(&wrong.instructions);
            }
            tx.world
                .smart_contract_state
                .insert(key.clone(), norito::to_bytes(&wrong).unwrap());
            assert!(matches!(
                read_pending_fee_proposal(&tx.world, &native.account_id, &p.instructions_hash, 500),
                Err(Attempt::Rejected(_))
            ));
        }
    });
}

#[test]
fn fee_settlement_requires_this_transaction_executed_outcome_and_block() {
    with_fixture(|tx, native| {
        let p = proposal(&native.account_id);
        let t = terminal(&p);
        let hash = *Hash::new(b"exact settlement entrypoint").as_ref();
        install_terminal(tx, &t, hash);
        let h = &p.instructions_hash;
        let read = |tx: &StateTransaction<'_, '_>| {
            read_settled_fee_proposal(&tx.world, &native.account_id, h, hash, 1)
        };
        assert_eq!(read(tx).unwrap(), Some(p.instructions.clone()));
        assert!(
            read_settled_fee_proposal(&tx.world, &native.account_id, h, [8; 32], 1)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            read_settled_fee_proposal(&tx.world, &native.account_id, h, hash, 2),
            Err(Attempt::Rejected(_))
        ));
        assert!(
            read_pending_fee_proposal(&tx.world, &native.account_id, h, 500)
                .unwrap()
                .is_none()
        );
        let key = multisig_approval_outcome_state_key(hash, &native.account_id, h);
        let bytes = tx.world.smart_contract_state.get(&key).unwrap().clone();
        tx.world.smart_contract_state.remove(key.clone());
        assert!(
            read(tx).unwrap().is_none(),
            "Finalized before inner work is insufficient"
        );
        let mut outcome = norito::decode_from_bytes::<MultisigApprovalOutcomeV1>(&bytes).unwrap();
        outcome.status = MultisigApprovalOutcomeStatusV1::NotExecuted;
        tx.world
            .smart_contract_state
            .insert(key.clone(), norito::to_bytes(&outcome).unwrap());
        assert!(read(tx).unwrap().is_none());
        let correct = norito::decode_from_bytes::<MultisigApprovalOutcomeV1>(&bytes).unwrap();
        for field in 0..5 {
            let mut wrong = correct.clone();
            match field {
                0 => {
                    wrong.entrypoint_account_id =
                        native.spec.signatories.keys().next().unwrap().clone()
                }
                1 => {
                    wrong.resolved_multisig_account_id =
                        native.spec.signatories.keys().next().unwrap().clone()
                }
                2 => wrong.instructions_hash = HashOf::new(&Vec::<InstructionBox>::new()),
                3 => wrong.entrypoint_hash = [5; 32],
                _ => wrong.block_height += 1,
            }
            tx.world
                .smart_contract_state
                .insert(key.clone(), norito::to_bytes(&wrong).unwrap());
            assert!(matches!(read(tx), Err(Attempt::Rejected(_))));
        }
        tx.world.smart_contract_state.insert(key, bytes);
        store_multisig_proposal_state(tx, &p).unwrap();
        assert!(matches!(read(tx), Err(Attempt::Rejected(_))));
    });
}

#[test]
fn fee_settlement_rejects_substituted_execution_and_terminal_bodies() {
    with_fixture(|tx, native| {
        let p = proposal(&native.account_id);
        let t = terminal(&p);
        let hash = *Hash::new(b"exact settlement entrypoint").as_ref();
        install_terminal(tx, &t, hash);
        let h = &p.instructions_hash;
        let execution_key =
            multisig_proposal_terminal_execution_state_key(hash, &native.account_id, h);
        let original = tx
            .world
            .smart_contract_state
            .get(&execution_key)
            .unwrap()
            .clone();
        let execution =
            norito::decode_from_bytes::<MultisigProposalTerminalExecutionStateV1>(&original)
                .unwrap();
        for field in 0..4 {
            let mut wrong = execution.clone();
            match field {
                0 => wrong.terminal_entrypoint_hash = [9; 32],
                1 => wrong.terminal_block_height += 1,
                2 => wrong.terminal.terminal_at_ms += 1,
                _ => {
                    wrong.entrypoint_account_id =
                        native.spec.signatories.keys().next().unwrap().clone()
                }
            }
            tx.world
                .smart_contract_state
                .insert(execution_key.clone(), norito::to_bytes(&wrong).unwrap());
            assert!(matches!(
                read_settled_fee_proposal(&tx.world, &native.account_id, h, hash, 1),
                Err(Attempt::Rejected(_))
            ));
        }
        tx.world
            .smart_contract_state
            .insert(execution_key, original);
        let mut wrong = t.clone();
        wrong.proposal.instructions =
            vec![Log::new(Level::INFO, "substituted terminal body".into()).into()];
        tx.world.smart_contract_state.insert(
            multisig_proposal_terminal_state_key(&native.account_id, h),
            norito::to_bytes(&wrong).unwrap(),
        );
        assert!(matches!(
            read_settled_fee_proposal(&tx.world, &native.account_id, h, hash, 1),
            Err(Attempt::Rejected(_))
        ));
    });
}

#[test]
fn fee_settlement_denies_canceled_expired_and_relayed_history() {
    with_fixture(|tx, native| {
        let p = proposal(&native.account_id);
        let original = terminal(&p);
        let hash = *Hash::new(b"exact settlement entrypoint").as_ref();
        let key = multisig_proposal_terminal_state_key(&native.account_id, &p.instructions_hash);
        for field in 0..4 {
            let mut t = original.clone();
            match field {
                0 => t.status = MultisigProposalTerminalStatus::Canceled,
                1 => t.status = MultisigProposalTerminalStatus::Expired,
                2 => t.proposal.is_relayed = Some(false),
                _ => t.proposal.is_relayed = Some(true),
            }
            tx.world
                .smart_contract_state
                .insert(key.clone(), norito::to_bytes(&t).unwrap());
            assert!(
                read_settled_fee_proposal(
                    &tx.world,
                    &native.account_id,
                    &p.instructions_hash,
                    hash,
                    1
                )
                .unwrap()
                .is_none()
            );
        }
    });
}

#[test]
fn fee_evidence_readers_preserve_actual_decoder_refusal_without_mutation() {
    with_fixture(|tx, native| {
        let p = proposal(&native.account_id);
        store_multisig_proposal_state(tx, &p).unwrap();
        assert!(matches!(
            limited(|| read_registered_account_state(&tx.world, &native.account_id)),
            Err(Attempt::Deferred(_))
        ));
        assert!(matches!(
            limited(|| read_pending_fee_proposal(
                &tx.world,
                &native.account_id,
                &p.instructions_hash,
                500
            )),
            Err(Attempt::Deferred(_))
        ));
        assert_eq!(
            read_pending_fee_proposal(&tx.world, &native.account_id, &p.instructions_hash, 500)
                .unwrap(),
            Some(p.instructions.clone())
        );
        tx.world
            .smart_contract_state
            .remove(multisig_proposal_state_key(
                &native.account_id,
                &p.instructions_hash,
            ));
        let hash = *Hash::new(b"exact settlement entrypoint").as_ref();
        install_terminal(tx, &terminal(&p), hash);
        let key = multisig_proposal_terminal_state_key(&native.account_id, &p.instructions_hash);
        let original = tx.world.smart_contract_state.get(&key).unwrap().clone();
        assert!(matches!(
            limited(|| read_settled_fee_proposal(
                &tx.world,
                &native.account_id,
                &p.instructions_hash,
                hash,
                1
            )),
            Err(Attempt::Deferred(_))
        ));
        assert_eq!(tx.world.smart_contract_state.get(&key), Some(&original));
        assert_eq!(
            read_settled_fee_proposal(&tx.world, &native.account_id, &p.instructions_hash, hash, 1)
                .unwrap(),
            Some(p.instructions)
        );
    });
}

#[test]
fn fee_proposal_new_key_requires_both_physical_rows_absent() {
    with_fixture(|tx, native| {
        let p = proposal(&native.account_id);
        let h = &p.instructions_hash;
        assert!(fee_proposal_key_is_unused(&tx.world, &native.account_id, h));
        for key in [
            multisig_proposal_state_key(&native.account_id, h),
            multisig_proposal_terminal_state_key(&native.account_id, h),
        ] {
            tx.world
                .smart_contract_state
                .insert(key.clone(), vec![0xff]);
            assert!(!fee_proposal_key_is_unused(
                &tx.world,
                &native.account_id,
                h
            ));
            tx.world.smart_contract_state.remove(key);
        }
        store_multisig_proposal_state(tx, &p).unwrap();
        assert!(!fee_proposal_key_is_unused(
            &tx.world,
            &native.account_id,
            h
        ));
        tx.world
            .smart_contract_state
            .remove(multisig_proposal_state_key(&native.account_id, h));
        store_multisig_proposal_terminal_state(tx, &terminal(&p)).unwrap();
        assert!(!fee_proposal_key_is_unused(
            &tx.world,
            &native.account_id,
            h
        ));
    });
}

#[test]
fn fee_registered_metadata_refusal_retains_original_json_attempt() {
    with_fixture(|tx, native| {
        // Start after the canonical binary decode to exercise the actual optional JSON reader.
        let state = native.clone();
        let account = native.account_id.clone();
        assert!(matches!(
            limited(|| validate_registered_account_state(&tx.world, account, state)),
            Err(Attempt::Deferred(_))
        ));
        assert_eq!(
            validate_registered_account_state(&tx.world, native.account_id.clone(), native.clone())
                .unwrap(),
            *native
        );
    });
}

#[test]
fn fee_terminal_comparison_checks_every_field_and_approved_body() {
    with_fixture(|_, native| {
        let p = proposal(&native.account_id);
        let original = terminal(&p);
        assert!(same_terminal_evidence(&original, &original).unwrap());
        for field in 0..9 {
            let mut changed = original.clone();
            match field {
                0 => {
                    changed.multisig_account_id =
                        native.spec.signatories.keys().next().unwrap().clone()
                }
                1 => changed.instructions_hash = HashOf::new(&Vec::<InstructionBox>::new()),
                2 => changed.status = MultisigProposalTerminalStatus::Canceled,
                3 => changed.terminal_at_ms += 1,
                4 => changed.proposal.proposed_at_ms += 1,
                5 => changed.proposal.expires_at_ms += 1,
                6 => {
                    changed
                        .proposal
                        .approvals
                        .insert(native.spec.signatories.keys().next().unwrap().clone());
                }
                7 => changed.proposal.is_relayed = Some(false),
                _ => {
                    changed.proposal.instructions = vec![
                        Log::new(
                            Level::INFO,
                            "different instruction under same approved hash".into(),
                        )
                        .into(),
                    ]
                }
            }
            assert!(
                !same_terminal_evidence(&changed, &original).unwrap(),
                "field {field}"
            );
            assert!(
                !same_terminal_evidence(&original, &changed).unwrap(),
                "field {field}"
            );
        }
    });
}
