//! Canonical row and lifecycle boundaries for scoped fee evidence readers.
use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    Registrable,
    account::Account,
    block::BlockHeader,
    prelude::{Level, Log},
};
use iroha_executor_data_model::isi::multisig::MultisigProposalNonce;
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
fn proposal(tx: &StateTransaction<'_, '_>, account: &AccountId) -> MultisigProposalState {
    let instructions = vec![Log::new(Level::INFO, "exact proposed body".into()).into()];
    let nonce = MultisigProposalNonce::new([7; 32]).unwrap();
    MultisigProposalState {
        network_id: tx.network_id,
        multisig_account_id: account.clone(),
        proposal_nonce: nonce,
        proposal_id: MultisigProposalId::derive(&tx.network_id, account, &nonce),
        instructions_hash: HashOf::new(&instructions),
        transaction_ttl_ms: None,
        instructions,
        proposed_at_ms: 100,
        expires_at_ms: 1_000,
        approvals: BTreeSet::new(),
    }
}
fn terminal(proposal: &MultisigProposalState) -> MultisigProposalTerminalState {
    MultisigProposalTerminalState::new(
        proposal.multisig_account_id.clone(),
        proposal.proposal_id,
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
        let original_metadata = tx
            .world
            .accounts
            .get(&native.account_id)
            .unwrap()
            .metadata()
            .clone();
        assert_actual_fee_decoder_owner(limited(|| {
            validate_registered_account_state(
                &tx.world,
                native.account_id.clone(),
                with_domain.clone(),
            )
        }));
        assert_eq!(
            tx.world
                .accounts
                .get(&native.account_id)
                .unwrap()
                .metadata(),
            &original_metadata
        );
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
fn fee_pending_proposal_is_exact_live_occurrence_and_never_terminal() {
    with_fixture(|tx, native| {
        let p = proposal(tx, &native.account_id);
        assert!(
            read_pending_fee_proposal(
                &tx.world,
                &native.account_id,
                &p.proposal_id,
                &p.instructions_hash,
                500
            )
            .unwrap()
            .is_none()
        );
        store_multisig_proposal_state(tx, &p).unwrap();
        assert_eq!(
            read_pending_fee_proposal(
                &tx.world,
                &native.account_id,
                &p.proposal_id,
                &p.instructions_hash,
                100
            )
            .unwrap(),
            Some(p.instructions.clone())
        );
        for time in [99, 1_000, u64::MAX] {
            assert!(
                read_pending_fee_proposal(
                    &tx.world,
                    &native.account_id,
                    &p.proposal_id,
                    &p.instructions_hash,
                    time
                )
                .unwrap()
                .is_none()
            );
        }
        store_multisig_proposal_state(tx, &p).unwrap();
        store_multisig_proposal_terminal_state(tx, &terminal(&p)).unwrap();
        assert!(matches!(
            read_pending_fee_proposal(
                &tx.world,
                &native.account_id,
                &p.proposal_id,
                &p.instructions_hash,
                500
            ),
            Err(Attempt::Rejected(_))
        ));
        tx.world
            .smart_contract_state
            .remove(multisig_proposal_state_key(
                &native.account_id,
                &p.proposal_id,
            ));
        assert!(
            read_pending_fee_proposal(
                &tx.world,
                &native.account_id,
                &p.proposal_id,
                &p.instructions_hash,
                500
            )
            .unwrap()
            .is_none()
        );
    });
}

#[test]
fn fee_pending_proposal_rejects_rehashed_key_and_body_substitution() {
    with_fixture(|tx, native| {
        let p = proposal(tx, &native.account_id);
        let key = multisig_proposal_state_key(&native.account_id, &p.proposal_id);
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
                read_pending_fee_proposal(
                    &tx.world,
                    &native.account_id,
                    &p.proposal_id,
                    &p.instructions_hash,
                    500
                ),
                Err(Attempt::Rejected(_))
            ));
        }
    });
}

#[test]
fn fee_settlement_requires_this_transaction_executed_outcome_and_block() {
    with_fixture(|tx, native| {
        let p = proposal(tx, &native.account_id);
        let t = terminal(&p);
        let hash = *Hash::new(b"exact settlement entrypoint").as_ref();
        install_terminal(tx, &t, hash);
        let read = |tx: &StateTransaction<'_, '_>| {
            read_settled_fee_proposal(
                &tx.world,
                &native.account_id,
                &p.proposal_id,
                &p.instructions_hash,
                hash,
                1,
            )
        };
        assert_eq!(read(tx).unwrap(), Some(p.instructions.clone()));
        assert!(
            read_settled_fee_proposal(
                &tx.world,
                &native.account_id,
                &p.proposal_id,
                &p.instructions_hash,
                [8; 32],
                1
            )
            .unwrap()
            .is_none()
        );
        assert!(matches!(
            read_settled_fee_proposal(
                &tx.world,
                &native.account_id,
                &p.proposal_id,
                &p.instructions_hash,
                hash,
                2
            ),
            Err(Attempt::Rejected(_))
        ));
        assert!(
            read_pending_fee_proposal(
                &tx.world,
                &native.account_id,
                &p.proposal_id,
                &p.instructions_hash,
                500
            )
            .unwrap()
            .is_none()
        );
        let key = multisig_approval_outcome_state_key(hash, &native.account_id, &p.proposal_id);
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
        for field in 0..6 {
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
                4 => wrong.block_height += 1,
                _ => wrong.proposal_id = "82".repeat(32).parse().unwrap(),
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
        let p = proposal(tx, &native.account_id);
        let t = terminal(&p);
        let hash = *Hash::new(b"exact settlement entrypoint").as_ref();
        install_terminal(tx, &t, hash);
        let execution_key = multisig_proposal_terminal_execution_state_key(
            hash,
            &native.account_id,
            &p.proposal_id,
        );
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
                read_settled_fee_proposal(
                    &tx.world,
                    &native.account_id,
                    &p.proposal_id,
                    &p.instructions_hash,
                    hash,
                    1
                ),
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
            multisig_proposal_terminal_state_key(&native.account_id, &p.proposal_id),
            norito::to_bytes(&wrong).unwrap(),
        );
        assert!(matches!(
            read_settled_fee_proposal(
                &tx.world,
                &native.account_id,
                &p.proposal_id,
                &p.instructions_hash,
                hash,
                1
            ),
            Err(Attempt::Rejected(_))
        ));
    });
}

#[test]
fn fee_settlement_denies_canceled_and_expired_history() {
    with_fixture(|tx, native| {
        let p = proposal(tx, &native.account_id);
        let original = terminal(&p);
        let hash = *Hash::new(b"exact settlement entrypoint").as_ref();
        let key = multisig_proposal_terminal_state_key(&native.account_id, &p.proposal_id);
        for field in 0..2 {
            let mut t = original.clone();
            match field {
                0 => t.status = MultisigProposalTerminalStatus::Canceled,
                _ => t.status = MultisigProposalTerminalStatus::Expired,
            }
            tx.world
                .smart_contract_state
                .insert(key.clone(), norito::to_bytes(&t).unwrap());
            assert!(
                read_settled_fee_proposal(
                    &tx.world,
                    &native.account_id,
                    &p.proposal_id,
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
        let p = proposal(tx, &native.account_id);
        store_multisig_proposal_state(tx, &p).unwrap();
        assert!(matches!(
            limited(|| read_registered_account_state(&tx.world, &native.account_id)),
            Err(Attempt::Deferred(_))
        ));
        assert!(matches!(
            limited(|| read_pending_fee_proposal(
                &tx.world,
                &native.account_id,
                &p.proposal_id,
                &p.instructions_hash,
                500
            )),
            Err(Attempt::Deferred(_))
        ));
        assert_eq!(
            read_pending_fee_proposal(
                &tx.world,
                &native.account_id,
                &p.proposal_id,
                &p.instructions_hash,
                500
            )
            .unwrap(),
            Some(p.instructions.clone())
        );
        tx.world
            .smart_contract_state
            .remove(multisig_proposal_state_key(
                &native.account_id,
                &p.proposal_id,
            ));
        let hash = *Hash::new(b"exact settlement entrypoint").as_ref();
        install_terminal(tx, &terminal(&p), hash);
        let key = multisig_proposal_terminal_state_key(&native.account_id, &p.proposal_id);
        let original = tx.world.smart_contract_state.get(&key).unwrap().clone();
        assert!(matches!(
            limited(|| read_settled_fee_proposal(
                &tx.world,
                &native.account_id,
                &p.proposal_id,
                &p.instructions_hash,
                hash,
                1
            )),
            Err(Attempt::Deferred(_))
        ));
        assert_eq!(tx.world.smart_contract_state.get(&key), Some(&original));
        assert_eq!(
            read_settled_fee_proposal(
                &tx.world,
                &native.account_id,
                &p.proposal_id,
                &p.instructions_hash,
                hash,
                1
            )
            .unwrap(),
            Some(p.instructions)
        );
    });
}

#[test]
fn fee_proposal_new_key_requires_both_physical_rows_absent() {
    with_fixture(|tx, native| {
        let p = proposal(tx, &native.account_id);
        assert!(fee_proposal_key_is_unused(
            &tx.world,
            &native.account_id,
            &p.proposal_id
        ));
        for key in [
            multisig_proposal_state_key(&native.account_id, &p.proposal_id),
            multisig_proposal_terminal_state_key(&native.account_id, &p.proposal_id),
        ] {
            tx.world
                .smart_contract_state
                .insert(key.clone(), vec![0xff]);
            assert!(!fee_proposal_key_is_unused(
                &tx.world,
                &native.account_id,
                &p.proposal_id
            ));
            tx.world.smart_contract_state.remove(key);
        }
        store_multisig_proposal_state(tx, &p).unwrap();
        assert!(!fee_proposal_key_is_unused(
            &tx.world,
            &native.account_id,
            &p.proposal_id
        ));
        tx.world
            .smart_contract_state
            .remove(multisig_proposal_state_key(
                &native.account_id,
                &p.proposal_id,
            ));
        store_multisig_proposal_terminal_state(tx, &terminal(&p)).unwrap();
        assert!(!fee_proposal_key_is_unused(
            &tx.world,
            &native.account_id,
            &p.proposal_id
        ));
    });
}

#[test]
fn fee_registered_metadata_refusal_retains_original_json_attempt() {
    with_fixture(|tx, native| {
        // Start after the canonical binary decode to exercise the actual optional JSON reader.
        let state = native.clone();
        let account = native.account_id.clone();
        let original_metadata = tx
            .world
            .accounts
            .get(&native.account_id)
            .unwrap()
            .metadata()
            .clone();
        assert_actual_fee_decoder_owner(limited(|| {
            validate_registered_account_state(&tx.world, account, state)
        }));
        assert_eq!(
            tx.world
                .accounts
                .get(&native.account_id)
                .unwrap()
                .metadata(),
            &original_metadata
        );
        assert_eq!(
            validate_registered_account_state(&tx.world, native.account_id.clone(), native.clone())
                .unwrap(),
            *native
        );
    });
}

#[test]
fn fee_terminal_comparison_checks_every_field_and_approved_body() {
    with_fixture(|tx, native| {
        let p = proposal(tx, &native.account_id);
        let original = terminal(&p);
        assert!(same_terminal_evidence(&original, &original).unwrap());
        for field in 0..13 {
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
                7 => changed.proposal.proposal_nonce = MultisigProposalNonce::new([8; 32]).unwrap(),
                9 => changed.proposal.proposal_id = "81".repeat(32).parse().unwrap(),
                10 => {
                    changed.proposal.network_id = iroha_data_model::NetworkId::from_genesis_hash(
                        HashOf::from_untyped_unchecked(Hash::new(b"different network")),
                    )
                }
                11 => changed.proposal.transaction_ttl_ms = NonZeroU64::new(700),
                12 => changed.proposal_id = "82".repeat(32).parse().unwrap(),
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

fn assert_actual_fee_decoder_owner<T: core::fmt::Debug>(
    result: Result<T, Attempt<ValidationFail>>,
) {
    let Err(Attempt::Deferred(original)) = result else {
        panic!("actual local decoder refusal must remain deferred: {result:?}");
    };
    assert_eq!(
        original.reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    let observed = original
        .decode_refusal()
        .expect("actual canonical reader observer")
        .clone();
    assert!(original.allocation_refusal().is_none());
    assert!(original.verification_refusal().is_none());
    let returned =
        crate::execution_attempt::ExecutionDeferred::try_from_vm_error(original.into_vm_error())
            .expect("consuming VM roundtrip retains the one original decoder cause");
    assert_eq!(returned.decode_refusal(), Some(&observed));
}

#[test]
fn registered_fee_reader_keeps_actual_binary_decoder_owner_and_unchanged_retry() {
    with_fixture(|tx, native| {
        let key = multisig_account_state_key(&native.account_id);
        let original = tx.world.smart_contract_state.get(&key).unwrap().clone();
        assert_actual_fee_decoder_owner(limited(|| {
            read_registered_account_state(&tx.world, &native.account_id)
        }));
        assert_eq!(tx.world.smart_contract_state.get(&key), Some(&original));
        assert_eq!(
            read_registered_account_state(&tx.world, &native.account_id).unwrap(),
            Some(native.clone()),
        );
    });
}

#[test]
fn settled_fee_reader_keeps_each_actual_binary_decoder_owner_and_same_evidence_retry() {
    use norito::core::DecodeBudgetContext;
    with_fixture(|tx, native| {
        let proposal = proposal(tx, &native.account_id);
        let terminal = terminal(&proposal);
        let hash = *Hash::new(b"three original settled fee decoders").as_ref();
        install_terminal(tx, &terminal, hash);
        let keys = [
            multisig_proposal_terminal_state_key(&native.account_id, &proposal.proposal_id),
            multisig_proposal_terminal_execution_state_key(
                hash,
                &native.account_id,
                &proposal.proposal_id,
            ),
            multisig_approval_outcome_state_key(hash, &native.account_id, &proposal.proposal_id),
        ];
        let original = keys
            .each_ref()
            .map(|key| tx.world.smart_contract_state.get(key).unwrap().clone());
        // Measure only the actual preceding canonical reads and approved-body hash.
        // Funding exactly that prefix forces the next reader to refuse, so all
        // three producer sites are exercised through the real settlement entry.
        let measured = DecodeBudgetContext::new(norito::DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX,
        ));
        let (terminal_cost, execution_cost) = measured.with(|| {
            let decoded =
                norito::decode_from_bytes::<MultisigProposalTerminalState>(&original[0]).unwrap();
            HashOf::try_new(&decoded.proposal.instructions).unwrap();
            let terminal_cost = measured.consumed_allocated_bytes();
            norito::decode_from_bytes::<MultisigProposalTerminalExecutionStateV1>(&original[1])
                .unwrap();
            (terminal_cost, measured.consumed_allocated_bytes())
        });
        assert!(terminal_cost > 0);
        assert!(execution_cost > terminal_cost);
        for funded_prefix in [0, terminal_cost, execution_cost] {
            let context = DecodeBudgetContext::new(norito::DecodeLimits::new(
                usize::MAX,
                usize::MAX,
                usize::MAX,
                usize::try_from(funded_prefix).unwrap(),
                usize::MAX,
            ));
            let refused = context.with(|| {
                read_settled_fee_proposal(
                    &tx.world,
                    &native.account_id,
                    &proposal.proposal_id,
                    &proposal.instructions_hash,
                    hash,
                    1,
                )
            });
            assert_eq!(
                context.consumed_allocated_bytes(),
                funded_prefix,
                "earlier readers complete under their measured exact funding"
            );
            assert_actual_fee_decoder_owner(refused);
            for (key, bytes) in keys.iter().zip(&original) {
                assert_eq!(tx.world.smart_contract_state.get(key), Some(bytes));
            }
            assert_eq!(
                read_settled_fee_proposal(
                    &tx.world,
                    &native.account_id,
                    &proposal.proposal_id,
                    &proposal.instructions_hash,
                    hash,
                    1
                )
                .unwrap(),
                Some(proposal.instructions.clone()),
            );
        }
    });
}

#[test]
fn fee_metadata_completed_invalid_json_keeps_original_diagnostics() {
    with_fixture(|tx, native| {
        let malformed = Json::new(17_u64);
        let account = &native.account_id;
        let expected = norito::json::from_str::<MultisigSpec>(malformed.get().as_str())
            .unwrap_err()
            .to_string();
        tx.world
            .accounts
            .get_mut(account)
            .unwrap()
            .metadata
            .insert(spec_key(), malformed.clone());
        let Err(Attempt::Rejected(ValidationFail::QueryFailed(QueryExecutionFail::Conversion(
            actual,
        )))) = validate_registered_account_state(&tx.world, account.clone(), native.clone())
        else {
            panic!("intrinsically invalid spec must remain completed rejection");
        };
        assert_eq!(
            actual,
            format!("invalid multisig/spec metadata for `{account}`: {expected}")
        );
        tx.world
            .accounts
            .get_mut(account)
            .unwrap()
            .metadata
            .remove(&spec_key());
        let expected = norito::json::from_str::<Option<iroha_model_base::domain::DomainId>>(
            malformed.get().as_str(),
        )
        .unwrap_err()
        .to_string();
        tx.world
            .accounts
            .get_mut(account)
            .unwrap()
            .metadata
            .insert(home_domain_key(), malformed);
        let Err(Attempt::Rejected(ValidationFail::QueryFailed(QueryExecutionFail::Conversion(
            actual,
        )))) = validate_registered_account_state(&tx.world, account.clone(), native.clone())
        else {
            panic!("intrinsically invalid domain must remain completed rejection");
        };
        assert_eq!(
            actual,
            format!("invalid multisig home-domain metadata for `{account}`: {expected}")
        );
    });
}

#[test]
fn fee_terminal_hashes_stream_canonical_body_without_decoder_budget() {
    with_fixture(|tx, native| {
        let proposal = proposal(tx, &native.account_id);
        let terminal = terminal(&proposal);
        // Encoding owns a streaming hash writer and must not consume decoder budget.
        // TODO: qualify an actual checked-writer failure separately; this successful
        // control does not pretend a decoder limit denies physical writer allocation.
        norito::with_decode_limits_scope(norito::DecodeLimits::new(0, 0, 0, 0, 0), || {
            assert_eq!(
                HashOf::try_new(&proposal.instructions).unwrap(),
                proposal.instructions_hash
            );
            assert!(same_terminal_evidence(&terminal, &terminal).unwrap());
        });
    });
}
