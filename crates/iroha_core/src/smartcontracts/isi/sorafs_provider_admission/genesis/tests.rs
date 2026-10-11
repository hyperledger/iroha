//! Actual signed genesis, derived network identity and durable native admission, on certified
//! test chains whose genesis carries the initializer.
use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::isi::sorafs_provider_admission::test_fixture::{
        NOW, ProviderAdmissionTestFixtureV1 as Fixture, key,
    },
    state::{State, World},
    sumeragi::test_chain::{CertifiedTestChain, StartFailure, TestChainConfig},
};
use iroha_data_model::{
    IntoKeyValue, NetworkId, Registrable,
    block::{BlockHeader, builder::BlockBuilder},
    isi::InstructionBox,
    sorafs::provider_admission::governance::{
        InitialProviderAdmissionCouncilV1, InitialProviderAdmissionV1,
    },
    transaction::{FeePaymentIntent, SignedTransaction, TransactionBuilder},
};
use std::{sync::Arc, time::Duration};

fn initializer(fixture: &Fixture) -> InitializeSorafsProviderAdmissionV1 {
    InitializeSorafsProviderAdmissionV1 {
        council: InitialProviderAdmissionCouncilV1 {
            policy_id: fixture.policy.policy_id,
            trusted_signers: fixture.policy.trusted_signers.clone(),
            signature_threshold: 1,
        },
        providers: vec![InitialProviderAdmissionV1 {
            owner: AccountId::new(key(1).public_key().clone()),
            material: norito::encode_canonical(&ProviderAdmissionGenesisMaterialV1 {
                proposal: fixture.envelope.proposal.clone(),
                advert_body: fixture.envelope.advert_body.clone(),
                issued_at: NOW,
                retention_epoch: NOW + 3600,
            })
            .unwrap(),
        }],
    }
}

/// A chain whose genesis (authorized by `key(1)`'s account, at `NOW`) carries `instructions`.
fn chain(
    instructions: Vec<InstructionBox>,
    existing_owner: Option<(ProviderId, AccountId)>,
) -> Result<CertifiedTestChain, StartFailure> {
    let mut world = World::new();
    if let Some((provider, owner)) = existing_owner {
        world.provider_owners.insert(provider, owner);
    }
    let mut config = TestChainConfig::new(world, NOW * 1000);
    config.genesis_key = key(1);
    config.genesis_instructions = instructions;
    CertifiedTestChain::start(config)
}

fn signed(instructions: Vec<InstructionBox>, network: NetworkId, now: u64) -> SignedTransaction {
    let owner = AccountId::new(key(1).public_key().clone());
    let mut builder = TransactionBuilder::new(
        network,
        owner,
        FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(Duration::from_millis(now));
    builder
        .with_instructions(instructions)
        .try_sign(key(1).private_key())
        .unwrap()
}

#[test]
fn signed_genesis_templates_bind_the_actual_genesis_hash_and_canonical_journal() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    for existing in [false, true] {
        let initialize = initializer(&fixture);
        let owner = initialize.providers[0].owner.clone();
        let mut chain = chain(
            vec![initialize.clone().into()],
            existing.then_some((provider, owner)),
        )
        .expect("genesis applies");
        let state = Arc::clone(chain.state());
        assert_eq!(
            state.network_id_ref().as_bytes(),
            chain.genesis().hash().as_ref()
        );
        assert!(
            native::read_finalized_provider_admission_v1(&state.view(), provider, NOW).is_err(),
            "the original signed proposal requires its actual H2 execution anchor"
        );
        assert!(chain.commit_at(NOW * 1000 + 1, Vec::new()).is_empty());
        assert_eq!(chain.height(), 2);
        let actual = native::read_finalized_provider_admission_v1(&state.view(), provider, NOW)
            .unwrap()
            .unwrap();
        assert!(actual.is_genesis_material());
        assert!(!actual.is_council_verified());
        assert!(actual.envelope().council_signatures.is_empty());
        assert_eq!(
            actual.envelope().network_id,
            *state.network_id_ref().as_bytes()
        );
        assert!(
            sorafs_manifest::provider_admission::verify_envelope_untrusted_signers(
                actual.envelope()
            )
            .is_err()
        );
        assert_eq!(
            native::retained_provider_count_v1(&state.view()).unwrap(),
            1
        );
        let original = native::read_head(state.view().world(), Some(provider)).unwrap();
        // The same initializer in an ordinary network-scoped transaction initializes nothing.
        let replay = signed(
            vec![initialize.into()],
            *state.network_id_ref(),
            NOW * 1000 + 500,
        );
        assert_eq!(chain.commit_at((NOW + 1) * 1000, vec![replay]), [false]);
        assert_eq!(
            native::read_head(state.view().world(), Some(provider)).unwrap(),
            original
        );
    }
}

#[test]
fn finalized_genesis_admission_expiry_rejects_a_lagging_local_clock() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let mut initialize = initializer(&fixture);
    let mut material: ProviderAdmissionGenesisMaterialV1 =
        decode_frame(&initialize.providers[0].material).unwrap();
    material.retention_epoch = NOW + 2;
    initialize.providers[0].material = norito::encode_canonical(&material).unwrap();
    let mut chain = chain(vec![initialize.into()], None).expect("genesis applies");
    let state = Arc::clone(chain.state());
    assert!(
        native::read_finalized_provider_admission_v1(&state.view(), provider, NOW - 1).is_err()
    );
    for (offset, valid) in [(1, true), (2, false)] {
        assert!(
            chain
                .commit_at((NOW + offset) * 1000, Vec::new())
                .is_empty()
        );
        let result = native::read_finalized_provider_admission_v1(&state.view(), provider, NOW);
        if valid {
            assert!(result.unwrap().is_some());
        } else {
            assert!(
                result.is_err(),
                "signed-genesis material cannot outlive finalized expiry"
            );
        }
    }
}

#[test]
fn applied_genesis_without_its_durable_frame_cannot_admit() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let mut chain = chain(vec![initializer(&fixture).into()], None).expect("genesis applies");
    chain.commit_at((NOW + 1) * 1000, Vec::new());
    let state = Arc::clone(chain.state());
    assert!(
        native::read_finalized_provider_admission_v1(&state.view(), provider, NOW)
            .unwrap()
            .is_some()
    );
    // Without the genesis frame and its result certificate, the initializer is not
    // authenticated (the signed genesis is the trust root of the admission).
    state
        .kura()
        .corrupt_canonical_body_for_testing(std::num::NonZeroUsize::MIN)
        .unwrap();
    assert!(native::read_finalized_provider_admission_v1(&state.view(), provider, NOW).is_err());
}

#[test]
fn malformed_templates_and_owner_conflicts_leave_no_genesis_journal() {
    let fixture = Fixture::new();
    for malformed in 0..6 {
        let mut initialize = initializer(&fixture);
        let mut existing = None;
        match malformed {
            0 => initialize.providers.push(initialize.providers[0].clone()),
            1 => initialize.providers[0].owner = AccountId::new(key(2).public_key().clone()),
            2 => initialize.council.signature_threshold = 2,
            3 => initialize.providers[0].material.push(0),
            4 => {
                existing = Some((
                    fixture.provider(),
                    AccountId::new(key(2).public_key().clone()),
                ));
            }
            5 => {
                let mut material: ProviderAdmissionGenesisMaterialV1 =
                    decode_frame(&initialize.providers[0].material).unwrap();
                material.retention_epoch = NOW;
                initialize.providers[0].material = norito::encode_canonical(&material).unwrap();
            }
            _ => unreachable!(),
        }
        // A failing genesis instruction makes the whole genesis invalid.
        let state = chain(vec![initialize.into()], existing)
            .err()
            .unwrap_or_else(|| panic!("malformed genesis {malformed} applied"))
            .state;
        assert!(
            native::read_head(state.view().world(), None)
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn second_initializer_in_one_genesis_transaction_rolls_back_the_first() {
    let fixture = Fixture::new();
    let initialize = initializer(&fixture);
    let state = chain(vec![initialize.clone().into(), initialize.into()], None)
        .err()
        .expect("a second initializer fails genesis")
        .state;
    assert!(
        native::read_head(state.view().world(), None)
            .unwrap()
            .is_none()
    );
}

#[test]
fn indirect_or_network_scoped_execution_cannot_acquire_genesis_authority() {
    let fixture = Fixture::new();
    let initialize = initializer(&fixture);
    let owner = AccountId::new(key(1).public_key().clone());
    let mut transaction = TransactionBuilder::new_genesis(
        owner.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    );
    transaction.set_creation_time(Duration::from_millis(NOW * 1000));
    let transaction = transaction
        .with_instructions([InstructionBox::from(initialize.clone())])
        .try_sign(key(1).private_key())
        .unwrap();
    let mut genesis = BlockBuilder::new(BlockHeader::new(
        1.try_into().unwrap(),
        None,
        None,
        NOW * 1000,
        0,
    ));
    genesis.push_transaction(transaction.clone());
    let genesis = genesis
        .try_build_with_signature(0, key(0xfe).private_key())
        .unwrap();
    let mut world = World::new();
    let (id, account) = iroha_data_model::account::Account::new(owner.clone())
        .build(&owner)
        .into_key_value();
    world.accounts.insert(id, account);
    let state = State::new_with_chain_and_network_id_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        "genesis-admission-test".parse().unwrap(),
        NetworkId::from_genesis_hash(genesis.hash()),
    );
    let mut block = state.block(genesis.header());
    let mut tx = block.transaction();
    tx.current_network_entrypoint_hash = Some(transaction.hash_as_entrypoint());
    tx.current_tx_hash = Some(transaction.hash());
    tx.tx_call_hash = Some(iroha_crypto::Hash::from(transaction.hash_as_entrypoint()));
    tx.current_entrypoint_index = Some(0);
    let boxed = initialize.clone().into();
    assert!(
        !crate::executor::Executor::direct_sorafs_admission_initialization(
            &tx,
            &transaction,
            &boxed,
            0,
            false
        )
    );
    assert!(
        !crate::executor::Executor::direct_sorafs_admission_initialization(
            &tx,
            &transaction,
            &boxed,
            1,
            true
        )
    );
    assert!(
        crate::executor::Executor::Initial
            .execute_instruction(&mut tx, transaction.authority(), boxed)
            .is_err()
    );
    assert!(native::read_head(tx.world(), None).unwrap().is_none());
    drop(tx);
    drop(block);
    // After genesis, a network-scoped initializer is an ordinary transaction and fails.
    let mut chain = chain(Vec::new(), None).expect("genesis applies");
    let ordinary = signed(
        vec![initialize.into()],
        chain.network_id(),
        NOW * 1000 + 500,
    );
    assert_eq!(chain.commit_at((NOW + 1) * 1000, vec![ordinary]), [false]);
    assert!(
        native::read_head(chain.state().view().world(), None)
            .unwrap()
            .is_none()
    );
}

#[test]
fn source_bound_current_admission_preserves_signed_genesis_material_expiry_and_custody() {
    use crate::query::{
        provider_admission::read_provider_admission_at_native_current_v1,
        signer_check::{SignerCertifiedWalkV1, with_native_check_read_limits},
    };
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let mut initialize = initializer(&fixture);
    let mut material: ProviderAdmissionGenesisMaterialV1 =
        decode_frame(&initialize.providers[0].material).unwrap();
    material.retention_epoch = NOW + 3;
    initialize.providers[0].material = norito::encode_canonical(&material).unwrap();
    let mut chain =
        chain(vec![initialize.into()], None).expect("actual signed genesis initializer");
    let log = chain.sign(
        &key(1),
        [iroha_data_model::isi::Log::new(
            iroha_logger::Level::INFO,
            "admission source-bound successor".to_owned(),
        )
        .into()],
        (NOW + 1) * 1000,
    );
    assert!(chain.commit_at((NOW + 1) * 1000, vec![log])[0]);
    let state = Arc::clone(chain.state());
    let view = state.view();
    let public_facade = native::read_finalized_provider_admission_v1(&view, provider, NOW + 1)
        .unwrap()
        .unwrap();
    with_native_check_read_limits(|| {
        let reader = SignerCertifiedWalkV1::new(&view).unwrap();
        let current = reader.walk(2, 2).next().unwrap().unwrap();
        let original =
            read_provider_admission_at_native_current_v1(&view, &current, provider, NOW + 1)
                .unwrap()
                .unwrap();
        assert!(original.is_genesis_material());
        assert_eq!(original.envelope(), public_facade.envelope());
        assert!(
            read_provider_admission_at_native_current_v1(&view, &current, provider, NOW + 3)
                .is_err(),
            "original interval cannot be renewed by re-reading"
        );
        let tiny =
            norito::DecodeLimits::new(64 * 1024 * 1024, 64 * 1024 * 1024, 64 * 1024 * 1024, 0, 128);
        assert!(
            norito::with_decode_limits_scope(
                tiny,
                || read_provider_admission_at_native_current_v1(&view, &current, provider, NOW + 1)
            )
            .is_err(),
            "retained current receipt does not waive original admission decode/source charge"
        );
    });
    drop(view);
    state
        .kura()
        .corrupt_canonical_body_for_testing(std::num::NonZeroUsize::MIN)
        .unwrap();
    let view = state.view();
    assert!(
        with_native_check_read_limits(|| SignerCertifiedWalkV1::new(&view)).is_err(),
        "missing original genesis frame is not replaced by retained admission bytes"
    );
}

/// Keep a real signed genesis transaction and its original empty-State context without executing
/// it, so each direct-source rejection can be inspected independently before any journal effect.
fn direct_initializer_context(instructions: Vec<InstructionBox>) -> (State, SignedTransaction) {
    let owner = AccountId::new(key(1).public_key().clone());
    let mut builder = TransactionBuilder::new_genesis(
        owner.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(Duration::from_millis(NOW * 1000));
    let transaction = builder
        .with_instructions(instructions)
        .try_sign(key(1).private_key())
        .unwrap();
    let mut genesis = BlockBuilder::new(BlockHeader::new(
        1.try_into().unwrap(),
        None,
        None,
        NOW * 1000,
        0,
    ));
    genesis.push_transaction(transaction.clone());
    let genesis = genesis
        .try_build_with_signature(0, key(0xfe).private_key())
        .unwrap();
    let mut world = World::new();
    let (id, account) = iroha_data_model::account::Account::new(owner.clone())
        .build(&owner)
        .into_key_value();
    world.accounts.insert(id, account);
    let state = State::new_with_chain_and_network_id_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        "genesis-admission-test".parse().unwrap(),
        NetworkId::from_genesis_hash(genesis.hash()),
    );
    (state, transaction)
}

#[test]
fn direct_initializer_hashes_only_its_exact_instruction_in_an_unrelated_genesis_batch() {
    use crate::executor::{Executor, sorafs_admission_hash_probe};
    let fixture = Fixture::new();
    let mut instructions: Vec<InstructionBox> = (0..16)
        .map(|index| {
            iroha_data_model::isi::Log::new(
                iroha_logger::Level::INFO,
                format!("unrelated genesis instruction {index}"),
            )
            .into()
        })
        .collect();
    instructions.push(initializer(&fixture).into());
    let (state, source) = direct_initializer_context(instructions.clone());
    let mut block = state.block(BlockHeader::new(
        1.try_into().unwrap(),
        None,
        None,
        NOW * 1000,
        0,
    ));
    let mut tx = block.transaction();
    tx.current_network_entrypoint_hash = Some(source.hash_as_entrypoint());
    tx.current_tx_hash = Some(source.hash());
    tx.tx_call_hash = Some(iroha_crypto::Hash::from(source.hash_as_entrypoint()));
    tx.current_entrypoint_index = Some(0);
    let (recognized, hashes) = sorafs_admission_hash_probe::count(|| {
        instructions
            .iter()
            .enumerate()
            .map(|(index, instruction)| {
                Executor::direct_sorafs_admission_initialization(
                    &tx,
                    &source,
                    instruction,
                    index,
                    true,
                )
            })
            .collect::<Vec<_>>()
    });
    assert!(recognized[..16].iter().all(|recognized| !recognized));
    assert!(
        recognized[16],
        "the exact initializer remains authenticated"
    );
    assert_eq!(
        hashes, 1,
        "unrelated instructions must never hash the full batch"
    );
    for index in [0, instructions.len(), usize::MAX] {
        let (recognized, hashes) = sorafs_admission_hash_probe::count(|| {
            Executor::direct_sorafs_admission_initialization(
                &tx,
                &source,
                &instructions[16],
                index,
                true,
            )
        });
        assert!(!recognized);
        assert_eq!(
            hashes, 0,
            "an absent or different original ordinal is not hashed"
        );
    }
    let mut different = initializer(&fixture);
    different.council.signature_threshold += 1;
    let (recognized, hashes) = sorafs_admission_hash_probe::count(|| {
        Executor::direct_sorafs_admission_initialization(&tx, &source, &different.into(), 16, true)
    });
    assert!(!recognized);
    assert_eq!(
        hashes, 0,
        "a same-type instruction must still equal its signed original"
    );
    assert!(native::read_head(tx.world(), None).unwrap().is_none());
}

#[test]
fn direct_initializer_keeps_original_hash_network_and_genesis_context_refusals() {
    use crate::executor::{Executor, sorafs_admission_hash_probe};
    let fixture = Fixture::new();
    let instruction: InstructionBox = initializer(&fixture).into();
    let (state, source) = direct_initializer_context(vec![instruction.clone()]);
    let mut block = state.block(BlockHeader::new(
        1.try_into().unwrap(),
        None,
        None,
        NOW * 1000,
        0,
    ));
    let mut tx = block.transaction();
    let outer = source.hash_as_entrypoint();
    let signed_hash = source.hash();
    let call_hash = iroha_crypto::Hash::from(outer);
    for refusal in 0..8 {
        tx.current_network_entrypoint_hash = Some(outer);
        tx.current_tx_hash = Some(signed_hash);
        tx.tx_call_hash = Some(call_hash);
        tx.current_entrypoint_index = Some(0);
        match refusal {
            0 => {}
            1 => tx.current_network_entrypoint_hash = None,
            2 => {
                tx.current_network_entrypoint_hash =
                    Some(iroha_crypto::HashOf::from_untyped_unchecked(
                        iroha_crypto::Hash::prehashed([0x42; 32]),
                    ))
            }
            3 => tx.tx_call_hash = None,
            4 => tx.tx_call_hash = Some(iroha_crypto::Hash::prehashed([0x42; 32])),
            5 => tx.current_tx_hash = None,
            6 => {
                tx.current_tx_hash = Some(iroha_crypto::HashOf::from_untyped_unchecked(
                    iroha_crypto::Hash::prehashed([0x42; 32]),
                ))
            }
            7 => tx.current_entrypoint_index = None,
            _ => unreachable!(),
        }
        let (recognized, hashes) = sorafs_admission_hash_probe::count(|| {
            Executor::direct_sorafs_admission_initialization(&tx, &source, &instruction, 0, true)
        });
        assert_eq!(
            recognized,
            refusal == 0,
            "original source refusal {refusal}"
        );
        assert_eq!(
            hashes, 1,
            "applicable instructions still authenticate the original hash"
        );
    }
    tx.current_network_entrypoint_hash = Some(outer);
    tx.current_tx_hash = Some(signed_hash);
    tx.tx_call_hash = Some(call_hash);
    tx.current_entrypoint_index = Some(0);
    let (recognized, hashes) = sorafs_admission_hash_probe::count(|| {
        Executor::direct_sorafs_admission_initialization(&tx, &source, &instruction, 0, false)
    });
    assert!(!recognized);
    assert_eq!(
        hashes, 0,
        "indirect execution cannot acquire the direct source"
    );
    let ordinary = signed(vec![instruction.clone()], *tx.network_id(), NOW * 1000);
    tx.current_network_entrypoint_hash = Some(ordinary.hash_as_entrypoint());
    tx.current_tx_hash = Some(ordinary.hash());
    tx.tx_call_hash = Some(iroha_crypto::Hash::from(ordinary.hash_as_entrypoint()));
    let (recognized, hashes) = sorafs_admission_hash_probe::count(|| {
        Executor::direct_sorafs_admission_initialization(&tx, &ordinary, &instruction, 0, true)
    });
    assert!(
        !recognized,
        "a valid Network-scoped source cannot gain genesis authority"
    );
    assert_eq!(hashes, 1);
    assert!(native::read_head(tx.world(), None).unwrap().is_none());
    drop(tx);
    drop(block);
    let mut later = state.block(BlockHeader::new(
        2.try_into().unwrap(),
        None,
        None,
        NOW * 1000 + 1,
        0,
    ));
    let mut tx = later.transaction();
    tx.current_network_entrypoint_hash = Some(outer);
    tx.current_tx_hash = Some(signed_hash);
    tx.tx_call_hash = Some(call_hash);
    tx.current_entrypoint_index = Some(0);
    let (recognized, hashes) = sorafs_admission_hash_probe::count(|| {
        Executor::direct_sorafs_admission_initialization(&tx, &source, &instruction, 0, true)
    });
    assert!(
        !recognized,
        "a matching signed source cannot authorize a later block"
    );
    assert_eq!(hashes, 0);
}
