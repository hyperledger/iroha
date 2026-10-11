//! The global chain's AMX instructions and deadline step over a real World: every `Begin` and
//! `Decision` becomes a write of the block's execution witness, proven against genuine
//! certificates of two foreign fixture chains.

use iroha_data_model::{
    block::{
        consensus::{ExecKv, ExecWitness},
        decode_framed_signed_block,
    },
    isi::sumeragi_amx::{BeginAmxV1, RegisterAmxDataspaceV1, RelayAmxPreparedV1},
    sumeragi_amx::{
        AmxCertifiedBlockV1, AmxForeignInstanceV1, AmxLegV1, AmxOutcomeV1, AmxPreparedV1,
        AmxRecordProofV1, AmxRecordV1, AmxTransactionV1, AmxVoteV1, SumeragiAmxState,
    },
    sumeragi_finality::{
        SUMERAGI_LANE_STATE_WITNESS_KEY, SumeragiLaneStateCommitment, authenticated_genesis,
        test_fixtures::NativeFinalityFixture,
    },
    sumeragi_lanes::SumeragiLaneState,
};
use iroha_model_base::topology::DataSpaceId;

use crate::{
    smartcontracts::{
        Execute,
        isi::sccp::test_support::{authority, blank_state, header},
    },
    state::{State, StateBlock},
};

const DS1: DataSpaceId = DataSpaceId::new(21);
const DS2: DataSpaceId = DataSpaceId::new(22);

/// A foreign dataspace chain with genuine native certificates.
struct Dataspace {
    id: DataSpaceId,
    chain: NativeFinalityFixture,
}

impl Dataspace {
    fn new(id: DataSpaceId) -> Self {
        Self {
            id,
            chain: NativeFinalityFixture::start(&format!("amx-dataspace-{}", id.as_u64())),
        }
    }

    fn instance(&self) -> [u8; 32] {
        self.chain.verifier().instance().0
    }

    fn register(&self) -> RegisterAmxDataspaceV1 {
        RegisterAmxDataspaceV1 {
            dataspace: self.id,
            instance: self.instance(),
            anchor: norito::encode_canonical(
                &authenticated_genesis(self.chain.genesis())
                    .map(|genesis| genesis.into_parts().0)
                    .unwrap(),
            )
            .unwrap(),
        }
    }

    /// Certify the next block of this chain, whose execution wrote `record`, and prove it.
    fn prove(&mut self, record: &AmxRecordV1) -> AmxRecordProofV1 {
        let header = self.chain.next_header();
        let height = header.height().get();
        let lanes = SumeragiLaneStateCommitment::from_state(
            self.chain.network_id(),
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
                key: record.witness_key().to_vec(),
                value: record.witness_value().unwrap(),
            },
        ];
        let block = self.chain.block_with_submitted_work(header);
        let witness = ExecWitness {
            writes: writes.clone(),
            ..ExecWitness::default()
        };
        let proof = self.chain.certify_with_witness(block, &witness);
        let certified = decode_framed_signed_block(&proof.block_wire).unwrap();
        AmxRecordProofV1::from_writes(
            AmxCertifiedBlockV1::from_certificate(certified.commit_certificate().unwrap()),
            writes
                .iter()
                .map(|write| (write.key.as_slice(), write.value.as_slice())),
            record.clone(),
        )
        .unwrap()
    }
}

fn transaction(deadline: u64, nonce: u8) -> AmxTransactionV1 {
    AmxTransactionV1 {
        legs: [DS1, DS2]
            .into_iter()
            .map(|dataspace| AmxLegV1 {
                dataspace,
                payload: vec![nonce],
            })
            .collect(),
        deadline,
        nonce: [nonce; 32],
    }
}

fn yes(tx: &AmxTransactionV1, participant: DataSpaceId) -> AmxRecordV1 {
    AmxRecordV1::Prepared(AmxPreparedV1 {
        tx: tx.id().unwrap(),
        participant,
        vote: AmxVoteV1::Yes([participant.as_u64() as u8; 32]),
    })
}

/// Execute `instruction` in its own transaction of `block`.
fn execute(block: &mut StateBlock<'_>, instruction: impl Execute) -> Result<(), String> {
    let mut transaction = block.transaction();
    instruction
        .execute(&authority(7), &mut transaction)
        .map_err(|error| error.to_string())?;
    transaction.apply();
    Ok(())
}

/// The AMX records among `writes`.
fn amx_records(writes: &[ExecKv]) -> Vec<AmxRecordV1> {
    writes
        .iter()
        .filter(|write| write.key.first() == Some(&0xD9))
        .map(|write| AmxRecordV1::from_witness(&write.key, &write.value).unwrap())
        .collect()
}

#[test]
fn sumeragi_amx_begin_and_decisions_are_witness_writes_of_the_block() {
    let mut ds1 = Dataspace::new(DS1);
    let mut ds2 = Dataspace::new(DS2);
    let tx = transaction(5, 1);
    let proof1 = ds1.prove(&yes(&tx, DS1));
    let proof2 = ds2.prove(&yes(&tx, DS2));
    let state: State = blank_state();
    let mut block = state.block(header(1));
    let _guard = crate::exec_witness::exec_witness_guard();
    crate::exec_witness::start_block();
    execute(&mut block, ds1.register()).unwrap();
    execute(&mut block, ds2.register()).unwrap();
    execute(
        &mut block,
        BeginAmxV1 {
            transaction: tx.clone(),
        },
    )
    .unwrap();
    // A second Begin for x is rejected.
    assert!(
        execute(
            &mut block,
            BeginAmxV1 {
                transaction: tx.clone(),
            }
        )
        .is_err()
    );
    // A proof certified by another dataspace's committee is rejected.
    let mut forged = proof1.clone();
    forged.record = yes(&tx, DS2);
    assert!(execute(&mut block, RelayAmxPreparedV1 { proof: forged }).is_err());
    execute(
        &mut block,
        RelayAmxPreparedV1 {
            proof: proof1.clone(),
        },
    )
    .unwrap();
    execute(&mut block, RelayAmxPreparedV1 { proof: proof2 }).unwrap();
    // Later proofs are ignored.
    execute(&mut block, RelayAmxPreparedV1 { proof: proof1 }).unwrap();
    let entry = block
        .world
        .sumeragi_amx
        .get()
        .transaction(&tx.id().unwrap())
        .cloned()
        .unwrap();
    assert_eq!(
        entry.decided.map(|decided| decided.outcome),
        Some(AmxOutcomeV1::Commit)
    );
    let witness = crate::exec_witness::drain_exec_witness();
    assert_eq!(
        amx_records(&witness.writes),
        vec![
            AmxRecordV1::Begin(tx.begin().unwrap()),
            AmxRecordV1::Decision(iroha_data_model::sumeragi_amx::AmxDecisionV1 {
                tx: tx.id().unwrap(),
                outcome: AmxOutcomeV1::Commit,
            }),
        ]
    );
}

#[test]
fn sumeragi_amx_registration_needs_genesis_or_permission() {
    let ds1 = Dataspace::new(DS1);
    let state = blank_state();
    {
        let mut block = state.block(header(2));
        let error = execute(&mut block, ds1.register()).unwrap_err();
        assert!(error.contains("CanSetParameters"), "{error}");
    }
    let mut malformed = ds1.register();
    malformed.anchor = vec![1, 2, 3];
    let mut genesis = state.block(header(1));
    assert!(execute(&mut genesis, malformed).is_err());
    assert!(genesis.require_storage_admission().is_ok());
    execute(&mut genesis, ds1.register()).unwrap();
    assert!(execute(&mut genesis, ds1.register()).is_err());
}

#[test]
fn sumeragi_amx_deadline_step_aborts_in_the_first_block_after_the_deadline() {
    let ds1 = Dataspace::new(DS1);
    let ds2 = Dataspace::new(DS2);
    let mut seeded = SumeragiAmxState::default();
    for dataspace in [&ds1, &ds2] {
        seeded
            .register_dataspace(
                dataspace.id,
                AmxForeignInstanceV1::new(
                    dataspace.instance(),
                    authenticated_genesis(dataspace.chain.genesis())
                        .map(|genesis| genesis.into_parts().0)
                        .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
    }
    let expiring = transaction(5, 2);
    let pending = transaction(9, 3);
    seeded.begin(2, &expiring).unwrap();
    seeded.begin(2, &pending).unwrap();
    let state = blank_state();
    for (height, expected) in [(5, vec![]), (6, vec![expiring.id().unwrap()])] {
        let mut block = state.block(header(height));
        *block.world.sumeragi_amx.get_mut() = seeded.clone();
        let _guard = crate::exec_witness::exec_witness_guard();
        crate::exec_witness::start_block();
        let count = block.advance_sumeragi_amx().unwrap();
        let decisions = expected
            .iter()
            .map(|tx| iroha_data_model::sumeragi_amx::AmxDecisionV1 {
                tx: *tx,
                outcome: AmxOutcomeV1::Abort,
            })
            .collect::<Vec<_>>();
        assert_eq!(count, decisions.len());
        assert_eq!(
            decisions
                .iter()
                .map(|decision| decision.tx)
                .collect::<Vec<_>>(),
            expected
        );
        assert!(
            decisions
                .iter()
                .all(|decision| decision.outcome == AmxOutcomeV1::Abort)
        );
        let witness = crate::exec_witness::drain_exec_witness();
        assert_eq!(
            amx_records(&witness.writes),
            decisions
                .iter()
                .copied()
                .map(AmxRecordV1::Decision)
                .collect::<Vec<_>>()
        );
        let amx = block.world.sumeragi_amx.get();
        assert_eq!(
            amx.transaction(&expiring.id().unwrap()).is_some(),
            expected.is_empty()
        );
        assert!(amx.transaction(&pending.id().unwrap()).is_some());
    }
    // Nothing to expire leaves the cell untouched.
    let mut idle = state.block(header(3));
    *idle.world.sumeragi_amx.get_mut() = seeded;
    assert_eq!(idle.advance_sumeragi_amx().unwrap(), 0);
}

#[test]
fn sumeragi_amx_write_proofs_match_the_executor_write_root() {
    use crate::exec_witness::smt::{KvPair, compute_post_state_root};
    use iroha_data_model::sumeragi_amx::{AmxDecisionV1, AmxWriteProofV1, write_set_root};

    // The executor's write-set tree and the record proofs' tree agree, so a record written by a
    // block's execution is proven against the ordinary-write root that `R` certifies.
    let tx = transaction(9, 4);
    let records = [
        AmxRecordV1::Begin(tx.begin().unwrap()),
        AmxRecordV1::Decision(AmxDecisionV1 {
            tx: tx.id().unwrap(),
            outcome: AmxOutcomeV1::Abort,
        }),
        yes(&tx, DS1),
    ];
    let mut writes: Vec<KvPair> = (0u8..48)
        .map(|index| KvPair::new(vec![index, 7, 7], vec![index; usize::from(index) + 1]))
        .collect();
    for record in &records {
        writes.push(KvPair::new(
            record.witness_key().to_vec(),
            record.witness_value().unwrap(),
        ));
    }
    // A later write of a key wins, in both trees.
    writes.push(KvPair::new(vec![3, 7, 7], b"latest".to_vec()));
    let pairs = || {
        writes
            .iter()
            .map(|write| (write.key.as_slice(), write.value.as_slice()))
    };
    let root = compute_post_state_root(&[], &writes);
    assert_eq!(write_set_root(pairs()).unwrap(), root);
    for record in &records {
        let key = record.witness_key();
        let (path, value) = AmxWriteProofV1::from_writes(pairs(), &key).unwrap();
        assert_eq!(value, record.witness_value().unwrap());
        assert_eq!(path.root(&key, &value).unwrap(), root);
    }
}

fn refused_decode_limits() -> norito::DecodeLimits {
    norito::DecodeLimits::new(
        96,
        iroha_data_model::sumeragi_finality::MAX_RESULT_PREIMAGE_BYTES,
        usize::MAX,
        0,
        32,
    )
}

#[test]
fn amx_anchor_decode_refusal_cannot_publish_even_when_instruction_error_is_caught() {
    use crate::state::{StateStorageAdmissionError, storage_transactions::TransactionsBlockError};
    use iroha_data_model::sumeragi_amx::AmxError;
    let dataspace = Dataspace::new(DS1);
    let instruction = dataspace.register();
    let original = instruction.anchor.clone();
    let expected = norito::with_decode_limits_scope(refused_decode_limits(), || {
        super::decode_anchor(&original)
    })
    .unwrap_err();
    let AmxError::Resource(resource) = expected else {
        panic!("anchor decoder lost original local category: {expected:?}")
    };
    let local = StateStorageAdmissionError::AmxDecode(resource);
    assert!(local.release_wait().is_none());
    let state = blank_state();
    let mut block = state.block(header(1));
    let before = block.world.sumeragi_amx.get().clone();
    let mut transaction = block.transaction();
    let error = norito::with_decode_limits_scope(refused_decode_limits(), || {
        instruction.execute(&authority(7), &mut transaction)
    })
    .unwrap_err();
    assert!(error.to_string().contains("resource refusal"));
    assert_eq!(transaction.require_storage_admission(), Err(local.clone()));
    // Catching the inner instruction error cannot grant a successful apply or publication.
    transaction.apply();
    assert_eq!(block.require_storage_admission(), Err(local.clone()));
    assert_eq!(block.world.sumeragi_amx.get(), &before);
    assert!(
        matches!(block.commit_world_overlay_for_testing(), Err(TransactionsBlockError::LocalStateStorage(error)) if error == local)
    );
    let mut retry = state.block(header(1));
    let again = dataspace.register();
    assert_eq!(again.anchor, original);
    execute(&mut retry, again).unwrap();
    assert!(retry.require_storage_admission().is_ok());
    assert_eq!(retry.world.sumeragi_amx.get().dataspaces.len(), 1);
}

#[test]
fn amx_relay_decode_refusal_keeps_original_undecided_record_and_retries_proof() {
    use crate::state::{StateStorageAdmissionError, storage_transactions::TransactionsBlockError};
    let mut first = Dataspace::new(DS1);
    let second = Dataspace::new(DS2);
    let tx = transaction(9, 71);
    let proof = first.prove(&yes(&tx, DS1));
    let original = proof.clone();
    let mut seeded = SumeragiAmxState::default();
    for dataspace in [&first, &second] {
        seeded
            .register_dataspace(
                dataspace.id,
                AmxForeignInstanceV1::new(
                    dataspace.instance(),
                    authenticated_genesis(dataspace.chain.genesis())
                        .map(|genesis| genesis.into_parts().0)
                        .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
    }
    seeded.begin(1, &tx).unwrap();
    let state = blank_state();
    let mut block = state.block(header(2));
    *block.world.sumeragi_amx.get_mut() = seeded.clone();
    let mut transaction = block.transaction();
    norito::with_decode_limits_scope(refused_decode_limits(), || {
        RelayAmxPreparedV1 { proof }.execute(&authority(7), &mut transaction)
    })
    .unwrap_err();
    let error = transaction.require_storage_admission().unwrap_err();
    assert!(matches!(error, StateStorageAdmissionError::AmxDecode(_)));
    drop(transaction);
    assert_eq!(block.world.sumeragi_amx.get(), &seeded);
    assert!(
        matches!(block.commit_world_overlay_for_testing(), Err(TransactionsBlockError::LocalStateStorage(local)) if local == error)
    );
    let mut retry = state.block(header(2));
    *retry.world.sumeragi_amx.get_mut() = seeded;
    execute(&mut retry, RelayAmxPreparedV1 { proof: original }).unwrap();
    assert!(retry.require_storage_admission().is_ok());
    let record = retry
        .world
        .sumeragi_amx
        .get()
        .transaction(&tx.id().unwrap())
        .unwrap();
    assert!(record.decided.is_none());
    assert_eq!(record.yes.len(), 1);
}

#[test]
fn amx_registration_borrows_exact_direct_and_role_grants_under_decode_refusal() {
    use crate::{kura::Kura, query::store::LiveQueryStore, role::RoleIdWithOwner, state::World};
    use iroha_data_model::{
        Registrable,
        account::Account,
        permission::Permission,
        role::{Role, RoleId},
    };
    use iroha_executor_data_model::permission::parameter::CanSetParameters;
    use iroha_primitives::json::Json;

    let actor = authority(7);
    let dataspace = Dataspace::new(DS1);
    let required = Permission::from(CanSetParameters);
    assert_eq!(required.name(), "CanSetParameters");
    assert_eq!(required.payload().get().as_str(), "null");
    for through_role in [false, true] {
        for (name, payload, expected) in [
            (required.name(), "null", true),
            (required.name(), "\"null\"", false),
            (required.name(), "{}", false),
            (required.name(), "false", false),
            ("CanSetParametersSubstituted", "null", false),
        ] {
            let grant = Permission::new(
                name.to_owned(),
                Json::from_raw_json(payload.to_owned()).unwrap(),
            );
            assert_eq!(grant == required, expected);
            let mut world = World::with([], [Account::new(actor.clone()).build(&actor)], []);
            if through_role {
                let id: RoleId = "amx_parameters".parse().unwrap();
                let role = Role::new(id.clone(), actor.clone())
                    .add_permission(grant)
                    .build(&actor);
                world.roles.insert(id.clone(), role);
                world
                    .account_roles
                    .insert(RoleIdWithOwner::new(actor.clone(), id), ());
            } else {
                world
                    .account_permissions
                    .insert(actor.clone(), [grant].into_iter().collect());
            }
            let state = State::new_for_testing(
                world,
                Kura::blank_kura_for_testing(),
                LiveQueryStore::start_test(),
            );
            let mut block = state.block(header(2));
            let instruction = dataspace.register();
            let mut transaction = block.transaction();
            let (present, usage) =
                norito::core::with_decode_limits_measured(refused_decode_limits(), || {
                    super::has_permission(&transaction.world, &actor)
                });
            assert_eq!(present, expected, "role={through_role} {name}({payload})");
            assert_eq!(usage.total_allocated_bytes(), 0);
            let error = norito::with_decode_limits_scope(refused_decode_limits(), || {
                instruction.execute(&actor, &mut transaction)
            })
            .unwrap_err();
            assert_eq!(transaction.require_storage_admission().is_err(), expected);
            if !expected {
                assert!(error.to_string().contains("CanSetParameters"));
            }
            assert!(transaction.world.sumeragi_amx.get().dataspaces.is_empty());
            drop(transaction);
            drop(block);
            if expected {
                let mut retry = state.block(header(2));
                execute(&mut retry, dataspace.register()).unwrap();
                assert_eq!(retry.world.sumeragi_amx.get().dataspaces.len(), 1);
            }
        }
    }
}

#[test]
fn amx_deadline_record_refusal_keeps_original_pending_state_and_typed_retry() {
    let mut seeded = SumeragiAmxState::default();
    for dataspace in [Dataspace::new(DS1), Dataspace::new(DS2)] {
        seeded
            .register_dataspace(
                dataspace.id,
                AmxForeignInstanceV1::new(
                    dataspace.instance(),
                    authenticated_genesis(dataspace.chain.genesis())
                        .map(|genesis| genesis.into_parts().0)
                        .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
    }
    let first = transaction(5, 21);
    let second = transaction(5, 22);
    let pending = transaction(9, 23);
    for tx in [&first, &second, &pending] {
        seeded.begin(2, tx).unwrap();
    }
    let state = blank_state();
    let mut block = state.block(header(6));
    *block.world.sumeragi_amx.get_mut() = seeded.clone();
    let original_pointer = block.world.sumeragi_amx.get().transactions.as_ptr();
    let original_capacity = block.world.sumeragi_amx.get().transactions.capacity();
    let original = norito::core::DecodeResourceError::AllocationFailed { bytes: 57 };
    let _guard = crate::exec_witness::exec_witness_guard();
    crate::exec_witness::start_block();
    let mut calls = 0;
    // Refuse the record callback after one genuine witness write. This is a typed
    // local boundary control, not a claim of physical allocator fault injection.
    let error = block
        .advance_sumeragi_amx_with(|record| {
            calls += 1;
            if calls == 2 {
                return Err(super::AmxError::Resource(original));
            }
            super::write(record)
        })
        .expect_err("unfinished witness output cannot prune the original source");
    assert_eq!(error, super::AmxError::Resource(original));
    assert_eq!(block.world.sumeragi_amx.get(), &seeded);
    assert_eq!(
        block.world.sumeragi_amx.get().transactions.as_ptr(),
        original_pointer
    );
    assert_eq!(
        block.world.sumeragi_amx.get().transactions.capacity(),
        original_capacity
    );
    assert_eq!(block.advance_sumeragi_amx().unwrap(), 2);
    let mut actual = amx_records(&crate::exec_witness::drain_exec_witness().writes);
    actual.sort_by_key(AmxRecordV1::tx);
    let mut expected = [first.id().unwrap(), second.id().unwrap()]
        .map(|tx| {
            AmxRecordV1::Decision(iroha_data_model::sumeragi_amx::AmxDecisionV1 {
                tx,
                outcome: AmxOutcomeV1::Abort,
            })
        })
        .to_vec();
    expected.sort_by_key(AmxRecordV1::tx);
    assert_eq!(actual, expected);
    assert!(
        block
            .world
            .sumeragi_amx
            .get()
            .transaction(&first.id().unwrap())
            .is_none()
    );
    assert!(
        block
            .world
            .sumeragi_amx
            .get()
            .transaction(&second.id().unwrap())
            .is_none()
    );
    assert!(
        block
            .world
            .sumeragi_amx
            .get()
            .transaction(&pending.id().unwrap())
            .is_some()
    );
    assert_eq!(block.advance_sumeragi_amx().unwrap(), 0);
}
