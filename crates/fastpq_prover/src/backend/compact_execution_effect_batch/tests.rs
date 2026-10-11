//! Synthetic complete-effect relation controls; these fixtures confer no finality authority.

use std::alloc::Layout;

use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    asset::{AssetBalanceScope, AssetDefinitionId},
    fastpq::{
        FastpqExecutionAssetV1, FastpqExecutionBalanceV1, FastpqExecutionEffectContextV1,
        FastpqExecutionEffectKindV1, FastpqExecutionEffectStatementV1, FastpqExecutionEffectV1,
        FastpqExecutionEffectsV1, FastpqExecutionSupplyChangeV1, FastpqExecutionTransferV1,
        FastpqSourceExecutionEntryV1, FastpqSourceExecutionKindV1, FastpqSourceLaneV1,
        FastpqSourceRouteV1, FastpqSourceStatementContextV1, execution_effect_statement_digest_v1,
        execution_effects_digest_v1,
    },
    nexus::AxtAssetIncarnationV1,
};
use iroha_model_base::{
    domain::DomainId,
    topology::{DataSpaceId, LaneId},
};
use iroha_test_samples::{ALICE_ID, BOB_ID};

use super::*;
use crate::gadgets::public_transfer_statement::{
    TransferSmtBuildLimits,
    execution_effect::{
        materialization_allocation_bytes, materialize_source_execution_effect_statement,
        preparation_allocation_bytes,
    },
};

fn balance(account: &AccountId) -> FastpqExecutionBalanceV1 {
    FastpqExecutionBalanceV1 {
        asset: FastpqExecutionAssetV1 {
            definition: AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            ),
            incarnation: AxtAssetIncarnationV1::try_from_bytes(
                Hash::new(b"synthetic effect batch incarnation").into(),
            )
            .unwrap(),
        },
        account: account.clone(),
        scope: AssetBalanceScope::Global,
    }
}

/// One test-owned mixed tape and locally derived roots; never an authenticated source opening.
/// All observed balances and the circulating supply reach zero before retirement.
pub(in crate::backend) fn fixture() -> (
    FastpqOrdinarySourceStatementLeafV1,
    FastpqExecutionEffectStatementV1,
    Vec<[u8; 32]>,
) {
    let alice = balance(&ALICE_ID);
    let bob = balance(&BOB_ID);
    let kinds = [
        FastpqExecutionEffectKindV1::Transfer(FastpqExecutionTransferV1 {
            source: alice.clone(),
            destination: bob.clone(),
            amount: 2_u32.into(),
            source_before: 10_u32.into(),
            source_after: 8_u32.into(),
            destination_before: 0_u32.into(),
            destination_after: 2_u32.into(),
        }),
        FastpqExecutionEffectKindV1::Mint(FastpqExecutionSupplyChangeV1 {
            balance: alice.clone(),
            amount: 3_u32.into(),
            balance_before: 8_u32.into(),
            balance_after: 11_u32.into(),
            supply_before: 10_u32.into(),
            supply_after: 13_u32.into(),
        }),
        FastpqExecutionEffectKindV1::Transfer(FastpqExecutionTransferV1 {
            source: bob,
            destination: alice.clone(),
            amount: 2_u32.into(),
            source_before: 2_u32.into(),
            source_after: 0_u32.into(),
            destination_before: 11_u32.into(),
            destination_after: 13_u32.into(),
        }),
        FastpqExecutionEffectKindV1::Burn(FastpqExecutionSupplyChangeV1 {
            balance: alice.clone(),
            amount: 13_u32.into(),
            balance_before: 13_u32.into(),
            balance_after: 0_u32.into(),
            supply_before: 13_u32.into(),
            supply_after: 0_u32.into(),
        }),
        FastpqExecutionEffectKindV1::Retire(alice.asset),
    ];
    let effects = FastpqExecutionEffectsV1 {
        context: FastpqExecutionEffectContextV1 {
            source: FastpqSourceStatementContextV1 {
                network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                    Hash::new(b"synthetic complete effect network"),
                )),
                height: 7,
            },
            entry: FastpqSourceExecutionEntryV1 {
                entry_hash: Hash::new(b"synthetic execution entry"),
                execution_kind: FastpqSourceExecutionKindV1::ExecutionCall,
                route: FastpqSourceRouteV1::Unrouted,
                dataspace_id: DataSpaceId::UNIVERSAL,
            },
        },
        effects: kinds
            .into_iter()
            .enumerate()
            .map(|(ordinal, kind)| FastpqExecutionEffectV1 {
                ordinal: u32::try_from(ordinal).unwrap(),
                authority_digest: Hash::new(b"synthetic authority"),
                authorization_context: Hash::new(b"synthetic permission context"),
                kind,
            })
            .collect(),
    };
    let source = FastpqOrdinarySourceStatementLeafV1 {
        source: effects.context.source,
        statement_index: 1,
        entry_index: 3,
        effect_count: u32::try_from(effects.effects.len()).unwrap(),
        entry_hash: effects.context.entry.entry_hash,
        execution_kind: effects.context.entry.execution_kind,
        route: effects.context.entry.route,
        dataspace_id: effects.context.entry.dataspace_id,
        effects_digest: execution_effects_digest_v1(&effects).unwrap().into(),
        slot: 99,
        perm_root: Hash::new(b"synthetic permission root").into(),
        tx_set_hash: Hash::new(b"synthetic transaction set").into(),
    };
    let limits = ExecutionEffectLimits::default();
    let tree = TransferSmtBuildLimits::for_update_limit(10).unwrap();
    let demand = materialization_allocation_bytes(&effects, limits, tree).unwrap();
    let budget = AllocationBudget::new(demand);
    let mut reservation = budget.try_reserve_bytes(demand).unwrap();
    let built = materialize_source_execution_effect_statement(
        &effects,
        &source,
        limits,
        tree,
        &budget,
        &mut reservation,
    )
    .unwrap();
    assert!(std::ptr::eq(built.effects(), &effects));
    let frame = norito::encode_canonical(&built.statement()).unwrap();
    let statement: FastpqExecutionEffectStatementV1 = norito::decode_canonical(&frame).unwrap();
    assert_eq!(statement.effects, effects);
    assert_eq!(norito::encode_canonical(&statement).unwrap(), frame);
    assert_eq!(built.witnesses().work().updates, 10);
    let roots = built.witnesses().intermediate_roots().collect();
    drop(built);
    drop(reservation);
    assert_eq!(budget.reserved_bytes(), 0);
    (source, statement, roots)
}

pub(in crate::backend) fn expected(
    statement: &FastpqExecutionEffectStatementV1,
) -> Result<ExecutionEffectExpectations> {
    Ok(ExecutionEffectExpectations {
        effects_digest: execution_effects_digest_v1(&statement.effects)?,
        statement_digest: execution_effect_statement_digest_v1(statement)?,
        public_inputs: statement.public_inputs,
    })
}

fn root_limbs(bytes: [u8; 32]) -> [u32; 8] {
    std::array::from_fn(|index| {
        u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap())
    })
}

fn limits() -> EffectBatchLimits {
    EffectBatchLimits {
        public: ExecutionEffectLimits::default(),
        context: BatchContextLimits::default(),
    }
}

fn demand(
    source: &FastpqOrdinarySourceStatementLeafV1,
    statement: &FastpqExecutionEffectStatementV1,
    roots: &[[u8; 32]],
) -> usize {
    ExecutionEffectBatch::allocation_bytes(
        &SourceExecutionEffectStatement::from_owned(statement),
        source,
        roots,
        limits(),
    )
    .unwrap()
}

pub(in crate::backend) fn batch(
    source: &FastpqOrdinarySourceStatementLeafV1,
    statement: &FastpqExecutionEffectStatementV1,
    roots: &[[u8; 32]],
) -> ExecutionEffectBatch {
    build(source, statement, roots, limits()).unwrap()
}

fn build(
    source: &FastpqOrdinarySourceStatementLeafV1,
    statement: &FastpqExecutionEffectStatementV1,
    roots: &[[u8; 32]],
    limits: EffectBatchLimits,
) -> Result<ExecutionEffectBatch> {
    let bytes = ExecutionEffectBatch::allocation_bytes(
        &SourceExecutionEffectStatement::from_owned(statement),
        source,
        roots,
        limits,
    )?;
    let budget = AllocationBudget::new(bytes);
    let mut reservation = budget.try_reserve_bytes(bytes).unwrap();
    ExecutionEffectBatch::new(
        &SourceExecutionEffectStatement::from_owned(statement),
        source,
        expected(statement)?,
        roots,
        limits,
        &budget,
        &mut reservation,
    )
}

// Independent derived owned layouts check the borrowed field and byte-sequence
// adapters. Shared frame projections are deliberate; nominal test owners differ.
#[derive(norito::SerializePayload, norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover::effect_batch_tests::OwnedBatch",
    frame = "fastpq_prover::compact_v1::ExecutionEffectBatchContextV1"
)]
struct OwnedBatch {
    version: u16,
    segment_count: u32,
    source: FastpqOrdinarySourceStatementLeafV1,
    statement: FastpqExecutionEffectStatementV1,
    intermediate_roots: Vec<[u8; 32]>,
}
#[derive(norito::SerializePayload, norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover::effect_batch_tests::OwnedSegment",
    frame = "fastpq_prover::compact_v1::ExecutionEffectSegmentContextV1"
)]
struct OwnedSegment {
    version: u16,
    segment_count: u32,
    ordinal: u32,
    batch_context: Vec<u8>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover::effect_batch_tests::OrdinaryBatch",
    frame = "fastpq_prover::compact_v1::OrdinaryTransferBatchContextV1"
)]
struct OrdinaryBatch;
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover::effect_batch_tests::OrdinarySegment",
    frame = "fastpq_prover::compact_v1::OrdinaryTransferSegmentContextV1"
)]
struct OrdinarySegment;

#[test]
fn borrowed_owned_canonical_frames_and_distinct_domains_match_exactly() {
    let (source, statement, roots) = fixture();
    let view = SourceExecutionEffectStatement::from_owned(&statement);
    assert_eq!(view.public_inputs(), statement.public_inputs);
    assert_eq!(view.ordering_hash(), statement.ordering_hash);
    assert!(std::ptr::eq(view.effects(), &statement.effects));
    assert_eq!(
        view.digest(ExecutionEffectLimits::default().max_public_bytes)
            .unwrap(),
        expected(&statement).unwrap().statement_digest
    );
    let bound = batch(&source, &statement, &roots);
    let owned = OwnedBatch {
        version: 1,
        segment_count: 5,
        source,
        statement: statement.clone(),
        intermediate_roots: roots,
    };
    for flags in [0, norito::core::header_flags::COMPACT_LEN] {
        let _flags = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(
            norito::encode_canonical(&view).unwrap(),
            norito::encode_canonical(&statement).unwrap()
        );
        assert_eq!(
            bound.context.as_slice(),
            norito::encode_canonical(&owned).unwrap()
        );
        for ordinal in 0..5 {
            let segment = OwnedSegment {
                version: 1,
                segment_count: 5,
                ordinal: u32::try_from(ordinal).unwrap(),
                batch_context: bound.context.as_slice().to_vec(),
            };
            assert_eq!(
                bound.segment_context(ordinal).unwrap(),
                norito::encode_canonical(&segment).unwrap()
            );
        }
    }
    let [whole, segment] = context_frame_hashes();
    assert_eq!(whole, norito::schema::identity::frame_hash::<OwnedBatch>());
    assert_eq!(
        segment,
        norito::schema::identity::frame_hash::<OwnedSegment>()
    );
    assert_ne!(whole, segment);
    assert_ne!(
        whole,
        norito::schema::identity::frame_hash::<OrdinaryBatch>()
    );
    assert_ne!(
        segment,
        norito::schema::identity::frame_hash::<OrdinarySegment>()
    );
}

#[test]
fn mixed_effects_preserve_repeated_key_ports_root_chain_and_fixed_air_geometry() {
    let (source, statement, roots) = fixture();
    let batch = batch(&source, &statement, &roots);
    assert_eq!(batch.statements().len(), 5);
    assert_eq!(statement.transitions.len(), 10);
    let paths: Vec<_> = batch
        .statements()
        .iter()
        .map(|port| port.updates.map(|update| update.path))
        .collect();
    let alice = paths[0][0];
    let bob = paths[0][1];
    let supply = paths[1][1];
    let lifecycle = paths[4][1];
    assert_eq!(
        paths,
        [
            [alice, bob],
            [alice, supply],
            [bob, alice],
            [alice, supply],
            [supply, lifecycle]
        ]
    );
    let mut unique = [alice, bob, supply, lifecycle];
    unique.sort_unstable();
    assert!(unique.windows(2).all(|pair| pair[0] != pair[1]));
    let mut total = 0;
    let mut maximum = 0;
    for ordinal in 0..5 {
        let port = &batch.statements()[ordinal];
        assert_eq!(
            port.old_root,
            root_limbs(if ordinal == 0 {
                statement.public_inputs.old_root
            } else {
                roots[ordinal - 1]
            })
        );
        assert_eq!(
            port.new_root,
            root_limbs(if ordinal == 4 {
                statement.public_inputs.new_root
            } else {
                roots[ordinal]
            })
        );
        let air = batch.segment(ordinal).unwrap();
        assert_eq!(
            air.schema(),
            FixedAirSchema {
                identity: IDENTITY,
                trace_rows: 65_536,
                width: 342,
                constraints: 923
            }
        );
        let ordinary = CompactTransferAir::new(port, None).unwrap();
        assert_ne!(air.schema().identity, ordinary.schema().identity);
        assert_ne!(air.statement_bytes(), ordinary.statement_bytes());
        let bytes = air.statement_bytes().len();
        assert_eq!(
            bytes,
            CompactTransferAir::encoded_statement_len(
                port,
                Some(&batch.segment_context(ordinal).unwrap())
            )
            .unwrap()
        );
        total += bytes;
        maximum = maximum.max(bytes);
        if ordinal != 0 {
            assert_ne!(
                batch.segment_context(ordinal - 1).unwrap(),
                batch.segment_context(ordinal).unwrap()
            );
        }
    }
    assert_eq!(batch.total_statement_bytes(), total);
    assert_eq!(batch.max_statement_bytes(), maximum);
    assert!(matches!(
        batch.segment(5),
        Err(Error::QueryIndexOutOfRange { index: 5, len: 5 })
    ));
    assert!(matches!(
        batch.segment_context(usize::MAX),
        Err(Error::QueryIndexOutOfRange { .. })
    ));
}

#[test]
fn independent_source_and_expectation_mutants_refuse_before_preparation_credit() {
    let (source, statement, roots) = fixture();
    let bytes = demand(&source, &statement, &roots);
    let view = SourceExecutionEffectStatement::from_owned(&statement);
    for mutation in 0..14 {
        let mut changed = source;
        match mutation {
            0 => {
                changed.source.network_id = NetworkId::from_genesis_hash(
                    HashOf::from_untyped_unchecked(Hash::new(b"other network")),
                )
            }
            1 => changed.source.height += 1,
            2 => changed.entry_hash = Hash::new(b"other entry"),
            3 => changed.execution_kind = FastpqSourceExecutionKindV1::ProtocolPurpose,
            4 => {
                changed.route = FastpqSourceRouteV1::Lane(FastpqSourceLaneV1 {
                    lane_id: LaneId::new(1),
                    lane_incarnation: Hash::new(b"other lane"),
                })
            }
            5 => changed.dataspace_id = DataSpaceId::new(1),
            6 => changed.effect_count += 1,
            7 => changed.effects_digest = Hash::new(b"other effects").into(),
            8 => changed.slot += 1,
            9 => changed.perm_root = Hash::new(b"other permissions").into(),
            10 => changed.tx_set_hash = Hash::new(b"other transaction set").into(),
            11 => changed.statement_index = changed.entry_index + 1,
            12 => changed.source.height = 0,
            13 => changed.effects_digest = [0; 32],
            _ => unreachable!(),
        }
        let budget = AllocationBudget::new(bytes);
        let mut reservation = budget.try_reserve_bytes(bytes).unwrap();
        assert!(
            ExecutionEffectBatch::new(
                &view,
                &changed,
                expected(&statement).unwrap(),
                &roots,
                limits(),
                &budget,
                &mut reservation
            )
            .is_err(),
            "source mutation {mutation}"
        );
        assert_eq!(
            reservation.remaining_bytes(),
            bytes,
            "source mutation {mutation}"
        );
        drop(reservation);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    for mutation in 0..3 {
        let mut expectation = expected(&statement).unwrap();
        match mutation {
            0 => expectation.statement_digest = Hash::new(b"other statement"),
            1 => expectation.effects_digest = Hash::new(b"other tape"),
            2 => expectation.public_inputs.old_root = Hash::new(b"other root").into(),
            _ => unreachable!(),
        }
        let budget = AllocationBudget::new(bytes);
        let mut reservation = budget.try_reserve_bytes(bytes).unwrap();
        assert!(
            ExecutionEffectBatch::new(
                &view,
                &source,
                expectation,
                &roots,
                limits(),
                &budget,
                &mut reservation
            )
            .is_err()
        );
        assert_eq!(reservation.remaining_bytes(), bytes);
    }
}

#[test]
fn inventory_positions_and_all_root_chain_claims_are_bound_without_invented_authority() {
    let (source, statement, roots) = fixture();
    let original = batch(&source, &statement, &roots);
    // Tape has no inventory indices. Both valid offers are locally preparable;
    // their contexts differ, so an external authenticated opening cannot be reused.
    for mutation in 0..2 {
        let mut changed = source;
        if mutation == 0 {
            changed.statement_index += 1;
        } else {
            changed.entry_index += 1;
        }
        let altered = batch(&changed, &statement, &roots);
        assert_eq!(altered.statements(), original.statements());
        for ordinal in 0..5 {
            assert_ne!(
                altered.segment_context(ordinal).unwrap(),
                original.segment_context(ordinal).unwrap()
            );
        }
    }
    for index in 0..roots.len() {
        let mut changed = roots.clone();
        changed[index] = Hash::new(b"other marked intermediate root").into();
        let altered = batch(&source, &statement, &changed);
        assert_eq!(
            altered.statements()[index].new_root,
            root_limbs(changed[index])
        );
        assert_eq!(
            altered.statements()[index + 1].old_root,
            root_limbs(changed[index])
        );
        // Local context construction is not verification of the claimed private paths.
        for ordinal in 0..5 {
            assert_ne!(
                altered.segment_context(ordinal).unwrap(),
                original.segment_context(ordinal).unwrap()
            );
        }
    }
    for count in [0, 3, 5] {
        let wrong = vec![Hash::new(b"marked root").into(); count];
        assert!(matches!(
            build(&source, &statement, &wrong, limits()),
            Err(Error::TransferInvariant { .. })
        ));
    }
    let mut wrong = roots;
    wrong[0] = [0; 32];
    assert!(build(&source, &statement, &wrong, limits()).is_err());
}

#[test]
fn complete_tape_and_canonical_rows_cannot_be_replaced_by_coherently_rehashed_offers() {
    let (source, statement, roots) = fixture();
    for mutation in 0..7 {
        let mut changed = statement.clone();
        match mutation {
            0 => changed.effects.effects[1].authority_digest = Hash::new(b"substituted authority"),
            1 => {
                changed.effects.effects[1].authorization_context =
                    Hash::new(b"substituted authorization")
            }
            2 => changed.effects.effects[2].ordinal = 1,
            3 => changed.transitions.swap(0, 1),
            4 => changed.ordering_hash = Hash::new(b"other order").into(),
            5 => {
                changed.transitions.pop();
            }
            6 => changed.transitions[0].key.push(0),
            _ => unreachable!(),
        }
        // Statement expectation alone is deliberately recomputed by this test;
        // the independent source effects commitment/canonical row checks remain.
        assert!(
            build(&source, &changed, &roots, limits()).is_err(),
            "statement mutation {mutation}"
        );
    }
    let mut empty = statement;
    empty.effects.effects.clear();
    assert!(matches!(
        build(&source, &empty, &[], limits()),
        Err(Error::TransferInvariant { .. })
    ));
}

#[test]
fn public_and_cumulative_limits_are_inclusive_and_cannot_be_skipped() {
    let (source, statement, roots) = fixture();
    let original = batch(&source, &statement, &roots);
    let exact = EffectBatchLimits {
        context: BatchContextLimits {
            max_segments: 5,
            max_total_statement_bytes: original.total_statement_bytes(),
        },
        ..limits()
    };
    assert_eq!(
        build(&source, &statement, &roots, exact)
            .unwrap()
            .total_statement_bytes(),
        original.total_statement_bytes()
    );
    for mutation in 0..7 {
        let mut low = exact;
        match mutation {
            0 => low.context.max_segments = 4,
            1 => low.context.max_total_statement_bytes -= 1,
            2 => low.public.max_effects = 4,
            3 => low.public.max_rows = 9,
            4 => low.public.max_public_bytes = 0,
            5 => low.public.max_unique_keys = 3,
            6 => low.public.max_allocation_steps = 0,
            _ => unreachable!(),
        }
        assert!(
            matches!(
                build(&source, &statement, &roots, low),
                Err(Error::VerifierLimitExceeded { .. })
            ),
            "limit mutation {mutation}"
        );
    }
    assert!(add(usize::MAX, 1).is_err());
    assert!(mul(usize::MAX, 2).is_err());
    assert!(check("inclusive", 7, 7).is_ok());
    assert!(check("inclusive", 8, 7).is_err());
}

#[test]
fn original_pool_exact_funding_and_output_drop_retain_physical_context_and_ports() {
    let (source, statement, roots) = fixture();
    let bytes = demand(&source, &statement, &roots);
    let view = SourceExecutionEffectStatement::from_owned(&statement);
    let budget = AllocationBudget::new(bytes);
    let foreign = AllocationBudget::new(bytes);
    let mut reservation = foreign.try_reserve_bytes(bytes).unwrap();
    assert!(matches!(
        ExecutionEffectBatch::new(
            &view,
            &source,
            expected(&statement).unwrap(),
            &roots,
            limits(),
            &budget,
            &mut reservation
        ),
        Err(Error::AllocationForeignPool)
    ));
    assert_eq!(reservation.remaining_bytes(), bytes);
    assert_eq!(budget.reserved_bytes(), 0);
    drop(reservation);
    assert_eq!(foreign.reserved_bytes(), 0);
    for available in [0, bytes - 1] {
        let mut reservation = budget.try_reserve_bytes(available).unwrap();
        assert!(
            ExecutionEffectBatch::new(
                &view,
                &source,
                expected(&statement).unwrap(),
                &roots,
                limits(),
                &budget,
                &mut reservation
            )
            .is_err()
        );
        drop(reservation);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    let mut reservation = budget.try_reserve_bytes(bytes).unwrap();
    let batch = ExecutionEffectBatch::new(
        &view,
        &source,
        expected(&statement).unwrap(),
        &roots,
        limits(),
        &budget,
        &mut reservation,
    )
    .unwrap();
    assert_eq!(reservation.remaining_bytes(), 0);
    drop(reservation);
    let retained = batch.context.capacity()
        + Layout::array::<PublicStatement>(batch.statements.capacity())
            .unwrap()
            .size();
    assert_eq!(budget.reserved_bytes(), retained);
    assert!(budget.try_reserve_bytes(bytes).is_err());
    let observer = budget.clone();
    drop(budget);
    assert_eq!(observer.reserved_bytes(), retained);
    assert_eq!(batch.statements().len(), 5);
    drop(batch);
    assert_eq!(observer.reserved_bytes(), 0);
    assert!(observer.try_reserve_bytes(bytes).is_ok());
}

#[test]
fn context_writer_refuses_growth_without_losing_original_charge() {
    let budget = AllocationBudget::new(3);
    let mut reservation = budget.try_reserve_bytes(3).unwrap();
    let mut bytes = ChargedBuffer::from_reservation(3, &mut reservation).unwrap();
    let mut writer = BufferWriter(&mut bytes);
    assert_eq!(writer.write(&[1, 2, 3]).unwrap(), 3);
    assert!(writer.write(&[4]).is_err());
    writer.flush().unwrap();
    assert_eq!(bytes.as_slice(), &[1, 2, 3]);
    assert_eq!(bytes.capacity(), 3);
    drop(reservation);
    assert_eq!(budget.reserved_bytes(), 3);
    drop(bytes);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn caller_raised_public_cap_cannot_allocate_before_fixed_byte_refusal() {
    let (source, mut statement, roots) = fixture();
    let fixed = ExecutionEffectLimits::default();
    statement.transitions[0]
        .key
        .resize(fixed.max_public_bytes + 1, 0);
    // Recompute the test-owned statement expectation so only the fixed public
    // ceiling, rather than a stale digest, causes this early refusal.
    let expectation = expected(&statement).unwrap();
    let raised = EffectBatchLimits {
        public: ExecutionEffectLimits {
            max_effects: usize::MAX,
            max_rows: usize::MAX,
            max_public_bytes: usize::MAX,
            max_unique_keys: usize::MAX,
            max_allocation_steps: usize::MAX,
        },
        context: BatchContextLimits {
            max_segments: usize::MAX,
            max_total_statement_bytes: usize::MAX,
        },
    };
    let budget = AllocationBudget::new(0);
    let mut reservation = budget.try_reserve_bytes(0).unwrap();
    assert!(matches!(
        ExecutionEffectBatch::new(
            &SourceExecutionEffectStatement::from_owned(&statement),
            &source, expectation, &roots, raised, &budget, &mut reservation,
        ),
        Err(Error::VerifierLimitExceeded { limit: "max_execution_effect_bytes", actual, max })
            if actual > fixed.max_public_bytes && max == fixed.max_public_bytes
    ));
    assert_eq!(reservation.remaining_bytes(), 0);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn charged_batch_demand_matches_independent_layouts_and_bounds() {
    let (source, statement, roots) = fixture();
    let view = SourceExecutionEffectStatement::from_owned(&statement);
    let binding = BoundBatchContext {
        version: 1,
        segment_count: 5,
        source: Field(&source),
        statement: Field(&view),
        intermediate_roots: Roots(&roots),
    };
    let independent =
        preparation_allocation_bytes(&statement.effects, ExecutionEffectLimits::default())
            .unwrap()
            .checked_add(Layout::array::<PublicStatement>(5).unwrap().size())
            .unwrap()
            .checked_add(norito::canonical_frame_len(&binding).unwrap())
            .unwrap();
    assert_eq!(
        ExecutionEffectBatch::allocation_bytes(&view, &source, &roots, limits()).unwrap(),
        independent
    );
    let zero = EffectBatchLimits {
        context: BatchContextLimits {
            max_segments: 0,
            ..BatchContextLimits::default()
        },
        ..limits()
    };
    assert!(matches!(
        ExecutionEffectBatch::allocation_bytes(&view, &source, &roots, zero),
        Err(Error::VerifierLimitExceeded { .. })
    ));
    assert!(matches!(
        ExecutionEffectBatch::allocation_bytes(&view, &source, &[], limits()),
        Err(Error::TransferInvariant { .. })
    ));
    let mut changed = source;
    changed.statement_index += 1;
    assert_eq!(
        ExecutionEffectBatch::allocation_bytes(&view, &changed, &roots, limits()).unwrap(),
        independent
    );
    // Sizing is not a replacement for the constructor's independent source validation.
    changed.effect_count += 1;
    assert_eq!(
        ExecutionEffectBatch::allocation_bytes(&view, &changed, &roots, limits()).unwrap(),
        independent
    );
    assert!(build(&changed, &statement, &roots, limits()).is_err());
}
