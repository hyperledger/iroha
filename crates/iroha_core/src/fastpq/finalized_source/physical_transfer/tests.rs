//! Actual certified Network/Time source selection and original borrowed custody controls.

use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, Signers, TestChainConfig},
};
use iroha_data_model::{
    block::execution_output::ExecutionOutputV1,
    events::time::{ExecutionTime, TimeEventFilter},
    fastpq::FastpqSourceRouteV1,
    prelude::*,
};
use iroha_model_base::domain::DomainId;
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID};

fn source(
    network_transfers: &[&[u32]],
    time_transfer: bool,
) -> (CertifiedTestChain, FinalizedFastpqSource) {
    let domain = DomainId::try_new("wonderland", "universal").unwrap();
    let definition =
        AssetDefinitionId::derive_from_components(domain.clone(), "source_fact".parse().unwrap());
    let asset = AssetId::new(definition.clone(), ALICE_ID.clone());
    let world = World::with_assets(
        [Domain::new(domain).build(&ALICE_ID)],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&ALICE_ID),
        ],
        [AssetDefinition::new(
            definition.clone(),
            "physical transfer".to_owned(),
            NumericSpec::default(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID)],
        [
            Asset::new(asset.clone(), Quantity::from(100_u32)),
            Asset::new(AssetId::new(definition, BOB_ID.clone()), Quantity::zero()),
        ],
        [],
    );
    let mut config = TestChainConfig::new(world, 1_000);
    if time_transfer {
        // Registered by the actual signed genesis and executed by the original
        // successor producer. No synthetic typed output or source leaf is injected.
        config.genesis_instructions.push(
            Register::trigger(Trigger::new(
                "source_fact_time".parse().unwrap(),
                Action::new(
                    vec![InstructionBox::from(Transfer::asset_quantity(
                        asset.clone(),
                        1_u32,
                        BOB_ID.clone(),
                    ))],
                    Repeats::Indefinitely,
                    ALICE_ID.clone(),
                    TimeEventFilter::new(ExecutionTime::PreCommit),
                )
                .unwrap(),
            ))
            .into(),
        );
    }
    let mut chain = CertifiedTestChain::start(config).unwrap();
    let created_ms = chain.committed(1).block_time_ms();
    let transactions = network_transfers
        .iter()
        .map(|amounts| {
            let instructions: Vec<InstructionBox> = if amounts.is_empty() {
                vec![
                    Log::new(
                        Level::INFO,
                        "physical transfer without quantity effects".into(),
                    )
                    .into(),
                ]
            } else {
                amounts
                    .iter()
                    .map(|amount| {
                        Transfer::asset_quantity(asset.clone(), *amount, BOB_ID.clone()).into()
                    })
                    .collect()
            };
            chain.sign(&ALICE_KEYPAIR, instructions, created_ms)
        })
        .collect();
    let proposal = chain.proposal(None, transactions);
    let mut pending = chain.begin_proposal(proposal, Default::default()).unwrap();
    pending.prepare(Signers::Quorum).unwrap();
    pending.publish(Signers::Quorum).unwrap();
    let original = pending.take_finalized_fastpq_source().unwrap();
    drop(pending);
    (chain, original)
}

fn location(source: &FinalizedFastpqSource, network_index: u32) -> PhysicalTransferLocation {
    let call = Hash::from(
        source
            .native()
            .block()
            .network_entrypoint_at(network_index as usize)
            .unwrap()
            .execution_call_hash(),
    );
    let entry_index = source
        .entries()
        .iter()
        .position(|entry| entry.entry_hash == call)
        .unwrap();
    let entry = &source.entries()[entry_index];
    let statement_index = source
        .leaves()
        .iter()
        .position(|leaf| leaf.entry_index as usize == entry_index)
        .unwrap();
    PhysicalTransferLocation {
        source_call: entry.entry_hash,
        network_index,
        entry_index: entry_index.try_into().unwrap(),
        statement_index: statement_index.try_into().unwrap(),
        transcript_index: 0,
        delta_index: 0,
        pair_ordinal: 0,
    }
}

fn limits(
    source: &FinalizedFastpqSource,
    location: PhysicalTransferLocation,
) -> PhysicalTransferScan {
    let bundle = &source.native().block().fastpq_transcripts()[&location.source_call];
    PhysicalTransferScan {
        max_source_entries: source.entries().len().try_into().unwrap(),
        max_transcripts: bundle.len().try_into().unwrap(),
        max_deltas: bundle
            .iter()
            .map(|transcript| transcript.deltas.len())
            .sum::<usize>()
            .try_into()
            .unwrap(),
    }
}

fn rejection(
    result: Result<PhysicalTransfer<'_>, PhysicalTransferError>,
) -> PhysicalTransferMismatch {
    match result {
        Err(PhysicalTransferError::Rejected(error)) => error,
        Err(other) => panic!("expected completed source rejection, got {other}"),
        Ok(_) => panic!("invalid selection returned a physical transfer"),
    }
}

#[test]
fn physical_transfer_joins_actual_native_d7_success_and_every_physical_transfer() {
    let _epoch = crossbeam_epoch::pin();
    let (_chain, original) = source(&[&[3, 5], &[7]], false);
    let baseline = original.pool().reserved_bytes();
    let materializations = crate::fastpq::quantity_materializer_invocations_for_testing();
    for network_index in 0..2 {
        let mut location = location(&original, network_index);
        let limits = limits(&original, location);
        let bundle = &original.native().block().fastpq_transcripts()[&location.source_call];
        let mut pair = 0;
        for (transcript_index, transcript) in bundle.iter().enumerate() {
            for (delta_index, delta) in transcript.deltas.iter().enumerate() {
                location.transcript_index = transcript_index.try_into().unwrap();
                location.delta_index = delta_index.try_into().unwrap();
                location.pair_ordinal = pair;
                let fact = original.physical_transfer(location, limits).unwrap();
                assert!(std::ptr::eq(fact.original(), &original));
                assert!(std::ptr::eq(
                    fact.input(),
                    original
                        .native()
                        .block()
                        .network_entrypoint_at(network_index as usize)
                        .unwrap()
                ));
                assert_eq!(
                    Hash::from(fact.input().execution_call_hash()),
                    location.source_call
                );
                assert!(std::ptr::eq(
                    fact.source_entry(),
                    &original.entries()[network_index as usize]
                ));
                assert!(std::ptr::eq(
                    fact.statement(),
                    &original.leaves()[location.statement_index as usize]
                ));
                assert!(std::ptr::eq(
                    fact.output(),
                    original
                        .native()
                        .block()
                        .network_output_at(network_index)
                        .unwrap()
                        .1
                ));
                assert!(std::ptr::eq(fact.transcript(), transcript));
                assert!(std::ptr::eq(fact.delta(), delta));
                assert!(fact.output().result.is_ok());
                assert_eq!(fact.location(), location);
                assert_eq!(
                    Hash::from(fact.original().native().committed().id().0),
                    original.native().committed().id().0.into()
                );
                assert_eq!(
                    fact.original().native().committed().result().0,
                    original.native().committed().result().0
                );
                assert_eq!(
                    fact.original()
                        .native()
                        .committed()
                        .commitment()
                        .execution
                        .ordinary_writes_root,
                    original
                        .native()
                        .committed()
                        .commitment()
                        .execution
                        .ordinary_writes_root
                );
                assert_eq!(
                    fact.original()
                        .native()
                        .committed()
                        .header()
                        .map(|header| header.availability_digest.0),
                    Some(
                        original
                            .native()
                            .committed()
                            .header()
                            .unwrap()
                            .availability_digest
                            .0
                    )
                );
                assert_eq!(
                    fact.statement().effects_digest,
                    original.leaves()[location.statement_index as usize].effects_digest
                );
                let expected_amount = if network_index == 0 {
                    [3_u32, 5][pair as usize]
                } else {
                    7
                };
                assert_eq!(fact.delta().amount, Quantity::from(expected_amount));
                assert_eq!(
                    fact.statement().effect_count,
                    if network_index == 0 { 2 } else { 1 }
                );
                assert!(matches!(
                    fact.statement().route,
                    FastpqSourceRouteV1::Lane(_)
                ));
                pair += 1;
            }
        }
        assert!(pair > 0);
    }
    assert_eq!(original.pool().reserved_bytes(), baseline);
    assert_eq!(
        crate::fastpq::quantity_materializer_invocations_for_testing(),
        materializations
    );
}

#[test]
fn physical_transfer_refuses_cross_entry_and_mismatched_occurrence_locations() {
    let (_chain, original) = source(&[&[3, 5], &[7]], false);
    let good = location(&original, 0);
    let limits = limits(&original, good);
    for (bad, expected) in [
        (
            PhysicalTransferLocation {
                source_call: Hash::new(b"other call"),
                ..good
            },
            PhysicalTransferMismatch::SourceCall,
        ),
        (
            PhysicalTransferLocation {
                network_index: 1,
                ..good
            },
            PhysicalTransferMismatch::SourceCall,
        ),
        (
            PhysicalTransferLocation {
                entry_index: 1,
                ..good
            },
            PhysicalTransferMismatch::SourceCall,
        ),
        (
            PhysicalTransferLocation {
                entry_index: u32::MAX,
                ..good
            },
            PhysicalTransferMismatch::SourceCall,
        ),
        (
            PhysicalTransferLocation {
                statement_index: 1,
                ..good
            },
            PhysicalTransferMismatch::Statement,
        ),
        (
            PhysicalTransferLocation {
                statement_index: u32::MAX,
                ..good
            },
            PhysicalTransferMismatch::Statement,
        ),
        (
            PhysicalTransferLocation {
                transcript_index: u32::MAX,
                ..good
            },
            PhysicalTransferMismatch::Coordinate,
        ),
        (
            PhysicalTransferLocation {
                delta_index: u32::MAX,
                ..good
            },
            PhysicalTransferMismatch::Coordinate,
        ),
        (
            PhysicalTransferLocation {
                pair_ordinal: 1,
                ..good
            },
            PhysicalTransferMismatch::Coordinate,
        ),
    ] {
        assert_eq!(rejection(original.physical_transfer(bad, limits)), expected);
        assert!(original.physical_transfer(good, limits).is_ok());
    }
}

#[test]
fn physical_transfer_retains_exact_local_work_refusal_and_retries_original() {
    let _epoch = crossbeam_epoch::pin();
    let (_chain, original) = source(&[&[3, 5]], false);
    let location = location(&original, 0);
    let enough = limits(&original, location);
    let baseline = original.pool().reserved_bytes();
    for (work, observed, limits) in [
        (
            PhysicalTransferWork::SourceEntries,
            enough.max_source_entries,
            PhysicalTransferScan {
                max_source_entries: enough.max_source_entries - 1,
                ..enough
            },
        ),
        (
            PhysicalTransferWork::Transcripts,
            enough.max_transcripts,
            PhysicalTransferScan {
                max_transcripts: enough.max_transcripts - 1,
                ..enough
            },
        ),
        (
            PhysicalTransferWork::Deltas,
            enough.max_deltas,
            PhysicalTransferScan {
                max_deltas: enough.max_deltas - 1,
                ..enough
            },
        ),
    ] {
        let error = match original.physical_transfer(location, limits) {
            Err(PhysicalTransferError::Refused(error)) => error,
            Err(other) => panic!("expected local work refusal, got {other}"),
            Ok(_) => panic!("one-less finite allowance succeeded"),
        };
        assert_eq!(
            error,
            PhysicalTransferRefusal {
                work,
                limit: observed - 1,
                observed: observed as usize
            }
        );
        assert_eq!(original.pool().reserved_bytes(), baseline);
        let retry = original.physical_transfer(location, enough).unwrap();
        assert!(std::ptr::eq(retry.original(), &original));
        assert_eq!(retry.location(), location);
        assert_eq!(original.pool().reserved_bytes(), baseline);
    }
}

#[test]
fn physical_transfer_rejects_actual_failed_network_output_before_statement_selection() {
    let (_chain, original) = source(&[&[1000], &[3]], false);
    assert!(
        original
            .native()
            .block()
            .network_output_at(0)
            .unwrap()
            .1
            .result
            .is_err()
    );
    let mut selected = location(&original, 1);
    selected.source_call = original.entries()[0].entry_hash;
    selected.network_index = 0;
    selected.entry_index = 0;
    // The valid leaf belongs to a different, successful Network call. It cannot
    // turn this actual rejected output into success even if fee effects are present.
    let enough = PhysicalTransferScan {
        max_source_entries: original.entries().len().try_into().unwrap(),
        max_transcripts: 10,
        max_deltas: 10,
    };
    assert_eq!(
        rejection(original.physical_transfer(selected, enough)),
        PhysicalTransferMismatch::RejectedExecution
    );
    assert!(
        original
            .physical_transfer(location(&original, 1), enough)
            .is_ok()
    );
}

#[test]
fn physical_transfer_rejects_actual_time_execution_as_a_network_source() {
    let (_chain, original) = source(&[&[3]], true);
    let block = original.native().block();
    let output = block
        .execution_outputs()
        .iter()
        .find(|row| matches!(row, ExecutionOutputV1::Time(_)))
        .expect("real successor Time output");
    assert!(output.result().is_ok());
    let call = output
        .execution_call_hash(block.hash(), block.as_ref())
        .unwrap();
    let (statement_index, leaf) = original
        .leaves()
        .iter()
        .enumerate()
        .find(|(_, leaf)| leaf.entry_hash == call)
        .expect("real Time quantity source");
    assert_eq!(
        leaf.execution_kind,
        FastpqSourceExecutionKindV1::ExecutionCall
    );
    assert!(leaf.entry_index as usize >= block.network_entrypoint_count());
    let selected = PhysicalTransferLocation {
        source_call: call,
        network_index: leaf.entry_index,
        entry_index: leaf.entry_index,
        statement_index: statement_index.try_into().unwrap(),
        transcript_index: 0,
        delta_index: 0,
        pair_ordinal: 0,
    };
    let enough = limits(&original, selected);
    assert_eq!(
        rejection(original.physical_transfer(selected, enough)),
        PhysicalTransferMismatch::NonNetworkSource
    );
    assert!(
        original
            .physical_transfer(location(&original, 0), enough)
            .is_ok()
    );
}

#[test]
fn physical_transfer_needs_no_optional_archive_or_fresh_allocation_capacity() {
    let _epoch = crossbeam_epoch::pin();
    let (_chain, mut original) = source(&[&[3]], false);
    let location = location(&original, 0);
    let enough = limits(&original, location);
    original.withhold_optional_archive_for_test(crate::state::QuantityCaptureIssue::Capacity);
    assert!(matches!(
        original.entry(0),
        Err(crate::state::QuantityCaptureIssue::Capacity)
    ));
    let pool = original.pool().clone();
    let remaining = pool.limit_bytes() - pool.reserved_bytes();
    let blocker = pool.try_reserve_bytes(remaining).unwrap();
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    let fact = original.physical_transfer(location, enough).unwrap();
    assert!(std::ptr::eq(fact.original(), &original));
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    drop(fact);
    drop(blocker);
    assert!(original.physical_transfer(location, enough).is_ok());
}

#[test]
fn physical_transfer_has_no_statement_for_actual_success_without_quantity_effects() {
    let (_chain, original) = source(&[&[], &[3]], false);
    assert!(
        original
            .native()
            .block()
            .network_output_at(0)
            .unwrap()
            .1
            .result
            .is_ok()
    );
    let mut selected = location(&original, 1);
    selected.source_call = original.entries()[0].entry_hash;
    selected.network_index = 0;
    selected.entry_index = 0;
    let enough = limits(&original, location(&original, 1));
    assert_eq!(
        rejection(original.physical_transfer(selected, enough)),
        PhysicalTransferMismatch::Statement
    );
    let valid = location(&original, 1);
    assert_ne!(valid.statement_index, valid.entry_index);
    let fact = original.physical_transfer(valid, enough).unwrap();
    assert_eq!(fact.statement().entry_index, valid.entry_index);
    assert_eq!(fact.statement().statement_index, valid.statement_index);
    assert_eq!(fact.delta().amount, Quantity::from(3_u32));
}
