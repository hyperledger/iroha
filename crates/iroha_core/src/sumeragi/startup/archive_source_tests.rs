//! Genesis archive authority stays bound to actual independently executed source owners.

use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, PreparedTestChainConfig, TestChainConfig},
};
use iroha_allocation::RetainedPayload;
use iroha_data_model::{
    block::consensus::SumeragiRootScope,
    sumeragi_finality::{CertifiedResultV1, NativeLaneStateProof},
};

struct ExecutedSource<'state> {
    valid: ValidBlock,
    overlay: Box<StateBlock<'state>>,
    result: RetainedPayload<CertifiedResultV1>,
    scope: SumeragiRootScope,
}

// Keep fixture construction and genuine execution in separate frames, as production does.
#[inline(never)]
fn prepared(time_ms: u64) -> PreparedTestChainConfig {
    CertifiedTestChain::prepare(TestChainConfig::new(World::new(), time_ms)).unwrap()
}

#[inline(never)]
fn execute(prepared: &PreparedTestChainConfig) -> Box<ExecutedSource<'_>> {
    let genesis = prepared.genesis.block().clone();
    let (epoch, scope) = super::super::epoch::authenticated_genesis(&genesis)
        .unwrap()
        .into_parts();
    let topology = Topology::new(genesis_committee_peers(&genesis).unwrap());
    let account = AccountId::new(prepared.genesis.public_key().clone());
    let (valid, mut overlay) = ValidBlock::validate_signed_genesis(
        genesis,
        &topology,
        &account,
        &TimeSource::new_system(),
        &prepared.state,
        prepared.genesis.consensus_metadata().mode.into(),
        scope,
    )
    .unpack(|_| {})
    .unwrap();
    let inputs = overlay.take_sumeragi_execution_inputs().unwrap();
    assert_eq!(inputs.get().schedule.current, epoch);
    assert!(inputs.get().schedule.boundary.is_none());
    assert!(inputs.get().beacon.is_none());
    overlay.take_sumeragi_lanes().unwrap();
    let mut witness = overlay.take_exec_witness().unwrap();
    let lanes =
        NativeLaneStateProof::from_witness(&witness, &prepared.state.ivm_execution_budget())
            .unwrap();
    let transition = overlay.world_state_transition().unwrap();
    let header = overlay.sealed_sccp_finality_header(valid.as_ref()).unwrap();
    let result = execution_result(
        &mut witness,
        valid.as_ref(),
        &transition,
        inputs,
        lanes,
        header,
        scope.into(),
    )
    .unwrap();
    Box::new(ExecutedSource {
        valid,
        overlay,
        result,
        scope,
    })
}

fn authorization<'execution, 'state>(
    source: &'execution ExecutedSource<'state>,
    state: &State,
) -> GenesisExecutionAuthorization<'execution, 'state> {
    // These private test fields come only from actual signed-genesis execution above.
    // The capability never escapes this child module or authorizes State publication.
    GenesisExecutionAuthorization {
        original_overlay: &source.overlay,
        original_result: &source.result,
        state: std::ptr::from_ref(state) as usize,
        tip: crate::state::native_execution_tip::NativeExecutionTipRecord {
            root_scope: source.scope,
            height: GENESIS_HEIGHT,
            creation_time_ms: u64::try_from(
                source.valid.as_ref().header().creation_time().as_millis(),
            )
            .unwrap(),
            iroha_hash: source.valid.as_ref().hash(),
            core_hash: core_hash_of(source.valid.as_ref()).0,
            result: source.result.get().result().unwrap().0,
        },
        telemetry_origin: super::super::executor::CommitTelemetryOrigin::Forward,
    }
}

#[test]
fn genesis_archive_authorization_rejects_every_substituted_source_owner() {
    let first = prepared(1_000);
    let equivalent = prepared(1_000);
    let foreign = prepared(2_000);
    assert_eq!(
        first.genesis.canonical_wire(),
        equivalent.genesis.canonical_wire()
    );
    assert_ne!(
        first.genesis.expected_hash(),
        foreign.genesis.expected_hash()
    );
    let first_source = execute(&first);
    let equivalent_source = execute(&equivalent);
    let foreign_source = execute(&foreign);
    let original = authorization(&first_source, &first.state);
    let block = first_source.valid.as_ref();
    assert!(first_source.overlay.native_execution_tip().is_none());
    assert_eq!(
        original.original_archive_scope(&first_source.overlay, block, &first_source.result),
        Some(first_source.scope)
    );
    // Equal canonical values in a separately funded original execution are still
    // a different retained owner, even when both signed genesis frames agree.
    assert_eq!(first_source.result.get(), equivalent_source.result.get());
    assert!(!std::ptr::eq(
        &first_source.result,
        &equivalent_source.result
    ));
    assert_eq!(
        original.original_archive_scope(&first_source.overlay, block, &equivalent_source.result),
        None
    );
    assert_eq!(
        original.original_archive_scope(&equivalent_source.overlay, block, &first_source.result),
        None
    );
    assert_eq!(
        original.original_archive_scope(&foreign_source.overlay, block, &first_source.result),
        None
    );
    let mut changed_height = block.clone();
    let mut header = changed_height.header();
    header.set_height(2_u64.try_into().unwrap());
    changed_height.replace_header_for_testing(header);
    assert_eq!(
        original.original_archive_scope(
            &first_source.overlay,
            &changed_height,
            &first_source.result
        ),
        None
    );
    let mut changed_hash = block.clone();
    let mut header = changed_hash.header();
    header.creation_time_ms += 1;
    changed_hash.replace_header_for_testing(header);
    assert_eq!(changed_hash.header().height().get(), GENESIS_HEIGHT);
    assert_ne!(changed_hash.hash(), block.hash());
    assert_eq!(
        original.original_archive_scope(&first_source.overlay, &changed_hash, &first_source.result),
        None
    );
    // Each refusal leaves the actual source usable and unpublished.
    assert_eq!(
        original.original_archive_scope(&first_source.overlay, block, &first_source.result),
        Some(first_source.scope)
    );
    assert_eq!(first.state.view().height(), 0);
    assert_eq!(first.kura.blocks_count(), 0);
}

#[inline(never)]
fn committed() -> CertifiedTestChain {
    CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap()
}

#[test]
fn genesis_archive_authorization_rejects_an_actual_predecessor_tip() {
    let prepared = prepared(1_000);
    let source = execute(&prepared);
    let committed = committed();
    let mut header = committed.genesis().header();
    header.set_height(2_u64.try_into().unwrap());
    header.set_prev_block_hash(Some(committed.genesis().hash()));
    let predecessor = Box::new(committed.state().block(header));
    assert!(predecessor.native_execution_tip().is_some());
    let original = authorization(&source, &prepared.state);
    // Rebind only inside this private test to isolate predecessor absence from
    // pointer identity: all other predicates match an actual executed source.
    // No production caller can construct or modify this authorization.
    let bound_to_predecessor = GenesisExecutionAuthorization {
        original_overlay: &predecessor,
        ..original
    };
    assert_eq!(
        bound_to_predecessor.original_archive_scope(
            &predecessor,
            source.valid.as_ref(),
            &source.result
        ),
        None
    );
    assert_eq!(committed.state().view().height(), 1);
    assert_eq!(committed.kura().blocks_count(), 1);
}
