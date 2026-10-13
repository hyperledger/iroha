//! Finalized source-coordinate checks; these fixtures do not enable AXT admission.

use super::axt_source_transfer::FinalizedAxtSourceTransferErrorV1 as Error;
use super::{State, World};
use crate::kura::tests::CommittedNetworkProofFixture;
use iroha_crypto::Hash;
use iroha_data_model::{
    asset::id::AssetDefinitionId,
    block::SignedBlock,
    fastpq::{FastpqPublicTransferDeltaV1, TransferDeltaTranscript, TransferSmtWitness},
    nexus::{AxtSourceTransferOccurrenceV1, axt_source_transfer_digest_v1},
};
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::Quantity;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use std::sync::Arc;

const MAX_WORK: u64 = 8;
const MAX_BYTES: u64 = 4 * 1024 * 1024;

fn test_delta(from_before: u32, to_before: u32) -> TransferDeltaTranscript {
    TransferDeltaTranscript {
        from_account: (*ALICE_ID).clone(),
        to_account: (*BOB_ID).clone(),
        asset_definition: AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("domain"),
            "rose".parse().expect("asset name"),
        ),
        amount: Quantity::one(),
        from_balance_before: Quantity::from(from_before),
        from_balance_after: Quantity::from(from_before - 1),
        to_balance_before: Quantity::from(to_before),
        to_balance_after: Quantity::from(to_before + 1),
        from_smt_witness: TransferSmtWitness::default(),
        to_smt_witness: TransferSmtWitness::default(),
    }
}

fn finalized_fixture(rejected: bool, retain_transcripts: bool) -> CommittedNetworkProofFixture {
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    use iroha_data_model::{
        account::Account,
        asset::{AssetBalancePolicy, AssetDefinition, id::AssetId},
        domain::Domain,
        isi::{InstructionBox, Log, Mint, Register, TransferAssetBatch, TransferAssetBatchEntry},
    };
    let domain = DomainId::try_new("wonderland", "universal").unwrap();
    let definition = test_delta(10, 0).asset_definition;
    let source = AssetId::new(definition.clone(), (*ALICE_ID).clone());
    let mut config = TestChainConfig::new(World::new(), 1000);
    config.genesis_key = iroha_test_samples::ALICE_KEYPAIR.clone();
    config.genesis_instructions = vec![
        Register::domain(Domain::new(domain.clone())).into(),
        Register::account(Account::new((*BOB_ID).clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            definition.clone(),
            "rose",
            AssetBalancePolicy::Global,
            Some(domain),
        ))
        .into(),
        Mint::asset_quantity(10_u32, source).into(),
    ];
    let mut chain = CertifiedTestChain::start(config).unwrap();
    let instructions: Vec<InstructionBox> = if retain_transcripts || rejected {
        vec![
            TransferAssetBatch::new(vec![
                TransferAssetBatchEntry::with_leg_id(
                    "source-first",
                    (*ALICE_ID).clone(),
                    (*BOB_ID).clone(),
                    definition.clone(),
                    if rejected { 1000_u32 } else { 1_u32 },
                ),
                TransferAssetBatchEntry::with_leg_id(
                    "source-second",
                    (*ALICE_ID).clone(),
                    (*BOB_ID).clone(),
                    definition,
                    1_u32,
                ),
            ])
            .into(),
        ]
    } else {
        vec![
            Log::new(
                iroha_data_model::Level::INFO,
                "no transfer transcript".into(),
            )
            .into(),
        ]
    };
    let tx = chain.sign(&iroha_test_samples::ALICE_KEYPAIR, instructions, 1001);
    assert_eq!(chain.commit(vec![tx]), vec![!rejected]);
    CommittedNetworkProofFixture::from_chain(chain)
}

fn source_state(fixture: &CommittedNetworkProofFixture) -> Arc<State> {
    Arc::clone(&fixture.state)
}

#[test]
fn duplicate_transfer_leg_identity_is_rejected_before_any_finalized_source_mutation() {
    use crate::smartcontracts::Execute as _;
    use iroha_data_model::{
        asset::id::AssetId,
        block::BlockHeader,
        isi::{TransferAssetBatch, TransferAssetBatchEntry},
    };
    use mv::storage::StorageReadOnly as _;
    let fixture = finalized_fixture(false, true);
    let state = source_state(&fixture);
    let definition = test_delta(10, 0).asset_definition;
    let alice = AssetId::new(definition.clone(), ALICE_ID.clone());
    let bob = AssetId::new(definition.clone(), BOB_ID.clone());
    let leg = TransferAssetBatchEntry::new(ALICE_ID.clone(), BOB_ID.clone(), definition, 1_u32);
    let mut block = state.block(BlockHeader::new(
        3.try_into().unwrap(),
        state.view().latest_block_hash(),
        None,
        1003,
        0,
    ));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new(b"duplicate-transfer-leg-control"));
    let alice_before = tx.world.assets.get(&alice).unwrap().as_ref().clone();
    let bob_before = tx.world.assets.get(&bob).unwrap().as_ref().clone();
    let error = TransferAssetBatch::new(vec![leg.clone(), leg])
        .execute(&ALICE_ID, &mut tx)
        .expect_err("identical leg IDs must not acquire two source occurrences");
    assert!(error.to_string().contains("duplicate leg_id"));
    assert_eq!(tx.world.assets.get(&alice).unwrap().as_ref(), &alice_before);
    assert_eq!(tx.world.assets.get(&bob).unwrap().as_ref(), &bob_before);
}

fn source_claim(block: &SignedBlock) -> AxtSourceTransferOccurrenceV1 {
    let source = block.network_entrypoint_at(0).expect("source input");
    let source_hash = Hash::from(source.execution_call_hash());
    let delta = block
        .fastpq_transcripts()
        .get(&source_hash)
        .and_then(|rows| rows.first())
        .and_then(|row| row.deltas.get(1))
        .cloned()
        .unwrap_or_else(|| test_delta(9, 1));
    AxtSourceTransferOccurrenceV1 {
        source_tx_commitment: source_hash.into(),
        source_success_receipt_digest: [0x71; 32],
        source_tx_index: 0,
        transcript_index: 0,
        delta_index: 1,
        pair_ordinal: 1,
        transfer_digest: axt_source_transfer_digest_v1(&FastpqPublicTransferDeltaV1::from(&delta)),
        remote_spend_claim_commitment: [0x72; 32],
    }
}

#[test]
fn finalized_source_resolver_confirms_success_and_one_exact_transfer() {
    let fixture = finalized_fixture(false, true);
    let state = source_state(&fixture);
    let claim = source_claim(fixture.target());
    let fact = state
        .resolve_finalized_axt_source_transfer_v1(2, &claim, MAX_WORK, MAX_BYTES)
        .expect("QC-bound successful source and exact second delta");
    assert_eq!(fact.height, 2);
    assert_eq!(fact.block_header_hash, fixture.target().hash());
    assert_eq!(fact.source_tx_commitment, claim.source_tx_commitment);
    assert_eq!(fact.source_tx_index, 0);
    assert_eq!(
        (fact.transcript_index, fact.delta_index, fact.pair_ordinal),
        (0, 1, 1)
    );
    assert_eq!(fact.transfer_digest, claim.transfer_digest);
    let unverified = AxtSourceTransferOccurrenceV1 {
        source_success_receipt_digest: [0x75; 32],
        remote_spend_claim_commitment: [0x76; 32],
        ..claim
    };
    assert_eq!(
        (state.resolve_finalized_axt_source_transfer_v1(2, &unverified, MAX_WORK, MAX_BYTES))
            .expect("completed successful fixture"),
        fact,
        "receipt and handle claims require separate authority checks"
    );

    for (changed, expected) in [
        (
            AxtSourceTransferOccurrenceV1 {
                source_tx_commitment: [0x73; 32],
                ..claim
            },
            Error::SourceExecution,
        ),
        (
            AxtSourceTransferOccurrenceV1 {
                source_tx_index: 1,
                ..claim
            },
            Error::SourceExecution,
        ),
        (
            AxtSourceTransferOccurrenceV1 {
                transcript_index: 1,
                ..claim
            },
            Error::TransferCoordinate,
        ),
        (
            AxtSourceTransferOccurrenceV1 {
                delta_index: 0,
                ..claim
            },
            Error::TransferCoordinate,
        ),
        (
            AxtSourceTransferOccurrenceV1 {
                pair_ordinal: 0,
                ..claim
            },
            Error::TransferCoordinate,
        ),
        (
            AxtSourceTransferOccurrenceV1 {
                transfer_digest: [0x74; 32],
                ..claim
            },
            Error::TransferFacts,
        ),
    ] {
        assert!(matches!(
            (
                state.resolve_finalized_axt_source_transfer_v1(2, &changed, MAX_WORK, MAX_BYTES),
                expected
            ),
            (Err(Error::SourceExecution), Error::SourceExecution)
                | (Err(Error::TransferCoordinate), Error::TransferCoordinate)
                | (Err(Error::TransferFacts), Error::TransferFacts)
        ));
    }
    assert!(matches!(
        state.resolve_finalized_axt_source_transfer_v1(2, &claim, 0, MAX_BYTES),
        Err(Error::FinalizedCarrier)
    ));
    assert!(matches!(
        state.resolve_finalized_axt_source_transfer_v1(0, &claim, MAX_WORK, MAX_BYTES),
        Err(Error::InvalidClaim)
    ));
    assert!(matches!(
        state.resolve_finalized_axt_source_transfer_v1(3, &claim, MAX_WORK, MAX_BYTES),
        Err(Error::FinalizedCarrier)
    ));
}

#[test]
fn finalized_source_resolver_rejects_rejected_or_missing_source_evidence() {
    let rejected = finalized_fixture(true, false);
    let rejected_state = source_state(&rejected);
    let claim = source_claim(rejected.target());
    assert!(matches!(
        rejected_state.resolve_finalized_axt_source_transfer_v1(2, &claim, MAX_WORK, MAX_BYTES),
        Err(Error::RejectedExecution)
    ));

    let missing = finalized_fixture(false, false);
    let missing_state = source_state(&missing);
    let claim = source_claim(missing.target());
    assert!(matches!(
        missing_state.resolve_finalized_axt_source_transfer_v1(2, &claim, MAX_WORK, MAX_BYTES),
        Err(Error::MissingTranscripts)
    ));
}

#[test]
fn finalized_source_resolver_requires_canonical_qc_bound_body() {
    let fixture = finalized_fixture(false, true);
    let state = source_state(&fixture);
    let claim = source_claim(fixture.target());
    fixture.make_target_cold();
    let mut wire = fixture.target_disk_bytes();
    let last = wire.len() - 1;
    wire[last] ^= 1;
    fixture.overwrite_target_wire(&wire);
    assert!(matches!(
        state.resolve_finalized_axt_source_transfer_v1(2, &claim, MAX_WORK, MAX_BYTES),
        Err(Error::FinalizedCarrier)
    ));
}

#[test]
fn finalized_source_capacity_refusal_retains_original_owner_and_exact_claim() {
    use iroha_allocation::AllocationRefusal;
    use std::{
        future::Future as _,
        num::NonZeroUsize,
        task::{Context, Poll, Waker},
    };

    let fixture = finalized_fixture(false, true);
    let state = source_state(&fixture);
    let claim = source_claim(fixture.target());
    let expected = state
        .resolve_finalized_axt_source_transfer_v1(2, &claim, MAX_WORK, MAX_BYTES)
        .expect("original exact finalized source");
    state
        .kura()
        .forget_cached_block_for_testing(NonZeroUsize::new(2).unwrap())
        .expect("durable source remains for cold retry");
    let budget = state.ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let retained = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let refusal = state
        .resolve_finalized_axt_source_transfer_v1(2, &claim, MAX_WORK, MAX_BYTES)
        .expect_err("original source pool occupied");
    let Error::Deferred(original) = refusal else {
        panic!("source capacity must remain an unfinished read: {refusal:?}");
    };
    let Some(AllocationRefusal::Capacity { release, .. }) = original.allocation_refusal() else {
        panic!("source read lost the original capacity owner");
    };
    let mut retry = std::pin::pin!(release.clone().wait_for_release(&mut registration));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(retry.as_mut().poll(&mut context), Poll::Pending));
    drop(retained);
    assert!(matches!(retry.as_mut().poll(&mut context), Poll::Ready(_)));
    assert_eq!(
        state
            .resolve_finalized_axt_source_transfer_v1(2, &claim, MAX_WORK, MAX_BYTES)
            .unwrap(),
        expected
    );
}
