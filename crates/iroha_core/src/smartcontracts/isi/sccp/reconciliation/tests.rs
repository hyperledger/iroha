//! Reconciliation window boundaries and authenticated finalized-event binding.

use super::*;
use crate::smartcontracts::isi::sccp::test_support::{blank_state, header, sample_route};
use iroha_data_model::sccp::{native::SccpQuarantineV1, registry::SccpRouteActivationV1};
use iroha_sccp::light_client::proof::SccpSourceEmitterV1;

const ETH: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;

#[test]
fn forged_mint_requires_exact_registered_event_and_payload_binding() {
    let route = sample_route(ETH);
    let deployment = &route.revisions[&1].deployment;
    let iroha_data_model::sccp::deployment::SccpDeploymentV1::Evm(evm) = deployment else {
        panic!("EVM fixture");
    };
    let emitter = SccpSourceEmitterV1::Evm(evm.address);
    assert!(
        bind_finalization(deployment, &emitter, [1; 32], 7, 100, [1; 32], 7, Some(100)).is_ok()
    );
    assert!(
        bind_finalization(deployment, &emitter, [1; 32], 7, 100, [2; 32], 7, Some(100)).is_err(),
        "a different payload id must not count forged supply"
    );
    assert!(
        bind_finalization(deployment, &emitter, [1; 32], 7, 100, [1; 32], 8, Some(100)).is_err()
    );
    assert!(
        bind_finalization(deployment, &emitter, [1; 32], 7, 100, [1; 32], 7, Some(101)).is_err()
    );
    assert!(
        bind_finalization(
            deployment,
            &SccpSourceEmitterV1::Evm([99; 20]),
            [1; 32],
            7,
            100,
            [1; 32],
            7,
            Some(100)
        )
        .is_err()
    );
}

#[test]
fn window_opens_once_and_close_reserves_refunds_without_scanning_claims() {
    let state = blank_state();
    let mut block = state.block(header(2));
    let mut stx = block.transaction();
    let mut route = sample_route(ETH);
    let revision = route.revisions.get_mut(&1).unwrap();
    revision.activation = SccpRouteActivationV1::InboundOnly;
    revision.liability = 100;
    store::routes::insert(&mut stx, ETH, route.clone()).unwrap();
    assert!(open(&mut stx, ETH, 1, 1).is_err());
    route.revisions.get_mut(&1).unwrap().quarantine = Some(SccpQuarantineV1 {
        certificate_id: [1; 32],
        since_height: 1,
    });
    store::routes::insert(&mut stx, ETH, route).unwrap();
    assert!(open(&mut stx, ETH, 1, 0).is_err());
    assert!(open(&mut stx, ETH, 1, u64::MAX).is_err());
    open(&mut stx, ETH, 1, 1).unwrap();
    assert!(open(&mut stx, ETH, 1, 1).is_err());
    assert!(!end_one(&mut stx, ETH, 1).unwrap());
    records::add_pending_refund(&mut stx, (ETH, 1), 20).unwrap();
    let now = stx.block_unix_timestamp_ms();
    // Test DATA moves the enacting time into the past; the production close path itself runs.
    let mut record = *records::get(&*stx.world, &(ETH, 1)).unwrap();
    record.opened_at_ms = now - 1;
    record.closes_at_ms = now;
    record.forged_supply = 20;
    records::put(&mut stx, (ETH, 1), record).unwrap();
    assert!(end_one(&mut stx, ETH, 1).unwrap());
    assert!(!end_one(&mut stx, ETH, 1).unwrap());
    let closed = records::get(&*stx.world, &(ETH, 1)).unwrap();
    assert_eq!(
        closed.rho,
        Some(SccpReconciliationRatioV1 {
            backing: 80,
            denominator: 100
        })
    );
    assert!(is_reconciled(&*stx.world, ETH, 1));
    assert_eq!(records::earliest_due(&*stx.world, u64::MAX), None);
    assert_eq!(
        claim_payout(&*stx.world, ETH, 1, 100, 100).unwrap(),
        Some(80)
    );
    assert!(open(&mut stx, ETH, 1, 10).is_err());
}

#[test]
fn forged_mint_actual_bsc_receipt_proof_counts_once_and_checks_payload_and_window() {
    use crate::smartcontracts::isi::sccp::test_support::authority;
    use iroha_data_model::{
        block::BlockHeader,
        sccp::{
            governance::SccpInitializeLightClientActionV1,
            light_client::{SccpLcInitExpectationV1, SccpLightClientParamsV1},
            outbound::{SccpOutboundMessageRecordV1, SccpOutboundStatusV1},
            reconciliation::{SccpForgedMintPayloadV1, SccpForgedMintProofV1},
        },
    };
    use iroha_sccp::{
        ethereum_source::EthereumLogV1,
        light_client::{
            bsc::{BscProofAnchorV1, BscSourceProofV1},
            ethereum::{EthereumEventSelectorV1, EthereumLogRefV1},
            proof::SccpSourceProofV1,
        },
        test_support::{
            bsc::SyntheticParliaChainV1,
            ethereum::{receipt_root_and_proof, successful_receipt},
        },
        v1::{evm_abi::FinalizedLogV1, payload::SccpTransferPayloadV1},
    };
    let network = SccpNetworkV1::BscMainnet;
    let now = SyntheticParliaChainV1::time_ms(5_400) + 2_000;
    let state = blank_state();
    let mut block = state.block(BlockHeader::new(
        std::num::NonZeroU64::new(2).unwrap(),
        None,
        None,
        now,
        0,
    ));
    let mut stx = block.transaction();
    let payload = SccpTransferPayloadV1::outbound(
        network,
        7,
        1,
        now + 86_400_000,
        100,
        vec![1, 2, 3],
        vec![0x42; 20],
    )
    .unwrap();
    let message_id = payload.message_id(stx.network_id().as_bytes()).unwrap();
    let bytes = payload.encode().unwrap();
    let finalized = FinalizedLogV1 {
        message_id,
        nonce: 7,
        recipient: [0x42; 20],
        token_amount: 100,
    };
    let (topics, data) = finalized.encode();
    let (root, receipt_proof) = receipt_root_and_proof(
        &[successful_receipt(vec![EthereumLogV1 {
            address: [0x33; 20],
            topics,
            data,
        }])],
        0,
    );
    let chain = SyntheticParliaChainV1::new([37; 32], 21, 16).with_receipts_root(5_390, root);
    light_clients::initialize(
        &mut stx,
        &SccpInitializeLightClientActionV1 {
            network,
            expected: SccpLcInitExpectationV1::Absent,
            params: SccpLightClientParamsV1::defaults_for(network).unwrap(),
            bootstrap: chain.bootstrap(5),
        },
        [0x44; 32],
    )
    .unwrap();
    let mut route = sample_route(network);
    route.revisions.get_mut(&1).unwrap().quarantine = Some(SccpQuarantineV1 {
        certificate_id: [1; 32],
        since_height: 1,
    });
    store::routes::insert(&mut stx, network, route).unwrap();
    open(&mut stx, network, 1, 10_000).unwrap();
    let step = chain.step(5_390, 5_400, 5_000, None);
    let proof = SccpSourceProofV1::Bsc(BscSourceProofV1 {
        anchor: BscProofAnchorV1::Finality(step.finality),
        headers: step.headers,
        transaction_index: 0,
        receipt_proof,
        event: EthereumEventSelectorV1::Finalized(EthereumLogRefV1 { log_index: 0 }),
    })
    .to_bytes()
    .unwrap();
    let instruction = ProveSccpForgedMintV1 {
        network,
        revision: 1,
        proof: SccpForgedMintProofV1 {
            source: proof,
            payload: SccpForgedMintPayloadV1::new(bytes.clone()).unwrap(),
        },
    };
    stx.apply();
    // Each submitted proof owns its original per-transaction verification allowance.
    // A payload mismatch also rolls back any checkpoints the authentic proof revealed.
    let mut stx = block.transaction();
    let mut changed_payload = payload.clone();
    changed_payload.amount = 101;
    let mut invalid = instruction.clone();
    invalid.proof.payload =
        SccpForgedMintPayloadV1::new(changed_payload.encode().unwrap()).unwrap();
    assert!(execute_prove(invalid, &authority(1), &mut stx).is_err());
    assert_eq!(
        records::get(&*stx.world, &(network, 1))
            .unwrap()
            .forged_supply,
        0
    );
    drop(stx);
    let mut stx = block.transaction();
    let mut accounting = *records::get(&*stx.world, &(network, 1)).unwrap();
    accounting.forged_supply = u128::MAX - 99;
    records::put(&mut stx, (network, 1), accounting).unwrap();
    assert!(execute_prove(instruction.clone(), &authority(1), &mut stx).is_err());
    accounting.forged_supply = 0;
    records::put(&mut stx, (network, 1), accounting).unwrap();
    // The source event is real, but an id already recorded for this revision is not forgery.
    store::outbound_messages::insert(
        &mut stx,
        message_id,
        SccpOutboundMessageRecordV1 {
            network,
            revision: 1,
            nonce: 7,
            height: 1,
            commitment_index: 0,
            deadline_ms: payload.deadline_ms,
            sender: authority(1),
            amount: 100,
            payload: bytes,
            leaf: [0; 32],
            status: SccpOutboundStatusV1::Recorded,
        },
    )
    .unwrap();
    assert!(execute_prove(instruction.clone(), &authority(1), &mut stx).is_err());
    store::outbound_messages::remove(&mut stx, message_id);
    execute_prove(instruction.clone(), &authority(1), &mut stx)
        .expect("actual finalized receipt is priced once");
    assert_eq!(
        records::get(&*stx.world, &(network, 1))
            .unwrap()
            .forged_supply,
        100
    );
    assert!(records::proven(&*stx.world, (network, 1), &message_id));
    assert!(execute_prove(instruction.clone(), &authority(1), &mut stx).is_err());
    let mut accounting = *records::get(&*stx.world, &(network, 1)).unwrap();
    accounting.opened_at_ms = now - 1;
    accounting.closes_at_ms = now;
    records::put(&mut stx, (network, 1), accounting).unwrap();
    assert!(
        execute_prove(instruction, &authority(1), &mut stx)
            .unwrap_err()
            .to_string()
            .contains("closed")
    );
    assert_eq!(
        records::get(&*stx.world, &(network, 1))
            .unwrap()
            .forged_supply,
        100
    );
}
