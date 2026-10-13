//! Genuine native admission of a signed advance followed by its dependent receipt proof.

use super::*;
use crate::{
    state::{StateReadOnly, World},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{
        governance::SccpInitializeLightClientActionV1,
        light_client::{SccpLcInitExpectationV1, SccpLightClientParamsV1},
        params::SccpParametersV1,
    },
};
use iroha_sccp::{
    light_client::{
        ethereum::{
            EthereumAncestryV1, EthereumEventSelectorV1, EthereumLogRefV1, EthereumProofAnchorV1,
            EthereumSourceProofV1,
        },
        proof::SccpSourceProofV1,
    },
    test_support::ethereum::{
        SyntheticBeaconChainV1, SyntheticBlockFieldsV1, execution_header_rlp, execution_of,
        receipt_root_and_proof, successful_receipt, transfer_log,
    },
    v1::evm_abi::TransferToTairaLogV1,
};

const NETWORK: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;
const PERIOD: u64 = 1_868;

struct Fixture {
    chain: CertifiedTestChain,
    key: KeyPair,
    advance: AdvanceSccpLightClientV1,
    submit: SubmitSccpInboundMessageV1,
    now: u64,
}

fn fixture() -> Fixture {
    let source = SyntheticBeaconChainV1::mainnet();
    let slot = (PERIOD + 1) * 8_192;
    let now = source.slot_unix_ms(slot + 300);
    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), now)).unwrap();
    chain.setup_world_at(now, |stx| {
        store::parameters::set(stx, Some(SccpParametersV1::taira_default()));
        let mut route = super::super::test_support::sample_route(NETWORK);
        route.revisions.get_mut(&1).unwrap().activation = SccpRouteActivationV1::Bidirectional;
        store::routes::insert(stx, NETWORK, route).unwrap();
        super::super::light_clients::initialize(
            stx,
            &SccpInitializeLightClientActionV1 {
                network: NETWORK,
                expected: SccpLcInitExpectationV1::Absent,
                params: SccpLightClientParamsV1::defaults_for(NETWORK).unwrap(),
                bootstrap: source.bootstrap_with_execution(
                    PERIOD * 8_192 + 64,
                    &source.synthetic_execution(PERIOD * 8_192 + 64),
                ),
            },
            [0x47; 32],
        )
        .unwrap();
    });
    let key = KeyPair::from_seed(vec![0x58; 32], Algorithm::Ed25519);
    let authority = AccountId::new(key.public_key().clone());
    let payload = SccpTransferPayloadV1::inbound(
        NETWORK,
        7,
        1,
        SccpParametersV1::taira_default().inbound_self_claim_fee + 100,
        vec![0x55; 20],
        AccountAddress::from_account_id(&authority)
            .unwrap()
            .canonical_bytes()
            .unwrap(),
    )
    .unwrap();
    let view = chain.state().view();
    let message_id = payload.message_id(view.network_id().as_bytes()).unwrap();
    let payload = payload.encode().unwrap();
    let (receipts_root, receipt_proof) = receipt_root_and_proof(
        &[successful_receipt(vec![transfer_log(
            [0x33; 20],
            &TransferToTairaLogV1 {
                message_id,
                sender: [0x55; 20],
                nonce: 7,
                payload: payload.clone(),
            },
        )])],
        0,
    );
    let header = execution_header_rlp(&SyntheticBlockFieldsV1 {
        parent_hash: [0x11; 32],
        number: 1_000,
        timestamp: source.slot_unix_ms(slot + 150) / 1_000,
        state_root: [0x22; 32],
        receipts_root,
    });
    let proof = SccpSourceProofV1::Ethereum(EthereumSourceProofV1 {
        anchor: EthereumProofAnchorV1::FinalityUpdate(Box::new(
            source.finality_update_for(execution_of(&header), slot + 200),
        )),
        ancestry: EthereumAncestryV1::SameBlock,
        event_header: header,
        transaction_index: 0,
        receipt_proof,
        event: EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index: 0 }),
    })
    .to_bytes()
    .unwrap();
    let advance = AdvanceSccpLightClientV1 {
        network: NETWORK,
        expected_state_hash: Some(
            store::light_clients::get(view.world(), &NETWORK)
                .unwrap()
                .state_hash,
        ),
        advance: source
            .catch_up_advance(PERIOD, PERIOD + 1)
            .to_bytes()
            .unwrap(),
    };
    drop(view);
    Fixture {
        chain,
        key,
        advance,
        submit: SubmitSccpInboundMessageV1 {
            network: NETWORK,
            revision: 1,
            payload,
            proof,
        },
        now,
    }
}

#[test]
fn signed_bundle_uses_original_overlay_and_checks_each_advance_cas() {
    let fixture = fixture();
    let view = fixture.chain.state().view();
    let before = *store::light_clients::get(view.world(), &NETWORK).unwrap();
    let classify = |instructions| {
        let tx = fixture.chain.sign(&fixture.key, instructions, fixture.now);
        super::super::admission::classify(view.world(), &view, 2, &tx)
    };
    assert!(
        classify(vec![fixture.submit.clone().into()]).is_err(),
        "unadvanced original state cannot authenticate the next-period signer"
    );
    assert_eq!(
        classify(vec![
            fixture.advance.clone().into(),
            fixture.submit.clone().into()
        ])
        .expect("the actual signed bundle must verify")
        .unwrap()
        .class,
        SccpExemptClassV1::SelfClaim
    );
    let mut stale = fixture.advance.clone();
    stale.expected_state_hash = Some([0xff; 32]);
    let stale_result = classify(vec![stale.into(), fixture.submit.clone().into()]);
    assert!(
        stale_result.is_err(),
        "SCCP bundled admission must enforce each signed advance state expectation"
    );
    assert_eq!(
        stale_result.unwrap_err().reason,
        "stale expected state hash"
    );
    assert_eq!(
        *store::light_clients::get(view.world(), &NETWORK).unwrap(),
        before
    );
    assert!(
        store::light_client_sets::get(view.world(), &(NETWORK, PERIOD + 1)).is_none(),
        "admission must never commit the signed overlay"
    );
}

#[test]
fn exhausted_bundle_admission_preserves_original_deferral_and_retry() {
    let Fixture {
        chain,
        key,
        advance,
        submit,
        now,
    } = fixture();
    let tx = chain.sign(&key, [advance.into(), submit.into()], now);
    let state = std::sync::Arc::clone(chain.state());
    // Finish the genuine chain worker before measuring this admission attempt. Its
    // asynchronous archive owners use this same original pool and otherwise may be
    // released after the baseline is observed. State and its committed source remain.
    drop(chain);
    let view = state.view();
    let budget = view.execution_budget();
    let baseline = budget.reserved_bytes();
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - baseline)
        .unwrap();
    let classify = || super::super::admission::classify(view.world(), &view, 2, &tx);
    let error = classify().unwrap_err();
    assert!(
        error.deferred.is_some(),
        "SCCP local allocation refusal must remain an original deferred attempt"
    );
    assert!(matches!(
        error.deferred.as_ref().unwrap().allocation_refusal(),
        Some(iroha_allocation::AllocationRefusal::Capacity { .. })
    ));
    assert!(
        error.reason.is_empty(),
        "local refusal is not a protocol rejection reason"
    );
    let foreign = iroha_allocation::AllocationBudget::new(1_024);
    drop(foreign.try_reserve_bytes(1_024).unwrap());
    assert!(
        classify().unwrap_err().deferred.is_some(),
        "foreign release cannot satisfy this source"
    );
    drop(error);
    drop(occupied);
    assert!(
        classify().unwrap().is_some(),
        "original release allows fresh genuine verification"
    );
    assert_eq!(
        budget.reserved_bytes(),
        baseline,
        "cancelled and completed attempts release their exact owners"
    );
}
