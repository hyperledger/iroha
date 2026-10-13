//! Recipient bundles exercise native verification and exact unsigned instruction ordering.

use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::sccp::light_client::{
    SccpLcAdvanceBytesV1, SccpLcBootstrapV1, SccpLightClientParamsV1,
};
use iroha_sccp::{
    light_client::{
        self,
        ethereum::{
            EthereumAncestryV1, EthereumEventSelectorV1, EthereumLogRefV1, EthereumProofAnchorV1,
            EthereumSourceProofV1,
        },
        profile::GENESIS_PROFILES,
        proof::SccpSourceProofV1,
    },
    test_support::ethereum::{
        SyntheticBeaconChainV1, SyntheticBlockFieldsV1, execution_header_rlp, execution_of,
        receipt_root_and_proof, successful_receipt, transfer_log,
    },
    v1::evm_abi::TransferToTairaLogV1,
};
use std::cell::Cell;

const NETWORK: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;
const PERIOD: u64 = 1_868;
struct Source {
    advance: SccpLcAdvanceBytesV1,
    evidence: SourceEvidenceV1,
    rotations: Cell<usize>,
}
impl SourceChainBuilder for Source {
    fn network(&self) -> SccpNetworkV1 {
        NETWORK
    }
    fn source_attempts(&self) -> usize {
        2
    }
    fn rotate_endpoints(&self) {
        self.rotations.set(self.rotations.get() + 1);
    }
    fn bootstrap(&self) -> std::result::Result<SccpLcBootstrapV1, BuildError> {
        Err(BuildError::Unavailable(
            "bootstrap is not part of a claim".into(),
        ))
    }
    fn advance(
        &self,
        latest: u64,
        budget: AdvanceBudgetV1,
    ) -> std::result::Result<SccpLcAdvanceBytesV1, BuildError> {
        if latest != PERIOD || self.advance.as_bytes().len() > budget.max_bytes {
            return Err(BuildError::Unavailable("outside this source range".into()));
        }
        Ok(self.advance.clone())
    }
    fn evidence(
        &self,
        _: &SourceEventRefV1,
        view: &dyn TairaLightClientView,
        _: u64,
    ) -> std::result::Result<SourceEvidenceV1, BuildError> {
        if view.light_client()?.head.latest_set_id != PERIOD + 1 {
            return Err(BuildError::Unavailable(
                "the source signer is not stored".into(),
            ));
        }
        Ok(self.evidence.clone())
    }
}
fn fixture() -> (AccountId, Vec<u8>, LightClientReplayV1, Source, u64) {
    let beacon = SyntheticBeaconChainV1::mainnet();
    let slot = (PERIOD + 1) * 8_192;
    let now = beacon.slot_unix_ms(slot + 300);
    let initial = light_client::verify_bootstrap_with_profiles(
        &GENESIS_PROFILES,
        NETWORK,
        &SccpLightClientParamsV1::defaults_for(NETWORK).unwrap(),
        &beacon.bootstrap_with_execution(
            PERIOD * 8_192 + 64,
            &beacon.synthetic_execution(PERIOD * 8_192 + 64),
        ),
        now,
    )
    .unwrap();
    let key = KeyPair::from_seed(vec![0x58; 32], Algorithm::Ed25519);
    let authority = AccountId::new(key.public_key().clone());
    let payload = SccpTransferPayloadV1::inbound(
        NETWORK,
        7,
        1,
        10_000_100,
        vec![0x55; 20],
        AccountAddress::from_account_id(&authority)
            .unwrap()
            .canonical_bytes()
            .unwrap(),
    )
    .unwrap()
    .encode()
    .unwrap();
    let (receipts_root, receipt_proof) = receipt_root_and_proof(
        &[successful_receipt(vec![transfer_log(
            [0x33; 20],
            &TransferToTairaLogV1 {
                message_id: [0x47; 32],
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
        timestamp: beacon.slot_unix_ms(slot + 150) / 1_000,
        state_root: [0x22; 32],
        receipts_root,
    });
    let proof = SccpSourceProofV1::Ethereum(EthereumSourceProofV1 {
        anchor: EthereumProofAnchorV1::FinalityUpdate(Box::new(
            beacon.finality_update_for(execution_of(&header), slot + 200),
        )),
        ancestry: EthereumAncestryV1::SameBlock,
        event_header: header,
        transaction_index: 0,
        receipt_proof,
        event: EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index: 0 }),
    })
    .to_bytes()
    .unwrap();
    (
        authority,
        payload,
        LightClientReplayV1::installed(&GENESIS_PROFILES, NETWORK, &initial),
        Source {
            advance: beacon
                .catch_up_advance(PERIOD, PERIOD + 1)
                .to_bytes()
                .unwrap(),
            evidence: SourceEvidenceV1 {
                backfills: Vec::new(),
                proof,
            },
            rotations: Cell::new(0),
        },
        now,
    )
}
fn event() -> SourceEventRefV1 {
    SourceEventRefV1::Evm {
        tx_hash: [0x71; 32],
        event: iroha_sccp_rpc::builders::ethereum::EthereumEventV1::TransferToTaira {
            log_index: 0,
        },
    }
}

#[test]
fn recipient_bundle_verifies_dependent_proof_without_changing_original_state() {
    let (authority, payload, original, source, now) = fixture();
    let before = original.light_client().unwrap();
    assert!(
        build(
            &original,
            original.clone(),
            &source,
            &event(),
            &payload,
            0,
            now
        )
        .is_err()
    );
    let evidence = build(
        &original,
        original.clone(),
        &source,
        &event(),
        &payload,
        1,
        now,
    )
    .unwrap();
    assert_eq!(evidence.advances.len(), 1);
    assert_eq!(
        evidence.advances[0].expected_state_hash,
        Some(before.state_hash)
    );
    assert_eq!(original.light_client().unwrap(), before);
    let bytes = source.advance.clone();
    let proof = source.evidence.proof.clone();
    let instructions =
        instructions(&authority, true, NETWORK, 1, payload.clone(), evidence).unwrap();
    assert_eq!(instructions.len(), 3);
    let register = instructions[0]
        .as_any()
        .downcast_ref::<Register<Account>>()
        .unwrap();
    assert_eq!(register.object, Account::new(authority.clone()));
    let advance = instructions[1]
        .as_any()
        .downcast_ref::<AdvanceSccpLightClientV1>()
        .unwrap();
    assert_eq!(advance.advance, bytes);
    assert_eq!(advance.expected_state_hash, Some(before.state_hash));
    let submit = instructions[2]
        .as_any()
        .downcast_ref::<SubmitSccpInboundMessageV1>()
        .unwrap();
    assert_eq!(submit.proof, proof);
    assert_eq!(submit.payload, payload);
    require_recipient(&authority, &payload, 10_000_000).unwrap();
    assert!(require_recipient(&authority, &payload, 10_000_100).is_err());
    let other = AccountId::new(
        KeyPair::from_seed(vec![0x59; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    assert!(require_recipient(&other, &payload, 0).is_err());
}

#[test]
fn recipient_bundle_rejects_substituted_payload_and_keeps_source_retries_finite() {
    let (_, mut payload, original, source, now) = fixture();
    payload[0] ^= 1;
    assert!(
        build(
            &original,
            original.clone(),
            &source,
            &event(),
            &payload,
            1,
            now
        )
        .is_err()
    );
    assert_eq!(
        source.rotations.get(),
        1,
        "two attempts exhaust the original endpoint list"
    );
    assert_eq!(original.light_client().unwrap().head.latest_set_id, PERIOD);
}

#[test]
fn recipient_recovery_intent_cannot_change_mode_registration_authority_or_bound() {
    let authority = AccountId::new(
        KeyPair::from_seed(vec![0x60; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let other = AccountId::new(
        KeyPair::from_seed(vec![0x61; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let original = claim_intent(NETWORK, "0x01", &authority, true, true, 4).unwrap();
    assert_eq!(
        original,
        claim_intent(NETWORK, "0x01", &authority, true, true, 4).unwrap()
    );
    for altered in [
        claim_intent(NETWORK, "0x01", &authority, false, true, 4),
        claim_intent(NETWORK, "0x01", &authority, true, false, 4),
        claim_intent(NETWORK, "0x01", &authority, true, true, 5),
        claim_intent(NETWORK, "0x01", &other, true, true, 4),
        claim_intent(NETWORK, "0x02", &authority, true, true, 4),
    ] {
        assert_ne!(original, altered.unwrap());
    }
}
