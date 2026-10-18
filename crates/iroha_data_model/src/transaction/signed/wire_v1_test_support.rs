//! Deterministic codec fixtures only; synthetic identities do not claim finalized ownership.

use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    Level, NetworkId,
    account::{AccountId, MultisigMember, MultisigPolicy},
    block::consensus::HeightContextId,
    isi::{
        InstructionBox, Log,
        musubi::{AdvanceMusubiPinOutboxV1, CheckMusubiPinOutboxV1},
    },
    musubi::{
        MusubiPinOutboxCheckExpectationV1, MusubiPinOutboxCheckFloorV1, MusubiPinOutboxHighWaterV1,
    },
    transaction::{FeePaymentIntent, SignedTransaction, TransactionBuilder},
};
use std::time::Duration;

pub(super) fn signed(profile: &str) -> SignedTransaction {
    let first = KeyPair::from_seed(vec![0x91; 32], Algorithm::Ed25519);
    let second = KeyPair::from_seed(vec![0x92; 32], Algorithm::Ed25519);
    let multisig = profile.starts_with("multisig-");
    let authority = if multisig {
        AccountId::new_multisig(
            MultisigPolicy::new(
                1,
                vec![
                    MultisigMember::new(first.public_key().clone(), 1).unwrap(),
                    MultisigMember::new(second.public_key().clone(), 1).unwrap(),
                ],
            )
            .unwrap(),
        )
    } else {
        AccountId::new(first.public_key().clone())
    };
    let network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"standalone fixed-V1 wire fixture",
    )));
    let instruction: InstructionBox = match profile {
        "advance" => AdvanceMusubiPinOutboxV1 {
            network_id,
            pin_authority: authority.clone(),
            session_id: [2; 32],
            expected_revision: 0,
            expected_inventory_digest: [0; 32],
            inventory_digest: [4; 32],
        }
        .into(),
        "check" | "check-present" | "check-metadata" => CheckMusubiPinOutboxV1 {
            network_id,
            pin_authority: authority.clone(),
            session_id: [2; 32],
            inventory_digest: [4; 32],
            challenge: [3; 32],
            floor: MusubiPinOutboxCheckFloorV1 {
                height: 2,
                block_hash: [0x33; 32],
                context_id: HeightContextId(HashOf::from_untyped_unchecked(Hash::new([0x55; 32]))),
            },
            expected: if profile == "check-present" {
                MusubiPinOutboxCheckExpectationV1::Present(MusubiPinOutboxHighWaterV1 {
                    version: 1,
                    network_id,
                    pin_authority: authority.clone(),
                    session_id: [2; 32],
                    revision: 1,
                    inventory_digest: [4; 32],
                    recorded_at_height: 2,
                    transaction_hash: [0x77; 32],
                })
            } else {
                MusubiPinOutboxCheckExpectationV1::Absent
            },
        }
        .into(),
        "large" | "large-one-over" => Log::new(
            Level::INFO,
            "x".repeat(8_192 + usize::from(profile == "large-one-over")),
        )
        .into(),
        "multisig-a" | "multisig-b" => {
            Log::new(Level::INFO, "same payload, different authorization".into()).into()
        }
        _ => panic!("unknown deterministic wire fixture"),
    };
    let mut builder = TransactionBuilder::new(
        network_id,
        authority,
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([instruction]);
    if profile == "check-metadata" {
        let mut metadata = iroha_model_base::metadata::Metadata::default();
        metadata.insert(
            "codec_fixture".parse().unwrap(),
            iroha_primitives::json::Json::new(vec![
                vec!["x".repeat(256)],
                vec!["nested".to_owned(), "public".to_owned()],
            ]),
        );
        builder = builder.with_metadata(metadata);
    }
    builder.set_creation_time(Duration::from_millis(42_001));
    if multisig {
        builder.sign_multisig([if profile == "multisig-b" {
            second.private_key()
        } else {
            first.private_key()
        }])
    } else {
        builder.sign(first.private_key())
    }
}
