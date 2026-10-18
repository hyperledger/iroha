//! Bounded receipt and contiguous capture controls; metadata is never finality authority.
//! Registration fixtures use real certificates with explicitly synthetic execution outputs.
use super::*;

#[test]
fn shifted_campaign_uses_exact_receipt_and_complete_observed_prefix() {
    // The component owner loads at H5; real retained DKG work shifts the same
    // consecutive stages to H8. Both have one current verifier, with no fallback.
    for load in [5, 8, HISTORY_MAX] {
        let heights = campaign_heights(load);
        assert_eq!(heights.registration, load - 2);
        assert_eq!(heights.activation, load - 1);
        assert_eq!(heights.load, load);
        let rows = (2..=heights.load)
            .map(|height| norito::json!({"height":height}))
            .collect::<Vec<_>>();
        capture_heights(&rows, heights);
    }
}

#[test]
fn campaign_refuses_early_and_overbound_receipt_heights() {
    for load in [0, 1, 2, 3, 4, HISTORY_MAX + 1, u64::MAX] {
        assert!(std::panic::catch_unwind(|| campaign_heights(load)).is_err());
    }
}

#[test]
fn capture_refuses_truncated_duplicate_reordered_and_invented_heights() {
    let heights = campaign_heights(8);
    let selected = (2..=heights.load)
        .map(|height| norito::json!({"height":height}))
        .collect::<Vec<_>>();
    let mut missing = selected.clone();
    missing.remove(3);
    let mut extra = selected.clone();
    extra.push(norito::json!({"height":9}));
    let mut duplicate = selected.clone();
    duplicate[3] = duplicate[2].clone();
    let mut reordered = selected.clone();
    reordered.swap(3, 4);
    let mut gap = selected.clone();
    gap[3] = norito::json!({"height":42});
    let mut invalid = selected.clone();
    invalid[3] = norito::json!({"height":"5"});
    for rows in [missing, extra, duplicate, reordered, gap, invalid] {
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| capture_heights(
                &rows, heights,
            )))
            .is_err()
        );
    }
    capture_heights(&selected, heights);
}

struct Registration {
    genesis: SumeragiFinalityVerifier,
    block: VerifiedSumeragiBlock,
    scheme: KagemushaWalletSchemeV1,
    asset: KagemushaWalletAssetScopeV1,
    reserve: AccountId,
}

fn registration(predecessor: u64, count: usize, accepted: bool) -> Registration {
    use iroha_crypto::KeyPair;
    use iroha_data_model::{
        asset::{AssetBalanceScope, AssetDefinitionId},
        block::{BlockSignatures, builder::BlockBuilder},
        isi::{InstructionBox, Log},
        kagemusha::{KagemushaDevicePublicKeyV1, kagemusha_wallet_provider_contract_v1},
        level::Level,
        sumeragi_finality::test_fixtures::NativeFinalityFixture,
        transaction::{
            FeePaymentIntent, TransactionBuilder,
            error::{TransactionLimitError, TransactionRejectionReason},
        },
    };
    let mut native = NativeFinalityFixture::start("native-load-registration");
    // The fixture's verifier already admitted H1. Start an independent verifier
    // from its signed genesis so the test authenticates H1 exactly once, followed
    // by every submitted-work proof through the selected registration height.
    let genesis = SumeragiFinalityVerifier::new(
        native.genesis(),
        native.chain_id(),
        native.genesis_proof().committee.clone(),
    )
    .unwrap();
    let mut verifier = genesis.clone();
    verifier.verify(native.genesis_proof()).unwrap();
    for _ in 2..=predecessor {
        let block = native.block_with_submitted_work(native.next_header());
        verifier.verify(&native.certify(block)).unwrap();
    }
    let signing = p256::ecdsa::SigningKey::from_bytes((&[7; 32]).into()).unwrap();
    let scheme = KagemushaWalletSchemeV1 {
        version: 1,
        network_id: *native.network_id().as_bytes(),
        scheme_root_key: KagemushaDevicePublicKeyV1::from_sec1_bytes(
            signing.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap(),
        relation_id: [9; 32],
        provider_contract: kagemusha_wallet_provider_contract_v1(),
    };
    let asset = KagemushaWalletAssetScopeV1 {
        version: 1,
        asset: AssetDefinitionId::from_uuid_bytes([
            0x2f, 0x17, 0xc7, 0x24, 0x66, 0xf8, 0x4a, 0x4b, 0xb8, 0xa8, 0xe2, 0x48, 0x84, 0xfd,
            0xcd, 0x2f,
        ])
        .unwrap(),
        asset_incarnation: *Hash::new(b"native Load registration").as_ref(),
        scale: 2,
    };
    let signer = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let reserve = AccountId::new(signer.public_key().clone());
    let register = KagemushaWalletLedgerV1::new(
        scheme.scheme_id(),
        KagemushaWalletLedgerActionV1::Register {
            scheme: scheme.to_canonical_bytes().unwrap(),
            asset: norito::encode_canonical(&asset).unwrap(),
            reserve: reserve.clone(),
            balance_scope: AssetBalanceScope::Global,
        },
    );
    let header = native.next_header();
    let mut transaction = TransactionBuilder::new(
        native.network_id(),
        reserve.clone(),
        FeePaymentIntent::authority(vec![], None),
    );
    transaction.set_creation_time(std::time::Duration::from_millis(
        header.creation_time_ms - 1,
    ));
    // Register is deliberately at instruction index one, after unrelated work.
    let mut instructions: Vec<InstructionBox> = vec![Log::new(Level::INFO, "work".into()).into()];
    instructions.extend((0..count).map(|_| register.clone().into()));
    let transaction = transaction
        .with_instructions(instructions)
        .sign(signer.private_key());
    let mut builder = BlockBuilder::new(header);
    builder.push_transaction(transaction);
    let mut block = builder.build(BlockSignatures::default());
    let result = if accepted {
        Ok(vec![])
    } else {
        Err(TransactionRejectionReason::LimitCheck(
            TransactionLimitError {
                reason: "synthetic refusal".into(),
            },
        ))
    };
    NativeFinalityFixture::install_network_results(&mut block, vec![result]);
    let block = verifier.verify(&native.certify(block)).unwrap();
    Registration {
        genesis,
        block,
        scheme,
        asset,
        reserve,
    }
}

#[test]
fn registration_is_selected_from_actual_index_in_each_verified_prefix() {
    for predecessor in [2, 5] {
        let f = registration(predecessor, 1, true);
        assert_eq!(
            f.block.height(),
            campaign_heights(predecessor + 3).registration
        );
        require_registration(
            &f.block,
            &f.genesis,
            f.scheme.scheme_id(),
            &f.asset,
            &f.reserve,
        );
    }
}

#[test]
fn registration_refuses_absent_ambiguous_failed_foreign_and_wrong_terms() {
    for (count, accepted) in [(0, true), (2, true), (1, false)] {
        let f = registration(5, count, accepted);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                require_registration(
                    &f.block,
                    &f.genesis,
                    f.scheme.scheme_id(),
                    &f.asset,
                    &f.reserve,
                );
            }))
            .is_err()
        );
    }
    let f = registration(5, 1, true);
    let mut wrong_asset = f.asset.clone();
    wrong_asset.scale += 1;
    let other = iroha_crypto::KeyPair::from_seed(vec![42; 32], Algorithm::Ed25519);
    let wrong_reserve = AccountId::new(other.public_key().clone());
    for (scheme, asset, reserve) in [
        ([0; 32], &f.asset, &f.reserve),
        (f.scheme.scheme_id(), &wrong_asset, &f.reserve),
        (f.scheme.scheme_id(), &f.asset, &wrong_reserve),
    ] {
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                require_registration(&f.block, &f.genesis, scheme, asset, reserve);
            }))
            .is_err()
        );
    }
}
