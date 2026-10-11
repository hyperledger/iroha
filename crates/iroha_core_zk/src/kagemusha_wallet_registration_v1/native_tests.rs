//! Real native exact-quorum certificate boundaries with explicitly synthetic execution rows.
//! Core separately tests actual registration permissions, balances and irreversible retention.
use super::*;
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    account::AccountId,
    asset::AssetBalanceScope,
    isi::kagemusha_wallet::registration_finality::KAGEMUSHA_WALLET_REGISTRATION_ASSET_MAX_BYTES_V1,
    isi::kagemusha_wallet::{KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1},
    kagemusha::{KagemushaWalletAssetScopeV1, KagemushaWalletSchemeV1},
    sumeragi_finality::VerifiedSumeragiBlock,
};
use iroha_data_model::{
    asset::AssetDefinitionId,
    block::{BlockSignatures, builder::BlockBuilder, consensus::SumeragiRootScope},
    isi::{InstructionBox, Log},
    kagemusha::{KagemushaDevicePublicKeyV1, kagemusha_wallet_provider_contract_v1},
    level::Level,
    sumeragi_finality::test_fixtures::NativeFinalityFixture,
    transaction::{
        FeePaymentIntent, TransactionBuilder, TransactionEntrypoint, TransactionResultInner,
        error::{TransactionLimitError, TransactionRejectionReason},
    },
};
use std::time::Duration;

fn committed(block: &iroha_data_model::block::SignedBlock) -> CommittedTransaction {
    let entrypoint = block.network_entrypoint_at(0).unwrap().clone();
    let (output_index, _) = block.network_output_at(0).unwrap();
    let output = block.execution_outputs()[output_index as usize].clone();
    CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: entrypoint.hash(),
        entrypoint_proof: block.network_input_proof(0).unwrap(),
        entrypoint,
        output_hash: iroha_crypto::HashOf::new(&output),
        output_proof: block.output_proof(output_index).unwrap(),
        output,
    }
}
fn original(
    fixture: &NativeFinalityFixture,
) -> (
    KagemushaWalletSchemeV1,
    KagemushaWalletAssetScopeV1,
    KagemushaWalletLedgerV1,
) {
    let key = p256::ecdsa::SigningKey::from_bytes((&[7; 32]).into()).unwrap();
    let scheme = KagemushaWalletSchemeV1 {
        version: 1,
        network_id: *fixture.network_id().as_bytes(),
        scheme_root_key: KagemushaDevicePublicKeyV1::from_sec1_bytes(
            key.verifying_key().to_encoded_point(false).as_bytes(),
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
        asset_incarnation: *Hash::new(b"registered exact incarnation").as_ref(),
        scale: 2,
    };
    asset.validate().unwrap();
    let reserve = AccountId::new(
        KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let instruction = KagemushaWalletLedgerV1::new(
        scheme.scheme_id(),
        KagemushaWalletLedgerActionV1::Register {
            scheme: scheme.to_canonical_bytes().unwrap(),
            asset: norito::encode_canonical(&asset).unwrap(),
            reserve,
            balance_scope: AssetBalanceScope::Global,
        },
    );
    (scheme, asset, instruction)
}
fn certify(
    fixture: &mut NativeFinalityFixture,
    instruction: KagemushaWalletLedgerV1,
    result: TransactionResultInner,
) -> (VerifiedSumeragiBlock, CommittedTransaction) {
    let signer = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let header = fixture.next_header();
    let mut transaction = TransactionBuilder::new(
        fixture.network_id(),
        AccountId::new(signer.public_key().clone()),
        FeePaymentIntent::authority(vec![], None),
    );
    transaction.set_creation_time(Duration::from_millis(header.creation_time_ms - 1));
    let instructions: Vec<InstructionBox> = vec![
        Log::new(Level::INFO, "before registration".into()).into(),
        instruction.into(),
    ];
    let transaction = transaction
        .with_instructions(instructions)
        .sign(signer.private_key());
    let mut builder = BlockBuilder::new(header);
    builder.push_transaction(transaction);
    let mut block = builder.build(BlockSignatures::default());
    NativeFinalityFixture::install_network_results(&mut block, vec![result]);
    let proof = fixture.certify(block);
    let verified = fixture.verifier().verify_retained_decision(&proof).unwrap();
    let committed = committed(verified.block());
    (verified, committed)
}
fn verify(
    fixture: &NativeFinalityFixture,
    block: &VerifiedSumeragiBlock,
    committed: &CommittedTransaction,
    scheme: &KagemushaWalletSchemeV1,
    asset: &KagemushaWalletAssetScopeV1,
) -> Result<FinalizedKagemushaWalletRegistrationV1, RegistrationErrorV1> {
    verify_finalized_kagemusha_wallet_registration_v1(
        block,
        committed,
        fixture.network_id(),
        fixture.chain_id(),
        scheme,
        asset.asset_digest(),
        1,
    )
}
#[test]
fn finalized_registration_retains_exact_successful_global_originals() {
    let mut fixture = NativeFinalityFixture::start("registration-finality");
    let (scheme, asset, instruction) = original(&fixture);
    let (block, committed) = certify(&mut fixture, instruction.clone(), Ok(vec![]));
    let selected = verify(&fixture, &block, &committed, &scheme, &asset).unwrap();
    assert_eq!(selected.scheme(), &scheme);
    assert_eq!(selected.asset(), &asset);
    assert_eq!(
        selected.scheme_original(),
        scheme.to_canonical_bytes().unwrap()
    );
    assert_eq!(
        selected.asset_original(),
        norito::encode_canonical(&asset).unwrap()
    );
    let KagemushaWalletLedgerActionV1::Register { reserve, .. } = instruction.action else {
        unreachable!()
    };
    assert_eq!(selected.reserve(), &reserve);
    assert_eq!(selected.block_hash(), *committed.block_hash().as_ref());
    assert_eq!(selected.height(), 2);
    assert_eq!(selected.instruction_index(), 1);
    let TransactionEntrypoint::External(tx) = committed.entrypoint() else {
        unreachable!()
    };
    assert_eq!(selected.transaction_hash(), *tx.hash().as_ref());
}
#[test]
fn registration_refuses_foreign_scope_index_asset_and_scheme() {
    let mut fixture = NativeFinalityFixture::start("registration-scope");
    let (scheme, asset, instruction) = original(&fixture);
    let (block, committed) = certify(&mut fixture, instruction, Ok(vec![]));
    assert!(
        verify_finalized_kagemusha_wallet_registration_v1(
            &block,
            &committed,
            fixture.network_id(),
            "foreign-chain",
            &scheme,
            asset.asset_digest(),
            1
        )
        .is_err()
    );
    for index in [0, 2, usize::MAX] {
        assert!(
            verify_finalized_kagemusha_wallet_registration_v1(
                &block,
                &committed,
                fixture.network_id(),
                fixture.chain_id(),
                &scheme,
                asset.asset_digest(),
                index
            )
            .is_err()
        );
    }
    let mut foreign = asset.clone();
    foreign.asset_incarnation = *Hash::new(b"foreign incarnation").as_ref();
    assert!(verify(&fixture, &block, &committed, &scheme, &foreign).is_err());
    foreign = asset.clone();
    foreign.scale += 1;
    assert!(verify(&fixture, &block, &committed, &scheme, &foreign).is_err());
    let mut foreign_scheme = scheme;
    foreign_scheme.relation_id[0] ^= 1;
    assert!(verify(&fixture, &block, &committed, &foreign_scheme, &asset).is_err());
    let mut private = NativeFinalityFixture::start_with_scope(
        "registration-scope",
        SumeragiRootScope::Dataspace {
            parent_network_id: fixture.network_id(),
            dataspace_id: 13_u64.into(),
        },
    );
    let (scheme, asset, instruction) = original(&private);
    let (block, committed) = certify(&mut private, instruction, Ok(vec![]));
    assert!(verify(&private, &block, &committed, &scheme, &asset).is_err());
}
#[test]
fn registration_refuses_failed_execution_and_tampered_membership() {
    let mut fixture = NativeFinalityFixture::start("registration-result");
    let (scheme, asset, instruction) = original(&fixture);
    let (block, committed) = certify(
        &mut fixture,
        instruction.clone(),
        Err(TransactionRejectionReason::LimitCheck(
            TransactionLimitError {
                reason: "synthetic failure".into(),
            },
        )),
    );
    assert!(verify(&fixture, &block, &committed, &scheme, &asset).is_err());
    let (block, mut committed) = certify(&mut fixture, instruction, Ok(vec![]));
    committed.block_hash =
        iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"foreign block"));
    assert!(verify(&fixture, &block, &committed, &scheme, &asset).is_err());
}
#[test]
fn registration_never_accepts_restricted_bucket_wrong_reserve_or_malformed_original() {
    for change in 0..4 {
        let mut fixture = NativeFinalityFixture::start("registration-terms");
        let (scheme, asset, mut instruction) = original(&fixture);
        let KagemushaWalletLedgerActionV1::Register {
            reserve,
            balance_scope,
            asset: bytes,
            ..
        } = &mut instruction.action
        else {
            unreachable!()
        };
        match change {
            0 => *balance_scope = AssetBalanceScope::Dataspace(13_u64.into()),
            1 => {
                *reserve = AccountId::new(
                    KeyPair::from_seed(vec![42; 32], Algorithm::Ed25519)
                        .public_key()
                        .clone(),
                )
            }
            2 => bytes.push(0),
            _ => *bytes = vec![0; KAGEMUSHA_WALLET_REGISTRATION_ASSET_MAX_BYTES_V1 + 1],
        }
        let (block, committed) = certify(&mut fixture, instruction, Ok(vec![]));
        assert!(
            verify(&fixture, &block, &committed, &scheme, &asset).is_err(),
            "change={change}"
        );
    }
}
