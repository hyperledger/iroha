//! Real account signatures and certified inclusion, plus explicit mock custody fault tests.
//! Fixture execution rows are synthetic; these do not claim production World execution.
use super::*;
use crate::kagemusha_wallet_state_v1::tests::{Wallet, bootstrap, field, fixture, wallet};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::AccountId,
    block::{BlockSignatures, builder::BlockBuilder},
    executor::ValidationFail,
    sumeragi_finality::test_fixtures::NativeFinalityFixture,
    transaction::{FeePaymentIntent, TransactionBuilder, error::TransactionRejectionReason},
};
use std::time::Duration;

fn signed(
    network: NetworkId,
    scheme: [u8; 32],
    original: &[u8],
    key: &KeyPair,
) -> SignedTransaction {
    signed_at(network, scheme, original, key, 1)
}
fn signed_at(
    network: NetworkId,
    scheme: [u8; 32],
    original: &[u8],
    key: &KeyPair,
    at: u64,
) -> SignedTransaction {
    let mut builder = TransactionBuilder::new(
        network,
        AccountId::new(key.public_key().clone()),
        FeePaymentIntent::authority(vec![], None),
    );
    builder.set_creation_time(Duration::from_millis(at));
    builder
        .with_instructions([KagemushaWalletLedgerV1::new(
            scheme,
            KagemushaWalletLedgerActionV1::Activate(original.to_vec()),
        )])
        .sign(key.private_key())
}

#[test]
fn same_activation_outer_attempts_have_independent_authenticated_outcomes() {
    for (old_succeeds, new_succeeds) in [(false, true), (true, false), (true, true)] {
        let mut ledger = NativeFinalityFixture::new_with_explicit_parameters();
        let key = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
        let account = AccountId::new(key.public_key().clone());
        let owner = kagemusha_wallet_account_digest_v1(&account).unwrap();
        let original = vec![7; 96]; // Opaque inner DATA for this signature/finality component test.
        let old = signed_at(ledger.network_id(), [1; 32], &original, &key, 1);
        let new = signed_at(ledger.network_id(), [1; 32], &original, &key, 2);
        assert_ne!(old.encode_wire_v1().unwrap(), new.encode_wire_v1().unwrap());
        for tx in [&old, &new] {
            signed_activate(
                &tx.encode_wire_v1().unwrap(),
                &ledger.network_id(),
                &[1; 32],
                &owner,
                &original,
            )
            .unwrap();
        }
        let mut builder = BlockBuilder::new(ledger.next_header());
        builder.push_transaction(old.clone());
        builder.push_transaction(new.clone());
        let mut block = builder.build(BlockSignatures::default());
        let rejected = Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted("fixture older/newer rejection".into()),
        ));
        NativeFinalityFixture::install_network_results(
            &mut block,
            [old_succeeds, new_succeeds]
                .into_iter()
                .map(|accepted| {
                    if accepted {
                        Ok(vec![])
                    } else {
                        rejected.clone()
                    }
                })
                .collect(),
        );
        let proof = ledger.certify(block);
        let verified = ledger.verifier().verify_retained_decision(&proof).unwrap();
        assert_eq!(
            successful_inclusion(&verified, &ledger.network_id(), old.clone()).is_ok(),
            old_succeeds
        );
        assert_eq!(
            successful_inclusion(&verified, &ledger.network_id(), new.clone()).is_ok(),
            new_succeeds
        );
        for (transaction, accepted) in [(old, old_succeeds), (new, new_succeeds)] {
            let (progress, actual) =
                authenticated_inclusion(&verified, &ledger.network_id(), transaction).unwrap();
            assert_eq!(actual, accepted);
            assert_eq!(progress.height, verified.height());
        }
    }
}

// Synthetic custody publishers below exercise retention, never installed authorization.
pub(super) fn register_data(wallet: &mut Wallet, plan: &Plan, wire: &[u8]) -> Plan {
    let (root, manifest) = wallet.sync_manifest().unwrap();
    wallet
        .publish_activation_attempt(root, manifest, plan, wire)
        .unwrap();
    wallet.activation_plan(&plan.asset).unwrap()
}
pub(super) fn confirmation_data(wallet: &mut Wallet, plan: &Plan, wire: &[u8]) -> Confirmation {
    let mut native = NativeFinalityFixture::start("activation-confirmation-retention");
    let block = native.block_with_submitted_work(native.next_header());
    native.certify(block);
    let checkpoint = native.checkpoint();
    let progress = ledger::progress(&checkpoint);
    Confirmation {
        version: 1,
        activation: plan.output.unwrap(),
        signed_transaction: wire.to_vec(),
        height: progress.height,
        block_hash: progress.block_hash,
        checkpoint: wallet
            .archive
            .write_object(
                &checkpoint.encode_canonical().unwrap(),
                MAX_FINALITY_CHECKPOINT_BYTES,
            )
            .unwrap(),
    }
}

#[test]
fn exact_signed_activate_rejects_foreign_original_account_network_and_noncanonical_wire() {
    let ledger = NativeFinalityFixture::new_with_explicit_parameters();
    let key = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let account = AccountId::new(key.public_key().clone());
    let owner = kagemusha_wallet_account_digest_v1(&account).unwrap();
    let original = vec![7; 96];
    let transaction = signed(ledger.network_id(), [1; 32], &original, &key);
    let wire = transaction.encode_wire_v1().unwrap();
    assert_eq!(
        signed_activate(&wire, &ledger.network_id(), &[1; 32], &owner, &original).unwrap(),
        transaction
    );
    assert!(signed_activate(&wire, &ledger.network_id(), &[2; 32], &owner, &original).is_err());
    assert!(signed_activate(&wire, &ledger.network_id(), &[1; 32], &[3; 32], &original).is_err());
    assert!(signed_activate(&wire, &ledger.network_id(), &[1; 32], &owner, &[8; 96]).is_err());
    let foreign = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
        iroha_crypto::Hash::new(b"foreign activation network"),
    ));
    assert!(signed_activate(&wire, &foreign, &[1; 32], &owner, &original).is_err());
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(signed_activate(&trailing, &ledger.network_id(), &[1; 32], &owner, &original).is_err());
    assert!(
        signed_activate(
            &vec![0; TRANSACTION_MAX + 1],
            &ledger.network_id(),
            &[1; 32],
            &owner,
            &original
        )
        .is_err()
    );
    let mut builder = TransactionBuilder::new(
        ledger.network_id(),
        account,
        FeePaymentIntent::authority(vec![], None),
    );
    builder.set_creation_time(Duration::from_millis(1));
    let instruction = KagemushaWalletLedgerV1::new(
        [1; 32],
        KagemushaWalletLedgerActionV1::Activate(original.clone()),
    );
    let multiple = builder
        .with_instructions([instruction.clone(), instruction])
        .sign(key.private_key())
        .encode_wire_v1()
        .unwrap();
    assert!(signed_activate(&multiple, &ledger.network_id(), &[1; 32], &owner, &original).is_err());
}

#[test]
fn activation_confirmation_requires_exact_successful_authenticated_execution() {
    for accepted in [false, true] {
        let mut ledger = NativeFinalityFixture::new_with_explicit_parameters();
        let key = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
        let transaction = signed(ledger.network_id(), [1; 32], &[7; 96], &key);
        let mut builder = BlockBuilder::new(ledger.next_header());
        builder.push_transaction(transaction.clone());
        let mut block = builder.build(BlockSignatures::default());
        let result = if accepted {
            Ok(vec![])
        } else {
            Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted("activation fixture refusal".into()),
            ))
        };
        NativeFinalityFixture::install_network_results(&mut block, vec![result]);
        let proof = ledger.certify(block);
        let verified = ledger.verifier().verify_retained_decision(&proof).unwrap();
        let (progress, actual) =
            authenticated_inclusion(&verified, &ledger.network_id(), transaction.clone()).unwrap();
        assert_eq!(actual, accepted);
        assert_eq!(progress.block_hash, *verified.block().hash().as_ref());
        let foreign = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"foreign outcome network"),
        ));
        assert!(authenticated_inclusion(&verified, &foreign, transaction.clone()).is_err());
        let result = successful_inclusion(&verified, &ledger.network_id(), transaction);
        assert_eq!(result.is_ok(), accepted);
        if let Ok(progress) = result {
            assert_eq!(progress.height, verified.height());
            assert_eq!(progress.block_hash, *verified.block().hash().as_ref());
        }
        let other = signed(ledger.network_id(), [1; 32], &[8; 96], &key);
        assert!(authenticated_inclusion(&verified, &ledger.network_id(), other.clone()).is_err());
        assert!(successful_inclusion(&verified, &ledger.network_id(), other).is_err());
        let mut changed = proof;
        changed.block_wire[0] ^= 1;
        assert!(
            ledger
                .verifier()
                .verify_retained_decision(&changed)
                .is_err()
        );
    }
}

#[test]
fn durable_confirmation_survives_publication_uncertainty_and_global_tip_change() {
    for after in [false, true] {
        let mut wallet = wallet();
        wallet.commit(bootstrap()).unwrap();
        let asset = fixture("KagemushaWalletAssetScopeV1");
        let plan = wallet.activation_plan(&asset).unwrap();
        let original = super::super::tests::output(&plan);
        wallet.finish_activation(&plan, &original).unwrap();
        let plan = wallet.activation_plan(&asset).unwrap();
        let plan = register_data(&mut wallet, &plan, &[7; 128]);
        let confirmation = confirmation_data(&mut wallet, &plan, &[7; 128]);
        let (root, manifest) = wallet.sync_manifest().unwrap();
        assert!(wallet.require_ledger_activation(&manifest).is_err());
        wallet.custody.fail_publication = Some(after);
        assert!(
            wallet
                .publish_activation_confirmation(root, manifest, &plan, &confirmation)
                .is_err()
        );
        let mut wallet = Coordinator::new(
            wallet.custody,
            wallet.archive,
            wallet.proofs,
            wallet.scheme_id,
            wallet.wallet_id,
        )
        .unwrap();
        let current = wallet.activation_plan(&asset).unwrap();
        assert_eq!(
            wallet
                .retained_activation_confirmation(&current)
                .unwrap()
                .is_some(),
            after
        );
        if !after {
            let (root, manifest) = wallet.sync_manifest().unwrap();
            wallet
                .publish_activation_confirmation(root, manifest, &current, &confirmation)
                .unwrap();
        }
        // Explicit mock manifest change represents independent main-ledger advancement.
        // A confirmation retains its own fact, not an alias to the current/global checkpoint.
        let (root, mut manifest) = wallet.sync_manifest().unwrap();
        manifest.ledger_checkpoint = Some(
            wallet
                .archive
                .write_object(b"later ordinary checkpoint", 1024)
                .unwrap(),
        );
        wallet.publish_manifest(root, &manifest).unwrap();
        wallet.require_ledger_activation(&manifest).unwrap();
        let current = wallet.activation_plan(&asset).unwrap();
        let retained = wallet
            .retained_activation_confirmation(&current)
            .unwrap()
            .unwrap();
        assert_eq!(retained.progress(), confirmation.progress());
        assert_eq!(retained.signed_transaction, confirmation.signed_transaction);
        let selected = current.confirmation.unwrap();
        wallet.archive.remove(ArchiveKey::Object(selected)).unwrap();
        assert!(matches!(
            wallet.require_ledger_activation(&manifest),
            Err(Error::WitnessLost(_))
        ));
    }
}

#[test]
fn confirmation_data_rejects_wrong_output_and_invalid_height_or_hash() {
    let mut wallet = wallet();
    wallet.commit(bootstrap()).unwrap();
    let asset = fixture("KagemushaWalletAssetScopeV1");
    let plan = wallet.activation_plan(&asset).unwrap();
    let original = super::super::tests::output(&plan);
    wallet.finish_activation(&plan, &original).unwrap();
    let plan = wallet.activation_plan(&asset).unwrap();
    let valid = confirmation_data(&mut wallet, &plan, &[7; 128]);
    valid.require(&plan).unwrap();
    let mut value = valid.clone();
    value.height = 1;
    assert!(value.require(&plan).is_err());
    let mut value = valid.clone();
    value.activation = field(99);
    assert!(value.require(&plan).is_err());
    let mut value = valid.clone();
    value.block_hash = [0; 32];
    assert!(value.require(&plan).is_err());
    let mut value = valid;
    value.signed_transaction.clear();
    assert!(value.require(&plan).is_err());
}

#[test]
fn selected_winning_finality_original_is_required_before_first_load() {
    let mut wallet = wallet();
    wallet.commit(bootstrap()).unwrap();
    let asset = fixture("KagemushaWalletAssetScopeV1");
    let plan = wallet.activation_plan(&asset).unwrap();
    let original = super::super::tests::output(&plan);
    wallet.finish_activation(&plan, &original).unwrap();
    let plan = wallet.activation_plan(&asset).unwrap();
    let plan = register_data(&mut wallet, &plan, &[7; 128]);
    let confirmation = confirmation_data(&mut wallet, &plan, &[7; 128]);
    let (root, manifest) = wallet.sync_manifest().unwrap();
    wallet
        .publish_activation_confirmation(root, manifest, &plan, &confirmation)
        .unwrap();
    let (_, manifest) = wallet.sync_manifest().unwrap();
    wallet.require_ledger_activation(&manifest).unwrap();
    wallet
        .archive
        .remove(ArchiveKey::Object(confirmation.checkpoint))
        .unwrap();
    assert!(wallet.require_ledger_activation(&manifest).is_err());
    let selected = wallet
        .activation_plan(&asset)
        .unwrap()
        .confirmation
        .unwrap();
    assert!(
        wallet
            .archive
            .read_object(&selected, CONFIRMATION_MAX)
            .is_ok()
    );
}
