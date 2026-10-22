//! Real account signatures and genuine native certificates and membership, plus explicit mock
//! custody fault tests. Fixture execution rows are synthetic; these do not claim production
//! World execution. Direct verification against a wallet's selected epoch is covered by the
//! shared outcome tests; here originals are verified by an independent genesis reader.
use super::super::super::ledger_outcome::tests::{
    bytes, certify, genesis, original, rejected, signed_action, verified,
};
use super::*;
use crate::kagemusha_wallet_state_v1::tests::{Wallet, bootstrap, field, fixture, wallet};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::AccountId,
    sumeragi_finality::test_fixtures::NativeFinalityFixture,
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use std::time::Duration;

fn signed(
    network: NetworkId,
    scheme: [u8; 32],
    original: &[u8],
    key: &KeyPair,
) -> SignedTransaction {
    let mut builder = TransactionBuilder::new(
        network,
        AccountId::new(key.public_key().clone()),
        FeePaymentIntent::authority(vec![], None),
    );
    builder.set_creation_time(Duration::from_millis(1));
    builder
        .with_instructions([KagemushaWalletLedgerV1::new(
            scheme,
            KagemushaWalletLedgerActionV1::Activate(original.to_vec()),
        )])
        .sign(key.private_key())
}

/// One genuinely signed outer Activate attempt over a plan's retained inner original and the
/// exact original Torii serves for its certified block.
pub(super) struct Genuine {
    pub(super) wire: Vec<u8>,
    pub(super) signed: SignedTransaction,
    pub(super) bytes: Vec<u8>,
    pub(super) outcome: VerifiedKagemushaLedgerOutcomeV1,
}

/// Certify `count` signed attempts over `plan`'s Activate with the given synthetic results.
pub(super) fn genuine(plan: &Plan, accepted: &[bool]) -> Vec<Genuine> {
    let mut native = NativeFinalityFixture::start("activation-direct-finality");
    let key = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let inner = super::super::tests::output(plan);
    let transactions: Vec<_> = (0..accepted.len())
        .map(|offset| {
            signed_action(
                &native,
                &key,
                plan.credential.body.scheme_id,
                KagemushaWalletLedgerActionV1::Activate(inner.clone()),
                offset as u64,
            )
        })
        .collect();
    let block = certify(
        &mut native,
        &transactions,
        accepted
            .iter()
            .map(|accepted| if *accepted { Ok(vec![]) } else { rejected() })
            .collect(),
    );
    transactions
        .into_iter()
        .enumerate()
        .map(|(index, signed)| {
            let served = original(&block, u32::try_from(index).unwrap());
            Genuine {
                wire: signed.encode_wire_v1().unwrap(),
                outcome: verified(&native, &served, &signed),
                bytes: bytes(&served),
                signed,
            }
        })
        .collect()
}

// Synthetic custody publishers below exercise retention, never installed authorization.
pub(super) fn register_data(wallet: &mut Wallet, plan: &Plan, wire: &[u8]) -> Plan {
    let (root, manifest) = wallet.sync_manifest().unwrap();
    wallet
        .publish_activation_attempt(root, manifest, plan, wire)
        .unwrap();
    wallet.activation_plan(&plan.asset).unwrap()
}
pub(super) fn confirmation_data(
    wallet: &mut Wallet,
    plan: &Plan,
    attempt: &Genuine,
) -> Confirmation {
    assert!(attempt.outcome.accepted());
    Confirmation {
        version: 1,
        activation: plan.output.unwrap(),
        signed_transaction: attempt.wire.clone(),
        outcome: wallet
            .write_ledger_original(&attempt.outcome, &attempt.bytes)
            .unwrap(),
    }
}
fn activated_plan(wallet: &mut Wallet) -> Plan {
    wallet.commit(bootstrap()).unwrap();
    let asset = fixture("KagemushaWalletAssetScopeV1");
    let plan = wallet.activation_plan(&asset).unwrap();
    let original = super::super::tests::output(&plan);
    wallet.finish_activation(&plan, &original).unwrap();
    wallet.activation_plan(&asset).unwrap()
}
fn reopen(wallet: Wallet) -> Wallet {
    Coordinator::new(
        wallet.custody,
        wallet.archive,
        wallet.proofs,
        wallet.scheme_id,
        wallet.wallet_id,
    )
    .unwrap()
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
    let foreign = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
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
fn activation_signed_original_read_refusal_preserves_exact_wire_and_signature() {
    let ledger = NativeFinalityFixture::new_with_explicit_parameters();
    let key = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let account = AccountId::new(key.public_key().clone());
    let owner = kagemusha_wallet_account_digest_v1(&account).unwrap();
    let original = vec![7; 96]; // Inner Activate DATA; only the genuine outer read/signature is tested.
    let transaction = signed(ledger.network_id(), [1; 32], &original, &key);
    let wire = transaction.encode_wire_v1().unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64);
    let refused = norito::with_decode_limits_scope(limits, || {
        signed_activate(&wire, &ledger.network_id(), &[1; 32], &owner, &original)
    });
    assert!(matches!(refused, Err(Error::DecodeResource(ref cause))
        if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
    let retried =
        signed_activate(&wire, &ledger.network_id(), &[1; 32], &owner, &original).unwrap();
    assert_eq!(retried, transaction);
    assert_eq!(retried.signature_count(), 1);
    assert_eq!(retried.encode_wire_v1().unwrap(), wire);
    assert!(matches!(
        signed_activate(&[0], &ledger.network_id(), &[1; 32], &owner, &original),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn retained_attempt_awaits_under_the_entrypoint_native_derives_from_its_wire() {
    let mut wallet = wallet();
    let plan = activated_plan(&mut wallet);
    let attempts = genuine(&plan, &[true, true]);
    let plan = register_data(&mut wallet, &plan, &attempts[0].wire);
    let publications = wallet.custody.publication_calls;
    assert_eq!(
        wallet
            .activation_outcome(&plan, &attempts[0].wire, &attempts[0].signed)
            .unwrap(),
        LedgerAttemptOutcomeV1::Awaiting {
            entrypoint: *attempts[0].signed.hash_as_entrypoint().as_ref()
        }
    );
    assert_eq!(wallet.custody.publication_calls, publications);
    // An unretained wire is an error, never Awaiting.
    assert!(matches!(
        wallet.activation_outcome(&plan, &attempts[1].wire, &attempts[1].signed),
        Err(Error::Invalid("activation attempt not retained"))
    ));
}

#[test]
fn durable_confirmation_survives_publication_uncertainty_and_global_tip_change() {
    for after in [false, true] {
        let mut wallet = wallet();
        let plan = activated_plan(&mut wallet);
        let attempts = genuine(&plan, &[true]);
        let attempt = &attempts[0];
        let asset = plan.asset.clone();
        let plan = register_data(&mut wallet, &plan, &attempt.wire);
        let confirmation = confirmation_data(&mut wallet, &plan, attempt);
        let (root, manifest) = wallet.sync_manifest().unwrap();
        assert!(wallet.require_ledger_activation(&manifest).is_err());
        wallet.custody.fail_publication = Some(after);
        assert!(
            wallet
                .publish_activation_confirmation(root, manifest, &plan, &confirmation)
                .is_err()
        );
        let mut wallet = reopen(wallet);
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
        assert_eq!(retained.outcome, confirmation.outcome);
        assert_eq!(retained.signed_transaction, confirmation.signed_transaction);
        assert_eq!(
            wallet
                .activation_outcome(&current, &attempt.wire, &attempt.signed)
                .unwrap(),
            LedgerAttemptOutcomeV1::Confirmed(confirmation.outcome.commit())
        );
        let selected = current.confirmation.unwrap();
        wallet.archive.remove(ArchiveKey::Object(selected)).unwrap();
        assert!(matches!(
            wallet.require_ledger_activation(&manifest),
            Err(Error::WitnessLost(_))
        ));
    }
}

#[test]
fn confirmation_binding_rejects_wrong_output_wire_and_every_outcome_binding() {
    let mut wallet = wallet();
    let plan = activated_plan(&mut wallet);
    let attempts = genuine(&plan, &[true]);
    let plan = register_data(&mut wallet, &plan, &attempts[0].wire);
    let valid = confirmation_data(&mut wallet, &plan, &attempts[0]);
    valid.require(&plan).unwrap();
    wallet
        .require_activation_confirmation_original(&plan, &valid)
        .unwrap();
    let mut value = valid.clone();
    value.activation = field(99);
    assert!(value.require(&plan).is_err());
    let mut value = valid.clone();
    value.version = 2;
    assert!(value.require(&plan).is_err());
    let mut value = valid.clone();
    value.signed_transaction.clear();
    assert!(value.require(&plan).is_err());
    for binding in 0..7 {
        let mut value = valid.clone();
        value.outcome = value.outcome.tampered(binding);
        assert!(matches!(
            wallet.require_activation_confirmation_original(&plan, &value),
            Err(Error::WitnessLost(_))
        ));
    }
}

#[test]
fn selected_winning_finality_original_is_required_before_first_load() {
    let mut wallet = wallet();
    let plan = activated_plan(&mut wallet);
    let attempts = genuine(&plan, &[true]);
    let plan = register_data(&mut wallet, &plan, &attempts[0].wire);
    let confirmation = confirmation_data(&mut wallet, &plan, &attempts[0]);
    let (root, manifest) = wallet.sync_manifest().unwrap();
    wallet
        .publish_activation_confirmation(root, manifest, &plan, &confirmation)
        .unwrap();
    let (_, manifest) = wallet.sync_manifest().unwrap();
    wallet.require_ledger_activation(&manifest).unwrap();
    let finality = wallet
        .archive
        .write_object(
            &attempts[0].bytes,
            KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1,
        )
        .unwrap();
    wallet.archive.remove(ArchiveKey::Object(finality)).unwrap();
    assert!(matches!(
        wallet.require_ledger_activation(&manifest),
        Err(Error::WitnessLost(_))
    ));
    let selected = wallet
        .activation_plan(&plan.asset)
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

#[test]
fn rejected_attempt_is_retained_alone_and_another_attempt_confirms_the_family() {
    let mut wallet = wallet();
    let plan = activated_plan(&mut wallet);
    let attempts = genuine(&plan, &[false, true]);
    let (refused, applied) = (&attempts[0], &attempts[1]);
    assert!(!refused.outcome.accepted());
    let plan = register_data(&mut wallet, &plan, &refused.wire);
    let plan = register_data(&mut wallet, &plan, &applied.wire);
    let mut attempt = wallet
        .retained_activation_attempt(&plan, &refused.wire)
        .unwrap()
        .unwrap();
    let rejection = wallet
        .write_ledger_original(&refused.outcome, &refused.bytes)
        .unwrap();
    attempt.rejection = Some(rejection);
    let (root, manifest) = wallet.sync_manifest().unwrap();
    wallet
        .publish_activation_rejection(root, manifest, &plan, &attempt)
        .unwrap();
    let plan = wallet.activation_plan(&plan.asset).unwrap();
    assert_eq!(
        wallet
            .activation_outcome(&plan, &refused.wire, &refused.signed)
            .unwrap(),
        LedgerAttemptOutcomeV1::Rejected(rejection.commit())
    );
    // The rejected attempt never activates the wallet or blocks another attempt.
    let (_, manifest) = wallet.sync_manifest().unwrap();
    assert!(wallet.require_ledger_activation(&manifest).is_err());
    assert!(matches!(
        wallet.activation_outcome(&plan, &applied.wire, &applied.signed),
        Ok(LedgerAttemptOutcomeV1::Awaiting { .. })
    ));
    let on_rejected = Confirmation {
        version: 1,
        activation: plan.output.unwrap(),
        signed_transaction: refused.wire.clone(),
        outcome: wallet
            .write_ledger_original(&applied.outcome, &applied.bytes)
            .unwrap(),
    };
    assert!(matches!(
        wallet.require_activation_confirmation_original(&plan, &on_rejected),
        Err(Error::WitnessLost(_))
    ));
    let confirmation = confirmation_data(&mut wallet, &plan, applied);
    let (root, manifest) = wallet.sync_manifest().unwrap();
    wallet
        .publish_activation_confirmation(root, manifest, &plan, &confirmation)
        .unwrap();
    let plan = wallet.activation_plan(&plan.asset).unwrap();
    let (_, manifest) = wallet.sync_manifest().unwrap();
    wallet.require_ledger_activation(&manifest).unwrap();
    for attempt in [refused, applied] {
        assert_eq!(
            wallet
                .activation_outcome(&plan, &attempt.wire, &attempt.signed)
                .unwrap(),
            LedgerAttemptOutcomeV1::Confirmed(confirmation.outcome.commit())
        );
    }
}

#[test]
fn retained_outcomes_answer_offered_originals_without_a_new_write() {
    let mut wallet = wallet();
    let plan = activated_plan(&mut wallet);
    let attempts = genuine(&plan, &[false, true]);
    let (refused, applied) = (&attempts[0], &attempts[1]);
    let plan = register_data(&mut wallet, &plan, &refused.wire);
    let plan = register_data(&mut wallet, &plan, &applied.wire);
    let mut attempt = wallet
        .retained_activation_attempt(&plan, &refused.wire)
        .unwrap()
        .unwrap();
    let rejection = wallet
        .write_ledger_original(&refused.outcome, &refused.bytes)
        .unwrap();
    attempt.rejection = Some(rejection);
    let (root, manifest) = wallet.sync_manifest().unwrap();
    wallet
        .publish_activation_rejection(root, manifest, &plan, &attempt)
        .unwrap();
    let plan = wallet.activation_plan(&plan.asset).unwrap();
    // This mock's ledger scope is not the fixture genesis, so these paths succeed only
    // because they never verify: the exact retained original is idempotent.
    let unrelated = genesis(&NativeFinalityFixture::start("unrelated-genesis"));
    let publications = wallet.custody.publication_calls;
    let (root, manifest) = wallet.sync_manifest().unwrap();
    assert_eq!(
        wallet
            .ingest_activation_original(
                root,
                manifest,
                &unrelated,
                &plan,
                &refused.wire,
                &refused.signed,
                &refused.bytes
            )
            .unwrap(),
        LedgerAttemptIngestV1::Outcome(LedgerAttemptOutcomeV1::Rejected(rejection.commit()))
    );
    // Another original must verify first; an unverifiable one is an error and writes nothing.
    let (root, manifest) = wallet.sync_manifest().unwrap();
    assert!(
        wallet
            .ingest_activation_original(
                root,
                manifest,
                &unrelated,
                &plan,
                &refused.wire,
                &refused.signed,
                &applied.bytes
            )
            .is_err()
    );
    assert_eq!(wallet.custody.publication_calls, publications);
    let confirmation = confirmation_data(&mut wallet, &plan, applied);
    let (root, manifest) = wallet.sync_manifest().unwrap();
    wallet
        .publish_activation_confirmation(root, manifest, &plan, &confirmation)
        .unwrap();
    let plan = wallet.activation_plan(&plan.asset).unwrap();
    let publications = wallet.custody.publication_calls;
    // Once the family is confirmed, any offered bytes for any retained attempt answer the
    // retained confirmation without verification or a write.
    for (attempt, offered) in [(refused, vec![0; 7]), (applied, applied.bytes.clone())] {
        let (root, manifest) = wallet.sync_manifest().unwrap();
        assert_eq!(
            wallet
                .ingest_activation_original(
                    root,
                    manifest,
                    &unrelated,
                    &plan,
                    &attempt.wire,
                    &attempt.signed,
                    &offered
                )
                .unwrap(),
            LedgerAttemptIngestV1::Outcome(LedgerAttemptOutcomeV1::Confirmed(
                confirmation.outcome.commit()
            ))
        );
    }
    assert_eq!(wallet.custody.publication_calls, publications);
}

#[test]
fn activation_confirmation_original_refusal_retries_the_exact_selected_original() {
    let mut wallet = wallet();
    let plan = activated_plan(&mut wallet);
    let attempts = genuine(&plan, &[true]);
    let plan = register_data(&mut wallet, &plan, &attempts[0].wire);
    let confirmation = confirmation_data(&mut wallet, &plan, &attempts[0]);
    let exact_confirmation = archive::encode(&confirmation).unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64);
    let (root, manifest) = wallet.sync_manifest().unwrap();
    let manifest_bytes = archive::encode(&manifest).unwrap();
    let refused = norito::with_decode_limits_scope(limits, || {
        wallet.publish_activation_confirmation(root, manifest, &plan, &confirmation)
    });
    assert!(matches!(refused, Err(Error::DecodeResource(ref cause))
        if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
    let (current_root, manifest) = wallet.sync_manifest().unwrap();
    assert_eq!(current_root, root);
    assert_eq!(archive::encode(&manifest).unwrap(), manifest_bytes);
    assert!(
        wallet
            .retained_activation_confirmation(&plan)
            .unwrap()
            .is_none()
    );
    wallet
        .publish_activation_confirmation(root, manifest, &plan, &confirmation)
        .unwrap();
    let selected = wallet.activation_plan(&plan.asset).unwrap();
    let retained = wallet
        .retained_activation_confirmation(&selected)
        .unwrap()
        .unwrap();
    assert_eq!(archive::encode(&retained).unwrap(), exact_confirmation);
}

#[test]
fn attempt_admission_recovers_uncertain_publication_and_fences_stale_concurrent_plan() {
    for after in [false, true] {
        let mut wallet = wallet();
        let plan = activated_plan(&mut wallet);
        let first = vec![7; 128];
        let plan = register_data(&mut wallet, &plan, &first);
        let wire = vec![8; 128];
        let (root, manifest) = wallet.sync_manifest().unwrap();
        wallet.custody.fail_publication = Some(after);
        assert!(
            wallet
                .publish_activation_attempt(root, manifest.clone(), &plan, &wire)
                .is_err()
        );
        let mut wallet = reopen(wallet);
        let current = wallet.activation_plan(&plan.asset).unwrap();
        assert_eq!(
            wallet
                .retained_activation_attempt(&current, &wire)
                .unwrap()
                .is_some(),
            after
        );
        if !after {
            register_data(&mut wallet, &current, &wire);
        }
        assert!(
            wallet
                .publish_activation_attempt(root, manifest, &plan, &[9; 128])
                .is_err()
        );
        let current = wallet.activation_plan(&plan.asset).unwrap();
        for retained in [&first, &wire] {
            assert!(
                wallet
                    .retained_activation_attempt(&current, retained)
                    .unwrap()
                    .is_some()
            );
        }
    }
}

#[test]
fn attempt_index_keeps_individual_originals_bounded_without_a_small_total_attempt_limit() {
    let mut wallet = wallet();
    let mut plan = activated_plan(&mut wallet);
    for n in 8..72 {
        plan = register_data(&mut wallet, &plan, &[n; 128]);
    }
    let mut wallet = reopen(wallet);
    let plan = wallet.activation_plan(&plan.asset).unwrap();
    for n in 8..72 {
        assert_eq!(
            wallet
                .retained_activation_attempt(&plan, &[n; 128])
                .unwrap()
                .unwrap()
                .signed_transaction,
            attempt_key(&[n; 128]).unwrap()
        );
    }
    let (root, manifest) = wallet.sync_manifest().unwrap();
    for wire in [Vec::new(), vec![7; TRANSACTION_MAX + 1]] {
        assert!(
            wallet
                .publish_activation_attempt(root, manifest.clone(), &plan, &wire)
                .is_err()
        );
        assert_eq!(wallet.manifest().unwrap().0, root);
    }
}

#[test]
fn rejected_attempt_with_a_large_signed_original_fits_one_index_leaf_and_fails_on_its_loss() {
    let mut wallet = wallet();
    let plan = activated_plan(&mut wallet);
    let attempts = genuine(&plan, &[false]);
    let refused = &attempts[0];
    let rejection = wallet
        .write_ledger_original(&refused.outcome, &refused.bytes)
        .unwrap();
    let large_wire = vec![9; TRANSACTION_MAX];
    let plan = register_data(&mut wallet, &plan, &large_wire);
    let key = attempt_key(&large_wire).unwrap();
    let mut attempt = wallet
        .retained_activation_attempt(&plan, &large_wire)
        .unwrap()
        .unwrap();
    attempt.rejection = Some(rejection);
    let (root, manifest) = wallet.sync_manifest().unwrap();
    wallet
        .publish_activation_rejection(root, manifest, &plan, &attempt)
        .unwrap();
    let plan = wallet.activation_plan(&plan.asset).unwrap();
    let leaf = plan
        .attempts
        .get(&mut wallet.archive, &key)
        .unwrap()
        .unwrap();
    assert!(leaf.len() <= crate::kagemusha_wallet_state_v1::index::INDEX_VALUE_LIMIT);
    let selection: Attempt = archive::decode(&leaf).unwrap();
    assert_eq!(selection.rejection, Some(rejection));
    assert_eq!(
        wallet.archive.read_object(&key, TRANSACTION_MAX).unwrap(),
        large_wire
    );
    wallet.archive.remove(ArchiveKey::Object(key)).unwrap();
    let selected = wallet.manifest().unwrap().0;
    assert!(
        wallet
            .retained_activation_attempt(&plan, &large_wire)
            .is_err()
    );
    assert_eq!(wallet.manifest().unwrap().0, selected);
}

impl Wallet {
    /// Install a genuine certified activation over the synthetic plan for coordinator-boundary
    /// tests only. Its certificate is verified by an independent fixture genesis reader.
    pub(in crate::kagemusha_wallet_state_v1) fn confirm_mock_activation_for_intake(&mut self) {
        let asset = fixture("KagemushaWalletAssetScopeV1");
        let plan = self.activation_plan(&asset).unwrap();
        let original = super::super::tests::output(&plan);
        self.finish_activation(&plan, &original).unwrap();
        let plan = self.activation_plan(&asset).unwrap();
        let attempts = genuine(&plan, &[true]);
        let attempt = &attempts[0];
        let plan = register_data(self, &plan, &attempt.wire);
        let confirmation = confirmation_data(self, &plan, attempt);
        let (root, manifest) = self.sync_manifest().unwrap();
        self.publish_activation_confirmation(root, manifest, &plan, &confirmation)
            .unwrap();
        let (_, manifest) = self.sync_manifest().unwrap();
        self.require_ledger_activation(&manifest).unwrap();
    }
}
