//! Genuine Native checkpoint verification plus explicitly synthetic archive/custody publication.
use super::*;
use crate::kagemusha_wallet_state_v1::tests::{Wallet, bootstrap, fixture, wallet};
use iroha_data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture;

fn setup() -> (Wallet, Plan, Cursor, NativeFinalityFixture) {
    let native = NativeFinalityFixture::start("activation-verifier-cursor");
    let mut wallet = wallet();
    wallet.commit(bootstrap()).unwrap();
    let asset = fixture("KagemushaWalletAssetScopeV1");
    let plan = wallet.activation_plan(&asset).unwrap();
    let original = super::super::super::tests::output(&plan);
    wallet.finish_activation(&plan, &original).unwrap();
    let plan = wallet.activation_plan(&asset).unwrap();
    let plan = super::super::tests::register_data(&mut wallet, &plan, &[7; 128]);
    let cursor = Cursor {
        activation: plan.output.unwrap(),
        signed_transaction: vec![7; 128], // Binding DATA only; real signed Activate tested separately.
        checkpoint: native.checkpoint().encode_canonical().unwrap(),
    };
    (wallet, plan, cursor, native)
}

fn select_original(wallet: &mut Wallet, plan: &Plan, bytes: &[u8]) -> [u8; 32] {
    let (root, mut manifest) = wallet.sync_manifest().unwrap();
    let mut attempt = wallet
        .retained_activation_attempt(plan, &[7; 128])
        .unwrap()
        .unwrap();
    let address = wallet.archive.write_object(bytes, CURSOR_MAX).unwrap();
    attempt.cursor = Some(address);
    let selected = wallet.plan_with_attempt(plan, &attempt).unwrap();
    manifest.activation = Some(
        wallet
            .archive
            .write_object(&archive::encode(&selected).unwrap(), PLAN_MAX)
            .unwrap(),
    );
    wallet.publish_manifest(root, &manifest).unwrap();
    address
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
fn fresh_verifier_cursor_restores_genuine_native_checkpoint_and_exact_binding() {
    let (mut wallet, plan, cursor, native) = setup();
    let bytes = archive::encode(&cursor).unwrap();
    assert_eq!(decode_cursor(&bytes).unwrap().checkpoint, cursor.checkpoint);
    let (root, manifest) = wallet.sync_manifest().unwrap();
    wallet
        .publish_activation_cursor(root, manifest, &plan, &cursor, false)
        .unwrap();
    let mut wallet = reopen(wallet);
    let plan = wallet.activation_plan(&plan.asset).unwrap();
    let restored = wallet
        .retained_activation_cursor(&plan, &cursor.signed_transaction)
        .unwrap()
        .unwrap();
    let (_, checkpoint) = restored.restore(&native.verifier()).unwrap();
    assert_eq!(checkpoint.encode_canonical().unwrap(), cursor.checkpoint);
    assert!(wallet.retained_activation_cursor(&plan, &[8; 128]).is_err());
    let foreign = NativeFinalityFixture::start("foreign-activation-cursor");
    assert!(restored.restore(&foreign.verifier()).is_err());
}

#[test]
fn current_cursor_publication_recovers_before_and_after_durable_selection() {
    for after in [false, true] {
        let (mut wallet, plan, cursor, native) = setup();
        let (root, manifest) = wallet.sync_manifest().unwrap();
        wallet.custody.fail_publication = Some(after);
        assert!(
            wallet
                .publish_activation_cursor(root, manifest, &plan, &cursor, false)
                .is_err()
        );
        let mut wallet = reopen(wallet);
        wallet
            .clean_activation_cursor(&cursor.signed_transaction)
            .unwrap();
        let plan = wallet.activation_plan(&plan.asset).unwrap();
        let (root, manifest) = wallet.sync_manifest().unwrap();
        wallet
            .publish_activation_cursor(root, manifest, &plan, &cursor, false)
            .unwrap();
        let plan = wallet.activation_plan(&plan.asset).unwrap();
        let restored = wallet
            .retained_activation_cursor(&plan, &cursor.signed_transaction)
            .unwrap()
            .unwrap();
        let (_, checkpoint) = restored.restore(&native.verifier()).unwrap();
        assert_eq!(checkpoint.encode_canonical().unwrap(), cursor.checkpoint);
        let attempt = wallet
            .retained_activation_attempt(&plan, &cursor.signed_transaction)
            .unwrap()
            .unwrap();
        let selected = wallet
            .archive
            .read_object(&attempt.cursor.unwrap(), CURSOR_MAX)
            .unwrap();
        assert_eq!(
            decode_cursor(&selected).unwrap().checkpoint,
            cursor.checkpoint
        );
    }
}

#[test]
fn current_cursor_missing_corrupt_or_foreign_binding_never_means_absent() {
    let (mut wallet, plan, cursor, native) = setup();
    let mut changed = cursor.clone();
    changed.activation[0] ^= 1;
    assert!(
        decode_cursor(&archive::encode(&changed).unwrap())
            .unwrap()
            .require(&plan, &cursor.signed_transaction)
            .is_err()
    );
    assert!(
        decode_cursor(&archive::encode(&cursor).unwrap())
            .unwrap()
            .require(&plan, &[8; 128])
            .is_err()
    );
    let mut missing_checkpoint = cursor.clone();
    missing_checkpoint.checkpoint.clear();
    let decoded = decode_cursor(&archive::encode(&missing_checkpoint).unwrap()).unwrap();
    assert!(decoded.require(&plan, &cursor.signed_transaction).is_err());
    assert!(decoded.restore(&native.verifier()).is_err());
    let mut changed_checkpoint = cursor.clone();
    changed_checkpoint.checkpoint[0] ^= 1;
    assert!(
        decode_cursor(&archive::encode(&changed_checkpoint).unwrap())
            .unwrap()
            .restore(&native.verifier())
            .is_err()
    );
    let old = archive::encode(&cursor).unwrap();
    let mut trailing = old.clone();
    trailing.push(0);
    let selected = select_original(&mut wallet, &plan, &trailing);
    let current = wallet.activation_plan(&plan.asset).unwrap();
    assert!(
        wallet
            .retained_activation_cursor(&current, &cursor.signed_transaction)
            .is_err()
    );
    assert_eq!(
        wallet.archive.read_object(&selected, CURSOR_MAX).unwrap(),
        trailing
    );
    wallet.archive.remove(ArchiveKey::Object(selected)).unwrap();
    assert!(
        wallet
            .retained_activation_cursor(&current, &cursor.signed_transaction)
            .is_err()
    );
    assert!(decode_cursor(b"unknown cursor schema").is_err());
}

#[test]
fn confirmation_preserves_selected_attempt_cursor_and_its_independent_winning_evidence() {
    let (mut wallet, plan, cursor, _native) = setup();
    let old = archive::encode(&cursor).unwrap();
    let address = select_original(&mut wallet, &plan, &old);
    let plan = wallet.activation_plan(&plan.asset).unwrap();
    let confirmation =
        super::super::tests::confirmation_data(&mut wallet, &plan, &cursor.signed_transaction);
    let (root, manifest) = wallet.sync_manifest().unwrap();
    wallet
        .publish_activation_confirmation(root, manifest, &plan, &confirmation)
        .unwrap();
    wallet
        .clean_activation_cursor(&cursor.signed_transaction)
        .unwrap();
    assert_eq!(
        wallet.archive.read_object(&address, CURSOR_MAX).unwrap(),
        old
    );
    let current = wallet.activation_plan(&plan.asset).unwrap();
    let attempt = wallet
        .retained_activation_attempt(&current, &cursor.signed_transaction)
        .unwrap()
        .unwrap();
    assert_eq!(attempt.cursor, Some(address));
    assert!(attempt.retired_cursor.is_none());
    let retained = wallet
        .retained_activation_confirmation(&current)
        .unwrap()
        .unwrap();
    assert_eq!(retained.signed_transaction, cursor.signed_transaction);
    assert!(
        wallet
            .archive
            .read_object(&retained.checkpoint, MAX_FINALITY_CHECKPOINT_BYTES)
            .is_ok()
    );
}

#[test]
fn unsupported_selected_cursor_is_preserved_and_never_treated_as_absent() {
    let (mut wallet, plan, cursor, _native) = setup();
    let bytes = b"unsupported activation cursor schema";
    let address = select_original(&mut wallet, &plan, bytes);
    let selected = wallet.activation_plan(&plan.asset).unwrap();
    let before = wallet.manifest().unwrap().0;
    assert!(
        wallet
            .retained_activation_cursor(&selected, &cursor.signed_transaction)
            .is_err()
    );
    assert_eq!(wallet.manifest().unwrap().0, before);
    assert_eq!(
        wallet.archive.read_object(&address, CURSOR_MAX).unwrap(),
        bytes
    );
}

#[test]
fn multiple_attempts_have_independent_cursors_and_only_replace_their_own_prefix() {
    let (mut wallet, plan, first, mut native) = setup();
    let second_wire = vec![8; 128];
    let plan = super::super::tests::register_data(&mut wallet, &plan, &second_wire);
    let second = Cursor {
        activation: first.activation,
        signed_transaction: second_wire.clone(),
        checkpoint: first.checkpoint.clone(),
    };
    let (root, manifest) = wallet.sync_manifest().unwrap();
    wallet
        .publish_activation_cursor(root, manifest, &plan, &first, false)
        .unwrap();
    let plan = wallet.activation_plan(&plan.asset).unwrap();
    let (root, manifest) = wallet.sync_manifest().unwrap();
    wallet
        .publish_activation_cursor(root, manifest, &plan, &second, false)
        .unwrap();
    let plan = wallet.activation_plan(&plan.asset).unwrap();
    let first_address = wallet
        .retained_activation_attempt(&plan, &first.signed_transaction)
        .unwrap()
        .unwrap()
        .cursor
        .unwrap();
    let second_address = wallet
        .retained_activation_attempt(&plan, &second_wire)
        .unwrap()
        .unwrap()
        .cursor
        .unwrap();
    let block = native.block_with_submitted_work(native.next_header());
    native.certify(block);
    let later = Cursor {
        checkpoint: native.checkpoint().encode_canonical().unwrap(),
        ..first.clone()
    };
    let (root, manifest) = wallet.sync_manifest().unwrap();
    wallet
        .publish_activation_cursor(root, manifest, &plan, &later, false)
        .unwrap();
    assert!(
        wallet
            .archive
            .get(ArchiveKey::Object(first_address), CURSOR_MAX)
            .unwrap()
            .is_none()
    );
    assert!(
        wallet
            .archive
            .read_object(&second_address, CURSOR_MAX)
            .is_ok()
    );
    let plan = wallet.activation_plan(&plan.asset).unwrap();
    let second_restored = wallet
        .retained_activation_cursor(&plan, &second_wire)
        .unwrap()
        .unwrap();
    assert_eq!(second_restored.checkpoint, second.checkpoint);
    assert!(wallet.retained_activation_cursor(&plan, &[9; 128]).is_err());
    let mut wallet = reopen(wallet);
    let plan = wallet.activation_plan(&plan.asset).unwrap();
    assert_eq!(
        wallet
            .retained_activation_cursor(&plan, &first.signed_transaction)
            .unwrap()
            .unwrap()
            .checkpoint,
        later.checkpoint
    );
    assert_eq!(
        wallet
            .retained_activation_cursor(&plan, &second_wire)
            .unwrap()
            .unwrap()
            .checkpoint,
        second.checkpoint
    );
}

#[test]
fn attempt_admission_recovers_uncertain_publication_and_fences_stale_concurrent_plan() {
    for after in [false, true] {
        let (mut wallet, plan, first, _native) = setup();
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
            super::super::tests::register_data(&mut wallet, &current, &wire);
        }
        assert!(
            wallet
                .publish_activation_attempt(root, manifest, &plan, &[9; 128])
                .is_err()
        );
        let current = wallet.activation_plan(&plan.asset).unwrap();
        assert!(
            wallet
                .retained_activation_attempt(&current, &first.signed_transaction)
                .unwrap()
                .is_some()
        );
        assert!(
            wallet
                .retained_activation_attempt(&current, &wire)
                .unwrap()
                .is_some()
        );
    }
}

#[test]
fn either_registered_attempt_can_confirm_family_without_losing_other_originals() {
    for winner in [7, 8] {
        let (mut wallet, plan, first, _native) = setup();
        let plan = super::super::tests::register_data(&mut wallet, &plan, &[8; 128]);
        let confirmation =
            super::super::tests::confirmation_data(&mut wallet, &plan, &[winner; 128]);
        let (root, manifest) = wallet.sync_manifest().unwrap();
        wallet
            .publish_activation_confirmation(root, manifest, &plan, &confirmation)
            .unwrap();
        let mut wallet = reopen(wallet);
        let plan = wallet.activation_plan(&plan.asset).unwrap();
        let (_, manifest) = wallet.sync_manifest().unwrap();
        wallet.require_ledger_activation(&manifest).unwrap();
        assert!(
            wallet
                .retained_activation_attempt(&plan, &first.signed_transaction)
                .unwrap()
                .is_some()
        );
        assert!(
            wallet
                .retained_activation_attempt(&plan, &[8; 128])
                .unwrap()
                .is_some()
        );
        assert_eq!(
            wallet
                .retained_activation_confirmation(&plan)
                .unwrap()
                .unwrap()
                .signed_transaction,
            vec![winner; 128]
        );
        let (root, manifest) = wallet.sync_manifest().unwrap();
        assert!(
            wallet
                .publish_activation_attempt(root, manifest, &plan, &[9; 128])
                .is_err()
        );
    }
}

#[test]
fn rejected_attempt_retains_terminal_checkpoint_without_blocking_another_attempt() {
    // Custody state transitions use synthetic attempt DATA; actual rejected execution
    // classification is independently exercised by the genuine finality tests above.
    let (mut wallet, plan, first, mut native) = setup();
    let plan = super::super::tests::register_data(&mut wallet, &plan, &[8; 128]);
    let block = native.block_with_submitted_work(native.next_header());
    native.certify(block);
    let terminal = Cursor {
        checkpoint: native.checkpoint().encode_canonical().unwrap(),
        ..first.clone()
    };
    let (root, manifest) = wallet.sync_manifest().unwrap();
    wallet
        .publish_activation_cursor(root, manifest, &plan, &terminal, true)
        .unwrap();
    let mut wallet = reopen(wallet);
    let plan = wallet.activation_plan(&plan.asset).unwrap();
    let rejected = wallet
        .retained_activation_attempt(&plan, &first.signed_transaction)
        .unwrap()
        .unwrap();
    assert!(rejected.rejected);
    let rejected_address = rejected.cursor.unwrap();
    let retained = wallet
        .retained_activation_cursor(&plan, &first.signed_transaction)
        .unwrap()
        .unwrap();
    assert_eq!(retained.checkpoint, terminal.checkpoint);
    retained.restore(&native.verifier()).unwrap();
    let (root, manifest) = wallet.sync_manifest().unwrap();
    assert!(wallet.require_ledger_activation(&manifest).is_err());
    assert!(
        wallet
            .publish_activation_cursor(root, manifest.clone(), &plan, &first, false)
            .is_err()
    );
    let false_confirmation =
        super::super::tests::confirmation_data(&mut wallet, &plan, &first.signed_transaction);
    assert!(
        wallet
            .publish_activation_confirmation(root, manifest, &plan, &false_confirmation)
            .is_err()
    );
    let second = Cursor {
        signed_transaction: vec![8; 128],
        ..first
    };
    let (root, manifest) = wallet.sync_manifest().unwrap();
    wallet
        .publish_activation_cursor(root, manifest, &plan, &second, false)
        .unwrap();
    let plan = wallet.activation_plan(&plan.asset).unwrap();
    let winner =
        super::super::tests::confirmation_data(&mut wallet, &plan, &second.signed_transaction);
    let (root, manifest) = wallet.sync_manifest().unwrap();
    wallet
        .publish_activation_confirmation(root, manifest, &plan, &winner)
        .unwrap();
    let mut wallet = reopen(wallet);
    let plan = wallet.activation_plan(&plan.asset).unwrap();
    let (_, manifest) = wallet.sync_manifest().unwrap();
    wallet.require_ledger_activation(&manifest).unwrap();
    assert_eq!(
        wallet
            .retained_activation_confirmation(&plan)
            .unwrap()
            .unwrap()
            .signed_transaction,
        second.signed_transaction
    );
    assert!(
        wallet
            .retained_activation_attempt(&plan, &[7; 128])
            .unwrap()
            .unwrap()
            .rejected
    );
    assert!(
        wallet
            .archive
            .read_object(&rejected_address, CURSOR_MAX)
            .is_ok()
    );
}

#[test]
fn cleanup_rejects_another_attempts_selected_checkpoint_without_deleting_it() {
    let (mut wallet, plan, first, _native) = setup();
    let plan = super::super::tests::register_data(&mut wallet, &plan, &[8; 128]);
    let (root, manifest) = wallet.sync_manifest().unwrap();
    wallet
        .publish_activation_cursor(root, manifest, &plan, &first, false)
        .unwrap();
    let plan = wallet.activation_plan(&plan.asset).unwrap();
    let first_address = wallet
        .retained_activation_attempt(&plan, &first.signed_transaction)
        .unwrap()
        .unwrap()
        .cursor
        .unwrap();
    let mut second = wallet
        .retained_activation_attempt(&plan, &[8; 128])
        .unwrap()
        .unwrap();
    second.retired_cursor = Some(first_address);
    let changed = wallet.plan_with_attempt(&plan, &second).unwrap();
    let (root, mut manifest) = wallet.sync_manifest().unwrap();
    manifest.activation = Some(
        wallet
            .archive
            .write_object(&archive::encode(&changed).unwrap(), PLAN_MAX)
            .unwrap(),
    );
    wallet.publish_manifest(root, &manifest).unwrap();
    let before = wallet.manifest().unwrap().0;
    assert!(wallet.clean_activation_cursor(&[8; 128]).is_err());
    assert_eq!(wallet.manifest().unwrap().0, before);
    assert_eq!(
        wallet
            .archive
            .read_object(&first_address, CURSOR_MAX)
            .unwrap(),
        archive::encode(&first).unwrap()
    );
}

#[test]
fn attempt_index_keeps_individual_originals_bounded_without_a_small_total_attempt_limit() {
    let (mut wallet, mut plan, first, _native) = setup();
    for n in 8..72 {
        plan = super::super::tests::register_data(&mut wallet, &plan, &[n; 128]);
    }
    let mut wallet = reopen(wallet);
    let plan = wallet.activation_plan(&plan.asset).unwrap();
    assert_eq!(
        wallet
            .retained_activation_attempt(&plan, &first.signed_transaction)
            .unwrap()
            .unwrap()
            .signed_transaction,
        attempt_key(&first.signed_transaction).unwrap()
    );
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
fn compact_selection_retains_one_exact_large_signed_original_and_fails_on_its_loss() {
    let (mut wallet, plan, first, _native) = setup();
    let large_wire = vec![9; TRANSACTION_MAX];
    let plan = super::super::tests::register_data(&mut wallet, &plan, &large_wire);
    let key = attempt_key(&large_wire).unwrap();
    let before = plan
        .attempts
        .get(&mut wallet.archive, &key)
        .unwrap()
        .unwrap();
    assert!(before.len() <= crate::kagemusha_wallet_state_v1::index::INDEX_VALUE_LIMIT);
    let original = wallet.archive.read_object(&key, TRANSACTION_MAX).unwrap();
    assert_eq!(original, large_wire);
    let cursor = Cursor {
        signed_transaction: large_wire.clone(),
        ..first
    };
    let (root, manifest) = wallet.sync_manifest().unwrap();
    wallet
        .publish_activation_cursor(root, manifest, &plan, &cursor, false)
        .unwrap();
    let plan = wallet.activation_plan(&plan.asset).unwrap();
    let after = plan
        .attempts
        .get(&mut wallet.archive, &key)
        .unwrap()
        .unwrap();
    assert!(after.len() <= crate::kagemusha_wallet_state_v1::index::INDEX_VALUE_LIMIT);
    assert_ne!(before, after);
    let selection: Attempt = archive::decode(&after).unwrap();
    assert_eq!(selection.signed_transaction, key);
    assert_eq!(
        wallet.archive.read_object(&key, TRANSACTION_MAX).unwrap(),
        original
    );
    wallet.archive.remove(ArchiveKey::Object(key)).unwrap();
    let selected = wallet.manifest().unwrap().0;
    assert!(
        wallet
            .retained_activation_attempt(&plan, &large_wire)
            .is_err()
    );
    assert_eq!(wallet.manifest().unwrap().0, selected);
    assert!(
        wallet
            .archive
            .read_object(&selection.cursor.unwrap(), CURSOR_MAX)
            .is_ok()
    );
}
