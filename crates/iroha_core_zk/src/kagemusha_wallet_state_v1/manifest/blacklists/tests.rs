//! Local blacklist custody over the coordinator test harness: native authentication of the
//! complete signed list, monotonic replacement, repair and exact readback. Lists here are
//! signed by the public vector RegulatoryPolicy key. Proofs are the harness's explicit mocks,
//! so no native Send, Request or Payment admission runs in these tests.

use super::*;
use crate::kagemusha_wallet_state_v1::tests::{
    Wallet, bootstrap, enrollment_issuer, field, fixture, frozen, wallet,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};

fn vectors() -> norito::json::Value {
    norito::json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/kagemusha/wallet_v1_vectors.json"
    )))
    .unwrap()
}

fn account(value: u128) -> [u8; 32] {
    kagemusha_wallet_field_from_u128_v1(value)
}

/// The golden RegulatoryPolicy certificate and its public vector key.
fn regulator() -> (KagemushaWalletSignerCertificateV1, SigningKey) {
    let all = vectors();
    let row = all["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"].as_str() == Some("regulator"))
        .unwrap();
    let key =
        SigningKey::from_slice(&hex::decode(row["scalar_hex"].as_str().unwrap()).unwrap()).unwrap();
    (fixture("KagemushaWalletSignerCertificateV1"), key)
}

/// A genuine signed list of `accounts`; `sign` verifies the signature under the certificate.
fn signed(list_version: u64, accounts: &[[u8; 32]]) -> KagemushaWalletBlacklistV1 {
    let (certificate, key) = regulator();
    let mut entries: Vec<_> = accounts
        .iter()
        .map(|account_digest| KagemushaWalletBlacklistEntryV1 {
            account_digest: *account_digest,
        })
        .collect();
    entries.sort();
    let mut body = fixture::<KagemushaWalletBlacklistV1>("KagemushaWalletBlacklistV1").body;
    body.list_version = list_version;
    body.entry_count = u32::try_from(entries.len()).unwrap();
    body.entries_root = kagemusha_wallet_blacklist_root_v1(&entries).unwrap();
    let signature: Signature = key.sign(&body.signing_message());
    KagemushaWalletBlacklistV1::sign(
        body,
        entries,
        &certificate,
        KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into()),
    )
    .unwrap()
}

fn certificates() -> Vec<u8> {
    archive::encode(&KagemushaWalletCertificateSetV1::new(vec![regulator().0]).unwrap()).unwrap()
}

fn install(w: &mut Wallet, list: &KagemushaWalletBlacklistV1) -> Result<Completion, Error> {
    w.install_blacklist(&list.to_canonical_bytes().unwrap(), &certificates())
}

fn complete(list: &KagemushaWalletBlacklistV1) -> Completion {
    Completion::Complete(list.blacklist_digest().to_vec())
}

fn bootstrapped() -> Wallet {
    let mut w = wallet();
    w.commit(bootstrap()).unwrap();
    w
}

fn stored(w: &mut Wallet, address: [u8; 32]) -> bool {
    w.archive
        .get(
            ArchiveKey::Object(address),
            KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1,
        )
        .unwrap()
        .is_some()
}

/// The list a derivation of the current head reads through its preparation custody.
/// Production passes the manifest selection before Advance and `None` for a fold replay.
fn derived_list(
    w: &mut Wallet,
    before_advance: bool,
) -> Result<Option<KagemushaWalletBlacklistV1>, Error> {
    let (_, manifest) = w.manifest()?;
    let step = w.indexed_step(&manifest, manifest.indexed.ok_or(Error::NoHead)?)?;
    let source = w.source_custody(&manifest, &step)?;
    PreparationCustodyV1::new(
        &mut w.archive,
        &source,
        &step.frozen.capsule.body().successor_state,
        KagemushaWalletOperationKindV1::Send,
        None,
        manifest.issued_requests,
        manifest.direct_anchors,
        manifest.finality_epochs,
        if before_advance {
            manifest.blacklist
        } else {
            None
        },
    )?
    .local_blacklist()
}

#[test]
fn install_authenticates_the_complete_signed_list_natively() {
    let mut w = bootstrapped();
    let (root, _) = w.manifest().unwrap();
    let list = signed(1, &[account(7)]);
    let original = list.to_canonical_bytes().unwrap();
    let (signer, _) = regulator();
    let enrollment = enrollment_issuer(&fixture("KagemushaWalletCredentialV1"));
    let both =
        archive::encode(&KagemushaWalletCertificateSetV1::new(vec![signer, enrollment]).unwrap())
            .unwrap();
    let without_signer =
        archive::encode(&KagemushaWalletCertificateSetV1::new(vec![enrollment]).unwrap()).unwrap();
    let mut forged = list.clone();
    forged.body.issued_at_ms += 1;
    let mut another_role = list.clone();
    another_role.body.signer_certificate = enrollment.certificate_digest();
    let mut another_scheme = list.clone();
    another_scheme.body.scheme_id[0] ^= 1;
    for (case, bytes, set) in [
        (
            "signature",
            forged.to_canonical_bytes().unwrap(),
            certificates(),
        ),
        (
            "signer role",
            another_role.to_canonical_bytes().unwrap(),
            both.clone(),
        ),
        ("absent signer", original.clone(), without_signer),
        (
            "scheme",
            another_scheme.to_canonical_bytes().unwrap(),
            certificates(),
        ),
        ("empty list", Vec::new(), certificates()),
        (
            "oversized list",
            vec![0; KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1 + 1],
            certificates(),
        ),
        ("no certificates", original.clone(), Vec::new()),
        ("malformed certificates", original.clone(), vec![0xff; 16]),
    ] {
        assert!(
            matches!(w.install_blacklist(&bytes, &set), Err(Error::Invalid(_))),
            "{case}"
        );
    }
    assert_eq!(w.manifest().unwrap().0, root, "nothing was selected");
    assert!(w.local_blacklist().unwrap().is_none());
    assert!(!stored(&mut w, object_digest(&original)));
    // Certificates of other roles do not matter once the list's own signer is present.
    assert_eq!(
        w.install_blacklist(&original, &both).unwrap(),
        complete(&list)
    );
    assert_eq!(w.local_blacklist().unwrap(), Some(list));
}

#[test]
fn install_before_bootstrap_has_no_head() {
    let mut w = wallet();
    let list = signed(1, &[account(7)]);
    assert!(matches!(install(&mut w, &list), Err(Error::NoHead)));
    assert!(w.local_blacklist().unwrap().is_none());
    assert!(!stored(
        &mut w,
        object_digest(&list.to_canonical_bytes().unwrap())
    ));
    assert_eq!(w.custody.signatures, 0);
}

#[test]
fn reinstalling_the_held_list_is_idempotent_and_repairs_its_lost_original() {
    let mut w = bootstrapped();
    let signatures = w.custody.signatures;
    let head = w.snapshot().unwrap().head;
    assert!(w.local_blacklist().unwrap().is_none(), "no list held");
    let list = signed(3, &[account(7), account(8)]);
    let original = list.to_canonical_bytes().unwrap();
    let address = object_digest(&original);
    assert_eq!(install(&mut w, &list).unwrap(), complete(&list));
    let (root, manifest) = w.manifest().unwrap();
    let selected = manifest.blacklist.unwrap();
    assert_eq!(
        (selected.list_version, selected.digest, selected.original),
        (3, list.blacklist_digest(), address)
    );
    assert_eq!(selected.original_bytes as usize, original.len());
    assert_ne!(
        selected.digest, address,
        "the signed list digest and its archive address are distinct selectors"
    );
    assert!(archive::encode(&selected).unwrap().len() <= index::INDEX_VALUE_LIMIT);
    assert_eq!(w.local_blacklist().unwrap(), Some(list.clone()));
    // The same list again publishes no new manifest generation.
    assert_eq!(install(&mut w, &list).unwrap(), complete(&list));
    assert_eq!(w.manifest().unwrap().0, root);
    // A lost archive copy is custody loss, never "no list"; reinstalling republishes it.
    w.archive.remove(ArchiveKey::Object(address)).unwrap();
    assert!(matches!(w.local_blacklist(), Err(Error::WitnessLost(_))));
    assert_eq!(install(&mut w, &list).unwrap(), complete(&list));
    assert_eq!(w.manifest().unwrap().0, root);
    assert_eq!(w.local_blacklist().unwrap(), Some(list));
    // Installing is not a wallet operation: no Advance, receipt or head change.
    assert_eq!(w.custody.signatures, signatures);
    assert_eq!(w.snapshot().unwrap().head, head);
    assert_eq!(w.released_steps().unwrap().len(), 1);
}

#[test]
fn a_different_list_needs_a_higher_list_version_and_replaces_the_held_original() {
    let mut w = bootstrapped();
    let first = signed(2, &[account(7)]);
    let first_address = object_digest(&first.to_canonical_bytes().unwrap());
    assert_eq!(install(&mut w, &first).unwrap(), complete(&first));
    let (root, _) = w.manifest().unwrap();
    for version in [1, 2] {
        assert!(
            matches!(
                install(&mut w, &signed(version, &[account(9)])),
                Err(Error::Invalid("blacklist list_version"))
            ),
            "list_version {version}"
        );
    }
    assert_eq!(w.manifest().unwrap().0, root);
    assert_eq!(w.local_blacklist().unwrap(), Some(first.clone()));
    let second = signed(3, &[account(9)]);
    let second_address = object_digest(&second.to_canonical_bytes().unwrap());
    assert_eq!(install(&mut w, &second).unwrap(), complete(&second));
    assert_ne!(w.manifest().unwrap().0, root);
    assert_eq!(w.local_blacklist().unwrap(), Some(second.clone()));
    assert!(!stored(&mut w, first_address), "replaced original removed");
    assert!(stored(&mut w, second_address));
    // A replaced list never returns.
    assert!(matches!(
        install(&mut w, &first),
        Err(Error::Invalid("blacklist list_version"))
    ));
    assert_eq!(w.local_blacklist().unwrap(), Some(second));
}

#[test]
fn an_uncertain_install_is_reconciled_by_installing_the_same_list_again() {
    // Selection publication fails before or after the manifest is committed.
    for committed in [false, true] {
        let mut w = bootstrapped();
        let list = signed(1, &[account(7)]);
        w.custody.fail_publication = Some(committed);
        assert!(install(&mut w, &list).is_err());
        assert_eq!(
            w.local_blacklist().unwrap(),
            committed.then(|| list.clone()),
            "committed {committed}"
        );
        assert_eq!(install(&mut w, &list).unwrap(), complete(&list));
        assert_eq!(w.local_blacklist().unwrap(), Some(list));
    }
    // The replaced original's removal fails after the new selection was published.
    let mut w = bootstrapped();
    install(&mut w, &signed(1, &[account(7)])).unwrap();
    let second = signed(2, &[account(8)]);
    w.archive.fail_remove = true;
    assert!(matches!(
        install(&mut w, &second),
        Err(Error::WitnessLost(_))
    ));
    assert_eq!(w.local_blacklist().unwrap(), Some(second.clone()));
    assert_eq!(install(&mut w, &second).unwrap(), complete(&second));
    assert_eq!(w.local_blacklist().unwrap(), Some(second));
}

#[test]
fn a_local_decode_refusal_is_not_an_invalid_list_and_the_exact_retry_authenticates() {
    let scheme: KagemushaWalletSchemeV1 = fixture("KagemushaWalletSchemeV1");
    let list = signed(1, &[account(7)]);
    let original = list.to_canonical_bytes().unwrap();
    let set = certificates();
    let limits = norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64);
    let refused =
        norito::with_decode_limits_scope(limits, || authenticate(&scheme, &original, &set));
    assert!(matches!(refused, Err(Error::DecodeResource(ref cause))
        if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
    assert_eq!(authenticate(&scheme, &original, &set).unwrap(), list);
}

#[test]
fn selected_original_loss_corruption_or_rebinding_is_custody_loss_never_no_list() {
    let mut w = bootstrapped();
    let list = signed(4, &[account(7)]);
    let original = list.to_canonical_bytes().unwrap();
    install(&mut w, &list).unwrap();
    let selected = w.manifest().unwrap().1.blacklist.unwrap();
    let scheme = w.scheme_id;
    assert_eq!(selected.read(&mut w.archive, &scheme).unwrap(), list);
    let other = signed(5, &[account(8)]);
    for case in 0..10 {
        let mut changed = selected.clone();
        match case {
            0 => changed.version = 2,
            1 => changed.list_version = 0,
            2 => changed.list_version += 1,
            3 => changed.digest = [0; 32],
            4 => changed.digest = other.blacklist_digest(),
            5 => changed.original = object_digest(&other.to_canonical_bytes().unwrap()),
            6 => changed.original_bytes = 0,
            7 => changed.original_bytes += 1,
            8 => changed.original_bytes -= 1,
            _ => {
                changed.original_bytes =
                    u32::try_from(KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1 + 1).unwrap()
            }
        }
        assert!(
            matches!(
                changed.read(&mut w.archive, &scheme),
                Err(Error::WitnessLost(_))
            ),
            "selection change {case}"
        );
    }
    assert!(matches!(
        selected.read(&mut w.archive, &[7; 32]),
        Err(Error::WitnessLost(_))
    ));
    // Unavailable storage stays retryable; it is neither loss nor absence.
    w.archive.hide_object_once(selected.original);
    assert!(matches!(w.local_blacklist(), Err(Error::Storage(_))));
    assert_eq!(w.local_blacklist().unwrap(), Some(list));
    w.archive.hide_object(selected.original);
    assert!(matches!(w.local_blacklist(), Err(Error::WitnessLost(_))));
    w.archive.reveal_object(selected.original);
    w.archive
        .remove(ArchiveKey::Object(selected.original))
        .unwrap();
    let mut corrupt = original;
    *corrupt.last_mut().unwrap() ^= 1;
    w.archive
        .put(ArchiveKey::Object(selected.original), &corrupt)
        .unwrap();
    assert!(matches!(w.local_blacklist(), Err(Error::WitnessLost(_))));
}

#[test]
fn install_keeps_storage_for_one_more_operation() {
    use crate::kagemusha_wallet_state_v1::{
        archive::METADATA_BOUND, capacity::OPERATION_RESERVATION_BYTES,
    };
    let mut w = bootstrapped();
    let list = signed(1, &[account(7)]);
    let original = list.to_canonical_bytes().unwrap();
    w.proofs.capacity.storage_bytes = 1_000;
    // Two archive copies of the list on top of the next operation's storage bound.
    let required =
        1_000 + OPERATION_RESERVATION_BYTES + 2 * (original.len() as u64 + METADATA_BOUND as u64);
    let (root, _) = w.manifest().unwrap();
    w.custody.resources.storage_bytes = required - 1;
    assert!(matches!(
        install(&mut w, &list),
        Err(Error::NotEnoughStorage)
    ));
    assert_eq!(w.manifest().unwrap().0, root);
    assert!(!stored(&mut w, object_digest(&original)));
    assert!(w.local_blacklist().unwrap().is_none());
    w.custody.resources.storage_bytes = required;
    assert_eq!(install(&mut w, &list).unwrap(), complete(&list));
    // Keeping (or repairing) the held list needs no new storage.
    w.custody.resources.storage_bytes = 0;
    assert_eq!(install(&mut w, &list).unwrap(), complete(&list));
    assert_eq!(w.local_blacklist().unwrap(), Some(list));
}

#[test]
fn a_full_size_list_is_named_by_a_bounded_manifest_selection() {
    let accounts: Vec<_> = (1..=9_000).map(account).collect();
    let list = signed(1, &accounts);
    let original = list.to_canonical_bytes().unwrap();
    assert!(
        original.len() > REQUEST_MAX_BYTES,
        "a list is not an operation request"
    );
    assert!(original.len() <= KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1);
    let mut w = bootstrapped();
    assert_eq!(
        w.install_blacklist(&original, &certificates()).unwrap(),
        complete(&list)
    );
    let selected = w.manifest().unwrap().1.blacklist.unwrap();
    assert!(archive::encode(&selected).unwrap().len() <= index::INDEX_VALUE_LIMIT);
    assert_eq!(selected.original_bytes as usize, original.len());
    assert_eq!(w.local_blacklist().unwrap(), Some(list));
}

#[test]
fn only_a_derivation_before_advance_reads_the_local_list() {
    let mut w = bootstrapped();
    assert_eq!(derived_list(&mut w, true).unwrap(), None, "no list held");
    let list = signed(1, &[account(7)]);
    install(&mut w, &list).unwrap();
    assert_eq!(derived_list(&mut w, true).unwrap(), Some(list));
    assert_eq!(derived_list(&mut w, false).unwrap(), None);
    // A refusing derivation fails closed on a lost list; a fold replay never reads it.
    let address = w.manifest().unwrap().1.blacklist.unwrap().original;
    w.archive.remove(ArchiveKey::Object(address)).unwrap();
    assert!(matches!(
        derived_list(&mut w, true),
        Err(Error::WitnessLost(_))
    ));
    assert_eq!(derived_list(&mut w, false).unwrap(), None);
}

#[test]
fn held_list_blocks_exactly_its_entries_as_a_distinct_native_outcome() {
    let request = fixture::<KagemushaWalletPaymentV1>("KagemushaWalletPaymentV1")
        .signed_request()
        .unwrap()
        .body;
    let (payer, receiver) = (
        request.payer_account_digest,
        request.receiver_account_digest,
    );
    // The one rule behind the payer's Send check and the receiver's Request and Payment checks.
    let block =
        |list: Option<&KagemushaWalletBlacklistV1>, field: &'static str, digest: &[u8; 32]| {
            valid(kagemusha_wallet_local_block_v1(list, field, digest))
        };
    let mut w = bootstrapped();
    let held = w.local_blacklist().unwrap();
    block(held.as_ref(), "request.payer_account_digest", &payer).unwrap();
    install(&mut w, &signed(1, &[payer])).unwrap();
    let held = w.local_blacklist().unwrap();
    assert!(matches!(
        block(held.as_ref(), "request.payer_account_digest", &payer),
        Err(Error::Blocked("request.payer_account_digest"))
    ));
    block(held.as_ref(), "request.receiver_account_digest", &receiver).unwrap();
    install(&mut w, &signed(2, &[receiver])).unwrap();
    let held = w.local_blacklist().unwrap();
    block(held.as_ref(), "request.payer_account_digest", &payer).unwrap();
    assert!(matches!(
        block(held.as_ref(), "request.receiver_account_digest", &receiver),
        Err(Error::Blocked("request.receiver_account_digest"))
    ));
}

#[test]
fn a_list_installed_after_a_committed_receive_never_changes_retry_fold_or_restart() {
    let payment: KagemushaWalletPaymentV1 = fixture("KagemushaWalletPaymentV1");
    let digests = payment.digests().unwrap();
    let request = payment.signed_request().unwrap().body;
    let mut w = wallet();
    let boot = bootstrap();
    w.commit(boot.clone()).unwrap();
    let receive = frozen(
        Some(&boot),
        KagemushaWalletEffectV1::Receive {
            credit_id: digests.credit_id,
            payer_wallet_id: [0x88; 32],
            amount: request.amount,
        },
    );
    let operation = receive.capsule.body().operation_id;
    let exact = w.commit(receive.clone()).unwrap();
    assert!(matches!(exact, Completion::Complete(_)));
    // Both parties' accounts are listed only after the Receive committed.
    let list = signed(
        1,
        &[
            request.payer_account_digest,
            request.receiver_account_digest,
        ],
    );
    install(&mut w, &list).unwrap();
    let signatures = w.custody.signatures;
    assert_eq!(w.retry(&operation).unwrap(), Some(exact.clone()));
    assert_eq!(w.commit(receive).unwrap(), exact, "exact first evidence");
    w.scheduler().set_activity(true, false);
    let mut folded = None;
    for _ in 0..8 {
        if let FoldStatus::Folded(sequence) = w.fold_once().unwrap() {
            folded = Some(sequence);
            if sequence == 1 {
                break;
            }
        }
    }
    assert_eq!(folded, Some(1));
    w.credit_status(&digests.credit_id, &digests.payment)
        .unwrap()
        .validate()
        .unwrap();
    let mut w = Coordinator::new(w.custody, w.archive, w.proofs, w.scheme_id, w.wallet_id).unwrap();
    assert_eq!(w.local_blacklist().unwrap(), Some(list));
    assert_eq!(w.retry(&operation).unwrap(), Some(exact));
    assert_eq!(w.custody.signatures, signatures);
}

#[test]
fn a_list_installed_after_a_committed_send_never_changes_its_exact_payment_retry_or_fold() {
    fn rebind(value: &mut FrozenTransition, mut c: KagemushaWalletRecoveryBodyV1) {
        c.statement.successor = c.successor_state.commitment().unwrap();
        c.operation_id = c.statement.operation_id(&c.wallet_id).unwrap();
        c.output = KagemushaWalletOutputDescriptorV1::for_transition(
            &c.statement,
            &c.proof_digest().unwrap(),
            &c.payment_digest,
        )
        .unwrap();
        value.capsule = c
            .freeze()
            .expect("valid synthetic body")
            .seal([0; 32])
            .expect("synthetic opening");
        value.validate().unwrap();
    }
    // The same committed Send as the harness's Send collection test, under its mock proofs.
    let mut w = wallet();
    w.scheduler().set_activity(true, false);
    let template: KagemushaWalletPaymentV1 = fixture("KagemushaWalletPaymentV1");
    let boot = bootstrap();
    w.commit(boot.clone()).unwrap();
    w.fold_once().unwrap();
    w.fold_once().unwrap();
    let mut policy = frozen(
        Some(&boot),
        KagemushaWalletEffectV1::RefreshPolicy {
            update_kind: KagemushaWalletPolicyUpdateKindV1::SchemePolicy,
            update: template.request.scheme_policy,
            accepted_time_floor_ms: boot
                .capsule
                .body()
                .successor_state
                .core
                .accepted_time_floor_ms,
        },
    );
    let mut body = policy.capsule.body().clone();
    body.successor_state.core.policy_epoch = template.request.policy_epoch;
    body.successor_state.rest.scheme_policy = template.request.scheme_policy;
    rebind(&mut policy, body);
    w.commit(policy.clone()).unwrap();
    w.fold_once().unwrap();
    w.fold_once().unwrap();
    let step = w.released_steps().unwrap().pop().unwrap();
    let fold = w.read_fold(&step).unwrap().unwrap();
    let mut pending = KagemushaWalletIndexedTreeV1::new();
    pending
        .insert(template.digests().unwrap().credit_id, field(42))
        .unwrap();
    let mut send = frozen(Some(&policy), template.send.statement.effect);
    let mut body = send.capsule.body().clone();
    body.predecessor_lineage = KagemushaWalletLineageSlotV1::Present {
        lineage: fold.record.lineage.clone(),
    };
    body.statement.lineage_burned_total = fold.record.lineage.public.burned_total;
    body.statement.lineage_pending_outgoing_root = fold.record.lineage.public.pending_outgoing_root;
    body.successor_state.core.pending_outgoing_root = pending.root();
    body.successor_state.core.policy_epoch = template.request.policy_epoch;
    body.successor_state.rest.scheme_policy = template.request.scheme_policy;
    rebind(&mut send, body);
    let operation = send.capsule.body().operation_id;
    let exact = w.commit(send.clone()).unwrap();
    assert!(matches!(exact, Completion::Complete(_)));
    // The payer lists the receiver only after its Send committed.
    let list = signed(
        1,
        &[template
            .signed_request()
            .unwrap()
            .body
            .receiver_account_digest],
    );
    install(&mut w, &list).unwrap();
    let signatures = w.custody.signatures;
    assert_eq!(w.retry(&operation).unwrap(), Some(exact.clone()));
    assert_eq!(w.commit(send).unwrap(), exact, "exact Payment bytes");
    w.fold_once().unwrap();
    w.fold_once().unwrap();
    assert_eq!(w.manifest().unwrap().1.folded, Some(2));
    let mut w = Coordinator::new(w.custody, w.archive, w.proofs, w.scheme_id, w.wallet_id).unwrap();
    assert_eq!(w.local_blacklist().unwrap(), Some(list));
    assert_eq!(w.retry(&operation).unwrap(), Some(exact));
    assert_eq!(w.custody.signatures, signatures);
}
