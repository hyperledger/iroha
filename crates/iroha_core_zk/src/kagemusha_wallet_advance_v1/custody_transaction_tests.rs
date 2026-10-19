//! Custody transactions over real host custody: the same answers with consolidated ancestry
//! walks, and no effect outside the store once the custody root has moved.

use super::{
    KagemushaWalletAdvanceOutcomeV1 as Advance, KagemushaWalletAnchorPolicyV1 as Policy,
    KagemushaWalletProviderErrorV1, KagemushaWalletProviderV1,
    KagemushaWalletPublishOutcomeV1 as Outcome, KagemushaWalletStdFsV1,
    KagemushaWalletUnavailableV1, kagemusha_wallet_custody_refusal_v1,
    test_support::{
        FakePlatformV1, SCHEME, TestOwnerV1, advance_request, bootstrapped_provider, next_capsule,
        test_options, wallet_fixture,
    },
};
use iroha_fs::CustodyWorkV1;
use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
};

fn std_root() -> (tempfile::TempDir, PathBuf) {
    let temporary = tempfile::tempdir().expect("tempdir");
    let root = temporary.path().join("custody");
    assert_eq!(
        KagemushaWalletStdFsV1::create_root(&root),
        Outcome::Published
    );
    (temporary, root)
}

fn reopen(
    root: &Path,
    platform: &FakePlatformV1,
) -> KagemushaWalletProviderV1<KagemushaWalletStdFsV1, FakePlatformV1> {
    KagemushaWalletProviderV1::open(
        KagemushaWalletStdFsV1::open(root).expect("std root"),
        platform.clone(),
        SCHEME,
        test_options(),
    )
    .expect("reopen")
}

fn walks<T>(work: impl FnOnce() -> T) -> (T, CustodyWorkV1) {
    let before = CustodyWorkV1::current_thread();
    let value = work();
    (value, CustodyWorkV1::current_thread().since(before))
}

#[test]
fn reconciliation_inside_a_custody_transaction_answers_the_same_with_consolidated_walks() {
    for policy in [Policy::NotRequired, Policy::Keychain] {
        let (_temporary, root) = std_root();
        let (provider, platform, slot, _) = bootstrapped_provider(
            KagemushaWalletStdFsV1::open(&root).expect("std root"),
            policy,
            0x61,
        );
        drop(provider);
        let (expected, outside) = walks(|| {
            reopen(&root, &platform)
                .status(&slot)
                .expect("full reconcile")
        });
        let start = CustodyWorkV1::current_thread();
        let (provider, actual, body) = iroha_fs::custody_transaction(|| {
            let mut provider = reopen(&root, &platform);
            let full = provider.status(&slot).expect("full reconcile");
            assert_eq!(provider.status(&slot).expect("cached reconcile"), full);
            let body = CustodyWorkV1::current_thread().since(start);
            // The provider outlives the transaction, so its exit observes this custody.
            Ok::<_, std::io::Error>((provider, full, body))
        })
        .expect("custody transaction");
        let inside = CustodyWorkV1::current_thread().since(start);
        drop(provider);
        // The exit walks the root and, by its suffix, each custody directory the step used:
        // probe, slots, the slot, markers, capsules, completion, ops and archive.
        assert_eq!(
            inside.since(body).ancestry_walks,
            9,
            "{policy:?}: {body:?} then {inside:?}"
        );
        assert_eq!(actual, expected, "{policy:?}");
        println!(
            "CUSTODY-TRANSACTION {{\"policy\":\"{policy:?}\",\"operation\":\"reopen_full_cached\",\
             \"walks_outside\":{},\"opens_outside\":{},\"walks_inside\":{},\"opens_inside\":{}}}",
            outside.ancestry_walks,
            outside.ancestry_opens,
            inside.ancestry_walks,
            inside.ancestry_opens,
        );
        // Outside, every custody operation walks from "/" before and after its leaf checks.
        assert!(outside.ancestry_walks > 300, "{policy:?}: {outside:?}");
        // Inside: the root's open and entry, one suffix walk per custody directory at its first
        // use, then the exit and, under the Keychain policy, the anchor fence of the full
        // reconcile, each a root walk plus the suffixes of those directories.
        assert!(inside.ancestry_walks < 48, "{policy:?}: {inside:?}");
    }
}

#[test]
fn effects_outside_the_store_never_follow_custody_that_moved_inside_a_transaction() {
    let (temporary, root) = std_root();
    let (mut provider, platform, slot, boot) = bootstrapped_provider(
        KagemushaWalletStdFsV1::open(&root).expect("std root"),
        Policy::Keychain,
        0x62,
    );
    let displaced = temporary.path().join("displaced");
    let effects = || platform.with(|state| (state.sign_calls, state.anchor_writes));
    let result = iroha_fs::custody_transaction(|| {
        let current = provider.status(&slot).expect("cached status");
        let capsule = next_capsule(&wallet_fixture(0x62), &boot);
        let request = advance_request(current.marker().expect("marker"), &capsule);
        let before = effects();
        fs::rename(&root, &displaced).expect("displace custody");
        fs::create_dir(&root).expect("replacement");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private mode");
        // Leaf work follows held descriptors, so the capsule and the Selected marker are
        // written to the held custody. The fence before the first effect, the Selected anchor,
        // observes the move: the operation stays pending, and neither the anchor nor the
        // payment key is reached.
        let outcome = provider
            .advance(&slot, &TestOwnerV1, &request)
            .expect("a selected operation is pending, not refused");
        assert!(matches!(outcome, Advance::Pending { .. }), "{outcome:?}");
        assert_eq!(
            provider.pending_reason(&slot),
            Some(KagemushaWalletProviderErrorV1::Unavailable(
                KagemushaWalletUnavailableV1::Io(0)
            )),
            "the fence's refusal, as a custody operation reports a changed ancestor"
        );
        assert_eq!(effects(), before, "no anchor write or signature");
        Ok::<_, std::io::Error>(())
    });
    assert!(result.is_err(), "the exit refuses custody that moved");
    fs::remove_dir(&root).expect("remove replacement");
    fs::rename(&displaced, &root).expect("restore custody");
}

#[test]
fn custody_fences_outside_a_transaction_observe_nothing() {
    let (fenced, work) = walks(super::store::kagemusha_wallet_custody_fence_v1);
    assert_eq!(fenced, Ok(()));
    assert_eq!(work, CustodyWorkV1::default());
    // A vanished ancestor is changed custody, never absence.
    assert_eq!(
        kagemusha_wallet_custody_refusal_v1(&std::io::ErrorKind::NotFound.into()),
        KagemushaWalletUnavailableV1::Io(0)
    );
    assert_eq!(
        kagemusha_wallet_custody_refusal_v1(&std::io::ErrorKind::WouldBlock.into()),
        KagemushaWalletUnavailableV1::Busy
    );
}
