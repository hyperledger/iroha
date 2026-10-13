//! iOS rollback anchor tests: value codec, bracketed reads, the selection comparison,
//! add-only creation and raising only to durable markers.

use super::*;
use crate::kagemusha_wallet_advance_v1::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletUnavailableV1,
    test_support::{AnchorWriteV1, BOOT_A, FakePlatformV1, bootstrap_capsule, wallet_fixture},
};

fn keychain() -> FakePlatformV1 {
    FakePlatformV1::new(KagemushaWalletAnchorPolicyV1::Keychain, 0x30)
}

/// Enrollment record of a keychain-anchored slot, its Selected successor and the Released one.
fn records(seed: u8) -> [KagemushaWalletMarkerRecordV1; 3] {
    let f = wallet_fixture(seed);
    let enrollment = f.enrollment_record_with(BOOT_A, KagemushaWalletAnchorPolicyV1::Keychain);
    let selected = enrollment
        .select(bootstrap_capsule(&f).head_marker_state(), BOOT_A)
        .expect("select");
    let released = selected.release([0xc4; 32], BOOT_A).expect("release");
    [enrollment, selected, released]
}

fn stored(
    platform: &FakePlatformV1,
    slot: &KagemushaWalletSlotIdV1,
) -> Option<KagemushaWalletAnchorV1> {
    platform.with(|state| {
        state
            .anchors
            .get(slot)
            .map(|bytes| KagemushaWalletAnchorV1::decode(bytes).expect("anchor"))
    })
}

#[test]
fn wallet_advance_v1_anchor_value_codec_and_validation() {
    let [enrollment, _, released] = records(0x31);
    for anchor in [
        KagemushaWalletAnchorV1::none(),
        KagemushaWalletAnchorV1::naming(&enrollment),
        KagemushaWalletAnchorV1::naming(&released),
    ] {
        let bytes = anchor.encode().expect("encode");
        assert_eq!(KagemushaWalletAnchorV1::decode(&bytes), Ok(anchor));
    }
    let named = KagemushaWalletAnchorV1::naming(&released);
    assert_eq!(named.generation, 2);
    assert_eq!(named.marker_file_digest, *released.marker_file_digest());
    let invalid = KagemushaWalletProviderErrorV1::Invalid { field: "anchor" };
    for anchor in [
        KagemushaWalletAnchorV1 {
            generation: 1,
            ..KagemushaWalletAnchorV1::none()
        },
        KagemushaWalletAnchorV1 {
            marker_file_digest: [1; 32],
            ..KagemushaWalletAnchorV1::none()
        },
        KagemushaWalletAnchorV1 {
            marker_file_digest: [0; 32],
            ..named
        },
        KagemushaWalletAnchorV1 {
            version: 2,
            ..named
        },
    ] {
        assert_eq!(anchor.encode(), Err(invalid));
    }
    let mut corrupt = named.encode().expect("encode");
    corrupt.push(0);
    assert!(KagemushaWalletAnchorV1::decode(&corrupt).is_err());
}

#[test]
fn wallet_advance_v1_anchor_read_is_bracketed() {
    let platform = keychain();
    let slot = KagemushaWalletSlotIdV1([0x31; 32]);
    assert_eq!(kagemusha_wallet_read_anchor_v1(&platform, &slot), Ok(None));
    // A lock event between the brackets turns an absence into Unavailable.
    platform.with(|state| state.storage_lock_after = Some(1));
    assert_eq!(
        kagemusha_wallet_read_anchor_v1(&platform, &slot),
        Err(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Locked
        ))
    );
    platform.with(|state| state.storage = Ok(()));
    platform.with(|state| state.storage_lock_after = Some(0));
    assert!(matches!(
        kagemusha_wallet_read_anchor_v1(&platform, &slot),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
    platform.with(|state| {
        state.storage = Ok(());
        state.anchor_read_unavailable = true;
    });
    assert!(matches!(
        kagemusha_wallet_read_anchor_v1(&platform, &slot),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
    platform.with(|state| {
        state.anchor_read_unavailable = false;
        state.anchors.insert(slot, vec![1, 2, 3]);
    });
    assert_eq!(
        kagemusha_wallet_read_anchor_v1(&platform, &slot),
        Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData { object: "anchor" })
    );
}

#[test]
fn wallet_advance_v1_anchor_check_classifies_against_the_current_marker() {
    let [enrollment, selected, released] = records(0x32);
    let slot = *enrollment.slot();
    let android = FakePlatformV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 0x32);
    let unanchored = wallet_fixture(0x32).enrollment_record(BOOT_A);
    assert_eq!(
        kagemusha_wallet_check_anchor_v1(&android, &unanchored),
        Ok(KagemushaWalletAnchorCheckV1::NotRequired)
    );
    // Regression: the slot's recorded kind decides, never the platform's answer alone. A
    // platform that stops reporting the keychain anchor for a keychain slot (or starts
    // reporting one for an unanchored slot) refuses the slot instead of skipping the check.
    let policy = Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
        object: "anchor policy",
    });
    assert_eq!(
        kagemusha_wallet_check_anchor_v1(&android, &released),
        policy
    );
    assert_eq!(
        kagemusha_wallet_raise_anchor_v1(&android, &released),
        policy.map(|_| ())
    );
    assert_eq!(
        kagemusha_wallet_check_anchor_v1(&keychain(), &unanchored),
        policy
    );
    assert_eq!(
        kagemusha_wallet_require_anchor_policy_v1(
            &android,
            KagemushaWalletAnchorPolicyV1::NotRequired
        ),
        Ok(())
    );
    let platform = keychain();
    let lost = |loss| Err(KagemushaWalletProviderErrorV1::LostCustody(loss));
    assert_eq!(
        kagemusha_wallet_check_anchor_v1(&platform, &enrollment),
        lost(KagemushaWalletLostCustodyV1::AnchorMissing)
    );
    let set = |anchor: KagemushaWalletAnchorV1| {
        platform.with(|state| state.anchors.insert(slot, anchor.encode().expect("encode")));
    };
    set(KagemushaWalletAnchorV1::none());
    assert_eq!(
        kagemusha_wallet_check_anchor_v1(&platform, &enrollment),
        Ok(KagemushaWalletAnchorCheckV1::Lagging)
    );
    set(KagemushaWalletAnchorV1::naming(&enrollment));
    assert_eq!(
        kagemusha_wallet_check_anchor_v1(&platform, &enrollment),
        Ok(KagemushaWalletAnchorCheckV1::Current)
    );
    assert_eq!(
        kagemusha_wallet_check_anchor_v1(&platform, &released),
        Ok(KagemushaWalletAnchorCheckV1::Lagging)
    );
    set(KagemushaWalletAnchorV1::naming(&released));
    assert_eq!(
        kagemusha_wallet_check_anchor_v1(&platform, &selected),
        lost(KagemushaWalletLostCustodyV1::RolledBack)
    );
    set(KagemushaWalletAnchorV1 {
        marker_file_digest: [0x99; 32],
        ..KagemushaWalletAnchorV1::naming(&released)
    });
    assert_eq!(
        kagemusha_wallet_check_anchor_v1(&platform, &released),
        lost(KagemushaWalletLostCustodyV1::AnchorMismatch)
    );
    assert_eq!(
        compare(&KagemushaWalletAnchorV1::naming(&selected), &released),
        Ok(KagemushaWalletAnchorCheckV1::Lagging)
    );
}

#[test]
fn wallet_advance_v1_anchor_create_is_add_only() {
    let [enrollment, ..] = records(0x33);
    let slot = *enrollment.slot();
    let android = FakePlatformV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 0x33);
    assert_eq!(kagemusha_wallet_create_anchor_v1(&android, &slot), Ok(()));
    assert!(android.with(|state| state.anchors.is_empty()));
    let platform = keychain();
    assert_eq!(kagemusha_wallet_create_anchor_v1(&platform, &slot), Ok(()));
    assert_eq!(
        stored(&platform, &slot),
        Some(KagemushaWalletAnchorV1::none())
    );
    // A retried E2 accepts its own NONE anchor; a named anchor means the slot was used.
    assert_eq!(kagemusha_wallet_create_anchor_v1(&platform, &slot), Ok(()));
    platform.with(|state| {
        state.anchors.insert(
            slot,
            KagemushaWalletAnchorV1::naming(&enrollment)
                .encode()
                .expect("encode"),
        )
    });
    assert_eq!(
        kagemusha_wallet_create_anchor_v1(&platform, &slot),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "anchor.exists"
        })
    );
    let other = KagemushaWalletSlotIdV1([0x34; 32]);
    platform.with(|state| state.anchor_write = AnchorWriteV1::Refused);
    assert!(matches!(
        kagemusha_wallet_create_anchor_v1(&platform, &other),
        Err(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Platform(_)
        ))
    ));
    platform.with(|state| state.anchor_write = AnchorWriteV1::UncertainLost);
    assert!(matches!(
        kagemusha_wallet_create_anchor_v1(&platform, &other),
        Err(KagemushaWalletProviderErrorV1::Uncertain(_))
    ));
    platform.with(|state| state.anchor_write = AnchorWriteV1::UncertainApplied);
    assert_eq!(kagemusha_wallet_create_anchor_v1(&platform, &other), Ok(()));
    assert_eq!(
        stored(&platform, &other),
        Some(KagemushaWalletAnchorV1::none())
    );
}

#[test]
fn wallet_advance_v1_anchor_raise_never_lowers() {
    let [enrollment, selected, released] = records(0x35);
    let slot = *enrollment.slot();
    let platform = keychain();
    assert_eq!(
        kagemusha_wallet_raise_anchor_v1(&platform, &enrollment),
        Err(KagemushaWalletProviderErrorV1::LostCustody(
            KagemushaWalletLostCustodyV1::AnchorMissing
        ))
    );
    kagemusha_wallet_create_anchor_v1(&platform, &slot).expect("create");
    kagemusha_wallet_raise_anchor_v1(&platform, &enrollment).expect("raise to 0");
    assert_eq!(
        stored(&platform, &slot),
        Some(KagemushaWalletAnchorV1::naming(&enrollment))
    );
    kagemusha_wallet_raise_anchor_v1(&platform, &released).expect("raise to 2");
    assert_eq!(
        stored(&platform, &slot),
        Some(KagemushaWalletAnchorV1::naming(&released))
    );
    // Already current: no write. Lower: refused as a rollback.
    platform.with(|state| state.anchor_write = AnchorWriteV1::Refused);
    kagemusha_wallet_raise_anchor_v1(&platform, &released).expect("current");
    assert_eq!(
        kagemusha_wallet_raise_anchor_v1(&platform, &selected),
        Err(KagemushaWalletProviderErrorV1::LostCustody(
            KagemushaWalletLostCustodyV1::RolledBack
        ))
    );
    let [enrollment, _, released] = records(0x36);
    let slot = *enrollment.slot();
    kagemusha_wallet_create_anchor_v1(&keychain(), &slot).expect("create on a throwaway");
    let platform = keychain();
    platform.with(|state| {
        state.anchors.insert(
            slot,
            KagemushaWalletAnchorV1::none().encode().expect("encode"),
        )
    });
    platform.with(|state| state.anchor_write = AnchorWriteV1::Refused);
    assert!(matches!(
        kagemusha_wallet_raise_anchor_v1(&platform, &released),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
    platform.with(|state| state.anchor_write = AnchorWriteV1::UncertainLost);
    assert!(matches!(
        kagemusha_wallet_raise_anchor_v1(&platform, &released),
        Err(KagemushaWalletProviderErrorV1::Uncertain(_))
    ));
    platform.with(|state| state.anchor_write = AnchorWriteV1::UncertainApplied);
    kagemusha_wallet_raise_anchor_v1(&platform, &released).expect("uncertain but applied");
    assert_eq!(
        stored(&platform, &slot),
        Some(KagemushaWalletAnchorV1::naming(&released))
    );
}

#[test]
fn wallet_advance_v1_anchor_not_published_mapping() {
    assert_eq!(
        not_published(KagemushaWalletNotPublishedV1::Failed(
            KagemushaWalletUnavailableV1::Locked
        )),
        KagemushaWalletProviderErrorV1::Unavailable(KagemushaWalletUnavailableV1::Locked)
    );
    assert_eq!(
        not_published(KagemushaWalletNotPublishedV1::NoSpace),
        KagemushaWalletProviderErrorV1::NoSpace
    );
    assert_eq!(
        not_published(KagemushaWalletNotPublishedV1::DestinationAbsent),
        KagemushaWalletProviderErrorV1::Unavailable(KagemushaWalletUnavailableV1::Busy)
    );
}
