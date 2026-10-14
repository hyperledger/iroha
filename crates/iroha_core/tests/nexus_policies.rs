//! Tests covering Nexus configuration helpers.

use iroha_config::parameters::actual::Nexus;
use std::num::{NonZeroU16, NonZeroU32};
#[test]
fn da_max_public_dataspaces_tracks_config() {
    let mut nexus = Nexus::default();
    nexus.da.q_in_slot_total = NonZeroU32::new(4_096).expect("non-zero");
    nexus.da.q_in_slot_per_ds_min = NonZeroU16::new(16).expect("non-zero");
    assert_eq!(nexus.da.max_public_dataspaces_per_slot(), 256);
    nexus.da.q_in_slot_total = NonZeroU32::new(2_048).expect("non-zero");
    nexus.da.q_in_slot_per_ds_min = NonZeroU16::new(32).expect("non-zero");
    assert_eq!(nexus.da.max_public_dataspaces_per_slot(), 64);
}
#[test]
fn fusion_decision_uses_configured_thresholds() {
    let mut nexus = Nexus::default();
    nexus.fusion.floor_teu = 5_000;
    nexus.fusion.exit_teu = 10_000;
    let history = [4_200, 4_900, 5_100, 4_000];
    assert!(!nexus.fusion.should_fuse(&history));
    let history = [4_200, 4_500, 4_800, 4_100];
    assert!(nexus.fusion.should_fuse(&history));
    assert!(nexus.fusion.should_exit(12_000));
    assert!(!nexus.fusion.should_exit(9_000));
}
#[test]
fn attester_rotation_cap_enforced_by_config() {
    let mut nexus = Nexus::default();
    nexus.da.rotation.max_hits_per_window = NonZeroU16::new(2).expect("non-zero");
    nexus.da.rotation.window_slots = NonZeroU16::new(32).expect("non-zero");
    assert!(nexus.da.rotation.violates_temporal_diversity(3, 32));
    assert!(!nexus.da.rotation.violates_temporal_diversity(2, 32));
    assert!(!nexus.da.rotation.violates_temporal_diversity(3, 16));
}
