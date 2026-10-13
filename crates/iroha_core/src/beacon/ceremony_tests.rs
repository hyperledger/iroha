//! Signed all-edge beacon ceremony tests for `n = 3f + 1` committees.

use iroha_crypto::{Algorithm, Hash, HashOf};
use iroha_data_model::block::BlockHeader;

use super::*;
use crate::beacon::{
    FinalizedGlobalThresholdBeaconKeySessionRecordV1, GlobalThresholdBeaconChainAnchorV1,
    GlobalThresholdBeaconError, GlobalThresholdBeaconPartialSignerV1 as _,
    GlobalThresholdBeaconPulseAggregatorV1,
    credential::decode_global_beacon_partial_signer_credential_v1,
};

const REVISION: u64 = 3;

fn network_id(marker: u8) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed([marker; 32]),
    ))
}

fn roster_keys(committee_size: u16, seed: u8) -> Vec<KeyPair> {
    let mut keys = (0..committee_size)
        .map(|index| {
            let mut material = vec![seed; 32];
            material[31] = u8::try_from(index).expect("test committee fits u8");
            KeyPair::from_seed(material, Algorithm::BlsNormal)
        })
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
    keys
}

fn roster(keys: &[KeyPair]) -> Vec<PeerId> {
    keys.iter()
        .map(|key| PeerId::new(key.public_key().clone()))
        .collect()
}

fn handles(committee_size: u16) -> Vec<String> {
    (1..=committee_size)
        .map(|index| format!("software://iroha/global-beacon/validator-{index}"))
        .collect()
}

fn plan(keys: &[KeyPair], network_marker: u8) -> GlobalBeaconCeremonyPlanV1 {
    let roster = roster(keys);
    let session = global_beacon_genesis_dkg_session_v1(network_id(network_marker), &roster)
        .expect("exact 3f + 1 session");
    GlobalBeaconCeremonyPlanV1::new(
        session,
        roster,
        handles(u16::try_from(keys.len()).expect("committee fits u16")),
        REVISION,
    )
    .expect("valid plan")
}

fn deal(plan: &GlobalBeaconCeremonyPlanV1, keys: &[KeyPair]) -> DealtGlobalBeaconV1 {
    deal_global_beacon_at_logical_clock_v1(
        plan,
        &keys.iter().collect::<Vec<_>>(),
        &crate::beacon::fixtures::fixture_budget(),
    )
    .expect("logical-clock deal")
}

fn validated(
    record: &RetainedFinalizedGlobalThresholdBeaconSessionV1,
) -> crate::beacon::ValidatedGlobalThresholdBeaconSessionV1 {
    record.session.clone()
}

fn custody(
    seat: &GlobalBeaconSeatCredentialV1,
    network: &NetworkId,
) -> crate::beacon::RuntimeGlobalThresholdBeaconShareCustodyV1 {
    decode_global_beacon_partial_signer_credential_v1(
        &seat.credential,
        network,
        &seat.binding.handle,
        seat.binding.revision,
        seat.binding.policy_digest,
        &crate::beacon::fixtures::fixture_budget(),
    )
    .expect("seat credential imports")
}

fn pulse(
    session: &crate::beacon::ValidatedGlobalThresholdBeaconSessionV1,
) -> GlobalThresholdBeaconPulseAggregatorV1 {
    let anchor = GlobalThresholdBeaconChainAnchorV1 {
        height: 9,
        block_hash: HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x6D; 32])),
    };
    GlobalThresholdBeaconPulseAggregatorV1::new(
        session.clone(),
        10,
        anchor,
        crate::beacon::pulse_context_fixture_v1(),
    )
    .expect("exact pulse")
}

#[test]
fn deal_roundtrips_credentials_and_inventory_digests_for_four_seven_and_ten_seats() {
    for committee_size in [4_u16, 7, 10] {
        let keys = roster_keys(committee_size, 0x40);
        let plan = plan(&keys, 0x51);
        let dealt = deal(&plan, &keys);
        let record = &dealt.record;
        let faults = (committee_size - 1) / 3;
        assert_eq!(record.session.committee_size, committee_size);
        assert_eq!(record.session.threshold, faults + 1);
        assert_eq!(record.session.adaptive_dkg.finalized_at_height, 4);
        assert_eq!(record.activated_at_height, None);
        assert_eq!(
            record.session.adaptive_dkg.qualified_dealers,
            (1..=committee_size).collect::<Vec<_>>()
        );
        // The public transcript holds every signed edge and acceptance.
        let edges = usize::from(committee_size).pow(2);
        assert_eq!(record.session.adaptive_dkg.encrypted_shares.len(), edges);
        assert_eq!(record.session.adaptive_dkg.share_acceptances.len(), edges);
        assert_eq!(dealt.seats.len(), usize::from(committee_size));
        let session = validated(record);
        let bindings = dealt
            .seats
            .iter()
            .map(|seat| seat.binding.clone())
            .collect::<Vec<_>>();
        plan.verify_seat_bindings(record, &bindings)
            .expect("bindings match the plan");
        for (offset, seat) in dealt.seats.iter().enumerate() {
            let signer_index = u16::try_from(offset + 1).expect("seat fits u16");
            assert_eq!(seat.binding.signer_index, signer_index);
            assert_eq!(seat.binding.validator, plan.roster()[offset]);
            assert_eq!(seat.binding.revision, REVISION);
            assert_eq!(
                seat.binding.policy_digest,
                global_beacon_partial_signer_public_inventory_digest_v1(
                    record.session.network_id,
                    &[(&record.session, signer_index)],
                )
                .expect("public inventory digest")
            );
            let custody = custody(seat, &record.session.network_id);
            assert!(
                custody
                    .attest_partial_signing_capability(&session, signer_index)
                    .expect("owned seat")
                    .matches(&session, signer_index)
            );
            let other = signer_index % committee_size + 1;
            assert!(
                custody
                    .attest_partial_signing_capability(&session, other)
                    .is_err()
            );
        }
        let mut tampered = bindings.clone();
        tampered.swap(0, 1);
        assert!(matches!(
            plan.verify_seat_bindings(record, &tampered),
            Err(GlobalBeaconCeremonyErrorV1::InvalidPlan)
        ));
        let mut tampered = bindings.clone();
        tampered[0].policy_digest = tampered[1].policy_digest;
        assert!(plan.verify_seat_bindings(record, &tampered).is_err());
        assert!(plan.verify_seat_bindings(record, &bindings[1..]).is_err());
    }
}

#[test]
fn any_f_plus_one_seats_reconstruct_the_unique_pulse_and_f_seats_cannot() {
    let committee_size = 7_u16;
    let keys = roster_keys(committee_size, 0x41);
    let dealt = deal(&plan(&keys, 0x52), &keys);
    let session = validated(&dealt.record);
    let network = dealt.record.session.network_id;
    let custodies = dealt
        .seats
        .iter()
        .map(|seat| custody(seat, &network))
        .collect::<Vec<_>>();
    let threshold = usize::from(dealt.record.session.threshold);
    assert_eq!(threshold, 3);
    let mut low = pulse(&session);
    for signer in &custodies[..threshold - 1] {
        let partial = signer
            .sign_partial(&session, low.payload())
            .expect("partial");
        assert!(low.accept_partial(partial).expect("verified partial"));
    }
    assert_eq!(
        low.finalize().err(),
        Some(GlobalThresholdBeaconError::InsufficientPartialSignatures)
    );
    let partial = custodies[threshold - 1]
        .sign_partial(&session, low.payload())
        .expect("threshold partial");
    assert!(low.accept_partial(partial).expect("verified partial"));
    let low = low.finalize().expect("f + 1 seats reconstruct");
    let mut high = pulse(&session);
    for signer in &custodies[custodies.len() - threshold..] {
        let partial = signer
            .sign_partial(&session, high.payload())
            .expect("partial");
        assert!(high.accept_partial(partial).expect("verified partial"));
    }
    assert_eq!(high.finalize().expect("disjoint f + 1 seats"), low);
}

#[test]
fn genesis_deals_share_the_canonical_identity_but_never_a_transcript() {
    let keys = roster_keys(4, 0x42);
    let network = network_id(0x53);
    let plan = plan(&keys, 0x53);
    let session = *plan.dkg_session();
    assert_eq!(
        session.session_id,
        global_beacon_genesis_session_id_v1(network)
    );
    assert_eq!(
        session.attempt_id,
        global_beacon_genesis_attempt_id_v1(network)
    );
    assert_ne!(session.session_id, session.attempt_id);
    assert_ne!(
        session.session_id,
        global_beacon_genesis_session_id_v1(network_id(0x54))
    );
    assert_eq!(session.authority_generation, 0);
    assert_eq!(
        [
            session.start_height,
            session.commitments_end_height,
            session.deliveries_end_height,
            session.acceptances_end_height,
        ],
        GLOBAL_BEACON_GENESIS_DKG_WINDOWS_V1
    );
    let first = deal(&plan, &keys);
    let second = deal(&plan, &keys);
    assert_eq!(
        first.record.session.session_id,
        second.record.session.session_id
    );
    assert_eq!(
        first.record.session.adaptive_dkg.finalized_at_height,
        GLOBAL_BEACON_GENESIS_DKG_WINDOWS_V1[3]
    );
    // Every seat draws fresh dealer and recipient randomness.
    assert_ne!(
        first.record.session.transcript_hash,
        second.record.session.transcript_hash
    );
    assert_ne!(
        first.seats[0].credential.as_slice(),
        second.seats[0].credential.as_slice()
    );
}

#[test]
fn deals_require_one_owning_signer_per_seat() {
    let budget = crate::beacon::fixtures::fixture_budget();
    let keys = roster_keys(4, 0x43);
    let plan = plan(&keys, 0x54);
    let mut reordered = keys.iter().collect::<Vec<_>>();
    reordered.swap(0, 1);
    let outsider = KeyPair::from_seed(vec![0x98; 32], Algorithm::BlsNormal);
    let mut foreign = keys.iter().collect::<Vec<_>>();
    foreign[3] = &outsider;
    for signers in [
        keys.iter().take(3).collect::<Vec<_>>(),
        keys.iter().chain([&outsider]).collect(),
        reordered,
        foreign,
    ] {
        assert!(matches!(
            deal_global_beacon_at_logical_clock_v1(
                &plan,
                &signers,
                &crate::beacon::fixtures::fixture_budget()
            )
            .err(),
            Some(GlobalBeaconCeremonyErrorV1::SeatSigner)
        ));
    }
    // A seat credential binds the plan's own session and an existing seat.
    let dealt =
        deal_global_beacon_at_logical_clock_v1(&plan, &keys.iter().collect::<Vec<_>>(), &budget)
            .expect("original-pool dealt session");
    let other = deal_global_beacon_at_logical_clock_v1(
        &self::plan(&keys, 0x55),
        &keys.iter().collect::<Vec<_>>(),
        &budget,
    )
    .expect("other original-pool dealt session");
    for (public, signer_index) in [
        (validated(&other.record), 1),
        (validated(&dealt.record), 0),
        (validated(&dealt.record), 5),
    ] {
        assert!(matches!(
            plan.seat_credential(
                public,
                signer_index,
                Zeroizing::new([[0x11; 32]; 3]),
                &budget
            )
            .err(),
            Some(GlobalBeaconCeremonyErrorV1::InvalidPlan)
        ));
    }
    // A share that is not the seat's own is never encoded.
    assert!(matches!(
        plan.seat_credential(
            validated(&dealt.record),
            1,
            Zeroizing::new([[0x11; 32]; 3]),
            &budget
        ),
        Err(GlobalBeaconCeremonyErrorV1::CredentialOutput(
            crate::beacon::credential::GlobalBeaconCredentialEncodeErrorV1::Share(_)
        ))
    ));
    // The seat owner itself refuses a transcript it did not help finalize.
    let seat = PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(
        *plan.dkg_session(),
        plan.roster(),
        1,
        &keys[0],
        &super::super::fixtures::fixture_budget(),
    )
    .expect("prepared seat")
    .generate(&keys[0])
    .expect("fresh seat");
    assert!(matches!(
        seat.aggregate_private_share(&validated(&dealt.record)),
        Err(super::super::LocalGlobalThresholdBeaconDkgErrorV1::Invalid(
            GlobalThresholdBeaconError::DkgTerminal
        ))
    ));
}

#[test]
fn plans_require_exact_three_f_plus_one_sessions_and_production_handles() {
    let keys = roster_keys(7, 0x44);
    let roster = roster(&keys);
    let network = network_id(0xB1);
    let session =
        global_beacon_genesis_dkg_session_v1(network, &roster).expect("seven-seat session");
    assert_eq!(session.committee_size, 7);
    assert_eq!(session.threshold, 3);
    assert_eq!(
        session.roster_hash,
        global_threshold_beacon_roster_hash_v1(&roster)
    );
    let mut duplicate = roster.clone();
    duplicate[1] = duplicate[0].clone();
    for invalid in [&roster[..5], &roster[..1], &duplicate[..]] {
        assert!(matches!(
            global_beacon_genesis_dkg_session_v1(network, invalid),
            Err(GlobalBeaconCeremonyErrorV1::InvalidPlan)
        ));
    }
    GlobalBeaconCeremonyPlanV1::new(session, roster.clone(), handles(7), REVISION)
        .expect("valid plan");
    let mut reordered = roster.clone();
    reordered.swap(0, 1);
    let mut wrong_threshold = session;
    wrong_threshold.threshold = 2;
    let mut collapsed_windows = session;
    collapsed_windows.deliveries_end_height = collapsed_windows.commitments_end_height;
    let mut repeated_handles = handles(7);
    repeated_handles[1] = repeated_handles[0].clone();
    let mut test_handle = handles(7);
    test_handle[0] = "software://iroha/test/validator-1".to_owned();
    for (session, roster, handles, revision) in [
        (session, reordered, handles(7), REVISION),
        (wrong_threshold, roster.clone(), handles(7), REVISION),
        (collapsed_windows, roster.clone(), handles(7), REVISION),
        (session, roster.clone(), handles(6), REVISION),
        (session, roster.clone(), repeated_handles, REVISION),
        (session, roster.clone(), test_handle, REVISION),
        (session, roster.clone(), handles(7), 0),
    ] {
        assert!(matches!(
            GlobalBeaconCeremonyPlanV1::new(session, roster, handles, revision),
            Err(GlobalBeaconCeremonyErrorV1::InvalidPlan)
        ));
    }
}

#[test]
fn install_range_certificates_verify_only_at_their_effective_height() {
    for committee_size in [4_u16, 7] {
        let keys = roster_keys(committee_size, 0x45);
        let dealt = deal(&plan(&keys, 0x56), &keys);
        let network = dealt.record.session.network_id;
        let roster = roster(&keys);
        let context = GlobalBeaconInstallContextV1::new(dealt.record.clone(), roster.clone())
            .expect("fresh install context");
        let quorum = usize::from(context.quorum());
        assert_eq!(quorum, usize::from((committee_size - 1) / 3 * 2 + 1));
        let tip = dealt.record.session.adaptive_dkg.finalized_at_height;
        // Hosts answer in arbitrary order; range order must not matter.
        let ranges = keys[..quorum]
            .iter()
            .rev()
            .map(|key| context.sign_range(key, tip + 1, 16).expect("host range"))
            .collect::<Vec<_>>();
        for range in &ranges {
            assert_eq!(range.signatures.len(), 16);
            assert_eq!(range.first_effective_height, tip + 1);
            assert_eq!(range.session_id, dealt.record.session.session_id);
        }
        for height in [tip + 1, tip + 8, tip + 16] {
            let certificate = context
                .assemble_from_ranges(height, &ranges)
                .expect("assembled certificate");
            assert_eq!(
                certificate.action,
                ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey
            );
            assert_eq!(certificate.expected_active_session_id, None);
            assert_eq!(certificate.effective_height, height);
            assert_eq!(certificate.signatures.len(), quorum);
            assert_eq!(certificate.committee_size, committee_size);
            assert!(
                certificate
                    .signatures
                    .windows(2)
                    .all(|pair| pair[0].signer_index < pair[1].signer_index)
            );
            verify_threshold_key_lifecycle_certificate_v1(&certificate, &network, height, &roster)
                .expect("Core verifier accepts the chosen height");
            for other in [height - 1, height + 1] {
                assert!(
                    verify_threshold_key_lifecycle_certificate_v1(
                        &certificate,
                        &network,
                        other,
                        &roster
                    )
                    .is_err()
                );
                let mut moved = certificate.clone();
                moved.effective_height = other;
                assert_eq!(
                    verify_threshold_key_lifecycle_certificate_v1(&moved, &network, other, &roster),
                    Err(ThresholdKeyLifecycleCertificateErrorV1::InvalidQuorum),
                    "a signature for one height must not authorize another"
                );
            }
            let record =
                norito::decode_canonical::<FinalizedGlobalThresholdBeaconKeySessionRecordV1>(
                    &certificate.public_state,
                )
                .expect("canonical public state");
            assert_eq!(&record.session, dealt.record.session.record());
            assert_eq!(record.activated_at_height, dealt.record.activated_at_height);
            assert_eq!(record.retired_at_height, dealt.record.retired_at_height);
        }
        // Heights outside every host's signed range cannot be assembled.
        for height in [tip, tip + 17] {
            assert!(matches!(
                context.assemble_from_ranges(height, &ranges).err(),
                Some(GlobalBeaconCeremonyErrorV1::InvalidRange)
            ));
        }
        assert!(matches!(
            context.draft_certificate(tip).err(),
            Some(GlobalBeaconCeremonyErrorV1::Height)
        ));
    }
}

#[test]
fn install_assembly_enforces_exactly_two_f_plus_one_distinct_signers() {
    let committee_size = 7_u16;
    let keys = roster_keys(committee_size, 0x46);
    let dealt = deal(&plan(&keys, 0x57), &keys);
    let network = dealt.record.session.network_id;
    let roster = roster(&keys);
    let context = GlobalBeaconInstallContextV1::new(dealt.record.clone(), roster.clone())
        .expect("fresh install context");
    let quorum = usize::from(context.quorum());
    let height = dealt.record.session.adaptive_dkg.finalized_at_height + 1;
    let ranges = keys
        .iter()
        .map(|key| context.sign_range(key, height, 2).expect("host range"))
        .collect::<Vec<_>>();
    assert!(matches!(
        context
            .assemble_from_ranges(height, &ranges[..quorum - 1])
            .err(),
        Some(GlobalBeaconCeremonyErrorV1::Quorum)
    ));
    assert!(matches!(
        context
            .assemble_from_ranges(height, &ranges[..=quorum])
            .err(),
        Some(GlobalBeaconCeremonyErrorV1::Quorum)
    ));
    let mut duplicate = ranges[..quorum].to_vec();
    duplicate[1] = duplicate[0].clone();
    assert!(matches!(
        context.assemble_from_ranges(height, &duplicate).err(),
        Some(GlobalBeaconCeremonyErrorV1::Quorum)
    ));
    let mut foreign = ranges[..quorum].to_vec();
    foreign[0].session_id = [0xEE; 32];
    assert!(matches!(
        context.assemble_from_ranges(height, &foreign).err(),
        Some(GlobalBeaconCeremonyErrorV1::InvalidRange)
    ));
    let mut corrupted = ranges[..quorum].to_vec();
    corrupted[0].signatures.swap(0, 1);
    assert!(matches!(
        context.assemble_from_ranges(height, &corrupted).err(),
        Some(GlobalBeaconCeremonyErrorV1::Certificate(
            ThresholdKeyLifecycleCertificateErrorV1::InvalidQuorum
        ))
    ));
    // Verbatim assembly keeps the caller's certificate order and exact count.
    let signatures = keys
        .iter()
        .map(|key| context.sign(key, height).expect("single-height signature"))
        .collect::<Vec<_>>();
    let certificate = context
        .assemble(height, signatures[..quorum].to_vec())
        .expect("exact quorum");
    verify_threshold_key_lifecycle_certificate_v1(&certificate, &network, height, &roster)
        .expect("Core verifier");
    for signatures in [
        signatures[..quorum - 1].to_vec(),
        signatures[..=quorum].to_vec(),
        signatures[..quorum].iter().rev().cloned().collect(),
    ] {
        assert!(matches!(
            context.assemble(height, signatures),
            Err(GlobalBeaconCeremonyErrorV1::Certificate(_))
        ));
    }
    let outsider = KeyPair::from_seed(vec![0x99; 32], Algorithm::BlsNormal);
    assert!(matches!(
        context.sign_range(&outsider, height, 1).err(),
        Some(GlobalBeaconCeremonyErrorV1::NotAuthorized)
    ));
    for count in [0, GLOBAL_BEACON_INSTALL_RANGE_MAX_HEIGHTS_V1 + 1] {
        assert!(matches!(
            context.sign_range(&keys[0], height, count).err(),
            Some(GlobalBeaconCeremonyErrorV1::InvalidRange)
        ));
    }
    assert!(matches!(
        context.sign_range(&keys[0], u64::MAX, 2).err(),
        Some(GlobalBeaconCeremonyErrorV1::InvalidRange)
    ));
    let mut active = dealt.record.clone();
    active.activate(height + 1).expect("activate fixture");
    assert!(matches!(
        GlobalBeaconInstallContextV1::new(active, roster.clone()).err(),
        Some(GlobalBeaconCeremonyErrorV1::InvalidPlan)
    ));
    assert!(matches!(
        GlobalBeaconInstallContextV1::new(dealt.record.clone(), roster[..6].to_vec()).err(),
        Some(GlobalBeaconCeremonyErrorV1::InvalidPlan)
    ));
}

#[test]
fn seat_bindings_and_install_ranges_roundtrip_norito_and_json() {
    let keys = roster_keys(4, 0x47);
    let dealt = deal(&plan(&keys, 0x58), &keys);
    let binding = dealt.seats[2].binding.clone();
    let encoded = norito::encode_canonical(&binding).expect("encode binding");
    assert_eq!(
        norito::decode_canonical::<GlobalBeaconSeatBindingV1>(&encoded).expect("decode binding"),
        binding
    );
    let json = norito::json::to_vec(&binding).expect("binding JSON");
    assert_eq!(
        norito::json::from_slice::<GlobalBeaconSeatBindingV1>(&json).expect("binding from JSON"),
        binding
    );
    let context = GlobalBeaconInstallContextV1::new(dealt.record.clone(), roster(&keys))
        .expect("install context");
    let range = context
        .sign_range(
            &keys[1],
            dealt.record.session.adaptive_dkg.finalized_at_height + 1,
            3,
        )
        .expect("range");
    assert_eq!(range.signer_index, 1);
    assert_eq!(context.signer_index(keys[1].public_key()).unwrap(), 1);
    let encoded = norito::encode_canonical(&range).expect("encode range");
    assert_eq!(
        norito::decode_canonical::<GlobalBeaconInstallRangeSignaturesV1>(&encoded)
            .expect("decode range"),
        range
    );
    let json = norito::json::to_vec(&range).expect("range JSON");
    assert_eq!(
        norito::json::from_slice::<GlobalBeaconInstallRangeSignaturesV1>(&json)
            .expect("range from JSON"),
        range
    );
    let mut value = norito::json::to_value(&range).expect("range JSON value");
    value
        .as_object_mut()
        .expect("range object")
        .insert("extra".to_owned(), norito::json::Value::from(1_u64));
    assert!(norito::json::from_value::<GlobalBeaconInstallRangeSignaturesV1>(value).is_err());
}

#[test]
fn maximum_deal_and_install_keep_one_original_graph_within_sixty_four_mebibytes() {
    let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    let keys = roster_keys(31, 0x49);
    let plan = plan(&keys, 0x59);
    let dealt =
        deal_global_beacon_at_logical_clock_v1(&plan, &keys.iter().collect::<Vec<_>>(), &budget)
            .expect("all 31 real DKG seats within the unchanged original pool");
    assert_eq!(dealt.seats.len(), 31);
    assert!(
        dealt
            .seats
            .iter()
            .all(|seat| seat.credential.belongs_to(&budget))
    );
    assert!(dealt.record.session.belongs_to(&budget));
    let retained = dealt.record.session.clone();
    let original_recipients = retained.adaptive_dkg.recipient_keys.as_ptr();
    let original_edges = retained.adaptive_dkg.encrypted_shares.as_ptr();
    let context = GlobalBeaconInstallContextV1::new(dealt.record.clone(), roster(&keys))
        .expect("install context shares the original validated graph");
    assert!(context.record().session.ptr_eq(&retained));
    assert_eq!(
        context
            .record()
            .session
            .adaptive_dkg
            .recipient_keys
            .as_ptr(),
        original_recipients
    );
    assert_eq!(
        context
            .record()
            .session
            .adaptive_dkg
            .encrypted_shares
            .as_ptr(),
        original_edges
    );
    assert_eq!(context.quorum(), 21);
    let bindings = dealt
        .seats
        .iter()
        .map(|seat| seat.binding.clone())
        .collect::<Vec<_>>();
    plan.verify_seat_bindings(&dealt.record, &bindings)
        .expect("every original target seat");
    drop(dealt);
    assert!(context.record().session.ptr_eq(&retained));
    drop(context);
    assert_eq!(
        budget.reserved_bytes(),
        retained.retained_allocation_bytes()
    );
    drop(retained);
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(budget.peak_reserved_bytes() <= 64 * 1024 * 1024);
}
