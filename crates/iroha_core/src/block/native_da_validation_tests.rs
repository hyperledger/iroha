// DA admission assertions on original native proposals over genuinely committed history.
impl NativeValidationFixture {
    fn pin_intent(
        &self,
        lane_id: LaneId,
        epoch: u64,
        sequence: u64,
        storage_ticket: StorageTicketId,
        manifest_hash: ManifestDigest,
    ) -> DaPinIntent {
        crate::da::signed_test_pin_intent(
            crate::da::signed_test_ingest_authorization(
                self.chain.network_id(),
                &self.user,
                lane_id,
                epoch,
                sequence,
                1,
            ),
            &self.user,
            storage_ticket,
            manifest_hash,
            None,
        )
    }
}
#[test]
fn native_validation_rejects_unknown_da_lane() {
    let fixture = NativeValidationFixture::new();
    let record = DaCommitmentRecord::new(
        LaneId::new(7),
        1,
        1,
        BlobDigest::new([0xAA; 32]),
        ManifestDigest::new([0xBB; 32]),
        DaProofScheme::MerkleSha256,
        Hash::prehashed([0xCC; 32]),
        None,
        RetentionClass::default(),
        StorageTicketId::new([0xEE; 32]),
        checked_da_ack_signature(0x11),
    );
    let bundle = DaCommitmentBundle::new(vec![record]);
    let mut signed = fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    signed.set_da_commitments(Some(bundle));
    let result = fixture.validate(signed).unpack(|_| {});
    let Err((_, err)) = result else {
        panic!("expected DA commitment bundle rejection");
    };
    assert!(
        matches!(
            err.as_ref(),
            BlockValidationError::DaCommitmentBundle(DaCommitmentValidationError::ProofPolicy(
                crate::da::DaProofPolicyError::UnknownLane { .. }
            ))
        ),
        "expected unknown DA lane rejection, got {err:?}"
    );

    assert_eq!(fixture.chain.state().view().height(), 2);
}

#[test]
fn native_validation_rejects_duplicate_da_manifest() {
    let fixture = NativeValidationFixture::new();
    let make_record = |sequence: u64, tag: u8| {
        DaCommitmentRecord::new(
            LaneId::new(0),
            1,
            sequence,
            BlobDigest::new([tag; 32]),
            ManifestDigest::new([0xBB; 32]),
            DaProofScheme::MerkleSha256,
            Hash::prehashed([tag; 32]),
            None,
            RetentionClass::default(),
            StorageTicketId::new([tag; 32]),
            checked_da_ack_signature(tag),
        )
    };
    let bundle = DaCommitmentBundle::new(vec![make_record(1, 0xC1), make_record(2, 0xC2)]);
    let mut signed = fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    signed.set_da_commitments(Some(bundle));
    let result = fixture.validate(signed).unpack(|_| {});
    let Err((_, err)) = result else {
        panic!("expected DA commitment duplicate-manifest rejection");
    };
    assert!(matches!(
        err.as_ref(),
        BlockValidationError::DaCommitmentBundle(
            DaCommitmentValidationError::DuplicateManifest { lane }
        ) if *lane == LaneId::new(0)
    ));

    assert_eq!(fixture.chain.state().view().height(), 2);
}

#[test]
fn native_validation_rejects_duplicate_da_storage_ticket() {
    let fixture = NativeValidationFixture::new();
    let make_record = |sequence: u64, tag: u8| {
        DaCommitmentRecord::new(
            LaneId::new(0),
            1,
            sequence,
            BlobDigest::new([tag; 32]),
            ManifestDigest::new([tag; 32]),
            DaProofScheme::MerkleSha256,
            Hash::prehashed([tag; 32]),
            None,
            RetentionClass::default(),
            StorageTicketId::new([0xDD; 32]),
            checked_da_ack_signature(tag),
        )
    };
    let bundle = DaCommitmentBundle::new(vec![make_record(1, 0xC1), make_record(2, 0xC2)]);
    let mut signed = fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    signed.set_da_commitments(Some(bundle));
    let result = fixture.validate(signed).unpack(|_| {});
    let Err((_, err)) = result else {
        panic!("expected DA commitment duplicate-storage-ticket rejection");
    };
    assert!(matches!(
        err.as_ref(),
        BlockValidationError::DaCommitmentBundle(
            DaCommitmentValidationError::DuplicateStorageTicket { lane, epoch, sequence }
        ) if *lane == LaneId::new(0) && *epoch == 1 && *sequence == 2
    ));

    assert_eq!(fixture.chain.state().view().height(), 2);
}

#[test]
fn native_validation_rejects_da_commitment_hash_mismatch() {
    let fixture = NativeValidationFixture::new();
    let record = DaCommitmentRecord::new(
        LaneId::new(0),
        1,
        1,
        BlobDigest::new([0xAA; 32]),
        ManifestDigest::new([0xBB; 32]),
        DaProofScheme::MerkleSha256,
        Hash::prehashed([0xCC; 32]),
        None,
        RetentionClass::default(),
        StorageTicketId::new([0xDD; 32]),
        checked_da_ack_signature(0xEE),
    );
    let bundle = DaCommitmentBundle::new(vec![record]);
    let expected = bundle.merkle_commitment();
    let forged = Some(HashOf::<DaCommitmentBundle>::from_untyped_unchecked(
        Hash::prehashed([0xFA; 32]),
    ));
    let mut signed = fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    signed.set_da_commitments(Some(bundle));
    let mut header = signed.header();
    header.set_da_commitments_hash(forged);
    signed.replace_header_for_testing(header);
    assert_ne!(expected, forged, "fixture forged hash must differ");
    let result = fixture.validate(signed).unpack(|_| {});
    let Err((_, err)) = result else {
        panic!("expected DA commitment hash mismatch rejection");
    };
    assert!(matches!(
        err.as_ref(),
        BlockValidationError::DaCommitmentHashMismatch { expected: seen_expected, actual }
            if *seen_expected == expected && *actual == forged
    ));

    assert_eq!(fixture.chain.state().view().height(), 2);
}

#[test]
fn native_validation_rejects_da_pin_intent_hash_mismatch() {
    let fixture = NativeValidationFixture::new();
    let intent = fixture.pin_intent(
        LaneId::new(0),
        1,
        1,
        StorageTicketId::new([0xAA; 32]),
        ManifestDigest::new([0xBB; 32]),
    );
    let bundle = DaPinIntentBundle::new(vec![intent]);
    let expected = bundle.merkle_commitment();
    let forged = Some(HashOf::<DaPinIntentBundle>::from_untyped_unchecked(
        Hash::prehashed([0xFB; 32]),
    ));
    let mut signed = fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    signed.set_da_pin_intents(Some(bundle));
    let mut header = signed.header();
    header.set_da_pin_intents_hash(forged);
    signed.replace_header_for_testing(header);
    assert_ne!(expected, forged, "fixture forged hash must differ");
    let result = fixture.validate(signed).unpack(|_| {});
    let Err((_, err)) = result else {
        panic!("expected DA pin-intent hash mismatch rejection");
    };
    match err.as_ref() {
        BlockValidationError::DaPinIntentHashMismatch {
            expected: seen_expected,
            actual,
        } if *seen_expected == expected && *actual == forged => {}
        other => panic!("expected DA pin-intent hash mismatch, got {other:?}"),
    }

    assert_eq!(fixture.chain.state().view().height(), 2);
}

#[test]
fn native_validation_rejects_duplicate_da_pin_intent_ticket() {
    let fixture = NativeValidationFixture::new();
    let first = fixture.pin_intent(
        LaneId::new(0),
        1,
        1,
        StorageTicketId::new([0xAA; 32]),
        ManifestDigest::new([0xB1; 32]),
    );
    let duplicate_ticket = fixture.pin_intent(
        LaneId::new(0),
        1,
        2,
        StorageTicketId::new([0xAA; 32]),
        ManifestDigest::new([0xB2; 32]),
    );
    let bundle = DaPinIntentBundle::new(vec![first, duplicate_ticket]);
    let mut signed = fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    signed.set_da_pin_intents(Some(bundle));
    let result = fixture.validate(signed).unpack(|_| {});
    let Err((_, err)) = result else {
        panic!("expected DA pin-intent duplicate-ticket rejection");
    };
    assert!(
        matches!(
            err.as_ref(),
            BlockValidationError::DaPinIntentBundle(
                DaPinIntentValidationError::DuplicateStorageTicket {
                    lane,
                    epoch: 1,
                    sequence: 2
                }
            ) if *lane == LaneId::new(0)
        ),
        "unexpected duplicate-ticket error: {err:?}"
    );

    assert_eq!(fixture.chain.state().view().height(), 2);
}

#[test]
fn native_validation_rejects_unsupported_da_pin_intent_version() {
    let fixture = NativeValidationFixture::new();
    let intent = fixture.pin_intent(
        LaneId::new(0),
        1,
        1,
        StorageTicketId::new([0xAA; 32]),
        ManifestDigest::new([0xBB; 32]),
    );
    let mut bundle = DaPinIntentBundle::new(vec![intent]);
    bundle.version = DaPinIntentBundle::VERSION_V1 + 1;
    let mut signed = fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    signed.set_da_pin_intents(Some(bundle));
    let result = fixture.validate(signed).unpack(|_| {});
    let Err((_, err)) = result else {
        panic!("expected DA pin-intent version rejection");
    };
    assert!(matches!(
        err.as_ref(),
        BlockValidationError::DaPinIntentBundle(
            DaPinIntentValidationError::UnsupportedVersion { version }
        ) if *version == DaPinIntentBundle::VERSION_V1 + 1
    ));

    assert_eq!(fixture.chain.state().view().height(), 2);
}

impl NativeValidationFixture {
    fn install_da_policy(&mut self) {
        use iroha_data_model::da::ingest::{DaIngestAdmissionLaneV1, DaIngestAdmissionPolicyV1};
        let state = self.chain.state();
        let view = state.view();
        let incarnation = StateReadOnly::lane_incarnation_at_height(
            &view,
            LaneId::SINGLE,
            self.chain.height() + 1,
        )
        .unwrap();
        drop(view);
        let policy = DaIngestAdmissionPolicyV1 {
            version: DaIngestAdmissionPolicyV1::VERSION,
            revision: 1,
            expected_previous_policy_hash: None,
            lanes: vec![DaIngestAdmissionLaneV1 {
                lane_id: LaneId::SINGLE,
                lane_incarnation: incarnation,
                producers: vec![AccountId::new(self.user.public_key().clone())],
                current_epoch: 1,
                grace_epoch: None,
            }],
        };
        policy.validate_transition(None).unwrap();
        let update = self.chain.sign(
            &self.user,
            [InstructionBox::from(
                iroha_data_model::isi::SetParameter::new(Parameter::Custom(
                    policy.into_custom_parameter(),
                )),
            )],
            2_001,
        );
        assert_eq!(self.chain.commit(vec![update]), vec![true]);
    }
}

#[test]
fn native_validation_rejects_stale_geometry_da_pin_intent_lane() {
    let fixture = NativeValidationFixture::new();
    let stale_lane = LaneId::new(1);
    let stale = LaneCatalog::new(
        nonzero!(2_u32),
        vec![
            LaneConfig::default(),
            LaneConfig {
                id: stale_lane,
                alias: "stale-derived-da-lane".to_owned(),
                ..LaneConfig::default()
            },
        ],
    )
    .unwrap();
    fixture.chain.state().nexus.write().lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&stale);
    let mut proposal = fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    proposal.set_da_pin_intents(Some(DaPinIntentBundle::new(vec![fixture.pin_intent(
        stale_lane,
        1,
        1,
        StorageTicketId::new([0xA1; 32]),
        ManifestDigest::new([0xB1; 32]),
    )])));
    let (_, error) = fixture.validate(proposal).unpack(|_| {}).err().unwrap();
    assert!(matches!(*error, BlockValidationError::DaPinIntentBundle(
        DaPinIntentValidationError::UnknownLane { lane }
    ) if lane == stale_lane));
    assert_eq!(fixture.chain.state().view().height(), 2);
}

#[test]
fn native_validation_enforces_consensus_da_ingest_quota() {
    let mut fixture = NativeValidationFixture::new();
    fixture.install_da_policy();
    fixture
        .chain
        .state()
        .nexus
        .write()
        .da
        .ingest_quota_max_count_per_account = nonzero!(1_u64);
    let mut proposal = fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    proposal.set_da_pin_intents(Some(DaPinIntentBundle::new(vec![
        fixture.pin_intent(
            LaneId::SINGLE,
            1,
            1,
            StorageTicketId::new([0xC1; 32]),
            ManifestDigest::new([0xD1; 32]),
        ),
        fixture.pin_intent(
            LaneId::SINGLE,
            1,
            2,
            StorageTicketId::new([0xC2; 32]),
            ManifestDigest::new([0xD2; 32]),
        ),
    ])));
    let (_, error) = fixture.validate(proposal).unpack(|_| {}).err().unwrap();
    assert!(matches!(
        *error,
        BlockValidationError::DaPinIntentBundle(DaPinIntentValidationError::QuotaExceeded {
            count: 2,
            max_count: 1,
            ..
        })
    ));
    assert_eq!(fixture.chain.state().view().height(), 3);
}

#[test]
fn native_validation_rejects_committed_da_pin_intent_identity_reuse() {
    let mut fixture = NativeValidationFixture::new();
    fixture.install_da_policy();
    let original = fixture.pin_intent(
        LaneId::SINGLE,
        1,
        1,
        StorageTicketId::new([0xA1; 32]),
        ManifestDigest::new([0xB1; 32]),
    );
    let mut proposal = fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    proposal.set_da_pin_intents(Some(DaPinIntentBundle::new(vec![original.clone()])));
    fixture.chain.commit_proposal(
        proposal,
        crate::sumeragi::test_chain::Signers::Quorum,
        iroha_sumeragi::types::ControlWitness::default(),
    );
    for (intent, expected) in [
        (
            fixture.pin_intent(
                LaneId::SINGLE,
                1,
                2,
                original.storage_ticket,
                ManifestDigest::new([0xB2; 32]),
            ),
            "ticket",
        ),
        (
            fixture.pin_intent(
                LaneId::SINGLE,
                1,
                2,
                StorageTicketId::new([0xA2; 32]),
                original.manifest_hash,
            ),
            "manifest",
        ),
        (
            fixture.pin_intent(
                LaneId::SINGLE,
                1,
                1,
                StorageTicketId::new([0xA3; 32]),
                ManifestDigest::new([0xB3; 32]),
            ),
            "identity",
        ),
    ] {
        let mut proposal =
            fixture.proposal(vec![fixture.transaction(2_010, None)], fixture.cadence());
        proposal.set_da_pin_intents(Some(DaPinIntentBundle::new(vec![intent])));
        let (_, error) = fixture.validate(proposal).unpack(|_| {}).err().unwrap();
        assert!(
            match (expected, error.as_ref()) {
                (
                    "ticket",
                    BlockValidationError::DaPinIntentBundle(
                        DaPinIntentValidationError::DuplicateStorageTicket { lane, .. },
                    ),
                ) => *lane == LaneId::SINGLE,
                (
                    "manifest",
                    BlockValidationError::DaPinIntentBundle(
                        DaPinIntentValidationError::DuplicateManifest { lane, .. },
                    ),
                ) => *lane == LaneId::SINGLE,
                (
                    "identity",
                    BlockValidationError::DaPinIntentBundle(
                        DaPinIntentValidationError::DuplicateIntent { lane, .. },
                    ),
                ) => *lane == LaneId::SINGLE,
                _ => false,
            },
            "unexpected committed {expected} reuse error: {error:?}"
        );
        assert_eq!(fixture.chain.state().view().height(), 4);
    }
}

#[test]
fn native_validation_enforces_height_aware_da_policy_before_lane_creation() {
    let fixture = NativeValidationFixture::new();
    let lane = LaneId::new(1);
    let nexus = future_created_autoscale_nexus(fixture.chain.state(), lane, 7);
    let height = fixture.chain.height() + 1;
    let correct = crate::da::active_proof_policy_bundle_at_height(&nexus, height);
    let heightless = crate::da::active_proof_policy_bundle(&nexus);
    assert!(
        correct
            .policies()
            .iter()
            .all(|policy| policy.lane_id != lane)
    );
    assert!(
        heightless
            .policies()
            .iter()
            .any(|policy| policy.lane_id == lane)
    );
    assert_ne!(HashOf::new(&correct), HashOf::new(&heightless));
    *fixture.chain.state().nexus.write() = nexus;
    let mut valid = fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    valid.set_da_proof_policies(Some(correct.clone()));
    let (_, overlay) = fixture.validate(valid).unpack(|_| {}).unwrap();
    drop(overlay);
    let mut invalid = fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    invalid.set_da_proof_policies(Some(heightless.clone()));
    let (_, error) = fixture.validate(invalid).unpack(|_| {}).err().unwrap();
    assert!(
        matches!(*error, BlockValidationError::ProofPolicyHashMismatch { expected, actual }
        if expected == HashOf::new(&correct) && actual == Some(HashOf::new(&heightless)))
    );
    assert_eq!(fixture.chain.state().view().height(), 2);

    let mut future_intent =
        fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    future_intent.set_da_pin_intents(Some(DaPinIntentBundle::new(vec![fixture.pin_intent(
        lane,
        1,
        1,
        StorageTicketId::new([0xA9; 32]),
        ManifestDigest::new([0xB9; 32]),
    )])));
    let (_, error) = fixture
        .validate(future_intent)
        .unpack(|_| {})
        .err()
        .unwrap();
    assert!(matches!(*error, BlockValidationError::DaPinIntentBundle(
        DaPinIntentValidationError::UnknownLane { lane: rejected }
    ) if rejected == lane));
    assert_eq!(fixture.chain.state().view().height(), 2);
}

#[test]
fn native_validation_rejects_stale_geometry_da_proof_policy() {
    let fixture = NativeValidationFixture::new();
    let stale = LaneCatalog::new(
        nonzero!(2_u32),
        vec![
            LaneConfig::default(),
            LaneConfig {
                id: LaneId::new(1),
                alias: "stale-proof-policy".to_owned(),
                ..LaneConfig::default()
            },
        ],
    )
    .unwrap();
    let stale_policies = crate::da::proof_policy_bundle(
        &iroha_config::parameters::actual::LaneConfig::from_catalog(&stale),
    );
    let expected =
        crate::da::active_proof_policy_bundle_hash(&fixture.chain.state().nexus_snapshot());
    let actual = Some(HashOf::new(&stale_policies));
    assert_ne!(actual, Some(expected));
    let mut proposal = fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    proposal.set_da_proof_policies(Some(stale_policies));
    let (_, error) = fixture.validate(proposal).unpack(|_| {}).err().unwrap();
    assert!(
        matches!(*error, BlockValidationError::ProofPolicyHashMismatch { expected: e, actual: a }
        if e == expected && a == actual)
    );
    assert_eq!(fixture.chain.state().view().height(), 2);
}

#[test]
fn native_validation_rejects_da_cursor_regression() {
    let mut fixture = NativeValidationFixture::new();
    let record = |sequence, byte| {
        DaCommitmentRecord::new(
            LaneId::SINGLE,
            2,
            sequence,
            BlobDigest::new([byte; 32]),
            ManifestDigest::new([byte; 32]),
            DaProofScheme::MerkleSha256,
            Hash::prehashed([byte; 32]),
            None,
            RetentionClass::default(),
            StorageTicketId::new([byte; 32]),
            checked_da_ack_signature(byte),
        )
    };
    let mut predecessor =
        fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    predecessor.set_da_commitments(Some(DaCommitmentBundle::new(vec![record(3, 0xAB)])));
    fixture.chain.commit_proposal(
        predecessor,
        crate::sumeragi::test_chain::Signers::Quorum,
        iroha_sumeragi::types::ControlWitness::default(),
    );
    {
        let cursors = fixture
            .chain
            .state()
            .da_shard_cursor_index()
            .expect("original DA hydration");
        let cursor = cursors.get(0, LaneId::SINGLE).unwrap();
        assert_eq!((cursor.epoch, cursor.sequence), (2, 3));
    }
    let mut proposal = fixture.proposal(vec![fixture.transaction(2_010, None)], fixture.cadence());
    proposal.set_da_commitments(Some(DaCommitmentBundle::new(vec![record(2, 0xBC)])));
    let generation = fixture.chain.state().state_view_generation();
    let receipts = fixture
        .chain
        .state()
        .da_receipt_cursors()
        .expect("original DA hydration")
        .snapshot();
    let (_, error) = fixture.validate(proposal).unpack(|_| {}).err().unwrap();
    // The original committed receipt cursor rejects this regression before the
    // shard cursor is advanced; both indexes must retain their certified values.
    assert!(
        matches!(
            *error,
            BlockValidationError::DaReceiptCursor(
                crate::da::receipts::DaReceiptCursorError::Regression {
                    lane: LaneId::SINGLE,
                    epoch: 2,
                    observed: 2,
                    recorded: 3,
                }
            )
        ),
        "unexpected regression rejection: {error:?}"
    );
    let cursors = fixture
        .chain
        .state()
        .da_shard_cursor_index()
        .expect("original DA hydration");
    let cursor = cursors.get(0, LaneId::SINGLE).unwrap();
    assert_eq!(
        (cursor.epoch, cursor.sequence, cursor.last_block_height),
        (2, 3, 3)
    );
    assert_eq!(
        fixture
            .chain
            .state()
            .da_receipt_cursors()
            .expect("original DA hydration")
            .snapshot(),
        receipts
    );
    assert_eq!(fixture.chain.state().state_view_generation(), generation);
    assert_eq!(fixture.chain.state().view().height(), 3);
}
