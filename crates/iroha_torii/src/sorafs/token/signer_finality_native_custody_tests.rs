//! Local native custody and certified finality integration, using software-signed fixtures.
//!
//! This is not replicated consensus, state-root certification, or physical HSM qualification.
//! The custody mutations are ordinary signed transactions in blocks of a certified test chain
//! (`iroha_core::sumeragi::test_chain`): real execution, and each block's local three-of-four BLS
//! `CommitQC` either verifies or (for the negative cases) does not.

use super::{
    StreamTokenIssuerError, StreamTokenSignerPinsV1,
    signer_finality::{CoreFinalityV1, FinalityFloorV1, HistoricalFinalityV1, SignerFinalityV1},
    signer_test_support::{NOW_MS, PROVIDER, storage_config},
};
use iroha_core::{
    query::stream_token_custody::{
        StreamTokenCustodyControlSnapshotV1, read_stream_token_custody_control_at_v1,
    },
    state::{State, StateReadOnly, World},
    sumeragi::{
        certified_chain::{CertifiedChain, QcVerification},
        test_chain::{CertifiedTestChain, Signers, TestChainConfig},
    },
};
use iroha_crypto::{Algorithm, KeyPair, Signature};
use iroha_data_model::{
    Registrable,
    account::{Account, AccountId},
    isi::{InstructionBox, Log, sorafs::MutateSorafsStreamTokenCustody},
    permission::{Permission, Permissions},
    sorafs::{
        capacity::ProviderId,
        stream_token_custody::{
            SorafsStreamTokenCustodyActionV1, SorafsStreamTokenCustodyRevocationV1,
        },
    },
};
use iroha_executor_data_model::permission::sorafs::CanManageSorafsStreamTokenCustody;
use sorafs_manifest::signer::{
    custody::{
        SIGNER_CUSTODY_MAGIC_V1, SIGNER_CUSTODY_VERSION_V1, SignerCustodyAnchorV1,
        SignerCustodyRecordV1, SignerCustodyStatementV1,
    },
    custody_control::SignerCustodyPolicyV1,
    stream_token::stream_token_binding_digest_v1,
    stream_token_evidence::{
        SignerStreamTokenObservationExpectedV1, SignerStreamTokenObservationPhaseV1,
        SignerStreamTokenStateObservationBodyV1, SignerStreamTokenStateObservationV1,
        SignerStreamTokenStateSubjectV1, verify_stream_token_signer_current_evidence_v1,
    },
};
use std::sync::Arc;

fn fixture_key(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("checked local fixture key")
}

struct NativeCustodyFixture {
    chain: CertifiedTestChain,
    state: Arc<State>,
    pins: StreamTokenSignerPinsV1,
    approval: SignerCustodyAnchorV1,
    current: StreamTokenCustodyControlSnapshotV1,
    enrollment: Vec<u8>,
}

impl NativeCustodyFixture {
    /// Configuration (height 2) and enrollment (height 3), both certified.
    fn new() -> Self {
        let key = fixture_key(0xA1);
        let authority = AccountId::new(key.public_key().clone());
        let provider = ProviderId::new(PROVIDER);
        let mut world = World::with([], [Account::new(authority.clone()).build(&authority)], []);
        world
            .provider_owners_mut_for_testing()
            .insert(provider, authority.clone());
        let mut permissions = Permissions::new();
        permissions.insert(Permission::from(CanManageSorafsStreamTokenCustody {
            provider_id: provider,
        }));
        world
            .account_permissions_mut_for_testing()
            .insert(authority, permissions);
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(world, NOW_MS - 1_500))
            .expect("certified fixture chain");
        let state = Arc::clone(chain.state());
        let pins = StreamTokenSignerPinsV1::from_config(
            &storage_config(1),
            &state.view().chain_id().to_string(),
            *state.network_id_ref().as_bytes(),
        )
        .expect("independent public fixture pins")
        .expect("enabled signer_backend profile");
        let trust = pins.custody_trust();
        assert_eq!(&trust.public_key, fixture_key(0x44).public_key());
        assert_eq!(
            &pins.observer_trust().public_key,
            fixture_key(0x55).public_key()
        );
        let policy = SignerCustodyPolicyV1 {
            binding: pins.binding().clone(),
            attester_authority: trust.authority.clone(),
            attester_public_key: trust.public_key.clone(),
            active_from_unix_ms: trust.active_from_unix_ms,
            active_until_unix_ms: trust.active_until_unix_ms,
            max_validity_ms: trust.max_validity_ms,
            max_anchor_age_ms: trust.max_anchor_age_ms,
        };
        let configure = MutateSorafsStreamTokenCustody {
            provider_id: provider,
            expected_revision: 0,
            expected_digest: [0; 32],
            action: SorafsStreamTokenCustodyActionV1::Configure(
                norito::encode_canonical(&policy).expect("canonical policy"),
            ),
        };
        let at = NOW_MS - 500;
        let transaction = chain.sign(&key, [InstructionBox::from(configure)], at - 1);
        assert_eq!(
            chain.commit_with(Some(at), vec![transaction], Signers::Quorum),
            [true],
            "actual authorized native configuration"
        );
        let approval = read_stream_token_custody_control_at_v1(&state.view(), pins.binding(), 2)
            .expect("real native approval lookup")
            .expect("configured native control");
        assert!(approval.state.active_head.is_none());
        let statement = SignerCustodyStatementV1 {
            magic: SIGNER_CUSTODY_MAGIC_V1,
            version: SIGNER_CUSTODY_VERSION_V1,
            binding: pins.binding().clone(),
            authority: trust.authority.clone(),
            anchor: approval.anchor,
            sequence: approval.state.next_sequence,
            predecessor_digest: approval.state.predecessor_digest,
            issued_at_unix_ms: NOW_MS,
            expires_at_unix_ms: NOW_MS + 5_000,
            evidence_digest: [0x88; 32],
            revoked: false,
        };
        // These signed signer assertions are trusted software fixture claims, not device evidence.
        let signature = Signature::try_new(
            fixture_key(0x44).private_key(),
            &statement
                .signing_payload()
                .expect("canonical custody preimage"),
        )
        .expect("software fixture attestation");
        let enrollment = norito::encode_canonical(&SignerCustodyRecordV1 {
            statement,
            attestation: signature.payload().try_into().expect("Ed25519 signature"),
        })
        .expect("canonical full enrollment");
        let enroll = MutateSorafsStreamTokenCustody {
            provider_id: provider,
            expected_revision: 1,
            expected_digest: approval.anchor.state_digest,
            action: SorafsStreamTokenCustodyActionV1::Enroll(enrollment.clone()),
        };
        let transaction = chain.sign(&key, [InstructionBox::from(enroll)], NOW_MS - 1);
        assert_eq!(
            chain.commit_with(Some(NOW_MS), vec![transaction], Signers::Quorum),
            [true],
            "actual authorized native enrollment"
        );
        let current = read_stream_token_custody_control_at_v1(&state.view(), pins.binding(), 3)
            .expect("real native current lookup")
            .expect("enrolled native control");
        assert_eq!(
            current
                .state
                .active_head
                .expect("native enrolled head")
                .approved_anchor,
            approval.anchor
        );
        Self {
            chain,
            state,
            pins,
            approval: approval.anchor,
            current,
            enrollment,
        }
    }

    fn guard(&self) -> CoreFinalityV1 {
        CoreFinalityV1::new(self.state.clone(), self.pins.clone())
    }

    fn verified_observation_at(
        &self,
        current_anchor: SignerCustodyAnchorV1,
    ) -> SignerStreamTokenStateObservationBodyV1 {
        self.verified_observation_for_phase(
            current_anchor,
            SignerStreamTokenObservationPhaseV1::BeforeAdmission,
        )
    }

    fn verified_observation_for_phase(
        &self,
        current_anchor: SignerCustodyAnchorV1,
        phase: SignerStreamTokenObservationPhaseV1,
    ) -> SignerStreamTokenStateObservationBodyV1 {
        let mut expected = SignerStreamTokenObservationExpectedV1::current(
            self.pins.binding(),
            phase,
            [0x93; 32],
            self.approval,
            NOW_MS,
        )
        .expect("exact independent observation request");
        let body = SignerStreamTokenStateObservationBodyV1 {
            magic: SignerStreamTokenStateObservationBodyV1::magic(),
            request_digest: expected
                .request()
                .digest()
                .expect("canonical request digest"),
            phase,
            subject: SignerStreamTokenStateSubjectV1::CurrentCustody {
                binding_digest: stream_token_binding_digest_v1(self.pins.binding())
                    .expect("exact binding digest"),
            },
            authority: self.pins.observer_trust().authority.clone(),
            chain_id: self.pins.binding().chain_id.clone(),
            network_id: self.pins.binding().network_id,
            observed_at_unix_ms: NOW_MS,
            expires_at_unix_ms: NOW_MS + 1_000,
            current_anchor,
            active_head: self.current.state.active_head.expect("native active head"),
            signer_revoked: self.current.state.signer_revoked,
            attester_revoked: self.current.state.attester_revoked,
        };
        let signature = Signature::try_new(
            fixture_key(0x55).private_key(),
            &body
                .signing_payload()
                .expect("exact state observation preimage"),
        )
        .expect("software fixture observer signature");
        let bytes = SignerStreamTokenStateObservationV1 {
            body: body.clone(),
            signature: signature.payload().try_into().expect("Ed25519 signature"),
        }
        .encode_canonical()
        .expect("canonical signed observation");
        verify_stream_token_signer_current_evidence_v1(
            &self.enrollment,
            &bytes,
            self.pins.binding(),
            self.pins.custody_trust(),
            self.pins.observer_trust(),
            &mut expected,
            NOW_MS,
        )
        .expect("full independent custody and observation verification");
        body
    }

    fn validate(
        &self,
        guard: &CoreFinalityV1,
        floor: FinalityFloorV1,
        candidate: SignerCustodyAnchorV1,
        observation: &SignerStreamTokenStateObservationBodyV1,
    ) -> Result<(), StreamTokenIssuerError> {
        guard.validate(
            self.approval,
            candidate,
            floor,
            &[HistoricalFinalityV1::Custody(self.approval)],
            observation,
            None,
        )
    }
}

#[test]
fn actual_native_custody_requires_both_certified_blocks_then_accepts_signed_observation() {
    for height in [2, 3] {
        let fixture = NativeCustodyFixture::new();
        // Publish both native mutations with genuine quorum certificates first. Corrupt the
        // retained configuration/enrollment QC independently at the consumer boundary: the
        // real publication worker must never be asked to accept a below-quorum certificate.
        fixture
            .chain
            .corrupt_local_quorum_for_test(height, Signers::BelowQuorum);
        assert!(matches!(
            fixture.guard().capture(fixture.approval),
            Err(StreamTokenIssuerError::SignerFinalityUnavailable)
        ));
    }
    let fixture = NativeCustodyFixture::new();
    let guard = fixture.guard();
    let observation = fixture.verified_observation_at(fixture.current.anchor);
    let floor = guard
        .capture(fixture.approval)
        .expect("real native and certified current floor");
    assert_eq!(floor.height, 3);
    assert_eq!(floor.block_hash, fixture.current.anchor.block_hash);
    fixture
        .validate(&guard, floor, fixture.current.anchor, &observation)
        .expect("exact native custody, historical approval and durable Commit QCs");
}

#[test]
fn actual_native_custody_rejects_same_height_forged_control_digests() {
    let fixture = NativeCustodyFixture::new();
    let guard = fixture.guard();
    let observation = fixture.verified_observation_at(fixture.current.anchor);
    let floor = guard
        .capture(fixture.approval)
        .expect("positive floor control");
    fixture
        .validate(&guard, floor, fixture.current.anchor, &observation)
        .expect("positive validation control");
    let mut forged = fixture.current.anchor;
    forged.state_digest[0] ^= 1;
    // Re-sign the substituted current anchor and pass the actual shared evidence verifier.
    // Core must reject its native digest even though the signed observation agrees with it.
    let forged_observation = fixture.verified_observation_at(forged);
    assert_eq!(forged_observation.current_anchor, forged);
    assert!(matches!(
        fixture.validate(&guard, floor, forged, &forged_observation),
        Err(StreamTokenIssuerError::SignerFinalityUnavailable)
    ));
    let mut forged_approval = fixture.approval;
    forged_approval.state_digest[0] ^= 1;
    assert!(matches!(
        guard.capture(forged_approval),
        Err(StreamTokenIssuerError::SignerFinalityUnavailable)
    ));
    guard
        .validate(
            fixture.approval,
            fixture.current.anchor,
            floor,
            &[
                HistoricalFinalityV1::Custody(fixture.approval),
                HistoricalFinalityV1::Custody(fixture.approval),
            ],
            &observation,
            None,
        )
        .expect("matching two-item historical custody control");
    assert!(matches!(
        guard.validate(
            fixture.approval,
            fixture.current.anchor,
            floor,
            &[
                HistoricalFinalityV1::Custody(fixture.approval),
                HistoricalFinalityV1::Custody(forged_approval),
            ],
            &observation,
            None,
        ),
        Err(StreamTokenIssuerError::SignerFinalityUnavailable)
    ));
}

#[test]
fn actual_native_custody_checks_every_unsorted_and_duplicate_height_target() {
    let fixture = NativeCustodyFixture::new();
    let guard = fixture.guard();
    let observation = fixture.verified_observation_at(fixture.current.anchor);
    let floor = guard.capture(fixture.approval).expect("certified floor");
    let genesis = FinalityFloorV1 {
        height: 1,
        block_hash: *fixture.chain.genesis().hash().as_ref(),
    };
    guard
        .validate(
            fixture.approval,
            fixture.current.anchor,
            floor,
            &[
                HistoricalFinalityV1::Custody(fixture.approval),
                HistoricalFinalityV1::Block(floor),
                HistoricalFinalityV1::Block(genesis),
            ],
            &observation,
            None,
        )
        .expect("one certified history authenticates unsorted, duplicate and genesis targets");

    // A valid hash at this height must not hide another supplied hash through deduplication.
    for mut forged in [
        floor,
        HistoricalFinalityV1::Custody(fixture.approval).coordinates(),
    ] {
        forged.block_hash[0] ^= 1;
        assert!(matches!(
            guard.validate(
                fixture.approval,
                fixture.current.anchor,
                floor,
                &[
                    HistoricalFinalityV1::Custody(fixture.approval),
                    HistoricalFinalityV1::Block(forged),
                ],
                &observation,
                None,
            ),
            Err(StreamTokenIssuerError::SignerFinalityUnavailable)
        ));
    }
    let mut forged_floor = floor;
    forged_floor.block_hash[0] ^= 1;
    assert!(matches!(
        fixture.validate(&guard, forged_floor, fixture.current.anchor, &observation),
        Err(StreamTokenIssuerError::SignerFinalityUnavailable)
    ));
}

#[test]
fn actual_native_custody_rechecks_certificates_after_successful_validation() {
    let fixture = NativeCustodyFixture::new();
    let guard = fixture.guard();
    let observation = fixture.verified_observation_at(fixture.current.anchor);
    let floor = guard.capture(fixture.approval).expect("certified floor");
    fixture
        .validate(&guard, floor, fixture.current.anchor, &observation)
        .expect("positive validation before durable evidence changes");
    fixture
        .chain
        .corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
    // The same guard, coordinates, native custody rows and signed observation cannot reuse an
    // earlier successful walk after its retained approval certificate becomes invalid.
    assert!(matches!(
        guard.capture(fixture.approval),
        Err(StreamTokenIssuerError::SignerFinalityUnavailable)
    ));
    assert!(matches!(
        fixture.validate(&guard, floor, fixture.current.anchor, &observation),
        Err(StreamTokenIssuerError::SignerFinalityUnavailable)
    ));
}

#[test]
fn actual_native_custody_retains_history_but_fences_removed_current_provider() {
    let fixture = NativeCustodyFixture::new();
    let guard = fixture.guard();
    let observation = fixture.verified_observation_at(fixture.current.anchor);
    let floor = guard
        .capture(fixture.approval)
        .expect("positive registered-provider control");
    fixture
        .validate(&guard, floor, fixture.current.anchor, &observation)
        .expect("positive validation control");
    // Isolate the current registry predicate with a World-only fixture edit. This does not
    // append or claim a certified provider-removal block; both certified blocks and the
    // retained native custody anchors remain exactly the same.
    fixture.chain.setup_world_at(NOW_MS + 1, |tx| {
        assert_eq!(
            tx.world_mut_for_testing()
                .remove_provider_owner_for_testing(ProviderId::new(PROVIDER)),
            Some(AccountId::new(fixture_key(0xA1).public_key().clone())),
            "the exact registered provider owner is removed",
        );
    });
    assert_eq!(
        read_stream_token_custody_control_at_v1(&fixture.state.view(), fixture.pins.binding(), 3)
            .expect("historical custody remains readable")
            .expect("retained control"),
        fixture.current
    );
    assert_eq!(fixture.state.view().block_hashes().len(), 3);
    let view = fixture.state.view();
    let reader = CertifiedChain::new(&view).expect("certified chain reader");
    for height in 2..=3 {
        assert_eq!(
            reader
                .certified(height)
                .expect("unchanged certified block")
                .verification(),
            QcVerification::Verified
        );
    }
    drop(view);
    assert!(matches!(
        guard.capture(fixture.approval),
        Err(StreamTokenIssuerError::SignerFinalityUnavailable)
    ));
    assert!(matches!(
        fixture.validate(&guard, floor, fixture.current.anchor, &observation),
        Err(StreamTokenIssuerError::SignerFinalityUnavailable)
    ));
}

#[test]
fn startup_custody_accepts_only_certified_unchanged_descendants() {
    let mut fixture = NativeCustodyFixture::new();
    let guard = fixture.guard();
    let floor = guard
        .capture(fixture.approval)
        .expect("certified original floor");
    let startup = fixture.verified_observation_for_phase(
        fixture.current.anchor,
        SignerStreamTokenObservationPhaseV1::Startup,
    );
    let live = [
        SignerStreamTokenObservationPhaseV1::BeforeProvider,
        SignerStreamTokenObservationPhaseV1::BeforeAdmission,
    ]
    .map(|phase| fixture.verified_observation_for_phase(fixture.current.anchor, phase));
    fixture
        .validate(&guard, floor, fixture.current.anchor, &startup)
        .unwrap();
    for observation in &live {
        fixture
            .validate(&guard, floor, fixture.current.anchor, observation)
            .unwrap();
    }
    // Ordinary signed nonempty work executes under this fixture's own genesis fee policy.
    // The fixture is a local certified chain, not a paid generated-localnet qualification.
    for height in [4, 5] {
        let at = NOW_MS + height;
        let transaction = fixture.chain.sign(
            &fixture_key(0xA1),
            [InstructionBox::from(Log::new(
                iroha_data_model::Level::INFO,
                format!("unrelated work while startup observation is in flight {height}"),
            ))],
            at - 1,
        );
        assert_eq!(
            fixture
                .chain
                .commit_with(Some(at), vec![transaction], Signers::Quorum),
            [true]
        );
        let latest = read_stream_token_custody_control_at_v1(
            &fixture.state.view(),
            fixture.pins.binding(),
            height,
        )
        .unwrap()
        .unwrap();
        assert_eq!(latest.state, fixture.current.state);
        assert_eq!(
            latest.anchor.state_digest,
            fixture.current.anchor.state_digest
        );
        assert!(startup.current_anchor.height < latest.anchor.height);
        fixture
            .validate(&guard, floor, fixture.current.anchor, &startup)
            .expect(
                "startup retains the original signed anchor across certified unchanged custody",
            );
        // The original floor is never relaxed to accept an older signed observation.
        let later_floor = guard.capture(fixture.approval).unwrap();
        assert!(matches!(
            fixture.validate(&guard, later_floor, fixture.current.anchor, &startup),
            Err(StreamTokenIssuerError::SignerFinalityUnavailable)
        ));
        for observation in &live {
            assert!(matches!(
                fixture.validate(&guard, floor, fixture.current.anchor, observation),
                Err(StreamTokenIssuerError::SignerFinalityUnavailable)
            ));
        }
    }
    // The added tip is an independent finality target, even when all observed custody is unchanged.
    fixture
        .chain
        .corrupt_local_quorum_for_test(5, Signers::BelowQuorum);
    assert!(matches!(
        fixture.validate(&guard, floor, fixture.current.anchor, &startup),
        Err(StreamTokenIssuerError::SignerFinalityUnavailable)
    ));
}

#[test]
fn startup_custody_rejects_certified_revocation_and_renewal_descendants() {
    for change in 0..3 {
        let mut fixture = NativeCustodyFixture::new();
        let guard = fixture.guard();
        let floor = guard.capture(fixture.approval).unwrap();
        let startup = fixture.verified_observation_for_phase(
            fixture.current.anchor,
            SignerStreamTokenObservationPhaseV1::Startup,
        );
        fixture
            .validate(&guard, floor, fixture.current.anchor, &startup)
            .unwrap();
        let action = if change < 2 {
            SorafsStreamTokenCustodyActionV1::Revoke(SorafsStreamTokenCustodyRevocationV1 {
                signer: change == 0,
                attester: change == 1,
            })
        } else {
            let statement = SignerCustodyStatementV1 {
                magic: SIGNER_CUSTODY_MAGIC_V1,
                version: SIGNER_CUSTODY_VERSION_V1,
                binding: fixture.pins.binding().clone(),
                authority: fixture.pins.custody_trust().authority.clone(),
                anchor: fixture.current.anchor,
                sequence: fixture.current.state.next_sequence,
                predecessor_digest: fixture.current.state.predecessor_digest,
                issued_at_unix_ms: NOW_MS + 1,
                expires_at_unix_ms: NOW_MS + 5_000,
                evidence_digest: [0x89; 32],
                revoked: false,
            };
            let signature = Signature::try_new(
                fixture_key(0x44).private_key(),
                &statement.signing_payload().unwrap(),
            )
            .unwrap();
            let record = SignerCustodyRecordV1 {
                statement,
                attestation: signature.payload().try_into().unwrap(),
            };
            SorafsStreamTokenCustodyActionV1::Enroll(norito::encode_canonical(&record).unwrap())
        };
        let transaction = fixture.chain.sign(
            &fixture_key(0xA1),
            [InstructionBox::from(MutateSorafsStreamTokenCustody {
                provider_id: ProviderId::new(PROVIDER),
                expected_revision: 2,
                expected_digest: fixture.current.anchor.state_digest,
                action,
            })],
            NOW_MS,
        );
        assert_eq!(
            fixture
                .chain
                .commit_with(Some(NOW_MS + 1), vec![transaction], Signers::Quorum),
            [true]
        );
        let latest = read_stream_token_custody_control_at_v1(
            &fixture.state.view(),
            fixture.pins.binding(),
            4,
        )
        .unwrap()
        .unwrap();
        assert_ne!(latest.state, fixture.current.state);
        assert_ne!(
            latest.anchor.state_digest,
            fixture.current.anchor.state_digest
        );
        let view = fixture.state.view();
        assert_eq!(
            CertifiedChain::new(&view)
                .unwrap()
                .certified(4)
                .unwrap()
                .verification(),
            QcVerification::Verified
        );
        drop(view);
        assert!(matches!(
            fixture.validate(&guard, floor, fixture.current.anchor, &startup),
            Err(StreamTokenIssuerError::SignerFinalityUnavailable)
        ));
    }
}

#[test]
fn startup_custody_descendant_still_requires_current_provider_registration() {
    let mut fixture = NativeCustodyFixture::new();
    let guard = fixture.guard();
    let floor = guard.capture(fixture.approval).unwrap();
    let startup = fixture.verified_observation_for_phase(
        fixture.current.anchor,
        SignerStreamTokenObservationPhaseV1::Startup,
    );
    let transaction = fixture.chain.sign(
        &fixture_key(0xA1),
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "unrelated certified startup successor".into(),
        ))],
        NOW_MS,
    );
    assert_eq!(
        fixture
            .chain
            .commit_with(Some(NOW_MS + 1), vec![transaction], Signers::Quorum),
        [true]
    );
    fixture
        .validate(&guard, floor, fixture.current.anchor, &startup)
        .unwrap();
    // Isolate the existing current-registry predicate; this World-only edit makes no claim
    // to be a certified provider-removal transaction and does not replace the signed blocks.
    fixture.chain.setup_world_at(NOW_MS + 2, |tx| {
        assert!(
            tx.world_mut_for_testing()
                .remove_provider_owner_for_testing(ProviderId::new(PROVIDER))
                .is_some()
        );
    });
    assert!(matches!(
        fixture.validate(&guard, floor, fixture.current.anchor, &startup),
        Err(StreamTokenIssuerError::SignerFinalityUnavailable)
    ));
}
