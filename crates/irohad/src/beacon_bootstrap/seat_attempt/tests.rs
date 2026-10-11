//! Actual claim, phase publication refusal, unchanged private source and no-reroll controls.

use super::*;
use iroha_allocation::release::ReleaseRegistration;
use std::os::unix::fs::PermissionsExt as _;
use std::task::{Context, Waker};
const HANDLE: &str = "software://iroha/consensus-threshold/retained-attempt";

fn identities() -> (GlobalThresholdBeaconDkgSessionV1, Vec<KeyPair>, Vec<PeerId>) {
    let mut keys = (1..=4)
        .map(|index| KeyPair::try_from_seed(vec![index; 32], Algorithm::BlsNormal).unwrap())
        .collect::<Vec<_>>();
    keys.sort_by(|left, right| left.public_key().cmp(right.public_key()));
    let roster = keys
        .iter()
        .map(|key| PeerId::new(key.public_key().clone()))
        .collect::<Vec<_>>();
    let network_id = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        Hash::new(b"retained-attempt-network"),
    ));
    (
        GlobalThresholdBeaconDkgSessionV1 {
            version: 1,
            network_id,
            session_id: Hash::new(b"retained-attempt-session").into(),
            attempt_id: Hash::new(b"retained-attempt-once").into(),
            authority_generation: 0,
            roster_hash: global_threshold_beacon_roster_hash_v1(&roster),
            committee_size: 4,
            threshold: 2,
            start_height: 1,
            commitments_end_height: 2,
            deliveries_end_height: 3,
            acceptances_end_height: 4,
        },
        keys,
        roster,
    )
}
pub(super) fn root() -> (tempfile::TempDir, PathBuf) {
    let temporary = tempfile::Builder::new()
        .prefix(".retained-attempt-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = fs::canonicalize(temporary.path()).unwrap();
    (temporary, path)
}
fn prepare(
    root: &Path,
    budget: &AllocationBudget,
) -> std::result::Result<(SeatDkgAttemptOwner, [File; 2]), AttemptError> {
    let (attempt, writes, _inherited) = prepare_restartable(root, budget)?;
    Ok((attempt, writes))
}
pub(super) fn prepare_restartable(
    root: &Path,
    budget: &AllocationBudget,
) -> std::result::Result<(SeatDkgAttemptOwner, [File; 2], [File; 2]), AttemptError> {
    let (public_read, public_write) = rustix::pipe::pipe().unwrap();
    let (finality_read, finality_write) = rustix::pipe::pipe().unwrap();
    let sources = [File::from(public_read), File::from(finality_read)];
    // A supervisor retains these exact inherited kernel streams across owner drop.
    // Reload never opens a named FIFO or creates another source.
    let inherited = [
        sources[0].try_clone().unwrap(),
        sources[1].try_clone().unwrap(),
    ];
    let attempt = prepare_with_sources(root, budget, sources, HANDLE, 7)?;
    Ok((
        attempt,
        [File::from(public_write), File::from(finality_write)],
        inherited,
    ))
}
pub(super) fn prepare_with_sources(
    root: &Path,
    budget: &AllocationBudget,
    [public_read, finality_read]: [File; 2],
    handle: &str,
    revision: u64,
) -> std::result::Result<SeatDkgAttemptOwner, AttemptError> {
    let (_, keys, roster) = identities();
    let mut config = iroha_core::sumeragi::test_chain::TestChainConfig::new(
        iroha_core::state::World::default(),
        10_000,
    );
    config.chain_id = ChainId::from("retained-attempt");
    config.consensus_mode = iroha_data_model::parameter::system::SumeragiConsensusMode::Npos;
    config
        .genesis_parameters
        .push(iroha_data_model::parameter::Parameter::Custom(
            iroha_data_model::parameter::system::SumeragiNposParameters::default()
                .into_custom_parameter(),
        ));
    config.validator_keys = Some(keys.clone());
    let genesis = iroha_core::sumeragi::test_chain::CertifiedTestChain::prepare(config).unwrap();
    let network = NetworkId::from_genesis_hash(genesis.genesis.expected_hash());
    let authority = AuthenticatedGlobalBeaconDkgAttemptV1::signed_genesis(
        genesis.genesis.block(),
        network,
        &ChainId::from("retained-attempt"),
    )?;
    let clock = NativeJournalCursor::new(
        ChainId::from("retained-attempt"),
        network,
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        NativeFinalityLimits {
            block_bytes: NATIVE_FINALITY_MAX_BLOCK_BYTES,
            journal_bytes: NATIVE_FINALITY_MAX_JOURNAL_BYTES,
            block_count: NATIVE_FINALITY_MAX_BLOCK_COUNT,
            allocated_bytes: 128 * 1024 * 1024,
        },
        budget,
    )?;
    SeatDkgAttempt::new(
        authority,
        &roster,
        1,
        keys[0].clone(),
        public_read,
        finality_read,
        clock,
        handle,
        revision,
        root,
        Instant::now() + Duration::from_secs(60),
        budget,
    )
}
pub(super) fn through_publication_encoding(attempt: &mut SeatDkgAttempt) {
    for expected in [
        Phase::Claimed,
        Phase::GenerationIntentDurable,
        Phase::Generated,
        Phase::PublicationEncoded,
    ] {
        attempt.step().unwrap();
        assert_eq!(attempt.phase, expected);
    }
}

#[test]
fn local_attempt_claim_follows_complete_original_pool_preparation() {
    let (_temporary, root) = root();
    let floor = ReleaseRegistration::allocation_layout().size();
    let budget = AllocationBudget::new(8 * 1024 * 1024 + floor);
    let mut reservation = budget.try_reserve_bytes(floor).unwrap();
    let mut registration = ReleaseRegistration::from_reservation(&mut reservation).unwrap();
    drop(reservation);
    let blocker = budget
        .try_reserve_bytes(budget.limit_bytes() - floor)
        .unwrap();
    let error = match prepare(&root, &budget) {
        Ok(_) => panic!("occupied pool cannot prepare private work"),
        Err(error) => error,
    };
    // Current preparation funds the original claim path before private DKG
    // banks. Saturation must preserve that first owning layer's exact refusal.
    let AttemptError::Claim(ClaimError::Admission(AllocationRefusal::Capacity { release, .. })) =
        error
    else {
        panic!("original claim-path capacity source: {error}")
    };
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    let mut context = Context::from_waker(Waker::noop());
    assert!(registration.poll_wait(&release, &mut context).is_pending());
    let foreign = AllocationBudget::new(1);
    drop(foreign.try_reserve_bytes(1).unwrap());
    assert!(registration.poll_wait(&release, &mut context).is_pending());
    drop(blocker);
    assert!(registration.poll_wait(&release, &mut context).is_ready());
    registration.cancel();
    let (mut attempt, _writes) = prepare(&root, &budget).unwrap();
    assert_eq!(attempt.phase, Phase::Prepared);
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    assert!(attempt.inputs.belongs_to(&budget));
    assert!(attempt.verifier.as_ref().unwrap().belongs_to(&budget));
    assert!(attempt.durable.belongs_to(&budget));
    assert!(attempt.original_publications.iter().all(Option::is_none));
    assert!(attempt.provider_handle.belongs_to(&budget));
    attempt.step().unwrap();
    let directory = attempt.claim.directory().unwrap();
    assert_eq!(directory.file.metadata().unwrap().mode() & 0o7777, 0o700);
    let inode = directory.file.metadata().unwrap().ino();
    let child = directory.path.clone();
    drop(attempt);
    assert_eq!(budget.reserved_bytes(), floor);
    assert_eq!(fs::metadata(&child).unwrap().ino(), inode);
    let (mut repeated, _writes) = prepare(&root, &budget).unwrap();
    assert!(matches!(
        repeated.step(),
        Err(AttemptError::Claim(ClaimError::AlreadyClaimed(_)))
    ));
    assert!(repeated.prepared.is_some());
    assert!(repeated.local.is_none());
    drop(repeated);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn publication_refusal_resumes_same_generated_secret_frame_and_original_file_only() {
    let (_temporary, root) = root();
    let budget = AllocationBudget::new(8 * 1024 * 1024);
    let (mut attempt, _writes) = prepare(&root, &budget).unwrap();
    through_publication_encoding(&mut attempt);
    let local = attempt.local.as_ref().unwrap();
    let public_hash = local.publication_hash();
    let frame_pointer = local.encoded_public_frame().as_ptr();
    let frame = local.encoded_public_frame().to_vec();
    assert!(attempt.prepared.is_none());
    let directory = attempt.claim.directory().unwrap();
    let path = directory.path.join("publication.norito");
    fs::write(&path, b"existing unrelated file").unwrap();
    let held = budget.reserved_bytes();
    assert!(matches!(
        attempt.step(),
        Err(AttemptError::Export(seat_export::ExportError::Io(_)))
    ));
    assert_eq!(attempt.phase, Phase::PublicationEncoded);
    assert_eq!(
        attempt.local.as_ref().unwrap().publication_hash(),
        public_hash
    );
    assert_eq!(
        attempt
            .local
            .as_ref()
            .unwrap()
            .encoded_public_frame()
            .as_ptr(),
        frame_pointer
    );
    assert_eq!(
        attempt.local.as_ref().unwrap().encoded_public_frame(),
        frame
    );
    assert_eq!(budget.reserved_bytes(), held);
    fs::remove_file(&path).unwrap();
    attempt.step().unwrap();
    assert_eq!(attempt.phase, Phase::PublicationDurable);
    assert_eq!(fs::read(&path).unwrap(), frame);
    let inode = fs::metadata(&path).unwrap().ino();
    attempt.publish_phase(1).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
    assert_eq!(
        attempt.local.as_ref().unwrap().publication_hash(),
        public_hash
    );
    drop(attempt);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn pending_attempt_keeps_generated_private_owner_and_terminal_deadline_never_rerolls() {
    let (_temporary, root) = root();
    let budget = AllocationBudget::new(8 * 1024 * 1024);
    let (mut attempt, _writes) = prepare(&root, &budget).unwrap();
    through_publication_encoding(&mut attempt);
    let original = attempt.local.as_ref().unwrap().publication_hash();
    let retained = budget.reserved_bytes();
    let receiver = std::ptr::from_ref(&*attempt);
    assert!(attempt.receiver.belongs_to(&budget));
    assert_eq!(attempt.receiver.as_slice().len(), 1);
    // An already elapsed absolute deadline is a real pending-owner failure;
    // neither resumption nor the error carrier may reset it or generate again.
    attempt.deadline = Instant::now();
    let failure = attempt.resume().unwrap_err();
    assert_eq!(std::ptr::from_ref(&*failure.owner), receiver);
    assert!(failure.owner.receiver.belongs_to(&budget));
    assert_eq!(failure.owner.phase, Phase::Terminal);
    assert!(failure.owner.prepared.is_none());
    assert_eq!(
        failure.owner.local.as_ref().unwrap().publication_hash(),
        original
    );
    assert_eq!(budget.reserved_bytes(), retained);
    let second = failure.owner.resume().unwrap_err();
    assert_eq!(std::ptr::from_ref(&*second.owner), receiver);
    assert!(second.owner.receiver.belongs_to(&budget));
    assert_eq!(second.owner.phase, Phase::Terminal);
    assert_eq!(
        second.owner.local.as_ref().unwrap().publication_hash(),
        original
    );
    assert_eq!(budget.reserved_bytes(), retained);
    drop(second);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
}

#[test]
fn bootstrap_error_carriers_keep_only_the_prepaid_receiver_handle() {
    // Error propagation through filesystem and config helpers must fit the
    // ordinary thread stack even while a pending receiver owns private DKG work.
    assert!(std::mem::size_of::<SeatDkgAttempt>() > 1024);
    assert!(std::mem::size_of::<SeatDkgAttemptOwner>() <= 128);
    assert!(std::mem::size_of::<PendingSeatDkgAttempt>() <= 1024);
    assert!(std::mem::size_of::<Error>() <= 1024);
}

#[test]
fn original_dealer_retirement_waits_for_complete_durable_delivery_publication() {
    let (_temporary, root) = root();
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let (mut attempt, _writes) = prepare(&root, &budget).unwrap();
    through_publication_encoding(&mut attempt);
    let (_, keys, roster) = identities();
    let session = attempt.session;
    let mut peers = keys
        .iter()
        .enumerate()
        .skip(1)
        .map(|(index, key)| {
            PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(
                session,
                &roster,
                (index + 1) as u16,
                key,
                &budget,
            )
            .unwrap()
            .generate(key)
            .unwrap()
        })
        .collect::<Vec<_>>();
    let mut recipients = Vec::new();
    let mut dealers = Vec::new();
    for seat in std::iter::once(attempt.local.as_ref().unwrap()).chain(peers.iter()) {
        let (key, dealer) = seat.publication();
        recipients.push(key.clone());
        dealers.push(dealer.clone());
    }
    let parameters = iroha_crypto::threshold_bls::AdaptiveThresholdBlsParameters::<
        iroha_crypto::threshold_bls::BeaconPurpose,
    >::derive(
        &iroha_crypto::threshold_bls::ThresholdBlsSession::new(
            *session.network_id.as_bytes(),
            session.session_id,
            session.roster_hash,
            session.committee_size,
            session.threshold,
        )
        .unwrap(),
    )
    .unwrap();
    let commitments = iroha_core::beacon::GlobalThresholdBeaconDkgSnapshotV1 {
        session,
        generator_h: *parameters.h_bytes(),
        generator_v: *parameters.v_bytes(),
        recipient_keys: recipients,
        dealer_commitments: dealers,
        encrypted_shares: vec![],
        share_acceptances: vec![],
        last_updated_height: session.start_height,
    };
    let encoded = norito::encode_canonical(&commitments).unwrap();
    attempt
        .inputs
        .full_mut()
        .unwrap()
        .decode_commitments(&encoded, norito::canonical_decode_limits(encoded.len()))
        .unwrap();
    let signer = &keys[0];
    let _ = attempt
        .local
        .as_mut()
        .unwrap()
        .deliver(
            &commitments.recipient_keys,
            &commitments.dealer_commitments,
            2,
            signer,
        )
        .unwrap();
    for (seat, key) in peers.iter_mut().zip(keys.iter().skip(1)) {
        let _ = seat
            .deliver(
                &commitments.recipient_keys,
                &commitments.dealer_commitments,
                2,
                key,
            )
            .unwrap();
    }
    // The actual output frame encoder owns the original seat's generated edges.
    {
        let attempt = &mut *attempt;
        attempt
            .local
            .as_mut()
            .unwrap()
            .delivery_frame(attempt.inputs.full().unwrap().commitments().unwrap())
            .unwrap();
    }
    let deliveries: iroha_core::beacon::GlobalThresholdBeaconDkgSnapshotV1 =
        norito::decode_canonical(attempt.local.as_ref().unwrap().encoded_public_frame()).unwrap();
    // This test starts at the actual writer boundary after genuine producers;
    // it does not replace or claim native-finality verification qualification.
    attempt.phase = Phase::DeliveriesEncoded;
    let frame = attempt
        .local
        .as_ref()
        .unwrap()
        .encoded_public_frame()
        .to_vec();
    let pointer = attempt
        .local
        .as_ref()
        .unwrap()
        .encoded_public_frame()
        .as_ptr();
    let public_hash = attempt.local.as_ref().unwrap().publication_hash();
    let path = attempt
        .claim
        .directory()
        .unwrap()
        .path
        .join("deliveries.norito");
    fs::write(&path, b"existing unrelated output").unwrap();
    let retained = budget.reserved_bytes();
    assert!(matches!(
        attempt.publish_phase(2),
        Err(AttemptError::Export(seat_export::ExportError::Io(_)))
    ));
    assert_eq!(attempt.phase, Phase::DeliveriesEncoded);
    assert_eq!(budget.reserved_bytes(), retained);
    assert_eq!(
        attempt
            .local
            .as_ref()
            .unwrap()
            .encoded_public_frame()
            .as_ptr(),
        pointer
    );
    assert_eq!(
        attempt.local.as_ref().unwrap().encoded_public_frame(),
        &frame
    );
    assert_eq!(
        attempt.local.as_ref().unwrap().publication_hash(),
        public_hash
    );
    assert!(
        matches!(
            attempt
                .local
                .as_mut()
                .unwrap()
                .accept(&deliveries, 3, signer),
            Err(
                iroha_core::beacon::LocalGlobalThresholdBeaconDkgErrorV1::Invalid(
                    iroha_core::beacon::GlobalThresholdBeaconError::DkgTerminal
                )
            )
        ),
        "writer refusal retains the original runtime polynomial"
    );
    fs::remove_file(&path).unwrap();
    attempt.publish_phase(2).unwrap();
    attempt
        .local
        .as_mut()
        .unwrap()
        .retire_durably_published_dealer()
        .unwrap();
    attempt.phase = Phase::DeliveriesDurable;
    assert_eq!(attempt.phase, Phase::DeliveriesDurable);
    assert!(attempt.publications[2].complete());
    assert_eq!(fs::read(&path).unwrap(), frame);
    assert!(
        attempt
            .local
            .as_mut()
            .unwrap()
            .retire_durably_published_dealer()
            .is_err(),
        "actual durable transition already retired the original polynomial once"
    );
    assert_eq!(
        attempt
            .local
            .as_ref()
            .unwrap()
            .encoded_public_frame()
            .as_ptr(),
        pointer
    );
    assert_eq!(
        attempt.local.as_ref().unwrap().publication_hash(),
        public_hash
    );
    drop(peers);
    drop(attempt);
    assert_eq!(budget.reserved_bytes(), 0);
}
