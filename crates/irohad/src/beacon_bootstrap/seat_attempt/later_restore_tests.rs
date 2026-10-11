//! Genuine original producers, native ancestry and later durable restart controls.

use super::tests::{prepare_restartable, prepare_with_sources, root, through_publication_encoding};
use super::*;

fn fixture_keys() -> Vec<KeyPair> {
    let mut keys = (1..=4)
        .map(|index| KeyPair::try_from_seed(vec![index; 32], Algorithm::BlsNormal).unwrap())
        .collect::<Vec<_>>();
    keys.sort_by(|left, right| left.public_key().cmp(right.public_key()));
    keys
}
fn genuine_chain() -> iroha_core::sumeragi::test_chain::CertifiedTestChain {
    use iroha_core::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    let mut config = TestChainConfig::new(World::default(), 10_000);
    config.chain_id = ChainId::from("retained-attempt");
    config.consensus_mode = iroha_data_model::parameter::system::SumeragiConsensusMode::Npos;
    config
        .genesis_parameters
        .push(iroha_data_model::parameter::Parameter::Custom(
            iroha_data_model::parameter::system::SumeragiNposParameters::default()
                .into_custom_parameter(),
        ));
    config.validator_keys = Some(fixture_keys());
    CertifiedTestChain::start(config).unwrap()
}
fn native_proof(
    chain: &iroha_core::sumeragi::test_chain::CertifiedTestChain,
    height: u64,
) -> Vec<u8> {
    let limits = NativeFinalityLimits {
        block_bytes: NATIVE_FINALITY_MAX_BLOCK_BYTES,
        journal_bytes: NATIVE_FINALITY_MAX_JOURNAL_BYTES,
        block_count: NATIVE_FINALITY_MAX_BLOCK_COUNT,
        allocated_bytes: 128 * 1024 * 1024,
    };
    let proof = NativeFinalityJournal {
        blocks: (1..=height)
            .map(|n| {
                iroha_data_model::sumeragi::finality::NativeFinalityArtifact::from_block(
                    chain.committed(n).block(),
                    limits,
                )
                .unwrap()
            })
            .collect(),
    };
    norito::encode_canonical(&proof).unwrap()
}
fn write_original_frame(writer: &File, bytes: &[u8]) -> std::io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(15);
    for bytes in [
        &u32::try_from(bytes.len()).unwrap().to_be_bytes()[..],
        bytes,
    ] {
        let mut offset = 0;
        while offset < bytes.len() {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(std::io::ErrorKind::TimedOut)?;
            let timeout = rustix::event::Timespec::try_from(remaining)
                .map_err(|_| std::io::ErrorKind::TimedOut)?;
            let mut ready = [rustix::event::PollFd::new(
                writer,
                rustix::event::PollFlags::OUT,
            )];
            if rustix::event::poll(&mut ready, Some(&timeout))? == 0 {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            match rustix::io::write(writer, &bytes[offset..]) {
                Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
                Ok(n) => offset += n,
                Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}
/// Execute actual local secret/signature producers and real committed clock work.
/// Every stored byte is produced by the same production attempt state machine.
pub(super) fn through_original_later_phase(
    root: &Path,
    budget: &AllocationBudget,
    phase: u16,
) -> (
    SeatDkgAttemptOwner,
    [File; 2],
    [File; 2],
    iroha_core::sumeragi::test_chain::CertifiedTestChain,
    Instant,
) {
    use iroha_core::beacon::GlobalThresholdBeaconDkgSnapshotV1;
    assert!((2..=4).contains(&phase));
    let (mut attempt, writers, inherited) = prepare_restartable(root, budget).unwrap();
    let admitted_deadline = attempt.deadline;
    let mut chain = genuine_chain();
    assert_eq!(chain.network_id(), attempt.session.network_id);
    through_publication_encoding(&mut attempt);
    attempt.step().unwrap();
    assert_eq!(attempt.phase, Phase::PublicationDurable);
    let keys = fixture_keys();
    let roster = keys
        .iter()
        .map(|key| PeerId::new(key.public_key().clone()))
        .collect::<Vec<_>>();
    let session = attempt.session;
    let mut peers = keys
        .iter()
        .enumerate()
        .skip(1)
        .map(|(index, key)| {
            PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(
                session,
                &roster,
                u16::try_from(index + 1).unwrap(),
                key,
                budget,
            )
            .unwrap()
            .generate(key)
            .unwrap()
        })
        .collect::<Vec<_>>();
    let mut recipients = Vec::new();
    let mut dealers = Vec::new();
    for seat in std::iter::once(attempt.local.as_ref().unwrap()).chain(peers.iter()) {
        let (recipient, dealer) = seat.publication();
        recipients.push(recipient.clone());
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
    let commitments = GlobalThresholdBeaconDkgSnapshotV1 {
        session,
        generator_h: *parameters.h_bytes(),
        generator_v: *parameters.v_bytes(),
        recipient_keys: recipients,
        dealer_commitments: dealers,
        encrypted_shares: vec![],
        share_acceptances: vec![],
        last_updated_height: session.start_height,
    };
    chain.commit_at(20_000, Vec::new());
    assert_eq!(chain.height(), session.commitments_end_height);
    let input = norito::encode_canonical(&commitments).unwrap();
    let proof = native_proof(&chain, 2);
    let [public, finality] = [&writers[0], &writers[1]].map(|file| file.try_clone().unwrap());
    let producer = std::thread::spawn(move || {
        write_original_frame(&public, &input)?;
        write_original_frame(&finality, &proof)
    });
    for expected in [
        Phase::CommitmentsDecoded,
        Phase::CommitmentsFinalized,
        Phase::DeliveriesSigned,
        Phase::DeliveriesEncoded,
        Phase::DeliveriesDurable,
    ] {
        attempt.step().unwrap();
        assert_eq!(attempt.phase, expected);
    }
    producer.join().unwrap().unwrap();
    assert_eq!(attempt.finality.clock().tip().unwrap().height(), 2);
    assert_eq!(
        attempt.finality.clock().tip().unwrap().result(),
        chain.committed(2).result()
    );
    if phase == 2 {
        return (attempt, writers, inherited, chain, admitted_deadline);
    }
    let mut edges = Vec::new();
    let original_delivery: GlobalThresholdBeaconDkgSnapshotV1 =
        norito::decode_canonical(attempt.local.as_ref().unwrap().encoded_public_frame()).unwrap();
    edges.extend(original_delivery.encrypted_shares);
    for (peer, key) in peers.iter_mut().zip(keys.iter().skip(1)) {
        edges.extend(
            peer.deliver(
                &commitments.recipient_keys,
                &commitments.dealer_commitments,
                session.commitments_end_height,
                key,
            )
            .unwrap()
            .cloned(),
        );
    }
    let deliveries = GlobalThresholdBeaconDkgSnapshotV1 {
        session,
        generator_h: commitments.generator_h,
        generator_v: commitments.generator_v,
        recipient_keys: commitments.recipient_keys,
        dealer_commitments: commitments.dealer_commitments,
        encrypted_shares: edges,
        share_acceptances: vec![],
        last_updated_height: session.commitments_end_height,
    };
    chain.commit_at(30_000, Vec::new());
    assert_eq!(chain.height(), session.deliveries_end_height);
    let input = norito::encode_canonical(&deliveries).unwrap();
    let proof = native_proof(&chain, 3);
    let [public, finality] = [&writers[0], &writers[1]].map(|file| file.try_clone().unwrap());
    let producer = std::thread::spawn(move || {
        write_original_frame(&public, &input)?;
        write_original_frame(&finality, &proof)
    });
    for expected in [
        Phase::EdgesDecoded,
        Phase::EdgesFinalized,
        Phase::AcceptancesSigned,
        Phase::AcceptancesEncoded,
        Phase::AcceptancesDurable,
    ] {
        attempt.step().unwrap();
        assert_eq!(attempt.phase, expected);
    }
    producer.join().unwrap().unwrap();
    assert_eq!(
        attempt.finality.clock().tip().unwrap().result(),
        chain.committed(3).result()
    );
    if phase == 3 {
        return (attempt, writers, inherited, chain, admitted_deadline);
    }
    let crypto = iroha_core::beacon::AdaptiveGlobalThresholdBeaconDkgCryptoV1;
    let mut reducer =
        iroha_core::beacon::GlobalThresholdBeaconDkgStateV1::new(session, &crypto, budget).unwrap();
    for recipient in &deliveries.recipient_keys {
        reducer
            .record_recipient_key(session.start_height, recipient)
            .unwrap();
    }
    for dealer in &deliveries.dealer_commitments {
        reducer
            .record_dealer_commitment(session.start_height, dealer, &crypto)
            .unwrap();
    }
    for edge in &deliveries.encrypted_shares {
        reducer
            .record_encrypted_share(session.commitments_end_height, edge)
            .unwrap();
    }
    let original_acceptance: GlobalThresholdBeaconDkgSnapshotV1 =
        norito::decode_canonical(attempt.local.as_ref().unwrap().encoded_public_frame()).unwrap();
    for acceptance in &original_acceptance.share_acceptances {
        reducer
            .record_share_acceptance(session.deliveries_end_height, acceptance)
            .unwrap();
    }
    for (peer, key) in peers.iter_mut().zip(keys.iter().skip(1)) {
        // The original all-edge input is already durably published by this fixture.
        // This peer fixture does not claim its own restart or filesystem qualification.
        peer.retire_durably_published_dealer().unwrap();
        for acceptance in peer
            .accept(&deliveries, session.deliveries_end_height, key)
            .unwrap()
        {
            reducer
                .record_share_acceptance(session.deliveries_end_height, acceptance)
                .unwrap();
        }
    }
    reducer
        .finalize(session.acceptances_end_height, &crypto)
        .unwrap();
    let finalized = reducer.into_finalized().unwrap();
    let input = norito::encode_canonical(finalized.record()).unwrap();
    drop(finalized);
    chain.commit_at(40_000, Vec::new());
    assert_eq!(chain.height(), session.acceptances_end_height);
    let proof = native_proof(&chain, 4);
    let [public, finality] = [&writers[0], &writers[1]].map(|file| file.try_clone().unwrap());
    let producer = std::thread::spawn(move || {
        write_original_frame(&public, &input)?;
        write_original_frame(&finality, &proof)
    });
    for expected in [
        Phase::SessionDecoded,
        Phase::SessionFinalized,
        Phase::SessionSealed,
        Phase::ExportPrepared,
    ] {
        attempt.step().unwrap();
        assert_eq!(attempt.phase, expected);
    }
    producer.join().unwrap().unwrap();
    assert_eq!(
        attempt.finality.clock().tip().unwrap().result(),
        chain.committed(4).result()
    );
    (attempt, writers, inherited, chain, admitted_deadline)
}

#[test]
fn original_complete_delivery_and_acceptance_heads_restore_signed_owners_real_ancestry_and_stream_generations()
 {
    for phase in [2, 3] {
        let (_temporary, root) = root();
        let budget = AllocationBudget::new(64 * 1024 * 1024);
        let (original, writers, inherited, chain, admitted_deadline) =
            through_original_later_phase(&root, &budget, phase);
        let original_output = original
            .local
            .as_ref()
            .unwrap()
            .encoded_public_frame()
            .to_vec();
        let original_identity = original.claim_and_fifo_identity().unwrap();
        let original_deadline = admitted_deadline;
        let original_expiry =
            norito::decode_canonical::<durable::Intent>(original.durable.intent_bytes(1).unwrap())
                .unwrap()
                .expiry;
        let original_stream_generations = original.stream_generations();
        let directory = original.claim.directory().unwrap().path.clone();
        let files = (1..=phase)
            .flat_map(|n| {
                [
                    format!("producer-{n}-intent.norito"),
                    format!("private-checkpoint-{n}.norito"),
                    format!("phase-head-{n}.norito"),
                ]
            })
            .map(|name| {
                let path = directory.join(name);
                (path.clone(), fs::read(path).unwrap())
            })
            .collect::<Vec<_>>();
        drop(original);
        assert_eq!(budget.reserved_bytes(), 0);
        let mut restored = prepare_with_sources(
            &root,
            &budget,
            inherited,
            "software://iroha/consensus-threshold/retained-attempt",
            7,
        )
        .unwrap();
        assert!(
            restored.original_publications[..usize::from(phase)]
                .iter()
                .all(|bank| bank.as_ref().is_some_and(|bank| bank.belongs_to(&budget)))
        );
        assert!(
            restored.original_publications[usize::from(phase)..]
                .iter()
                .all(Option::is_none)
        );
        assert!(restored.local.is_none());
        let receiver = std::ptr::from_ref(&*restored);
        restored.step().unwrap();
        assert_eq!(restored.phase, Phase::RestoringDeliveries);
        assert!(
            restored.claim.directory().is_none(),
            "private phase one cannot adopt a later claim"
        );
        for n in 2..=phase {
            restored.step().unwrap();
            assert_eq!(restored.restored_private_phase, n);
        }
        assert_eq!(
            restored.phase,
            if phase == 2 {
                Phase::DeliveriesDurable
            } else {
                Phase::AcceptancesDurable
            }
        );
        assert_eq!(
            restored.local.as_ref().unwrap().encoded_public_frame(),
            original_output
        );
        assert_eq!(
            restored.claim_and_fifo_identity().unwrap(),
            original_identity
        );
        assert_eq!(restored.stream_generations(), original_stream_generations);
        assert_eq!(restored.finality.height(), u64::from(phase));
        assert_eq!(
            restored.finality.clock().tip().unwrap().result(),
            chain.committed(u64::from(phase)).result()
        );
        assert!(restored.deadline <= original_deadline);
        assert_eq!(
            norito::decode_canonical::<durable::Intent>(restored.durable.intent_bytes(1).unwrap())
                .unwrap()
                .expiry,
            original_expiry
        );
        assert_eq!(std::ptr::from_ref(&*restored), receiver);
        for (path, bytes) in files {
            assert_eq!(
                fs::read(path).unwrap(),
                bytes,
                "no original source rewritten"
            );
        }
        assert!(restored.durable.belongs_to(&budget));
        drop(restored);
        assert_eq!(budget.reserved_bytes(), 0);
        drop(writers);
    }
}

#[test]
fn complete_later_restore_exact_source_admission_refusal_keeps_original_descriptors_before_private_restore()
 {
    let (_temporary, root) = root();
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let (original, _writers, inherited, _chain, _admitted_deadline) =
        through_original_later_phase(&root, &budget, 2);
    drop(original);
    assert_eq!(budget.reserved_bytes(), 0);
    let mut restored = prepare_with_sources(
        &root,
        &budget,
        inherited,
        "software://iroha/consensus-threshold/retained-attempt",
        7,
    )
    .unwrap();
    let receiver = std::ptr::from_ref(&*restored);
    let blocker = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let cause = restored.step().unwrap_err();
    assert!(
        matches!(
            cause,
            AttemptError::Admission(AllocationRefusal::Capacity { .. })
        ),
        "original physical cause: {cause:?}"
    );
    assert!(
        restored.original_publications[..2]
            .iter()
            .all(|bank| bank.as_ref().is_some_and(|bank| bank.belongs_to(&budget)))
    );
    assert!(restored.original_publications[2].is_none());
    assert!(restored.local.is_none());
    assert!(restored.prepared.is_some());
    assert_eq!(restored.restored_private_phase, 0);
    assert_eq!(restored.finality.height(), 1);
    assert!(restored.claim.directory().is_none());
    let descriptors = restored.durable.later_descriptor_ids(2).unwrap();
    assert!(restored.durable.later_sources_unadmitted(2).unwrap());
    drop(blocker);
    restored.step().unwrap();
    restored.step().unwrap();
    assert_eq!(restored.phase, Phase::DeliveriesDurable);
    assert_eq!(std::ptr::from_ref(&*restored), receiver);
    assert_eq!(
        restored.durable.later_descriptor_ids(2).unwrap(),
        descriptors
    );
    drop(restored);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn complete_original_later_head_never_reopens_partial_next_read_or_extraction_intent() {
    use std::os::unix::fs::PermissionsExt as _;
    for marker in [
        "delivery-input-consumption.norito",
        "producer-extraction-intent.norito",
    ] {
        let (_temporary, root) = root();
        let budget = AllocationBudget::new(64 * 1024 * 1024);
        let (original, _writers, inherited, _chain, _admitted_deadline) =
            through_original_later_phase(&root, &budget, 2);
        let path = original.claim.directory().unwrap().path.join(marker);
        fs::write(&path, b"original interrupted immutable intent").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let previous = fs::read(&path).unwrap();
        drop(original);
        assert_eq!(budget.reserved_bytes(), 0);
        let mut restored = prepare_with_sources(
            &root,
            &budget,
            inherited,
            "software://iroha/consensus-threshold/retained-attempt",
            7,
        )
        .unwrap();
        assert!(matches!(restored.step(), Err(AttemptError::Binding)));
        assert!(restored.local.is_none());
        assert_eq!(restored.finality.height(), 1);
        assert!(restored.claim.directory().is_none());
        assert_eq!(fs::read(path).unwrap(), previous);
        drop(restored);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn fresh_four_and_maximum_committee_claim_uses_genuine_producer_owners_without_recovery_decoder_banks()
 {
    use iroha_core::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    for count in [4u16, 31] {
        let (_temporary, root) = root();
        let budget = AllocationBudget::new(64 * 1024 * 1024);
        let mut keys = (1..=count)
            .map(|index| {
                KeyPair::try_from_seed(vec![u8::try_from(index).unwrap(); 32], Algorithm::BlsNormal)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        keys.sort_by(|left, right| left.public_key().cmp(right.public_key()));
        let mut config = TestChainConfig::new(World::default(), 10_000);
        config.consensus_mode = iroha_data_model::parameter::system::SumeragiConsensusMode::Npos;
        config.validator_keys = Some(keys);
        config
            .genesis_parameters
            .push(iroha_data_model::parameter::Parameter::Custom(
                iroha_data_model::parameter::system::SumeragiNposParameters::default()
                    .into_custom_parameter(),
            ));
        let chain_id = config.chain_id.clone();
        let source = CertifiedTestChain::prepare(config).unwrap();
        let network = NetworkId::from_genesis_hash(source.genesis.expected_hash());
        let authority = AuthenticatedGlobalBeaconDkgAttemptV1::signed_genesis(
            source.genesis.block(),
            network,
            &chain_id,
        )
        .unwrap();
        let roster = source
            .validator_keys
            .iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect::<Vec<_>>();
        let clock = NativeJournalCursor::new(
            chain_id,
            network,
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
            NativeFinalityLimits {
                block_bytes: NATIVE_FINALITY_MAX_BLOCK_BYTES,
                journal_bytes: NATIVE_FINALITY_MAX_JOURNAL_BYTES,
                block_count: NATIVE_FINALITY_MAX_BLOCK_COUNT,
                allocated_bytes: 128 * 1024 * 1024,
            },
            &budget,
        )
        .unwrap();
        let (public_read, _public_writer) = rustix::pipe::pipe().unwrap();
        let (finality_read, _finality_writer) = rustix::pipe::pipe().unwrap();
        let mut attempt = SeatDkgAttempt::new(
            authority,
            &roster,
            count,
            source.validator_keys[usize::from(count - 1)].clone(),
            File::from(public_read),
            File::from(finality_read),
            clock,
            "software://iroha/consensus-threshold/retained-attempt",
            7,
            &root,
            Instant::now() + Duration::from_secs(60),
            &budget,
        )
        .unwrap();
        assert_eq!(attempt.phase, Phase::Prepared);
        assert!(attempt.original_publications.iter().all(Option::is_none));
        assert!(attempt.prepared.is_some());
        assert!(attempt.local.is_none());
        assert!(attempt.claim.read_directory().is_none());
        assert!(attempt.durable.later_sources_unadmitted(2).unwrap());
        assert!(attempt.durable.later_sources_unadmitted(3).unwrap());
        assert!(attempt.inputs.belongs_to(&budget));
        assert!(attempt.durable.belongs_to(&budget));
        let admitted = budget.reserved_bytes();
        let receiver = std::ptr::from_ref(&*attempt);
        attempt.step().unwrap();
        assert_eq!(attempt.phase, Phase::Claimed);
        assert!(attempt.claim.directory().is_some());
        assert!(
            attempt.local.is_none(),
            "claim must precede any genuine secret producer"
        );
        assert_eq!(budget.reserved_bytes(), admitted);
        assert_eq!(std::ptr::from_ref(&*attempt), receiver);
        assert!(attempt.original_publications.iter().all(Option::is_none));
        eprintln!(
            "fresh DKG exact original-pool preparation: seats={count} charged_bytes={admitted} cap_bytes={}",
            budget.limit_bytes()
        );
        drop(attempt);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn fresh_prepared_owner_cannot_adopt_another_original_claim_or_allocate_late_recovery_banks() {
    let (_temporary, root) = root();
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let (mut original, _writers, _inherited) = prepare_restartable(&root, &budget).unwrap();
    let (mut raced, _raced_writers, _raced_inherited) =
        prepare_restartable(&root, &budget).unwrap();
    assert!(original.original_publications.iter().all(Option::is_none));
    assert!(raced.original_publications.iter().all(Option::is_none));
    original.step().unwrap();
    assert_eq!(original.phase, Phase::Claimed);
    let admitted = budget.reserved_bytes();
    assert!(matches!(raced.step(), Err(AttemptError::Binding)));
    assert!(raced.original_publications.iter().all(Option::is_none));
    assert!(raced.prepared.is_some());
    assert!(raced.local.is_none());
    assert!(raced.claim.directory().is_none());
    assert_eq!(raced.finality.height(), 1);
    assert_eq!(budget.reserved_bytes(), admitted);
    drop(raced);
    drop(original);
    assert_eq!(budget.reserved_bytes(), 0);
}
