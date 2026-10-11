//! Real native work, proof replay, same-frame refusal and unchanged finality cursor.

use super::*;
use iroha_allocation::release::ReleaseRegistration;
use std::task::{Context, Waker};

fn limits() -> NativeFinalityLimits {
    NativeFinalityLimits {
        block_bytes: NATIVE_FINALITY_MAX_BLOCK_BYTES,
        journal_bytes: NATIVE_FINALITY_MAX_JOURNAL_BYTES,
        block_count: NATIVE_FINALITY_MAX_BLOCK_COUNT,
        allocated_bytes: 128 * 1024 * 1024,
    }
}
fn proof() -> (Vec<u8>, ChainId, NetworkId) {
    use iroha_core::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    let config = TestChainConfig::new(World::default(), 10_000);
    let chain_id = config.chain_id.clone();
    let mut chain = CertifiedTestChain::start(config).unwrap();
    chain.commit_at(20_000, Vec::new()); // Adds actual signed clock work.
    let journal = NativeFinalityJournal {
        blocks: (1..=2)
            .map(|height| {
                iroha_data_model::sumeragi::finality::NativeFinalityArtifact::from_block(
                    chain.committed(height).block(),
                    limits(),
                )
                .unwrap()
            })
            .collect(),
    };
    (
        norito::encode_canonical(&journal).unwrap(),
        chain_id,
        chain.network_id(),
    )
}
fn source(chain: ChainId, network: NetworkId, pool: &AllocationBudget) -> (File, FinalityInput) {
    let (read, write) = super::super::test_pipe::pipe(true);
    let input = FrameInput::new(
        File::from(read),
        limits().journal_bytes,
        Instant::now() + Duration::from_secs(1),
        pool,
    )
    .unwrap_or_else(|(_, error)| panic!("exact FIFO: {error}"));
    let cursor = NativeJournalCursor::new(
        chain,
        network,
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        limits(),
        pool,
    )
    .unwrap();
    assert!(
        cursor.tip().is_none(),
        "signed genesis alone is not a finalized execution"
    );
    (
        File::from(write),
        FinalityInput::new(input, cursor, 1).unwrap(),
    )
}
fn write_frame(writer: &File, bytes: &[u8]) -> std::io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    for source in [
        &u32::try_from(bytes.len()).unwrap().to_be_bytes()[..],
        bytes,
    ] {
        let mut offset = 0;
        while offset < source.len() {
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
            match rustix::io::write(writer, &source[offset..]) {
                Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
                Ok(written) => offset += written,
                Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

#[test]
fn current_phase_pipe_accepts_real_work_and_rejects_replay() {
    let (bytes, chain, network) = proof();
    let pool = AllocationBudget::new(64 * 1024 * 1024);
    let (writer, mut input) = source(chain, network, &pool);
    let producer = std::thread::spawn(move || {
        write_frame(&writer, &bytes)?;
        write_frame(&writer, &bytes)
    });
    let first = input.advance_to(2, 4, |_| Ok(()));
    let replay = input.advance_to(3, 4, |_| Ok(()));
    let last = input.height();
    drop(input);
    producer
        .join()
        .expect("original proof producer")
        .expect("two original frames");
    first.expect("genuinely certified native work");
    assert!(matches!(replay, Err(AttemptError::Height)));
    assert_eq!(last, 2);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn original_pool_refusal_keeps_once_decoded_journal_and_same_complete_frame_until_release() {
    let (bytes, chain, network) = proof();
    let pool = AllocationBudget::new(64 * 1024 * 1024);
    let mut reservation = pool
        .try_reserve(ReleaseRegistration::allocation_layout())
        .unwrap();
    let mut registration = ReleaseRegistration::from_reservation(&mut reservation).unwrap();
    drop(reservation);
    let (writer, mut input) = source(chain, network, &pool);
    let producer = std::thread::spawn(move || write_frame(&writer, &bytes));
    input.input.read_until_complete().unwrap();
    producer.join().unwrap().unwrap();
    let frame_pointer = input.input.frame().unwrap().as_ptr();
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
        .unwrap();
    let error = input.advance_to(2, 4, |_| Ok(())).unwrap_err();
    let AttemptError::Journal(iroha_core::sumeragi::native_journal::NativeJournalError::Block(
        iroha_data_model::block::SharedBlockAdmissionError::Admission(
            AllocationRefusal::Capacity { release, .. },
        ),
    )) = error
    else {
        panic!("exact original native block-control source: {error}")
    };
    assert_eq!(input.height(), 1);
    assert!(input.clock.tip().is_none());
    let journal_pointer = input
        .journal
        .view(input.input.charged_frame().unwrap())
        .unwrap()
        .frames()
        .next()
        .unwrap()
        .wire()
        .as_ptr();
    assert_eq!(input.input.frame().unwrap().as_ptr(), frame_pointer);
    let mut context = Context::from_waker(Waker::noop());
    assert!(registration.poll_wait(&release, &mut context).is_pending());
    let foreign = AllocationBudget::new(1);
    drop(foreign.try_reserve_bytes(1).unwrap());
    assert!(registration.poll_wait(&release, &mut context).is_pending());
    assert!(input.advance_to(2, 4, |_| Ok(())).is_err());
    assert_eq!(
        input
            .journal
            .view(input.input.charged_frame().unwrap())
            .unwrap()
            .frames()
            .next()
            .unwrap()
            .wire()
            .as_ptr(),
        journal_pointer
    );
    assert_eq!(input.input.frame().unwrap().as_ptr(), frame_pointer);
    drop(blocker);
    assert!(registration.poll_wait(&release, &mut context).is_ready());
    registration.cancel();
    input.advance_to(2, 4, |_| Ok(())).unwrap();
    assert_eq!(input.height(), 2);
    assert!(!input.journal.is_decoded());
    assert!(input.input.frame().is_none());
    drop(input);
    drop(registration);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn rotation_phase_pipe_rejects_truncated_oversized_and_noncanonical_proofs() {
    for frame in [
        0u32.to_be_bytes().to_vec(),
        u32::try_from(NATIVE_FINALITY_MAX_JOURNAL_BYTES + 1)
            .unwrap()
            .to_be_bytes()
            .to_vec(),
        vec![0, 0, 0, 1, 0],
        vec![0, 0, 0, 2, 0],
    ] {
        let pool = AllocationBudget::new(64 * 1024 * 1024);
        let network = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            Hash::new(b"retained-proof-negative"),
        ));
        let (mut writer, mut input) =
            source(ChainId::from("retained-proof-negative"), network, &pool);
        writer.write_all(&frame).unwrap();
        drop(writer);
        input.height = 10;
        assert!(input.advance_to(11, 20, |_| Ok(())).is_err());
        assert_eq!(input.height(), 10);
        assert!(input.clock.tip().is_none());
        drop(input);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn malformed_original_journal_and_prepared_source_failures_are_terminal() {
    for phase in [
        Phase::CommitmentsDecoded,
        Phase::EdgesDecoded,
        Phase::SessionDecoded,
    ] {
        let error = NativeFinalityJournal::decode(&[0], limits()).unwrap_err();
        assert!(
            AttemptError::Journal(
                iroha_core::sumeragi::native_journal::NativeJournalError::Decode(error)
            )
            .terminal(phase)
        );
        let pool = AllocationBudget::new(64 * 1024 * 1024);
        let mut malformed = ChargedBuffer::new(1, &pool).unwrap();
        malformed.append(&[0]).unwrap();
        let (wire, _, _) = proof();
        let mut bytes = ChargedBuffer::new(wire.len(), &pool).unwrap();
        bytes.append(&wire).unwrap();
        drop(wire);
        let source_bytes = malformed.capacity() + bytes.capacity();
        assert_eq!(pool.reserved_bytes(), source_bytes);
        let source_pointer = bytes.as_slice().as_ptr();
        let source_hash = Hash::new(bytes.as_slice());
        let foreign_pool = AllocationBudget::new(pool.limit_bytes());
        let mut foreign_source = ChargedBuffer::new(bytes.as_slice().len(), &foreign_pool).unwrap();
        foreign_source.append(bytes.as_slice()).unwrap();
        let foreign_pointer = foreign_source.as_slice().as_ptr();
        let foreign_hash = Hash::new(foreign_source.as_slice());
        let mut prepared = PreparedNativeFinalityJournal::new(limits(), &pool).unwrap();
        let original_bytes = pool.reserved_bytes();
        let foreign_bytes = foreign_pool.reserved_bytes();
        let foreign_error = prepared.decode(&foreign_source).unwrap_err();
        assert!(matches!(
            foreign_error,
            iroha_data_model::sumeragi::finality::PreparedNativeFinalityError::ForeignPool
        ));
        let foreign_error = AttemptError::JournalSource(foreign_error);
        assert!(foreign_error.terminal(phase));
        assert!(!prepared.is_decoded());
        assert_eq!(pool.reserved_bytes(), original_bytes);
        assert_eq!(foreign_pool.reserved_bytes(), foreign_bytes);
        assert_eq!(bytes.as_slice().as_ptr(), source_pointer);
        assert_eq!(Hash::new(bytes.as_slice()), source_hash);
        assert_eq!(foreign_source.as_slice().as_ptr(), foreign_pointer);
        assert_eq!(Hash::new(foreign_source.as_slice()), foreign_hash);
        let malformed_error = AttemptError::JournalSource(prepared.decode(&malformed).unwrap_err());
        assert!(malformed_error.terminal(phase));
        prepared.clear_consumed();
        let enclosing_error = norito::core::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || prepared.decode(&bytes),
        )
        .unwrap_err();
        assert!(matches!(
            enclosing_error,
            iroha_data_model::sumeragi::finality::PreparedNativeFinalityError::Decode(
                norito::core::PreparedDecodeError::Codec(ref original)
            ) if original.kind() == norito::core::DecodeAttemptErrorKind::EnclosingLimit
        ));
        let enclosing_error = AttemptError::JournalSource(enclosing_error);
        assert!(!enclosing_error.terminal(phase));
        prepared.decode(&bytes).unwrap();
        assert!(foreign_error.terminal(phase));
        assert!(malformed_error.terminal(phase));
        assert!(!enclosing_error.terminal(phase));
        assert_eq!(malformed.as_slice(), &[0]);
        assert_eq!(bytes.as_slice().as_ptr(), source_pointer);
        assert_eq!(Hash::new(bytes.as_slice()), source_hash);
        assert_eq!(foreign_source.as_slice().as_ptr(), foreign_pointer);
        assert_eq!(Hash::new(foreign_source.as_slice()), foreign_hash);
        assert_eq!(foreign_pool.reserved_bytes(), foreign_bytes);
        drop(foreign_error);
        drop(malformed_error);
        drop(enclosing_error);
        drop(prepared);
        assert_eq!(pool.reserved_bytes(), source_bytes);
        drop(bytes);
        drop(malformed);
        assert_eq!(pool.reserved_bytes(), 0);
        drop(foreign_source);
        assert_eq!(foreign_pool.reserved_bytes(), 0);
    }
}

#[test]
fn original_verified_target_proof_publication_refusal_retains_frame_and_never_advances_twice() {
    use super::super::publication::{PhaseFile, PhasePublication};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let (bytes, chain, network) = proof();
    let pool = AllocationBudget::new(64 * 1024 * 1024);
    let (writer, mut input) = source(chain, network, &pool);
    let producer = std::thread::spawn({
        let bytes = bytes.clone();
        move || write_frame(&writer, &bytes)
    });
    input.input.read_until_complete().unwrap();
    producer.join().unwrap().unwrap();
    let pointer = input.input.frame().unwrap().as_ptr();
    let (_temporary, path) = super::super::tests::root();
    let directory = Directory::open(&path).unwrap();
    let file_path = path.join("proof-commitments.norito");
    fs::write(&file_path, b"unrelated exact destination").unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut publication = PhasePublication::new(PhaseFile::CommitmentsProof);
    let result = input.advance_to(2, 4, |frame| {
        assert_eq!(frame.as_ptr(), pointer);
        publication.publish(&directory, frame)?;
        Ok(())
    });
    let AttemptError::Export(seat_export::ExportError::Io(cause)) = result.unwrap_err() else {
        panic!("actual original exclusive-create cause");
    };
    assert_eq!(cause.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(input.height(), 2);
    assert_eq!(input.clock.tip().unwrap().height(), 2);
    let result = input.clock.tip().unwrap().result();
    assert!(input.committed);
    assert!(input.journal.is_decoded());
    assert_eq!(input.input.frame().unwrap().as_ptr(), pointer);
    assert_eq!(input.generation(), 0);
    assert!(!publication.complete());
    let retained = pool.reserved_bytes();
    fs::remove_file(&file_path).unwrap();
    input
        .advance_to(2, 4, |frame| {
            assert_eq!(frame.as_ptr(), pointer);
            publication.publish(&directory, frame)?;
            Ok(())
        })
        .unwrap();
    assert!(publication.complete());
    assert_eq!(
        publication.complete_hash().unwrap(),
        <[u8; 32]>::from(Hash::new(&bytes))
    );
    assert_eq!(fs::read(&file_path).unwrap(), bytes);
    let inode = fs::metadata(&file_path).unwrap().ino();
    assert_eq!(input.generation(), 1);
    assert_eq!(input.clock.tip().unwrap().result(), result);
    assert!(!input.committed);
    assert!(!input.journal.is_decoded());
    assert!(input.input.frame().is_none());
    assert!(pool.reserved_bytes() < retained);
    assert_eq!(fs::metadata(&file_path).unwrap().ino(), inode);
    drop(publication);
    drop(input);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn original_durable_native_proof_replay_checks_true_ancestry_and_keeps_original_source_on_refusal()
{
    let (wire, chain, network) = proof();
    let pool = AllocationBudget::new(64 * 1024 * 1024);
    let mut bytes = ChargedBuffer::new(wire.len(), &pool).unwrap();
    bytes.append(&wire).unwrap();
    let mut same_bytes_different_owner = ChargedBuffer::new(wire.len(), &pool).unwrap();
    same_bytes_different_owner.append(&wire).unwrap();
    drop(wire);
    let source_bytes = pool.reserved_bytes();
    let (_writer, mut input) = source(chain.clone(), network, &pool);
    let source_pointer = bytes.as_slice().as_ptr();
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
        .unwrap();
    assert!(matches!(
        input.restore_target_from_original_frame(&bytes, 2, 4),
        Err(AttemptError::Journal(_))
    ));
    assert_eq!(input.height(), 1);
    assert!(input.clock.tip().is_none());
    assert!(input.journal.is_decoded());
    let span = input
        .journal
        .view(&bytes)
        .unwrap()
        .frames()
        .next()
        .unwrap()
        .wire()
        .as_ptr();
    assert!(matches!(
        input.restore_target_from_original_frame(&same_bytes_different_owner, 2, 4),
        Err(AttemptError::Binding)
    ));
    assert_eq!(
        input
            .journal
            .view(&bytes)
            .unwrap()
            .frames()
            .next()
            .unwrap()
            .wire()
            .as_ptr(),
        span
    );
    drop(blocker);
    input
        .restore_target_from_original_frame(&bytes, 2, 4)
        .unwrap();
    assert_eq!(input.height(), 2);
    assert_eq!(input.clock.tip().unwrap().height(), 2);
    assert_eq!(
        input.generation(),
        0,
        "replay reads only the durable original frame"
    );
    assert_eq!(
        input.restored_source.as_ref().unwrap().address,
        source_pointer.addr()
    );
    assert!(!input.journal.is_decoded());
    let actual_result = input.clock.tip().unwrap().result();
    input
        .restore_target_from_original_frame(&bytes, 2, 4)
        .unwrap();
    assert_eq!(input.clock.tip().unwrap().result(), actual_result);
    assert!(matches!(
        input.restore_target_from_original_frame(&same_bytes_different_owner, 2, 4),
        Err(AttemptError::Binding)
    ));
    let foreign = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        Hash::new(b"foreign proof replay network"),
    ));
    let (_foreign_writer, mut wrong) = source(chain, foreign, &pool);
    assert!(
        wrong
            .restore_target_from_original_frame(&bytes, 2, 4)
            .is_err()
    );
    assert!(wrong.clock.tip().is_none());
    assert_eq!(wrong.height(), 1);
    drop(wrong);
    drop(input);
    assert_eq!(pool.reserved_bytes(), source_bytes);
    drop(same_bytes_different_owner);
    assert_eq!(pool.reserved_bytes(), bytes.capacity());
    drop(bytes);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn durable_native_replay_rejects_foreign_source_pool_without_pinning_or_advancing() {
    let (wire, chain, network) = proof();
    let pool = AllocationBudget::new(64 * 1024 * 1024);
    let foreign_pool = AllocationBudget::new(pool.limit_bytes());
    let mut foreign_source = ChargedBuffer::new(wire.len(), &foreign_pool).unwrap();
    foreign_source.append(&wire).unwrap();
    let mut original = ChargedBuffer::new(wire.len(), &pool).unwrap();
    original.append(&wire).unwrap();
    drop(wire);
    let pointer = original.as_slice().as_ptr();
    let digest = Hash::new(original.as_slice());
    let (_writer, mut input) = source(chain, network, &pool);
    let mut foreign_journal = PreparedNativeFinalityJournal::new(limits(), &foreign_pool).unwrap();
    foreign_journal.decode(&foreign_source).unwrap();
    let original_bytes = pool.reserved_bytes();
    let foreign_bytes = foreign_pool.reserved_bytes();
    let native_error = input
        .clock
        .advance(foreign_journal.view(&foreign_source).unwrap())
        .unwrap_err();
    assert!(matches!(
        native_error,
        iroha_core::sumeragi::native_journal::NativeJournalError::SourcePool
    ));
    let native_error = AttemptError::Journal(native_error);
    for phase in [
        Phase::CommitmentsDecoded,
        Phase::EdgesDecoded,
        Phase::SessionDecoded,
    ] {
        assert!(native_error.terminal(phase));
    }
    assert!(input.clock.tip().is_none());
    assert!(input.restored_source.is_none());
    assert!(!input.journal.is_decoded());
    assert_eq!(input.height(), 1);
    assert_eq!(pool.reserved_bytes(), original_bytes);
    assert_eq!(foreign_pool.reserved_bytes(), foreign_bytes);
    drop(native_error);
    assert!(matches!(
        input.restore_target_from_original_frame(&foreign_source, 2, 4),
        Err(AttemptError::Binding)
    ));
    assert!(input.restored_source.is_none());
    assert!(!input.journal.is_decoded());
    assert!(input.clock.tip().is_none());
    assert_eq!(input.height(), 1);
    assert_eq!(input.generation(), 0);
    assert_eq!(pool.reserved_bytes(), original_bytes);
    assert_eq!(foreign_pool.reserved_bytes(), foreign_bytes);
    input
        .restore_target_from_original_frame(&original, 2, 4)
        .unwrap();
    assert_eq!(input.clock.tip().unwrap().height(), 2);
    assert_eq!(input.height(), 2);
    assert_eq!(input.generation(), 0);
    assert_eq!(
        input.restored_source.as_ref().unwrap().address,
        pointer.addr()
    );
    assert_eq!(original.as_slice().as_ptr(), pointer);
    assert_eq!(Hash::new(original.as_slice()), digest);
    drop(input);
    assert_eq!(pool.reserved_bytes(), original.capacity());
    drop(original);
    assert_eq!(pool.reserved_bytes(), 0);
    drop(foreign_journal);
    assert_eq!(foreign_pool.reserved_bytes(), foreign_source.capacity());
    drop(foreign_source);
    assert_eq!(foreign_pool.reserved_bytes(), 0);
}

#[test]
fn aggregate_restart_replays_complete_original_history_before_next_phase_and_keeps_cutoff() {
    use iroha_core::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    let config = TestChainConfig::new(World::default(), 10_000);
    let chain_id = config.chain_id.clone();
    let mut chain = CertifiedTestChain::start(config).unwrap();
    for timestamp in [20_000, 30_000, 40_000] {
        chain.commit_at(timestamp, Vec::new());
    }
    let pool = AllocationBudget::new(64 * 1024 * 1024);
    let original_frame = |height| {
        let journal = NativeFinalityJournal {
            blocks: (1..=height)
                .map(|n| {
                    iroha_data_model::sumeragi::finality::NativeFinalityArtifact::from_block(
                        chain.committed(n).block(),
                        limits(),
                    )
                    .unwrap()
                })
                .collect(),
        };
        let wire = norito::encode_canonical(&journal).unwrap();
        let mut frame = ChargedBuffer::new(wire.len(), &pool).unwrap();
        frame.append(&wire).unwrap();
        frame
    };
    let accepted = original_frame(3);
    let final_session = original_frame(4);
    let source_bytes = pool.reserved_bytes();
    let (_writer, mut input) = source(chain_id, chain.network_id(), &pool);
    assert!(matches!(
        input.restore_target_from_original_frame(&accepted, 3, 3),
        Err(AttemptError::Height)
    ));
    assert_eq!(input.height(), 1);
    assert!(input.clock().tip().is_none());
    assert!(input.restored_source.is_none());
    input
        .restore_target_from_original_frame(&accepted, 3, 5)
        .expect("aggregate restart must verify complete original H3 history from genesis");
    assert_eq!(input.height(), 3);
    assert_eq!(
        input.clock().tip().unwrap().result(),
        chain.committed(3).result()
    );
    // Reusing exactly the authenticated source does not re-execute its history.
    assert!(matches!(
        input.restore_target_from_original_frame(&accepted, 3, 3),
        Err(AttemptError::Height)
    ));
    input
        .restore_target_from_original_frame(&accepted, 3, 5)
        .unwrap();
    assert!(matches!(
        input.restore_target_from_original_frame(&final_session, 4, 4),
        Err(AttemptError::Height)
    ));
    assert_eq!(input.height(), 3);
    input
        .restore_target_from_original_frame(&final_session, 4, 5)
        .unwrap();
    assert_eq!(input.height(), 4);
    assert_eq!(
        input.clock().tip().unwrap().result(),
        chain.committed(4).result()
    );
    assert!(matches!(
        input.restore_target_from_original_frame(&accepted, 3, 5),
        Err(AttemptError::Height)
    ));
    assert_eq!(
        input.generation(),
        0,
        "durable replay never consumes a live FIFO frame"
    );
    drop(input);
    assert_eq!(pool.reserved_bytes(), source_bytes);
    drop(accepted);
    drop(final_session);
    assert_eq!(pool.reserved_bytes(), 0);
}
