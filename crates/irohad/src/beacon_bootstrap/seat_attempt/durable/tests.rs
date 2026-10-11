//! Original partial source prefix and immutable checkpoint source retry controls.

use super::super::tests::{
    prepare_restartable, prepare_with_sources, root, through_publication_encoding,
};
use super::*;
use std::os::unix::fs::PermissionsExt as _;

#[test]
fn retained_partial_file_prefix_retries_same_descriptor_without_crossing_uninitialized_boundary() {
    let (_temporary, root) = root();
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let (mut attempt, _writers, _inherited) = prepare_restartable(&root, &budget).unwrap();
    attempt.step().unwrap();
    let directory = attempt.claim.directory().unwrap();
    let expected = b"original bounded canonical-source backing";
    let path = directory.path.join("partial-prefix-control.norito");
    fs::write(&path, expected).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut r = budget.try_reserve_bytes(expected.len()).unwrap();
    let mut source = ChargedBuffer::from_reservation(expected.len(), &mut r).unwrap();
    drop(r);
    source.append(&expected[..3]).unwrap();
    let pointer = source.as_slice().as_ptr();
    let mut loaded = Loaded::default();
    read_file(
        directory,
        "partial-prefix-control.norito",
        true,
        &mut source,
        &mut loaded,
    )
    .unwrap();
    let inode = loaded
        .descriptor
        .as_ref()
        .unwrap()
        .metadata()
        .unwrap()
        .ino();
    assert_eq!(source.as_slice(), expected);
    assert_eq!(source.as_slice().as_ptr(), pointer);
    read_file(
        directory,
        "partial-prefix-control.norito",
        true,
        &mut source,
        &mut loaded,
    )
    .unwrap();
    assert_eq!(
        loaded
            .descriptor
            .as_ref()
            .unwrap()
            .metadata()
            .unwrap()
            .ino(),
        inode
    );
    assert_eq!(source.as_slice().as_ptr(), pointer);
    fs::write(&path, b"changed bounded canonical-source backing!").unwrap();
    assert!(matches!(
        read_file(
            directory,
            "partial-prefix-control.norito",
            true,
            &mut source,
            &mut loaded
        ),
        Err(AttemptError::Binding)
    ));
    assert_eq!(source.as_slice(), expected);
    drop(loaded);
    drop(source);
    drop(attempt);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn checkpoint_source_is_bound_before_writer_refusal_and_cannot_be_substituted_or_unblocked() {
    let (_temporary, root) = root();
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let (mut attempt, _writers, _inherited) = prepare_restartable(&root, &budget).unwrap();
    through_publication_encoding(&mut attempt);
    let directory = attempt.claim.directory().unwrap().path.clone();
    fs::write(
        directory.join("private-checkpoint-1.norito"),
        b"occupied destination",
    )
    .unwrap();
    assert!(matches!(
        attempt.seal_and_publish_checkpoint(1),
        Err(AttemptError::Export(seat_export::ExportError::Io(_)))
    ));
    let source = attempt.durable.checkpoint_sources[0].unwrap();
    let retained = budget.reserved_bytes();
    let changed = vec![0x4a; source.length];
    assert!(matches!(
        {
            let original = &mut *attempt;
            original
                .durable
                .publish_checkpoint(original.claim.directory().unwrap(), 1, &changed)
        },
        Err(AttemptError::Binding)
    ));
    assert!(attempt.durable.checkpoint_terminal[0]);
    assert_eq!(attempt.durable.checkpoint_sources[0], Some(source));
    fs::remove_file(directory.join("private-checkpoint-1.norito")).unwrap();
    assert!(matches!(
        attempt.seal_and_publish_checkpoint(1),
        Err(AttemptError::Binding)
    ));
    assert!(!directory.join("private-checkpoint-1.norito").exists());
    assert!(!directory.join("phase-head-1.norito").exists());
    assert_eq!(budget.reserved_bytes(), retained);
    drop(attempt);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn visible_complete_original_head_is_synced_before_restored_claim_and_publication() {
    let (_temporary, root) = root();
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let (mut original, _writers, inherited) = prepare_restartable(&root, &budget).unwrap();
    let original_deadline = original.deadline;
    let original_expiry = original.durable.expiry;
    through_publication_encoding(&mut original);
    original.seal_and_publish_checkpoint(1).unwrap();
    original.publish_phase(1).unwrap();
    let public = original.local.as_ref().unwrap().encoded_public_frame();
    let public_hash = Hash::new(public).into();
    let expected_public = public.to_vec();
    let context = original
        .context(1, public_hash, original.durable.intent_hash(1).unwrap())
        .unwrap();
    let encrypted_hash = {
        let attempt = &mut *original;
        Hash::new(
            attempt
                .local
                .as_mut()
                .unwrap()
                .seal_private_checkpoint(&context, &attempt.signer)
                .unwrap(),
        )
        .into()
    };
    {
        let attempt = &mut *original;
        attempt
            .durable
            .stop_generation_head_before_sync(
                attempt.claim.directory().unwrap(),
                context.binding(),
                encrypted_hash,
            )
            .unwrap();
    }
    // Actual producer bytes are complete on the real filesystem, but its retained
    // progress has not executed the original file or directory sync operations.
    assert!(!original.durable.head_progress[0].is_synced());
    assert!(!original.durable.head_progress[0].complete());
    let directory = original.claim.directory().unwrap().path.clone();
    let expected_head = original.durable.heads[0].as_slice().to_vec();
    assert_eq!(
        fs::read(directory.join(HEAD_FILES[0])).unwrap(),
        expected_head
    );
    let original_identity = original.claim_and_fifo_identity().unwrap();
    let inodes = [
        INTENT_FILES[0],
        HEAD_FILES[0],
        "publication.norito",
        CHECKPOINT_FILES[0],
    ]
    .map(|name| fs::metadata(directory.join(name)).unwrap().ino());
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
    restored.step().unwrap();
    assert_eq!(restored.phase, Phase::PublicationDurable);
    assert!(restored.durable.loaded.iter().all(|owner| owner.synced));
    assert!(restored.durable.restored_directory_synced);
    assert!(restored.claim.directory().is_some());
    assert!(restored.publications[..2].iter().all(|p| p.complete()));
    assert_eq!(
        restored.claim_and_fifo_identity().unwrap(),
        original_identity
    );
    assert_eq!(std::ptr::from_ref(&*restored), receiver);
    assert!(restored.deadline <= original_deadline);
    assert_eq!(restored.durable.expiry, original_expiry);
    assert_eq!(
        restored.local.as_ref().unwrap().encoded_public_frame(),
        expected_public
    );
    assert_eq!(
        fs::read(directory.join(HEAD_FILES[0])).unwrap(),
        expected_head
    );
    assert_eq!(
        [
            INTENT_FILES[0],
            HEAD_FILES[0],
            "publication.norito",
            CHECKPOINT_FILES[0]
        ]
        .map(|name| fs::metadata(directory.join(name)).unwrap().ino()),
        inodes
    );
    // Successful publication decoding moves the original rows and retires its
    // prepared row containers. The blocker prevents new admission beforehand;
    // these genuine refunds do not replace any retained source or file owner.
    assert!(budget.reserved_bytes() < budget.limit_bytes());
    drop(restored);
    assert_eq!(budget.reserved_bytes(), blocker.remaining_bytes());
    drop(blocker);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_restore_sync_refusal_keeps_all_descriptors_sources_and_unfinished_barrier() {
    use std::os::fd::AsRawFd as _;
    let (_temporary, root) = root();
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let (mut original, _writers, inherited) = prepare_restartable(&root, &budget).unwrap();
    through_publication_encoding(&mut original);
    original.step().unwrap();
    let path = original.claim.directory().unwrap().path.clone();
    let expected_private = fs::read(path.join(CHECKPOINT_FILES[0])).unwrap();
    drop(original);
    let mut restored = prepare_with_sources(
        &root,
        &budget,
        inherited,
        "software://iroha/consensus-threshold/retained-attempt",
        7,
    )
    .unwrap();
    restored.phase = Phase::RestoringGeneration;
    restored.claim.open_existing().unwrap();
    {
        let attempt = &mut *restored;
        attempt
            .durable
            .load_generation(attempt.claim.read_directory().unwrap())
            .unwrap();
    }
    // Match the production order: publication decoding precedes the durability
    // barrier and retires its prepared row containers on successful extraction.
    // Measure sync refusal/retry after that transition, while private adoption
    // and claim authentication remain unfinished.
    {
        let attempt = &mut *restored;
        let source = attempt.durable.public_source();
        attempt.original_publications[0]
            .as_mut()
            .unwrap()
            .decode(source, norito::canonical_decode_limits(source.len()))
            .unwrap();
    }
    let fds = restored
        .durable
        .loaded
        .each_ref()
        .map(|owner| owner.descriptor.as_ref().unwrap().as_raw_fd());
    let private_pointer = restored.durable.private_source().as_ptr();
    let retained = budget.reserved_bytes();
    let (refusing_read, _refusing_write) = rustix::pipe::pipe().unwrap();
    let refusing = File::from(refusing_read);
    let actual = refusing.sync_all().unwrap_err().raw_os_error();
    let result = {
        let attempt = &mut *restored;
        let mut calls = 0;
        attempt.durable.sync_restored_generation_with(
            attempt.claim.read_directory().unwrap(),
            |held| {
                calls += 1;
                if calls == 2 {
                    refusing.sync_all()
                } else {
                    held.sync_all()
                }
            },
        )
    };
    let AttemptError::Export(seat_export::ExportError::Io(error)) = result.unwrap_err() else {
        panic!("original native sync cause must survive");
    };
    assert_eq!(error.raw_os_error(), actual);
    assert!(restored.durable.loaded[0].synced);
    assert!(
        restored.durable.loaded[1..]
            .iter()
            .all(|owner| !owner.synced)
    );
    assert!(!restored.durable.restored_directory_synced);
    assert!(restored.claim.directory().is_none());
    assert_eq!(restored.phase, Phase::RestoringGeneration);
    assert!(restored.local.is_none());
    assert_eq!(
        restored.durable.loaded.each_ref().map(|owner| owner
            .descriptor
            .as_ref()
            .unwrap()
            .as_raw_fd()),
        fds
    );
    assert_eq!(restored.durable.private_source().as_ptr(), private_pointer);
    assert_eq!(restored.durable.private_source(), expected_private);
    assert_eq!(budget.reserved_bytes(), retained);
    let blocker = budget
        .try_reserve_bytes(budget.limit_bytes() - retained)
        .unwrap();
    restored.step().unwrap();
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    drop(blocker);
    assert_eq!(restored.phase, Phase::PublicationDurable);
    assert!(restored.durable.loaded.iter().all(|owner| owner.synced));
    assert!(restored.durable.restored_directory_synced);
    assert_eq!(
        restored.durable.loaded.each_ref().map(|owner| owner
            .descriptor
            .as_ref()
            .unwrap()
            .as_raw_fd()),
        fds
    );
    assert_eq!(restored.durable.private_source().as_ptr(), private_pointer);
    assert_eq!(
        fs::read(path.join(CHECKPOINT_FILES[0])).unwrap(),
        expected_private
    );
    assert_eq!(budget.reserved_bytes(), retained);
    drop(restored);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn genuine_later_source_sync_refusal_keeps_all_original_descriptors_bytes_and_unfinished_head_barrier()
 {
    use super::super::later_restore_tests::through_original_later_phase;
    use std::os::fd::AsRawFd as _;
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
    restored.step().unwrap();
    assert_eq!(restored.phase, Phase::RestoringDeliveries);
    let (intent, head) = {
        let attempt = &mut *restored;
        attempt
            .durable
            .load_later(attempt.claim.read_directory().unwrap(), 2)
            .unwrap()
    };
    let descriptors = restored.durable.later[0]
        .files
        .iter()
        .map(|file| file.descriptor.as_ref().unwrap().as_raw_fd())
        .collect::<Vec<_>>();
    let sources = restored.durable.later[0]
        .bytes
        .iter()
        .map(|source| {
            let source = source.as_ref().unwrap().as_slice();
            (source.as_ptr(), source.to_vec())
        })
        .collect::<Vec<_>>();
    let (read, _write) = rustix::pipe::pipe().unwrap();
    let actual_refusal = File::from(read);
    let expected_cause = actual_refusal.sync_all().unwrap_err().raw_os_error();
    let mut calls = 0;
    let cause = {
        let attempt = &mut *restored;
        attempt
            .durable
            .sync_restored_later_with(attempt.claim.read_directory().unwrap(), 2, |file| {
                calls += 1;
                if calls == 2 {
                    actual_refusal.sync_all()
                } else {
                    file.sync_all()
                }
            })
            .unwrap_err()
    };
    let AttemptError::Export(seat_export::ExportError::Io(cause)) = cause else {
        panic!("original actual fsync cause")
    };
    assert_eq!(cause.raw_os_error(), expected_cause);
    assert!(
        restored.durable.later[0].files[6].synced,
        "actual original read-marker barrier completed"
    );
    assert!(!restored.durable.later[0].files[4].synced);
    assert!(
        !restored.durable.later[0].files[1].synced,
        "head cannot precede its original sources"
    );
    assert!(matches!(
        restored.durable.retain_restored_later(2, intent, head),
        Err(AttemptError::Binding)
    ));
    assert!(restored.claim.directory().is_none());
    assert_eq!(
        restored.finality.height(),
        1,
        "file custody never fabricates native finality"
    );
    {
        let attempt = &mut *restored;
        attempt
            .durable
            .sync_restored_later(attempt.claim.read_directory().unwrap(), 2)
            .unwrap();
    }
    assert!(
        restored.durable.later[0]
            .files
            .iter()
            .all(|file| file.synced)
    );
    assert_eq!(
        restored.durable.later[0]
            .files
            .iter()
            .map(|file| file.descriptor.as_ref().unwrap().as_raw_fd())
            .collect::<Vec<_>>(),
        descriptors
    );
    for (source, (pointer, bytes)) in restored.durable.later[0].bytes.iter().zip(sources) {
        let source = source.as_ref().unwrap().as_slice();
        assert_eq!(source.as_ptr(), pointer);
        assert_eq!(source, bytes);
    }
    assert!(
        restored.claim.directory().is_none(),
        "barriers alone cannot authorize restored secrets or claim"
    );
    restored.step().unwrap();
    assert_eq!(restored.phase, Phase::DeliveriesDurable);
    assert_eq!(restored.finality.height(), 2);
    drop(restored);
    assert_eq!(budget.reserved_bytes(), 0);
}

fn inline_decode_records() -> (DurableDeadline, Intent, Head) {
    let expiry = DurableDeadline {
        boot: [0x41; 32],
        origin_nanos: 100,
        expiry_nanos: 200,
    };
    let mut intent = Intent::empty(expiry);
    intent.version = 1;
    intent.operation = 3;
    intent.context.network_id = [0x11; 32];
    intent.context.attempt_id = [0x12; 32];
    intent.context.authority_generation = 7;
    intent.context.session_id = [0x13; 32];
    intent.context.roster_hash = [0x14; 32];
    intent.context.seat_index = 4;
    intent.context.lifecycle_key_hash = [0x15; 32];
    intent.context.provider_handle_hash = [0x16; 32];
    intent.context.provider_revision = 11;
    intent.context.start_height = 12;
    intent.context.commitments_end_height = 13;
    intent.context.deliveries_end_height = 14;
    intent.context.acceptances_end_height = 15;
    intent.context.source = DkgCheckpointSourceV1::ExecutedNativeTip {
        height: 9,
        block_hash: [0x17; 32],
        core_hash: [0x18; 32],
        result_hash: [0x19; 32],
    };
    intent.context.cutoff_height = 16;
    intent.context.phase = 3;
    intent.context.public_output_hash = [0x1a; 32];
    intent.context.phase_input_hash = [0x1b; 32];
    intent.context.producer_intent_hash = [0x1c; 32];
    intent.context.previous_checkpoint_hash = [0x1d; 32];
    intent.claim_identity = [17, 18, 19, 20];
    intent.claim_path_hash = [0x1e; 32];
    intent.fifo_identity = [21, 22, 23, 24];
    intent.previous_head_hash = [0x1f; 32];
    intent.continuation_hash = [0x20; 32];
    intent.continuation_source = DkgCheckpointSourceV1::SignedGenesisAuthorization {
        genesis_hash: [0x21; 32],
    };
    intent.source_hashes = [[0x24; 32], [0x25; 32]];
    intent.stream_generations = [25, 26];
    let head = Head {
        version: 1,
        context: intent.context,
        checkpoint_hash: [0x22; 32],
        previous_head_hash: [0x23; 32],
    };
    (expiry, intent, head)
}

#[test]
fn prepared_durable_nested_records_match_original_canonical_frames_in_same_full_pool() {
    let (expiry, intent, head) = inline_decode_records();
    let intent_frame = norito::encode_canonical(&intent).unwrap();
    let head_frame = norito::encode_canonical(&head).unwrap();
    assert_eq!(
        norito::decode_canonical::<Intent>(&intent_frame).unwrap(),
        intent
    );
    assert_eq!(norito::decode_canonical::<Head>(&head_frame).unwrap(), head);
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let mut durable = PreparedDurableDkg::new(expiry, 0, 0, &pool).unwrap();
    let pointers = (
        durable.destination.intent.as_slice().as_ptr(),
        durable.destination.head.as_slice().as_ptr(),
    );
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
        .unwrap();
    // Four levels are independently root -> context -> source -> source leaf.
    // Zero codec-allocation allowance also rules out an aligned archive copy.
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 4);
    for _ in 0..2 {
        durable
            .workspace
            .decode_canonical_into::<Intent, _>(
                &intent_frame,
                limits,
                &mut DestinationFor::<Intent> {
                    owner: &mut durable.destination,
                    expiry,
                    marker: std::marker::PhantomData,
                },
            )
            .unwrap();
        assert_eq!(durable.destination.intent.as_slice()[0], intent);
        durable
            .workspace
            .decode_canonical_into::<Head, _>(
                &head_frame,
                limits,
                &mut DestinationFor::<Head> {
                    owner: &mut durable.destination,
                    expiry,
                    marker: std::marker::PhantomData,
                },
            )
            .unwrap();
        assert_eq!(durable.destination.head.as_slice()[0], head);
        assert_eq!(durable.destination.intent.as_slice().as_ptr(), pointers.0);
        assert_eq!(durable.destination.head.as_slice().as_ptr(), pointers.1);
        assert!(durable.belongs_to(&pool));
        assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    }
    drop(durable);
    assert_eq!(pool.reserved_bytes(), blocker.remaining_bytes());
    drop(blocker);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn partial_nested_decode_refusal_and_malformed_frames_reset_without_replacing_original_records() {
    let (expiry, intent, _) = inline_decode_records();
    let frame = norito::encode_canonical(&intent).unwrap();
    let mut trailing = frame.clone();
    trailing.push(0);
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let mut durable = PreparedDurableDkg::new(expiry, 0, 0, &pool).unwrap();
    let pointer = durable.destination.intent.as_slice().as_ptr();
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
        .unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 4);
    let short_depth = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 3);
    let error = norito::core::with_decode_limits_scope(short_depth, || {
        durable.workspace.decode_canonical_into::<Intent, _>(
            &frame,
            limits,
            &mut DestinationFor::<Intent> {
                owner: &mut durable.destination,
                expiry,
                marker: std::marker::PhantomData,
            },
        )
    })
    .unwrap_err();
    assert!(
        matches!(error, norito::core::PreparedDecodeError::Codec(ref cause)
        if cause.kind() == norito::core::DecodeAttemptErrorKind::EnclosingLimit)
    );
    assert!(!AttemptError::DurableDecode(error).terminal(Phase::RestoringGeneration));
    assert_eq!(
        durable.destination.intent.as_slice()[0],
        Intent::empty(expiry)
    );
    for bytes in [&frame[..frame.len() - 1], trailing.as_slice()] {
        let error = durable
            .workspace
            .decode_canonical_into::<Intent, _>(
                bytes,
                limits,
                &mut DestinationFor::<Intent> {
                    owner: &mut durable.destination,
                    expiry,
                    marker: std::marker::PhantomData,
                },
            )
            .unwrap_err();
        assert!(AttemptError::DurableDecode(error).terminal(Phase::RestoringGeneration));
        assert_eq!(
            durable.destination.intent.as_slice()[0],
            Intent::empty(expiry)
        );
        assert_eq!(durable.destination.intent.as_slice().as_ptr(), pointer);
        assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    }
    durable
        .workspace
        .decode_canonical_into::<Intent, _>(
            &frame,
            limits,
            &mut DestinationFor::<Intent> {
                owner: &mut durable.destination,
                expiry,
                marker: std::marker::PhantomData,
            },
        )
        .unwrap();
    assert_eq!(durable.destination.intent.as_slice()[0], intent);
    assert_eq!(durable.destination.intent.as_slice().as_ptr(), pointer);
    assert!(durable.belongs_to(&pool));
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    drop(durable);
    assert_eq!(pool.reserved_bytes(), blocker.remaining_bytes());
    drop(blocker);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn late_malformed_nested_source_cannot_preserve_partially_decoded_expiry() {
    let (expiry, mut intent, _) = inline_decode_records();
    intent.expiry.origin_nanos = 300;
    intent.expiry.expiry_nanos = 400;
    let valid = norito::encode_canonical(&intent).unwrap();
    let flags = norito::core::default_encode_flags();
    let mut payload = Vec::new();
    {
        let _flags = norito::core::DecodeFlagsGuard::enter(flags);
        norito::core::serialize_to_writer(&intent, &mut payload).unwrap();
    }
    // Field9's unchanged V1 payload is tag0 + compact32 + raw32. The
    // incoming source-hash/generation fields remain after it. Locate its exact
    // borrowed range with the original framing kernel, then alter only its tag
    // and use the actual nominal framer/CRC. This failure occurs after expiry.
    let continuation_start = {
        let _flags = norito::core::DecodeFlagsGuard::enter(flags);
        let mut offset = 0;
        norito::core::framed_field::<u16>(&payload, &mut offset).unwrap();
        norito::core::framed_field::<u16>(&payload, &mut offset).unwrap();
        norito::core::framed_field::<DkgCheckpointBindingV1>(&payload, &mut offset).unwrap();
        norito::core::framed_field::<DurableDeadline>(&payload, &mut offset).unwrap();
        norito::core::framed_field::<[u64; 4]>(&payload, &mut offset).unwrap();
        norito::core::framed_field::<[u8; 32]>(&payload, &mut offset).unwrap();
        norito::core::framed_field::<[u64; 4]>(&payload, &mut offset).unwrap();
        norito::core::framed_field::<[u8; 32]>(&payload, &mut offset).unwrap();
        norito::core::framed_field::<[u8; 32]>(&payload, &mut offset).unwrap();
        let source =
            norito::core::framed_field::<DkgCheckpointSourceV1>(&payload, &mut offset).unwrap();
        assert_eq!(source.bytes().len(), 37);
        assert!(offset < payload.len());
        source.bytes().as_ptr() as usize - payload.as_ptr() as usize
    };
    assert_eq!(
        &payload[continuation_start..continuation_start + 4],
        &[0; 4]
    );
    assert_eq!(payload[continuation_start + 4], 32);
    payload[continuation_start] = 2;
    let layout = norito::core::FixedFrameLayout::<Intent>::new(payload.len(), flags).unwrap();
    let mut malformed = Vec::new();
    layout.write(&mut malformed, &payload).unwrap();
    assert_eq!(malformed.len(), valid.len());
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let mut durable = PreparedDurableDkg::new(expiry, 0, 0, &pool).unwrap();
    let pointer = durable.destination.intent.as_slice().as_ptr();
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
        .unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 4);
    durable
        .workspace
        .decode_canonical_into::<Intent, _>(
            &valid,
            limits,
            &mut DestinationFor::<Intent> {
                owner: &mut durable.destination,
                expiry,
                marker: std::marker::PhantomData,
            },
        )
        .unwrap();
    assert_eq!(durable.destination.intent.as_slice()[0], intent);
    assert_ne!(durable.destination.intent.as_slice()[0].expiry, expiry);
    let error = durable
        .workspace
        .decode_canonical_into::<Intent, _>(
            &malformed,
            limits,
            &mut DestinationFor::<Intent> {
                owner: &mut durable.destination,
                expiry,
                marker: std::marker::PhantomData,
            },
        )
        .unwrap_err();
    assert!(
        matches!(error, norito::core::PreparedDecodeError::Codec(ref cause)
        if cause.kind() == norito::core::DecodeAttemptErrorKind::Invalid)
    );
    assert!(AttemptError::DurableDecode(error).terminal(Phase::RestoringGeneration));
    assert_eq!(
        durable.destination.intent.as_slice()[0],
        Intent::empty(expiry)
    );
    assert_eq!(durable.expiry, expiry);
    assert_eq!(durable.destination.intent.as_slice().as_ptr(), pointer);
    assert!(durable.belongs_to(&pool));
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    drop(durable);
    assert_eq!(pool.reserved_bytes(), blocker.remaining_bytes());
    drop(blocker);
    assert_eq!(pool.reserved_bytes(), 0);
}
