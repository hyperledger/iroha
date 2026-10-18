//! Actual PendingCommit retries retain one immutable original after physical I/O refusal.
use super::*;
use crate::{
    fastpq::lane::isolated_replay_retryable_for_test,
    query::native_context_archive::{NativeContextArchiveError, publication_test_hook},
    sumeragi::{driver::traits::PublicationDeferral, node::IsolatedReplayError},
};
use std::{
    cell::Cell,
    io::{Read as _, Write as _},
    os::unix::net::UnixStream,
    rc::Rc,
};

fn with_isolated_worker(
    test: impl FnOnce(
        &CertifiedTestChain,
        &mut Worker<'_>,
        &KuraBlockStore,
        &mut tokio::sync::broadcast::Receiver<EventBox>,
    ) + Send
    + 'static,
) {
    crate::sumeragi::threads::sumeragi_thread_builder("isolated-publication-owner")
        .spawn(move || {
            let chain = permissioned_chain();
            let mut test = Some(test);
            with_worker_chain_erased(
                &chain,
                ConsensusMode::Permissioned,
                Arc::new(crate::sumeragi::lanes::merge::NoLanes),
                chain.execution_time_source(),
                true,
                &mut |chain, worker, blocks, events| {
                    test.take().unwrap()(chain, worker, blocks, events);
                },
            );
        })
        .unwrap()
        .join()
        .unwrap_or_else(|failure| std::panic::resume_unwind(failure));
}

// Fill a real nonblocking socket. The publication callback's write obtains the
// OS WouldBlock itself; no constructed io::Error or string controls retry policy.
fn saturated_stream() -> (UnixStream, UnixStream) {
    let (mut output, input) = UnixStream::pair().unwrap();
    output.set_nonblocking(true).unwrap();
    input.set_nonblocking(true).unwrap();
    let chunk = [7u8; 8192];
    loop {
        match output.write(&chunk) {
            Ok(count) => assert!(count > 0),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("socket saturation: {error}"),
        }
    }
    (output, input)
}

#[test]
fn isolated_pending_commit_keeps_original_after_physical_would_block() {
    with_isolated_worker(|chain, worker, blocks, events| {
        let (block, qc) = executed(chain, worker);
        let original = worker
            .live
            .as_ref()
            .unwrap()
            .native_contexts
            .as_ref()
            .unwrap();
        let pointer = original.canonical_bytes().as_ptr();
        let bytes = original.canonical_bytes().to_vec();
        let carrier = original.carrier_hash();
        worker.prepare(&block, &qc).unwrap();
        blocks.append(&block, &qc).unwrap();
        let canonical_frame = chain
            .kura()
            .canonical_block_wire_bytes_for_testing(core::num::NonZeroUsize::new(2).unwrap())
            .unwrap();
        let (mut output, mut input) = saturated_stream();
        let writes = Rc::new(Cell::new(0));
        let observed = Rc::clone(&writes);
        let _hook = publication_test_hook::install(move || {
            observed.set(observed.get() + 1);
            output.write(&[1]).map(|_| ())
        });
        let publications = Cell::new(0);
        let error = worker
            .commit_with(&block, &qc, |overlay| {
                publications.set(publications.get() + 1);
                overlay.try_publish()
            })
            .unwrap_err();
        assert!(
            matches!(&error, PublicationError::Deferred(PublicationDeferral::IsolatedSourceTransport(NativeContextArchiveError::Io(original))) if original.kind() == std::io::ErrorKind::WouldBlock)
        );
        assert!(isolated_replay_retryable_for_test(
            &IsolatedReplayError::Execution(error)
        ));
        assert_eq!(writes.get(), 1);
        assert_eq!(publications.get(), 1);
        assert_eq!(worker.state.view().height(), 2);
        assert_eq!(worker.applied.0, 1);
        assert!(worker.recovery.is_none());
        let root = worker.state.verify_world_state_accumulator().unwrap();
        let pending = worker.pending_commit.as_ref().unwrap();
        let owner = std::ptr::from_ref(pending);
        let event_count = pending.events.len();
        assert!(event_count > 0);
        assert_eq!(pending.native_contexts.canonical_bytes().as_ptr(), pointer);
        assert_eq!(pending.native_contexts.canonical_bytes(), bytes);
        assert!(events.try_recv().is_err());
        let mut drained = [0u8; 8192];
        while matches!(input.read(&mut drained), Ok(count) if count > 0) {}
        assert_eq!(
            std::ptr::from_ref(worker.pending_commit.as_ref().unwrap()),
            owner
        );
        let next = worker
            .commit_with(&block, &qc, |_| {
                panic!("the original State already published")
            })
            .unwrap();
        assert!(worker.pending_commit.is_none());
        assert_eq!(worker.applied, (2, qc.block_hash));
        assert_eq!(worker.state.verify_world_state_accumulator().unwrap(), root);
        assert_eq!(
            worker
                .context
                .native_context_archive
                .read_exact(2, carrier)
                .unwrap()
                .as_slice(),
            bytes
        );
        assert_eq!(
            chain
                .kura()
                .canonical_block_wire_bytes_for_testing(core::num::NonZeroUsize::new(2).unwrap())
                .unwrap(),
            canonical_frame
        );
        let mut delivered = 0;
        while events.try_recv().is_ok() {
            delivered += 1;
        }
        assert_eq!(delivered, event_count);
        assert_eq!(
            worker
                .commit_with(&block, &qc, |_| panic!("duplicate State publication"))
                .unwrap(),
            next
        );
        assert_eq!(publications.get(), 1);
        assert!(events.try_recv().is_err());
    });
}

#[test]
fn isolated_pending_commit_namespace_replacement_is_terminal_and_retains_original() {
    with_isolated_worker(|chain, worker, blocks, events| {
        let (block, qc) = executed(chain, worker);
        let original = worker
            .live
            .as_ref()
            .unwrap()
            .native_contexts
            .as_ref()
            .unwrap();
        let pointer = original.canonical_bytes().as_ptr();
        let bytes = original.canonical_bytes().to_vec();
        worker.prepare(&block, &qc).unwrap();
        blocks.append(&block, &qc).unwrap();
        let directory = chain.kura().store_root().join("native-contexts");
        let hidden = directory.with_extension("original-namespace");
        std::fs::rename(&directory, &hidden).unwrap();
        std::fs::create_dir(&directory).unwrap();
        let error = worker.commit(&block, &qc).unwrap_err();
        assert!(
            matches!(&error, PublicationError::Deferred(PublicationDeferral::IsolatedSourceTransport(NativeContextArchiveError::Io(original))) if original.kind() == std::io::ErrorKind::Other)
        );
        assert!(!isolated_replay_retryable_for_test(
            &IsolatedReplayError::Execution(error)
        ));
        let pending = worker.pending_commit.as_ref().unwrap();
        assert_eq!(pending.native_contexts.canonical_bytes().as_ptr(), pointer);
        assert_eq!(pending.native_contexts.canonical_bytes(), bytes);
        assert_eq!(worker.state.view().height(), 2);
        assert_eq!(worker.applied.0, 1);
        assert!(events.try_recv().is_err());
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
        std::fs::remove_dir(&directory).unwrap();
        std::fs::rename(&hidden, &directory).unwrap();
    });
}
