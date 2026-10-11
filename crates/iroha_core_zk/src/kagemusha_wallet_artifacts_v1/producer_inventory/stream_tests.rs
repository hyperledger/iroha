//! Integrity-only streaming controls; these fixtures never grant proof-source authority.

use std::{cell::RefCell, io, rc::Rc};

use super::*;

#[derive(Default)]
struct Observed {
    opens: Vec<[u8; 32]>,
    reads: usize,
    requests: Vec<usize>,
    eof: usize,
}

#[derive(Clone, Copy)]
enum ReadFailure {
    Unavailable,
    Custody,
    CustodyText,
}

struct StreamSource {
    blobs: BTreeMap<[u8; 32], Vec<u8>>,
    observed: Rc<RefCell<Observed>>,
    token: iroha_pasta::CancellationToken,
    cancel_open: bool,
    cancel_read: Option<usize>,
    failure: Option<ReadFailure>,
    interrupt_first: bool,
}

struct StreamReader {
    bytes: Cursor<Vec<u8>>,
    observed: Rc<RefCell<Observed>>,
    token: iroha_pasta::CancellationToken,
    cancel_read: Option<usize>,
    failure: Option<ReadFailure>,
    interrupt_first: bool,
}

impl Read for StreamReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let index = {
            let mut observed = self.observed.borrow_mut();
            observed.reads += 1;
            observed.requests.push(output.len());
            observed.reads
        };
        if self.cancel_read == Some(index) {
            self.token.cancel();
        }
        if self.interrupt_first && index == 1 {
            return Err(io::ErrorKind::Interrupted.into());
        }
        match self.failure {
            Some(ReadFailure::Unavailable) => return Err(io::ErrorKind::PermissionDenied.into()),
            Some(ReadFailure::Custody) => {
                return Err(io::Error::other(OriginalCustodyFailure(
                    io::ErrorKind::NotFound.into(),
                )));
            }
            Some(ReadFailure::CustodyText) => {
                return Err(io::Error::other("original custody refused: missing file"));
            }
            None => {}
        }
        let count = self.bytes.read(output)?;
        if count == 0 {
            self.observed.borrow_mut().eof += 1;
        }
        Ok(count)
    }
}

impl OriginalSourceV1 for StreamSource {
    fn open(&mut self, hash: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
        self.observed.borrow_mut().opens.push(hash);
        if self.cancel_open {
            self.token.cancel();
        }
        let bytes = self.blobs.get(&hash).ok_or(Error::Unavailable)?.clone();
        Ok(Box::new(StreamReader {
            bytes: Cursor::new(bytes),
            observed: Rc::clone(&self.observed),
            token: self.token.clone(),
            cancel_read: self.cancel_read,
            failure: self.failure,
            interrupt_first: self.interrupt_first,
        }))
    }
}

fn selected() -> AuthenticatedProducerInventoryV1 {
    // Structural private fixture, deliberately not a signed or source-qualified graph.
    AuthenticatedProducerInventoryV1 {
        inventory: structural_inventory(),
        scheme_id: [1; 32],
        manifest_digest: [2; 32],
    }
}

fn source() -> StreamSource {
    StreamSource {
        blobs: memory().blobs,
        observed: Rc::new(RefCell::new(Observed::default())),
        token: iroha_pasta::CancellationToken::new(),
        cancel_open: false,
        cancel_read: None,
        failure: None,
        interrupt_first: false,
    }
}

#[test]
fn revalidation_streams_each_selected_role_and_observes_exact_eof() {
    let selected = selected();
    let original = selected.inventory.originals[0];
    let mut source = source();
    selected
        .revalidate_original_cancellable(0, &mut source, 3, None)
        .unwrap();
    let observed = source.observed.borrow();
    assert_eq!(
        observed.opens,
        [
            original.descriptor,
            original.verifying_key,
            original.proving_key
        ]
        .map(|blob| blob.sha256)
    );
    assert_eq!(observed.eof, 3);
    assert_eq!(observed.reads, 6);
    assert!(observed.requests.iter().all(|length| *length <= 64 * 1024));
}

#[test]
fn revalidation_refuses_every_invalid_cap_or_identity_before_open() {
    let original = selected();
    for (index, cap) in [
        (u32::MAX, 3),
        (0, 0),
        (0, 2),
        (0, PROVING_KEY_MAX_BYTES_V1 + 1),
    ] {
        let mut source = source();
        assert_eq!(
            original.revalidate_original_cancellable(index, &mut source, cap, None),
            Err(Error::Inventory)
        );
        assert!(source.observed.borrow().opens.is_empty());
    }
    for role in 0..3 {
        for mutation in 0..4 {
            let mut selected = selected();
            let original = &mut selected.inventory.originals[0];
            let blob = match role {
                0 => &mut original.descriptor,
                1 => &mut original.verifying_key,
                _ => &mut original.proving_key,
            };
            match mutation {
                0 => blob.bytes = 0,
                1 => blob.bytes = u64::MAX,
                2 => blob.sha256 = [0; 32],
                _ => {
                    blob.bytes = match role {
                        0 => DESCRIPTOR_MAX_BYTES_V1 as u64 + 1,
                        1 => VERIFYING_KEY_MAX_BYTES_V1 as u64 + 1,
                        _ => 4,
                    };
                }
            }
            let mut source = source();
            assert_eq!(
                selected.revalidate_original_cancellable(0, &mut source, 3, None),
                Err(Error::Inventory)
            );
            assert!(source.observed.borrow().opens.is_empty());
        }
    }
}

#[test]
fn revalidation_rejects_short_extended_changed_and_missing_roles_without_fallback() {
    let selected = selected();
    let original = selected.inventory.originals[0];
    for (role, blob) in [
        original.descriptor,
        original.verifying_key,
        original.proving_key,
    ]
    .into_iter()
    .enumerate()
    {
        for mutation in 0..5 {
            let mut source = source();
            if mutation == 3 {
                source.blobs.remove(&blob.sha256);
            } else {
                let bytes = source.blobs.get_mut(&blob.sha256).unwrap();
                match mutation {
                    0 => {
                        bytes.pop();
                    }
                    1 => bytes.push(0),
                    2 => bytes[0] ^= 1,
                    // A reader returning another role's payload cannot gain authority.
                    _ => *bytes = if role == 1 { vec![1] } else { vec![2] },
                }
            }
            assert_eq!(
                selected.revalidate_original_cancellable(0, &mut source, 3, None),
                Err(if mutation == 3 {
                    Error::Unavailable
                } else {
                    Error::Inventory
                })
            );
            assert_eq!(source.observed.borrow().opens.len(), role + 1);
        }
    }
}

#[test]
fn shared_scan_preserves_collect_bytes_and_discard_chunk_bounds_after_interruption() {
    let bytes = vec![0x5a; 3 * 64 * 1024 + 17];
    let blob = BlobV1::of(&bytes);
    for collect in [false, true] {
        let mut source = source();
        source.blobs.insert(blob.sha256, bytes.clone());
        source.interrupt_first = true;
        if collect {
            assert_eq!(
                read_cancellable(&mut source, blob, bytes.len(), None).unwrap(),
                bytes
            );
        } else {
            scan_cancellable(&mut source, blob, bytes.len(), None, |_| (), |(), _| {}).unwrap();
        }
        let observed = source.observed.borrow();
        assert_eq!(observed.opens, [blob.sha256]);
        assert_eq!(observed.reads, 6); // Interrupted, four payload reads, EOF.
        assert_eq!(observed.eof, 1);
        assert_eq!(observed.requests.last(), Some(&1));
        assert!(observed.requests.iter().all(|length| *length <= 64 * 1024));
    }
}

#[test]
fn revalidation_cancellation_precedes_open_read_errors_and_final_digest() {
    let selected = selected();
    let mut pre_cancelled = source();
    pre_cancelled.token.cancel();
    let token = pre_cancelled.token.clone();
    assert_eq!(
        selected.revalidate_original_cancellable(0, &mut pre_cancelled, 3, Some(&token)),
        Err(Error::Cancelled)
    );
    assert!(pre_cancelled.observed.borrow().opens.is_empty());
    let mut cancel_open = source();
    cancel_open.cancel_open = true;
    // Cancellation while opening also dominates an unavailable source.
    cancel_open.blobs.clear();
    let token = cancel_open.token.clone();
    assert_eq!(
        selected.revalidate_original_cancellable(0, &mut cancel_open, 3, Some(&token)),
        Err(Error::Cancelled)
    );
    assert_eq!(cancel_open.observed.borrow().reads, 0);
    for read in [1, 2] {
        for failure in [
            None,
            Some(ReadFailure::Unavailable),
            Some(ReadFailure::Custody),
        ] {
            // An injected failure before the requested cancellation point would stop
            // the reader first. Exercise EOF cancellation only on the successful reader.
            if read == 2 && failure.is_some() {
                continue;
            }
            let mut source = source();
            source.cancel_read = Some(read);
            source.failure = failure;
            let token = source.token.clone();
            assert_eq!(
                selected.revalidate_original_cancellable(0, &mut source, 3, Some(&token)),
                Err(Error::Cancelled)
            );
            assert_eq!(source.observed.borrow().reads, read);
            assert_eq!(source.observed.borrow().opens.len(), 1);
        }
    }
    // The cancelled attempt did not mutate the authenticated selection.
    selected
        .revalidate_original_cancellable(0, &mut source(), 3, None)
        .unwrap();
}

#[test]
fn shared_scan_cancels_between_payload_chunks_and_discards_partial_collection() {
    let bytes = vec![7; 3 * 64 * 1024 + 17];
    let blob = BlobV1::of(&bytes);
    for collect in [false, true] {
        let mut source = source();
        source.blobs.insert(blob.sha256, bytes.clone());
        source.cancel_read = Some(2);
        let token = source.token.clone();
        let result = if collect {
            read_cancellable(&mut source, blob, bytes.len(), Some(&token)).map(|_| ())
        } else {
            scan_cancellable(
                &mut source,
                blob,
                bytes.len(),
                Some(&token),
                |_| (),
                |(), _| {},
            )
        };
        assert_eq!(result, Err(Error::Cancelled));
        assert_eq!(source.observed.borrow().reads, 2);
        assert_eq!(source.observed.borrow().eof, 0);
    }
}

#[test]
fn revalidation_preserves_typed_custody_failure_without_trusting_error_text() {
    let selected = selected();
    for (failure, expected) in [
        (ReadFailure::Unavailable, Error::Unavailable),
        (ReadFailure::Custody, Error::Inventory),
        (ReadFailure::CustodyText, Error::Unavailable),
    ] {
        let mut source = source();
        source.failure = Some(failure);
        assert_eq!(
            selected.revalidate_original_cancellable(0, &mut source, 3, None),
            Err(expected)
        );
        assert_eq!(source.observed.borrow().reads, 1);
    }
}

#[test]
fn hash_only_scan_refuses_real_retained_original_namespace_replacement() {
    use super::super::directory::DirectoryOriginalsV1;

    struct ReplacedSource {
        originals: DirectoryOriginalsV1,
        root: std::path::PathBuf,
    }
    impl OriginalSourceV1 for ReplacedSource {
        fn open(&mut self, hash: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
            let reader = self.originals.open_original(hash)?;
            std::fs::rename(
                self.root.join(hex::encode(hash)),
                self.root.join("retained-old"),
            )
            .unwrap();
            // Even byte-identical replacement is not the retained original.
            std::fs::copy(
                self.root.join("retained-old"),
                self.root.join(hex::encode(hash)),
            )
            .unwrap();
            Ok(reader)
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("originals");
    drop(iroha_fs::PrivateDirectory::open_or_create(&root).unwrap());
    let root = root.canonicalize().unwrap();
    let mut originals = DirectoryOriginalsV1::open_existing(&root, 1024).unwrap();
    let bytes = b"exact original";
    let blob = BlobV1::of(bytes);
    originals.store_original(blob, bytes).unwrap();
    let mut source = ReplacedSource { originals, root };
    assert_eq!(
        scan_cancellable(&mut source, blob, 1024, None, |_| (), |(), _| {}),
        Err(Error::Inventory)
    );
}
