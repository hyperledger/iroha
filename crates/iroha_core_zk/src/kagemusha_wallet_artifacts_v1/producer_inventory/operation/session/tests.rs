//! Controls over genuine admitted Receive owners from complete-catalog acceptance,
//! and over the route-stage workers: synthetic routes, then the genuine catalog.

use std::{
    collections::BTreeMap,
    io::Cursor,
    sync::atomic::{AtomicUsize, Ordering},
    thread::ThreadId,
    time::{Duration, Instant},
};

use super::*;

#[test]
fn complete_q_identity_preflight_rejects_missing_foreign_duplicate_and_reordered_programs() {
    let installation = ([1; 32], [2; 32]);
    let expected: Vec<_> = (0..3).map(|program| (installation, program)).collect();
    require_program_identities(installation, 3, expected.clone().into_iter()).unwrap();
    for count in [0, 1, 2, 4] {
        let values: Vec<_> = (0..count).map(|program| (installation, program)).collect();
        assert!(matches!(
            require_program_identities(installation, 3, values.into_iter()),
            Err(Error::Inventory)
        ));
    }
    for changed in 0..expected.len() {
        let mut values = expected.clone();
        values[changed].0.0[0] ^= 1;
        assert!(matches!(
            require_program_identities(installation, 3, values.into_iter()),
            Err(Error::Authority)
        ));
        let mut values = expected.clone();
        values[changed].0.1[0] ^= 1;
        assert!(matches!(
            require_program_identities(installation, 3, values.into_iter()),
            Err(Error::Authority)
        ));
        let mut values = expected.clone();
        values[changed].1 = (values[changed].1 + 1) % 3;
        assert!(matches!(
            require_program_identities(installation, 3, values.into_iter()),
            Err(Error::Authority)
        ));
    }
    let mut reordered = expected;
    reordered.swap(0, 2);
    assert!(matches!(
        require_program_identities(installation, 3, reordered.into_iter()),
        Err(Error::Authority)
    ));
}

#[derive(Clone, Copy)]
enum Fault {
    Missing,
    Changed,
    Truncated,
    Extended,
    Cancelled,
}

struct Observed<'a> {
    source: &'a mut dyn OriginalSourceV1,
    fault: Option<(BlobV1, Fault)>,
    opens: Vec<[u8; 32]>,
}

struct ChangedReader<'a> {
    original: Box<dyn Read + 'a>,
    changed: bool,
}

impl Read for ChangedReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let count = self.original.read(output)?;
        if count > 0 && !self.changed {
            output[0] ^= 1;
            self.changed = true;
        }
        Ok(count)
    }
}

impl OriginalSourceV1 for Observed<'_> {
    fn open(&mut self, digest: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
        self.opens.push(digest);
        match self.fault.filter(|(blob, _)| blob.sha256 == digest) {
            Some((_, Fault::Missing)) => Err(Error::Unavailable),
            Some((_, Fault::Cancelled)) => Err(Error::Cancelled),
            Some((_, Fault::Changed)) => Ok(Box::new(ChangedReader {
                original: self.source.open(digest)?,
                changed: false,
            })),
            Some((blob, Fault::Truncated)) => Ok(Box::new(
                self.source
                    .open(digest)?
                    .take(blob.bytes.checked_sub(1).unwrap()),
            )),
            Some((_, Fault::Extended)) => {
                Ok(Box::new(self.source.open(digest)?.chain(Cursor::new([0]))))
            }
            None => self.source.open(digest),
        }
    }
}

fn same_route(actual: &QualifiedOperationRouteV1, expected: &QualifiedOperationRouteV1) {
    assert_eq!(actual.identity(), expected.identity());
    assert_eq!(actual.stage_memory_bytes(), expected.stage_memory_bytes());
    assert_eq!(actual.terminal().binding(), expected.terminal().binding());
    assert_eq!(
        actual.terminal().key().to_bytes(),
        expected.terminal().key().to_bytes()
    );
    let actual_omega = actual.candidate_omega().unwrap();
    let expected_omega = expected.candidate_omega().unwrap();
    assert_eq!(actual_omega.binding(), expected_omega.binding());
    assert_eq!(
        actual_omega.key().to_bytes(),
        expected_omega.key().to_bytes()
    );
    let (QualifiedOperationOwnerV1::Receive(actual), QualifiedOperationOwnerV1::Receive(expected)) =
        (actual.owner(), expected.owner())
    else {
        panic!("genuine Receive owners only")
    };
    assert!(Arc::ptr_eq(actual, expected));
}

fn expected_reads(inventory: &ProducerInventoryV1, record: &OperationV1) -> Vec<BlobV1> {
    let omega = inventory.member(inventory.omega).unwrap();
    let mut blobs = vec![omega.descriptor, omega.verifying_key];
    for (stage, member) in record.a.iter().enumerate() {
        let original = inventory.member(*member).unwrap();
        blobs.extend([
            original.descriptor,
            original.verifying_key,
            original.proving_key,
        ]);
        if let Some(member) = record.w.get(stage) {
            let original = inventory.member(*member).unwrap();
            blobs.extend([
                original.descriptor,
                original.verifying_key,
                original.proving_key,
            ]);
        }
    }
    blobs
}

/// Exercise source reuse only after the public whole-wallet constructor succeeded.
/// No production cache can be seeded by this cfg(test)-private helper.
pub(crate) fn assert_receive_alias_controls(
    qualified: &QualifiedWalletSourcesV1,
    installed: &InstalledVerifierPackV1,
    source: &mut dyn OriginalSourceV1,
    config: ReadConfig,
) -> usize {
    assert_alias_controls(
        qualified,
        installed,
        source,
        config,
        super::super::super::builtin::Admission::Strict,
    )
}

pub(crate) fn assert_builtin_receive_alias_controls(
    qualified: &QualifiedWalletSourcesV1,
    installed: &InstalledVerifierPackV1,
    source: &mut dyn OriginalSourceV1,
    config: ReadConfig,
    profile: &iroha_plonk::keys::BuiltinSourceProfileV1,
) -> usize {
    let admission = super::super::super::builtin::Admission::Builtin(profile);
    let cases = assert_alias_controls(qualified, installed, source, config, admission);
    // The phone path: the built-in route stage on 1, 2, 4 and 8 workers over an
    // immutable copy of the same originals. Counted apart from the alias cases.
    let stages = assert_parallel_routes(
        qualified,
        installed,
        source,
        config,
        admission,
        &[1, 2, 4, 8],
    );
    assert_eq!(stages, 12);
    cases
}

fn assert_alias_controls(
    qualified: &QualifiedWalletSourcesV1,
    installed: &InstalledVerifierPackV1,
    source: &mut dyn OriginalSourceV1,
    config: ReadConfig,
    admission: super::super::super::builtin::Admission<'_>,
) -> usize {
    let inventory = qualified.inventory();
    let authenticated = installed
        .authenticate_producer_inventory(&inventory.to_canonical_bytes().unwrap())
        .unwrap();
    let compiled = compiled_routes();
    let q: Vec<_> = (0..inventory.operations.len())
        .map(|program| {
            let route = inventory
                .routes
                .iter()
                .position(|index| usize::try_from(*index).unwrap() == program)
                .unwrap();
            qualified.q(compiled[route]).unwrap().clone()
        })
        .collect();
    // One memo for every alias below: the first successful alias primes it, so
    // each later changed, missing or truncated original is refused at its read
    // while a memo hit for that content address exists.
    let descriptors = DescriptorMemo::default();
    let inputs = QualificationInputs {
        inventory: &authenticated,
        installed,
        qualified_q: &q,
        config,
        admission,
        descriptors: &descriptors,
    };
    // The complete public batch rejects foreign/missing/reordered Q metadata
    // before progress or original I/O, even after another batch qualified it.
    for invalid in [Vec::new(), q[..q.len() - 1].to_vec(), {
        let mut reordered = q.clone();
        reordered.swap(0, 1);
        reordered
    }] {
        let mut observed = Observed {
            source,
            fault: None,
            opens: Vec::new(),
        };
        let mut events = Vec::new();
        assert!(
            authenticated
                .qualify_operation_routes_with_admission(
                    installed,
                    &invalid,
                    &mut observed,
                    config,
                    |event| { events.push(event) },
                    admission,
                    &DescriptorMemo::default(),
                )
                .is_err()
        );
        assert!(observed.opens.is_empty());
        assert!(events.is_empty());
    }
    let mut wrong_installation = installed
        .authenticate_producer_inventory(&inventory.to_canonical_bytes().unwrap())
        .unwrap();
    wrong_installation.scheme_id[0] ^= 1;
    let mut observed = Observed {
        source,
        fault: None,
        opens: Vec::new(),
    };
    let mut events = Vec::new();
    assert!(matches!(
        wrong_installation.qualify_operation_routes_with_admission(
            installed,
            &q,
            &mut observed,
            config,
            |event| events.push(event),
            admission,
            &DescriptorMemo::default(),
        ),
        Err(OperationQualificationErrorV1::Original(Error::Authority))
    ));
    assert!(observed.opens.is_empty());
    assert!(events.is_empty());
    drop(observed);
    struct Unavailable {
        opens: usize,
    }
    impl OriginalSourceV1 for Unavailable {
        fn open(&mut self, _: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
            self.opens += 1;
            Err(Error::Unavailable)
        }
    }
    let mut unavailable = Unavailable { opens: 0 };
    let mut events = Vec::new();
    assert!(
        authenticated
            .qualify_operation_routes_with_admission(
                installed,
                &q,
                &mut unavailable,
                config,
                |event| events.push(event),
                admission,
                &DescriptorMemo::default(),
            )
            .is_err()
    );
    assert_eq!(unavailable.opens, 1);
    assert_eq!(
        events,
        [OperationQualificationProgressV1::Started { route_index: 0 }]
    );
    // No result or private cache escapes the failed batch, and no Completed
    // observation was emitted for the failing route.
    let mut programs: BTreeMap<u32, &QualifiedOperationRouteV1> = BTreeMap::new();
    let mut duplicate_count = 0;
    let mut pairs = Vec::new();
    for (index, route) in compiled.iter().copied().enumerate() {
        let owner = qualified.route(route).unwrap();
        assert_eq!(owner.identity().1, u32::try_from(index).unwrap());
        if !matches!(route.variant, Variant::Receive | Variant::ReceiveRenewed) {
            continue;
        }
        let program = owner.identity().2;
        if let Some(&first) = programs.get(&program) {
            let (QualifiedOperationOwnerV1::Receive(a), QualifiedOperationOwnerV1::Receive(b)) =
                (first.owner(), owner.owner())
            else {
                panic!("Receive route must retain its native owner")
            };
            assert!(
                Arc::ptr_eq(a, b),
                "public batch must share the exact strict native owner"
            );
            assert_ne!(first.identity().1, owner.identity().1);
            duplicate_count += 1;
            // One genuine program per variant is enough for all hit mutations.
            if !pairs
                .iter()
                .any(|(variant, _, _)| *variant == route.variant)
            {
                pairs.push((route.variant, first, owner));
            }
        } else {
            for &previous in programs.values() {
                let (QualifiedOperationOwnerV1::Receive(a), QualifiedOperationOwnerV1::Receive(b)) =
                    (previous.owner(), owner.owner())
                else {
                    panic!("Receive route must retain its native owner")
                };
                assert!(
                    !Arc::ptr_eq(a, b),
                    "different programs cannot share source authority"
                );
            }
            programs.insert(program, owner);
        }
    }
    assert_eq!(duplicate_count, 16);
    assert_eq!(pairs.len(), 2);
    let mut cases = 5;
    for (_, first, second) in pairs {
        let program = usize::try_from(first.identity().2).unwrap();
        let record = &inventory.operations[program];
        let mut admitted = AdmittedReceive::from_qualified_route(first, record).unwrap();
        let reads = expected_reads(inventory, record);
        if let super::super::super::builtin::Admission::Builtin(profile) = admission {
            let route = second.identity().1;
            assert!(profile.member(&[3, route, u32::MAX]).is_err());
            assert!(profile.member(&[4, route, u32::MAX]).is_err());
            assert_ne!(record.a[0], record.a[1]);
            assert_ne!(record.w[0], record.w[1]);
            let a_original = authenticated
                .read_original(record.a[0], source, config.maximum_bytes)
                .unwrap();
            let a_seal = admitted.a_seals[0].seal(record.a[0]).unwrap();
            let a_view = admitted.owner.bind_a(0, a_seal, None).unwrap();
            assert!(
                super::super::super::builtin::require_member_source(
                    profile.member(&[3, route, 1]).unwrap(),
                    &a_original,
                    installed.verifier().vesta_parameters(16).unwrap().as_ref(),
                    config,
                    a_view,
                    a_seal,
                )
                .is_err()
            );
            let w_original = authenticated
                .read_original(record.w[0], source, config.maximum_bytes)
                .unwrap();
            let w_seal = admitted.w_seals[0].seal(record.w[0]).unwrap();
            let w_view = admitted.owner.bind_w(0, w_seal, None).unwrap();
            assert!(
                super::super::super::builtin::require_member_source(
                    profile.member(&[4, route, 1]).unwrap(),
                    &w_original,
                    installed.verifier().pallas_parameters().as_ref(),
                    config,
                    w_view,
                    w_seal,
                )
                .is_err()
            );
            cases += 4;
        }
        for expected in [second, first] {
            let mut observed = Observed {
                source,
                fault: None,
                opens: Vec::new(),
            };
            let actual = admitted
                .qualify_alias(&inputs, expected.identity().1, &mut observed)
                .unwrap();
            same_route(&actual, expected);
            assert_eq!(
                observed.opens,
                reads.iter().map(|blob| blob.sha256).collect::<Vec<_>>()
            );
            cases += 1;
        }
        // An alias presented first in another local qualification order still
        // refers to the same previously admitted source, never an individual mask.
        let reversed = AdmittedReceive::from_qualified_route(second, record).unwrap();
        let mut observed = Observed {
            source,
            fault: None,
            opens: Vec::new(),
        };
        same_route(
            &reversed
                .qualify_alias(&inputs, first.identity().1, &mut observed)
                .unwrap(),
            first,
        );
        cases += 1;
        drop(observed);
        let foreign = inventory
            .routes
            .iter()
            .position(|index| *index != first.identity().2)
            .unwrap();
        let mut observed = Observed {
            source,
            fault: None,
            opens: Vec::new(),
        };
        assert!(matches!(
            admitted.qualify_alias(&inputs, u32::try_from(foreign).unwrap(), &mut observed),
            Err(OperationQualificationErrorV1::Original(Error::Authority))
        ));
        assert!(observed.opens.is_empty());
        cases += 1;
        drop(observed);
        // Private-state mutation tests confirm that the common hit path binds
        // the first source-checked context and the exact member of each seal.
        admitted.record.context[0][0] ^= 1;
        let mut observed = Observed {
            source,
            fault: None,
            opens: Vec::new(),
        };
        assert!(matches!(
            admitted.qualify_alias(&inputs, second.identity().1, &mut observed),
            Err(OperationQualificationErrorV1::Source)
        ));
        assert!(observed.opens.is_empty());
        admitted.record.context[0][0] ^= 1;
        cases += 1;
        drop(observed);
        admitted.a_seals.swap(0, 1);
        let mut observed = Observed {
            source,
            fault: None,
            opens: Vec::new(),
        };
        assert!(
            admitted
                .qualify_alias(&inputs, second.identity().1, &mut observed)
                .is_err()
        );
        assert!(observed.opens.is_empty());
        admitted.a_seals.swap(0, 1);
        cases += 1;
        drop(observed);
        admitted.w_seals.swap(0, 1);
        let mut observed = Observed {
            source,
            fault: None,
            opens: Vec::new(),
        };
        assert!(
            admitted
                .qualify_alias(&inputs, second.identity().1, &mut observed)
                .is_err()
        );
        assert!(observed.opens.is_empty());
        admitted.w_seals.swap(0, 1);
        cases += 1;
        drop(observed);
        for blob in &reads {
            // Every role, including repeated content addresses, remains mandatory.
            let mut observed = Observed {
                source,
                fault: Some((*blob, Fault::Changed)),
                opens: Vec::new(),
            };
            let result = admitted.qualify_alias(&inputs, second.identity().1, &mut observed);
            assert!(matches!(
                result,
                Err(OperationQualificationErrorV1::Original(Error::Inventory))
            ));
            assert!(observed.opens.contains(&blob.sha256));
            cases += 1;
        }
        // Both Omega metadata originals and a compact PK exercise length/outage/
        // cancellation controls without buffering the original or changing custody.
        let pk = inventory.member(record.a[0]).unwrap().proving_key;
        for blob in [reads[0], reads[1], pk] {
            for fault in [
                Fault::Missing,
                Fault::Truncated,
                Fault::Extended,
                Fault::Cancelled,
            ] {
                let mut observed = Observed {
                    source,
                    fault: Some((blob, fault)),
                    opens: Vec::new(),
                };
                let result = admitted.qualify_alias(&inputs, second.identity().1, &mut observed);
                match fault {
                    Fault::Missing => assert!(matches!(
                        result,
                        Err(OperationQualificationErrorV1::Original(Error::Unavailable))
                    )),
                    Fault::Cancelled => assert!(matches!(
                        result,
                        Err(OperationQualificationErrorV1::Original(Error::Cancelled))
                    )),
                    _ => assert!(matches!(
                        result,
                        Err(OperationQualificationErrorV1::Original(Error::Inventory))
                    )),
                }
                assert_eq!(observed.opens.last(), Some(&blob.sha256));
                cases += 1;
            }
        }
        let max_pk = record
            .a
            .iter()
            .chain(&record.w)
            .map(|member| inventory.member(*member).unwrap().proving_key.bytes)
            .max()
            .unwrap();
        let mut exact = config;
        exact.maximum_bytes = usize::try_from(max_pk).unwrap();
        let mut observed = Observed {
            source,
            fault: None,
            opens: Vec::new(),
        };
        same_route(
            &admitted
                .qualify_alias(
                    &QualificationInputs {
                        config: exact,
                        ..inputs
                    },
                    second.identity().1,
                    &mut observed,
                )
                .unwrap(),
            second,
        );
        cases += 1;
        let mut bytes_limited = exact;
        bytes_limited.maximum_bytes -= 1;
        let mut rows_limited = config;
        rows_limited.maximum_rows = (1 << 16) - 1;
        for limited in [bytes_limited, rows_limited] {
            let mut observed = Observed {
                source,
                fault: None,
                opens: Vec::new(),
            };
            assert!(
                admitted
                    .qualify_alias(
                        &QualificationInputs {
                            config: limited,
                            ..inputs
                        },
                        second.identity().1,
                        &mut observed
                    )
                    .is_err()
            );
            assert!(observed.opens.is_empty());
            cases += 1;
        }
    }
    // Only the exact Omega descriptor entered the aliases' memo: no refused
    // read, failed decode or cancellation added an entry.
    let omega = inventory.member(inventory.omega).unwrap().descriptor.sha256;
    assert!(
        descriptors
            .entries
            .lock()
            .unwrap()
            .iter()
            .map(|(address, _)| *address)
            .eq([omega])
    );
    cases
}

// Immutable in-memory originals that any number of workers read at once, like a
// captured snapshot. A static fault applies to every open of its address; once
// `cancel` is cancelled every open refuses as cancelled, like a cancelled reader.
// `order` records every open in the order it happened.
struct SharedMemory {
    blobs: BTreeMap<[u8; 32], Vec<u8>>,
    faults: BTreeMap<[u8; 32], Fault>,
    cancel: iroha_pasta::CancellationToken,
    opens: AtomicUsize,
    order: Mutex<Vec<[u8; 32]>>,
}

fn shared_memory(blobs: BTreeMap<[u8; 32], Vec<u8>>) -> SharedMemory {
    SharedMemory {
        blobs,
        faults: BTreeMap::new(),
        cancel: iroha_pasta::CancellationToken::new(),
        opens: AtomicUsize::new(0),
        order: Mutex::default(),
    }
}

impl SharedOriginalSourceV1 for SharedMemory {
    fn open_shared(&self, digest: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        self.order.lock().unwrap().push(digest);
        if self.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let bytes = self.blobs.get(&digest).ok_or(Error::Unavailable)?;
        let original: Box<dyn Read + '_> = Box::new(Cursor::new(bytes.as_slice()));
        Ok(match self.faults.get(&digest) {
            None => original,
            Some(Fault::Missing) => return Err(Error::Unavailable),
            Some(Fault::Cancelled) => return Err(Error::Cancelled),
            Some(Fault::Changed) => Box::new(ChangedReader {
                original,
                changed: false,
            }),
            Some(Fault::Truncated) => {
                Box::new(original.take(u64::try_from(bytes.len()).unwrap().saturating_sub(1)))
            }
            Some(Fault::Extended) => Box::new(original.chain(Cursor::new([0]))),
        })
    }
}

// One worker's handle on shared memory that offers its shared view, or withholds
// it like a live directory.
struct Handle<'a> {
    memory: &'a SharedMemory,
    shared: bool,
}

impl OriginalSourceV1 for Handle<'_> {
    fn open(&mut self, digest: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
        self.memory.open_shared(digest)
    }

    fn shared_view(&self) -> Option<&(dyn SharedOriginalSourceV1 + Sync)> {
        if self.shared { Some(self.memory) } else { None }
    }
}

fn wait_until(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !ready() {
        assert!(Instant::now() < deadline, "a concurrent route never ran");
        std::thread::yield_now();
    }
}

// Synthetic routes for the scheduler alone. Route i reads its own original through
// its worker's reader, so opening work is counted on the thread that does it; an
// alias checks that it got its lead's admitted value after that lead finished.
struct Synthetic {
    blobs: Vec<(BlobV1, Vec<u8>)>,
    leads: Vec<Option<usize>>,
    // Refused by their own checks, after their read.
    refused: Vec<usize>,
    // Refused before it starts.
    unstarted: Option<usize>,
    // With several workers, `(waiting, awaited)`: route `waiting` finishes only
    // after route `awaited` finished.
    hold: Option<(usize, usize)>,
    // With several workers, route 0 waits until a route ran on another thread.
    rendezvous: bool,
    // The route whose start cancels every later read.
    cancels: Option<usize>,
    started: Mutex<Vec<(usize, ThreadId)>>,
    finished: Mutex<Vec<usize>>,
    running: AtomicUsize,
    peak: AtomicUsize,
}

impl Synthetic {
    fn new(count: usize, groups: &[(usize, &[usize])]) -> Self {
        let mut leads = vec![None; count];
        for (lead, aliases) in groups {
            for alias in *aliases {
                leads[*alias] = Some(*lead);
            }
        }
        let blobs = (0..count)
            .map(|index| {
                let bytes = vec![u8::try_from(index % 251).unwrap(); 64 + 17 * index];
                (BlobV1::of(&bytes), bytes)
            })
            .collect();
        Self {
            blobs,
            leads,
            refused: Vec::new(),
            unstarted: None,
            hold: None,
            rendezvous: false,
            cancels: None,
            started: Mutex::default(),
            finished: Mutex::default(),
            running: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }

    fn memory(&self) -> SharedMemory {
        shared_memory(
            self.blobs
                .iter()
                .map(|(blob, bytes)| (blob.sha256, bytes.clone()))
                .collect(),
        )
    }

    fn routes(&self) -> Vec<Result<Option<usize>, OperationQualificationErrorV1>> {
        self.leads
            .iter()
            .enumerate()
            .map(|(index, lead)| {
                if self.unstarted == Some(index) {
                    Err(OperationQualificationErrorV1::Source)
                } else {
                    Ok(*lead)
                }
            })
            .collect()
    }

    fn route(
        &self,
        index: usize,
        lead: Option<&usize>,
        originals: &mut dyn OriginalSourceV1,
        memory: &SharedMemory,
        concurrent: bool,
    ) -> Result<(usize, Option<usize>), OperationQualificationErrorV1> {
        let running = self.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(running, Ordering::SeqCst);
        let thread = std::thread::current().id();
        self.started.lock().unwrap().push((index, thread));
        assert_eq!(lead.copied(), self.leads[index]);
        if let Some(lead) = self.leads[index] {
            assert!(self.finished.lock().unwrap().contains(&lead));
        }
        if self.cancels == Some(index) {
            memory.cancel.cancel();
        }
        if concurrent && self.rendezvous && index == 0 {
            wait_until(|| {
                self.started
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(_, other)| *other != thread)
            });
        }
        if let Some((_, awaited)) = self
            .hold
            .filter(|(waiting, _)| concurrent && *waiting == index)
        {
            wait_until(|| self.finished.lock().unwrap().contains(&awaited));
        }
        let (blob, bytes) = &self.blobs[index];
        let result = super::super::super::read(originals, *blob, bytes.len())
            .map_err(OperationQualificationErrorV1::from)
            .and_then(|_| {
                if self.refused.contains(&index) {
                    Err(OperationQualificationErrorV1::A(index))
                } else {
                    Ok((index, Some(index)))
                }
            });
        self.finished.lock().unwrap().push(index);
        self.running.fetch_sub(1, Ordering::SeqCst);
        result
    }
}

struct Outcome {
    result: Result<Vec<usize>, OperationQualificationErrorV1>,
    events: Vec<OperationQualificationProgressV1>,
    work: OpeningWorkV1,
    opens: usize,
    started: Vec<(usize, ThreadId)>,
    caller: ThreadId,
    peak: usize,
}

// One synthetic route stage on the calling thread; helpers go to the pool of that
// thread, or to the global pool from any other thread, as in production.
fn run_stage(
    synthetic: &Synthetic,
    memory: &SharedMemory,
    workers: usize,
    shared: bool,
) -> Outcome {
    synthetic.started.lock().unwrap().clear();
    synthetic.finished.lock().unwrap().clear();
    synthetic.peak.store(0, Ordering::SeqCst);
    let concurrent = shared && workers > 1;
    let caller = std::thread::current().id();
    let opens = memory.opens.load(Ordering::SeqCst);
    let before = OpeningWorkV1::current_thread();
    let mut events = Vec::new();
    let result = schedule(
        synthetic.routes(),
        workers,
        &mut Handle { memory, shared },
        &|index: usize, lead: Option<&usize>, originals: &mut dyn OriginalSourceV1| {
            synthetic.route(index, lead, originals, memory, concurrent)
        },
        &mut |event: OperationQualificationProgressV1| events.push(event),
    );
    Outcome {
        result,
        events,
        work: OpeningWorkV1::current_thread().since(before),
        opens: memory.opens.load(Ordering::SeqCst) - opens,
        started: synthetic.started.lock().unwrap().clone(),
        caller,
        peak: synthetic.peak.load(Ordering::SeqCst),
    }
}

// The same stage run from a thread of `pool`, like an opening that a pool worker
// runs: helpers go to that pool, and its waiting join may run them itself.
fn stage(
    pool: &rayon::ThreadPool,
    synthetic: &Synthetic,
    memory: &SharedMemory,
    workers: usize,
    shared: bool,
) -> Outcome {
    pool.install(|| run_stage(synthetic, memory, workers, shared))
}

// The progress of the one-worker order: every route below `completed` started and
// completed, then `started` started.
fn sequential_events(
    completed: usize,
    started: Option<usize>,
) -> Vec<OperationQualificationProgressV1> {
    let index = |route: usize| u32::try_from(route).unwrap();
    let mut events: Vec<_> = (0..completed)
        .flat_map(|route| {
            [
                OperationQualificationProgressV1::Started {
                    route_index: index(route),
                },
                OperationQualificationProgressV1::Completed {
                    route_index: index(route),
                },
            ]
        })
        .collect();
    if let Some(route) = started {
        events.push(OperationQualificationProgressV1::Started {
            route_index: index(route),
        });
    }
    events
}

fn test_pool() -> rayon::ThreadPool {
    rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .unwrap()
}

#[test]
fn route_workers_match_one_worker_in_results_progress_reads_and_opening_work() {
    let pool = test_pool();
    let mut synthetic = Synthetic::new(24, &[(3, &[7, 12, 20][..]), (5, &[9][..])]);
    synthetic.rendezvous = true;
    let memory = synthetic.memory();
    // The old order: one worker, no shared view, every route on the calling thread
    // in index order.
    let reference = stage(&pool, &synthetic, &memory, 1, false);
    assert_eq!(
        reference.result.as_ref().unwrap(),
        &(0..24).collect::<Vec<_>>()
    );
    assert_eq!(reference.events, sequential_events(24, None));
    assert!(reference.started.iter().map(|(route, _)| *route).eq(0..24));
    assert!(
        reference
            .started
            .iter()
            .all(|(_, thread)| *thread == reference.caller)
    );
    let bytes: usize = synthetic.blobs.iter().map(|(_, bytes)| bytes.len()).sum();
    assert_eq!(
        reference.work,
        OpeningWorkV1 {
            originals_opened: 24,
            raw_bytes_hashed: u64::try_from(bytes).unwrap(),
            ..OpeningWorkV1::default()
        }
    );
    assert_eq!(reference.opens, 24);
    let mut helped = false;
    for workers in [1, 2, 3, 4, 8, 24, 64] {
        for shared in [false, true] {
            let outcome = stage(&pool, &synthetic, &memory, workers, shared);
            assert_eq!(
                format!("{:?}", outcome.result),
                format!("{:?}", reference.result)
            );
            assert_eq!(outcome.events, reference.events);
            assert_eq!(
                outcome.work, reference.work,
                "workers {workers} shared {shared}"
            );
            assert_eq!(outcome.opens, reference.opens);
            let mut routes: Vec<_> = outcome.started.iter().map(|(route, _)| *route).collect();
            if workers == 1 || !shared {
                // One worker is the old order exactly, on the calling thread.
                assert!(routes.iter().copied().eq(0..24));
                assert!(
                    outcome
                        .started
                        .iter()
                        .all(|(_, thread)| *thread == outcome.caller)
                );
                assert_eq!(outcome.peak, 1);
            } else {
                assert!(outcome.peak <= workers.min(24));
                // Route 0 waited until another worker ran: helpers did real work,
                // and their opening work was still counted once, on this thread.
                assert!(
                    outcome
                        .started
                        .iter()
                        .any(|(_, thread)| *thread != outcome.caller)
                );
                helped = true;
            }
            routes.sort_unstable();
            assert!(routes.into_iter().eq(0..24));
        }
    }
    assert!(helped);
    // From a thread outside any pool, as the bridge opens: helpers run on the global
    // pool and never on this thread, and their work is still counted here once.
    let outcome = run_stage(&synthetic, &memory, 4, true);
    assert_eq!(
        format!("{:?}", outcome.result),
        format!("{:?}", reference.result)
    );
    assert_eq!(outcome.events, reference.events);
    assert_eq!(outcome.work, reference.work);
    assert_eq!(outcome.opens, reference.opens);
    assert!(
        outcome
            .started
            .iter()
            .any(|(_, thread)| *thread != outcome.caller)
    );
}

#[test]
fn the_lowest_refused_route_wins_even_when_a_later_refusal_finishes_first() {
    let pool = test_pool();
    let mut synthetic = Synthetic::new(16, &[(2, &[6, 13][..])]);
    synthetic.refused = vec![4, 11];
    // Several workers: route 4 is refused only after route 11 was refused.
    synthetic.hold = Some((4, 11));
    let memory = synthetic.memory();
    for workers in [1, 2, 4, 8] {
        for shared in [false, true] {
            let outcome = stage(&pool, &synthetic, &memory, workers, shared);
            assert!(matches!(
                outcome.result,
                Err(OperationQualificationErrorV1::A(4))
            ));
            assert_eq!(outcome.events, sequential_events(4, Some(4)));
            if shared && workers > 1 {
                assert!(outcome.started.iter().any(|(route, _)| *route == 11));
            } else {
                // One worker stops at the first refusal and never starts a later route.
                assert!(outcome.started.iter().map(|(route, _)| *route).eq(0..5));
            }
        }
    }
}

#[test]
fn a_route_refused_before_it_starts_never_starts_and_no_later_route_runs() {
    let pool = test_pool();
    let mut synthetic = Synthetic::new(12, &[(1, &[8][..])]);
    synthetic.unstarted = Some(6);
    let memory = synthetic.memory();
    for workers in [1, 3, 8] {
        for shared in [false, true] {
            let outcome = stage(&pool, &synthetic, &memory, workers, shared);
            assert!(matches!(
                outcome.result,
                Err(OperationQualificationErrorV1::Source)
            ));
            assert_eq!(outcome.events, sequential_events(6, None));
            let mut routes: Vec<_> = outcome.started.iter().map(|(route, _)| *route).collect();
            routes.sort_unstable();
            assert!(routes.into_iter().eq(0..6));
        }
    }
}

#[test]
fn an_alias_never_runs_when_its_lead_is_refused() {
    let pool = test_pool();
    let mut synthetic = Synthetic::new(10, &[(2, &[5, 8][..])]);
    synthetic.refused = vec![2];
    let memory = synthetic.memory();
    for workers in [1, 2, 8] {
        for shared in [false, true] {
            let outcome = stage(&pool, &synthetic, &memory, workers, shared);
            assert!(matches!(
                outcome.result,
                Err(OperationQualificationErrorV1::A(2))
            ));
            assert_eq!(outcome.events, sequential_events(2, Some(2)));
            assert!(
                outcome
                    .started
                    .iter()
                    .all(|(route, _)| *route != 5 && *route != 8)
            );
        }
    }
}

#[test]
fn cancellation_during_the_stage_is_never_success() {
    let pool = test_pool();
    for cancels in [0, 7, 19] {
        let mut synthetic = Synthetic::new(20, &[(4, &[10, 15][..])]);
        synthetic.cancels = Some(cancels);
        for workers in [1, 2, 4, 8] {
            for shared in [false, true] {
                // The cancelled reader is permanent, so every run gets a fresh one.
                let memory = synthetic.memory();
                let outcome = stage(&pool, &synthetic, &memory, workers, shared);
                let Err(error) = outcome.result else {
                    panic!("a cancelled stage returned success");
                };
                assert!(matches!(
                    error,
                    OperationQualificationErrorV1::Original(Error::Cancelled)
                ));
                assert!(WalletSourcesErrorV1::Operation(error).is_cancelled());
                if workers == 1 || !shared {
                    // One worker: the cancelling route's own read is the lowest refusal.
                    assert_eq!(outcome.events, sequential_events(cancels, Some(cancels)));
                }
            }
        }
    }
}

#[test]
fn route_workers_fit_the_largest_declared_reads_under_the_memory_budget() {
    let quarter = ROUTE_WORKERS_MEMORY_BUDGET_BYTES / 4;
    let half = ROUTE_WORKERS_MEMORY_BUDGET_BYTES / 2;
    // Never fewer than one, even with no route, no thread or one route over budget.
    assert_eq!(route_workers(Vec::new(), 8), 1);
    assert_eq!(route_workers(vec![1; 5], 0), 1);
    assert_eq!(route_workers(vec![u64::MAX, 1, 1], 8), 1);
    assert_eq!(
        route_workers(vec![1, ROUTE_WORKERS_MEMORY_BUDGET_BYTES + 1, 1], 8),
        1
    );
    // Any `n` routes in flight read at most what the `n` largest read.
    assert_eq!(route_workers(vec![quarter; 10], 8), 4);
    assert_eq!(route_workers(vec![1, quarter, 1, quarter, 1], 8), 5);
    assert_eq!(
        route_workers(vec![1, quarter, quarter, 1, quarter, quarter, 1], 8),
        4
    );
    assert_eq!(route_workers(vec![half, 1, half], 8), 2);
    assert_eq!(route_workers(vec![half, half], 8), 2);
    // At most one worker per route and per pool thread.
    assert_eq!(route_workers(vec![1; 3], 8), 3);
    assert_eq!(route_workers(vec![quarter; 10], 3), 3);
}

#[test]
fn declared_route_reads_count_every_original_a_route_can_read() {
    let original = |descriptor: u64, verifying_key: u64, proving_key: u64| OriginalV1 {
        descriptor: BlobV1 {
            bytes: descriptor,
            sha256: [1; 32],
        },
        verifying_key: BlobV1 {
            bytes: verifying_key,
            sha256: [2; 32],
        },
        proving_key: BlobV1 {
            bytes: proving_key,
            sha256: [3; 32],
        },
    };
    let mut inventory = ProducerInventoryV1 {
        version: 1,
        native_profile: [0; 32],
        originals: vec![
            original(10, 20, 30),
            original(1, 2, 3),
            original(4, 5, 6),
            original(7, 8, 9),
        ],
        sigma: [0; 16],
        operations: vec![OperationV1 {
            variant: 1,
            own_class: Vec::new(),
            incoming_class: Vec::new(),
            context: Vec::new(),
            q: Vec::new(),
            a: vec![1, 2],
            w: vec![3],
        }],
        routes: vec![0],
        terminals: vec![2],
        omega: 0,
    };
    // Omega (10 + 20) and terminal (4 + 5) metadata, then each A and W member's
    // metadata twice and its proving key: (2 * 3 + 3) + (2 * 9 + 6) + (2 * 15 + 9).
    assert_eq!(route_read_bytes(&inventory, 0), Some(30 + 9 + 9 + 24 + 39));
    assert_eq!(route_read_bytes(&inventory, 1), None);
    inventory.originals[3].proving_key.bytes = u64::MAX;
    assert_eq!(route_read_bytes(&inventory, 0), Some(u64::MAX));
    assert_eq!(route_workers(vec![u64::MAX, 1], 8), 1);
    inventory.operations[0].w = vec![9];
    assert_eq!(route_read_bytes(&inventory, 0), None);
    inventory.operations[0].a.clear();
    assert_eq!(route_read_bytes(&inventory, 0), None);
}

// The one-worker loop the route stage replaced, kept as its reference: the same
// checks, reads, Receive reuse and progress, in index order.
#[allow(clippy::too_many_arguments)]
fn sequential_reference(
    authenticated: &AuthenticatedProducerInventoryV1,
    installed: &InstalledVerifierPackV1,
    qualified_q: &[QualifiedQProgramV1],
    originals: &mut dyn OriginalSourceV1,
    config: ReadConfig,
    observer: &mut dyn FnMut(OperationQualificationProgressV1),
    admission: super::super::super::builtin::Admission<'_>,
    descriptors: &DescriptorMemo,
) -> Result<Vec<QualifiedOperationRouteV1>, OperationQualificationErrorV1> {
    let inputs = QualificationInputs {
        inventory: authenticated,
        installed,
        qualified_q,
        config,
        admission,
        descriptors,
    };
    let mut receive: Vec<Option<AdmittedReceive>> = (0..qualified_q.len()).map(|_| None).collect();
    let mut routes = Vec::with_capacity(authenticated.inventory.routes.len());
    for (index, program) in authenticated.inventory.routes.iter().copied().enumerate() {
        let route_index = u32::try_from(index).map_err(|_| Error::Inventory)?;
        let program = usize::try_from(program).map_err(|_| Error::Inventory)?;
        let q = qualified_q.get(program).ok_or(Error::Inventory)?;
        let route = *compiled_routes().get(index).ok_or(Error::Inventory)?;
        observer(OperationQualificationProgressV1::Started { route_index });
        let qualified = if matches!(route.variant, Variant::Receive | Variant::ReceiveRenewed) {
            if let Some(admitted) = &receive[program] {
                admitted.qualify_alias(&inputs, route_index, originals)?
            } else {
                let qualified = authenticated.qualify_operation_route_with_admission(
                    installed,
                    q,
                    route_index,
                    originals,
                    config,
                    admission,
                    descriptors,
                )?;
                receive[program] = Some(AdmittedReceive::from_qualified_route(
                    &qualified,
                    authenticated
                        .inventory
                        .operations
                        .get(program)
                        .ok_or(Error::Inventory)?,
                )?);
                qualified
            }
        } else {
            authenticated.qualify_operation_route_with_admission(
                installed,
                q,
                route_index,
                originals,
                config,
                admission,
                descriptors,
            )?
        };
        observer(OperationQualificationProgressV1::Completed { route_index });
        routes.push(qualified);
    }
    Ok(routes)
}

// Identical routes: identities, stage memory, terminal, candidate Omega and every
// A and W binding and verifying key; within one stage, Receive aliases share their
// lead's owner and different programs never share one.
fn same_routes(
    actual: &[&QualifiedOperationRouteV1],
    expected: &[&QualifiedOperationRouteV1],
    inventory: &ProducerInventoryV1,
) {
    assert_eq!(actual.len(), expected.len());
    for (actual, expected) in actual.iter().zip(expected) {
        assert_eq!(actual.identity(), expected.identity());
        assert_eq!(actual.stage_memory_bytes(), expected.stage_memory_bytes());
        assert_eq!(actual.terminal().binding(), expected.terminal().binding());
        assert_eq!(
            actual.terminal().key().to_bytes(),
            expected.terminal().key().to_bytes()
        );
        match (actual.candidate_omega(), expected.candidate_omega()) {
            (Some(actual), Some(expected)) => {
                assert_eq!(actual.binding(), expected.binding());
                assert_eq!(actual.key().to_bytes(), expected.key().to_bytes());
            }
            (None, None) => {}
            _ => panic!("candidate Omega presence differs"),
        }
        let record = &inventory.operations[usize::try_from(actual.identity().2).unwrap()];
        for (stage, member) in record.a.iter().copied().enumerate() {
            let left = actual.bind_a(stage, member, None).unwrap();
            let right = expected.bind_a(stage, member, None).unwrap();
            assert_eq!(left.binding(), right.binding());
            assert_eq!(
                left.verifying_key().to_bytes(),
                right.verifying_key().to_bytes()
            );
        }
        for (stage, member) in record.w.iter().copied().enumerate() {
            let left = actual.bind_w(stage, member, None).unwrap();
            let right = expected.bind_w(stage, member, None).unwrap();
            assert_eq!(left.binding(), right.binding());
            assert_eq!(
                left.verifying_key().to_bytes(),
                right.verifying_key().to_bytes()
            );
        }
    }
    let mut owners: BTreeMap<u32, &Arc<receive::Prover>> = BTreeMap::new();
    for &route in actual {
        if let QualifiedOperationOwnerV1::Receive(owner) = route.owner() {
            match owners.get(&route.identity().2) {
                Some(lead) => assert!(Arc::ptr_eq(lead, owner)),
                None => {
                    assert!(owners.values().all(|other| !Arc::ptr_eq(other, owner)));
                    owners.insert(route.identity().2, owner);
                }
            }
        }
    }
}

type StageResult = (
    Result<Vec<QualifiedOperationRouteV1>, OperationQualificationErrorV1>,
    Vec<OperationQualificationProgressV1>,
    OpeningWorkV1,
    Vec<[u8; 32]>,
);

// The route stage of a genuinely admitted graph, run again over an immutable
// in-memory copy of its originals. The old one-worker loop and the stage on each
// of `workers` give identical routes, progress, opening work and reads, and so does
// the production worker count; under each static fault (an Omega verifying key
// changed, the last route's terminal proving key changed or cancelled) the largest
// worker count gives the reference's exact error and progress, and a cancelled
// original is never success. Returns the stages run.
fn assert_parallel_routes(
    qualified: &QualifiedWalletSourcesV1,
    installed: &InstalledVerifierPackV1,
    source: &mut dyn OriginalSourceV1,
    config: ReadConfig,
    admission: super::super::super::builtin::Admission<'_>,
    workers: &[usize],
) -> usize {
    let inventory = qualified.inventory();
    let authenticated = installed
        .authenticate_producer_inventory(&inventory.to_canonical_bytes().unwrap())
        .unwrap();
    let compiled = compiled_routes();
    let q: Vec<_> = (0..inventory.operations.len())
        .map(|program| {
            let route = inventory
                .routes
                .iter()
                .position(|index| usize::try_from(*index).unwrap() == program)
                .unwrap();
            qualified.q(compiled[route]).unwrap().clone()
        })
        .collect();
    // Every original role a route reads, read once through the admitted source.
    let mut memory = shared_memory(BTreeMap::new());
    for record in &inventory.operations {
        for member in record.a.iter().chain(&record.w).chain([&inventory.omega]) {
            let original = inventory.member(*member).unwrap();
            for blob in [
                original.descriptor,
                original.verifying_key,
                original.proving_key,
            ] {
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    memory.blobs.entry(blob.sha256)
                {
                    entry.insert(
                        super::super::super::read(
                            source,
                            blob,
                            usize::try_from(blob.bytes).unwrap(),
                        )
                        .unwrap(),
                    );
                }
            }
        }
    }
    let run = |memory: &SharedMemory, workers: Option<usize>| -> StageResult {
        let mut events = Vec::new();
        let descriptors = DescriptorMemo::default();
        memory.order.lock().unwrap().clear();
        let before = OpeningWorkV1::current_thread();
        let result = match workers {
            // The old loop, on an exclusive handle.
            None => sequential_reference(
                &authenticated,
                installed,
                &q,
                &mut Handle {
                    memory,
                    shared: false,
                },
                config,
                &mut |event: OperationQualificationProgressV1| events.push(event),
                admission,
                &descriptors,
            ),
            // The production worker count.
            Some(0) => authenticated.qualify_operation_routes_with_admission(
                installed,
                &q,
                &mut Handle {
                    memory,
                    shared: true,
                },
                config,
                |event| events.push(event),
                admission,
                &descriptors,
            ),
            Some(workers) => authenticated.qualify_operation_routes_with_workers(
                installed,
                &q,
                &mut Handle {
                    memory,
                    shared: true,
                },
                config,
                |event| events.push(event),
                admission,
                &descriptors,
                workers,
            ),
        };
        let work = OpeningWorkV1::current_thread().since(before);
        let opens = std::mem::take(&mut *memory.order.lock().unwrap());
        (result, events, work, opens)
    };
    let (reference, reference_events, reference_work, reference_opens) = run(&memory, None);
    let reference = reference.unwrap();
    let reference: Vec<_> = reference.iter().collect();
    same_routes(&reference, &qualified_routes(qualified), inventory);
    for count in workers.iter().copied().chain([0]) {
        let (routes, events, work, mut opens) = run(&memory, Some(count));
        let routes = routes.unwrap();
        same_routes(&routes.iter().collect::<Vec<_>>(), &reference, inventory);
        assert_eq!(events, reference_events);
        assert_eq!(work, reference_work, "{count} workers");
        if count == 1 {
            // One worker reads every original in exactly the old loop's order.
            assert_eq!(opens, reference_opens);
        }
        // Any worker count opens the same originals the same number of times.
        let mut expected = reference_opens.clone();
        opens.sort_unstable();
        expected.sort_unstable();
        assert_eq!(opens, expected, "{count} workers");
    }
    let largest = workers.iter().copied().max().unwrap_or(1);
    let omega = inventory
        .member(inventory.omega)
        .unwrap()
        .verifying_key
        .sha256;
    let last = &inventory.operations[usize::try_from(*inventory.routes.last().unwrap()).unwrap()];
    let terminal = inventory
        .member(*last.a.last().unwrap())
        .unwrap()
        .proving_key
        .sha256;
    let faults = [
        (omega, Fault::Changed),
        (terminal, Fault::Changed),
        (terminal, Fault::Cancelled),
    ];
    for (address, fault) in faults {
        memory.faults = BTreeMap::from([(address, fault)]);
        let (expected, expected_events, _, _) = run(&memory, None);
        let (actual, actual_events, _, _) = run(&memory, Some(largest));
        let (Err(expected), Err(actual)) = (expected, actual) else {
            panic!("a faulted original qualified");
        };
        assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
        assert_eq!(actual_events, expected_events);
        if matches!(fault, Fault::Cancelled) {
            assert!(WalletSourcesErrorV1::Operation(actual).is_cancelled());
        }
    }
    // The reference, every worker count and the production count, then two per fault.
    1 + workers.len() + 1 + 2 * faults.len()
}

// The qualified graph's routes in compiled order.
fn qualified_routes(qualified: &QualifiedWalletSourcesV1) -> Vec<&QualifiedOperationRouteV1> {
    compiled_routes()
        .iter()
        .map(|route| qualified.route(*route).unwrap())
        .collect()
}

#[test]
#[ignore = "strict complete52 engineering acceptance from independently pinned persisted originals, then ten strict route stages over an in-memory copy; no key regeneration or deployment authority"]
fn strict_route_workers_match_the_old_order_on_the_pinned_catalog() {
    let output = std::path::PathBuf::from(
        std::env::var_os("KAGEMUSHA_PARALLEL_ROUTES_ACCEPTANCE_OUTPUT").unwrap(),
    );
    let (installed, qualified, _native, mut originals) =
        crate::kagemusha_wallet_artifacts_v1::producer_inventory::open_pinned_engineering_wallet_sources(&output);
    let config = ReadConfig {
        maximum_bytes: PROVING_KEY_MAX_BYTES_V1,
        maximum_rows: 1 << 16,
        coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
        msm_budget: iroha_pasta::msm::MemoryBudget::DEFAULT,
    };
    let stages = assert_parallel_routes(
        &qualified,
        &installed,
        &mut originals,
        config,
        super::super::super::builtin::Admission::Strict,
        &[1, 4],
    );
    assert_eq!(stages, 10);
}
