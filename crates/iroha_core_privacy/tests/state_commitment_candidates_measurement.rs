//! Native and in-circuit measurement of the State commitment candidates of ZK
//! delivery plan task G.2.
//!
//! The candidates are the development-only prototypes of
//! `fastpq_prover::state_commitment_prototypes`; this target only drives them
//! and records what they cost with the shared phase and resource recorder.
//! It selects nothing: task G.3 selects from the tracked summary
//! `specs/state_commitment_candidates.json`, which
//! `scripts/check_state_commitment_candidates.py` derives from the records of
//! harness runs.
//!
//! The target is opt-in (`fastpq-replay-measurement` enables the proof crate's
//! `dev-tools` surface). The default test is a small smoke run that checks
//! every record; the measurement runs are ignored tests, one process each, to
//! be run one at a time so that no measurement run competes with another:
//!
//! ```text
//! cargo test --release -p iroha_core_privacy --features fastpq-replay-measurement \
//!     --test state_commitment_candidates_measurement --no-run
//! python3 scripts/zk_resource_harness.py run --hardware <record> --profile <profile> \
//!     --config <config> --cache-policy warm --record-arguments -- <test-binary> \
//!     --ignored --exact native_blake2b --nocapture
//! ```
//!
//! What a record holds:
//!
//! - a **native** record: one construction under one hash profile over one
//!   declared State population. Every timed phase is repeated on identical
//!   inputs and recorded once per repetition (`r<k>.<phase>`): the cold build
//!   from the empty State, change sets of each size replayed on a clone of the
//!   built State, and witness production and verification for inclusion,
//!   absence, populated cells and complete ranges. Counters: the deterministic
//!   hash work of each phase, witness sizes, the accounting model of the
//!   authenticated structure, and the heap the prototype's containers really
//!   hold, counted by this executable's allocator on the building thread
//!   alone. Every record also names the schema its process read. The record of the
//!   linked-leaf map also counts what its range witnesses would carry if
//!   their address paths shared their common nodes.
//! - a **circuit** record: for a tree candidate under a sponge profile, the
//!   relation of `state_commitment_prototypes::circuit` on witnesses of the
//!   tree just measured. For every statement of the native sample: the
//!   permutations, registers and rows of its program beside the permutations
//!   of its native verification. For one statement of each kind: program
//!   derivation, trace generation, the uncommitted reference build and its
//!   check. **The reference is uncommitted, nonsuccinct and non-hiding**: its
//!   time and memory are not committed-proof figures, which do not exist for
//!   this relation until task B.2. A statement whose trace exceeds the
//!   reference's supported order is recorded with the rows it needs and is not
//!   built.
//! - a **gadget** record: the two key gadgets a private key needs beside the
//!   hash chain, built and checked as relations of their own.
//! - a **latency** record: nanoseconds per hash call of every profile.
//!
//! The populations are declared experimental assumptions: the State inventory
//! names the tables and codecs and states no population. Phase and workload
//! labels are public names built from the construction, the profile and the
//! population; no key, value or witness byte is recorded.

use std::{
    collections::BTreeMap,
    hint::black_box,
    path::{Path, PathBuf},
};

use fastpq_prover::{
    air::{
        MAX_REFERENCE_TRACE_ROWS, NoObserver, ReferenceChallenges, ReferencePlan, SemanticAir,
        WorkLimits, build_reference, check_reference,
    },
    state_commitment_prototypes::{
        Engine, KeyedMap, PrototypeSchema,
        btree::MerkleBTree,
        chain::SortedHashChain,
        circuit::{
            AirPermutation, ChainAir, Input, Program, Sibling, WitnessPrograms, absence_statement,
            as_built_blake2b_gadget, inclusion_statement, range_statement,
        },
        hash::{
            AlgebraicSponge, Blake2bProfile, ByteHash, ByteProfile, Digest384Comparator,
            HashProfile, HashWork, Permutation12, Poseidon2Profile, RescuePrimeProfile,
            take_hash_work,
        },
        key_gadgets::{GadgetUse, KeyBitAir, KeyOrderAir},
        keyed::{TableChange, descriptor_from_rows},
        linked::LinkedLeafMap,
        poseidon2::Poseidon2Goldilocks12,
        radix::RadixTree,
        rescue::RescuePrime64,
        workload::{
            BACKGROUND_ENTRIES, KeyShape, OwnedChange, SplitMix64, StateWorkload, borrow_changes,
            descriptor_from_inventory,
        },
    },
};
use iroha_measurement::{
    ByteKind, CollectingSink, DirectoryReport, DirectorySink, Finding, FlowKind,
    HARNESS_OUTPUT_DIR_ENV, MeasurementRecord, RecordSink, RunContext, RunIdentity, RunOutcome,
    Session, TeeSink, WorkerDeclaration, read_harness_context,
};
use sha2::{Digest as _, Sha256};

/// Heap accounting of this executable: every allocation goes to the system
/// allocator unchanged and is counted twice over.
///
/// - Two process-wide counters keep the live bytes and their peak. They see
///   every thread, which is what the peak of a reference build is: the build
///   works on the pool's threads.
/// - Two counters of the calling thread keep what that thread alone allocated
///   and freed inside [`of_this_thread`]. The heap a candidate map holds is
///   read this way: the build runs on one thread, and a worker of the pool
///   that starts late, or goes to sleep for the first time, allocates on its
///   own thread at a moment no measurement controls.
///
/// The counting costs two relaxed atomic updates and one thread-local read
/// per allocation, the same for every candidate.
#[allow(
    unsafe_code,
    reason = "a global allocator is an unsafe trait; this one only forwards and counts"
)]
mod heap {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        cell::Cell,
        sync::atomic::{AtomicUsize, Ordering},
    };

    static LIVE: AtomicUsize = AtomicUsize::new(0);
    static PEAK: AtomicUsize = AtomicUsize::new(0);

    /// The counters of one thread inside [`of_this_thread`].
    struct Scope {
        counting: Cell<bool>,
        live: Cell<i64>,
        peak: Cell<i64>,
    }

    thread_local! {
        // Constant initialisation and no destructor: reading it allocates
        // nothing, so the allocator may read it on every call.
        static SCOPE: Scope = const {
            Scope {
                counting: Cell::new(false),
                live: Cell::new(0),
                peak: Cell::new(0),
            }
        };
    }

    /// Count `allocated` and `freed` bytes for the calling thread's scope.
    fn scoped(allocated: usize, freed: usize) {
        let _ = SCOPE.try_with(|scope| {
            if scope.counting.get() {
                let bytes = |count: usize| i64::try_from(count).unwrap_or(i64::MAX);
                let live = scope.live.get() + bytes(allocated) - bytes(freed);
                scope.live.set(live);
                scope.peak.set(scope.peak.get().max(live));
            }
        });
    }

    fn grown(bytes: usize) {
        let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
        PEAK.fetch_max(live, Ordering::Relaxed);
        scoped(bytes, 0);
    }

    fn shrunk(bytes: usize) {
        LIVE.fetch_sub(bytes, Ordering::Relaxed);
        scoped(0, bytes);
    }

    /// The system allocator with a count of the bytes it holds.
    pub struct Counting;

    // SAFETY: every method forwards its arguments unchanged to the system
    // allocator and returns its result unchanged, so the allocator contract
    // the caller upholds is exactly the one `System` requires. The counters
    // are updated from the caller's layout sizes and touch no allocation.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller's contract for `alloc` is forwarded as is.
            let pointer = unsafe { System.alloc(layout) };
            if !pointer.is_null() {
                grown(layout.size());
            }
            pointer
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller's contract for `alloc_zeroed` is forwarded as is.
            let pointer = unsafe { System.alloc_zeroed(layout) };
            if !pointer.is_null() {
                grown(layout.size());
            }
            pointer
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            // SAFETY: the caller's contract for `dealloc` is forwarded as is.
            unsafe { System.dealloc(pointer, layout) };
            shrunk(layout.size());
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            // SAFETY: the caller's contract for `realloc` is forwarded as is.
            let moved = unsafe { System.realloc(pointer, layout, size) };
            if !moved.is_null() {
                shrunk(layout.size());
                grown(size);
            }
            moved
        }
    }

    /// Run `work` and count the allocations of the calling thread alone:
    /// the bytes that thread holds more afterwards than before, and the most
    /// it held more while `work` ran. Allocations and frees of every other
    /// thread are left out. Scopes do not nest.
    pub fn of_this_thread<T>(work: impl FnOnce() -> T) -> (T, u64, u64) {
        SCOPE.with(|scope| {
            assert!(!scope.counting.get(), "heap scopes do not nest");
            scope.live.set(0);
            scope.peak.set(0);
            scope.counting.set(true);
        });
        let value = work();
        let (live, peak) = SCOPE.with(|scope| {
            scope.counting.set(false);
            (scope.live.get(), scope.peak.get())
        });
        (
            value,
            u64::try_from(live).unwrap_or(0),
            u64::try_from(peak).unwrap_or(0),
        )
    }

    /// Bytes the process holds from the allocator now.
    pub fn live() -> u64 {
        LIVE.load(Ordering::Relaxed) as u64
    }

    /// Start a new peak at the bytes held now and return them.
    pub fn restart_peak() -> u64 {
        let live = LIVE.load(Ordering::Relaxed);
        PEAK.store(live, Ordering::Relaxed);
        live as u64
    }

    /// The most bytes held since the last [`restart_peak`].
    pub fn peak() -> u64 {
        PEAK.load(Ordering::Relaxed) as u64
    }
}

#[global_allocator]
static ALLOCATOR: heap::Counting = heap::Counting;

const EMITTER: &str = "rust.iroha_core_privacy.state_commitment_candidates";
/// Table of the inventory schema that holds the measured population.
const POPULATED_TABLE: &str = "world.accounts";
/// Root time outside every phase tolerated in a flow no harness bound: the
/// smoke run's flows last a few milliseconds, where the session's own start
/// and end are more than the recorder's one percent. A harness-bound run has
/// no allowance: the recorder's finding fails it.
const UNBOUND_FLOW_UNATTRIBUTED_NS: u64 = 2_000_000;
/// Domain tags of the latency microbenchmark; any distinct small words do.
const LATENCY_DOMAIN: u64 = 0x4732_0000_0000_00ff;
/// Largest trace whose reference build and check are repeated.
const REPEATED_REFERENCE_ROWS: usize = 4_096;
/// Repetitions of a reference build and check of such a trace.
const REFERENCE_REPEATS: usize = 3;

/// Raw BLAKE3-256, supplied here because this crate owns a `blake3` dependency
/// and the proof crate does not. The framing is `ByteProfile`'s.
struct Blake3Raw;

impl ByteHash for Blake3Raw {
    const NAME: &'static str = "blake3-256-raw";

    fn digest(parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        for part in parts {
            hasher.update(part);
        }
        *hasher.finalize().as_bytes()
    }
}

type Blake3Profile = ByteProfile<Blake3Raw>;

/// A public measurement name as the static label the recorder takes. The
/// names are built only from construction, profile and population tags.
fn label(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

/// The label of a timed phase in one repetition.
fn repeated(repetition: usize, phase: &str) -> &'static str {
    label(format!("r{repetition}.{phase}"))
}

/// Identity context and output directory handed over by the harness, if any.
/// This diagnostic-only variable selects where public records are written.
fn harness() -> (RunContext, Option<PathBuf>) {
    std::env::var_os(HARNESS_OUTPUT_DIR_ENV)
        .map(PathBuf::from)
        .map_or_else(
            || (RunContext::unbound(), None),
            |directory| {
                (
                    read_harness_context(&directory).expect("harness context"),
                    Some(directory),
                )
            },
        )
}

/// Where one measured flow delivers its record: to memory for this test's
/// checks, and to the harness directory when one was supplied.
struct Delivery {
    memory: CollectingSink,
    files: Option<DirectoryReport>,
    bound: bool,
}

impl Delivery {
    fn new(directory: Option<&Path>) -> (Box<dyn RecordSink>, Self) {
        let memory = CollectingSink::new();
        let collector: Box<dyn RecordSink> = Box::new(memory.clone());
        match directory {
            Some(directory) => {
                let files = DirectorySink::new(directory.to_path_buf(), "state-candidates");
                let report = files.report();
                (
                    Box::new(TeeSink::new(collector, Box::new(files))),
                    Self {
                        memory,
                        files: Some(report),
                        bound: true,
                    },
                )
            }
            None => (
                collector,
                Self {
                    memory,
                    files: None,
                    bound: false,
                },
            ),
        }
    }

    /// The one record of the session, required to be complete and valid:
    /// succeeded, written once and without any finding.
    ///
    /// Every phase of a flow is a child of its root, so the recorder's own
    /// one-percent rule is the rule: the root time outside every phase. In a
    /// harness-bound run it is applied as the recorder reports it. A run no
    /// harness bound has no identity to complete and, for its
    /// millisecond flows, an absolute allowance instead of the ratio.
    fn checked(&self) -> MeasurementRecord {
        let mut records = self.memory.take();
        assert_eq!(records.len(), 1);
        if let Some(files) = &self.files {
            assert!(files.errors().is_empty(), "{:?}", files.errors());
            assert!(files.partial().is_empty());
            assert_eq!(files.written().len(), 1);
        }
        let record = records.remove(0);
        assert_eq!(record.outcome, RunOutcome::Succeeded);
        let findings: Vec<Finding> = record
            .findings()
            .into_iter()
            .filter(|finding| match finding {
                Finding::IdentityIncomplete { .. } | Finding::DirtyDigestMismatch => self.bound,
                Finding::UnattributedExceedsLimit {
                    unattributed_wall_ns,
                    ..
                } => self.bound || *unattributed_wall_ns > UNBOUND_FLOW_UNATTRIBUTED_NS,
                _ => true,
            })
            .collect();
        assert_eq!(findings, [], "{}", record.identity.workload);
        // No phase has a child, so no time hides inside a parent.
        assert!(
            record
                .phase_tree
                .nodes
                .iter()
                .skip(1)
                .all(|node| node.parent == Some(0)),
            "{}: every phase is a child of the root",
            record.identity.workload
        );
        record
    }
}

/// One measured flow: its session and its delivery.
struct Flow {
    session: Session,
    delivery: Delivery,
}

impl Flow {
    /// Close the session and return the checked record.
    fn finish(self) -> MeasurementRecord {
        self.session.finish();
        self.delivery.checked()
    }
}

/// One process-wide measurement run: the harness hand-off and the schema.
struct Run {
    context: RunContext,
    directory: Option<PathBuf>,
    schema: PrototypeSchema,
    populated: u32,
    identity: SchemaIdentity,
}

/// What identifies the schema a run measured over, as every flow records it:
/// the keyed tables, the cells, the length of the canonical descriptor and
/// the first eight bytes of its SHA-256, big-endian.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SchemaIdentity {
    tables: u64,
    cells: u64,
    descriptor_bytes: u64,
    descriptor_sha256_prefix: u64,
}

impl SchemaIdentity {
    fn of(schema: &PrototypeSchema) -> Self {
        let cells = (0..schema.tables())
            .filter(|position| schema.is_cell(*position) == Some(true))
            .count() as u64;
        let digest = Sha256::digest(schema.descriptor());
        let prefix: [u8; 8] = digest[..8].try_into().expect("eight bytes of a digest");
        Self {
            tables: u64::from(schema.tables()) - cells,
            cells,
            descriptor_bytes: schema.descriptor().len() as u64,
            descriptor_sha256_prefix: u64::from_be_bytes(prefix),
        }
    }
}

impl Run {
    /// A run over the schema of the tracked State inventory.
    fn over_the_state_inventory() -> Self {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../specs/state_table_inventory.json");
        let inventory = std::fs::read_to_string(path).expect("read the State inventory");
        let descriptor = descriptor_from_inventory(&inventory).expect("an inventory");
        Self::over(PrototypeSchema::from_descriptor(&descriptor).expect("a canonical descriptor"))
    }

    fn over(schema: PrototypeSchema) -> Self {
        let (context, directory) = harness();
        let populated = schema
            .position(POPULATED_TABLE)
            .expect("the populated table");
        let identity = SchemaIdentity::of(&schema);
        Self {
            context,
            directory,
            schema,
            populated,
            identity,
        }
    }

    fn begin(&self, workload: String, flow: FlowKind, root: &'static str) -> Flow {
        let (sink, delivery) = Delivery::new(self.directory.as_deref());
        let session = Session::begin(
            RunIdentity::new(self.context.clone(), label(workload), flow, EMITTER),
            root,
            WorkerDeclaration {
                workers: u32::try_from(rayon::current_num_threads()).unwrap_or(u32::MAX),
                provenance: "rayon.current_num_threads",
            },
            sink,
        );
        // Every record says which schema its process read.
        let identifying = session.enter("schema");
        session.record_work("schema.tables", self.identity.tables);
        session.record_work("schema.cells", self.identity.cells);
        session.record_work("schema.descriptor_bytes", self.identity.descriptor_bytes);
        session.record_work(
            "schema.descriptor_sha256_prefix",
            self.identity.descriptor_sha256_prefix,
        );
        identifying.complete();
        Flow { session, delivery }
    }
}

/// One declared State population and what is measured over it.
#[derive(Clone, Copy, Debug)]
struct Case {
    /// Base-two logarithm of the entries of the populated table.
    population_log2: u32,
    key_shape: KeyShape,
    value_bytes: usize,
    /// Sizes of the change sets; a size above half the population is skipped.
    change_sets: &'static [usize],
    /// Least number of change sets applied per size.
    update_rounds: usize,
    /// Changes applied per size when that takes more sets: small sets are
    /// repeated so their phase is long enough to time.
    update_changes: usize,
    /// Claimed entries of the measured ranges.
    range_entries: &'static [usize],
    /// Inclusion and absence statements measured.
    point_statements: usize,
    /// Range statements measured per size.
    range_statements: usize,
    /// Repetitions of every timed phase on identical inputs.
    repeats: usize,
    /// Repetitions of the cold build among them. Fewer than `repeats` only
    /// where one build takes minutes; the tracked file marks such a build as
    /// not replicated.
    build_repeats: usize,
}

impl Case {
    const fn base(population_log2: u32) -> Self {
        Self {
            population_log2,
            key_shape: KeyShape::Scattered32,
            value_bytes: 32,
            change_sets: &[1, 100, 10_000],
            update_rounds: 2,
            update_changes: 128,
            range_entries: &[0, 1, 16, 1_024],
            point_statements: 128,
            range_statements: 8,
            repeats: 5,
            build_repeats: 5,
        }
    }

    /// The variants of the representative population: clustered keys, long
    /// keys and large values.
    fn variants(population_log2: u32) -> [Self; 3] {
        let base = Self::base(population_log2);
        [
            Self {
                key_shape: KeyShape::SharedPrefix32,
                ..base
            },
            Self {
                key_shape: KeyShape::Long128,
                ..base
            },
            Self {
                value_bytes: 256,
                ..base
            },
        ]
    }

    /// A linear construction is sampled less the larger the map is: every
    /// statement costs the whole map.
    fn for_linear(self) -> Self {
        Self {
            point_statements: ((1 << 16) >> self.population_log2).clamp(4, self.point_statements),
            range_statements: ((1 << 14) >> self.population_log2).clamp(2, self.range_statements),
            update_rounds: 1,
            update_changes: self.update_changes.min(4),
            ..self
        }
    }

    fn tag(&self) -> String {
        format!(
            "p{}.{}.v{}",
            self.population_log2,
            self.key_shape.name(),
            self.value_bytes
        )
    }
}

/// One range statement: its interval and its claimed keys.
struct RangeStatement {
    lower: Vec<u8>,
    upper: Option<Vec<u8>>,
    keys: Vec<Vec<u8>>,
}

/// A measured population: the map and the content of its populated table.
struct Population<E: Engine> {
    map: KeyedMap<E>,
    model: BTreeMap<Vec<u8>, Vec<u8>>,
    present: Vec<Vec<u8>>,
    absent: Vec<Vec<u8>>,
    ranges: Vec<(usize, Vec<RangeStatement>)>,
}

impl<E: Engine> Population<E> {
    fn entries<'a>(&'a self, statement: &'a RangeStatement) -> Vec<(&'a [u8], &'a [u8])> {
        statement
            .keys
            .iter()
            .map(|key| (key.as_slice(), self.model[key].as_slice()))
            .collect()
    }
}

/// A generated index below `bound`.
fn pick(generator: &mut SplitMix64, bound: usize) -> usize {
    usize::try_from(generator.below(bound as u64)).expect("below a usize bound")
}

/// `count` complete ranges of `claimed` entries over sorted committed keys,
/// each with a committed key on both sides. Empty when the table is too small.
fn range_statements(
    keys: &[&Vec<u8>],
    claimed: usize,
    count: usize,
    generator: &mut SplitMix64,
) -> Vec<RangeStatement> {
    if claimed + 2 > keys.len() {
        return Vec::new();
    }
    (0..count)
        .map(|_| {
            let first = 1 + pick(generator, keys.len() - claimed - 1);
            let lower = if claimed == 0 {
                // Between two adjacent keys: just above the lower one.
                let mut above = keys[first - 1].clone();
                above.push(0);
                above
            } else {
                keys[first].clone()
            };
            RangeStatement {
                lower,
                upper: Some(keys[first + claimed].clone()),
                keys: keys[first..first + claimed]
                    .iter()
                    .map(|key| (*key).clone())
                    .collect(),
            }
        })
        .collect()
}

fn record_hash_work(session: &Session, work: HashWork) {
    session.record_work("hash.byte_hashes", work.byte_hashes);
    session.record_work("hash.hashed_bytes", work.bytes);
    session.record_work("hash.compressions", work.compressions);
    session.record_work("hash.permutations", work.permutations);
}

/// Measure one construction natively over one population and return it.
fn measure_native<E: Engine>(
    run: &Run,
    construction: &str,
    profile: &str,
    case: &Case,
) -> (MeasurementRecord, Population<E>) {
    measure_native_with(run, construction, profile, case, |_, _| {})
}

/// Measure one construction natively over one population, then let `extra`
/// record construction-specific counts in further phases of the same flow.
fn measure_native_with<E: Engine>(
    run: &Run,
    construction: &str,
    profile: &str,
    case: &Case,
    extra: impl FnOnce(&Session, &Population<E>),
) -> (MeasurementRecord, Population<E>) {
    let population = 1_u64 << case.population_log2;
    let flow = run.begin(
        format!(
            "state_candidates.native.{construction}.{profile}.{}",
            case.tag()
        ),
        FlowKind::Native,
        "native_flow",
    );
    let session = &flow.session;
    let table = run.populated;
    let map_heap = session.allocation_counter("candidate_map_heap");

    // Everything that is not candidate work is one phase of its own.
    let generating = session.enter("generate_workload");
    let workload = StateWorkload::new(
        &run.schema,
        table,
        population,
        case.key_shape,
        case.value_bytes,
        0x4732_2026_1005,
    );
    let initial = workload.initial();
    let mut model: BTreeMap<Vec<u8>, Vec<u8>> = initial
        .iter()
        .filter(|(candidate, _, _)| *candidate == table)
        .map(|(_, key, value)| (key.clone(), value.clone().expect("an initial entry")))
        .collect();
    let mut cell_values: BTreeMap<u32, Vec<u8>> = initial
        .iter()
        .filter(|(candidate, _, _)| run.schema.is_cell(*candidate) == Some(true))
        .map(|(candidate, _, value)| (*candidate, value.clone().expect("an initial entry")))
        .collect();
    let sets: Vec<(usize, Vec<Vec<OwnedChange>>)> = case
        .change_sets
        .iter()
        .filter(|size| (**size as u64) <= population / 2)
        .enumerate()
        .map(|(ordinal, size)| {
            let rounds = (0..case.update_rounds.max(case.update_changes / size))
                .map(|round| workload.change_set((ordinal * 1_000 + round) as u64, *size))
                .collect();
            (*size, rounds)
        })
        .collect();
    // Borrowed forms are prepared here so a timed phase only applies them.
    let initial_changes = borrow_changes(&initial);
    let set_changes: Vec<(usize, Vec<Vec<TableChange<'_>>>)> = sets
        .iter()
        .map(|(size, rounds)| {
            (
                *size,
                rounds.iter().map(|round| borrow_changes(round)).collect(),
            )
        })
        .collect();
    generating.complete();

    // Each repetition builds the same State from nothing and replays the same
    // change sets on it, so repetitions differ only in when they ran.
    assert!(case.repeats >= 1 && (1..=case.repeats).contains(&case.build_repeats));
    let mut built: Option<(KeyedMap<E>, u64)> = None;
    let mut updated: Option<KeyedMap<E>> = None;
    let mut roots: Vec<([u8; 32], [u8; 32])> = Vec::new();
    for repetition in 0..case.repeats {
        let preparing = session.enter("prepare_state");
        drop(updated.take());
        if repetition < case.build_repeats
            && let Some((map, held)) = built.take()
        {
            drop(map);
            map_heap.freed(held);
        }
        // The empty State with its copy of the schema is not candidate work.
        let mut fresh =
            (repetition < case.build_repeats).then(|| KeyedMap::<E>::empty(run.schema.clone()));
        preparing.complete();
        if let Some(mut map) = fresh.take() {
            let building = session.enter(repeated(repetition, "cold_build"));
            // Nothing but the build runs inside the scope: what this thread
            // holds more after it is what the map holds.
            let _ = take_hash_work();
            let ((), held, peak) = heap::of_this_thread(|| {
                map.apply(&initial_changes).expect("the initial State");
            });
            let work = take_hash_work();
            record_hash_work(session, work);
            session.record_work("entries", map.entries());
            session.record_work("heap.live_bytes", held);
            session.record_work("heap.peak_bytes", peak);
            map_heap.allocated(held);
            built = Some((map, held));
            building.complete();
        }
        let preparing = session.enter("prepare_state");
        let (base, _) = built.as_ref().expect("the first repetition builds");
        let mut map = base.clone();
        let built_root = map.root();
        preparing.complete();
        for (size, rounds) in &set_changes {
            let updating = session.enter(repeated(repetition, &format!("update_set_{size}")));
            let _ = take_hash_work();
            for changes in rounds {
                map.apply(changes).expect("a valid change set");
            }
            record_hash_work(session, take_hash_work());
            session.record_work("change_sets", rounds.len() as u64);
            session.record_work("changes", (rounds.len() * size) as u64);
            updating.complete();
        }
        let preparing = session.enter("prepare_state");
        roots.push((built_root, map.root()));
        updated = Some(map);
        preparing.complete();
    }
    assert!(
        roots.windows(2).all(|pair| pair[0] == pair[1]),
        "every repetition reaches the same roots"
    );

    let sampling = session.enter("generate_workload");
    drop(set_changes);
    drop(initial_changes);
    drop(initial);
    if let Some((map, held)) = built.take() {
        drop(map);
        map_heap.freed(held);
    }
    let map = updated.expect("at least one repetition");
    for (_, rounds) in &sets {
        for (candidate, key, value) in rounds.iter().flatten() {
            if *candidate == table {
                match value {
                    Some(value) => model.insert(key.clone(), value.clone()),
                    None => model.remove(key),
                };
            } else if let (Some(slot), Some(value)) = (cell_values.get_mut(candidate), value) {
                // A change set rewrites a cell; it never removes one.
                slot.clone_from(value);
            }
        }
    }
    drop(sets);
    let keys: Vec<&Vec<u8>> = model.keys().collect();
    let mut generator = SplitMix64::new(0x5a17 ^ u64::from(case.population_log2));
    let present: Vec<Vec<u8>> = (0..case.point_statements)
        .map(|_| keys[pick(&mut generator, keys.len())].clone())
        .collect();
    let absent: Vec<Vec<u8>> = (0..case.point_statements as u64)
        .map(|index| workload.key(table, (1 << 48) + index))
        .collect();
    let ranges: Vec<(usize, Vec<RangeStatement>)> = case
        .range_entries
        .iter()
        .map(|&claimed| {
            (
                claimed,
                range_statements(&keys, claimed, case.range_statements, &mut generator),
            )
        })
        .filter(|(_, statements)| !statements.is_empty())
        .collect();
    let cells: Vec<(u32, Vec<u8>)> = cell_values.into_iter().take(16).collect();
    drop(keys);
    let population = Population {
        map,
        model,
        present,
        absent,
        ranges,
    };
    sampling.complete();
    let map = &population.map;
    let root = map.root();

    // The accounting model of the structure after the change sets.
    let sizing = session.enter("storage");
    let storage = map.storage();
    session.record_work("entries", storage.entries);
    session.record_work("structure_digests", storage.digests);
    session.record_work("structure_bytes", storage.structure_bytes);
    session.record_work("auxiliary_bytes", storage.auxiliary_bytes);
    session.record_work("max_depth", u64::from(storage.max_depth));
    sizing.complete();

    for repetition in 0..case.repeats {
        let timed = |phase: &str| session.enter(repeated(repetition, phase));
        // Witnesses are kept until the repetition's timed phases are over.
        let mut produced: Vec<Vec<Vec<u8>>> = Vec::new();

        // Inclusion.
        let proving = timed("prove_inclusion");
        let included: Vec<Vec<u8>> = population
            .present
            .iter()
            .map(|key| map.prove_inclusion(table, key).unwrap().expect("committed"))
            .collect();
        for witness in &included {
            session.record_bytes(ByteKind::Proof, "witness", witness.len() as u64);
        }
        session.record_work("statements", included.len() as u64);
        proving.complete();
        let verifying = timed("verify_inclusion");
        let _ = take_hash_work();
        for (key, witness) in population.present.iter().zip(&included) {
            let value = &population.model[key];
            KeyedMap::<E>::verify_inclusion(&run.schema, &root, table, key, value, witness)
                .expect("an honest inclusion witness");
        }
        record_hash_work(session, take_hash_work());
        session.record_work("statements", included.len() as u64);
        verifying.complete();
        produced.push(included);

        // Absence.
        let proving = timed("prove_absence");
        let absences: Vec<Vec<u8>> = population
            .absent
            .iter()
            .map(|key| {
                map.prove_absence(table, key)
                    .unwrap()
                    .expect("never committed")
            })
            .collect();
        for witness in &absences {
            session.record_bytes(ByteKind::Proof, "witness", witness.len() as u64);
        }
        session.record_work("statements", absences.len() as u64);
        proving.complete();
        let verifying = timed("verify_absence");
        let _ = take_hash_work();
        for (key, witness) in population.absent.iter().zip(&absences) {
            KeyedMap::<E>::verify_absence(&run.schema, &root, table, key, witness)
                .expect("an honest absence witness");
        }
        record_hash_work(session, take_hash_work());
        session.record_work("statements", absences.len() as u64);
        verifying.complete();
        produced.push(absences);

        // Populated cells: the single entry of each at the empty key.
        let proving = timed("prove_cell_inclusion");
        let cell_witnesses: Vec<Vec<u8>> = cells
            .iter()
            .map(|(cell, _)| {
                map.prove_inclusion(*cell, b"")
                    .unwrap()
                    .expect("a populated cell")
            })
            .collect();
        for witness in &cell_witnesses {
            session.record_bytes(ByteKind::Proof, "witness", witness.len() as u64);
        }
        session.record_work("statements", cells.len() as u64);
        proving.complete();
        let verifying = timed("verify_cell_inclusion");
        let _ = take_hash_work();
        for ((cell, value), witness) in cells.iter().zip(&cell_witnesses) {
            KeyedMap::<E>::verify_inclusion(&run.schema, &root, *cell, b"", value, witness)
                .expect("a populated cell verifies with its current value");
        }
        record_hash_work(session, take_hash_work());
        session.record_work("statements", cells.len() as u64);
        verifying.complete();
        produced.push(cell_witnesses);

        // Complete ranges.
        let mut range_witnesses: Vec<Vec<Vec<u8>>> = Vec::new();
        for (claimed, statements) in &population.ranges {
            let proving = timed(&format!("prove_range_{claimed}"));
            let witnesses: Vec<Vec<u8>> = statements
                .iter()
                .map(|statement| {
                    map.prove_range(table, &statement.lower, statement.upper.as_deref())
                        .expect("a well-formed range")
                })
                .collect();
            for witness in &witnesses {
                session.record_bytes(ByteKind::Proof, "witness", witness.len() as u64);
            }
            session.record_work("statements", statements.len() as u64);
            session.record_work("claimed_entries", (statements.len() * claimed) as u64);
            proving.complete();
            let verifying = timed(&format!("verify_range_{claimed}"));
            let _ = take_hash_work();
            for (statement, witness) in statements.iter().zip(&witnesses) {
                let entries = population.entries(statement);
                KeyedMap::<E>::verify_range(
                    &run.schema,
                    &root,
                    table,
                    &statement.lower,
                    statement.upper.as_deref(),
                    &entries,
                    witness,
                )
                .expect("an honest range witness");
            }
            record_hash_work(session, take_hash_work());
            session.record_work("statements", statements.len() as u64);
            verifying.complete();
            range_witnesses.push(witnesses);
        }
        // An omitted entry is rejected; checked outside the timed phases, in
        // the one phase that also releases the repetition's witnesses.
        let checking = session.enter("prepare_state");
        for ((_, statements), witnesses) in population.ranges.iter().zip(&range_witnesses) {
            if let (Some(statement), Some(witness)) = (statements.first(), witnesses.first()) {
                let entries = population.entries(statement);
                if let Some((_, shorter)) = entries.split_first() {
                    assert!(
                        KeyedMap::<E>::verify_range(
                            &run.schema,
                            &root,
                            table,
                            &statement.lower,
                            statement.upper.as_deref(),
                            shorter,
                            witness,
                        )
                        .is_err()
                    );
                }
            }
        }
        drop(range_witnesses);
        drop(produced);
        checking.complete();
    }
    extra(session, &population);
    (flow.finish(), population)
}

/// What the address paths of a linked-leaf range would hash and carry if they
/// shared their common nodes. A projection of a witness form the prototype
/// does not implement, counted from the witnesses it does produce, in phases
/// of the linked-leaf map's native flow.
fn record_shared_paths<H: HashProfile>(
    session: &Session,
    table: u32,
    population: &Population<LinkedLeafMap<H>>,
) {
    let prefix = table.to_be_bytes();
    let composite = |key: &[u8]| [&prefix[..], key].concat();
    for (claimed, statements) in &population.ranges {
        let counting = session.enter(label(format!("shared_paths_range_{claimed}")));
        for statement in statements {
            let witness = population
                .map
                .prove_range(table, &statement.lower, statement.upper.as_deref())
                .expect("a well-formed range");
            let keys: Vec<Vec<u8>> = statement.keys.iter().map(|key| composite(key)).collect();
            let entries: Vec<(&[u8], &[u8])> = keys
                .iter()
                .zip(&statement.keys)
                .map(|(key, plain)| (key.as_slice(), population.model[plain].as_slice()))
                .collect();
            let upper = statement.upper.as_deref().map(composite);
            let shared = LinkedLeafMap::<H>::shared_paths(
                &composite(&statement.lower),
                upper.as_deref(),
                &entries,
                &witness,
            )
            .expect("an honest range witness");
            session.record_work("leaves", shared.leaves);
            session.record_work("carried_steps", shared.carried_steps);
            session.record_work("distinct_branches", shared.distinct_branches);
            session.record_work("carried_siblings", shared.carried_siblings);
            session.record_bytes(ByteKind::Proof, "witness", witness.len() as u64);
        }
        let _ = take_hash_work();
        counting.complete();
    }
}

/// Measure the linked-leaf map natively, with the shared-path counts of its
/// range witnesses.
fn measure_linked<H: HashProfile>(
    run: &Run,
    profile: &str,
    case: &Case,
) -> (MeasurementRecord, Population<LinkedLeafMap<H>>) {
    measure_native_with(run, "linked", profile, case, |session, population| {
        record_shared_paths(session, run.populated, population);
    })
}

/// Statements of the relation measured for each tree candidate, with the
/// number of claimed entries of a range.
const CIRCUIT_RANGES: [usize; 5] = [0, 1, 16, 64, 1_024];

/// Build and check the reference of one program inside its own phases.
fn measure_program<P: AirPermutation + Sync>(session: &Session, kind: &str, program: &Program) {
    let rows = ChainAir::<P>::rows_for(program);
    let deriving = session.enter(label(format!("{kind}.geometry")));
    session.record_work("permutations", program.permutations() as u64);
    session.record_work("registers", program.registers() as u64);
    session.record_work("rows", rows as u64);
    session.record_work(
        "width",
        ChainAir::<P>::width_with(program.registers()) as u64,
    );
    session.record_work(
        "constraints",
        ChainAir::<P>::constraints_with(program.registers()) as u64,
    );
    session.record_work("rows_per_permutation", P::ROWS as u64);
    session.record_work("private_siblings", program.private_siblings() as u64);
    if rows > MAX_REFERENCE_TRACE_ROWS {
        // The shape is recorded; the uncommitted reference cannot hold it.
        session.record_work("exceeds_reference_rows", 1);
        deriving.complete();
        return;
    }
    session.record_work("exceeds_reference_rows", 0);
    let air = ChainAir::<P>::new(&program.public_view());
    let schema = air.schema();
    let limits = air.reference_limits();
    let plan = ReferencePlan::new(&air, limits).expect("the relation is within its own limits");
    session.record_work(
        "numerator_degree_bound",
        schema.numerator_degree_bound as u64,
    );
    session.record_work("trace_cells", schema.trace_cells() as u64);
    session.record_work("interpolation_rows", plan.interpolation_rows as u64);
    session.record_work("quotient_coefficients", plan.quotient_coefficients as u64);
    session.record_work(
        "reference_declared_payload_bytes",
        plan.payload_bytes as u64,
    );
    session.record_work("reference_declared_work_units", plan.work_units as u64);
    let repeats = if rows <= REPEATED_REFERENCE_ROWS {
        REFERENCE_REPEATS
    } else {
        1
    };
    session.record_work("reference_repeats", repeats as u64);
    deriving.complete();

    let challenges = ReferenceChallenges::derive(&[0x47; 32], schema.constraints);
    for repetition in 0..repeats {
        let tracing = session.enter(repeated(repetition, &format!("{kind}.witness_columns")));
        let columns = air.witness_columns(program);
        tracing.complete();
        let building = session.enter(repeated(repetition, &format!("{kind}.reference_build")));
        let before = heap::restart_peak();
        let artifact = build_reference(&air, columns, &challenges, limits, &NoObserver)
            .expect("an honest witness satisfies the relation");
        session.record_work("heap.peak_bytes", heap::peak() - before);
        // The uncommitted artifact is the whole trace and the quotient in the clear.
        session.record_bytes(
            ByteKind::Proof,
            "uncommitted_reference_artifact",
            (schema.trace_cells() * 8 + artifact.quotient().len() * 32) as u64,
        );
        building.complete();
        let checking = session.enter(repeated(repetition, &format!("{kind}.reference_check")));
        let before = heap::restart_peak();
        check_reference(&air, &artifact, &challenges, limits, &NoObserver)
            .expect("the checker accepts the honest artifact");
        session.record_work("heap.peak_bytes", heap::peak() - before);
        checking.complete();
        let releasing = session.enter("prepare_state");
        drop(artifact);
        releasing.complete();
    }
}

/// A trace that follows a program whose first statement-fixed side is
/// flipped must not satisfy the relation of the stated program.
fn forged_side_is_rejected<P: AirPermutation + Sync>(program: &Program) -> bool {
    if ChainAir::<P>::rows_for(program) > REPEATED_REFERENCE_ROWS {
        return false;
    }
    let mut forged = program.clone();
    let Some(side) = forged
        .blocks
        .iter_mut()
        .find_map(|block| match &mut block.input {
            Input::Compress {
                previous_right,
                side_public: true,
                ..
            } => Some(previous_right),
            _ => None,
        })
    else {
        return false;
    };
    *side = !*side;
    let air = ChainAir::<P>::new(&program.public_view());
    let challenges = ReferenceChallenges::derive(&[0x47; 32], air.schema().constraints);
    let refused = build_reference(
        &air,
        air.witness_columns(&forged),
        &challenges,
        air.reference_limits(),
        &NoObserver,
    );
    assert!(
        refused.is_err(),
        "a flipped statement-fixed side must not satisfy the relation"
    );
    true
}

/// Record one statement's program beside its native verification.
fn record_statement<P: AirPermutation>(
    session: &Session,
    witness_bytes: usize,
    native: &HashWork,
    program: &Program,
) {
    session.record_bytes(ByteKind::Proof, "native_witness", witness_bytes as u64);
    session.record_work("native_permutations", native.permutations);
    session.record_work("permutations", program.permutations() as u64);
    session.record_work("registers", program.registers() as u64);
    session.record_work("rows", ChainAir::<P>::rows_for(program) as u64);
    session.record_work("private_siblings", program.private_siblings() as u64);
    session.record_work(
        "anchors",
        program.blocks.iter().filter(|block| block.anchor).count() as u64,
    );
}

fn record_gadget_use(session: &Session, gadgets: GadgetUse) {
    session.record_work("gadget_bit_scans", gadgets.bit_scans as u64);
    session.record_work("gadget_comparisons", gadgets.comparisons as u64);
}

/// Measure the relation on witnesses of one measured tree.
fn measure_circuit<E, P>(
    run: &Run,
    construction: &str,
    profile: &str,
    case: &Case,
    population: &Population<E>,
) -> MeasurementRecord
where
    E: WitnessPrograms<Hash = AlgebraicSponge<P>>,
    P: AirPermutation + Sync,
{
    let flow = run.begin(
        format!(
            "state_candidates.circuit.{construction}.{profile}.{}",
            case.tag()
        ),
        FlowKind::Proof,
        "circuit_flow",
    );
    let session = &flow.session;
    let table = run.populated;
    let map = &population.map;
    let root = map.root();
    let mut first: Vec<(String, Program)> = Vec::new();

    // Every statement of the native sample: its program beside the hashes of
    // its native verification.
    let deriving = session.enter("inclusion.statements");
    for (index, key) in population.present.iter().enumerate() {
        let value = &population.model[key];
        let witness = map.prove_inclusion(table, key).unwrap().expect("committed");
        let _ = take_hash_work();
        KeyedMap::<E>::verify_inclusion(&run.schema, &root, table, key, value, &witness)
            .expect("an honest inclusion witness");
        let native = take_hash_work();
        let program = inclusion_statement::<E>(&run.schema, &root, table, key, value, &witness)
            .expect("an honest inclusion witness");
        record_statement::<P>(session, witness.len(), &native, &program);
        if index == 0 {
            first.push(("inclusion".to_owned(), program));
        }
    }
    record_gadget_use(session, GadgetUse::default());
    deriving.complete();

    let deriving = session.enter("absence.statements");
    for (index, key) in population.absent.iter().enumerate() {
        let witness = map
            .prove_absence(table, key)
            .unwrap()
            .expect("never committed");
        let _ = take_hash_work();
        KeyedMap::<E>::verify_absence(&run.schema, &root, table, key, &witness)
            .expect("an honest absence witness");
        let native = take_hash_work();
        let program = absence_statement::<E>(&run.schema, &root, table, key, &witness)
            .expect("an honest absence witness");
        record_statement::<P>(session, witness.len(), &native, &program);
        if index == 0 {
            first.push(("absence".to_owned(), program));
        }
    }
    record_gadget_use(session, E::ABSENCE_GADGETS);
    deriving.complete();

    let sampling = session.enter("prepare_state");
    let keys: Vec<&Vec<u8>> = population.model.keys().collect();
    let mut generator = SplitMix64::new(0xc12c ^ u64::from(case.population_log2));
    let ranges: Vec<(usize, Vec<RangeStatement>)> = CIRCUIT_RANGES
        .iter()
        .map(|&claimed| {
            (
                claimed,
                range_statements(&keys, claimed, case.range_statements, &mut generator),
            )
        })
        .filter(|(_, statements)| !statements.is_empty())
        .collect();
    sampling.complete();
    for (claimed, statements) in &ranges {
        let deriving = session.enter(label(format!("range_{claimed}.statements")));
        for (index, statement) in statements.iter().enumerate() {
            let entries = population.entries(statement);
            let upper = statement.upper.as_deref();
            let witness = map.prove_range(table, &statement.lower, upper).unwrap();
            let _ = take_hash_work();
            KeyedMap::<E>::verify_range(
                &run.schema,
                &root,
                table,
                &statement.lower,
                upper,
                &entries,
                &witness,
            )
            .expect("an honest range witness");
            let native = take_hash_work();
            let program = range_statement::<E>(
                &run.schema,
                &root,
                table,
                &statement.lower,
                upper,
                &entries,
                &witness,
            )
            .expect("an honest range witness");
            record_statement::<P>(session, witness.len(), &native, &program);
            if index == 0 {
                first.push((format!("range_{claimed}"), program));
            }
        }
        record_gadget_use(session, E::RANGE_GADGETS);
        deriving.complete();
    }

    for (kind, program) in &first {
        measure_program::<P>(session, kind, program);
    }

    // Forged traces are rejected by the relation, at every population: a
    // changed private sibling of the inclusion and a flipped statement-fixed
    // side of the inclusion, the absence and the first nonempty range.
    let rejecting = session.enter("forged_traces_rejected");
    let mut rejected = 0_u64;
    let (_, inclusion) = &first[0];
    let mut forged = inclusion.clone();
    let sibling = forged
        .blocks
        .iter_mut()
        .find_map(|block| match &mut block.input {
            Input::Compress {
                sibling: Sibling::Private(digest),
                ..
            } => Some(digest),
            _ => None,
        });
    if let Some(sibling) = sibling {
        sibling[1] ^= 1;
        let air = ChainAir::<P>::new(&forged.public_view());
        let challenges = ReferenceChallenges::derive(&[0x47; 32], air.schema().constraints);
        let refused = build_reference(
            &air,
            air.witness_columns(&forged),
            &challenges,
            air.reference_limits(),
            &NoObserver,
        );
        assert!(
            refused.is_err(),
            "a forged sibling must not satisfy the relation"
        );
        rejected += 1;
    }
    for kind in ["inclusion", "absence", "range_1"] {
        if let Some((_, program)) = first.iter().find(|(name, _)| name == kind) {
            rejected += u64::from(forged_side_is_rejected::<P>(program));
        }
    }
    session.record_work("forged_traces_rejected", rejected);
    rejecting.complete();
    flow.finish()
}

/// Constructions measured natively under one hash profile.
fn native_matrix<H: HashProfile>(run: &Run, profile: &str, cases: &[Case], linear_max_log2: u32) {
    for case in cases {
        let _ = measure_native::<RadixTree<H>>(run, "radix", profile, case);
        let _ = measure_native::<MerkleBTree<H>>(run, "btree", profile, case);
        let _ = measure_linked::<H>(run, profile, case);
        if case.population_log2 <= linear_max_log2 {
            let _ = measure_native::<SortedHashChain<H>>(run, "chain", profile, &case.for_linear());
        }
    }
}

/// Constructions measured natively and in-circuit under one sponge profile.
fn algebraic_matrix<P: AirPermutation + Sync>(
    run: &Run,
    profile: &str,
    cases: &[Case],
    circuit_cases: &[Case],
    linear_max_log2: u32,
) {
    type H<P> = AlgebraicSponge<P>;
    for case in cases {
        let circuit = circuit_cases
            .iter()
            .any(|candidate| candidate.tag() == case.tag());
        let (_, population) = measure_native::<RadixTree<H<P>>>(run, "radix", profile, case);
        if circuit {
            measure_circuit(run, "radix", profile, case, &population);
        }
        drop(population);
        let (_, population) = measure_native::<MerkleBTree<H<P>>>(run, "btree", profile, case);
        if circuit {
            measure_circuit(run, "btree", profile, case, &population);
        }
        drop(population);
        let (_, population) = measure_linked::<H<P>>(run, profile, case);
        if circuit {
            measure_circuit(run, "linked", profile, case, &population);
        }
        drop(population);
        if case.population_log2 <= linear_max_log2 {
            let _ =
                measure_native::<SortedHashChain<H<P>>>(run, "chain", profile, &case.for_linear());
        }
    }
}

/// The representative and maximum measured populations with the variants.
/// The small population takes more statements and change sets, so that its
/// phases are long enough to time and the flow is long beside its boundaries.
fn full_cases() -> Vec<Case> {
    let small = Case {
        update_changes: 512,
        point_statements: 512,
        range_statements: 32,
        ..Case::base(10)
    };
    let mut cases = vec![small, Case::base(16)];
    cases.extend(Case::variants(16));
    cases.push(Case::base(20));
    cases
}

/// The populations whose witnesses are measured in-circuit: the three base
/// populations and, at the representative one, long keys and large values,
/// which change the sponge block count.
fn circuit_cases() -> Vec<Case> {
    let [_, long_keys, large_values] = Case::variants(16);
    vec![
        Case::base(10),
        Case::base(16),
        long_keys,
        large_values,
        Case::base(20),
    ]
}

#[test]
#[ignore = "measurement run: release build under scripts/zk_resource_harness.py"]
fn native_blake2b() {
    let run = Run::over_the_state_inventory();
    native_matrix::<Blake2bProfile>(&run, "blake2b", &full_cases(), 20);
}

#[test]
#[ignore = "measurement run: release build under scripts/zk_resource_harness.py"]
fn native_blake3() {
    let run = Run::over_the_state_inventory();
    native_matrix::<Blake3Profile>(&run, "blake3", &full_cases(), 20);
}

#[test]
#[ignore = "measurement run: release build under scripts/zk_resource_harness.py"]
fn native_and_circuit_poseidon2() {
    let run = Run::over_the_state_inventory();
    // The baseline chain is linear in the population: under a sponge profile
    // it is measured up to the representative population only.
    algebraic_matrix::<Poseidon2Goldilocks12>(
        &run,
        "poseidon2",
        &full_cases(),
        &circuit_cases(),
        16,
    );
}

#[test]
#[ignore = "measurement run: release build under scripts/zk_resource_harness.py"]
fn native_and_circuit_rescue_prime() {
    let run = Run::over_the_state_inventory();
    // One cold build of the maximum population takes minutes under the
    // slowest profile: it is built once, and only its change sets and
    // statements are repeated. The baseline chain is measured at the small
    // population only.
    let cases: Vec<Case> = full_cases()
        .into_iter()
        .map(|case| {
            if case.population_log2 >= 20 {
                Case {
                    build_repeats: 1,
                    update_rounds: 1,
                    ..case
                }
            } else {
                case
            }
        })
        .collect();
    algebraic_matrix::<RescuePrime64>(&run, "rescue-prime", &cases, &circuit_cases(), 10);
}

#[test]
#[ignore = "measurement run: release build under scripts/zk_resource_harness.py"]
fn native_digest384_comparator() {
    let run = Run::over_the_state_inventory();
    // The repository's own digest is a native comparator. One hash costs
    // about as much as several thousand BLAKE2b compressions, so all four
    // constructions are measured at the small population with few statements,
    // and one tree candidate at the representative one with a single build.
    let small = Case {
        change_sets: &[1, 100],
        update_rounds: 1,
        update_changes: 8,
        range_entries: &[0, 1, 16],
        point_statements: 16,
        range_statements: 2,
        ..Case::base(10)
    };
    native_matrix::<Digest384Comparator>(&run, "digest384", &[small], 10);
    let representative = Case {
        build_repeats: 1,
        ..Case {
            population_log2: 16,
            ..small
        }
    };
    let _ = measure_native::<RadixTree<Digest384Comparator>>(
        &run,
        "radix",
        "digest384",
        &representative,
    );
}

/// Repetitions of every latency phase.
const LATENCY_REPEATS: usize = 5;

/// Time `calls` evaluations of one hash operation as one phase per repetition.
fn time_operation(session: &Session, name: &str, calls: u64, mut operation: impl FnMut(u64)) {
    for repetition in 0..LATENCY_REPEATS {
        let timing = session.enter(repeated(repetition, name));
        for index in 0..calls {
            operation(index);
        }
        session.record_work("calls", calls);
        timing.complete();
    }
}

fn profile_latency<H: HashProfile>(session: &Session, profile: &str, calls: u64) {
    let left = H::hash_bytes(LATENCY_DOMAIN, b"left");
    let right = H::hash_bytes(LATENCY_DOMAIN, b"right");
    time_operation(session, &format!("{profile}.compress"), calls, |index| {
        black_box(H::compress(LATENCY_DOMAIN, index, black_box(&left), &right));
    });
    for bytes in [36_usize, 32, 132, 256] {
        let input = vec![0xa5_u8; bytes];
        time_operation(
            session,
            &format!("{profile}.hash_bytes_{bytes}"),
            calls,
            |index| {
                black_box(H::hash_bytes(LATENCY_DOMAIN ^ index, black_box(&input)));
            },
        );
    }
}

fn permutation_latency<P: Permutation12>(session: &Session, name: &str, calls: u64) {
    let mut state = [7_u64; 12];
    time_operation(session, &format!("{name}.permutation"), calls, |_| {
        P::permute(black_box(&mut state));
    });
    black_box(state);
}

/// Record the latency of every hash profile.
fn measure_latency(run: &Run, calls: u64) -> MeasurementRecord {
    let flow = run.begin(
        "state_candidates.latency.hash_profiles".to_owned(),
        FlowKind::Native,
        "latency_flow",
    );
    let session = &flow.session;
    profile_latency::<Blake2bProfile>(session, "blake2b", calls);
    profile_latency::<Blake3Profile>(session, "blake3", calls);
    profile_latency::<Poseidon2Profile>(session, "poseidon2", calls / 4);
    profile_latency::<RescuePrimeProfile>(session, "rescue-prime", calls / 32);
    profile_latency::<Digest384Comparator>(session, "digest384", calls / 256);
    permutation_latency::<Poseidon2Goldilocks12>(session, "poseidon2", calls / 4);
    permutation_latency::<RescuePrime64>(session, "rescue-prime", calls / 32);
    let mut narrow = [7_u64; 3];
    time_operation(
        session,
        "in-repo-poseidon-w3.permutation",
        calls / 4,
        |_| fastpq_isi::poseidon::permute_state(black_box(&mut narrow)),
    );
    black_box(narrow);
    // The as-built BLAKE2b gadget of the sealed relation, read from its owner.
    let recording = session.enter("as_built_blake2b_gadget");
    let (rows, columns, slot_rows) = as_built_blake2b_gadget();
    session.record_work("rows", rows as u64);
    session.record_work("columns", columns as u64);
    session.record_work("physical_rows_per_hash_slot", slot_rows as u64);
    recording.complete();
    flow.finish()
}

/// Build and check the reference of one gadget relation, three times.
fn measure_gadget<A: SemanticAir>(
    session: &Session,
    kind: &str,
    air: &A,
    limits: WorkLimits,
    private_columns: usize,
    key_bytes: usize,
    columns: impl Fn() -> Vec<Vec<u64>>,
) {
    let schema = air.schema();
    let deriving = session.enter(label(format!("{kind}.geometry")));
    session.record_work("key_bytes", key_bytes as u64);
    session.record_work("rows", schema.trace_rows as u64);
    session.record_work("width", schema.width as u64);
    session.record_work("private_columns", private_columns as u64);
    session.record_work("constraints", schema.constraints as u64);
    session.record_work(
        "numerator_degree_bound",
        schema.numerator_degree_bound as u64,
    );
    session.record_work("trace_cells", schema.trace_cells() as u64);
    session.record_work("reference_repeats", REFERENCE_REPEATS as u64);
    deriving.complete();
    let challenges = ReferenceChallenges::derive(&[0x47; 32], schema.constraints);
    for repetition in 0..REFERENCE_REPEATS {
        let tracing = session.enter(repeated(repetition, &format!("{kind}.witness_columns")));
        let trace = columns();
        tracing.complete();
        let building = session.enter(repeated(repetition, &format!("{kind}.reference_build")));
        let artifact = build_reference(air, trace, &challenges, limits, &NoObserver)
            .expect("an honest trace satisfies the gadget");
        building.complete();
        let checking = session.enter(repeated(repetition, &format!("{kind}.reference_check")));
        check_reference(air, &artifact, &challenges, limits, &NoObserver)
            .expect("the checker accepts the honest artifact");
        checking.complete();
    }
}

/// Measure the two key gadgets for composite keys of the measured key shapes:
/// four bytes of table position and 32 or 128 key bytes.
fn measure_gadgets(run: &Run) -> MeasurementRecord {
    let flow = run.begin(
        "state_candidates.gadget.key_gadgets".to_owned(),
        FlowKind::Proof,
        "gadget_flow",
    );
    let session = &flow.session;
    let mut rejected = 0_u64;
    for key_bytes in [36_usize, 132] {
        // Two keys that differ in their last byte: the comparison decides on
        // the last row of the scan.
        let mut generator = SplitMix64::new(0x6ad6 ^ key_bytes as u64);
        let mut low = vec![0_u8; key_bytes];
        generator.fill(&mut low);
        low[key_bytes - 1] = 7;
        let mut high = low.clone();
        high[key_bytes - 1] = 9;
        let order = KeyOrderAir::new(&low, &high, true);
        measure_gadget(
            session,
            &format!("order_k{key_bytes}"),
            &order,
            order.reference_limits(),
            KeyOrderAir::PRIVATE_COLUMNS,
            key_bytes,
            || order.witness_columns(&low, &high),
        );
        // Twenty-four stated bits, as a radix path of that depth states them.
        let total = u32::try_from(9 * key_bytes).expect("a short key");
        let stated: Vec<(u32, bool)> = (0..24_u32)
            .map(|step| {
                let index = step * total / 24;
                let byte = low[(index / 9) as usize];
                let bit = index % 9 == 0 || (byte >> (8 - index % 9)) & 1 == 1;
                (index, bit)
            })
            .collect();
        let bits = KeyBitAir::new(&low, &stated);
        measure_gadget(
            session,
            &format!("bits_k{key_bytes}"),
            &bits,
            bits.reference_limits(),
            KeyBitAir::PRIVATE_COLUMNS,
            key_bytes,
            || bits.witness_columns(&low),
        );
        // False statements have no trace that satisfies the gadgets.
        let checking = session.enter("prepare_state");
        let reversed = KeyOrderAir::new(&high, &low, true);
        let challenges = ReferenceChallenges::derive(&[0x47; 32], KeyOrderAir::CONSTRAINTS);
        assert!(
            build_reference(
                &reversed,
                reversed.witness_columns(&high, &low),
                &challenges,
                reversed.reference_limits(),
                &NoObserver,
            )
            .is_err()
        );
        let mut wrong = stated.clone();
        wrong[5].1 = !wrong[5].1;
        let flipped = KeyBitAir::new(&low, &wrong);
        let challenges = ReferenceChallenges::derive(&[0x47; 32], KeyBitAir::CONSTRAINTS);
        assert!(
            build_reference(
                &flipped,
                flipped.witness_columns(&low),
                &challenges,
                flipped.reference_limits(),
                &NoObserver,
            )
            .is_err()
        );
        rejected += 2;
        checking.complete();
    }
    let recording = session.enter("false_statements_rejected");
    session.record_work("false_statements_rejected", rejected);
    recording.complete();
    flow.finish()
}

#[test]
#[ignore = "measurement run: release build under scripts/zk_resource_harness.py"]
fn hash_latency_and_key_gadgets() {
    let run = Run::over_the_state_inventory();
    measure_latency(&run, 1 << 20);
    measure_gadgets(&run);
}

fn phase<'a>(
    record: &'a MeasurementRecord,
    name: &str,
) -> Option<(u32, &'a iroha_measurement::PhaseNode)> {
    record
        .phase_tree
        .nodes
        .iter()
        .enumerate()
        .find(|(_, node)| node.label == name)
        .map(|(index, node)| (u32::try_from(index).expect("a bounded tree"), node))
}

fn counter<'a>(
    record: &'a MeasurementRecord,
    phase_name: &str,
    name: &str,
) -> Option<&'a iroha_measurement::WorkCounter> {
    let (index, _) = phase(record, phase_name)?;
    record
        .work_counters
        .entries
        .iter()
        .find(|entry| entry.phase == index && entry.label == name)
}

fn work(record: &MeasurementRecord, phase_name: &str, name: &str) -> Option<u64> {
    counter(record, phase_name, name).map(|entry| entry.total_units)
}

/// The relation on witnesses of each tree candidate under one sponge profile:
/// every statement kind is built and checked, with its recorded geometry, and
/// every program hashes what its native verification hashes.
fn smoke_circuits<P: AirPermutation + Sync>(run: &Run, profile: &str, case: &Case) {
    fn check<E, P>(run: &Run, construction: &str, profile: &str, case: &Case, per_leaf: bool)
    where
        E: WitnessPrograms<Hash = AlgebraicSponge<P>>,
        P: AirPermutation + Sync,
    {
        let (native, population) = measure_native::<E>(run, construction, profile, case);
        assert!(work(&native, "r0.cold_build", "hash.permutations").unwrap() > 0);
        let record = measure_circuit(run, construction, profile, case, &population);
        assert_eq!(record.identity.flow, FlowKind::Proof);
        for kind in ["inclusion", "absence", "range_0", "range_1", "range_16"] {
            // Every statement: the program's permutations are the native
            // verifier's, plus one root normalisation per further anchor.
            let statements = format!("{kind}.statements");
            let native = counter(&record, &statements, "native_permutations").expect("recorded");
            let circuit = counter(&record, &statements, "permutations").expect("recorded");
            let anchors = counter(&record, &statements, "anchors").expect("recorded");
            assert_eq!(native.count, circuit.count);
            assert_eq!(
                circuit.total_units,
                native.total_units + anchors.total_units - anchors.count,
                "{construction} {kind}"
            );
            if !per_leaf {
                assert_eq!(anchors.total_units, anchors.count, "{construction} {kind}");
            }
            let registers = counter(&record, &statements, "registers").expect("recorded");
            assert!(registers.min_units >= 1 && registers.max_units <= 8);

            let geometry = format!("{kind}.geometry");
            let rows = work(&record, &geometry, "rows").expect("recorded rows");
            assert!(rows.is_power_of_two() && rows >= P::ROWS as u64, "{kind}");
            let registers =
                usize::try_from(work(&record, &geometry, "registers").expect("recorded"))
                    .expect("a small register count");
            assert_eq!(
                work(&record, &geometry, "width"),
                Some(ChainAir::<P>::width_with(registers) as u64)
            );
            assert_eq!(
                work(&record, &geometry, "constraints"),
                Some(18 + 4 * registers as u64)
            );
            assert_eq!(
                work(&record, &geometry, "numerator_degree_bound"),
                Some(8 * (rows - 1) + 1)
            );
            assert_eq!(work(&record, &geometry, "exceeds_reference_rows"), Some(0));
            // A trace of at most 4,096 rows is built and checked three times.
            let repeats = if rows <= REPEATED_REFERENCE_ROWS as u64 {
                REFERENCE_REPEATS
            } else {
                1
            };
            assert_eq!(
                work(&record, &geometry, "reference_repeats"),
                Some(repeats as u64)
            );
            assert!(phase(&record, &format!("r{repeats}.{kind}.reference_build")).is_none());
            for repetition in 0..repeats {
                for step in ["witness_columns", "reference_build", "reference_check"] {
                    let (_, node) =
                        phase(&record, &format!("r{repetition}.{kind}.{step}")).expect("a phase");
                    assert_eq!((node.calls, node.completed), (1, 1));
                }
            }
            assert!(
                work(
                    &record,
                    &format!("r0.{kind}.reference_build"),
                    "heap.peak_bytes"
                )
                .unwrap()
                    > rows * 8
            );
        }
        // Inclusion needs no gadget; absence and ranges need the declared ones.
        assert_eq!(
            work(&record, "inclusion.statements", "gadget_comparisons"),
            Some(0)
        );
        assert_eq!(
            work(&record, "absence.statements", "gadget_bit_scans"),
            Some(E::ABSENCE_GADGETS.bit_scans as u64)
        );
        assert_eq!(
            work(&record, "range_16.statements", "gadget_comparisons"),
            Some(E::RANGE_GADGETS.comparisons as u64)
        );
        // A changed sibling and a flipped side for each of the three kinds.
        assert_eq!(
            work(&record, "forged_traces_rejected", "forged_traces_rejected"),
            Some(4)
        );
    }
    check::<RadixTree<AlgebraicSponge<P>>, P>(run, "radix", profile, case, false);
    check::<MerkleBTree<AlgebraicSponge<P>>, P>(run, "btree", profile, case, false);
    check::<LinkedLeafMap<AlgebraicSponge<P>>, P>(run, "linked", profile, case, true);
}

/// Every candidate under every profile yields a complete, valid record over a
/// small population, natively and, for the tree candidates under the sponge
/// profiles, in-circuit.
#[test]
fn smoke_every_candidate_yields_valid_native_and_circuit_records() {
    let schema = PrototypeSchema::from_descriptor(&descriptor_from_rows(&[
        (POPULATED_TABLE, "norito:K@0.0.2", "norito:V@0.0.2"),
        ("world.assets", "norito:K@0.0.2", "norito:V@0.0.2"),
        ("world.parameters", "", "norito:P@0.0.2"),
    ]))
    .expect("a canonical descriptor");
    let run = Run::over(schema);
    let case = Case {
        change_sets: &[1, 8],
        update_rounds: 2,
        update_changes: 4,
        range_entries: &[0, 1, 4],
        point_statements: 4,
        range_statements: 2,
        repeats: 3,
        build_repeats: 2,
        ..Case::base(5)
    };

    let (record, population) =
        measure_native::<RadixTree<Blake2bProfile>>(&run, "radix", "blake2b", &case);
    assert_eq!(record.identity.flow, FlowKind::Native);
    assert_eq!(
        record.identity.workload,
        "state_candidates.native.radix.blake2b.p5.scattered-32.v32"
    );
    // Every record names the schema its process read: two keyed tables, one
    // cell and the canonical descriptor.
    assert_eq!(
        run.identity,
        SchemaIdentity {
            tables: 2,
            cells: 1,
            descriptor_bytes: run.schema.descriptor().len() as u64,
            descriptor_sha256_prefix: run.identity.descriptor_sha256_prefix,
        }
    );
    assert_eq!(
        run.identity.descriptor_sha256_prefix.to_be_bytes(),
        Sha256::digest(run.schema.descriptor())[..8]
    );
    for (name, value) in [
        ("schema.tables", 2),
        ("schema.cells", 1),
        (
            "schema.descriptor_bytes",
            run.schema.descriptor().len() as u64,
        ),
        (
            "schema.descriptor_sha256_prefix",
            run.identity.descriptor_sha256_prefix,
        ),
    ] {
        assert_eq!(work(&record, "schema", name), Some(value), "{name}");
    }
    let total = 32 + BACKGROUND_ENTRIES + 1;
    // The build is repeated twice and everything else three times, on
    // identical inputs: the deterministic counters of the repetitions agree.
    assert_eq!(work(&record, "r0.cold_build", "entries"), Some(total));
    assert!(phase(&record, "r1.cold_build").is_some());
    assert!(phase(&record, "r2.cold_build").is_none());
    for name in ["hash.compressions", "heap.live_bytes", "heap.peak_bytes"] {
        assert_eq!(
            work(&record, "r0.cold_build", name),
            work(&record, "r1.cold_build", name),
            "{name}"
        );
    }
    // The built map holds at least its digests on the heap, and no more than
    // a generous multiple of them.
    let held = work(&record, "r0.cold_build", "heap.live_bytes").unwrap();
    assert!(held >= total * 3 * 32 && held < total * 4_096, "{held}");
    assert!(work(&record, "r0.cold_build", "heap.peak_bytes").unwrap() >= held);
    let sources = &record.allocations.sources;
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].label, "candidate_map_heap");
    assert_eq!(
        (sources[0].allocations, sources[0].allocated_bytes),
        (2, 2 * held)
    );
    assert_eq!((sources[0].frees, sources[0].live_bytes), (2, 0));
    for repetition in 0..3 {
        let name = |phase: &str| format!("r{repetition}.{phase}");
        assert_eq!(work(&record, &name("update_set_8"), "changes"), Some(16));
        assert_eq!(
            work(&record, &name("update_set_8"), "hash.compressions"),
            work(&record, "r0.update_set_8", "hash.compressions")
        );
        assert_eq!(
            work(&record, &name("verify_inclusion"), "statements"),
            Some(4)
        );
        assert_eq!(
            work(&record, &name("verify_range_4"), "statements"),
            Some(2)
        );
        assert_eq!(
            work(&record, &name("verify_range_4"), "hash.compressions"),
            work(&record, "r0.verify_range_4", "hash.compressions")
        );
    }
    assert!(work(&record, "r0.cold_build", "hash.compressions").unwrap() >= total);
    assert_eq!(work(&record, "r0.cold_build", "hash.permutations"), Some(0));
    assert!(work(&record, "storage", "structure_bytes").unwrap() > 0);
    let witnesses = record
        .byte_counters
        .entries
        .iter()
        .filter(|entry| entry.label == "witness")
        .count();
    assert_eq!(
        witnesses,
        3 * 6,
        "inclusion, absence, cells and three ranges in each repetition"
    );
    assert_eq!(population.map.entries(), population.map.storage().entries);
    drop(population);

    // Every other construction and profile.
    let _ = measure_native::<MerkleBTree<Blake2bProfile>>(&run, "btree", "blake2b", &case);
    let (shared, linked) = measure_linked::<Blake2bProfile>(&run, "blake2b", &case);
    assert_eq!(
        shared.identity.workload,
        "state_candidates.native.linked.blake2b.p5.scattered-32.v32"
    );
    // Two statements of four claimed entries: five leaves each, and sharing
    // the paths hashes fewer branches than the witness carries steps.
    assert_eq!(work(&shared, "shared_paths_range_4", "leaves"), Some(10));
    assert!(
        work(&shared, "shared_paths_range_4", "distinct_branches").unwrap()
            < work(&shared, "shared_paths_range_4", "carried_steps").unwrap()
    );
    assert_eq!(work(&shared, "r2.verify_range_4", "statements"), Some(2));
    drop(linked);
    let linear = case.for_linear();
    assert_eq!((linear.point_statements, linear.range_statements), (4, 2));
    assert_eq!(Case::base(20).for_linear().point_statements, 4);
    assert_eq!(full_cases()[0].for_linear().point_statements, 64);
    assert_eq!(full_cases()[0].for_linear().range_statements, 16);
    let _ = measure_native::<SortedHashChain<Blake2bProfile>>(&run, "chain", "blake2b", &linear);
    let _ = measure_native::<RadixTree<Blake3Profile>>(&run, "radix", "blake3", &case);
    let _ = measure_native::<RadixTree<Digest384Comparator>>(&run, "radix", "digest384", &case);
    let _ =
        measure_native::<SortedHashChain<Poseidon2Profile>>(&run, "chain", "poseidon2", &linear);

    // In-circuit: each tree candidate under each sponge profile.
    smoke_circuits::<Poseidon2Goldilocks12>(&run, "poseidon2", &case);
    smoke_circuits::<RescuePrime64>(&run, "rescue-prime", &case);

    // A statement beyond the reference's trace order is recorded, not built.
    let flow = run.begin(
        "state_candidates.circuit.oversized".to_owned(),
        FlowKind::Proof,
        "circuit_flow",
    );
    let oversized = Program {
        blocks: vec![
            fastpq_prover::state_commitment_prototypes::circuit::Block {
                input: Input::Fresh {
                    capacity: [0; 4],
                    message: [0; 8],
                },
                save: None,
                anchor: false,
            };
            MAX_REFERENCE_TRACE_ROWS / RescuePrime64::ROWS + 1
        ],
        root: [0; 4],
    };
    measure_program::<RescuePrime64>(&flow.session, "oversized", &oversized);
    let record = flow.finish();
    assert_eq!(
        work(&record, "oversized.geometry", "exceeds_reference_rows"),
        Some(1)
    );
    assert_eq!(
        work(&record, "oversized.geometry", "rows"),
        Some(2 * MAX_REFERENCE_TRACE_ROWS as u64)
    );
    assert!(phase(&record, "r0.oversized.reference_build").is_none());

    // Latency of every profile, with few calls, five repetitions each.
    let latency = measure_latency(&run, 256);
    assert_eq!(work(&latency, "r0.blake2b.compress", "calls"), Some(256));
    assert_eq!(work(&latency, "r4.blake2b.compress", "calls"), Some(256));
    assert_eq!(
        work(&latency, "r4.rescue-prime.permutation", "calls"),
        Some(8)
    );
    assert_eq!(work(&latency, "as_built_blake2b_gadget", "rows"), Some(408));
    assert!(Blake3Profile::NAME != Blake2bProfile::NAME);
    // The measurement copy of the BLAKE3 profile is BLAKE3 itself.
    assert_eq!(
        Blake3Raw::digest(&[b"ab", b"c"]),
        *blake3::hash(b"abc").as_bytes()
    );

    // The key gadgets for both measured key lengths.
    let gadgets = measure_gadgets(&run);
    assert_eq!(gadgets.identity.flow, FlowKind::Proof);
    for (kind, rows, width, private, constraints, degree) in [
        ("order_k36", 64, 42, 32, 47, 4),
        ("order_k132", 256, 42, 32, 47, 4),
        ("bits_k36", 64, 37, 11, 25, 3),
        ("bits_k132", 256, 37, 11, 25, 3),
    ] {
        let geometry = format!("{kind}.geometry");
        assert_eq!(work(&gadgets, &geometry, "rows"), Some(rows), "{kind}");
        assert_eq!(work(&gadgets, &geometry, "width"), Some(width));
        assert_eq!(work(&gadgets, &geometry, "private_columns"), Some(private));
        assert_eq!(work(&gadgets, &geometry, "constraints"), Some(constraints));
        assert_eq!(
            work(&gadgets, &geometry, "numerator_degree_bound"),
            Some(degree * (rows - 1) + 1)
        );
        assert!(phase(&gadgets, &format!("r2.{kind}.reference_check")).is_some());
    }
    assert_eq!(
        work(
            &gadgets,
            "false_statements_rejected",
            "false_statements_rejected"
        ),
        Some(4)
    );
    // The counting allocator sees this test's own allocations.
    let before = heap::restart_peak();
    let buffer = vec![0_u8; 1 << 20];
    assert!(heap::live() >= before + (1 << 20));
    assert!(heap::peak() >= before + (1 << 20));
    drop(black_box(buffer));
    assert!(heap::live() < before + (1 << 20));

    // A thread scope counts the calling thread alone. While it is open the
    // other thread allocates a megabyte and holds it; this thread keeps 64 KiB
    // and frees a quarter megabyte. The slack is for the first use of the
    // barrier on this thread.
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let other = {
        let barrier = std::sync::Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            let foreign = vec![1_u8; 1 << 20];
            barrier.wait();
            barrier.wait();
            drop(black_box(foreign));
        })
    };
    let (kept, held, peak) = heap::of_this_thread(|| {
        barrier.wait();
        let scratch = vec![2_u8; 1 << 18];
        let kept = vec![3_u8; 1 << 16];
        // The other thread holds its megabyte from here on.
        barrier.wait();
        drop(black_box(scratch));
        kept
    });
    let slack = 1 << 14;
    assert!((1 << 16..(1 << 16) + slack).contains(&held), "{held}");
    let most = (1 << 16) + (1 << 18);
    assert!((most..most + slack).contains(&peak), "{peak}");
    barrier.wait();
    other.join().expect("the other thread");
    drop(black_box(kept));
    // Outside a scope nothing is counted for the thread.
    let ((), held, peak) = heap::of_this_thread(|| ());
    assert_eq!((held, peak), (0, 0));
}
