//! Public-only phase tree and resource observation records for diagnostics.
//!
//! This crate is the shared owner of phase timing and resource instrumentation
//! for proof, verification, native and SDK flows. It sits below the proof,
//! Core and data-model crates: it depends only on `iroha_allocation`, the
//! Norito codec and the C library.
//!
//! # What a record contains
//!
//! One [`Session`] measures one root flow and produces one
//! [`MeasurementRecord`]:
//!
//! - a phase tree with inclusive and exclusive wall time, opening-thread CPU
//!   time and process-window CPU time per phase, the peak number of
//!   concurrently open child phases, the number of active threads and the
//!   system load at phase boundaries;
//! - allocation counts and bytes and live-buffer high-water marks, read from
//!   existing `iroha_allocation` budgets or reported through a scoped counter;
//! - named byte counters for ciphertext, key, proof and transaction sizes,
//!   and named work counters for public counts such as transform calls,
//!   columns and rows;
//! - process CPU, peak resident set size, thermal state, and the address-space
//!   limit actually in force;
//! - the exact run identity, raw failures, and caller-declared projections,
//!   engineering targets, consensus bounds and local limits, each classified.
//!
//! # Measurements never affect validity
//!
//! Nothing in this crate may be consulted by validation code. Transaction
//! validity, gas, effects and certified roots must not depend on a
//! measurement, a target, a local limit or the presence of a recorder. The
//! recording interface supports this by construction: every method of
//! [`Session`], [`SessionHandle`], [`PhaseGuard`], [`PhaseParent`] and
//! [`AllocationCounter`] returns `()` or an opaque guard, so instrumented
//! code has nothing to branch on. A finished record leaves only through the
//! [`RecordSink`] given at [`Session::begin`]. The checks in [`report`] take
//! a finished record and are for reporting tools and tests.
//! `tests/public_api.rs` compares every public recorder function with a
//! reviewed list, and `fixtures/consumers.json` lists every workspace member
//! and source file that uses the recorder; both tests fail on drift.
//!
//! # Public-only recording interface
//!
//! After [`Session::begin`] the recorder accepts only `&'static str` labels
//! from a closed grammar, enumerated kinds and unsigned integers. There is no
//! parameter of type `&[u8]`, `String`, `&str` with a shorter lifetime, or
//! `impl Display`, so witness bytes, secret keys, hidden programs and
//! formatted error payloads are not attached by accident. Run identity is
//! supplied once, before the workload starts, and identity text outside its
//! grammar is replaced before it is recorded.
//!
//! This prevents accidental attachment; it is not a sandbox against code that
//! sets out to leak. `String::leak` yields a `&'static str`, a label of up to
//! 96 bytes can spell a short secret in hexadecimal, [`MeasurementRecord`]
//! has public fields and a [`RecordSink`] accepts a hand-built record. Such
//! text must still fit the label grammar or the record is reported as not
//! public, but a value that fits the grammar is not detected. Instrumented
//! code must therefore record only static names and public geometry.
//!
//! # Example
//!
//! ```
//! use iroha_measurement::{
//!     ByteKind, CollectingSink, FlowKind, RunContext, RunIdentity, Session, WorkerDeclaration,
//! };
//!
//! let sink = CollectingSink::new();
//! let session = Session::begin(
//!     RunIdentity::new(RunContext::unbound(), "example", FlowKind::Proof, "rust.doc"),
//!     "prove",
//!     WorkerDeclaration { workers: 1, provenance: "doc.single_thread" },
//!     Box::new(sink.clone()),
//! );
//! let commit = session.enter("commit");
//! session.record_bytes(ByteKind::Proof, "proof_frame", 1024);
//! commit.complete();
//! session.finish();
//!
//! let record = sink.take().remove(0);
//! assert_eq!(record.phase_tree.nodes.len(), 2);
//! assert_eq!(record.phase_tree.nodes[1].label, "commit");
//! ```

mod platform;
pub mod probe;
pub mod recorder;
pub mod report;
pub mod schema;
pub mod sink;
pub mod text;

#[cfg(test)]
mod test_support;

pub use recorder::{
    AllocationCounter, Declaration, DeclaredClass, LiveBuffer, PhaseGuard, PhaseParent, Session,
    SessionHandle, WorkerDeclaration,
};
pub use report::{Attribution, Finding, Severity, UndividedPhase, unclassified_numbers};
pub use schema::{
    AddressSpaceObservation, AllocationObservation, AllocationSource, AllocationSourceKind,
    ByteCounter, ByteCounters, ByteKind, CachePolicy, Classification, DeclaredQuantity, FailureLog,
    FlowKind, HARNESS_CONTEXT_FILE, HARNESS_OUTPUT_DIR_ENV, MeasurementRecord, PeakRssSource,
    PhaseNode, PhaseTree, PhaseWorkers, ProcessObservation, ProvenanceKind, RECORD_SCHEMA_V1,
    RawFailure, RecorderHealth, RunContext, RunIdentity, RunOutcome, Scheduling, SchemaError,
    ThermalState, Unit, WorkCounter, WorkCounters, schema_descriptor, schema_descriptor_text,
};
pub use sink::{
    CollectingSink, DirectoryReport, DirectorySink, HandoffError, RecordSink, TeeSink,
    read_harness_context,
};
