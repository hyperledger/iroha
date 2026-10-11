//! Native global consensus and lane instances, executed and published by the node driver.

/// AMX two-phase commit on the global chain (`specs/sumeragi.md` §11).
pub mod amx;
/// The driver's block store over Kura: one certified `SignedBlockWire` frame per height.
pub mod block_store;
/// File-backed body store of the Sumeragi driver (bodies of accepted, unapplied blocks).
pub mod bodies;
/// The certified-chain reader: committed blocks as their Kura frames certify them.
pub mod certified_chain;
/// The execution result `R` of a block (`specs/sumeragi.md` §4.1).
pub mod commitment;
/// QC-based consensus message types and helpers (single-chain).
pub mod consensus;
/// Production cryptography of the Sumeragi driver: `H = iroha_crypto::Hash`, BLS-normal
/// signatures with admitted proofs of possession, and the node's signer.
pub mod crypto;
/// The production node driver of the sans-IO Sumeragi core (`iroha_sumeragi`).
pub mod driver;
/// The lag-2 height-configuration schedule and the genesis committee (`specs/sumeragi.md` §10).
pub(crate) mod epoch;
pub(crate) mod epoch_beacon;
pub(crate) mod epoch_election;
/// The node's executor: executes, applies and builds blocks on the committed State.
pub mod executor;
/// Portable proofs and challenge-bound current-node finality statements.
pub mod finality;
/// Genesis-bound consensus metadata derived from the staged genesis state.
pub mod genesis_meta;
/// Lanes of the global chain: identity, pinned configuration, batches and admission.
pub mod lanes;
/// Per-instance observations of the current Sumeragi core and driver.
pub mod metrics;
/// Bounded canonical native journals for offline operators and qualification.
pub mod native_journal;
/// The Sumeragi driver's P2P transport: the frame envelope, traffic classes, egress and
/// ingress.
pub mod net;
pub mod network_topology;
/// The node's Sumeragi instance: startup, production backends and the driver.
pub mod node;
/// Nonempty block payloads and the leader's proposal builder.
pub mod payload;
pub(crate) mod penalties;
pub mod private_dataspace;
/// Body-free owner-private root registration and native certificate exports.
pub mod private_dataspace_export;
/// File-backed safety records, store id and installation log of the Sumeragi driver (§7.4).
pub mod records;
pub mod schedule;
/// Startup: genesis apply and replay, and the core's `Init`.
pub mod startup;
/// A certified test chain: real genesis, execution and BLS-certified Kura frames.
#[cfg(any(test, feature = "iroha-core-tests"))]
pub mod test_chain;
pub use genesis_meta::{
    staged_genesis_execution_policy_hash, staged_genesis_nexus_amx_context_hash,
    staged_genesis_nexus_amx_context_preimage,
};
/// The initial validator roster: the authenticated subset of the configured trusted peers.
pub mod roster;
pub use roster::filter_validators_from_trusted;
/// Named Sumeragi threads with an explicit, configured stack-size budget.
pub(crate) mod threads;
pub use threads::set_sumeragi_stack_size_bytes;

// TODO: replace the remaining evidence record layout and admission with authenticated native
// epoch/instance evidence before release. The retired runtime is not an authority source.
pub(crate) mod evidence;

// Original-tip authority for native evidence and mandatory staking penalties.
pub(crate) mod evidence_history;

/// Retained funded artifact reads.
pub(crate) mod artifact_read;

/// Source-bound body read jobs.
pub mod body_read;

/// Independent historical availability authority.
pub mod availability_schedule;

/// Canonical durable body records.
pub(crate) mod body_record;

/// Bounded canonical record decoder.
pub(crate) mod durable_record_codec;

/// Bounded canonical certificate metadata.
pub(crate) mod durable_qc_codec;

/// Original-funded durable availability artifacts.
pub mod durable_artifact;

/// Native State availability authority.
pub(crate) mod runtime_availability;

mod storage_attempt;
