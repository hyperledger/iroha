//! # Sumeragi
//!
//! Sumeragi is the Byzantine-fault-tolerant consensus protocol of Iroha. One core instance runs
//! per chain — the global (Nexus) chain and every dataspace or lane chain run the *same* core
//! with their own committee and 32-byte instance id — and instances never wait on each other.
//! There is one version of the protocol; it is called Sumeragi. The normative protocol
//! specification is the workspace file `specs/sumeragi.md`; section numbers (§) and the
//! `// SPEC:` markers (its Appendix E) in this crate refer to it, and `tests/spec.rs` checks
//! that every reference resolves.
//!
//! The native node driver in `iroha_core::sumeragi` runs this core. Remaining qualification
//! work, including signed RS16 payload availability, is tracked in `specs/sumeragi_goals.md`.
//!
//! ## The topology overlay (after B-Chain)
//!
//! Inspired by B-Chain (Duan, Meling, Peisert, Zhang), Sumeragi overlays a total order on the
//! committee for every round `(height, view)` instead of treating validators as an unordered
//! set ([`topology`]):
//!
//! - a per-committee permutation (seeded from the committee and instance, so nobody can grind
//!   it) anchors view 0 of height `h` at permutation slot `h mod n`; views rotate over the
//!   non-demoted members, so any `f + 1` consecutive views have `f + 1` distinct leaders;
//! - position 0 is the **leader**, the first `q = n − f` positions are **set A** with the
//!   **proxy tail** as its last member, and the remaining `f` positions are **set B**;
//! - in the normal case only set A votes and the proxy tail aggregates (`O(n)` messages, five
//!   one-way hops to finality); a graded fallback lets set B join through the proxy tail and
//!   then switches to broadcast voting where every member aggregates;
//! - leaders of failed views are recorded in committed headers and demoted to the tail for a
//!   window of heights (their slots pass to their successors).
//!
//! Topology only affects liveness and routing; no safety rule depends on positions.
//!
//! ## Protocol summary
//!
//! Two voting phases (Prepare, Commit) with a Jolteon/HotStuff-2 style timeout-certificate
//! rule: a TC-justified proposal must re-propose the block of the TC's highest `PrepareQC`.
//! Execution happens **before** the Prepare vote: votes and certificates bind
//! `(instance, height, view, block_hash, R)` where `R` is the execution commitment, so a
//! `CommitQC` finalizes order and result. The only reason not to vote is deterministic
//! invalidity; slowness is absorbed by the pacemaker ([`pacemaker`]). Quorums are always
//! `q = n − f` with `f = floor((n − 1) / 3)` ([`types::quorum`]).
//!
//! ## Sans-IO contract
//!
//! The core is a pure state machine: `handle(now, event) -> Vec<Action>` ([`api`]). It never
//! blocks, never reads a clock, and performs no I/O. The driver owns timers, network, durable
//! storage, the signer and the executor, and honours the ordering guarantees of §12.3 — in
//! particular persist-before-effect: after an [`api::Action::PersistSafety`] nothing externally
//! visible happens until the safety record ([`safety`]) is durable.
//!
//! ## Modules
//!
//! - [`types`]: hashes, keys, signatures, bitmaps, committees, quorum math, chain parameters.
//! - [`preimage`]: every signing and hash preimage as a fixed byte layout (§3).
//! - [`message`]: blocks, votes, certificates, service messages, evidence (Norito encodings),
//!   the wire version and the traffic classes of encoded and decoded frames (§3.5).
//! - [`crypto`]: the `Signer`/`Crypto` traits and pure certificate verification and formation.
//! - [`topology`]: permutation, demotion set, round order and roles, stage hint (§2).
//! - [`safety`]: the persisted safety record and the restart classification R1–R6 (§7.4).
//! - [`pacemaker`]: view timeouts, levels, timer formulas and config validation (§9).
//! - [`api`]: events, actions, startup input, configuration and diagnostics (§12).
//! - [`Core`]: the state machine itself (§6–§10): intake, proposals, execution, votes and
//!   aggregation, timeouts and view changes, commit, sync, proposing, timers and restart.
//!
//! ## Mutation testing (§13.4)
//!
//! Every mutation of §13.4 (the `MS*`, `ML*` and `MA*` rows, plus `ME*` for the as-built rules
//! of Appendix E and `MR-*` for the revision-4 rules with `det_r4_*` tests) is a tiny alternative at
//! its code site, compiled only under `cfg(sumeragi_mutation = "<ID>")`: a
//! `#[cfg(sumeragi_mutation = "<ID>")]` attribute on a statement or match arm, or
//! `cfg!(sumeragi_mutation = "<ID>")` where the change sits inside an expression. Without that
//! cfg the code is the unmutated protocol. `build.rs` sets the cfg only when the crate feature
//! `mutation-testing` is enabled and `SUMERAGI_MUTATION=<ID>` is set, so a production build
//! (feature off) can never be mutated; a `sumeragi_mutation` cfg passed through `RUSTFLAGS`
//! without the feature fails the build. `scripts/sumeragi_mutation_gate.py` is the meta-check:
//! for each ID it builds the mutated crate and requires its named deterministic test(s) to fail
//! (then its randomized scenario, as a second line), and requires the unmutated build to pass.
//!
//! CI runs specification traceability and quorum checks (`tests/spec.rs`) with every pull
//! request's crate tests and the mutation gate nightly (`.github/workflows/nightly_sumeragi.yml`,
//! `--strict`).
//!
//! TODO: add the §13.5 multi-process soak (the conformance runs of the production driver kernel
//! in this simulator live in `iroha_core::sumeragi::driver`) and the O-AMX oracle with the AMX
//! application; narrow the public API to what the §12 driver in `iroha_core` needs (`Core`,
//! `api`, the wire types, the safety record, the §11 exports).

// The workspace denies `clippy::redundant_feature_names`, and clippy attributes a violation in
// the workspace member `vendor/concread` (feature `simd_support`) to every crate it checks. This
// crate's features are `sim` and `mutation-testing`.
#![allow(clippy::redundant_feature_names)]

pub mod api;
pub mod availability;
mod bytes;
pub mod crypto;
pub mod evidence;
mod machine;
pub mod message;
pub mod pacemaker;
pub mod preimage;
pub mod safety;
#[cfg(any(test, feature = "sim"))]
pub mod sim;
#[cfg(any(test, feature = "sim"))]
pub mod testing;
pub mod topology;
pub mod types;

pub use machine::Core;
