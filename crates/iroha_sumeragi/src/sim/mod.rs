//! Deterministic discrete-event simulator of Sumeragi (spec §13.1–§13.3).
//!
//! The simulator runs **unmodified** [`crate::Core`]s — one per machine and instance — under a
//! fake driver that honours the ordering guarantees of §12.3, in a single-threaded scheduler
//! over virtual milliseconds. All randomness comes from one seeded PRNG ([`rng::Rng`]), so a
//! failing run is reproduced exactly from `(scenario, seed)`; a failure report prints both and
//! the last events (`SUMERAGI_SIM_TRACE=1` prints every handled event with its actions).
//!
//! - [`world`]: machines (clock offset and drift, crash and restart), replicas (core plus fake
//!   driver: ingress lanes with O5 priorities, O6 bounds and per-peer round-robin, the write
//!   device with the O2 barrier and loss of non-durable writes on crash, the O4 executor with
//!   `Cancelled` answers and a post-state cache, the payload builder with `PayloadReady` and
//!   quarantine, the block store and O3 apply with divergence detection), several instances
//!   with shared or separate keys, scripted faults and crash churn at action boundaries, write
//!   completions and inside apply.
//! - [`net`]: per-link delays with heavy tails, loss, duplication, reordering, spikes, directed
//!   partitions, heal (GST), NIC bandwidth with O8 strict-priority classes, the O10 frame limit.
//! - [`byz`]: composable Byzantine strategies with their own keys (the targeted adversaries of
//!   §13.4: split brain, twins, withholding and selective proxy tails, lowest-`hq` and
//!   downgraded TCs, hidden `PrepareQC`s, forged bodies, sync chains and `CommitQC`s, short
//!   certificates, replays across instances, floods, removed-committee collusion) and the
//!   adaptive network adversary; identities may be chosen with hindsight from the deterministic
//!   topology of a target height ([`world::preview`]).
//! - [`oracle`]: the §13.2 oracles, checked after every event of every honest replica. O-SIGN
//!   is checked at signing time in the provenance log ([`crypto::SigLog`]), which also checks
//!   that honest Commits are backed by a `PrepareQC` of their view, that honest Prepares match
//!   a proposal of their view, that timeouts after a Commit carry the lock, and the R2/R6
//!   abstentions; signatures that never left a crashed node and are not durably recorded are
//!   retracted (O2 makes them harmless). O-PBS is checked at the first exposure of every own
//!   signature.
//! - [`records`]: the fake key store with its installation log and the record-store id of the
//!   §7.4 record-provenance rules (initial records only at installation events, never over an
//!   existing file; a rolled-back or replaced store makes every key imported).
//! - [`scenarios`]: seeded fault scenarios ([`scenarios::ALL`]). F31 runs independent
//!   instances with the toy two-phase settlement application and O-AMX over certified results;
//!   F39 runs the application clock guard of §4.5 (per-machine wall clocks, block times, CT1 and
//!   CT5 for uncertified executions) with O-TIME.
//!
//! Seeds: `SUMERAGI_SIM_SEEDS` (count per scenario), `SUMERAGI_SIM_SEED_BASE` (first seed) or
//! `SUMERAGI_SIM_SEED` (exactly one seed, to reproduce a failure). Diagnostics:
//! `SUMERAGI_SIM_TRACE` (every handled event), `SUMERAGI_SIM_GAPS` (largest commit gaps of a
//! P1 run).

pub mod amx;
pub mod byz;
pub mod crypto;
pub mod driver;
pub mod host;
pub mod net;
pub mod oracle;
pub mod records;
pub mod rng;
pub mod scenario;
pub mod scenarios;
pub mod world;

#[cfg(test)]
mod mutation_group_1;
#[cfg(test)]
mod mutation_group_2;
#[cfg(test)]
mod mutation_group_3;
#[cfg(test)]
mod mutation_group_4;
#[cfg(test)]
mod sweep;
#[cfg(test)]
mod tests;

pub use scenario::Scenario;
pub use world::World;

/// Run a scenario; `Err` carries the failure report (scenario, seed, violation, trace).
///
/// # Errors
/// The report of the first oracle violation.
pub fn run(scenario: Scenario) -> Result<World, String> {
    let mut world = World::new(scenario);
    world.run()?;
    Ok(world)
}
