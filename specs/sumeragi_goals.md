# Sumeragi goals

Set: 2026-09-25. Overall goal: **Active**. Complete and qualify the single
first-release Sumeragi core, node integration and application consumers.
Implementation completion and network/release qualification are separate gates.
Regression and fault diagnostics do not authorize or block deployment; on-chain governance
owns deployment policy for testnet and production (§13.5).
Required working directory: `/Users/takemiyamakoto/dev/iroha`. Required branch:
`optimizations`.

Protocol contract: [specs/sumeragi.md](sumeragi.md). Implementation:
[`crates/iroha_sumeragi`](../crates/iroha_sumeragi) (sans-IO core and deterministic
simulator). There is one protocol and it is called Sumeragi; no v1/v2 naming survives
the cutover.

## Decisions (2026-09-25)

| Decision | Choice |
| --- | --- |
| Voting | Execute before vote. Prepare and Commit votes sign `(instance, height, view, block, result)`; a CommitQC finalizes order and result. |
| Topology | B-Chain overlay per round: leader, set A (first `n − f`), proxy tail (last of set A), set B (standby `f`). Only set A works in the normal case. |
| Collector | Proxy tail aggregates; graded fallback (retransmit, set B via the proxy tail, then broadcast voting) when it or a set-A member fails. |
| Finality | One core instance per chain. Dataspaces and lanes keep DS-local finality; cross-dataspace AMX uses two-phase commit through the global chain (spec §11). |
| Provenance | In-house protocol and code; no external consensus library. |
| Compatibility | None. Fresh wire, storage and genesis; Taira is reset. |
| Scale | The global production committee is exactly `3f + 1` with `1 <= f <= 10` (4 through 31), and every certificate contains exactly `2f + 1` equal validator votes. Candidate and observer pools do not contribute voting seats. The generic simulator exercises additional sizes; those runs do not qualify global production committees. |

## Goals

| Id | Goal | Status | Acceptance |
| --- | --- | --- | --- |
| S1 | Sans-IO core and simulator | Implemented; current-source qualification remains open. CI: the PR job runs the simulator and the driver/node/lane tests; `.github/workflows/nightly_sumeragi.yml` runs every scenario at 10 000 seeds and the mutation gate (`scripts/sumeragi_mutation_gate.py --strict`). | Spec conformance; every safety and liveness mutation of spec §13.4 killed by its named deterministic test (`scripts/sumeragi_mutation_gate.py`); all fault scenarios pass nightly at 10 000 seeds. |
| S2 | Node driver | Implemented: `iroha_core::sumeragi::driver` (kernel, persistence, executor scheduling, serving, ingress) with the simulator conformance run; E49, E55. | Driver in `iroha_core` generic over `Net`, `RecordStore`, `BodyStore`, `BlockStore`, `Clock` and `Executor`; the same driver code runs in the simulator (spec §13.5); O2/O3/O5/O8/O9 conformance oracles pass at every I/O completion. |
| S3 | Execution and storage binding | Implemented with the E51 result commitment (complete World roots, ordered events and witnessed writes): State executor on one live overlay, Kura frames with commit certificates, file record/body stores, genesis result-only certificate, replay checked against each certified result; 4 in-process validators commit, restart and reject a forged result. | Define `R` (post-state root, transaction-outcome root, event root, scheduled committee); speculative execution chained on certified parents; apply reuses cached post-states; Kura stores blocks with CommitQCs; per-key safety-record files with the installation log and store id (spec §7.4). |
| S4 | Cutover and deletion | Done (2026-09-29). irohad starts only Sumeragi (`node::prepare` then `start_on_network`); four `iroha3d` peers over P2P commit transactions, restart one and all, and replace a crashed leader (`integration_tests/tests/sumeragi.rs`). Application readers of committed blocks read Kura's certified frames through the certified-chain reader (spec §12.7, Appendix E, E57). `kagami localnet` passes `--sumeragi-assert-fresh-key` on a peer's first boot; the SoraFS provider-ingest and reputation finalized archives are captured by the native executor (`sumeragi::executor::FinalizedArchives`); bridge finality proofs, bundles and challenge-bound attestations are built from commit certificates (`iroha_core::sumeragi::finality`). The v2 runtime and everything that existed only for it are deleted (inventory below). Accelerated snapshot restoration moved to S9. | Swap at `SumeragiStartArgs::start` (`crates/iroha_core/src/sumeragi/mod.rs`, started from `crates/irohad/src/main.rs`); P2P control/bulk traffic classes; config surface reduced to spec §12.4; status endpoint from `Core::status`. Then delete the v2 runtime and everything that exists only for it (inventory below). |
| S5 | Dataspace and lane instances | Lanes implemented ([specs/sumeragi_lanes.md](sumeragi_lanes.md)): every lane incarnation is a core instance with a pinned committee, the global chain merges certified lane blocks by reference, and autoscale opens, closes and retires elastic lanes; tested in-process with 4 validators and over P2P (`integration_tests/tests/sumeragi_lanes.rs`). The daemon also hosts one independent signed dataspace root with its own State, Kura, allocation pool and native context archive. Current-source network isolation and restart qualification remain open. | Per-instance identity, committees and records; O9 isolation (one stalled instance never delays another). Nodes host several lane cores; separate dataspace roots may run in separate daemons and need not share a process. |
| S6 | AMX two-phase commit | In progress. The global instructions and deadline step, native transfer prepare/escrow/settle instructions, signed independent-root binding and historical record-proof construction are implemented in `crates/iroha_core/src/sumeragi/amx/`. Records bind the witnessed-write root of `R`; foreign authority advances through authenticated handoffs. The daemon supervises its signed root and mandatory archive. Explicit and managed Kagami bootstrap retain the parent's original G1/H2 and stage one participant instruction in private genesis. Explicit administrative parent registration preserves the original signed request and certified execution outcome; the proof reader can detach its exact original carrier/archive job from the State view. Current-source qualification of these paths, complete outbound proof custody, durable validator relaying and monetary/network qualification remain open (TODO(S6), Appendix E, E58); lane instances alone do not establish dataspace isolation. | Begin, prepare/escrow, relay, decision by deadline, settle; authenticated persisted record proofs and sequential foreign-committee handoffs (spec §11); O-AMX simulator coverage plus real independent-dataspace commit, abort, deadline and restart. |
| S7 | Taira reset and qualification | Open project gate owned by the deployment owner, outside this coding task. The [reset runbook](runbooks/sumeragi_taira_reset.md) defines cutover; [status.md](../status.md#deployment-state) records deployment observations. Earlier deployment evidence does not qualify a new source candidate. `scripts/sumeragi_soak.py`, `integration_tests/tests/sumeragi_lanes_soak.rs` and `.github/workflows/nightly_sumeragi_soak.yml` provide optional engineering diagnostics. | Fresh genesis and operator runbook (spec §14.5); authenticated native control authority, genesis and committee, safety-record custody, and live four-validator readiness/write/restart evidence. Deployment policy belongs to on-chain governance for Taira and production. No fixed fault-test duration or soak verdict authorizes or blocks deployment. |
| S8 | Evidence and committee scheduling | Open; complete historical key/PoP records and prefix verifier implemented, Core qualification pending | Evidence → penalties; authenticated E+2 elections, a complete E+1 preparation interval and atomic activation/retention under the validator staking requirements below. Qualify every historical `CommitQC` against the genesis-anchored authority prefix (spec §12.7), including rotated-away and revoked keys, without a local-trust fallback. |
| S9 | Full state root in `R` | World part implemented; the complete State root is open. E51 binds parent/post-execution World roots from an incremental LtHash16 accumulator and ordered event roots; publication incorporates deterministic tail writes and startup checks certified replay against a cold World capture. Canonical State-level fields (transaction membership, commit topologies, the canonical runtime, chain and network identity, lane manifests and compliance, node-configured policy cells) affect no certified root, and the multiset root has no inclusion, absence or range witness ([`state_table_inventory.json`](state_table_inventory.json), open defects G1-D1 to G1-D11). The keyed State commitment that closes this is specified in spec §16 and built by ZK delivery plan task G.3. Current-candidate qualification and authenticated accelerated snapshot restoration remain open. | Qualify exhaustive canonical World coverage, incremental/cold equivalence, rollback, event ordering and restart against certified results. Accelerated restoration additionally authenticates the complete restored State and retained native tip/history; a matching World root alone is insufficient. |

S2 and S3 come before S4. S5 and S6 build on S4. S7 gates the release.

### Active handoff completion gates

This coding task owns H1–H5: production integration, native dataspaces and AMX,
staking and committee transitions, authenticated snapshot restoration, and
current-source validation with rebuilt native SDK artifacts. Taira deployment
and live cutover execution and evidence (H6) are managed separately by the
deployment owner and are outside this task. H6 remains an open project gate.

H1–H5 remain active. All work uses the required checkout and branch above.
Work starts with H1; independent implementation and simulator work may proceed
in parallel. Each gate requires current-source
evidence, and implementation coverage alone does not close its network or release acceptance.

| Id | Outcome | Completion gate |
| --- | --- | --- |
| H1 | Production integration | Rebuild the daemon and Nexus harness; qualify proposal publication, repeated accepted paid settlements and disjoint lane gossip. Preserve the original funded execution through finality and restart; reclaim retired lane storage only when retained global history no longer needs it. |
| H2 | Native dataspaces and AMX (S5/S6) | Independent dataspace State; production escrow and prepare/settle instructions; authenticated persisted record proofs and validator relayers; real multi-dataspace commit, abort, deadline and restart coverage. |
| H3 | Staking and committee transitions (S8) | Complete authenticated lane offence attribution and original-pool resource accounting; prove E+2 selection, the full beacon preparation interval and paid 4→7→4 transitions with restart, rewards, exits and slashing. |
| H4 | Authenticated snapshot restoration (S9) | Authenticate complete State, the exact certified native tip and retained history before restoration; reject substituted, incomplete and corrupt provenance and establish replay equivalence. |
| H5 | Current-source qualification (S1/S2/S3) | All simulator scenarios at 10,000 seeds; every required mutation killed by its named test; whole-node signed RS16 loss/withholding, lane isolation/restart, workspace build/tests, strict applicable lint and rebuilt native SDK artifacts on the same candidate. |
| H6 | Taira cutover (S7; deployment owner) | Authenticate Linux source/artifacts and native control authority; complete the fresh four-validator cutover through the canonical reset workflow and retain readiness, paid-write and restart evidence. |

All six gates remain open. H6 uses the reset runbook's deployment authority and runtime-only
signing inputs; local build or component results cannot stand in for live qualification.

### Current validation contract (2026-10-09)

Validate the current implementation and its surviving requirements. Generic
consensus attestation, its flag/attachments and its dedicated mutations are
removed from the first-release protocol. Controls must prove exact BLS quorums,
progress through committee boundaries, rejection of retired wire fields, and
original execution custody through refusal and publication. Challenge-bound
node finality evidence remains a separate authenticated service. Retired
mint-finality, Halo2 State curve-policy and generic-attestation controls are not
prerequisites. Supported Native PIPA-R and STARK admission, key/envelope binding,
refusal, deduplication and retry remain required, alongside the remaining safety,
custody and liveness controls.

Native AMX reader changes must pass the paid startup, certified restart and debit-
bypass regression under the default stack limit, together with the complete affected
component selection. Passing selected custody mutations alone does not qualify this
path; retain startup or restart aborts as failures and fix them without widening the
stack or runtime deadlines.

Discover test names and ignores from the actual built executable. Match libtest's
substring filter semantics and account for every selected test. Mutation controls
must exist under their exact qualified test path or exact final path segment;
every resolved required control must execute nonignored. Only a failed declared
control can establish a named or scenario kill. Failures of additional substring
matches remain errors when the declared controls pass; they cannot replace a
missing control or hide behind another scenario's failure. Baselines still require
every selected test to pass. Derive World coverage from the current authoritative
field inventory; never restore retired fields or pin an obsolete test count.
Direct native logger output may split a serial libtest name from its terminal
status. Libtest's `- should panic` annotation retains that same test identity;
the annotation alone establishes no result. Bind the terminal status to exactly
one unfinished test and still require the
complete discovered selection, matching result summary and process exit; orphan,
duplicate or unfinished statuses cannot establish a pass or a mutation kill.
Nexus happy-day and restart checks require the selected native test's successful
terminal between one running header and one matching summary, together with the
unique Rust experiment completion marker. A marker and summary alone cannot pass.
Standalone Nexus campaign acceptance and saved-evidence validation also require
every validator boot's clean terminal exit, including both boots across restart;
a successful Rust test cannot substitute for validator process closure.
Soak runs must schedule every requested fault within the configured duration and
record an actual positive fault window. Expired, late or clear-only injection and an
unconfirmed peer exit fail the harness; report-only analysis enforces the same
requested-fault coverage contract. These controls do not qualify signed RS16
withholding by themselves.
Each new safety, liveness or custody rule requires its current registered named
mutation control under spec §13.4. A prepared runner is not execution evidence.
Regenerate State inventory with its canonical Rust generator on the candidate;
then invoke Cargo against that generated fixture. Compare exact field and table
identities, including new owners, while preserving writer, rollback and encoder
parity checks. Classify record identifiers separately from State commitments.
A successful canonical regeneration may leave an already-current fixture byte
identical. Require the actual generator invocation, complete terminal result and
matching fixture; permit only no change or the declared State inventory change.
A no-op regeneration may reuse the generator's genuinely compiled Core artifact
only when its input cut, toolchain, profile, features, executable path and bytes
match the actual post-generation Cargo invocation. Changed compiled inputs require
a new compilation; cached reuse does not qualify an optimized build or resources.
Qualify the default genesis confidential-policy pin against the current ZK defaults
and compiled SCCP profiles, then execute signed genesis in the State custody controls.
Resource-refusal controls derive demand from the current owning record or declared
allocation layout. Inline scalar and borrowed framing reads must not invent heap
charges. Retained decoder controls must preserve their exact admitted allocation
identity and original cause through refusal and retry.
SDK accounting retains raw executed test identities and multiplicities, checks
their actual reporter projection and filenames, and accounts for every physical
XML report. Neither an old source census nor a report filename prefix establishes
complete current coverage.
Strict lint evidence records the actual target and effective lint policy. A
successful `-D warnings` run with crate-wide Clippy groups disabled does not
qualify those groups. Remove blanket suppressions and repair the resulting
diagnostics before claiming full strict lint; retain reviewed, specific exceptions
with their actual scope. A `--no-deps` component pass does not cover dependency
or workspace lint failures.
Mutation campaigns require a positive worker count and a simulator seed count
that fits a positive `u64`. Explicit mutation selections must be nonempty and
contain unique IDs; zero-case sweeps and duplicated kill counts cannot qualify.
The PR Sumeragi job and every nightly Sumeragi owner install the repository-pinned
Rust toolchain before cache restoration and native execution. A container image
tag does not identify the compiler used by a validation run. PR formatting uses
that same pinned toolchain and checks the complete workspace. Optional nextest
diagnostics select the current native proof, wallet, AMX and ordinary committed-Load/
finality owners; removed module paths and omitted current controls fail the source guard.
Ordinary Clippy and documentation checks derive their explicit feature selection
from current manifests, including implicit optional-dependency features. They keep
all supported diagnostic features and exclude only the owned mutation selectors;
dedicated jobs compile those selectors as their owning unit tests. SDK public-read,
Deploy bootstrap and Torii canonical-outcome custody controls have separate test-only
selectors; their named
positive baselines and mutation kills use their actual owning crates. Forwarded mutation
selectors are refused, and feature coverage is checked against actual Cargo metadata.
Owning mutation libtests must not introduce a self dev-dependency that also builds
the mutation feature as a non-test library. Full Torii, workspace and coverage
routes explicitly enable `iroha_torii/test-fixtures`; all eight current Torii
integration targets remain required. Unit-test fixture helpers use `cfg(test)`,
and shipping mutation guards remain enforced.
CI sweeps clear inherited single-seed and seed-base overrides. The nightly
simulator explicitly runs 10,000 seeds; PR simulator and driver controls clear
the inherited count as well to preserve each scenario's default coverage.

Record source inputs, features, toolchain, artifact identity, invocation, results
and elapsed time. Changed inputs require affected checks to run again; staging
unchanged bytes is metadata, not a source change. Unrelated documentation edits
do not invalidate an unchanged compiled test artifact. Reuse requires matching
its actual dependency inputs, build scripts, generated fixtures, features,
runtime inputs, tools and executable bytes; a matching Git revision alone is
insufficient. Keep the original whole-source receipt and record this comparison
separately. Final H5 qualification still
requires one source candidate across the full required checks. Preserve earlier
receipts with their original outcome and scope.

Functional compilation and runtime correctness are separate from compiler-resource
qualification. A successfully built executable can expose and verify bugs even
when its build misses the 20-minute optimization target; that target remains open.
Ordinary crate suites use the normal test profile, including its debug-only
test counters. Feature-matrix evidence uses the features on actual Cargo artifacts;
repeating the default governance-enabled build is one configuration, and
`--no-default-features` qualifies the other branch only when dependency unification
has not re-enabled it. Model tests must not depend back on the ABI consumer:
interoperability tests belong in `ivm_abi`, which authenticates the shared test-only
ABI-v1 fixture. Model mutation selectors remain forbidden in non-test libraries.
The Core mutation gate defaults to the test profile, and its nightly
job pins `--core-profile test` for both the baseline and every mutant, preserving
dependency decode counters and debug-only controls. Explicit Core release diagnostics
remain available; protocol and daemon mutations retain their release profile.
Production optimized artifacts receive separate qualification.
Production resource qualification still requires the unchanged optimized compiler
invocation and kernel-measured 13-GiB ceiling from roadmap A5. Focused mutation
build/test/scenario deadlines retain the defaults in `sumeragi_mutation_gate.py`;
they do not impose a 15-minute limit on an unfiltered crate or workspace suite.
The baseline runs each distinct registered named-selector tuple separately, and
baseline and mutant runs give each distinct simulator scenario its own original
deadline. Discovery and execution share that deadline; any incomplete or late
step fails aggregation. This prospective schedule does not reclassify old runs.
Full-suite schedules allow the several hours described in `AGENTS.md` and record
their prospective timeout before launch. Network and ceremony deadlines are
recorded separately and remain part of their own liveness acceptance.

**Snapshot contract.** The node publishes signed local snapshot exports only after
original genesis execution and certified journal replay finish and the native driver
starts. A native halt or worker failure revokes the writer gate; orderly shutdown
retains successful recovery for the final write. Export signatures authenticate bytes,
not execution of a decoded World. Strict startup rejects nonempty snapshot caches and
replays the original journal. Accelerated restoration remains an S9 outcome: it needs
authenticated complete State provenance plus the exact native tip, CommitQC and
retained headers. The implemented World accumulator and a local export signature
do not authenticate State-level fields outside World.

### Validator staking integration requirements

The [validator staking completion plan](staking_validator_completion.md) remains
active across the consensus replacement. Replacing runtime owners does not waive
the original liveness acceptance criteria: silent authors, saturation,
final-transaction progress, authenticated loss, lane retirement and restart must
be qualified on the production path. The rewrite's simulator passes alone do not
close those outcomes.

- Global membership comes from authenticated prepared elections, with E+2 frozen
  at the end of E and E+1 reserved for keys and beacon DKG. The lag-2 storage window
  is not a substitute for this full-epoch preparation policy. Registration adds
  candidates only; exact voting geometry alone does not authenticate a transition.
- Activation publishes the complete ordered committee and beacon
  session together after every target seat proves custody and the current exact
  quorum certifies the boundary. Failed preparation requires certified retention
  of the current generation and cancellation of that attempt. It cannot shrink or
  reroll the frozen roster, and does not require fresh incumbent keys.
- Authority generations and scheduling epochs are separate authenticated records.
  Every signature binds its epoch and complete context. Leader scheduling retains
  fresh authenticated epoch-boundary randomness.
- Signed RS16 availability remains mandatory. Raw full-body dissemination is not
  the qualified replacement. Original resource-funded execution must survive
  validation, publication, application and restart under the sole production owner.
- Bonds, rewards, fees and withdrawals use the immutable network-authenticated real
  XOR asset with exact scoped custody; no placeholder token or implicit funding.
  Retained exit requests keep voting and slashing obligations until an
  authenticated replacement takes effect.

These requirements are not yet implemented end to end in the new native driver.
One unchanged candidate must pass actual disposable 4→7→4 transitions with
noncommittee-sized candidate pools, all-seat restart and the full monetary,
formal, DA, workspace and SDK gates. Qualification does not authorize live
network deployment or value-moving transactions.

## Guardrails

- A liveness fix lands only with a simulator seed or deterministic test that fails before it
  and passes after it.
- Every new rule gets a mutation in spec §13.4 and a named test that kills it; the mutation
  gate runs in CI.
- Changes preserve the source-bound protocol owners, deterministic behavior and
  independently checked safety, liveness and custody invariants (spec §12.6).
- No compatibility shims and no parallel implementation after S4.

## v2 deletion inventory (S4)

Measured on 2026-09-25 (`git ls-files`, lines including tests):

| Area | Lines |
| --- | --- |
| `crates/iroha_core/src/sumeragi/` (393 files) | 625 642 |
| `formal/sumeragi_v2/` (919 files) | 356 775 |
| `scripts/*sumeragi*` (169 files) | 308 146 |
| `pytests/**sumeragi*` | 152 924 |
| `integration_tests/**sumeragi*` | 22 059 |
| `specs/sumeragi*` (v2 specs and goals) | 14 588 |
| `crates/iroha_sumeragi_core` (Verus proofs of the v2 reducer) | 13 019 |
| `crates/iroha_data_model/src/block/consensus_v2*` | 11 201 |

Outside the subsystem, 262 `iroha_core` files and a few files in `iroha_torii`, `irohad`,
`iroha_kagami`, `iroha_test_network` and `iroha_cli` reference `crate::sumeragi::*`.

Removed: `crates/iroha_sumeragi_core` and the v2 CI and release-gate scripts (2026-09-27);
the v2 runtime modules and the old Nexus lane machinery (QueuePlan, lane relay, merge ledger,
native AMX, v2 finality artifacts and snapshot bootstrap), `formal/sumeragi_v2/`, the v2
specs, scripts, CI jobs and configuration surface (2026-09-29). The shared consensus
vocabulary of `block::consensus_v2` now lives in `iroha_data_model::block::consensus`.

## Open questions for the owner

These are the open questions of spec §15. The implementation uses the stated default until
the owner decides otherwise.

1. **Committee preparation.** Decided for validator staking: freeze E+2 at the end of E
   and prepare throughout E+1. The native lag-2 height window must carry this authenticated
   epoch policy; it cannot activate every registered key at `h + 2`. Integration is open.
2. **No empty blocks.** Decided: idle instances never create blocks. Empty or missed builds
   wait for queued transactions, with a bounded `payload_retry_interval` (default 5 s).
   Decoded application payloads must contain at least one network entrypoint.
3. **Crashed leader under load.** View 0 currently allows
   `payload_retry_interval + build_timeout` for a proposal. A shorter wait after a busy
   parent is a future latency optimization; neither timeout nor retry creates a block.
4. **Schedule randomness.** Validator staking requires fresh authenticated epoch-boundary
   randomness for leader scheduling. The topology consumes the authenticated epoch seed;
   preparation must not preselect or reroll boundary randomness. Network qualification remains open.
5. **Demotion.** Default: only leaders of failed views are demoted, for `W = 128` heights,
   at most `f` at a time, with slot substitution. Silent set-A members and proxy tails are not
   demoted. Confirm.
6. **Block timestamps.** Which time-monotonicity rule should the application enforce? Default:
   timestamps are application payload and the core never checks clocks; no rule is defined
   yet, and it must not compare against local clocks.
7. **Execution divergence.** Is a halt acceptable for launch? Default: `ApplyDiverged` halts
   the instance; authenticated State restoration is covered by S9 and remains open.
8. **Payload availability.** Signed RS16 `PayloadManifest`/`PayloadChunk` availability
   is mandatory for the first release. The core integrates signed manifests, authenticated RS16 row acquisition and
   source-bound payload custody. Whole-node loss/withholding, committee geometry
   and resource qualification remain required; component tests do not close them.
9. **AMX epoch length.** What epoch length should AMX-participating instances use (handoff
   cadence for light clients, spec §11)? Default: `epoch_length` is 3 600 heights, one hour at
   1 s blocks.
