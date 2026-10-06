# ZK first-release completion goals

Set: 2026-09-26. Execution resumed: 2026-09-30. Reviewed: 2026-10-04. Overall status: **Active**.

This record owns the remediation requested after the current-source ZK critique.
It supplements [first-release completion](first_release_completion_goals.md) and
[privacy closure](privacy_first_release_closure.md). Implementation remains in the
existing `/Users/takemiyamakoto/devstuff/iroha` checkout on `optimizations`.
All further implementation and validation use this checkout; earlier separate
candidates are historical evidence only. Unrelated changes remain.

The outcome is useful, safe proof algorithms with simple developer APIs. Renaming,
disabling, status objects, source hashes or relaxed caps do not complete an algorithm.
Dedicated review uses independent derivations and adversarial controls bound to
the actual artifacts. Implementation tests alone do not establish cryptographic
qualification; physical-device and signing claims require their actual runs.

The [September 30 continuation](../docs/history/2026-09-30/zk-completion-continuation.md)
retains earlier native/SDK provenance and validation boundaries.
The six unfinished outcomes remain ZK03 through ZK08; no running build, source
review or partial test selection closes one of them.

## Goals and acceptance criteria

| ID | Status | Owner / outcome | Completion criteria |
| --- | --- | --- | --- |
| ZK01 | Complete (implementation) | Vega / secret-safe proving | Every private commitment uses public work dimensions and constant-time secret arithmetic; no raw uncleared witness copies cross the MSM boundary. Differential arithmetic, zero/partial/full row, failure/cleanup and worker-bound tests pass. Report resource limits only when actually enforced. Review other reachable secret hashing scratch, including ZK-ACE. Target timing and independent qualification remain ZK06. |
| ZK02 | Complete (implementation) | Confidential circuits / optional inputs | One owned note can be fully redeemed at maximum tree capacity. Absent inputs require no empty-leaf membership or caller-created dummy witness. Ownership, nonzero/duplicate-nullifier, range and conservation constraints remain enforced. Regenerate all changed circuit keys, digests and dependent fixtures; reject superseded keys. Positive and adversarial circuit/native/SDK tests pass. |
| ZK03 | In progress | Core / honest proof semantics | Generic verification cannot confer a stronger guarantee than its compiled relation. Retire IVM binding-only circuits, registrations, keygen, service routes and SDK/CLI consumers. Production IvmProved admission requires the complete native execution relation and authoritative finalized State anchor; replay or caller-supplied commitments cannot substitute. Implement the complete RAM-LFE program relation before enabling proof receipts. |
| ZK04 | In progress | FASTPQ / bounded private verification | Implement a sound source-state-bound relation with reviewed trace/composition masking and bounded verifier work; fit unchanged proof and total resource limits. Produce and verify real maximum-shape proofs, negative source/witness/statement cases, and CPU/accelerator parity. Full replay and unmasked offline compact proofs do not satisfy this goal. |
| ZK05 | In progress | ZK-X509 / complete bounded credential proof | Redesign or compose the full certificate, CRL, disclosure and ownership relation below 9,437,184 bytes without reducing supported coverage. Account for all segments, recursion, openings and prover resources together. Regenerate fixed profiles and produce actual positive/negative proofs before activation. Arithmetic size projections alone are insufficient. |
| ZK06 | In progress | Cryptographic qualification | Obtain independent artifact-bound soundness, zero-knowledge, Fiat–Shamir/qROM, digest/multi-target, arithmetic and side-channel evidence for the selected release protocols. Keep explicit protocol-specific blockers; do not infer qualification from implementation markers. |
| ZK07 | In progress | SDK / simple developer workflow | One typed prepare/prove/verify workflow per actual capability, actionable errors, early availability/resource checks, secure randomness and private witness ownership by default. Callers do not construct dummy inputs, choose transcript internals, or infer guarantees from backend names. Maintain executable Rust examples and equivalent supported SDK entrypoints, with public guidance in `iroha-docs`. |
| ZK08 | In progress | Validation / reproducible candidate | Reconcile current failing Halo2/note-STARK source contracts by preserving their substantive assertions. Run changed-function tests, real proof/adversarial suites, serialization guards, formatting and applicable SDK tests; then the workspace and four-validator qualification on a fixed candidate. Record exact passes, failures and unexecuted checks separately. |

## Execution order

1. Repair secret arithmetic and optional-input constraints with regression tests.
2. Make guarantees explicit at verifier/developer boundaries; migrate callers and remove stale claims.
3. Use one allocation-free resource plan at developer preflight and actual prover
   admission. Resolve the mathematical construction before widening execution.
4. Complete FASTPQ and X509 constructions against fixed statement and resource
   contracts, then regenerate profiles, keys and fixtures.
5. Qualify end-to-end SDK/native/network paths and independent cryptographic
   evidence. Close each goal only with its acceptance evidence.

## Resource bounds

The [resource contract](zk_resource_contract.json) lists the byte, count and
work bounds from SDK admission to storage with their value, single code owner,
enforcement sites, tests and class: consensus bound, local resource that defers,
local scheduling limit or engineering target. It also records the relations
between bounds. `python3 scripts/check_zk_resource_contract.py` reads each owner
from the source and fails on drift. The checker scans the owner files, the
committed-parameter modules and every production source of the crates on the
path: the data model (`iroha_data_model`), Torii (`iroha_torii`), the node
(`iroha_core`) and the proof-verification crate (`iroha_core_zk`) whole, with
the consensus core, the IVM and its ABI and the P2P layer. A limit defined
there, as a constant or an immutable `static`, is a listed bound or is excluded
with a reason; no directory of those four crates is skipped. An exclusion
records the defining expression of its limit, so a changed value of an excluded
limit fails the checker until its reason is reviewed and `--refresh` records the
new expression, and a second definition of a listed name fails as well.
`--mutate` changes every scanned limit in memory, one at a time, and fails when
a change goes unnoticed.

A limit is found by its name (MAX, LIMIT, BUDGET, CAP and the like) in every
scanned source. In the four crates on the path it is also found by how the code
uses it, whatever its name:

- an integer constant that takes part in a `<`, `<=`, `>` or `>=` comparison
  (also written as the methods `.lt`, `.le`, `.gt`, `.ge`), in a capping call
  (`.min`, `.max`, `.clamp`, `.take`, `.truncate`), in either of the two called
  as a function, bare or behind any path (`cmp::max(a, b)`,
  `u32::clamp(n, 2, 64)`), or in a range tested with `.contains`, the tested
  value included. A call compares its arguments and, for `.min`, `.max`,
  `.clamp` and the comparison methods, its receiver: the whole method chain in
  front of the call, on one line or broken across several (`ROWS.min(n)`,
  `n.saturating_mul(ROWS).saturating_add(1).min(cap)`);
- an integer constant that the defining expression of a scanned limit names: a
  term of that limit, followed until no new constant appears. An excluded term
  records under `term_of` the limits it is part of, and `--refresh` rewrites
  that list;
- a limit-named function without parameters that returns an integer, an
  `Option` of one or a `Result` of one;
- a literal comparison: a comparison, capping call or tested range of those
  kinds that holds an integer literal of 2 or more. The literal may be a whole
  operand (`len > 4096`), a part of one (`len > MAX + 1024`,
  `len / 2 >= MAX`, `timeout > Duration::from_secs(30)`) or a part of a capped
  receiver (`delta.saturating_mul(10_000).saturating_div(n).min(cap)`): a part
  moves the limit like a whole operand does. A whole-operand literal is
  recorded with its operand and operator, a part literal with the whole
  comparison or, where it stands above the last element of a receiver chain,
  with the chain from its head. A comparison inside an enforcement site of a
  listed bound belongs to that bound when the site holds its text whole. Every
  other one is recorded under `completeness.literals` as `text: count` of its
  file, in a group whose reason says why it is not a resource bound of the
  path. A changed literal, a removed comparison and a new one each fail the
  checker, and `--mutate` raises every literal of every recorded comparison by
  one to prove it.

A source whose name looks like a test or fixture file is scanned when its crate
compiles it outside test builds. A source that every declaration gates by
`cfg(test)` is read by name only. An inline module is test code when one of its
`cfg` gates holds only in test builds, in whatever order the gate is written
(`all(feature = "..", test)`); its block is read on the code alone, so a brace
in a character literal or a raw string of the tests hides nothing after it.

No textual scan sees the following, and the contract does not claim them:

- a limit that reaches its comparison only through a function argument, a
  struct field or a local variable and is neither limit-named nor compared by
  name;
- a limit a function returns when the function takes parameters, its name has
  no limit word, or it returns neither an integer nor an `Option` or `Result`
  of one;
- a limit computed at run time;
- a constant of a non-integer type, such as a `Duration` or a range, that its
  name does not mark;
- a literal below 2 or that is no integer;
- a comparison the scan does not read, for a constant that no name marks as for
  a literal: one with `==`, `!=`, `cmp` or `partial_cmp`; a `match` pattern; a
  relational operator written without whitespace around it; checked arithmetic
  that refuses by underflow (`limit.checked_sub(64)?`); the receiver of `.take`
  and `.truncate`, which is the collection that is cut (`(0..ROWS).take(n)`);
  what a block yields when the block is the receiver of a cap or an operand
  (`match kind { .. }.min(cap)`); the head of a receiver chain in front of a
  blank outside brackets (the first arguments of a turbofish, as in
  `rows::<A, B>().min(cap)`); a cap or comparison function called under another
  name (an alias of `use`); and a constant or literal further than 600
  characters from the operator of its relational comparison (no comparison of
  the four crates is that long);
- for an excluded limit, what its expression names besides the integer
  constants of the four crates: an associated constant of a type
  (`Header::SIZE`), a constant of a crate that is not compared and a value a
  function computes. An exclusion pins the text of the expression and its
  terms. A listed bound has no such gap, because its expression is resolved
  through other listed bounds;
- in the consensus core, the IVM and its ABI and the P2P layer, every limit
  that its name does not mark: those crates are scanned by name only.

The proof ceilings of single products (the confidential-asset proof, the
execution-proof envelope, the Soracloud FHE envelopes, the private-dataspace
record proof and the SCCP light-client proof) are pinned exclusions, not listed
bounds. The declared item `proof.product_proof_ceilings` names each of them and
its owner.

The checker also reads the fields of five typed catalogs and fails on a field
that is neither listed nor excluded: `execution_policy_digest_v1` and the Nexus
consensus-policy preimage for node configuration, and the committed
`compute_zk_consensus_policy_hash` inventory (the ZK validity policy),
`ExecutionOutputPolicyV1` and `FastpqSourcePolicyV1`. A site records how often its text occurs, and a named
test must be reached by text from a target of its crate. A test behind Cargo
features records them (`features`, read from the `cfg` attributes on the test,
on every inline module around it and on the way from its file to its target,
and from `required-features`); a feature its crate does not declare fails. A
gate that never holds where the test is compiled fails as well: `any()` or the
boolean literal `false` at any depth of the predicate (`not(true)` too),
`not(test)`, and a predicate that is false with the default features and the
recorded ones (`not(feature = "..")` of a default feature). A `cfg(Q)` applied
through `cfg_attr(P, cfg(Q))` is read as
`any(not(P), Q)`. Other predicates (`target_os = ".."`, `unix`, a `--cfg` of
the build) are not judged: a test behind one is taken as compiled.
`--test-commands` prints the cargo command that runs every named test with its
features. `--refresh` rewrites values,
expressions, pinned exclusion expressions, test features and site counts from
the source and keeps the classifications; `--propose` prints a skeleton with
candidate sites and tests for an unlisted limit.

Facts it records about the current tree:

- The transaction cap is 10 MiB and the default block payload limit is 4 MiB. A
  transaction above 4,128,768 bytes (the payload limit less the proposer's
  64 KiB reserve) cannot be included, so queue admission and
  `Parameters::check_signed_transaction_bytes` refuse it instead of leaving it
  queued until it expires. The bound follows the transaction's route: a
  transaction routed to a native lane also has the budget of that lane's
  committed record, and a transaction routed to lane zero does not. Block
  validity is unchanged. The bound holds for the route at admission and is not a
  promise of inclusion: a lane-routed transaction above the global budget is
  carried by its lane's proposer only, because the global rescue of a stalled
  lane selects within the global budget. If the lane stalls or closes, it stays
  queued until it expires.
- A default block carries at most eleven of its own transactions, not 512: the
  proposer selects up to the Network input cap of the committed FASTPQ source
  policy.
- The proof attachment list of a signed transaction is at most 16 attachments
  and 8 MiB of canonical frame, below the 9,437,184-byte proof ceiling. A
  ceiling-sized proof cannot travel as an attachment today.
- The privacy action bound equals the proof ceiling, so an action carrying a
  ceiling-sized proof is rejected as too large; two maximum actions per block
  do not fit any payload limit.
- A 16 MiB payload passes the chain parameter rule but has no feasible
  `sync_max_bytes`; the largest payload with one is 16,185,312 bytes.
- Transaction gossip frames are 256 KiB: a larger transaction stays with the
  node that admitted it.
- 25 limits and charges that decide validity are still read from node
  configuration and bound into State only as a hash: the decoded-instruction,
  overlay, quarantine and query limits of `[pipeline]`, and the atomic private
  settlement, uploaded-model and DA ingest quota limits of `[nexus]`. The 49
  proof, SCCP and confidential limits and gas charges of `[zk]` and
  `[confidential]` are committed State (see "Committed ZK validity policy"
  below). Eight of the 74 are bound into a hash and compared by no state
  transition; four of those (the settlement leg proof, capsule and sidecar
  sizes) are compared only by Torii's settlement service.
- The configured settlement carrier limit (4,194,304 bytes) is above the
  includable transaction bound of the default payload (4,128,768 bytes): a
  carrier near its limit passes the State check and is refused at queue
  admission.
- An executed block may be 256 MiB of wire; the authenticated block-proof
  carrier a client confirms inclusion through serves at most 32 MiB, and so
  does the portable finality-proof reader.
- One section of a ZK1 envelope is at most 8 MiB, below the 9,437,184-byte
  proof ceiling. zk-X509 proofs do not use that envelope; a ceiling-sized proof
  could not travel in it.

These are open relations and defects with owning tasks in the contract, not
accepted behavior. The 300-second CRL age and presentation window are consensus
validity bounds. The 300-second zk-X509 proving time is an engineering target
with the same value, and the 12 GiB and 32 GiB memory limits are applied by the
prover to itself; none of the three is validity. `exec_budget_ms` and
`apply_budget_ms` are committed parameters used as local scheduling limits.
RAM-LFE budgets cover the registered program, key registration, request,
evaluation, receipt, verification, opening, threshold opening, validator scratch
and each class; those that need a selected profile have formulas and inputs and
no number.

## Committed ZK validity policy

Every value that `compute_zk_consensus_policy_hash` binds is chain policy: the
Halo2 and STARK proof, envelope and batch limits and their enable switches, the
SCCP proof and verifier-work limits, proof retention, bridge-proof windows, the
relation-selecting Kaigi verifying-key references and parameter-set
identifiers, the confidential anchor age, policy-transition windows and
registry caps, and the verification gas schedule (65 fields). Its source is the
committed custom parameter `zk_validity_policy_v1`. The type, the protocol
default and the canonical validation are in
`iroha_data_model::zk_validity_policy`; `iroha_core::zk_validity_policy` applies
a policy to State.

An ordinary authorized `SetParameter` installs or changes the policy, in
genesis or later. Block construction freezes the policy of the predecessor's
committed parameters for the whole block, so a change governs the next block,
the genesis block runs under the protocol default, and a proof is judged by the
policy of the block that executes it (no grandfathering). A payload is
rejected, identically on every validator, when it is malformed, breaks a
structural rule (a zero count, a size above the fixed protocol maximum, an
undefined curve or backend) or is incoherent: a per-proof limit above the
per-transaction limit, a per-transaction limit above the per-block limit, a
proof limit above its envelope, or retained commitment-tree roots that do not
cover the admissible anchor age. Limits may shrink while those rules hold;
widening a retention window does not restore pruned records. A new per-height
transition limit below a committed pending count is rejected. Executor
data-model reconciliation can neither insert, replace nor remove the parameter.
A chain that commits none uses the protocol default, so a default chain's
genesis and World root are unchanged.

A node configuration has no ZK validity key. `[zk]` and `[confidential]` hold
local resources only (verifier workers, queues, retry and wall-clock budgets,
FASTPQ prover settings); a file or environment variable that names a removed
key fails to load with the ordinary unknown-parameter error. Genesis generators
sign the protocol-default confidential policy hash and cannot hash a node
configuration into a header. The tracked Taira deployment carries its two
non-default limits (8 MiB per confidential proof, 16 MiB per block) in
`configs/soranexus/taira/genesis.template.json`. Torii's configuration record,
the telemetry gauges and `iroha confidential gas get` report the gas schedule
State charges. The P2P handshake advertises the protocol-default policy hash of
the release, not the committed policy, so a node that restarts after a policy
change still connects to peers that did not; block headers carry the committed
policy hash and decide.

The execution limits of the transaction pipeline follow the same design. The
committed custom parameter `pipeline_validity_policy_v1`
(`iroha_data_model::pipeline_validity_policy`, applied by
`iroha_core::pipeline_validity_policy`) carries the overlay bounds, the IVM
cycle and decoded-program bounds, the quarantine lane, the IVM query limits,
the AMX budget model and `dynamic_prepass` (16 fields, 15 of them resource
bounds of the contract). An authorized `SetParameter` installs or changes it
and the change governs the next block; executor reconciliation cannot write
it; a node installs local pipeline resources and the fee policy only
(`State::install_node_pipeline`), and `[pipeline]` has no key or environment
alias for a limit. The default ballot and tally verifying keys of `[gov]` are
removed from the node schema: an election's proof relations are selected only
by the keys the election commits.

A Cargo feature that changes validity is measured as well as listed. The unit
test `feature_parity_record` prints a record of one fixed scenario (a certified
history with an authorized policy change, policy identities, limit decisions
and verification gas) and `python3 scripts/check_zk_feature_parity.py` builds
`iroha_core` under several feature selections and compares the records. Every
`must_equal` record has to agree; a `gated` record (today the real native STARK
proof, which a build without `zk-stark` does not compile) may differ only while
the census lists that feature as an open gate.

Verification gas is metered with the schedule frozen in each block's settings.
`iroha_core::gas::meter_instruction`, `meter_instructions` and
`confidential_gas_cost` take the schedule as an argument: the executor and
trigger execution pass the transaction's frozen `zk.gas`, the IVM host the
settings it was configured with for the block, queue admission and the fee
quotes the schedule of the view they read. No process-wide schedule exists, so
two States with different committed schedules run in one process; a certified
chain test accepts a real proof priced at exactly the block gas limit under a
committed schedule and rejects it one gas unit above, on nodes with divergent
settings (`gas.process_wide_schedule`, done).

Custom parameters whose payload Core validates and reads as committed State
(the two validity policies, the lane policy, the governed gas rates, the DA
ingest admission policy, the Nexus runtime catalog, the Hijiri, validation-fee,
account-admission and private-root-fee policies, the corridor registry, their
transition commands, alias bootstrap grants and Hijiri account risks) are
written only by a validated `SetParameter`: executor data-model reconciliation
neither inserts, replaces nor removes them
(`is_consensus_owned_custom_parameter`).

Open in this family, each a census entry with its owner:

- `halo2.enabled` and `stark.enabled` are committed fields. The plan author
  decided they are deleted; that changes the consensus-policy hash preimage and
  needs the pinned first-release history regenerated in a declared cutover
  (`switch.zk.backend_enabled`). `zk-stark` is still a Cargo feature
  (`feature.zk_stark`).
- `confidential.enabled`, `assume_valid` and `verifier_backend` are still
  node-local and compared in the P2P handshake; the plan author decided they
  are deleted (`cfg.confidential.node_switches`).
- The AMX budget values are tested at their boundary through the budget
  check with the limits a block freezes
  (`amx_budgets_accept_exactly_the_committed_budget_and_reject_one_unit_above`);
  no test drives that check through the host's `AXT_COMMIT` syscall.
- The fee policy `[pipeline.gas]` and the `[nexus]`, `[gov]` and `[crypto]`
  validity values are still node configuration (`cfg.pipeline.gas_identity`,
  `cfg.nexus.*`, `cfg.governance`, `cfg.crypto.algorithms`); ten `[nexus]`
  resource bounds remain node-local defects of the resource contract.

## Runtime-validity census

[`zk_runtime_validity_census.json`](zk_runtime_validity_census.json) lists
every place where the validity or availability of a ZK, privacy, FHE or proof
operation depends on an environment variable, node-local configuration, a Cargo
feature, a source, build or catalog digest, a chain condition, a readiness or
qualification record, an activation or lifecycle switch, a global manifest or a
wall clock, with what it gates, the committed source that decides it instead
(or its removal) and the owning plan task.
`python3 scripts/check_zk_runtime_validity.py` scans 29 crates (the proof,
privacy, FHE and execution crates, the node with its configuration, P2P
handshake and Torii, the genesis and deployment tools, the test network, the
command line, the Rust SDK and the native bridges of the other SDKs) and the
SDK sources. It fails when a detector finds a site no entry lists, when a
listed site is gone, when a field of a node-configuration catalog or a Cargo
feature is unclassified, or when a `done` entry loses its test. Besides gate
names it detects any installation of a complete ZK or pipeline settings value
into a State, any write to a `zk` or `pipeline` settings field (plain or
compound assignment), any mutable borrow or `clone_from` of one, every
production use of a protocol-default gas schedule or settings value, and every
read of a field of the node-configuration policy catalogs that is not
committed yet. The settings fields of `State` are private: the installers are
their only production writers and other code reads them through
`installed_zk`, `installed_pipeline`, the snapshots, a view or a block. A
typed failure of a node's own entropy, allocator, storage or platform is
recorded as a local resource, not as unfinished work; a version check, a
block-height deadline and the outcome name of a passed deadline
(`...DeadlineExpired`) are recorded as not a gate, and `fully_qualified`
parsing names and `build_sha<bits>_...` builder functions are not matched. Two
classes are derived from the source: a lifecycle enum whose variants are only
`Active` and `Revoked` (with or without `Superseded`) is the revocation state
of a committed record, not an activation gate, and a `bool` constant that is
`true` gates nothing; a `bool` constant on the proof path that is `false` and
named as an availability or completion flag is listed as unfinished work. A
test module renamed with `#[path = "file.rs"]` is recognized as test code. The
census states what the text scan cannot see. An entry is written
from reading its code (`read`) or assigned by a path rule (`path_rule`); a
path-rule entry records where a class of names occurs and who owns that code,
not a site-by-site reading. Every entry with status `open` or `unsupported`
was read site by site; the remaining path-rule entries are local resources,
names that are not a gate and code outside the plan. Listing a gate does not
remove it.

## Operation and admission-route inventory

[`zk_operation_inventory.json`](zk_operation_inventory.json) maps each
operation of the plan's products through its native instruction and wire id,
handler, proof relation and verifier (or the typed refusal that stands where a
relation is missing), authority checks, Kotodama binding, Torii routes and the
files of the six SDK families and of the native bridges that reference it. It
also lists the proof-admission routes (generic verification, IVM syscalls,
Torii, preverification, verifying-key registration, direct protocol
instructions, genesis, restore), the native and in-circuit digests each
product uses, and every site where an uploaded key, a source hash or catalog
membership selects which proof is accepted. Each entry records presence,
verification, state effects and delivery separately; a registered type is not
a usable operation, and no operation is recorded as delivered.

`implemented` verification means a compiled verifier that the operation
reaches by a recorded path from its handler. `test_evidence` then says whether
a cited test that runs by default calls that verifier (`default`), only an
ignored or feature-gated test does (`not_default`), or none does (`none`). A
cited test that is no such evidence says what it covers instead.

`python3 scripts/check_zk_operation_inventory.py` reads the source and fails
when the instruction registry, the twelve-protocol list, a closed relation,
class, job-kind or executable list, the family syscalls and Kotodama builtins,
the Torii route catalog, an SDK or a native bridge gains or loses an entry in
these families that the inventory does not record; when a handler gains an
authority check or a proof-verifier call the inventory does not list; when a
verifier or restore-validator entry point is called in a file or a number of
times that no admission route class records; when a recorded path from a
handler no longer names its verifier, or a cited test no longer reaches it;
and when a recorded symbol or test is gone. `--refresh` recomputes the scanned
parts and keeps every classification; `--propose` prints a skeleton for an
unlisted instruction or route. The reading is textual; the script's
documentation states what that does not show. Primitive parameters and
deterministic vectors are in
[`zk_primitive_workloads.json`](zk_primitive_workloads.json), and the gates on
validity in the runtime-validity census above; the inventory points at both by
key.

Facts it records about the current tree:

- 81 instructions are registered in these families. Twelve operations have no
  instruction. Seven travel another way: a complete IVM proof is a separate
  executable variant, the ordinary FASTPQ artifact is produced and checked
  only by the node that proves it, RAM-LFE execution is a Torii route, the
  leg proofs of an atomic private settlement are verified by committee
  validators before they sign the certificate the instruction checks, and an
  AXT envelope, a dataspace proof inside it and an anchored spend inside it
  are assembled by syscalls. Five do not exist: the WG witness assertion,
  confidential shield, transfer and unshield, RAM-LFE opening, RAM-LFE
  threshold opening and SoraCloud threshold decryption.
- The twelve protocols share one instruction and one dispatch. This binary
  refuses the compiled profile of ZK-ACE, ZK-AMS, Vega and ZK-X509 and
  constructs the other eight, which a default test asserts. The effects of
  all twelve are behind the activation and all-twelve qualification records.
- A typed refusal stands where a relation is missing for the proved IVM
  executable, RAM-LFE proof mode, both BFV backends, every SoraCloud FHE job,
  standalone ZK ballots and tallies, and bridge proofs. Two more refusals
  close AXT: the host refuses every dataspace FASTPQ proof a contract carries
  into an envelope, because its only production admission mode is the
  unanchored one, and block validation refuses every envelope that carries a
  spend before any proof is examined. The one instruction that consumes an
  AXT FASTPQ proof is the fee-sponsor vault allocation. The accepted HKDF
  RAM-LFE backend has no consumer, and identifier claims rest on a resolver
  signature.
- Fourteen operations have an `implemented` verifier. For ten a default test
  calls it. For two only an ignored or feature-gated test does: RaceV1
  verification and Kaigi usage recording with a proof. For two none does:
  game settlement and committee validation of a settlement leg. Among the
  twelve protocols no test calls the IVM private-note verifier, and the
  default PQ-MASP test shows rejections only.
- Kaigi creation and ending verify a host authorization proof in a private
  session, like joining and leaving. `VerifyProof` requires no relation: the
  circuit of the registered key selects it.
- A contract can queue only `SubmitBallot` through the instruction bridge.
  The only other Kotodama bindings are the AXT builtins of the three AXT
  carriers.
- World restore verifies no proof. It validates the RAM-LFE policies, the
  privacy activations and qualification record, the persisted privacy and
  atomic-settlement state, the proof-tag and verifying-key indexes, identifier
  claims, the timed-OVN and Parliament records and the SoraCloud service
  history; State construction rebuilds the proof-status index and validates
  standalone election state. The content of a verifying-key record is
  validated at use, not at restore.
- Of 19 selection sites, a substituted Halo2 key, a generic STARK key under a
  semantic name, an election key without a vote role, an uploaded RAM-LFE
  verifier description, a drifted SoraCloud role key, a changed envelope
  digest, a release manifest with another catalog commitment and a fee-sponsor
  proof under another policy are each rejected by a test that reaches the
  site. Still open, with owners in the inventory: the all-twelve
  qualification record decides admission (its registration also requires the
  running binary's ABI hash and syscall list, the chain id and the
  four-validator roster), the compiled-profile digests bind implementation
  provenance, the RaceV1 and classed-race profile ids hash Rust source bytes,
  a Cargo feature decides whether a SoraCloud key payload is validated, and
  atomic settlement needs a node-configured activation.

## Primitive and workload specification

The [primitive and workload specification](zk_primitive_workloads.json) is the
delivery-plan task H.1 output. `python3 scripts/check_zk_primitive_workloads.py`
checks it against the source and fails when a file of the proof, privacy, FHE,
IVM and primitive-owner scope starts to name a digest, or a listed wrapper of
one, that is not listed for it, and when a production function of the catalog,
Kaigi, spentness, MKHE or privacy-model owners calls a digest without a
recorded role. It establishes consistency, not cryptographic qualification or
performance. What it records:

- The catalog commitment, the Kaigi authorization identities, the confidential
  spentness tree and the MKHE proof digest all hash today with the six-lane
  `GoldilocksDigest384V1`, which
  [the digest boundary](fastpq_compact_digest_security.md) records as
  unqualified. The H.1 candidate for commitments that are hashed natively and
  never recomputed in a relation is raw BLAKE3-256 over one canonical byte
  frame, conditional on each role accepting a generic quantum collision
  estimate near 85 bits; SHAKE256 with 48 bytes of output is the comparator
  where 128 bits are required. H.2 freezes the choice and F.5 implements it.
  `iroha_crypto::Hash` stays the ledger identity hash.
- Every native commitment that moves is bound into a proof, so none can be
  re-hashed on its own. The catalog commitment is the catalog field of every
  frame of the privacy STARK substrate, of the generic native STARK verifier
  and of the MKHE proof hash; the Kaigi identities are instance values of the
  authorization relation; the execution catalog identity is the catalog field
  of every frame of the execution fork. Each changes in the same cutover as the
  proof profile that consumes it. The spentness tree is provisional on G.2/G.3;
  no relation opens it today.
- MKHE: the commitment, transcript and challenge hash of the qPCS is
  proof-internal and follows the shared backend. Its outer parameter, release,
  source and receipt identities are domain-tagged Keccak-256 digests; the
  release manifest digest and the readiness digest seed the admission proof
  through the compiled profile digest. The ceremony identities and the BLAKE3
  payload digests exist in test-only code only. The statement identity shared
  by all twelve protocols is BLAKE3-256 and is absorbed by every engine.
- Two Pasta Poseidon parameterizations are compiled: 57 partial rounds (the
  Axiom tables of the confidential relations and the PLONK gadgets) and 56
  (P128Pow5T3 of the Kaigi relation and the SoraFS credential circuit). The
  56-round owner in `iroha_zkp_poseidon::pasta` is a candidate without
  production callers. The thirteen public RAM-LFE commitments use the ledger
  identity hash; only the private ones use BLAKE3.
- BN254 Poseidon: an independent Grain and Cauchy regeneration reproduces all
  621 fixed field elements and every square MDS minor is nonzero. The
  width-three table uses 56 partial rounds where the published BN254
  instantiation uses 57, so no constant is shared with it. The width-six table
  is one partial round below the paper's margin rule as evaluated here (a
  margin-rule defect candidate, not an attack). The two- and six-input helpers
  are single permutations without capacity or domain separation. F.5 owns the
  correction; the parameters are unchanged.
- Post-quantum: `Cargo.lock` holds no pre-standard package. ML-KEM-512/768/1024
  and ML-DSA-44/65/87 reproduce the official known-answer response and the
  identities that separate FIPS 203 and FIPS 204 from the round-three
  algorithms. Kyber and Dilithium names still label these bytes in types,
  configuration keys and telemetry, and ACVP vectors are not covered. The
  Falcon-512 trapdoor arithmetic of the Bootle Lantern issuer is adapted in
  tree from a pre-standard implementation and is invisible to a lockfile audit.
- Exploratory workloads for the shared backend and the product roles, and the
  requirements a shared transcript must meet, are inputs to H.2 and H.3. The
  one recorded measurement is a single exploratory run.

## Current implementation and evidence

Work remains in the existing `optimizations` checkout, with merged HEAD
`68d8bb58ff4af339aba2229f18da3ed00d58d2e6` and subsequent reviewed repairs.
Each native diagnostic retains its actual compiler artifacts and
compile/runtime input observations. Component results below do not establish one
unchanged, fully qualified release candidate. Original failures remain retained
under `dist/zk-remediation/2026-09-30/`; no ZK03–ZK08 goal is closed.

The merged-source script suite passes 722 tests and 163 subtests, and all 58
typed workflow controls pass on their separately recorded unchanged inputs.
The shipping inventory retains its 24-default-binary ceiling while accounting
for the canonical standalone artifact-admission tool. The canonical lockfile
pin now matches the reviewed merged graph: all 1,154 package identities are
unchanged, with four reviewed dependency-edge changes. Stock locked offline
metadata resolves successfully. These checks do not replace native validation.

The applied X509 terminal replay batches 35 eligible four-column families,
reducing native source requests from 364 to 259 while retaining all 364 logical
checks. BindingSink remains scalar. The existing mask, endpoint-check and
failure order is preserved; peak retained native columns rises from one to
seven, with the additional 25,165,824 bytes charged within the existing budget.
Eight ordinary controls and the genuine comparison of all 35 production-source
batches against 140 single-column replays pass in optimized Mac and Linux
artifacts. The complete maximum below still fails the proving-time gate; no
speedup is inferred from the request count. All 46 corrected Mac RFC/DER controls pass, including
three regenerated proof fixtures and eight separate IO/projection mutation
controls. All native source and artifact observations pass. The standalone DER
proof is 1,527,952 bytes, below the unchanged 1.8 MB ceiling, and proves in
261.293296 seconds. Both verification runs, all mutations and the unchanged
timing assertions pass; verification takes 129.589 and 129.297 milliseconds.
The reduced wire authenticates both DEEP evaluations, opens current query rows
and checks the complete 898-residue relation at the out-of-domain point. All
eight terminal claims, 136 queries and resource ceilings remain unchanged.
This test-only standalone format exposes its terminal products; these component
results do not establish the complete credential's hiding guarantee.

The inactive source-root correction passes at both certificate depths, with
degree inventory `[0,1,903,390,651]` and maximum degree four. Both genuine
ordinary and maximum native-column RFC replays pass. The compiled constructor
matches all 29 expected profile fields and rejects its predecessor. Complete
ordinary and maximum credential proofs were still pending at that stage.
Independent source review found a further completeness mismatch:
reference admission allows a CA path-length limit above its required depth,
while native RFC construction and its fixed byte table require the exact
minimum. Native before-fix regression reproduces all 32 larger valid path-length
rejections across both depths and u32 DER boundaries; the two minimum controls
pass. A separate native diagnostic accepts removal of equality rows, embedded-copy
rows, and both, after rebuilding all 280 auxiliary columns and checking every
local residue and terminal. This demonstrates the erasable RFC census, not a
complete forged credential proof. The reviewed full private-u32, forced copy
census and authenticated extension-profile identity repair is now applied.
Genuine signed capacity fixtures cover both depths, maximum copied Names and
identifiers, u32 path lengths, u64 CRL numbers and all admitted leaf EKUs.
The native signed regression now passes all 34 u32 path-length cases. Its
maximum-capacity baseline exposed stale enterprise EKU identifiers in both
native parsing and verifier-fixed tables; the reference profile uses canonical
UUID OIDs. The coherent correction uses those canonical constants and adds
all seven supported EKU combinations plus retired-identifier rejection. The
SourceNode retention and complete node-query census tests retain their full
replay assertions for the mandatory copy endpoints. Fresh optimized Mac and
Linux artifacts confirm all 29 fields of profile
`fb4dc4d0b2ce277e23d3de9d4ccd6c32c9a9b0ef5b39f7c963f8b914cf15860b`,
with an exact 2,841/73 test census. After the verified three-literal fixture
correction, both fresh native runs pass all 218 selected controls with zero
failures or skips. Signed path-length, capacity, omission, all source observations
and compiler/artifact custody pass. Authentic proof hashes match across platforms.
The standalone DER remains 1,527,952 bytes and takes 268.121060 seconds on Mac
and 268.733106 seconds on Linux. Both verifications and every original mutation
and timing assertion pass. Complete current ordinary and maximum credential
proofs, including the unchanged 300-second, proof-size, RSS and address-space
limits, remain required. Original 215-pass/three-failure runs remain retained.

The latest eighteen-target Core/Kagami build and all 262 selected native
executions pass on their recorded unchanged source and artifacts. They cover all
246 surviving controls from the original 247 obligations, the genuine replacement
producer/consumer controls, paired identical captures, both repaired Kura fixtures,
three corrected chronology controls and six FASTPQ context controls. No obligation
is dropped. The genuine fixture producer also builds and executes through real
genesis; all four sequential/parallel comparisons pass and its outputs exactly
match the canonical fixtures. Both optimized Mac and Linux scalar-CALL, callable,
frame and private-history selections pass all 61 ordinary controls on their
recorded artifacts; two heavy frame controls remain unexecuted. Those components
do not establish complete native execution or finalized-State binding. The full
locked, offline workspace all-target check now passes after the canonical
shared-block, fallible-tip and original-State custody corrections. The corrected
chronology controls pass using the actual retained genesis and strict ordering.
The fresh locked offline workspace all-target check passes on the combined
X509, fixture and arithmetic candidate. All 5,005 affected native tests pass:
35 artifact-admission, 4,633 data-model, two allocation-observer and 335 Primitives
controls. The original harness result remains a failure because its parser missed
17 standard `should panic` annotations; independent reconciliation checks every
actual test event, exact expected selection and retained source/artifact input.
No native failures or skips are hidden. Strict Clippy still fails on two decoder
visibility diagnostics, remaining CoreZK lifecycle/relation items and one observer
test pattern. Reviewed visibility, private projection, result-field and receipt-method repairs
are applied without blanket unused-code allowances or capability changes; fresh
compiler/native replay and the remaining lifecycle/relation work are required.
Two genuine native captures execute all 107 owner/wire printers each, with
identical output. The applied fixture correction preserves all 105 prior owners
and all 395 prior wire assignments, adding only the reserve-policy owner and
verifier-release retirement instruction. Current paired captures have 106 typed
owners and 1,559 nominal identities; these component passes do not establish
integrated, physical-device or release qualification.

The earlier seventeen-target Core/Kagami compilation passes with stock Rust 1.93.1 on
its recorded inputs. The rebuilt aggregate Core library and group04 artifact now
passes all 246 still-existing exact controls from the original 247-test request,
with zero failures or skips. Its retired control now has three passing genuine
producer/consumer replacements across five native invocations. Both captures are
byte-identical, and both public bridge consumers verify them. The original 247
obligations are fully accounted for, with no uncovered control. All five
previously stack-aborting controls pass on the unchanged default stack, as do all
72 selected certified-chain controls and both allocation-owner controls. The
complete rebuilt 66-control group04 replay now passes, including both previously
failing pin fixtures. The fixture seeds its initial fee-owning domain and its
canonical golden is regenerated by the maintained genuine producer; ordinary
replay verifies all ten changed leaves. The explicit allocation-credit refund
control also passes. The separate CoreZK libtest now compiles after canonical
import repairs, without changing witnesses or assertions; all eight bootstrap,
canonical-stream and shared-capacity controls pass. Its original compiler-input
audit refusal remains retained. A supplemental audit checks the actual IVM sample
readers against every original compiler observation before admitting the copied
native artifact.
The earlier 4,132-execution partition (4,040 passes, 17 failures, one stack abort,
49 unexecuted and 25 deferred heavy controls) and its 49-control tail (36 passes,
nine boundary failures and four stack aborts) remain retained; later passes do
not rewrite those outcomes. All four lane time-floor/build-count regressions pass.
The fresh lifetime compile-fail doctest passes; the separate Primitives 333 and
Norito derive 59 unit, 17 strict-JSON and 32 compiler cases in four UI tests pass.
Full Mint/Guard/receiver, genuine proof/export and full-State authority remain
incomplete. The separate current fixture captures 106 typed codec owners and 1,559 nominal
identities, preserving the 1,551 still-active historical hashes. Its new ordinary,
publication and reduced-feature controls remain pending; the preceding capture
and native component runs do not qualify the merged candidate.

The fresh Linux and Mac optimized privacy artifacts pass all 133 private-dispatch
controls, including all eight direct-jump and eleven CALL descriptor/frame-work
controls, with no failures or skips. The earlier 148 ordinary RFC controls with
four explicitly ignored and both actual ignored RFC auxiliary oracles remain
passes on their recorded artifacts. The original scalar scratch
bound and every clearing assertion remain. The earlier 106-group run's 103
passing and three failing groups are retained; the failing LOAD/RFC cases have
fresh native repairs, while four reviewed PQ profile pins are applied and
require their original complete KAT. All original FFT oracles and nonce controls pass.
The complete current ordinary privacy suite requires a fresh native census and
execution after the combined arithmetic and dispatcher changes. Applied DER/RFC
constructor repairs replace eleven private-zero inversion sites with the
canonical fixed schedule while preserving malformed-input effects. Fresh complete
DER/RFC tests and actual compiled-caller review remain required; parser, activity,
sorting and other private branches remain outside whole-prover qualification.
Test-only public phase counters now separate composition joins and source adapters;
the fixed diagnostic receipt grows by 1,680 bytes within the existing runtime
reserve, without changing proof, time, RSS or address-space limits.

The latest Linux maximum (`epoch26-rfc-linux-maximum4`) produces **9,412,944
bytes** on corrected profile
`fb4dc4d0b2ce277e23d3de9d4ccd6c32c9a9b0ef5b39f7c963f8b914cf15860b`.
Producer self-verification, independent replay, wrong-genesis, corruption and all
32 nonce-byte substitutions pass. A separate fresh public verifier passes in
**7.977963 seconds** without regenerating the proof. Conservative reported RSS is
7,163,871,232 bytes; sampled address space has an 8,709,255,168-byte observed lower
bound, not an exact measured peak. The unchanged limits remain 9,437,184 proof
bytes, 12 GiB RSS, literal hard/soft 32 GiB `RLIMIT_AS` and **300 seconds**.
Proof size and memory gates pass, but proving takes **1,437.185689 seconds**, so
the complete maximum still fails. All 65 phase timers, exact test artifacts and
full source observations pass their custody checks. Nested timers are not
additive; the 11.59-second terminal-link phase is too small to explain the gap.
The preceding Metal maximum verifies the complete proof but fails the time and
Darwin address-space gates. Earlier failed runs and observer records remain
retained. Complete current ordinary coverage, integrated and cryptographic
qualification remain open; no cap or supported shape is relaxed.

FASTPQ maximum ordinary and AXT proofs and fresh verifier replays pass on their
recorded preceding candidate. The current optimized hardware artifact passes
57 selected controls, including all nine mandatory Metal controls on the M1 Ultra,
affine next-column checks and secret-buffer ownership. Other hardware, whole-prover
side channels and concrete cryptographic qualification remain open. The current
four-validator finalized-transcript scenario now passes after replacing unsupported
iterable queries with exact authenticated transaction details and exact asset
queries. Its bounded peer-local status is only a locator: the original contiguous
finality verification still starts from independently provisioned genesis. Both
transfers retain identical certified transcript bytes on all four peers before and
after restart; all eleven source substitutions, foreign-network, malformed-wire,
committee and cross-carrier checks remain. The actual run takes 155.13 seconds;
the new local-Applied/height refusal control also passes. This establishes native
finalized transcript custody, not the complete q77 relation or D7 source/spend
admission.

The rebuilt current host passes its loaded ABI-25 probe and all ten authentic
fixture modes, each generated twice with identical paired bytes. All eight
current Kotlin tasks pass: **2,498 tests**, zero failures or skips, including
1,859 JVM, 30 tooling, 422 Android client managed, 91 wallet managed, 95 client
host-JNI and one wallet host-JNI controls. The genuine native confidential
redemption example and tooling distribution also pass. The native consumers
load the rebuilt host image. Android ELF audits were not run in this cohort;
earlier ARM64/x86_64 132-method audits remain scoped to their recorded artifacts.
The Darwin host's four Android-only absences are explicit. These results do not
qualify physical devices or later source changes.

The physical Android main and instrumentation APKs are genuinely built and pass
native ZIP, signature, package, permission and complete 3,276-class checks. They
contain the 20 selected local controls and no INTERNET permission. USB device
connection has been requested; no physical-device result is claimed. The preceding
Apple package completes all five native targets and three XCFramework slices;
fresh packaging is held until the X509 profile and native fixture corrections
are validated.
The original projection-wrapper environment failure remains separate from the
successful official-environment projection and authentic Swift pin adoption. The
initial full Swift suite records 2,357 passes and one compact metadata reader
failure. Correcting its string lengths to canonical varints preserves order,
tag, signature, metadata and full-consumption assertions. The focused test and
complete 2,358-test replay pass without failures or skips. The unsigned arm64
iOS example test build now passes after canonical Darwin handle, UTF-8 buffer
and exclusivity repairs. Both maintained demo bridge sources pass 32 native
envelope cases. The retired raw-hash callers are replaced by canonical SDK key
derivation, and the genuine ABI-25 symbol probe passes. The canonical
wallet-request SDK suite passes all 12 controls. Both maintained simulator
classes pass without failures or skips: 18 tests in NoritoDemoXcode and 19 in
the NoritoDemo template. Controls cover entropy refusal, low-order keys,
approval verification before key installation, immutable launch bindings,
replay/substitution refusal, session renewal, stale HTTP publication and bearer
credentials kept out of URLs and logs. Both demos route OS wallet-launch URIs
through the SDK-owned canonical request; the original Open is consumed once, and
signed approval is verified before its one frame is prepared. Retired socket
callbacks cannot publish into a replacement session. Deterministic tests
preserve all 256 repeated-byte session values through canonical standard Base64
and unpadded Base64URL while refusing malformed aliases. The earlier decode and
test-owner failures remain retained. The template builds its maintained sources
through an ignored generated project. These are actual consumer tests of the
recorded Apple package, not native qualification of later Rust changes. Physical
iPhone testing and signed release artifacts remain outstanding. A
development-signed diagnostic APK does not satisfy release signing.

The earlier stock workspace all-target pass remains scoped to its recorded
source; concurrent edits prevented fixed-candidate qualification. The latest
merged-source check and applied fixture corrections are recorded above. The
script and typed-workflow passes do not replace native workspace coverage.
The recorded strict all-target Clippy run failed with 146 rendered error blocks
before subsequent mechanical and test repairs. Fresh strict lint and unresolved
production proof-owner joins remain required.

The current daemon, CLI and integration harnesses build. Real
four-validator transaction commitment and lane P2P restart pass in 37.116 and
114.416 seconds. The wallet proof-record replay now builds both native stages
and observes exactly four validators. It passes the encoded `halo2/ipa` path but
fails after 165.74 seconds with HTTP 502. The production proof fanout requests
JSON and feeds it into its strict Norito decoder. The explicit Norito request
repair and regression are applied. The fresh native router artifact passes all
23 strict-target, proof-route and retention controls without skips. Genuine route
authority, exact block-hash publication refusal, canonical missing-route envelopes,
both 404/503 precedence orders and JSON/Norito grace-boundary counts pass.
The complete four-validator wallet replay remains required. The complete workspace tests, current fixtures, source-bound
network checks and remaining cryptographic/device/release evidence remain open.

### ZK01 — secret arithmetic

Vega private commitments use fixed-window secret MSM, public dimensions and
clearing scalar owners. ZK-ACE borrowed private preimages and reachable hashing
scratch clear. Accelerator allocations clear only after observed completion;
unknown completion quarantines their owners and blocks further private admission.
Compiler-created copies, device timing and independent review remain ZK06.

### ZK02 — optional confidential inputs

Absent inputs require no empty-leaf path. One owned note can be fully redeemed at
the 65,536-leaf maximum, or redeemed with private change. Ownership, range,
conservation and nullifier constraints remain enforced. Canonical replacement
keys reject superseded keys. Same-candidate network, distribution and device
qualification remains open.

### ZK03 — complete proof semantics

`zk::verify_for_relation` admits only an explicit role supported by its compiled
relation. IVM replay-binding circuits, registrations, keygen, service routes and
associated SDK/CLI consumers are retired. Production `IvmProved` admission stays
closed until the complete native transition relation and authoritative finalized
State binding exist; G3 in the [IVM goals](kotodama_ivm_completion.md) owns this work.

RAM-LFE registration, activation, restoration, evaluation and receipts reject the
insecure signed/proof BFV modes before private work. The exact-lift profile loses
public-key noise modulo 257. The diagnostic interpreter's clearing tape, bounded
initializer, reduction and commitments are prerequisites, not an execution proof.
Secure encryption replacement, exact refresh, malicious-key/input validation,
circuit privacy, the complete program relation and integrated qualification remain
open under the [replacement contract](ram_lfe_encryption_replacement.md).
The [canonical V1 contract](ram_lfe_execution_proof.md#canonical-v1-contract)
(roles, leakage bound and lifetime query limit, three classes, function identity,
policy, receipt, opening and cleartext reference) is implemented as types,
commitments and tests; no evaluator, relation or Core path consumes it yet.

The candidate [packing](ram_lfe_plaintext_packing.md) and
[semantic](ram_lfe_semantic_commitments.md) interfaces preserve private length,
ordered scalar output including 256, clearing owners and explicit public
policy/key/profile/context binding. They authenticate no submitted key or proof.
Input and proof-envelope caps remain independently 1 MiB, with the configured
proof cap at 192 KiB. Input and output ciphertexts do not share the same input
frame; complete replacement proof encoding and total working memory remain open.
A separate fixed-basis native RNS key-switch component passes ten native tests,
nine complete public-fixture parity cases and 16 adversarial/public controls;
independent review verifies its public roots, primes and exact division. Its
3,031,040-byte owned allocation bound applies only to that component. Native
policy/key custody, complete refresh, secure parameters and the full
program relation remain open; the component is not a qualified encryption
construction. The proposed full-ring N=131072/QP2725 refresh point fails its
ordinary-LWE quantum screen at about 122.165 bits against the 128-bit target. A
smaller mixed-width QP2589 candidate satisfies the conditional arithmetic bounds.
Its original nonfinite BDD run remains a failed screen; certified numerical
repair completes the twelve original attack cases, but the expanded ChaLoy21
quantum screen fails at 127.472 bits. The exact QP2571 successor passes twenty
ordinary-LWE model cases, with a minimum 128.4063 bits, and all five selected BDD
minima pass full-factor interval checks. Scoped ring-primal and small CRT
projection bounds do not establish joint ring, algebraic or related-key security.
The return key targets an embedded old-ring secret, requiring separate analysis:
its modulo-special-prime screen is incomplete, while the disjoint-digit model
has finite estimates but leaves its multimodal error structure unqualified.
The direct-bootstrap research candidate satisfies a conditional positive-width
refresh bound; the earlier public-key bootstrap construction fails that bound.
Its adaptive-key joint-randomizer reduction requires a separate Gaussian-RLWE
assumption, extractable common-secret admission, authoritative entropy and finite
sampling evidence. These are mathematical prerequisites, not implemented or
qualified encryption. The two-secret cycle, full refresh, circuit privacy and
complete program relation remain open. No candidate is selected or activated by
these screens.

The held native canonical-input/digit and key-custody experiment passes all
32 component tests. It owns both complete canonical ciphertext components,
derives balanced digits without an external digit stream, shares the original
allocation ledger, and applies each selected Galois automorphism to that retained
input. Complete manifest/key contents are authenticated before input work and
selected key entries are authenticated again from the same decoded bytes.
Substitution, allocation refusal, cleanup and arithmetic parity controls pass.
The combined modeled owned allocation bound is 4,079,616 bytes; actual test-process
RSS reaches 72,679,424 bytes. These remain public-fixture component results,
outside maintained production integration. Common-secret validation, secure
parameters, complete refresh and circuit privacy, relinearized assembly and the
full program relation remain absent.

The historical IVM library selection passes 1,026 controls, and all four selected
frame-initialization controls pass. The repaired memory-bank selection passes all
26 controls: seven initialization, ten LOAD and nine STORE. STORE fixtures now
capture the VM's initialized register values and preserve byte, log, gas, PC and
cycle assertions. The separate scalar/AIR
proof controls have no complete current-source result. Reviewed LOAD/STORE banks
remain unregistered prerequisites. Memory authority, initialization/history,
execution sequencing, integrated resource accounting and finalized State binding
remain open. All 15 private lifecycle/history/access controls pass in the
normal optimized native build. This component binds original private
dispatcher, Owner and Initialization ports and retains canonical inactive packets;
the added private descriptor/copyback and partial-dispatch relations pass their
26 selected controls before the merge. Both genuine native capture producers pass twice on source17 with identical
bytes, and all four original AIR consumers pass on those captures. These remain
component equations, not a complete private invocation proof.
Governed runtime availability now
has a distinct local deferral path, and publication checks the authenticated
registry and immutable cache without transferring local key ownership into
consensus state. Full instruction/region semantics, masking integration and the
original finalized State joins remain open.

The private dispatcher now constrains the original owner depth to the native
0..=1,024 range, with exact push/pop transitions and root depth zero. The native
limit has one shared owner; the reviewed change preserves its value. The private AIR depth controls and full-depth native LIFO/slot-reuse control
pass on source17 with default stacks.
The private dispatcher also has original-port scalar arithmetic, bitwise,
signed/unsigned/equality comparison and all six conditional-branch equations.
Branches use the same constrained predicate for the PC, require both native
operand tags to be public and preserve the original 21-port history join.
Prepared-contract admission checks both successors. Scalar, branch, alias/r0,
gas/cycle, degree and shared-bank controls await native execution on the combined
source. The same original ports constrain all seven native shift/rotate
operations, low-six-bit amounts, operand tags and native gas costs, plus NOT,
NEG and signed MIN/MAX. The comparison relation charges the native two gas.
All 65 private-dispatch controls pass in the retained optimized Linux artifact,
including coherent wrong-gas forgeries, seven unary/select controls, four
multiplication controls and four bit-count controls. POPCNT, CLZ and CTZ reuse
the original zero-prefix equations over canonical source bits with native
six-gas, one-cycle behavior. CMOV/CMOVI now bind the full public condition and
only the native conditionally read source and written destination. DIV/DIVU/REM/REMU
reuse the original arithmetic bank and preserve public trap-sensitive operands,
native gas and the original 21 packet ports. GETGAS binds the destination directly
to the original gas port, preserves its native zero-gas tariff and one-cycle
transition, clears the destination's private tag, and ignores both encoded source
bytes. Register zero remains unwritable, including at zero remaining opcode gas.
ABS constrains the public operand and rejects signed overflow. MEAN owns exact
65-bit signed addition and truncation toward zero, 44 shared result cells and
native two-gas/three-cycle behavior. ISQRT constrains the 32-bit floor root and
exact remainder in the existing product bank; DIV_CEIL constrains signed correction
in the shared MEAN bank; GCD uses bounded exact products and Bezout arithmetic.
The same append-only, bounded residue stream evaluates these shared banks without
accumulating or rereading private equations. Their original tags, history ports
and native gas/cycles remain constrained.

Successful LOAD64 and STORE64 relations bind the original memory, initialization,
frame, control and history ports in four phases. LOAD64 shares the dispatcher's
original atomic destination value/tag transition; its 37-packet schedule places
that destination after the physical memory read, with no duplicate register or
tag event. An `r0` destination suppresses only the register write, preserving
memory checks and the three-gas debit. Closed opcode selection rejects other
running operations. Native LOAD64 controls retain the admitted artifact and bind
the original value/tag, memory, frame and architectural transitions. Native
STORE64 controls bind original operand order, stored bytes and completion tariffs.
Complete instruction/region semantics and finalized State binding remain open;
these components do not enable IVM proof admission.

The separate callable-lookup component derives frame sizes and exact argument
and result word counts once from the original admitted artifact's complete flat
schemas. Child selection uses the existing canonical fetch columns and binds
the loaded-image target separately from the executable-relative callable entry.
Return selection uses the original active frame generation's protected entry
read, not the return continuation. The same lifecycle packets feed child
descriptor publication, return operands and all 4,097 initialization/copyback
cells without duplicate lifecycle producers. The composed evaluator joins all
8,243 original packets and 54 reserved zero gaps to their actual clocks in one
immutable global history view. It derives every current/next row and fixed phase
from that view; caller-selected row lists and reclocked producer copies are not
accepted. This establishes the complete 8,297-slot window's consistency, not
initialization authority or a complete invocation history outside the window.
Ordinary constructors cannot supply independent callable truth fields. The
composed relation retains the dispatcher's degree-four bound; callable and scan
equations have degree at most three. Admitted compiled returns remain nonempty:
Unit occupies one word, and a zero-result schema is rejected by admission.

The scan retains one funded, move-only 11,012,736-byte allocation and wipes its
private fields before release. Equation output uses reusable 721-field scratch
instead of accumulating scan/history residues. The 66,376 history rows require
log 17 under the existing public diagnostic profile; a second such window exceeds
that profile's unchanged 16,384-slot cap. The internal relation view can borrow
exactly one or two original segment banks with the same per-segment log 13..17
geometry. It uses absolute clocks, global first/last masks and the actual next
segment's lookup state, counters and auxiliary products across the seam. One
borrowed permutation challenge family serves the whole view and every callable
window; no window can substitute a second family. The view retains only fixed
column descriptors and scrubbed row scratch, without copying the backing banks.
This bounded component does not enlarge the public adapter's degree-four,
136-query, 4-MiB, single-segment proof profile. Joint base-commitment/transcript
ownership, aggregate FRI and masking, exhaustive native packet production,
full-invocation sizing and complete proof-memory admission remain open.
Root entry is deliberately absent: the presence of a
private callable does not authorize a public invocation. Recursive typed
traversal, TLV/canonical payload and privacy relations, staged gas and exact
faults, authoritative initialization and terminal publication,
statement/code/finalized-State binding and whole-invocation masking remain open.
This component has no production prover, verifier registration or admission path.

A separate native producer component now owns a fresh ordinary IVM invocation
from the original admitted artifact, selected public entrypoint and initial gas.
Its sole constructor accepts no warmed VM, initial memory/register arrays, host,
raw packet data or caller clocks. Coverage is restricted to empty public arguments,
a Unit result, no child calls or syscalls, and bounded public scalar,
LDI64/LOAD64/STORE64/root JALR execution with at most 64 total instructions
including the return. Packet
backing for all 16,384 private slots is partitioned from
original parent credit before execution. Native commit hooks capture actual
register/control and frame state, successful physical memory/initialization
changes, both staged root and result-validation debits, all 4,097 return-scan
slots and ordinary ZK padding. Unsupported reached operations refuse the local
capture before their effects; failed or unwound attempts publish no owner.
Final-owner cleanup erases payloads and packet metadata before refunding the
original charge; allocation and reservation refusals retain their original
typed ownership.

The native initializer/instruction/history component moves this original owner into a sole
source, projects one scrubbed packet at a time, and streams every original clock
through the existing private history relation with one borrowed challenge family.
It requires exactly the complete 16,384-slot history, including both global
endpoints. All 64 initializer slots, including reserved zeros, have linear
constraints derived from the admitted public entrypoint, its callable schema,
public initial gas and the V1 stack policy. These bind staged root allocation and
frame gas, registers, heap bounds, generation and protected frame/return words;
absolute fetch PC and relative callable entry remain distinct. The initializer
never derives expected values from captured observations or private-callable
presence alone. Its bounded instruction workspace admits public scalar ALU,
comparison, shift, rotate, multiply and bit-count operations, LDI64, public-root
LOAD64/STORE64 and root JALR through
the existing fetch/control/scalar relation. Additional native-source
equations restrict the selected original code words to that subset and require
the original return parent to be zero; constructor refusal is not an AIR premise.
Every compact instruction
captures an actual protected-depth read; the root return captures the original
depth before and after the native pop. All 64 compact windows and the fixed
return window are evaluated. Inactive windows have only zero packets; the former
synthetic running write is removed. All 65 private witness rows are funded before
construction and erased before their final backing refund, while the bounded
public code stays inline. The sole source owns both native packets and derived
workspace, so composed callers cannot substitute another packet bank.

The public scalar subset is exactly ADD/SUB/AND/OR/XOR,
ADDI/ANDI/ORI/XORI, NEG/NOT, SLT/SLTU/SEQ/SNE, signed MIN/MAX,
SLL/SRL/SRA, ROTL/ROTR, ROTL_IMM/ROTR_IMM, MUL/MULH/MULHU/MULHSU
and POPCNT/CLZ/CTZ.
The native producer and constrained consumer share the immutable instruction
operand-shape lookup. Actual source reads occupy the original left/right slots,
including `r0` and aliases; immediate and unary operations never invent a second
register read. One atomic destination packet carries the original value and tag
transition. Native subset equations require public operands independently of
constructor checks; the broader private scalar diagnostic bank does not authorize
general Secret arithmetic. Shared canonical word, ALU, comparison and barrel-shift witness
algorithms populate the existing fully constrained banks without expected-output
inputs. Shift and rotate counts use the low six bits while authenticating the
full original register word; rotate immediates are zero-extended eight-bit code
values and never authorize a register read. SRA preserves the original sign bit.
The full 128-bit product bank constrains the low and unsigned high halves,
including bounded carries and signed-high corrections for the first or both
original operands. Bit counts consume all 64 canonical source bits; CLZ alone
reverses the prefix traversal selected by the immutable artifact word. Zero has
64 leading and trailing zeros. Unused operand ports remain entirely zero.
Comparisons and rotates consume two gas, products three, bit counts six and the
other admitted scalars one; all advance one cycle and four code bytes. The canonical public gas
descriptor supplies witness debit arithmetic; equations bind the actual original
debit. Native packet geometry remains fixed. The shared instruction workspace has
1,512 fields per row, including disabled arithmetic banks; all 65 rows reserve
786,240 bytes before private construction. The composed maximum degree remains four. Conditional moves, GETGAS, division, branching and
fault outcomes remain outside this native source's coverage.

Public-root LOAD64/STORE64 consume the original compact memory and initialization
packets. Checked 64-bit address/end arithmetic and comparisons prove containment
in the immutable public root stack frame or public-leaf result region; native preflight
acceptance is not a permission premise. The shared scalar payload selection and
initialization OR arithmetic bind the selected half-cell, preserve the other
half, and require public payloads and the original generation. Its 64 additional
422-field witness rows reserve exactly 216,064 bytes before private construction
and erase them before refund. All nine other compact slots are constrained to
zero, completing the 32-slot compact schedule without synthetic events or clock
changes. LOAD64 requires complete containment in the stack frame and all eight
selected initialization bits; the result table remains write-only to guest code.
Both read ports preserve their original values. The original atomic destination
receives the selected half and a public tag, with no manufactured second tag event.
An `r0` destination suppresses only the register write, preserving memory checks
and the three-gas debit. LDI64 resolves its full 16-bit index through the same
immutable prepared artifact's admitted scalar table; pointer entries cannot
supply scalar coefficients or confer pointer provenance. Its one-gas debit and
atomic destination remain in the same dispatcher and history. Neither operation
increases packet or witness geometry. Memory equations have maximum degree three;
the composed instruction relation retains the existing maximum degree four.

The artifact-selected public Unit/Bool root return consumes its actual public-entrypoint callable, original
operands and every one of the 4,097 initialization-scan cells through the existing
return equations. Its additional 9,308,384-byte workspace is reserved before
private construction and erased before the original allocation is refunded;
scan packets remain solely owned by the native capture. The original NODE and
WORD debits are constrained separately to 1 and 8 gas with bounded subtraction,
and the original typed memory read must contain a public zero Unit word or a public Bool0/1. The retained artifact selects the exact one-node kind; no value or packet flag selects it. All four original u16 limbs are constrained, rejecting complete field-modulus aliases rather than reducing the word to one proof field.
The three occupied typed-work slots are consumed directly, with the other return
gaps constrained to zero; the callable-window diagnostic's zero-gap
schedule is not used for this native composition.
The sole `NativeInvocation::run_public_leaf_root` constructs a fresh ordinary VM
and retains its admitted artifact. Unsupported aggregate, pointer, private,
argument, child-call and syscall profiles still refuse this local component;
ordinary transaction validity is unchanged. Both leaves share the original
packet/scan/private workspace geometry. Unit equations and controls are retained;
Bool adds a degree-two low-limb Boolean equation with all upper limbs zero.
Authentic cross-crate Bool controls use this same producer, never raw packet or
clock inputs. General faults, jointly committed masked invocation/typed-output
columns, FRI registration, private/AXT admission and finalized-State authority
remain open. Local equation evaluation is not a native invocation proof.

The successful terminal bank consumes original return cycles and final public-leaf gas,
then constrains optional native padding at clocks 10,409 and 10,410. One 96-byte
zeroizing witness is admitted before private construction. Bounded delta bits and
an inverse require padding exactly when the public artifact's cycle horizon has
not been reached; checked limb subtraction charges one gas per padded cycle.
Disabled packets are entirely zero, and all 5,973 remaining packet slots must be
zero. Compact activity is a contiguous prefix of at most 63 non-return
instructions before the mandatory fixed root return. These new equations have
maximum degree two; the composed component retains maximum degree four.
Native gas/cycle summary getters are not expected-output coefficients. Final gas
is derived from the constrained original gas packets; no external output or
statement-authority constructor is added.

This closes bounded initializer, fetch/control/public scalar arithmetic and bit operations, admitted scalar literals,
public-root LOAD64/STORE64, public Unit/Bool return, compact scheduling, successful padding and
original-source history joins only. The successful private LOAD bank and native invocation both consume atomic
destinations; diagnostic setter logs are compared to that completed native
transition only in tests. General private/wide memory, pointer literals and other
instruction semantics, general typed validation and its staged gas, faults,
terminal statement publication and masked transcript ownership remain open. Native output and history consistency
grant no signed-intent/finalized-State authority or production proof admission.

The focused native capture bridge is runnable with
`python3 scripts/check_ivm_native_frame_equations.py --ivm-test-binary <exact-ivm-libtest-path> --privacy-test-binary <exact-privacy-libtest-path> --output-dir target/<fresh-directory>`.
It runs both native producers and all four exact equation consumers, retains
owner-only captures/logs and records executed binary hashes in a bounded local
receipt. Supplied binary paths do not establish common source/build provenance.
The captures check native frame/call-method equivalence; they do not supply
original instruction-packet ownership or a complete invocation proof.

A reviewed successful JMP/JAL rd0 dispatcher relation is applied with the
original 21 ports, artifact-bound signed target and native two-gas/one-cycle
controls. Eight tests cover native target/tag behavior, coherent control
forgeries, unsupported encodings, OOG/cycle limits, inactive producers, degree
and original private-history joins. All eight pass within the fresh Linux and Mac
133-control private namespaces. The successful CALL component also passes all
eleven controls: it binds the authenticated callable, immediate parent descriptor,
native validation rereads and exact frame-work debit through 47 original producers.
Its backward-call fixture now uses its actual reachable entrypoint. Argument
validation, allocation failures, return/copyback, complete invocation semantics
and finalized State remain unfinished; these components do not enable proof admission.

### ZK04 — FASTPQ

The public Quantity facade uses the masked bounded DEEP producer and independent
verifier. Expected statements derive from canonical authenticated context; proof
consistency alone does not authorize remote spending. Development replay APIs and
required-Metal readiness preserve their existing boundaries.

On the preceding fixed candidate, all 16 ordinary controls, both actual maximum
producers and both fresh verifier replays pass. The ordinary artifact is 972,623
bytes (SHA-256 `c6bc0bb2d94e49fd5743995c767c121d313933805ca8dc517ce7ff1126ffdfba`),
with 1,494,040,576-byte RSS; the AXT artifact is 1,020,465 bytes
(SHA-256 `10f633d4409cb54bf07608c0da49e8519f8cad34d242e532aebd38d6e22292b5`),
with 1,508,605,952-byte RSS. Actual child times are 836.194 and 874.408 seconds;
fresh replay times are 0.316 and 0.348 seconds. These are observed durations,
not quiet-host comparisons. Both fit the unchanged 1 MiB artifact, per-segment
2 GiB charged-payload and 2^42 work caps; payload accounting is distinct from RSS.

The same source passes 52 actual local hardware controls, including nine
required-Metal controls, independent hash vectors, NEON state/scratch clearing,
exact-root transform parity and both private-next affine AIR guards. Thirteen
actual entropy/preflight/owned-erasure controls pass separately. Production
mask sampling uses fresh fallible OsRng and bounded unbiased canonical-field
rejection; no test seed is admitted by the public Quantity facade. This covers
the available M1 Ultra, not every target or whole-prover side channels.

[FASTPQ readiness](fastpq_production_readiness.md) owns unchanged resource limits.
Independent ideal-QROM review now covers explicit public simulator/conditional
completion kernels, adaptive request channels and honest-conflict accounting.
The retained bound is below 2^-91 for at most 108 attempts and 2^32 oracle queries
under its explicit ideal assumptions; this is not a 128-bit work-factor claim.
Concrete Keccak/entropy, complete zero-knowledge/side-channel, remaining hardware
and complete finalized-source admission remain open. The current four-validator
native transcript-custody prerequisite passes, including full restart and source
substitutions; this does not complete q77/D7 admission. Changed candidates need
fresh integrated evidence; historical seeded CPU/Metal parity is not inherited.

The integrated ordinary candidate now binds the complete original execution-effect
tape and independently materialized statement roots, with a distinct ordinary
profile and canonical artifact layout. It preserves the AXT route. The mandatory
ordered-source census covers every input, including empty and rejected entries;
optional proof allocation refusal cannot erase execution effects or invalidate
consensus. The native finalized join consumes the published authenticated
execution and original captured source, checking the complete result and D7 leaf.
The lane retains that move-only source, cursor and original allocation pool through
backpressure, refusal and completion. Admission checks the complete source once
and hashes each original effect tape once; later work borrows individual entries.
The producer retains its mandatory verifier result with the exact encoded bytes.

The coherent 122-path candidate is applied, including the genuine fixture and
test migrations. Formatting found three nested test-module path errors; those
declarations are corrected without dropping assertions. Compiler/native checks,
fresh canonical profiles and ordinary/AXT proofs are still required. Historical
transfer-only maximum measurements do not qualify the changed ordinary relation.
Durable completion publication, recovery and automatic dispatch remain unfinished;
complete finalized-source admission and network qualification remain unavailable.

### ZK05 — ZK-X509

The current relation retains all 49 MAIN registrations, compact CA, the full
certificate/CRL/disclosure/ownership shape, key/digest byte joins and the original
masked trace owners. The joint protocol removes all 320 remaining public terminal
values through original-polynomial equations. Both auxiliary roots precede active
composition challenges; both composition and FRI-mask roots precede the common
DEEP point. All joint openings precede local mixing. The
[joint relation contract](zk_x509_joint_private_relation.md) records the exact
schedule, geometry and still-conditional algebraic ledger.

The public presentation window has one definition, recorded in the
[interval contract](zk_x509_presentation_interval.md): it starts at or after the
latest `notBefore` and ends at or before the earliest `notAfter` of every
certificate in the path, and ends strictly before the CRL `nextUpdate`. State
admission, the native relation, the DER-to-bounds helper, the in-relation
numeric rows and the RFC 5280 AIR base constraints agree on genuinely signed
boundary paths. The native relation and the DER-to-bounds helper are compiled
with the prover, for tests and the `privacy-release-evidence` feature only; no
SDK builds an X509 statement yet, and no complete proof was generated at those
shapes.

The latest Linux CPU maximum proof is 9,412,944 bytes, under the unchanged
9,437,184-byte cap, with SHA-256
`b69426bc8648cf1c492591371bbbfc4e18f1fe48a3d3f11108eb9ec2237ec7c0`.
Producer self-check, independent replay, a separate fresh verifier, wrong-genesis,
all 32 nonce-byte substitutions and corruption controls pass. Conservative
reported RSS is 7,163,871,232 bytes and sampled address space reaches
8,709,255,168 bytes; the unchanged 12 GiB RSS and enforced hard/soft 32 GiB
address-space gates pass. Neither observation establishes an exact physical
peak. Proving takes 1,437.185689 seconds against 300, so qualification remains
failed; fresh replay takes 7.977963 seconds. Exact receipts, retained proof,
65 nested phase timers and fresh replay are in
`dist/zk-remediation/2026-09-30/epoch26-rfc-linux-maximum4`.
Original failed runs and observer evidence remain preserved separately. These
results qualify only their measured source and do not transfer to later repairs.

Retained-query replay reuses original masks and authenticated Merkle cuts while
checking original roots and allocation capacities. The selected-coordinate
transform is correct in the current native controls and complete proof, but its
CPU performance needs repair. The new required 32-byte X509 instance nonce binds
dynamic MAIN/CA/joint hash contexts and consumes a separate checked RNG prefix.
Fixed schedule metadata stays unchanged. Its actual native maximum is now
9,412,944 bytes, with every nonce-byte mutation rejected. Authentic profile/proof/pre-aux values are
regenerated and independently checked, and the four primary diagnostics pass.
The merged descriptors enumerate the current 192 endpoint, 17 key/digest,
20 SHA-union and 108 CA-link alpha phases, retaining the claim-free joint wire
and 39 RFC lookup relations. Their current profile pin and deterministic
IO/Projection goldens bind the sole merged descriptor. Complete current-candidate
qualification remains required; earlier descriptor passes do not qualify it.
The scoped DER/profile fixture repairs now pass the 137 ordinary RFC controls
and both actual ignored auxiliary oracles on the preceding fixed candidate.
The repaired current ordinary RFC namespace passes 148 controls and both actual
ignored auxiliary oracles. Remaining accelerator coverage and a maximum proof
within the time limit remain required.

The applied composition repair preserves public coefficient extents through
zero values and cancellation, with full initialized-allocation erasure. Arithmetic
fixed preprocessing now fills its already-owned public matrix once per row,
reducing full row constructions from 44,564,480 to 2,621,440 across the five
maximum registrations while retaining eight-column IFFT batches. This is a
work-count reduction, not an isolated measured proof speedup. The rebuilt artifact
passes the original FFT parity controls and completes the maximum above. The
reviewed shared-power tables, compact P-256 retention and reuse of original
masked RFC coefficients are applied and complete the latest Linux maximum. The
mixed DEEP path preserves native replay for uncached sources and checks each
original opening before updating either weighted owner. The exact public-count
capacity repair retains the strict workspace check. Both Linux and Metal now
complete the proof and fresh verification; the unchanged time gate still fails,
and Darwin cannot enforce the required address-space limit. Complete ordinary
coverage and integrated qualification remain required. No
quiet-host full-proof speedup is inferred.

Full semantic, soundness, zero-knowledge, transcript and side-channel qualification
remain open. Conditional classical-ROM/masking derivations do not establish
adaptive shared-transcript simulation, quantum hiding, complete relation
correspondence or resource compliance. Soundness/resource activation pins stay zero.

### ZK06 — cryptographic qualification

Dedicated independent source reads, derivations and adversarial controls are
recorded against exact protocol artifacts. Their scope is explicit: component
arithmetic, conditional soundness/hiding bounds and authentic native verification
do not establish complete soundness, zero-knowledge, transcript security,
side-channel resistance or release qualification. RAM-LFE construction and full
IVM semantics remain absent. X509 now has a verified joint maximum proof, but
complete relation/transcript/hiding review and time compliance remain open.
The current nonce-bearing maximum and conservative resource observer have actual
fresh evidence; these controls do not establish whole-prover side-channel safety.

An independent bounded review accepts the source15 X509 classical-ROM argument
recorded in `epoch18-zk-dag-root3` and `epoch18-zk-dag-review-sdk3` under
`dist/zk-remediation/2026-09-30`. Its bound is below 2^-161 for at most 2^64
classical oracle queries, conditional on the reviewed algebraic/masking
prerequisites, a fixed statement/authority/geometry, one atomic proof, ideal
random oracles and independent random bytes. It does not establish adaptive or
multiple-proof security, qROM security, concrete hash/entropy guarantees,
side-channel resistance or failure-channel privacy. Subsequent source changes
require a fresh applicability review. Physical hardware and authenticated final
release artifacts require actual runs.

### ZK07 — developer workflow

Typed wallet workflows own clearing private inputs, canonical keys and circuit
selection; callers do not supply dummy inputs or transcript internals. JavaScript,
Python, Swift, Kotlin/Java and C# use the shared native owner with bounded inputs
and asynchronous custody. Managed strings do not promise erasure.

Historical host ABI-25 controls pass 62 tests with 397 expected exports, plus ten
top-up executions. Kotlin records 1,562 passes and six full-tree controls; Android
host/JNI consumers pass 291 tests. C# records 6,015 passes. Installed Python passes
4,370 tests plus 281 subtests and five genuine maximum-tree wallet controls.
Normal Kotodama generation and all 57 official sample mappings pass.

The last tested pre-merge host library passes a normal locked Rust check, test build
and dylib build. The actual loaded image reports ABI 25, exactly 359 exports and
117 Kotlin JNI symbols; all 38 retired Java-Android aliases are absent. All 674
ordinary bridge controls pass on unchanged source after the fixture repairs.
Two genuine top-up fixture-producer executions are byte-identical to each other
and the canonical fixture. Ten authentic Kotlin fixture modes also run twice
with identical output. The subsequent Kotlin consumer run refuses the changed
source before starting Gradle. Current merged native, Kotlin, Swift and device
qualification remains open.

Historical evidence covers all five Apple slices and ABI-25 package/resource
checks. The current Apple builder uses stock pinned Cargo and the original
authenticated root lock; it rejects compiler/configuration overrides and retires
the temporary compiler wrapper. Its source and workflow owner controls pass. The
current five-target Apple package, authentic Swift pins and complete 2,358-test
Swift host suite pass. The original metadata reader and projection wrapper
failures remain retained. The unsigned arm64 iOS test build and both maintained
demo simulator classes pass with canonical SDK cryptography, explicit entropy
failure and bound approval/session custody. Current native-package,
physical-device and release-signing qualification remain open. The historical
JavaScript suite records 3,634 passes and 15 failures in bundle accounting,
manifest fields, scope and artifact identity. The original official Node unit
profile records 3,840 passes, 38 failures and no skips among 3,878 tests.
Maximum full-tree unshielding with one owned note and all 65,536 occupied leaves
passes, as do its adversarial controls. The retail raw-byte correction preserves
both identical genuine producer outputs and the canonical fixture. A fresh
official addon build passes all 160 controls on its recorded generation across
seven complete affected files: compiler, source-capture, Norito, Parliament,
retail and validation-fee consumers. Original failures remain retained. Full
official unit replay on the final generation remains pending; the focused run
does not qualify the browser distribution or the full profile. The maintained
golden producer emits two identical sets of 61 outputs, now adopted. Rebuilding
the current Kotodama compiler then produces the canonical JavaScript artifact
fixture twice identically. All 16 Rust artifact-admission controls pass,
including the eight original negative cases previously blocked by stale ABI
bytes; no assertion is relaxed. These are component results, not integrated SDK
or release qualification. The managed bundle/checkpoint selection passes 34
controls, and browser module ownership and unchanged bundle caps pass on their
recorded inputs. The retained authentic ABI-25 C producer independently
reproduces both canonical assessment markers and intent hashes twice, with exact
decode roundtrips and eight malformed-input refusals. Its 2,513 recorded
compiler inputs and artifact identity remain unchanged; this confirms the shared
fixture without substituting for the JavaScript addon or consumer run. Reviewed
corrections retain strict parsing and unchanged bundle caps; the reconciled
manifest and bundle/replication proposals pass five and 35 focused managed
controls. Full integrated/native rerunning remains required.

Historical Android native arm64/x86_64 libraries and diagnostic APK packaging
pass source, native-payload, signature, manifest and six-method DEX census checks.
Dependency resolution recovered the original offline-cache packaging failure,
which remains retained. Physical testing requires rebuilt current packages and
a connected device. The diagnostic APK's debug signature is not release signing.

A genuine merged-base Core/Kagami finalized-execution fixture producer and
public SDK bridge consumer pass. Paired schema, query/native fixture generation
and the executable examples also pass. The current maintained golden producer
generates two byte-identical sets of 61 outputs, and their authentic projection
is adopted. The fresh compiler's paired JavaScript fixture and all 16 Rust
artifact-admission controls pass. The top-up producer's two executions and eight
consumer controls pass. Current installed consumers and packages, physical
Apple/Android evidence and signed final artifacts remain open. The candidate RAM
interfaces and stable unavailable errors confer no encryption qualification.
Public guidance belongs in `iroha-docs`; this checkout's build and validation do
not depend on that sibling repository.

### ZK08 — current source contracts

Earlier seventeen-target Core/Kagami builds and whole-workspace all-target
checks pass on their recorded inputs; the latest merged-source build failure
and applied fixture repair are described above. The original 247 obligations have
complete native component evidence as listed above; combined-source workspace
and SDK qualification remain required. Current
four-validator transaction commitment, lane restart and FASTPQ transcript custody
pass. Wallet proof-record routing now requires native replay of the binary
response-format and fixture-owner repairs. The fresh strict workspace Clippy run fails as recorded above; its repairs
and rerun remain required. The earlier selections
below remain historical evidence, not inherited current-candidate passes.

The historical `051df111` build passes workspace all-targets checking and Core/Kagami,
Torii/bridge, CLI/daemon and both network-test targets. The default Core selection
passes 1,145 tests across 70 groups with no failures or ignored tests. The original
247-control map has 246 exact-name passes and three genuine producer/consumer
controls replacing its retired fixture control; all 251 later selected names
also pass. A separate normal optimized Core build and all eight AXT proof
controls pass on unchanged source, for a 1,153-execution union. The original
retained selection accounts for 1,152 executions; the extra current test covers
authenticated-genesis successor ordering and rejected-interval poisoning. The
earlier source-drifted run remains unqualified.

Both four-validator component controls pass on that unchanged source:
transaction commitment and lane transactions across a full network restart.
Each observes exactly four concurrent daemons. These are component scenarios;
finalized FASTPQ authority, wallet workflows and full release qualification
remain open. Compiler artifact recovery never converts a failed command into a
pass.

The pre-merge private SHA/RFC production and optimized test builds, three authentic
pins and all 1,061 selected ordinary controls pass. Genuine Core/Kagami/SDK fixture
production and all 674 ordinary native bridge controls also pass. The Core run
records 1,084 passes and 30 failures among 1,114 executed controls; its last group
overlaps the merge and 66 planned controls are unrun. Source guards refuse later
privacy, MV and Kotlin stages. The applied committed-marker and fixture repairs need
one fresh integrated source, genuine producers, expanded Core controls, workspace
checks and four-validator scenarios. Historical failures remain failures. The
unadapted release-evidence Python suite passes 130 tests on its recorded source.

## Remaining execution sequence

1. Replace the insecure RAM-LFE encryption construction, retire diagnostic public
   surfaces, and complete its semantic relation and current SDK/consumer controls.
2. Preserve the clean FASTPQ maximum ordinary/AXT production and replay evidence;
   qualify finalized-source network and hardware behavior without changing proof
   or resource limits. Rerun affected proofs after any protocol/source changes.
3. Complete X509 relation/transcript/hiding review and repair measured CPU time,
   preserving the conservative resource observer, with native parity, independent
   review and another complete maximum proof under
   unchanged coverage, byte, memory and time limits.
4. Complete IVM G3's native execution relation and finalized authority. Validate
   rejection of retired APIs and relation-confusion attempts in current consumers.
5. Capture one integrated source after the reviewed repair cohort; rebuild SDK artifacts,
   run applicable workspace checks and current four-validator tests. Preserve
   `3f + 1` committees, exact `n - f` certificates and no idle empty blocks.
6. Complete dedicated independent protocol/side-channel review and run the
   physical-device and authorized release-signing workflows. Each qualification
   claim requires its corresponding artifact-bound evidence.

## Evidence discipline

Normal builds, immutable executables and retained artifacts identify the tested
source. Distinguish a structural resource charge from measured process RSS,
a component proof from a complete credential, and local verification from
finalized network authority. Record failures and unexecuted checks explicitly.
Do not restore retired surfaces, bless changed source hashes, bypass native
provenance or relax proof/resource ceilings to obtain a passing result.
