# First-release history and cutover

Contract of task T.1 of the [ZK delivery plan](zk_delivery_plan.md). Its factual
part is [`first_release_history_cutover.json`](first_release_history_cutover.json),
which `scripts/check_first_release_history.py` checks against the source
(`pytest pytests/scripts/first_release_history_guard_test.py`).

This is an engineering rule, not a protocol activation. Editing this file, the
inventory or the plan authorizes no reset, deployment or movement of live value.
A live cutover is a separate operator decision carried out with the existing
signed deployment and reset tooling.

## One history per genesis

A history is one signed genesis and the certified blocks built on it, all in the
current canonical layouts. The genesis hash fixes the `NetworkId`, the consensus
instance peers bind in the handshake, and the network a Kura store is bound to.

Strict startup (`iroha_core::sumeragi::node::prepare`) starts from an empty
State: it re-executes the stored genesis, replays every stored block, compares
each result with the block's CommitQC, and finally compares the advanced World
accumulator with a cold capture. Any difference is `NodeError::Replay` and the
node does not start. A store whose durable journal names another network is
refused before a State is anchored to it, and a supplied genesis that is not the
stored one is refused before anything is applied.

Every history-bearing wire type admits exactly one version (`history_wire` in
the inventory). A stored block is the version byte `1`, the Norito header with
the fixed V1 flags and the canonical payload. Storage, block distribution and
genesis loading decode only that framed form (`decode_framed_signed_block`),
which refuses other versions, headerless payloads, other header layouts and
non-canonical encodings. `SignedBlock` has no dedicated headerless decoder or
framing helper: `SignedBlock::canonical_wire` is the only framer, and the guard
refuses the retired helper and the retired `DecodeVersioned` implementation
anywhere in the source (`retired_identifiers`, `retired_impls`). A test that
needs another frame assembles it locally and asserts its rejection.

Two residual forms are open findings, not accepted wire:

- `SignedBlock` still has a headerless versioned form (T1-A16).
  `EncodeVersioned` emits it, and the generic
  `iroha_version::codec::decode_exact_versioned` decodes it for any type that
  implements `Version` and `DecodeFromSlice`. Storage, distribution and genesis
  loading use neither. The guard refuses the explicit call
  `decode_exact_versioned::<SignedBlock>` in production source
  (`test_only_references`); it cannot see a call whose type is inferred.
- Norito's `[u8; N]` leaf decoder accepts N packed bytes besides the emitted
  array of N length-prefixed elements (T1-A17). A headerless or inline decode
  therefore reads two byte strings as one value. The frame decoders compare the
  source with the canonical encoding and refuse the packed one:
  `framed_block_rejects_packed_confidential_digest_hash_arrays` shows that for
  the two hashes of a block header's confidential digest, in the ordinary and
  in the prepared decoder.

Retired on-disk artifacts are refused by name and never opened. The inventory
(`retired_store_artifacts`) lists every refusal with its function, its call
from the Strict open path and the names it refuses.

## Ordinary change

A change is ordinary when a node built from it starts in Strict mode on a store
written by an earlier build of the same history and reaches the same heights,
block hashes, certified results and World root.

Two kinds of test hold this. Within one build, `replay_tests` cover cold restart
and full replay: four validators write on-disk stores, every store is closed,
reopened and replayed with nothing else supplied, and real peers restart. Across
builds, `fixtures/core/first_release_history` pins the frames an earlier build
persisted together with their block hashes, World root and execution tip;
`pinned_history_of_an_earlier_build_replays_to_its_pinned_state` stores those
frames, reads them back from disk and replays them. A change that fails it is
not ordinary.

The pinned history is small: the node-test genesis and two blocks of `Log`
transactions. It detects a change to the block or transaction wire, to genesis
execution, to the certified result or to the World root. It does not exercise
every instruction, proof or contract; a change to one of those is classified by
the table below.

`fixtures/sumeragi/native-finality` holds two checkpoint frames of the certified
result. `tracked_native_checkpoint_fixtures_are_the_current_exporter_output`
compares them with the exporter's output of the current tree and with the sizes
and digests `capture.json` lists for them. The `generator` block of
`capture.json` records the capture itself: its source digests are those of the
day of the capture and are not compared with the current sources.

`iroha3d --check-storage` decodes every retained block of a stopped node with
the candidate build, and `iroha3d --check-config --json` prints the values peers
and the signed genesis bind. They are read-only diagnostics an operator may run
before installing a binary. They are not a deployment prerequisite.

## Deliberately incompatible change

A change is incompatible when it alters the bytes, validity or certified result
of anything a stored history contains. In the same change it must:

1. replace the layout, relation or semantics directly: no old-layout decoder,
   old-verifier branch, version dispatch, migration shim or compatibility alias;
2. regenerate every artifact the inventory lists for its surface
   (`incompatible_change_surfaces`, each with its generator or checking test);
3. state its cutover in the pull request;
4. make no claim that the previous history replays in the new binary.

| Id | Surface | Cutover | Also regenerate |
| --- | --- | --- | --- |
| `wire` | Block, transaction, entrypoint or query wire | `fresh_genesis` | Signed genesis, SDK fixtures and bindings, `norito.md` |
| `state_layout` | Instruction, event or State layout | `fresh_genesis` | Schema identities, OpenAPI, the owning spec |
| `execution_root` | Certified execution result or complete World root | `fresh_genesis` | `specs/sumeragi.md` Appendix E |
| `genesis` | Signed genesis manifest or its consensus metadata | `fresh_genesis` | Deployment genesis files |
| `execution_semantics` | Gas, executor or verifier semantics of anything a stored block contains | `fresh_genesis` | Gas goldens and schedule hash |
| `abi` | ABI V1: syscall list or semantics, pointer types, `abi_hash` | `contract_redeployment`, and a fresh genesis when the history holds contracts or runtime-ABI records | The hash golden and every artifact that carries the hash: Kotodama goldens and manifests, compiler captures, contract artifacts, SDK fixtures; `crates/ivm/docs/syscalls.md` |
| `proof` | Proof relation, statement, transcript or parameters | `fresh_genesis_when_stored`: a fresh genesis when a stored block carries such a proof or State derived from it, otherwise direct replacement | Parameter and key artifacts, SDK builders |

The guard fails when this table and the inventory list different surfaces or
cutovers.

**Fresh genesis.** A new signed genesis starts a new history: a new `NetworkId`
and instance, and an empty store on every validator. The old store is not
migrated, re-rooted or partially replayed. Contracts are not part of genesis;
their owners recompile and redeploy them on the new history. The pinned history
is regenerated and its new `history_sha256` is recorded in the inventory in the
same change; the guard fails until both agree, so a regenerated history is
always a declared cutover:

```sh
IROHA_CAPTURE_FIRST_RELEASE_HISTORY_DIR="$PWD/fixtures/core/first_release_history" \
  cargo test -p iroha_core --lib capture_pinned_first_release_history -- --ignored
```

Without the variable the capture writes to a scratch directory and the tracked
fixture is untouched.

**Contract redeployment.** Admission compares a contract manifest's `code_hash`
with the hash of the submitted bytecode and its `abi_hash` with the ABI V1 hash
compiled into the node (`validate_manifest_hashes`); a mismatch stays a
rejection. Recompile `.ko` to `.to` and deploy the new manifest. Stored
deployments made under another `abi_hash` no longer replay, so a history that
contains any also needs a fresh genesis. Batch ABI changes per cutover.

The ABI V1 hash is recorded in the inventory (`declared_abi_cutover`). The guard
fails until the golden in `crates/ivm/tests/abi_hash_versions.rs`, every
regeneration target of the `abi` surface that states how it `carries` the hash,
and the inventory agree, so a regenerated hash is always a declared cutover with
its listed carriers. How a carrier is read depends on its form:

- A compiled program is read at its header. The artifact map
  `scripts/ivm_artifacts.tsv` lists the program files; a compiler capture
  (`fixtures/kotodama/*/native_v1.tsv`) is read row by row, both programs of
  every row; a fixture that embeds a program as base64 is decoded.
- A text carrier holds the hash, in each form its entry states, exactly as often
  as the entry says (once unless it states `occurrences`). One stale statement
  beside a regenerated one changes the count and fails.

Two limits remain. The guard counts the declared hash; it does not know every
field of a text carrier that could state a hash, so a new field with another
value is not seen. And the carrier list is maintained by hand: the guard reads
the listed files and does not search the tree for others. A change that
regenerates the hash searches for the previous one (`git grep -il <hash>`, and
the program headers through the artifact map) and lists every file that states
it, hand-maintained records such as
`crates/iroha/tests/fixtures/contract_code_readback/provenance.json` included.

The guard also fails when the pinned history holds the declared hash while the
declaration says no fresh genesis is needed. It compares bytes: it computes no
ABI hash and admits no contract, which `abi_hash_versions` and the admission
tests do.

Declared cutover, 2026-10-05: surface `abi`, cutover `contract_redeployment`.
Commit `a5d2617d6a` replaced the body of `CallSchemaV1`, the argument and result
schema of every contract callable, with the compact CS1 body, and rewrote the
`call_table_layout` clause of the hashed descriptor to describe it. That clause
is the only difference between the descriptors before and after the commit; the
syscall list, signatures and pointer types are unchanged and the ABI version
stays 1. The hash is now
`c7281066ec6f2fb47a2b0051c1d2ac95562f6ca7a576011cf173e07e845fdec1`. A contract
compiled before the change is refused twice, by the callable decoder and by the
manifest `abi_hash` comparison: recompile and redeploy it. No alias for the
former hash and no second decoder exists. The pinned history holds no contract
and no runtime-ABI record, so this cutover takes no fresh genesis. No live
network was changed.

Declared cutover, 2026-10-05 (ZK delivery plan task F.4): surfaces `genesis` and
`execution_semantics`, cutover `fresh_genesis`. Every limit, window, verifier
switch, relation-selecting key and verification gas charge that the ZK
consensus-policy hash binds is now read from committed State, the
`zk_validity_policy_v1` parameter, or from the protocol default; the node
configuration schema has no key for them, and genesis generators sign the
protocol-default confidential policy hash. Three things follow. A history
written by validators whose node configuration set other values of those keys
does not replay in this binary, which evaluates the protocol default: such a
network takes a fresh genesis that carries `zk_validity_policy_v1` (the tracked
Taira template now does, with its two non-default confidential limits). The
built-in `sora-nexus-v1` profile lost its `[static.zk.halo2]` key, so its pinned
consensus digest changed (`crates/iroha_config/src/profile/tests.rs`,
`digests_are_pinned`). And a node configuration that still names a removed key
fails to load. No decoder, alias or ignored key was kept. The pinned history
holds no such parameter and was written under the protocol default, so it
replays unchanged
(`pinned_history_of_an_earlier_build_replays_to_its_pinned_state`) and this
cutover does not regenerate it. No live network was changed. The inventory has
no key for this declaration yet; the guard checks only the `abi` one.

Declared cutover, 2026-10-06 (ZK delivery plan task F.4, pipeline limits):
surfaces `genesis` and `execution_semantics`, cutover `fresh_genesis`. The
sixteen execution limits of the pipeline (overlay bounds, IVM cycle and
decoded-program bounds, the quarantine lane, IVM query limits, the AMX budget
model and `dynamic_prepass`) are now read from committed State, the
`pipeline_validity_policy_v1` parameter, or from the protocol default, with the
same rules as the ZK policy above. The `[pipeline]` node schema has no key and
no environment alias for them, so a configuration that names one fails to
load; `[pipeline.gas]` is unchanged. A history written by validators whose
configuration set another value of one of those keys does not replay: its
signed genesis binds an execution-policy hash this binary no longer derives
from node configuration. Such a network takes a fresh genesis that carries
`pipeline_validity_policy_v1`. No tracked deployment configuration set any of
the keys. The default `ZK ballot` and `tally` verifying keys of `[gov]` are
removed from the node schema as well; no validation path read them once an
election commits its own keys, and their two (always empty) digest terms are
unchanged. The pinned history was written under the protocol defaults and
replays unchanged; this cutover does not regenerate it. No live network was
changed.

Declared cutover, 2026-10-06 (ZK delivery plan task I.1): surface `wire`,
cutover `fresh_genesis`. The ninth field of the signed transaction payload,
`attachments`, changed its type in place from the optional proof-attachment
list to the optional ordered intent descriptor with signed inline attachment
occurrences (`SignedAttachmentsV1`, layout in `norito.md`, "Signed attachments
and ordered intent"). The payload still has nine fields and a transaction
without attachments still encodes the field as the single `None` byte, so
every attachment-free transaction, the signed genesis and every block that
holds only such transactions keep their bytes, hashes and signatures. A
transaction that carries the former list no longer decodes: there is no second
decoder, version dispatch or alias, and the payload has a single decoder that
also checks the descriptor against the rest of the payload. A history that
holds an attachment-bearing transaction therefore does not replay in this
binary and takes a fresh genesis; a history without one replays unchanged.
The pinned history holds no attachment and replays unchanged
(`pinned_history_of_an_earlier_build_replays_to_its_pinned_state`); this
cutover does not regenerate it, and the other artifacts of the `wire` surface
were checked through their tests and are byte-identical. New shared vectors
for the layout are `fixtures/zk/signed_attachments_v1/vectors.json`. An SDK
that still encodes the former list produces transactions every node refuses at
decode. No live network was changed. The inventory has no key for this
declaration yet; the guard checks only the `abi` one.

Classify by effect on the stored history, not by intent. When unsure, run the
pinned-history test and the read-only probes against a store written by the
previous build.

## Obsolete histories

Keep evidence, not decoders. For a history that the current binary no longer
reads, retain as opaque bytes with digests: the stopped store, its signed
genesis and genesis hash, logs and exported telemetry, the last
`--check-storage` and `--check-config --json` reports of the build that wrote
it, and that build's source revision and build identity.

`scripts/first_release_history_evidence.py record` writes that manifest: every
store file with its size and SHA-256, the genesis, the two reports and what they
state about the history. `verify` recomputes the digests later. The tool hashes
bytes; it opens no store and decodes no block.

Diagnose an obsolete history with a binary built from the recorded revision.
The current tree gains no reader for it; a test that needs an obsolete shape
builds it locally and asserts its rejection. The Taira reset tooling follows the
same rule: a predecessor inventory is custody, never executable input.

## Snapshots and checkpoints

Restart is full replay from the signed genesis. Authenticated snapshot restore
is separate unfinished work: a positive-height snapshot does not replace native
replay today, and no delivery waits for it or assumes it.

A future authenticated checkpoint must state its height, block hash and
certified result, how they are authenticated against the genesis-bound
committee schedule, and the suffix it verifies: the blocks after the checkpoint,
replayed and compared with their certificates. It verifies nothing below its
height and cannot retroactively validate discarded history. A node restored
from one reports the height from which its history is verified.

## Halted chain

A chain that cannot commit is repaired by its operators: install a corrected
signed binary that still replays the current history, or carry out an explicitly
authorized reset. No on-chain approval, activation record or snapshot is part of
that path.

## Inventory and guard

The guard reads source text and the pinned fixture. It fails when:

- a history type admits a second version or a `Version` implementation is unlisted;
- a listed test disappears, is ignored or is conditionally compiled;
- the pinned history differs from its manifest or from the recorded digest;
- a history loader defines or imports a compatibility-named item that is neither
  a listed rejection helper nor a classified definition;
- a retired decoder or shim identifier reappears, or a retired trait
  implementation is written again (tests included);
- production source references a helper kept only for tests;
- a retired-artifact refusal changes its names, loses its call from the open
  path, or exists without being listed;
- a surface lacks a concrete artifact with a generator or checking test;
- the ABI V1 golden differs from the hash the inventory declares, a listed
  carrier does not carry that hash in every stated form (a text carrier the
  stated number of times, a capture or fixture in every program it holds), or
  the pinned history holds it while the declaration says no fresh genesis is
  needed;
- a probe or custody anchor of the obsolete-history evidence is gone;
- the section "Snapshots and checkpoints" changes or loses a statement the
  inventory lists, or the source no longer marks checkpoint restore as
  unimplemented, while the inventory is unchanged. This preserves the rule for
  future work. It is not evidence that a checkpoint exists.

The loader check is name-based. It does not see a fallback written inside an
existing function, a version `match` outside the `Version` trait or a neutral
name; review and the listed tests cover those. The guard does not run tests:
`--test-commands` prints the `cargo test` commands for exactly the listed tests,
and `blocked_test_targets` names targets that do not build today, so their tests
are not counted as evidence. The real-peer tests start `iroha3d`: their lines
are preceded by the daemon build and carry `TEST_NETWORK_BIN_IROHAD`, so each
line runs as printed from the repository root. Whether a retired artifact is refused at run time
is established by `every_inventoried_retired_store_artifact_stops_strict_startup`,
which plants each listed artifact in a real store.

`open_findings` lists compatibility constructs owned by other tasks, each with a
source anchor. `--report` prints them as `path:line`. When an owner removes one,
the guard reports the stale entry: delete it and list what was removed under
`retired_identifiers`.
