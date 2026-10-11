# iroha_kagemusha_proof

Native KAGEMUSHA step relations on PIPA-R (`iroha_plonk`). The crate depends
on `iroha_pasta`, `iroha_plonk`, `iroha_plonk_gadgets` and
`iroha_plonk_recursion`; it does not depend
on the legacy proving stack or node execution.

The σ API fixes the base-field RP57 transcript, Direct instances, the folded
IPA generator suffix, and one `Bounded` public-input column. Keys use the
canonical V2 descriptor; the reader rejects V1 descriptors and other transcript
or instance profiles. The `kgwvkey1` base-field Poseidon verifying-key digest
binds the descriptor digest, transcript representation, counts and ordered
commitment coordinates. The shared engine owns this digest definition.

## Protocol layout

The implementation follows G1 revision 4 and owner decisions B1, B5–B8 in
`specs/kagemusha_wallet_wire_v1.md`. Shared vectors in
`fixtures/kagemusha/wallet_v1_vectors.json` pin each field and digest.

Wallet framing now pins direct `u128` records/enums to 16-byte archived alignment,
with enclosing fields and inline arrays inheriting it. Shipping assertions preserve
all 26 existing frame padding values and retained-original layouts without changing
Norito primitives, decoders or frozen vectors as part of that alignment change.
Nine selected host codec cases passed in three runs, each with the same 3,435
recorded inputs and 33 local packages unchanged. Those recorded source cuts
cover frozen/retained frames, generated vectors and existing codec checks;
subsequent source changes require fresh validation. ARMv7 compilation, runtime
and physical-device byte parity remain separate qualification gates.

- The core has 33 fields and the rest has 8. The head is
  `P(kgwcore1, core || P(kgwrest1, rest))`; σ carries the rest digest.
- Poseidon digests are single canonical field elements. SHA-256 identifiers
  and byte nonces remain two little-endian `u128` limbs. Noncanonical
  Poseidon bytes are rejected before synthesis or native consumer acceptance.
- `credit_id = P(kgwcrdt1, Request body)` binds all 26 Request fields,
  including both account digests and the receiver's recorded blacklist
  version and root. The public input is the 26-field statement digest under
  `kgwstmt1`; its effect union has 9 fields.
- Send chains have 8 fields: prior chain, credit, receiver wallet limbs,
  ordinal, amount, fee, Request digest. Receive chains have 5 fields: prior
  chain, credit, payer wallet limbs, amount.

Both steps open an Active or Retiring predecessor, require distinct payer
and receiver wallets and a nonzero amount, advance sequence without
overflow, append a chain and commit the successor. Send debits `amount +
fee` from balance while preserving the lineage's burned-value restriction,
advances its ordinal, checks policy epoch and monotonic accepted time, and
raises the time floor. Receive credits without overflow and matches an
issued Request by wallet identity, so credential renewal does not invalidate
it. Pending, fee and consumed-credit transitions belong to native Advance
and Λ; σ binds their carried successor roots.

## Recursive sigma leaf

`q_sigma` checks own σ hard and optional incoming σ soft on one shared
verifier lane. It binds the complete witness-key digest to a circuit-fixed
allowlist and exports the same LE32-length-prefixed proof bytes in 31-byte
chunks (107 for k12 and 112 for k14). The parent A relation recomputes the
statement digest and checks the operation/mask selector and global mode rule.
One σ forwards a checked source-k claim; two σ use a hard local PIPA-AS fold
with the selected incoming claim and an explicit pinned k16 trivial input.
Public columns have explicit homogeneous PIPA-R types. These component
constraints remain separate from final recursive artifact qualification.

`QSigmaSource::source_circuit` reconstructs the fixed two-bus unknown source;
`QSignaturePlan::source_circuit` reconstructs the exact signature roles and root.
Offline construction and strict original-key intake share these factories. The
captured component selection passes source-layout parity, selector and
signature-key rejection and the monetary recipe checks
(`target/qualification/native-q-source-factories`). These checks grant no wallet
or full-catalog authority.

## Bootstrap composition

`admin_sigma::BootstrapCircuit` proves the exact zero-value initial G1 state,
empty maps/counters and statement binding at k12 with five advice columns;
its PIPA-R proof is 3,296 bytes. A authenticates the state credential and the
same-byte certificate/credential/receipt transcripts through the separate
2-variable/1-fixed signature Q. `a_relation::bootstrap` pins the provider and
root key and requires the credential, state/key and receipt bindings. Scheme
and relation identities are carried by those constrained objects, so the keys
can be built before the scheme identity that commits their finished inventory.
Native admission binds both carried identities to the authenticated installation.

Removing the former scheme constants in `BootstrapPolicy` and `OwnPolicy`
requires fresh A/W/Omega keys and catalog qualification. Earlier captures below
retain their original source scope; their keys do not qualify this correction.
The corrected two-scheme regression passes 1/1 in 289.24 s: both genuine
sigma/Q/A1/W/A2 chains have identical six source VK byte strings and exact
known/unknown layouts. A third actual sigma/Q/A1/W chain rejects a genuinely
signed certificate scoped to the other scheme before its terminal proof.
The administrative sigma suite passes 8/8 in 19.01 s. Source manifests, binaries
and logs are retained in `target/qualification/bootstrap-carried-scheme`;
corrected Omega/catalog and installed-wallet qualification remain open.

The actual sigma → Q_sigma → A1 → W → A2 test fits k16 and independently
decides every retained claim. Its context and every deferred opening are
retained; signature-role/root substitutions and dropped obligations fail.
The installed native Bootstrap producer also passes actual Tagged3 A1/W/A2
proving against those original keys. The shared native differential suite passes
all three selected Bootstrap/Load/Send tests; its binary/source snapshot is in
`target/qualification/native-tagged-differential-source.json`. These are
component checks, not time/RSS gates. See `specs/kagemusha_a_split_context_v1.md`;
final Omega/artifact, hardware and wallet acceptance qualification remain open.

`a_relation::native::bootstrap::Prover::from_artifacts` installs shared exact
`KeyArtifact` descriptor/VK metadata without retaining any proving key or
original PK bytes. `import_first`, `import_wrapper` and `import_terminal`
reconstruct the exact unknown A1/W0/A2 sources and return one owned PK for the
caller to borrow during its stage and release afterward. W0 binds the complete
installed A1 key digest, and A2 binds the installed W0 identity. Existing
`PIPAPK01` import checks source tables, copy mapping, selectors and commitments;
every import and borrowed proof boundary checks the full installed descriptor
and VK. Metadata consistency alone is not source or catalog authority.
Preparation verifies both Q proofs and openings, binds the original sigma tape
and decides its part claim. Native checkpoint verification uses verifier metadata
only. The captured Bootstrap original-import, borrowed-key, exact-proof-byte
and canonical-checkpoint replay passes1/1 in1,359.45 s
(`target/qualification/native-bootstrap-borrowed*`), including same-descriptor
foreign-stage keys, original/table/VK changes and five descriptor-profile mutations.
This busy-host component result establishes neither RSS, latency nor phone-memory
gates; its immutable binary and source drift are recorded separately. The installation owner must authenticate the
complete scheme/Q/root/stage catalog before granting a `NativeProofs` owner or
wallet-open capability.

## Load components

`admin_sigma::LoadCircuit` proves both state openings, exact arithmetic,
continuity and unchanged fields on the five-column k12 class (3,296 bytes).
`a_relation::load` parses one ordinary 282-byte ledger receipt and three signed
objects: the own Advance receipt, Enrollment certificate and current credential.
The ordinary receipt digest, scheme, asset, wallet, ordinal, amount and online
charge are bound to the same operation and state fields. Request, quote,
transaction, height and payer account digest remain bound by the exact receipt transcript.

The fixed native schedule has four Tagged3 A stages and three W continuations:
predecessor/recovery with receipt binding, Q_sigma, own Advance receipt, and
current credential/Enrollment. The native wallet verifies the ordinary BLS
certificate and counted receipt event against authenticated signed genesis and
epoch transitions before requesting the Advance signature. Under the selected
released-app/uncompromised-OS profile, that credential-bound signature authorizes
the exact Load effect. The monetary circuit does not verify BLS itself.

`a_relation::native::load::Prover::from_artifacts` retains seven descriptor/VK
identities. Imports reconstruct the fixed monetary source and authenticate each
original key. Runtime preparation verifies the predecessor, three Q proofs and
all monetary carried claims. Each wrapper binds its previous stage. Checkpoint
restoration preserves this chain, and the terminal exports its obligations to
Omega; it grants no monetary head alone.

The recursive finality circuits, source catalog, block-history prover, proving
cache, proof journal and finality artifact compiler are deleted. Direct BLS
verification needs no finality proving artifacts. Tests retain the exact captured
receipt, native certificate checks, monetary term binding and a genuine Load
composition harness. Changed A/W/Omega artifacts and real funded wallet exchange
require current-candidate qualification; see
[`kagemusha_native_finality_goals.md`](../../specs/kagemusha_native_finality_goals.md).

The Core artifact inventory also qualifies all sixteen sigma originals against
fixed compiled sources, one original PK at a time. Quota-enabled Send uses the
one-lane folded k14 recipe; other Send masks and both Receive selectors use k12,
and administrative selectors use their typed k12 sources. These recipes are part
of the sole native profile. Actual source generation, wrong-selector/changed-PK
rejection and public strict import under a genuinely signed inventory pass
(23.32 s; `target/qualification/native-sigma-source-qualification`). Returned keys
retain only exact descriptor/VK metadata. The current signed public-route capture
imports actual Bootstrap2Q/A1/W0/A2 (267.84 s) and Retiring2Q/4A/3W (309.06 s),
rejecting signed context changes, foreign manifests before storage and incomplete
final-Omega catalogs. Retiring retains an explicitly unqualified candidate Omega
(`target/qualification/native-route-omega-qualification`, zero recorded source drift).
The artifact namespace passes17 cases with6explicit expensive ignores (3.44 s),
including the independent14,513-byte native-profile preimage. The loader now
reconstructs each logical operation route, including fixed Send masks and the
native-authorized receipt binding for Load, then checks every A/W original.
Final Omega intake requires all52 qualified routes, exact terminal D/VK deduplication
in signed program order, common predecessor identity and the canonical compact
source. Its compiled placement recipe is part of the sole native profile. Complete
catalog runtime qualification and native wallet admission remain open.

`omega::native::Program::for_compiled_catalog` derives the compact placement from
unknown source metadata and ordered terminal keys. The k18 scratch trace plans
fixed-table occupancy only; guarded production replay remains k16. Its 162-byte
`compiled_policy_transcript` binds the exact constants and planner identity in the
native profile. `source_circuit` and strict original-PK intake share this recipe;
cloning a Program retains metadata only. The merged native binary passes 83 cases
with three explicit source-import sweeps excluded from that batch. The separately
rebuilt genuine rooted Bootstrap regression passes in 289.54 s, reproducing exact
unknown-source descriptor/VK bytes and original import before verifying the
3,712-byte proof/4,800-byte transport and both claims. Its executable SHA is
`4947f8d9643fa8841d9a38631ec579bf3a4d4527e7775028dc7dbff1fd48f447`;
recorded build/runtime sources and copied binary remain unchanged
(`target/qualification/merge-reconcile-root/fixture-capture`). The same capture
passes seven default Load/recovery/claim cases, with one explicit expensive case
ignored; the initial all-ignored Bootstrap invocation is retained separately.
Shared fixture bodies preserve all current builders and keep test registration
in their own harnesses. All proof test targets compile and pass scoped strict lint.
This single-terminal check establishes no full-catalog, latency or memory pass.

## Send composition

`a_relation::send` binds the exact payer credential, signed Request and held-fee
slot to the same state/statement cells and depth32 pending and fee map paths.
Zero held fees permit a total malformed dummy slot; enabled fees require the
exact held schedule and arithmetic. The receiver owns the Request signature.
Send separately requires the hard own receipt/current credential/certificate
Q and its mandatory fixed authorization task. `own::ConsumingProofCells` binds
its receipt digest to the exact 320-byte public transcript, predecessor proof,
both full-k16 transported claims and own sigma, including their lengths. The
mandatory `SendProof` task checks those bytes beside the hard predecessor;
the signature stage authenticates the same entire receipt tape in `D_ctx`.

The genuine mask0 chain composes all five A stages with two-bus Q_sigma and
Tagged3 A profiles. Every source proof is 7,744 bytes; stage maxima are
36,704 / 56,018 / 57,868 / 62,212 / 60,051 rows, all within k16. This includes
mandatory own authorization, exact consuming bytes, both maps and every
retained opening. The captured witnessed-key Bootstrap/Load/Send-mask0 catalog
passed under one actual compact Omega key: all signed source chains were rebuilt
under its digest, with exact source/outer key equality and native verification.
Each captured outer proof is 3,712 bytes; transport is 4,800 bytes. The current
helper instead uses the canonical native pinned-catalog source and original-PK
importer, with canonical checkpoint replay and a seed/extension API that rebuilds
both wallets under each new immutable key. The captured native-source run completes the immutable three-terminal
Bootstrap/Load/Receive catalog: it rebuilds both signed wallet chains under the
common key, proves accepted Receive, and closes its exact four outer obligations.
The actual terminal VK matches the planned key; all four selected claims decide,
dropping the fourth fails, and the resulting credit membership is retained.
Outer proofs are3,712 bytes and transports4,800 bytes. The run passes in7,069.43 s,
including original import and canonical checkpoint replay
(`target/qualification/kagemusha-receive/pinned-omega-accept/run.log`). Its Load
ancestry uses the superseded voucher trust construction, and its continuation
source predates the current constant-size context links. This is captured
component evidence; current source keys, ordinary-finality Load, corrected-burn
outer closure and the full terminal catalog remain unqualified.
Descriptor equality alone does not establish source equality. Fresh merged-wire
size tests retain the 1,723-byte Payment overhead: structural
3,456-byte sigma plus 4,800-byte Omega encode to 9,979 bytes, leaving 21 bytes
under the 10,000-byte envelope cap. This checks encoding, not proof admission.
These are three-terminal component results. The other seven control masks, full
uniform catalog and loaded-host/physical-device qualification remain open.

`a_relation::native::send` assembles each fixed-mask five-stage chain with
fixed Tagged3 columns and installed A/W keys. Its immutable catalog requires one
source for every mask0..7 and an authorized sigma selector for each; repeated
mask0 keys never establish catalog completeness. It checks the original predecessor,
both Q proofs and all carried claims, frames the complete consuming tape, and
retains source-bound proof/claim checkpoints for exact restoration. Its signature
stage uses the installed root policy and the original Credential, Enrollment
certificate and Advance Receipt. Fifteen native Send component tests pass in
`target/qualification/native-funded-send-unit-3`, including all eight sigma
selectors, original tapes, Q-export bindings, absent-fee dummy policy and import
bounds. The four new binding tests use fabricated signatures/proofs; genuine
proof admission is exercised separately. The
ignored `compact_predecessor_native_send_preserves_every_installed_stage_and_original`
passes all five A and four W native proofs under the original installed keys,
including exact-original checkpoint replay, in
`target/qualification/native-tagged-differential.log`. Its compact Load
predecessor still uses the superseded trust model described above; the result
qualifies that native component snapshot. The current producer replaces eager
retention of nine PKs with shared exact descriptor/VK metadata and per-stage
`import_a`/`import_w` calls. Imports now return source-bound verifier metadata;
each proof checks its complete installed identity before proof/fold work and
reconstructs temporary proving buffers, releasing them before verification.
Original-source validation still binds the preceding A/W key. The fixed five-stage schedules, all-mask catalog checks,
control semantics and transport limits are unchanged. The migrated regression
preserves source/table/key mutations and foreign stage-metadata rejection and
exact proof-byte comparison. Canonical Norito custody derives all nine payload
layouts from installed descriptor/VK identities, bounds decoding before allocation,
and restores exact proofs and claims through native verification. The preserved
regression now restores every payload into a fresh session. Its native-BLS-funded
run completed all five A/four W proofs and checkpoint replay, then exposed a
native preparation gap accepting a changed Credential tape. Preparation now
joins all five signed originals to their exact digests and Q exports; its fifteen
unit tests pass. The same genuine regression now passes from isolated capture3
in `target/qualification/native-funded-send-retry-1`: all five A/four W stages,
exact checkpoint replay and the original mutations complete successfully. The
failed capture remains retained; this is a component result under the captured
keys, not complete-catalog or wallet qualification.
The current proof library and five selected funded integration targets compile.
This ownership change grants no memory gate or wallet authority. The other seven
control masks and complete authenticated catalog remain required before admission.

Receive, Archive, Unload and Retiring preparation now also joins the wallet's own
Credential, Enrollment certificate and Receipt to the exact hard Q1 exports.
Receive and Archive bind their own statement and sigma tape to Q0 before costly
proof work. Incoming soft evidence keeps its existing circuit policy. These are
early admission checks; the mandatory circuit owners still enforce the complete
relation. Five new unit controls and mutations in the existing genuine
regressions are applied but await the next compiler capture and execution.

Incoming lineage decoding now preserves the original byte source and derives
the canonical/header/claim verdicts together. Exact active-byte ingestion
separates a padded verifier view from the original short or overlong input;
its total Receive composition and operation qualification remain open.
Receive now has fixed owners for all five soft results, hard current-credential
and receipt authorization, original signature tapes, and terminal map/mode
constraints. Content addresses are mandatory: substituted Request, package,
credential or certificate preimages cannot manufacture a burn. Captured complete ten-A/nine-W chains cover accepted, renewed and corrected-burn
branches under the earlier continuation source. The corrected carried-scheme
source now passes Bootstrap-only malformed-sigma Receive through final Omega in
1,614.99 s. It proves all ten A stages and nine W continuations, checks all nineteen
strict original imports, reproduces borrowed-key proof bytes, and restores exact
canonical checkpoints in a fresh session. Actual Q soft-fails the altered sigma;
exact re-signed originals remain bound, the consumed root stays unchanged and
adjusted spendable balance stays zero. This chain has no Load dependency.
All ten source layouts fit k16, with maximum 65,305 rows under the 65,529 ceiling.
A fresh immutable two-terminal Bootstrap/Receive catalog rebuild retains the
exact planned terminal VK. The genuine outer proof is 3,712 bytes in a 4,800-byte
transport; all four selected obligations decide, dropping the fourth rejects,
and burned-credit membership is retained. The captured binary is `eeff209e…44c32`
(`target/qualification/kagemusha-receive/bootstrap-burn-omega-carried-scheme`).
Build drift is confined to unrelated finality metadata, recorded with both source
snapshots. Earlier constant-context runs predate the scheme-policy correction.
Current accepted/renewed/corrected branches, ordinary-finality Load and full-catalog
admission remain open. These component timings are not performance gates.
The `receive_omega` harness registers thirteen funded native-BLS cases under
`native_load_tests`: accepted and corrected-burn closure through Omega, accepted
and renewed Receive, both corrected-burn insertion branches, nondeciding Vesta
correction, Bootstrap/Load and Bootstrap/Load/Send re-keying, installed-native
Send replay, Send authorization/map owners, and exact catalog identity for the
funded payer and two distinct wallets. They reuse the existing branch, source,
checkpoint and obligation assertions. The shared
first-Load fixture verifies the unchanged captured BLS receipt before key
production and reconstructs every predecessor in a fresh directory; the receipt's
execution identities remain synthetic component data. Compilation and execution
of these newly registered cases are pending. Run each separately, for example:

```sh
KAGEMUSHA_LOAD_OUTPUT="$PWD/target/qualification/receive-accept-1" \
  cargo test --release -p iroha_kagemusha_proof --test receive_omega \
  native_load_tests::funded_receive_acceptance_closes_all_four_outer_obligations \
  -- --ignored --exact --nocapture --test-threads=1
```

The output directory must not exist. Passing one component case would not qualify
the complete installed catalog, ledger-backed exchange or physical phones.
The `a_receive_native_bounds` target also registers
`funded_generic_omega_is_rejected_by_receive_payment_cap` against the same fixture.
It proves an oversized generic predecessor and Send source to exercise native
joint-bound rejection; it is not an accepted Payment. Its compilation and
execution remain pending, with the same fresh-directory requirement.

The own Receive credit, payer-wallet and amount are hard projections of the
same Request; changing those generated effect fields cannot turn a valid
Payment into a burn. Original incoming asset/recipient mismatches remain soft.
The staged Receive context retains exact active tape commitments and typed Q
instances, with four-bus internal A circuits and a three-bus terminal candidate;
internal keys cannot enter the final Omega catalog.

## ArchiveSent sigma

`admin_sigma::ArchiveCircuit` and `native::ArchiveProver` supply the single
`(ArchiveSent, 0)` sigma source shared by both Credited evidence forms. The k12
circuit opens both complete G1 states, binds the tag5 statement and sequence
advance, and preserves every core word except sequence, nonce and the committed
pending root. All rest words, adjusted burned value and permanent credit evidence
remain unchanged. It takes no evidence-verdict input and cannot refund value,
restore quota or authorize deleting retained Payment bytes.

Native Advance must authenticate the committed-root removal. A still binds the
retained Request/Payment/Credited originals, verifies evidence, and proves the
separate adjusted-lineage removal or no-op before durable cleanup. The sigma
component does not establish that complete ArchiveSent operation. The original
PK is admitted through the existing strict source/commitment importer against an
independently authenticated descriptor/VK and fixed operation; this requires no
additional PK-signature ceremony.

## Unload and Retiring

The fixed k12 `UnloadCircuit` and `RetiringCircuit` share the administrative
transition constraints with Load. Unload spends only the folded lineage's
adjusted available balance, binds the scheme/wallet/redeem-ordinal nullifier,
and checks its charge, counters and exact changed fields. Retiring permits
only Active → Retiring and synchronizes adjusted burned/pending values without
moving value. Both real native proofs are 3,296 bytes and verify their complete
opening; rehashed state mutations, overflow, invalid charges, burned-value
spending and reverse/repeated retirement reject.

`a_relation::unload` assigns mandatory hard predecessor/proof-byte, current
credential/direct Enrollment/own receipt, and recovery-map or retirement-state
tasks. Its fixed schema rejects missing, duplicated and misplaced owners.
The genuine Unload and Retiring component run passes all four A proofs and three
W continuations for each operation, with hard predecessor, own authorization,
original consuming bytes, maps and every opening decision. Each A proof is7,744 B.
The run's Bootstrap/Load ancestry uses the superseded voucher trust model, so it
does not qualify the ordinary-finality Load replacement. TODO: rebuild that
ancestry, qualify the complete Q → A → Ω chains, rebind their terminal keys into
the common catalog, and connect the installed wallet provider.

`a_relation::native::consuming` assembles the four fixed Tagged3 A stages and
three W continuations using installed artifacts. It checks original Q and
predecessor proofs, decides every claim, and restores checkpoints only against
the retained source context. Its terminal retains predecessor Vesta, current
Vesta and terminal-A opening obligations separately. The reader also requires the exact original public320/proof/claims tape and
rejects Omega transports above the common Payment bound before proof admission.
The current producer retains shared verifier metadata for four A and three W
stages and admits each original PK against its exact unknown source and installed
preceding key. The import drops the PK and returns a compact source-admission seal;
every proof checks full descriptor/VK identity before folds, reconstructs exact
temporary buffers, and releases them before verification. Canonical checkpoint
verification uses metadata only. Earlier captures passed all11 native consuming
component tests and compiled both consuming/Retiring integration targets; the
metadata-reconstruction API requires current validation. The preserved regression now tests
source/table/key mutations, per-stage foreign-key rejection, exact original
proof-byte replay and all7 canonical checkpoints restored into a fresh session.
`a_consuming_recursive::native_load_tests` registers two funded cases against the
shared native-BLS first-Load fixture: all-owner Unload/Retiring composition and
installed-native differential/checkpoint replay. Each reconstructs two exact
Load predecessors and exercises both operations. They compile in isolated
capture3 but remain unrun. Run each exact ignored selector separately with a fresh
`KAGEMUSHA_LOAD_OUTPUT`, as for the Receive cases above; select
`--test a_consuming_recursive`.
The captured genuine zero-balance Bootstrap-to-Retiring component passes1/1 in
2,246.38 seconds (`target/qualification/native-bootstrap-retiring-borrowed*`):
all four A/three W stages reproduce original proof bytes with strict source imports
and borrowed keys, all seven canonical checkpoints replay in fresh sessions, and
every unrelated state field and zero value are preserved. It moves no value and
does not admit a terminal Omega. Source/binary identity and concurrent source drift
are recorded in its manifest; the duration is not a performance gate.
Earlier consuming component results remain scoped
to their captured source and key-ownership implementation. Full catalog, installed
wallet admission and memory/latency gates remain unqualified.


## Archive state leaf

`admin_sigma::ArchiveCircuit` shares one k12 class across Receive-package and
`CreditStatus` evidence. The native proof is 3,296 bytes with at most 2,367
assigned rows. It binds both state openings and the statement, preserving every
core field except sequence, nonce and the removed core pending root, and every
rest field. Adjusted burned value and credit roots are unchanged. The map owner
separately authenticates both removals and selects the adjusted pending root from
the actual evidence verdict. Exhaustive rehashed core/rest mutations reject in
both evidence variants and both verdict branches.

Archive now declares ten mandatory operation owners and a separate hard Q0 stage. The hard own owner binds the current
credential, direct Enrollment certificate, receipt and exact tag5 sigma tape.
Two own-authorization component tests pass with genuine sigma/Q0/Q1 proofs and
original-byte mutations. Two result-context tests bind every proposed bit and
all original Status-opening limbs to the fixed complete owner set.
Typed result claims commit all three evidence verdicts and, for CreditStatus,
the original incoming opening under a separate internal-word context domain.
Incoming proof and terminal map owners consume these exact commitments; their
complete composition is still pending.

Canonical CreditStatus component hashes and Credited Payment/evidence hashes
hard-bind their exact preimages before any soft verdict. A substituted component
cannot manufacture a no-op. Noncanonical original references remain false and
retain the original transcript digest. The corrected Request receiver-credential
binding uses field8; its certificate-set field17 stays distinct. Six focused
delivery/status checks pass, including all-byte mutations and changed-preimage
tests under both proposed verdicts. Two retained-Payment tests bind its original
signed sources, exact opaque proof bytes and lengths, Send statement and pending
descriptor. Those fixtures explicitly do not claim historical proof validity.

The fixed Archive stage dispatcher requires every owner, the complete original
source schema, and Q1/Q2 at their authorization/signature owners. Constructor
tests reject missing or duplicate tasks, substituted categories and misplaced
Q verifiers. Incoming-source tests enforce the held Request's quoted credential
while retaining malformed incoming receipt bodies and signatures for their soft
owners. Status takes its carried proof digest from its exact original transcript;
a disagreement with the receipt derives false evidence without replacing those
bytes. That totality regression passes. Independent local source review found
no binding gap in the new dispatch, incoming, evidence, proof and result paths;
this is component review, not complete recursive execution or artifact admission.
The incoming signature owner also passes with actual Q2 proofs for both valid
and invalid signatures. Each proof is7,936 bytes; the isolated A owner uses at
most24,294 rows. Changed receipt bytes, signature, quoted key, verified verdict,
result proposal, context ordering, proof bytes/length and stage assignment all
reject, including after recomputing original object digests. Known/unknown
layouts match. These local Q2 proofs are not the transmitted terminal Ω.

The context-proposal regression passes for both the17-slot Receive and19-slot
Status schemas, including known/unknown layout equality, all three commitment
words, UInt32 overflow and missing-owner/schema rejection. These are untrusted
proposals until the fixed owners recompute their original sources. Native indexed
removal now emits both authenticated relink/clear paths, with both-field tests
for absent keys, the final u32 slot and permanent non-reuse after removal.

All staged producers now use one immutable operation commitment C and a small
fixed-stage commitment to C and the current Pallas claim under `kgwlink1`.
Hard verification of the exact previous W key and unchanged P/V folds bind
successive stages; repeated historical hash traces and their private storage
are removed. This keeps context-hash work fixed per continuation. All staged
source keys change and require fresh qualification; prior captured runs below
remain evidence only for their recorded executables.

`a_relation::native::archive` now implements the shared ten-A/nine-W producer
for both evidence forms. It preserves all original bytes and soft proposals,
checks hard predecessor/Q proofs, imports one original PK against its exact
unknown compiled source, and retains only its compact source-admission seal. Proving
reconstructs the exact source and drops the temporary key before verification.
Canonical Norito
checkpoints pin role, stage, descriptor, verifier and source context; restoration
reconstructs current claims from checked prior checkpoints. Status retains both selected
Pallas obligations and the original Vesta mode/correction for final Omega.
The original seven-stage full-domain sweep failed k16 even with constructor-only
Q metadata: Receive terminal stage6 overflowed, and Status retained stage1
overflowed. Those failures are retained under `target/qualification/archive-complete`.
The current split gives opaque retained proof hashing its own mandatory owner,
and separates unconditional core pending removal from terminal adjusted removal.
The current schedule has ten A stages and nine W continuations, with tagged4
internal owners and the common tagged3 terminal. It combines unconditional core
removal with the first own-proof stage and keeps retained proof hashing, hard Q0,
incoming proof binding, adjusted pending removal and terminal closure separate.
Each map owner assigns its own path. Adjusted removal and terminal closure use
the same complete result/mode verdict: any Corrected claim forces no-op even when
all soft results are true. The k16 and original-envelope limits are unchanged.

Earlier full-domain source attempts failed the fixed gate; their executable
captures remain under `target/qualification/archive-{real-q,ten}-sources`.
Removing historical context replay lets both actual-Q source sweeps fit with a
constructor predecessor. That capture passes all19 original-key imports for each
variant (Status559.49s, Receive616.15s), with wrong-stage and truncation rejection,
plus77 native unit tests (`archive-constant-context-imports`). These are source
checks, not complete Archive proof evidence.

Replacing the placeholder with the exact descriptor/VK exported by a genuinely
proved current Bootstrap Omega exposed Status stage1 at66,341 rows. An extra
range bus did not affect the sponge bottleneck and was removed; both failed
captures remain in `archive-captured-omega` and `archive-status-five-bus`.
Explicit incoming proof messages now use two exact128-bit halves in the immutable
context, preserving all256 bits and every existing owner/claim binding. The
native/circuit byte and limb mutations, malformed encodings and known/unknown
layout regression passes (72.24s). Both actual-Q/k12-incoming source sweeps then
fit all ten A and nine sequential W sources with the genuine Bootstrap metadata:
Status peaks at64,195 rows (71.16s), Receive at63,048 (66.62s), below65,529.
Captured binary/source and predecessor provenance are in
`target/qualification/archive-two-half-context`. All19 original-key imports now pass for each variant (Status403.25s,
Receive294.50s), including truncated/wrong-stage rejection. These layouts use a
pinned single-terminal Bootstrap source, not the
complete Omega catalog. The additional actual-k14 incoming sigma/Q preflight
also fits all ten stages (maximum63,344 rows,55.16s; `archive-k14-source`).
Its strict import sweep passes all19 original A/W keys with truncation and
wrong-stage rejection (447.25s; `archive-k14-import`, binary `d7819bd4…3c2f`).
The copied executable and predecessor originals stayed unchanged; unrelated
finality/Receive source drift is retained in the manifest. Actual Archive proof
chains and complete-catalog admission remain unqualified.

`a_archive_recursive` retains complete source-layout/proof-byte differential
checks, all19 checkpoint restores in a fresh session, and altered original,
foreign session, wrong role/stage and truncated payload rejection. Its
`native_load_tests` module registers acceptance, invalid-proof no-op and
full-envelope-tail no-op cases against the shared native-BLS first-Load fixture.
Each requires three exact predecessor reconstructions in fresh directories.
Compilation and execution remain pending. Select `--test a_archive_recursive`
and one exact ignored case with a fresh `KAGEMUSHA_LOAD_OUTPUT`. The source-only constructor-key sweep uses
labelled metadata Q keys and cannot qualify real proof workloads. Historical
accept/no-op binaries use the earlier narrow Archive and retired Load sources.
The superseded four-stage native duplicate is removed. Full-domain real layouts,
both complete evidence chains and the final catalog remain unqualified.

The retained owner now hard-enforces the same joint Payment proof budget as
Receive. A coherent oversized fixture was accepted before this fix; after it,
the exact limit passes and adding one byte to either tape rejects even after
re-signing the receipt and recomputing the Payment and all public hashes. All
four retained/incoming-source tests pass. The running complete-chain binaries
predate this added constraint, so they cannot qualify the changed owner key.
The [Archive composition argument](../../specs/kagemusha_recursion_soundness_v1.md#archive-original-sources-and-conditional-terminal-closure)
has passed independent internal source review, conditional on executing all
fixed owners and closing every obligation. A subsequent capacity review found
that the earlier3,456-byte incoming sigma buffer did not cover the complete
Credited envelope. The canonical Archive context now fixes retained raw Omega
at8,597 bytes and sigma at8,277 bytes, with their separate hard joint bound;
incoming Receive sigma has9,321 bytes and incoming Status raw Omega8,132 bytes.
Descriptor-length mismatches remain soft proof failures. Pending membership
authenticates the seven-word Send descriptor, not old proof lengths or bytes.
The isolated retained owner passes strict constraints and known/unknown layout
parity at the full capacities and inclusive joint boundary, using at most26,973
rows. All five retained/incoming-source tests pass. The shared full-domain
constructor pins the owner order and Q assignment used by the complete runner;
a new re-signed9,321-byte incoming-proof-tail case requires the no-op branch.
Fresh complete layouts and chains for this domain are required before native
installation or artifact admission; historical narrow-buffer runs do not
qualify it.

TODO: compose and qualify retained-Payment, evidence, signature, corrected-claim
and all recursive owners under admitted terminal keys. These components do not
accept complete delivery evidence or release retained Payment bytes.

## RefreshPolicy

CoreZK's preparation adapter retains distinct current/successor credential
owners for renewal: C4 receives the predecessor's original Credential and
Enrollment certificate, while the released receipt is checked with the successor.
It derives every permitted state effect from the exact issuer-authenticated
update and checks complete successor equality. Credential, SchemePolicy,
Blacklist and TimeAnchor preparation pass the 22-test namespace, including five
signed-update and custody regressions. The new Quota conversion retains a canonical
64-slot predecessor-usage frame under capsule role 10, authenticates its root
against the actual predecessor, and derives every successor slot from the signed
share. Independent source review found no local binding gap. The actual Rust
generator and three canonical witness/role tests pass; the complete Kotlin/Swift
vector classes pass 39/36 cases. The full witness is 2,805 bytes under its
8,192-byte cap, and the quota capsule is 7,591 bytes. The fresh data-model
namespace passes 228 cases with two maintenance captures ignored (34.60 s);
its recorded transitive source drift limits it to component evidence.
All 33 expanded CoreZK preparation tests and all 12 capsule tests pass,
including exact quota-witness power-loss replica repair/replay. The retained
binary uses its captured proof dependency before the acyclic-scheme correction;
CoreZK sources were unchanged throughout build and execution
(`target/qualification/quota-refresh-custody/results.json`). These conversions
grant no installed producer or wallet-opening authority.

`PreparationV1::prepare_refresh` derives all five Refresh operations before
Advance from a verified released head, including an unfolded head. It shares
the folding decoder for exact signed updates, certificate sets, blacklist
openings and the quota usage frame. It retains those original bytes and the
source capsule identity, derives sequence/nonce/state/statement, and uses only
a private core projection for sigma; it creates no Omega or folded authority.
The six typed administrative proving adapters require exact installed
descriptor/VK equality and a matching 26-field statement, then fully verify
each result through the installed sigma verifier. Native custody must still
recheck the source under its lock before Advance.

`PreparationV1::prepare_load` binds the qualified ordinary receipt source to
the installed scheme and manifest, verifies its proof and both claims, and then
derives the checked balance, sequence, ordinal and exact recovery insertion.
It adds only the net offline amount and retains original receipt/finality bytes.
Its public positive still depends on the complete ordinary receipt proof.

`PreparationV1::prepare_consuming` derives Unload/Retiring from the opaque verified
fold, preserving its adjusted burned value, pending root and permanent credit root.
It authenticates the exact optional charge quote and certificate set, checks the
chosen positive amount against adjusted spendable value, and verifies both recovery
insertion paths. Retiring changes lifecycle once without removing value or claims.
The native owner supplies nonce and paths. Charge originals stay in payout custody,
matching the existing rule that Lambda does not consume them. The old public
caller-derived consuming-witness entry point is now private.

The captured preparation namespace passes 49 cases (1.11 s), including seven new
consuming signature/derivation/adversarial cases and strict k12 circuit agreement.
The genuine public Refresh case also passes 1/1 (11.13 s): all five updates produce
and fully verify 3,296-byte sigma proofs; re-signing a receipt around corrupt sigma
cannot bypass verification. Capture `target/qualification/prepare-consuming/current`
retains executable `a41f8067…af73bc`, unchanged preparation sources and separate
wallet lifecycle status failures. The Refresh case uses two actual sigma keys in a
signed engineering inventory and a synthetic retained marker. Full public consuming
preparation through the real producer, recursive admission and Advance custody remain
open; arithmetic tests do not manufacture a folded-source capability.

`admin_sigma::RefreshCircuit` uses one k12 key for all five tag7 update kinds.
The kind is constrained to exactly 1 through 5; it does not select a host-side
circuit or key. Each genuine proof is 3,296 bytes with the same 2,538-row maximum.
All five proofs verify under one key, and known/unknown fixed columns,
permutations and assignment footprints agree across kinds. The genuine Q-sigma
composition also passes for every kind under one shared Q key, with 7,008-byte
local Q proofs and complete sigma/Q opening decisions. Rehashed changes to
fields owned only by another kind reject, as do invalid selectors, stale
counters, changed adjusted lineage, invalid policy intersections and expired
shares. This leaf binds the exact state effects and statement; A authenticates
the signed update projections and owns blacklist-history insertion and the
fixed64 quota rebuild.

The native `RefreshProver` imports the original sigma key against its
independently authenticated descriptor/VK and compiled source commitments. It
binds the typed update projection to the statement kind and signed original,
then fully verifies every produced proof. Its newly merged original-import API
and current-source proofs remain to be qualified; earlier measurements above
refer to the retained source snapshots. No runtime key generation or alternate
source profile is accepted.

`a_relation::refresh` requires the exact five original signed tapes in its
recursive context, hard update/receipt and current-credential Q slots (3V/2F),
direct purpose-scoped issuer certificates, state effects and every kind-specific
map owner. Credential renewal authenticates the old credential against the
predecessor and the replacement against the successor. Genuine compact
Bootstrap-rooted Credential, SchemePolicy, TimeAnchor and Blacklist compositions
now pass: each closes four A stages and three W stages, with 7,744-byte A proofs,
actual sigma/Q0/Q1/Q2 proofs and every native opening decided. Their maximum
assigned source rows are 61,725, 61,671, 61,659 and 61,665 respectively. Omitted
proofs/fold claims, altered Q proofs, dropped history and changed original
receipts with recomputed contexts reject. Internal A keys are excluded from
terminal-only catalog checks. Logs and source/binary manifests are retained in
`target/qualification/refresh-recursive*` and `refresh-map-recursive*`.

The complete Quota source exceeded k16 at 91,131 rows; its failed attempt is
retained and no oversized proof was generated. Its replacement separates three
fixed64 array-root owners from the deterministic matching owner. The shared
context commits typed old/window/used array hashes plus issue/count; each root
opens every array it reads, and the mandatory matching owner opens all578 words
and binds the signed share fields. All 64-slot checks remain. Isolated typed
owners pass with a 28,638-row maximum, but the first complete eight-stage attempt
failed at the PreviousRoot stage: four valid 7,744-byte A proofs preceded its
68,931-row overflow. That failed source/binary is retained in
`target/qualification/quota-split-recursive*`. The revised root-only path carries
object digest/length/tape proposals; mandatory signed-original owners recompute
all five originals, and the merge owner binds the signed issue/count. Two proposal
binding/schema/layout tests pass (69.26 s), and independent code review found no
binding gap conditional on complete source-bound closure. The following eight-stage
preflight stopped before Refresh proofs: PreviousRoot fit at 65,490 rows, while
WindowRoot/UsageRoot needed 67,303/70,411. The current seven-stage schedule places
Effects+PreviousRoot at A0, WindowRoot at A1, UsageRoot at A2, Q-sigma at A3,
update authorization at A4, current authorization at A5 and Merge at A6. All seven
unknown-witness layouts and actual proofs pass at
53,206/60,014/63,122/62,715/61,679/62,974/61,420 maximum rows, preserving the 65,529
ceiling. The earlier preflights reused a representative W key and remain sizing
diagnostics, not proofs of later-stage key identity. The replacement planner now
derives each successive A/W verifier without retaining PKs and requires exact
binding/VK equality before every actual proof. The captured replacement Quota
run passes this exact sequential planner and all seven actual A/six W proofs at
the same fitting row bounds; strict borrowed-key import and replay also pass below. The captured
`quota-seven-native` candidate reaches complete seven-A/six-W closure with genuine 7,744-byte A proofs, all five signed originals, hard3V/2F
and every opening decided. The complete captured test passes in 3,884.48 seconds,
including exact native proof-byte parity, restoration of every checkpoint and
canonical Norito payload replay. It uses the earlier typed-key mounting API; the
new strict original-PK importer is qualified separately. All earlier overflows
are retained, and this busy-host duration is not a performance gate.
The captured strict original-PK Credential run passes 1/1 in 2,985.22 seconds
(`target/qualification/native-refresh-original-credential2*`): all four A and
three W stages import against their exact compiled sources, reject changed
stage/VK/table/truncation cases, reproduce original proof bytes, and restore
canonical checkpoint payloads. This result used eager PK retention.
The current native Refresh producer instead retains only the shared
`native::artifact::KeyArtifact` descriptor/VK metadata. Its per-stage `import_a`
and `import_w` methods reconstruct the exact unknown source, validate original
PIPAPK01 tables and installed VK, drop the imported PK and return a compact
source-admission seal. Each proof reconstructs the exact admitted source and drops temporary
proving buffers before verification. It retains no original PK bytes.
Metadata construction does not authenticate a release catalog; that remains the
installation owner's prerequisite. Source construction creates no Prepared
operation or accepted claims and generates no runtime key. Proving checks the
complete descriptor and VK before any fold. Independent review found no local
binding gap, and the shared-metadata/Receive unit batch passes 15/15. The captured
borrowed-key Credential run passes 1/1 in 3,725.63 seconds
(`target/qualification/native-refresh-borrowed-credential*`), including all four
A/three W strict original imports, foreign-key rejection, exact proof-byte parity
and raw/canonical restoration. Captured Quota also passes 1/1 in 4,990.54 seconds
(`target/qualification/native-refresh-borrowed-quota*`): all seven A/six W stages
use exact sequential verifier identities, strict original source imports and
borrowed stage keys, reproduce every original proof byte and restore all raw and
canonical checkpoints.
No phone-memory or RSS gate follows from the ownership design or these busy-host
component durations. The installed candidate assembles
all five kinds from actual predecessor/Q proofs and exact signed originals,
using the fixed four- or seven-stage schedule. It consumes witnesses for proving,
self-verifies every A/W proof and restores original bytes with source-bound
history and full accumulator decisions. The resolved candidate passes ten Refresh preparation/checkpoint tests and all
61 native component tests, including the exact seven-stage schedule, canonical
checkpoint metadata and all eight Send selectors. Genuine Credential parity also passes
(1,111.59 s): all four A and three W proofs reproduce exact diagnostic bytes under
the original installed keys, every checkpoint restores, and changed proof/Q or
invalid stage transitions reject. Its source and binary are retained in
`target/qualification/native-refresh-credential*`. The retained-candidate SchemePolicy/TimeAnchor/Blacklist run also passes all
three kinds (3,983.89 s, `target/qualification/native-refresh-policy-anchor-blacklist*`).
These four ordinary variants reproduce exact original A/W proof bytes and raw
checkpoints. The seven-stage Quota run separately closes native/canonical-payload
replay. Captured Credential and Quota passed the earlier borrowed-key
original-import API; current metadata-reconstruction parity remains to be run. The authenticated final Omega catalog and installed wallet
producer remain required before admission.

TODO: complete current original-key import/proof replay, prove final Refresh
Ω wrappers under the full common terminal catalog, and connect the installed
wallet provider. The five genuine Q/A/W component closures do not admit release terminal keys or
establish latency, memory or physical-phone compliance.

Native A/W original importers return compact opaque source-admission seals only
after strict factory-based source, table, commitment and full-key checks.
Bootstrap, Load, Send, Receive, Archive, Unload/Retiring, and every Refresh route
borrow the existing installed D/V through those seals and check the exact stage
before folding. A private proving helper reconstructs the actual circuit's
witnessless source with `OnDemand` cosets and no commitment tables, checks its
full previously admitted source fingerprint, consumes the witness, and drops
the temporary PK before the owner's unchanged full verification and decisions.
Live witness data and matching D/V alone cannot mint source authority. The three
Bootstrap `Prepared` proving helpers are private; public Session methods enforce
the installed role. Public circuit/source builders remain available to producers.

The qualified CoreZk owner retains one seal and signed member index per A/W
stage alongside its existing graph. Every acquisition checks the exact member,
seal, installed D/V and current row cap before opening any source; it then streams
and hashes every signed descriptor/VK/PK original under current byte limits.
Missing, changed or unavailable originals and cancellation never grant a view.
No PK, original byte vector, duplicate D/V graph or global cache is retained.
Initial qualification still performs every strict original import. Later A/W
acquisitions avoid repeating its commitment work but still perform exact byte
custody checks, and proving still rebuilds and hashes the admitted source.
Qualified wallet Q and Omega owners likewise keep compact seals beside their
existing D/V and program metadata and lend purpose-specific views after identity,
current-cap and three-original streaming checks. Standalone producer owners still
own their public metadata; there is one canonical borrowed reconstruction path.
Seals are not persisted or decoded, so each fresh installation repeats strict
source qualification. No per-acquisition plan/catalog or D/V graph is cloned.
Checkpoint restores do not acquire sources or rebuild keys. Sigma proving remains
a separate owner; Load finality uses native BLS verification. Complete wallet memory and performance qualification remain
open; existing genuine family differentials and both-curve helper controls retain
proof/opening/checkpoint parity and pre/post-reconstruction cancellation coverage.


## Controls

Send's verifying key is selected by the opened core mask. Receive's key is
selected by the Request's recorded version: `(4, 0)` for zero, `(4, 1)` for
nonzero. Its current core mask is still restricted to defined bits and is
carried in the statement, but does not select Receive enforcement.

- **Blacklist:** a depth-16 gap opening in limb order proves the
  counterparty absent. Send uses the payer's current committed list and
  enforces its maximum age. Receive uses the receiver's list recorded in
  the Request, regardless of later list or mask changes. Version zero is
  valid exactly with root zero.
- **Quotas:** the depth-6 window tree and the aligned depth-6 usage array
  have exactly 64 slots. A usage leaf is
  `P(kgwquse1, [kind, start, end, used])`; usage nodes use `kgwqusn1`.
  Each touched window is charged once at its own slot, within its limit,
  against the running usage root. Four consecutive window openings per
  kind establish that the two candidates include every touched window.
  Padding slots retain zero usage. There is no quota indexed map or quota
  insertion path.
- **Quota time:** σ requires `upper < quota_share_expires_at_ms` and
  `upper - lower <= time_anchor_max_response_ms`, authenticated core fields.
  Native installation/Λ require windows longer than the span bound; hence
  at most two windows of each kind can be touched.
- **Lease:** Send requires `upper < lease_expires_at_ms` when enabled.

`StepWitness::evaluate` reports native violations and every derived digest.
The circuit compares its digests with that reference during synthesis with
known witnesses. `check_send` and `check_receive` compare a statement with
the Request and, for Send, Ω's public lineage view before returning the
verifying-key selector and public digest.

## Shapes and proof bytes

Folded-prefix shapes, fewest lanes that fit:

| Relation | Permutations | Smallest shape | One-lane budget shape |
| --- | ---: | --- | --- |
| Send, no controls or lease | 69 | k10 / 4 lanes, 5,120 B | k12, 3,296 B |
| Receive, no recorded list | 67 | k10 / 4 lanes, 5,120 B | k12, 3,296 B |
| Send, blacklist | 106 | k11 / 2 lanes, 3,840 B | k12, 3,296 B |
| Receive, recorded list | 104 | k11 / 2 lanes, 3,840 B | k12, 3,296 B |
| Send, quotas | 309 | k12 / 4 lanes, 5,280 B | k14, 3,456 B |
| Send, all controls | 345 | k12 / 4 lanes, 5,280 B | k14, 3,456 B |

The k14 one-lane quota shapes occupy 12,123 and 13,542 rows respectively.
Their 3,456-byte proofs fit the current 3,541-byte σ share of the joint
Payment budget. These are exact descriptor lengths; performance and memory
qualification are separate gates. `select_shape` synthesizes candidates and
can impose a byte budget. Keys, descriptors and proof bytes are independent
of the Rayon pool size and optional commitment tables.

`SigmaProver` generates producer keys or imports an original proving key with
`from_original_artifact`, then rejects invalid witnesses. `SigmaVerifier`
rebuilds from descriptor/key bytes and pinned parameters. `SigmaAllowlist`
selects by `(operation tag, mask)`. Sigma and Q imports check bounded originals
against the independently selected descriptor, verifying key and compiled source;
they regenerate no key and reject substitutions. Default and explicit serialized
Q profiles never fall back to another profile. Original/domain bounds do not
qualify total synthesis or prover memory.

`q_sigma::native::QSigmaSource` removes live prepared-operation input from
original-key installation. It checks one genuine member VK per fixed slot
against the complete independently installed plan/catalog and descriptor. The
member supplies layout metadata only: private source construction assigns its
key coordinates, proof tapes and modes as unknown, and preserves every fixed
catalog entry. Installation checks the exact k16/Pallas profile, bounded original
source/commitments and installed VK; no extra PK signature or runtime keygen is
required. Only source-bound verifier metadata survives import or the explicit
native keygen constructors; `QSigmaProver` has no retained PK or PK accessor.
Artifact production remains the engine keygen path over the exact source circuit.
Each proof reconstructs the chosen default/serialized source with on-demand buffers
and no commitment tables, then releases its temporary PK before full verification.
Source/catalog mismatch is a hard reconstruction error, never an incoming-failure
verdict. Actual `QSigmaPlan::prepare` and `QSigmaProver::prove` still verify the real
proofs, decide required claims/folds and fully verify the produced Q proof.
Per-acquisition original commitment checks remain; this change alone establishes
no total memory, speed, complete catalog or restored-checkpoint qualification.

The source-only constructor/layout tests, existing soft-failure classifier and
both genuine imported Q proof regressions passed for the earlier retained-key
implementation: five host cases with the same 1,748 recorded inputs unchanged
throughout. The metadata-only caller requires its own current proof-byte parity,
cancellation and source-refusal execution; that historical result does not qualify it. Complete authenticated producer-graph
installation and Native typed intake remain separate requirements; this component
does not grant wallet-open capability or qualify any Android device.

`q_signature::native::QSignatureProver` imports the original k16/Pallas/V2
signature key against an independently installed immutable slot plan, descriptor,
VK and compiled source. It derives low-S P-256 verdicts from raw signatures,
refuses invalid hard slots and proves false verdicts for invalid soft slots,
then fully self-verifies the proof. Strict original import remains mandatory;
only source-bound verifier metadata survives it. Each proof reconstructs the same
source's on-demand proving buffers without commitment MSMs, then releases them
before full verification. No proving-key accessor or retained PK remains. This
path does not qualify total memory or speed; per-acquisition original import still
checks commitments. A still binds original tapes, signature roles and the global
branch; this leaf does not grant
complete producer-catalog admission, a Native wallet owner or wallet open.

`admin_sigma::native` provides typed `BootstrapProver`, `LoadProver`,
`ArchiveProver`, `RefreshProver`, `UnloadProver` and `RetiringProver`
original-key importers over the existing
administrative circuits. Each fixes Vesta/k12, the PIPA-R direct bounded statement
profile and its compiled operation, checks original source tables and commitments,
and requires exact agreement with the independently installed VK. Selector
compression remains the authenticated descriptor's choice, checked by the same
source importer; no profile fallback or runtime key generation occurs. Proving
derives the public statement digest from the typed witness and completes native
verification before returning bytes. The shared descriptor does not authorize
substitution of another operation's original key. These are proving components;
A still authenticates objects, maps, signatures and predecessor obligations.

The installation owner must authenticate the signed scheme and complete producer
inventory before import. These constructors supply proving components only;
they supply no `NativeProofs` owner or wallet-open grant. Freezing the production
artifact set and integrating Λ/Ω with wallet and node paths remain separate
G3–G5 work; this crate's σ implementation alone does not establish complete
protocol readiness.

## Validation

`q_signature` implements ordered hard/soft P-256 signature leaves on the
17-advice/10-lookup Q layout. One Bounded public column contains ten words
per slot: digest, x/y/r/s as low128/high128, then verdict. Raw 256-bit
integers remain unreduced until the total P-256 checks. The existing SHA
codec binds the canonical Fp digest's LE bytes. Fixed keys and slot modes
are part of the circuit; A still binds these public words to object bytes,
certificate purpose and the global branch rule. The 5-variable/1-fixed
component uses 64,238 rows at k16. Signature proofs, exact-input mutations,
raw-width boundaries and every bridge cell are tested. This is not a
composed operation or runtime qualification.

- `digest_parity`: every G1 field encoding, named controlled-state positions,
  hashes, packing domains, fixed64 usage roots/openings and in-circuit parity
  on both fields; deterministic known answers.
- `controls`: blacklist snapshot enforcement, zero version/root agreement,
  exact expiry/span boundaries, repeated/misaligned/out-of-range slots,
  forged usage roots and noncanonical Poseidon bytes.
- `relation_checks` and `forgeries`: arithmetic boundaries, every step rule,
  wrong-head and consistent-forgery attacks, and release per-cell tampering.
- `shapes`: exact shapes, row counts, joint byte budget and verifier rebuilds.
- `real_proofs`: real valid and rejected proofs, selector binding, byte
  tampering and deterministic keys/proofs; quota shapes use k14. The two
  `installed_sigma_originals_` release cases exercise imported Send/Receive keys
  on both Pasta curves, actual proofs, public-input tampering and import refusals.
- `q_sigma`: `actual_two_sigma_q_proof_verifies` and
  `installed_serialized_q_originals_prove_and_reject_default_profile` exercise
  original-key continuity, explicit profile refusals and genuine imported Q
  proofs. All four selected import cases passed. Fixture producers generate the
  originals; the import path does not. The default Q's 10,496-byte proof is a
  local component, not a final Payment/Ω size or wallet/device qualification.
- `q_signature::native` and `q_signature`: one selected Native verdict case and
  three explicitly selected release cases passed. Two release cases generate
  and fully verify genuine imported hard/soft signature proofs, retain their
  openings and reject changed inputs/verdicts; the third checks key, fixed-slot
  source and original bounds refusals. Each of the two runs retained its 1,700
  inputs and 17 local dependency packages unchanged. The earlier unapplied
  zero-case attempt contributes no passes. The hard signature Q's 8,576 bytes
  qualify this local component only, with Payment/Ω and wallet/device gates open.

- `admin_sigma` and `consuming_sigma`: the `installed_admin_sigma_originals_`
  cases import all four typed administrative keys and exercise genuine proof
  verification, complete opening decisions, changed public inputs, corrupted
  proofs and rehashed invalid value transitions. A same-descriptor four-by-four
  original-key substitution matrix and malformed/bounded/profile/curve/VK intake
  checks cover the import boundary. Test producers generate fixture originals;
  Native imports do not. These cases do not establish a signed producer catalog,
  final Omega, Native wallet open or physical-device qualification.

- `archive_sigma`: complete rehashed unchanged-field and statement/opening
  mutations, source-layout equality, imported-key proofs for Active and Retiring
  under the same key, full opening decisions, forged-refund rejection and
  bidirectional administrative-key substitutions. These cases exercise sigma
  state effects and original intake; they do not authenticate Credited evidence
  or qualify complete ArchiveSent execution, wallet open or physical devices.

- `measure`: ignored diagnostic throughput/footprint workloads. They are not
  the fresh-process qualification procedure in the design record.

Together these Sigma/Q and signature runs passed eight selected Native component
cases across their separate guarded cuts. This count includes refusal and Native
verdict cases; it is neither eight proof-generation cases nor one unchanged
current release. Fixture producers generate original keys; Native imports do not.

```sh
cargo test -p iroha_kagemusha_proof
cargo test --release -p iroha_kagemusha_proof --test real_proofs -- --include-ignored
cargo clippy -p iroha_kagemusha_proof --all-targets -- -D warnings
```
