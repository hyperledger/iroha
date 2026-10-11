# Canonical Norito schema identity

Norito typed frames now use one declared identity in both directions. The codec,
derive, model and workspace consumer migration compiles all workspace test
targets. The [compilation repair](../docs/cargo_test_compile_validation.md)
records focused regressions and separates these results from full runtime and
feature qualification. This is a first-release cutover without alternate
accepted hashes or compatibility paths.

The enum-prefix correction passes 1,338 default tests and 1,340 tests with
`schema-structural`, each with one existing ignored generator. The structural
suite, all 60 derive unit tests, 14 strict JSON tests, four UI harness tests and
strict codec/derive test Clippy bind the same candidate source; the default suite
retains its separate earlier source seal. Earlier captures retain passing Norito
doctests and all 950 default SoraFS library tests,
including the captured revocation preimage. These captures are not a full
workspace or release qualification. See the
[current cutover evidence](#active-identity-cutover-2026-09-09).

The concrete model fixtures now preserve five owned records and two
encoding-only projections: Action, DataEvent, the executor context, block
subscriptions/messages, the block-send adapter and reputation event-ID
material. Their 44 root/container frames and three adapter projections
are documented in
[`model_concrete_identity_frames.md`](../crates/iroha_data_model/tests/fixtures/model_concrete_identity_frames.md).
The borrowed adapters retain their owning decoders and exact projected bytes.

DataEvent assigns explicit wire discriminants to all variants. Governance
reserves 19 even when disabled; Social, Bridge and GameSession retain 20, 21
and 22. A normal-dependency consumer exposed GameSession shifting to 21 when
governance was disabled. The canonical fixture remains the governance-enabled
capture, shared by every feature selection for common variants; disabled
capabilities reject their reserved variant. No alternate old tags are accepted.

## One identity contract

`norito::NoritoSchema` declares a nominal name and its single root-frame
projection. Generic parents compose nominal children, never their projected
root names. Type and const arguments retain declaration order. Lifetime slots
use the fixed erased marker `'_`; the pinned compiler names `Cow<str>` as
`alloc::borrow::Cow<'_, str>`, so dropping that slot changes enclosing frames.
The fixed `schema::identity::frame_hash` helper applies the existing
domain-separated SHA-256 digest truncated to 16 bytes. Implementers cannot
override its algorithm.

Root projections preserve the existing distinction between `String` and its
borrowed/boxed forms, explicitly named DTOs and their containing vectors,
transparent wrappers and their inner types. A generic derive cannot use a
fixed projection that erases its type or const arguments. Generic forwarding
projections, such as an owned wrapper advertising its inner type's frame, need
an explicit manual identity implementation. Markers used by `HashOf<T>` and
`SignatureOf<T>` need an identity, not a payload codec.

Manual borrowed producers declare the logical value they serialize. An iterator
implementation parameter does not enter that identity: a slice iterator and a
chained iterator producing the same element type share the borrowed sequence
identity and project the same `Vec<T>` root frame. Element types still compose
nominally. Their bare payload implementation requires only payload codecs;
typed framing separately requires the declared identity.

HTTP producers and typed consumers use one shared wire definition. SCCP Torii
read-API records (capabilities, proof bundles, rotation chains) are owned by
`iroha_sccp::api`; bounded PoR status pages are owned by
`sorafs_manifest::por`. Torii, the Rust SDK and
CLI import these owners directly. Duplicate SDK/server declarations and their
competing frame identities are removed, without aliases or alternate accepted
hashes. Declared producer names remain protocol identities independent of the
Rust module that now owns their implementation.

There will be no source-path registry, alternate accepted header names,
compatibility dispatch or opt-in framing mode. Actual pre-cutover names must be
captured under the pinned compiler: public imports can conceal private `model`
modules retained by `iroha_data_model_derive/src/model.rs`.

## Final trait and framing boundary

`SerializePayload` owns object-safe serialization and encoded-size methods;
`DeserializePayload<'a>` owns bounded value reconstruction. Bare `Encode` and
`Decode`, sequence containers and canonical field decoders use these payload
contracts without requiring frame identities on their children.

The typed contracts are blanket implementations of the payload contract plus
`NoritoSchema`:

```rust,ignore
pub trait NoritoSerialize: SerializePayload + NoritoSchema {}
impl<T: SerializePayload + NoritoSchema + ?Sized> NoritoSerialize for T {}
pub trait NoritoDeserialize<'a>: DeserializePayload<'a> + NoritoSchema {}
impl<'a, T: DeserializePayload<'a> + NoritoSchema> NoritoDeserialize<'a> for T {}
```

Neither typed direction owns a hash method. Typed derives emit the payload
implementation; `NoritoSchema` is declared separately. Payload-only records
cannot acquire a typed frame API from reconstruction alone. The retired
`#[norito(schema_name = "...")]` attribute is rejected; root projections belong
in the canonical `#[norito_schema(...)]` declaration. All frame writers, readers,
collection collectors and map iterators use `schema::identity::frame_hash`.
Derived `static_frame_name()` borrows the exact explicit root projection or
complete nominal literal without constructing a `String`. Generic and erased
lifetime compositions still retain all arguments; only an explicitly declared
fixed projection can supply a static root for a lifetime-bearing owner. A manual
static nominal declaration never substitutes for its independent root projection.
The hash domain, declared names, immutable fixture bytes and wire layouts are
unchanged. Other serializer allocations remain subject to their own admission.
Streaming padding follows the known container representation, without inspecting
hashes to select a layout. Structural schema exports remain inspection data.

Public `IdBox` and `BlockSignature` retain one typed frame API each, with their
compiler-observed nominal identities and 24 immutable root/container frames.
`IdBoxCandidate` and the block header/signature tuple adapters expose only the
payload contracts. `IdBox::try_deserialize` delegates to its carrier's fallible
method, preserving unknown/truncated-tag errors without panicking. The
[public-owner fixture contract](../crates/iroha_data_model/tests/fixtures/public_frame_owner_identities.md)
records the exact original captures and their validation scope. Model consumer
migration and current-candidate qualification are still incomplete.

The implemented codec boundary is:

1. `SerializePayload` and `DeserializePayload<'a>` retain their respective bare
   serialization and reconstruction responsibilities.
2. `NoritoSerialize: SerializePayload + NoritoSchema` is the typed contract,
   implemented once for types satisfying both. Erased bare writers use
   `dyn SerializePayload`; typed generic callers inherit the identity bound.
3. `NoritoDeserialize<'a>: DeserializePayload<'a> + NoritoSchema` is the typed
   decoding contract. Reconstruction remains solely on `DeserializePayload`.
4. Both codec directions remove their independent `schema_hash` methods. Every
   typed frame writer/checker uses the fixed helper. Update framed callers,
   derives, manual implementations and qualified calls together. No legacy
   hash or reconstruction-method forwarding remains.

This keeps allocation-conscious bare streaming while preventing a type without
an identity from entering a typed frame. `schema-structural` remains explicit
inspection data, not a feature-selected active header digest.

Bare `Decode` requires `for<'de> DeserializePayload<'de> + SerializePayload`;
canonical field/container decoders use the payload contracts for reconstruction
and byte comparison. Exact slice helpers combine `DeserializePayload` with
`DecodeFromSlice` and do not require a frame identity. Typed frame consumers
explicitly retain their `NoritoSerialize`/`NoritoDeserialize` bounds; bare
`Encode`/`Decode` bounds do not imply those contracts. Option fields use the
shared canonical decoder without inventing
a nested frame schema, retaining advertised flags and resource limits.
Tuple and result slice decoders enforce exact child consumption with runtime
errors. Both result branches guard child nesting and restore the previous depth
before subsequent decodes in the same limit scope. Unit size diagnostics use
the shared layout calculation, including the existing packed zero-offset table;
canonical field/frame comparison continues to validate that metadata.

The actual `MultisigPolicy` and `MultisigMember` owners derive binary decoding
with the fallible
`#[norito(validate = "path")]` hook. It consumes the reconstructed owner and
returns `Result<Self, norito::Error>` once per reconstruction, preserving typed
errors and the existing strict constructors. Their private `PolicyFields` and
`MemberFields` carriers retain only JSON decoding and acquire no binary frame
identity. Moving the generated reconstruction implementation to
`DeserializePayload` retains this validation behavior and one reconstruction
owner. Qualification of the remaining feature/runtime matrix is pending.

## Active identity cutover (2026-09-09)

The source-bound checkpoints below precede the workspace compilation repair
linked above and retain their original validation scopes.

The stack-overflow correction removes recursive participant ownership and makes
`HashOf<T>` export the schema of its stored hash without traversing phantom `T`.
All 32 Native AMX tests pass again after the model identity migration on source
`b010aafd437eb82c5fd9a5adcd5c4c51379f85c5eaac6479be74a3aed6af0357`,
including 4,096 sources through schema export, encoding, decoding, hashing and
explicit drop. All 184 ABI tests pass on that same source. No stack-size override
or optimization-level change is part of this correction.

The complete model run on that source retains 3,718 passes, one failure and six
ignored generators. Its sole failure exposed a separate generated named-slice
decoder that ignored packed layout flags. Named slice decoding now delegates to
one layout-aware payload decoder, preserving exact prefix consumption, typed
validation errors and active resource budgets. Two independently failing
regressions now pass across every advertised layout; decoder-only records need
neither a serializer nor a frame identity. The corrected codec/derive suites and
strict Clippy bind source
`10eee68576a910c217093f70a0e3febf050af4ab3319ca0b5fc3be4617e8fa51`.
The corrected dependent candidate binds source
`433901ee984f27689625a8c217dec16f9364563966f8247ae4bc620be6d2be89`:
3,720 model library tests pass with six existing generators ignored, all 184 ABI
tests pass, and all 289 shared HTTP model library tests pass. The field regression
and all 32 Native AMX cases also pass as explicit selections from the same model
artifact. Both dependent library builds emit zero warnings. The shared crate's
own default suite additionally passes its library and both integration targets,
including the unchanged status and Android Connect wire fixtures.

The shared HTTP model build identified two additional framed owners,
`KagemushaOperationLookupV1` and `KagemushaOperationStatusV1`, whose captured
frames matched the candidate. Both were deleted with the KAGEMUSHA V1 Torii API
on 2026-10-05.
Failed predecessor builds and the original one-failure model run remain retained;
none is counted as a pass. The following SDK qualification advances that
consumer batch; remaining workspace migration, strict dependent/workspace
Clippy, model extraction and release qualification remain open.

The SDK and executor model declare 35 additional production owners against 70
original serializer/decoder observations. Three required HTTP model
owners add six observations for validation errors and DA ingest requests and
receipts. All recorded owner bodies, field order and captured frame roots stay
fixed. The shared library passes 293 tests, the model frame selection passes 25,
DA passes nine and Native AMX passes all 32 on source
`74380d062e594983f387cb2ef33f0c609bf01e46190c3cdc67570170c46202bf`.

The original SDK and Torii request-witness implementations signed different
complete frames despite equal bare payloads. Both now call one bounded borrowed
encoder in `iroha_torii_shared`, retaining the captured SDK signing frame. The
conflicting Torii frame is removed. The shared tests compare complete captured
bytes, signatures, all advertised layouts and allocation bounds; Torii handler
runtime qualification remains pending. Its bounded witness decoder retains the
actual public model frame identity and existing resource limits.

The complete SDK library passes 792 tests on source
`852016adf21328a291d3f9e3ce50e60e0cdbbd52ed1dc30bc1266e8cee1dee0b`.
The preceding 788-pass/three-failure run remains retained. Exact faucet metadata
verification now includes the mandatory version-one claim marker already
required by Torii and Core. Signed negative controls reject a missing marker,
wrong version, wrong type and extra metadata. Expired test envelopes use coherent
historical signed lifetimes; the proxy fixture explicitly restores blocking mode
on its accepted socket without changing production transport or deadlines.
The four focused checks and the complete SDK suite pass on that same source,
with zero build warnings and no stack override. The C# follow-up replaces its
obsolete reset binding with the canonical five-field operation binding, transcript
and exact metadata, including the faucet version-one marker. Durable verification
retains caller-trusted network, authority/policy and fee intent without checking
current time. Signed positive TTL cannot outlive the authenticated operation;
submission checks its deadline after asynchronous request preparation, immediately
before the single HTTP dispatch. The shared signed fixture is unchanged.

The C# build passes with zero warnings/errors and 187 unchanged inputs. Its 17 pure
protocol tests pass. The broader 81-case selection passes 32 and fails 49 because
the complete ABI-23 address validator is unavailable. Full signed expiry and faucet
mutation execution remain unverified; broad negatives which stop at native absence
are not downstream predicate evidence. The exact eight-path patch and independent
parent review are retained under `target/architecture-redesign/csharp-prepared-protocol/`.
JavaScript still lacks this prepared verification capability. Complete cross-SDK
and native release qualification remains open.

The crypto library passes 1,392 tests with three existing ignored cases on source
`c94d02167d2634897ce8221f62292c2738007c5a91b0545241e7cfac2a4a0f85`;
its scalar integration passes one. Two BFV tests in that run create explicit
32/64 MiB test stacks. Unsetting `RUST_MIN_STACK` does not make those two tests
default-stack evidence for that historical source. The subsequent correction
and its qualification scope are recorded below.
The grouped integration originally failed two
stale empty-root expectations. Independent Blake2b reconstruction corrects those
fixtures while preserving production hashing and its domain tags byte-for-byte.
The corrected group passes all 200 tests with one existing ignored case on
`852016adf21328a291d3f9e3ce50e60e0cdbbd52ed1dc30bc1266e8cee1dee0b`.
These separate source records do not establish a single-source full crypto or
release result. `consumer-candidate/sdk-and-crypto-corrections-checkpoint-3.json`
binds the SDK and corrected crypto runs, logs and compiler artifacts.

The final consumer batch binds one source, `701ddd6dbbc0088a1363671f9480ac9530ff5d94419175d908062f241898f004`,
with 19,787 unchanged inputs and zero build warnings. Complete library runs
pass 3,725 model, 792 SDK, 293 shared HTTP, 194 SCCP and 36 executor tests;
all 3 SDK integration tests pass. Only the six existing model fixture generators
are ignored. The model run includes the maximum-size Native AMX stack regression.
All 42 changed consumer paths and the three independently reviewed stack-correction
owners match the live working tree. The combined result is recorded in
`consumer-candidate/canonical-consumer-qualification-checkpoint-4.json`.

The node-support follow-up removes a duplicate Halo2 decoder that coupled bare
payloads to frame identities and rejected valid caller suffixes. The three bare
IPA records use Norito's generated bounded prefix decoder; public exact-slice
entry points still reject trailing bytes. Only the outer verification envelope
declares its captured frame identity. Its unchanged valid Pallas proof, complete
root/Option/Vec frames, malformed-input and budget checks pass in all eight
focused tests under both default and the crate's structural feature, on source
`45cbe190596c4a2a62ac76c919599139511e39ec52701c4fef0f1e4caeac85f6`.

Fifteen settlement wire owners now declare the identities measured from their
original serializers and decoders. The timestamp/duration codecs and arithmetic
are unchanged. All 18 library tests and three new wire-contract tests pass with
zero build warnings on source
`4cc08ce4a1d50f79cc5bd8957256c1d7743f5819734ef14e3cf68d193324f437`.
The new cases preserve complete scalar/container frames, timestamp rejection,
signed duration extremes and prefix/exact-boundary behavior. All 16 changed
proof/settlement paths match the live working tree; both source records use the
default stack. `consumer-candidate/node-support-wire-checkpoint-9.json` binds
these results. This does not qualify the full proof engine or Core/Torii; their
production graph and remaining codec consumers are still being migrated.

The next compiler boundary declares only `EntrypointArgumentSchemaV1` and
`RejectionExpectation`, the actual roots passed to the canonical framed ABI
encoder. Their 40 original compiler-captured frames retain exact root, Option
and Vec bytes and both directional hashes. Payload-only children remain
unchanged. The combined library build has zero warnings on source
`e662e6cd535965fa542971f1a03df7e0de8d02f1c0b5a98b9a937facaf06f384`
with 19,797 unchanged inputs. All 1,091 compiler library tests and 28 entrypoint
tests pass. The exact Native AMX module passes 26 tests, including the maximum
4,096-source regression; a separate one-test selection repeats that regression.
An earlier filter selected zero tests and supplies no regression evidence.
All three stack-correction owners are unchanged and all runs use the default
stack. `compiler-frame-owners-v1/qualification.json` and the independent
`compiler-frame-parent-review-v1.json` retain the precise source/artifact scope.

The next configuration patch removes ten obsolete frame markers from five
payload-only types: Kura `InitMode`/`FsyncMode`, logger `Format`/`Directives`,
and snapshot `Mode`. Their payload and JSON implementations are unchanged;
no frame identity is invented. All 11 focused tests pass with zero build
warnings on source
`f4129b10bcca74a8912c3c4b6a8be0cf9113f06cf3c6ab420e88a488098bf3dc`.
The five new tests cover exact fixed bare bytes, both explicit field layouts,
JSON parity, invalid values and trailing-byte rejection. The initial five
fixture failures remain recorded separately in `config-field-codec-v2/qualification.json`.

Two direct hash-schema regressions guard the stack-overflow root cause: a
referent sentinel rejects accidental phantom traversal, and a record containing
`Option<HashOf<Self>>` has a finite schema from either root. All 46 selected
hash/multihash tests and all 26 Native AMX tests pass on source
`a0732816c7ca50812212459555cbe4270ee88cf52b102b151e864a9b95a4ba6a`,
with 19,798 unchanged inputs and zero build warnings. This includes the
4,096-source schema/codec/hash/drop regression. These selected tests have no
enlarged-stack wrapper and run with `RUST_MIN_STACK` unset. BFV qualification is
separately recorded below; the complete node graph and release remain open.
The Core/Torii check on that same source passes configuration and stops at
99 FASTPQ and two telemetry codec errors. That failed check is retained; the
`hash-phantom-regression-v1/qualification.json` record distinguishes them from
the passing stack regressions and the earlier configuration source.

The BFV audit's oversized test function is decomposed into sixteen cohesive
groups with concrete fixture owners and borrowed inputs. All 1,127 original
statements, including the extracted shared helper, preserve their assertion
tokens; the 799-entry diagnostic fixture is unchanged. Both 32/64 MiB thread
wrappers are removed. Production BFV code is unchanged. On the same compiler,
features and unoptimized test profile, the original function's fixed local
reservation was 1,592,496 bytes; the new runner reserves 13,968 bytes and the
largest group 274,944 bytes. These are emitted prologue measurements, not
whole-stack or compiler-memory peaks.

The zero-warning BFV build and its runtime evidence bind source
`d22c04be7ccadc6d8c4cf6ac9ecd95d1e56b671bb27d3cf60222ce7b6a2cea26`.
Both targeted BFV tests pass on the default stack: the byte-admission test
preserves all six original assertion paths, and the complete audit passes all
799 unchanged diagnostics in 6,360.88 seconds. All 46 hash/multihash regressions
pass on the same retained artifact
`344cbe5bf22c13b137c4cdfa9718074e075eb4a333542030c360f3ce0ac727af`.
All 19,815 recorded inputs remain unchanged during execution, and all 18 edited
source files match the live repository, frozen candidate and patch replay.
`bfv-stack-boundaries/final-qualification-v1/qualification.json` binds these
results to their exact source, compiler and executable; its SHA-256 is
`75eb983d8910ac57a3759089d508f1dda295e36c896248e5e4cf0bf9f7ed8d61`.
The frozen statement-preservation and emitted-frame records remain under
`bfv-stack-boundaries/`; `bfv-stack-parent-review-v1/` records independent
fixture-ownership and compilation-unit checks. This qualifies two targeted BFV
tests and 46 hash/schema tests, not the full crypto library or release.

FASTPQ now declares only its actual frame owners, preserving separately captured
nominal names and root projections. Thirteen obsolete attributes disappear from
payload-only records. The manual Fp4 scalar retains its exact four canonical
little-endian limbs and coefficient checks. Forty-five original complete frames
cover public roots, Options and vectors; they reproduce exactly and reject
wrong identities, truncation and suffixes. The retained-layer cache test compares
opening payload bytes inside `Proof`, which owns their enclosing frame. The nine
proof wire tests and all 61 backend test declarations remain.
Telemetry removes its unused duplicate bucket DTO and uses the existing
`iroha_torii_shared::status::SchedulerLayerWidthBuckets` owner.

The final focused builds have zero warnings on source
`40daf5943871f74ff82af4edb17e92b41a434856e6e598d15829efacb871ec2c`
with 19,819 unchanged inputs. All 118 selected FASTPQ tests and both bucket tests
pass on the default stack. One existing CPU timing diagnostic is ignored.
The first FASTPQ attempt's two test-boundary errors are retained separately;
they do not count as passes. Original observations, frozen changes and independent
review are under `fastpq-frame-reference-v2/`, `fastpq-frame-candidate-v1/`,
`fastpq-backend-test-boundary-v1/` and `fastpq-frame-independent-review-v1.json`;
the final build/runtime records are under `consumer-next-candidate/`.
Source-size checking still fails with 235 findings and 171 unchanged exceptions.
The Core/Torii check passes the corrected FASTPQ/telemetry boundaries and stops
at two obsolete `IvmPath` frame markers in Genesis. Its build script also records
the isolated source's unavailable Git commit marker; this is not a release build.
Strict FASTPQ library/test Clippy stops in six unchanged dependency sites: one
needless lifetime in Halo2 and five SoraFS API lints. This is a failed lint run,
not qualification of the unreached FASTPQ lint target. The exact outcomes and
26 qualified live owner paths are bound by `fastpq-frame-candidate-v1/qualification.json`.
This is scoped codec/stack evidence, not proof-system, compiler-memory, workspace
or release qualification.

Genesis paths now use String payload decoding directly, preserving caller layout,
prefix consumption and nested resource limits. Fallible archived decoding returns
typed String errors. The three containing records use Norito's generated prefix
decoders; their fields, valid serializers, JSON codecs and validation remain
unchanged. No standalone path frame is introduced. Nine regressions cover exact
bytes, all advertised record layouts, containers, malformed input, exact-tail
rejection, inherited allocation/field limits and restored caller state.

The complete Genesis library passes 118 tests with four existing diagnostic cases
ignored, on source
`968229f704aa81498f7a1dbdf81f55ef6b5ae62890e03a79a8eadcc023289ac4`,
with 19,820 unchanged inputs and zero build warnings. Full-suite corrections supply
mandatory protocol/authority fields in test fixtures, align the SM signing/curve
fixture, verify eight example registrations after the generated parameter prefix
and all four validator PoPs, and compare canonical registry wire IDs while rejecting
Rust-name aliases. The Taira source template supplies three missing null enum-content
fields. Production validation is unchanged. Formatting and codec guards pass.
`genesis-payload-candidate-v1/qualification.json` binds the six live source owners,
retained artifact and runtime. The initial import error, one incorrect canonical
field-length expectation and seven full-suite fixture failures remain recorded.
The earlier node check reaches 14 IVM and 273 P2P codec errors on its separate
`0b80bd5776b049c87552cd8567e98a8c50e8d1e88d7b9169a180efa2fdf82ab5`
source. Final-source strict Clippy stops at nine service-model documentation sites.
A separate comment-only correction fixes those sites and strict service-model
Clippy passes for all targets on
`d35b39e0ec72998f1f37ae464fdaeab07a310d1db0ca5d994ff1d083e7bd2a5a`.
The same-source Genesis Clippy run then stops at three excessive-argument and two
unit-error API sites in SoraFS. Both failed runs remain;
`service-model-doc-markdown-v1/qualification.json` binds this narrow correction.
There is no passing dependent/workspace lint, node or release qualification.


The IVM follow-up declares six measured frame owners and routes the private
registry's diagnostic decoding through the registry itself. The original-codec
capture records 65 complete root/Option/Vec frames before declaration changes.
Batch envelopes use their one declared frame hash; signature preimages, codec
bytes, ABI, gas and production admission limits remain unchanged. The retired
argument-shape test now frames its unchanged payload under the actual record
identity before asserting rejection. Separate fixtures exercise the full
256-level logical type limit and the 33-level JSON nesting limit, including
rejection beyond each limit; the normative ABI assertion counts registers r10
through r15.

All 774 default IVM library tests pass with no ignored cases on source
`1cc39965cf1079960933795fab51066c8bdbab8e61abcbe78bd7302eb90a2341`,
with 19,829 unchanged inputs, zero build warnings and the default stack.
`ivm-boundary-candidate-v2/library-qualification-v1.json` has SHA-256
`b170a7898b3474ccd1f8ca775db4a0aeff1abeb2794391f1113e84f72b4d2a7a`.
The prior full run's two fixture failures remain retained. Four integration
selections pass 18/41/1/91 tests on their separately sealed earlier source; they
are not promoted to final-source evidence. P2P's same-source default library
passes 592 tests; the subsequent QUIC selection retains one failure in disabled
DATAGRAM negotiation and two existing ignored cases. Its transport correction
and new payload-prefix checks are pending separate candidate qualification.
Strict dependent/workspace Clippy, full node/consensus and release qualification
remain open.


The next prefix-boundary tests reproduce both manual P2P decoder failures, then
isolate an enum-derive defect: its slice adapter entered an exact payload context
and reported the entire input length. Enum slice generation now uses the same
bounded prefix decoder as named records. Every enum arm retains its original
field codec, discriminant and validation hook; exact fields and complete frames
still reject unread bytes. The direct suite passes all ten enum cases, including
four new layout/container/validation/allocation regressions.

The complete default Norito suite then passes 1,338 tests with one existing
snapshot generator ignored, zero build warnings and the default stack, on source
`f6a27445597bef9361c7e323a8279e068e149c2f04cae179ffd32c37bdfde4fb`.
All 19,834 inputs and ten executed artifact identities are sealed by
`norito-enum-prefix-v1/default-codec-qualification-v1.json` (SHA-256
`ca4f3bd3c183a27af05d35cdb1f3b5f96121160bf3e7e908b34c71533e00e7be`).
The next candidate binds 19,835 unchanged inputs on source
`06cda5887fc4aef22e554a56245d368906f8f466fa52a21c7dbbfc5eacb0b35b`.
Its complete structural codec suite passes 1,340 tests with one existing ignored
snapshot generator; all 78 derive unit/JSON/UI tests pass, and default-feature
codec/derive test Clippy passes with warnings denied. The complete default P2P
library passes 598 tests; its QUIC-enabled library passes 633 with two existing
ignored cases. Both builds have zero warnings and both runs use the default
stack. This includes all six new payload-prefix tests and the disabled-DATAGRAM
regression after the listener explicitly sets zero buffers. Public QUIC
qualification gates remain unchanged.

`norito-enum-prefix-v1/structural-and-derive-qualification-v1.json` (SHA-256
`7f6d64f6f82eaaba92d27d47d0af3d099ede0dcfc9f461aa681241d06147f2b8`),
`norito-enum-prefix-v1/strict-clippy-qualification-v1.json` (SHA-256
`873269df7b453504c51fd0ea0fe268020de42557995a754cfe95168beb5e5b03`),
and `p2p-payload-prefix-v1/full-library-qualification-v1.json` (SHA-256
`ea5e7c5c7055e816c40536bccc3f13fefd0cd33b48876af4f4526c6a19e49a0a`)
bind the exact artifacts, source and retained results. Earlier default IVM and
BFV results retain their distinct source seals; they are not promoted to this
candidate. The first Core/P2P build exhausted disk space while writing compiler
caches; the retried Core build reports 1,525 diagnostics across the remaining
frame-owner/trait migrations and produces no Core test executable. Both failed
attempts are retained. Full Core, dependent/workspace lint, measured memory and
release qualification remain open.

Borrowed singular-query sources now implement payload serialization only. One
private output frame selects the owned result's identity and preserves its
alignment without constructing the result. Iterator/option/struct/trigger views
and six Musubi page producers carry no independent frame projection. The output
frame ceiling, active allocation limits and source-drop-before-decode sequence
remain enforced. All 22 focused query-memory tests pass using the exact module
source and built Norito/model dependencies, including five new identity,
alignment, payload-only, allocation and drop-order regressions. That harness
does not qualify the full Core crate or Musubi/trigger callers; their complete
consumer build remains pending. The exact query-memory source, 22 passing tests
and independent review are bound by
`core-singular-payload-v1/focused-qualification-v1.json` (SHA-256
`ef3c7735fffae50496065ca68b91ce09e3d0952fbd8801e7686f3f0b6d52863b`).

Twelve additional actual Core frame owners now declare their measured identities:
three STARK parameters/key/envelope records, two recursion archives, six outgoing
operation/redemption records and the trigger-set persistence DTO. Their 24
original directional observations retain the same nominal names, explicit root
projections, field order and payload bodies. Nested DTOs and removed-shape
negative fixtures stay payload-only. The trigger executable's source-owned
payload regression passes with the current model/codec dependencies, including
fixed/compact field boundaries and malformed input; no full trigger-store
qualification is inferred from that focused harness.

The combined candidate binds 19,844 unchanged inputs on source
`0d431ab01f1b91896a51cae26295e4437a4eced0f4add462dd42e7cf9085e2fc`.
Its Core test build still fails with 1,252 diagnostics and no executable, with
zero compiler warnings plus the isolated checkout's recorded missing-git
build-script notice. The intermediate query/STARK build retains 1,350 diagnostics
on its separately sealed source. Neither result is a passing Core build. Scoped
formatting, patch checks and codec guards pass for all 18 changed source/fixture
paths; the complete state/consensus, workspace, native, memory and release gates
remain open.

The following Core stage declares 42 actual KAGEMUSHA state owners (deleted
with the old KAGEMUSHA state on 2026-10-05) and 25 finalized-query owners from retained directional identity observations. Eight
commitment functions and their private preimages move unchanged into one cohesive
module; the state root falls to 4,858 lines and the commitment module is 312 lines.
The one previously uncaptured function-local lane-binding record retains its
compiler nominal with a source assertion; it is not claimed as original capture
evidence. Existing Kura/private-settlement changes are reconciled as a separate
54-owner, 103-observation slice. These observations establish identities and
unchanged record bodies, not original complete frames or passing state recovery.

Bare receiver accounting, query memory meters and their callers now require only
payload serialization. Sort keys require ordering, with their preflight byte
budget still enforced before allocation. JSON-only tiered values retain their
existing hash/accounting contract without a binary-frame requirement. Two exact
receiver-accounting tests and eight exact query budget/heap/sort tests pass on the
default stack. The query tests replace their shared static observation counter with
fixture-owned counters excluded from encoding; the retained harness inherits
worker settings and does not independently establish parallel execution. Four unused-code warnings belong to that partial-module harness.

Seven further DA/query persistence owners preserve 13 original directional
observations and all 191 earlier assertions. Their production tokens are
unchanged except for declarations. The checkpoint descriptor stays a nested
payload under its durable journal owner. All 25 tests from the complete query
index/checkpoint/journal/shard/rowset modules pass using the actual filesystem,
codec/model and compression dependencies, with inherited worker settings and
the default stack. The old harness report says default parallel execution but
does not pin or record a worker count; that wording does not qualify concurrency.
Three unused-code warnings belong to this focused harness; DA quota/cursor,
Windows, Core state/consensus and release execution are not qualified by it.

The intermediate Core source `c2cc2094e1049fd936877d075c4706f92d11d744f5c5a52a31c3b4245be5d794`
binds 19,852 unchanged inputs and still fails its test build with 534 diagnostics,
zero compiler warnings and no executable. The earlier 1,080- and 542-diagnostic
builds are retained. A separate early failure exposed a missed production import
that the original focused harness supplied; the corrected production import and
its full-build check supersede that initial review. None of these failures is
reported as a passing Core build. The focused source/artifact records are
`core-query-fixture-isolation-v1/query-isolation-runtime-1/qualification.json`
and `core-da-query-frame-adoption-v1/query-persistence-runtime-2/qualification.json`.
The original sequential seven-test query result and failed persistence harness
are retained with their exact limitations.
All 45 scoped Rust formatter checks pass. The authoritative repository source
budget still reports 236 findings with 171 unchanged exceptions; the two
KAGEMUSHA modules above pass their individual production limits. Codec guards
and exact historical-archive verification pass.

The subsequent queue slice keeps eight actual frame owners with 16 captured
original directions. Route legs stay payload-only; the synthetic queue context
hashes their bytes under an explicit layout, with ambient-layout and exact
payload checks. Routing-plan and journal owners retain typed framing and
substituted-header rejection. Unrelated concurrent reservation/recovery changes
are preserved in ROOT and excluded from this isolated adoption slice. Its five
formatter and exact patch-replay checks pass; queue runtime remains pending.

The combined Core source
`a561f59d7c223d665dec71a47aa7b2538cbae88714399133ff5cb1eec666fbb7`
binds 19,852 unchanged inputs and fails with 389 diagnostics (157 distinct
messages), zero compiler warnings and no test executable. None of the latest
changed query, queue or DA sites has a primary diagnostic. This is still a failed
Core build, with the isolated checkout's missing-git build-script notice retained.
The source-bound result is `consumer-next-candidate/core-queue-query-persistence-build-1.json`
(SHA-256 `98f72656e6ec27967a7504b6176a4a34ec7eb8b87073828038d49994a7b16035`).
This partial-source failure is retained; the full-source reconciliation below
supersedes it for current Core compilation. State/consensus execution and all
broader qualification gates remain open.

The complete working-tree reconciliation preserves all existing changes and binds
19,865 inputs to source `2d9d8ffd95e96afaa0c174f5fd61fe58c850f344d0e4a4856e0d294b90c55839`.
The full Core library test build passes with zero compiler warnings; its retained
executable is `9e8fc627300ff92adea2538bcf1b408514f11de200b9207cc059e635a6f21047`.
The isolated checkout notice about missing Git metadata remains recorded. On the
default stack, this executable passes all 55 Native AMX, 258 DA, 21 projection
persistence and four index-status tests. Four-worker runs pass 24 frame-owner,
11 lane-drain and eight merge tests. The model and crypto test builds also
pass with zero warnings; four-worker default-stack runs pass 32 Native AMX
model tests and 82 hash-related crypto tests, including both direct schema
recursion regressions. The other selections inherit the host
one-worker setting; this is not a claim of default-parallel qualification.

A separate frame-identity run passes 29 and fails one provider archive fixture:
its default retention epoch precedes its approval. The source correction gives
the fixture its existing order deadline as retention and keeps production
lifecycle validation intact. The complete query run passes 156 tests and fails 22. It finds metadata keys
charged as source rows, two identifier decoder field-bound failures, and stale
authority/configuration/resource fixtures rejected by current validation. The correction separates source-item accounting from
key-byte work, keeps skipped rows and history projection work charged, and
adds exact-budget and one-unit-short controls. The subsequent full Core runtime
results are recorded below; the failed reports remain unchanged. The new identifier bound is the complete borrowed
root payload, including its discriminant and field prefix. All 14 tests from
the complete canonical top-K module pass on the default stack with four
explicit workers, retaining exact allocation and one-byte-short rejection
controls. This focused artifact is `ef40dc702781450d1f94ad0e85c367ff22868bc9dae9eee48f8454b9e4af6454`,
with exact source and dependency seals in `core-canonical-id-root-budget-fix-v1/runtime-1`. Three uncalled-public-API warnings belong to this isolated module harness.

The ten-path correction bundle binds source
`25b0562999e5d8123096ad0050d48f89ea5cde90aea8cfac7e9a20dc2d79d294`
with 19,866 inputs. Query fixtures now use registered, explicitly authorized
readers, valid configuration and execution geometry, and individually valid
JSON rows that cross the aggregate tail bound. All 302 earlier assertions
remain; five positive/boundary controls are added. The first Core rebuild
reaches LLVM and fails from exhausted disk space, with zero compiler warnings
and no executable. Its source seal remains unchanged. Only idle model/Core
incremental caches from the task-isolated target are reclaimed; sources, actual
library/test artifacts and evidence are retained. The second build passes with
zero compiler warnings and retained executable
`f54bb8fd3efa1438ccf1f77774bf8d118e441680e3f9093a58bf460de0823ecf`.
Four-worker default-stack runs pass all 258 DA and 31 frame-identity tests.
The complete query selection passes 180 and fails one; the provider archive
selection passes 40 and fails four. The remaining query fixture constructs its
state overlay from a dummy header instead of the block it actually validates.
The correction uses the actual header and asserts the exact descending domain
batch. The four archive fixtures change projected deadlines without changing
their canonical order payloads. Their correction updates both representations
together, retaining production validation and all previous assertions.
The combined Core/model/schema test build passes with zero warnings on source
`fff529153d260f6bca32859c2503fede7b084845ed7867b8de8b3e98232647d3`
with 19,868 unchanged candidate inputs. A test-only schema closure correction
then binds source `809c092f3f92d300dced319010c8bfb8b91d1f547d1e379f76dc140a39403d01`;
all three Cargo test targets still build without warnings. Four-worker runs on
the default stack pass all 181 query, 258 Core DA, 31 frame-identity, 53 model DA,
32 model Native AMX and nine schema-generator tests. The model tests include the
maximum 4,096-source schema/codec/hash/drop regression and both permanent receipt
tests. These are selected suites, not the full model or Core library runtime.
`runtime-stage-809c-v1.json` binds all seven reports, including the provider
failure below (SHA-256 `c1a01804c432c6d7366f7aad7d57665fb610e5754994635085ef70062839369a`).

The schema closure check now iterates actual stored `Metadata` references rather
than parsing type names. Its exhaustive variant match checks every stored edge
without recursion and does not expand `HashOf<T>` phantom referents or leaf
`Compact<T>` name parameters. Four additional controls exercise dangling edges,
independent map/result slots, valid cycles and phantom parameters. The complete
current registry is closed under these references; all nine tests pass both in
the exact-source harness and in the Cargo-built test executable.

The provider selection initially passes 39 and fails five because its shortened
six-second order window still carries a ten-second ingest SLA. The corrected
fixture sets both values explicitly and rejects a seven-second SLA. The unchanged
default fixture, exact replacement window and both oversized SLA controls pass
three source-bound canonical-component tests with zero warnings. Production
validation, default fixture values and all previous assertions remain intact.
The complete Core archive rerun on source
`bdf268c369fbb170155538901874f996478dfa46bde2d4be9b0d7233fc149f99`
passes 43 and fails one: the approval-substitution fixture approves after its
order was issued, so local validation rejects it before the intended history
check. That fixture now issues at epoch two, expires at seven and uses a
five-second SLA. Explicit positive controls prove both modified records are
locally valid before the unchanged substitution/rollback assertions. Four
canonical-component tests cover the original default, both replacement windows
and oversized SLA rejection.

The final combined Core/model/schema test build passes with zero warnings on
source `70f4ec63fa35913aa645eeb5b86cee6ee811f9bc3e7421c4977594d043afecc8`
with 19,868 unchanged inputs. All 44 provider archive tests then pass with four
workers on the default stack, including the history controls. The model and
schema executables are byte-identical to the passing `809c` build above; only
provider test fixtures changed afterward. The final checkpoint
`stack-root-final-runtime-checkpoint-v1.json`
(SHA-256 `317c3b4e60aaba7059b3c348f9e8cbb8240ce29cf9c40b102b72ec1601f754a8`)
binds these reports, the retained failures and source-preservation checks for
all three stack-fix owners and 18 BFV audit paths. The earlier 799-case BFV audit
retains its own source identity; it is not a fresh run on this final source.
These scoped results do not qualify full workspace, native, memory or release
acceptance.

A freshly rebuilt original dependency graph reproduces the exact Torii receipt
DTO and writer in their original crate/module scope. Ten original complete
root/Option/Vec frames retain nominal
`iroha_torii::da::persistence::StoredDaReceipt` and both directional root hashes
`f4b055d4b6a06ed2ff40fb14e1400fb3`. The corrected shared model keeps that one
wire owner. The source-bound original capture is
`stored-da-receipt-original-reference-v1/capture-seal.json`
(SHA-256 `d7903477574dc1739e5b795a1ed7fe4970f3e4acaad53922781b1150d441c7ac`).
The current shared-model probe passes with zero warnings and all ten original
records equal byte-for-byte, including names and frame hashes. Its comparison
seal is `stored-da-receipt-current-comparison-v2/comparison-seal.json`
(SHA-256 `b7c15645db5ec7406afe6aa7a3cb3c0ee049e520cd1abdcbc98ce573f6ae23d3`).
The first copy attempt failed from disk exhaustion before probe compilation;
that failure is retained, and the successful attempt uses copy-on-write
dependency retention. This bounded DTO/writer reproduction does not qualify
full Torii or receipt-signature authentication; actual Torii execution remains
open. The ten captured frames now have permanent model regression tests. The
complete new test module and existing owner test pass against the actual current
model libraries: two tests, zero warnings, four workers and the default stack.
They also reject truncated, trailing and corrupt frames under an unrelated
ambient layout. The exact-module qualification is
`stored-da-receipt-golden-runtime-v1/qualified-proposal.json`
(SHA-256 `e8cac1dc8b70cfa6769cc1a26051783fc67325c8f1227862d29313e75dedd609`).
These tests and the byte-identical original fixture are integrated. The combined
build and 53-test model DA suite above qualify their actual model test executable.

All 16 feature-resolved normal/build dependency-boundary selections and 45 guard
tests pass on this full source. Manifest dependency budgets remain failed. The
reviewed original baseline attributes all 24 changed metric cells to four
`rustix` filesystem edges, one dependency-free `fastpq_isi` edge and two removed
build-support edges. Required no-follow filesystem checks remain in place; no
budget has been widened. CLI-only SoraFS validator migration is inventoried but
not implemented by this checkpoint. The reports reside under
`consumer-next-candidate/core-full-root-*`, `full-root-architecture-checks-v1`
and `full-root-budget-attribution-v1` in the retained evidence directory.

The SCCP correction changes only three stale test provenance pins to the existing
Tolk-owned StateInit fixture, authenticated against its generator and source
history. Its independent minimal-feature run also passes all 194 tests, retaining
one model-private helper warning when governance instructions are absent; the
combined zero-warning build does not erase that separate feature-graph warning.

The executor's original multisig hash failure exposed an extra JSON field-length
prefix in Kotlin. One shared Rust-produced vector now binds the exact bytes and
independently checked hash; Kotlin removes the redundant encoding layer and rejects
the malformed form. Three Kotlin checks and one Java consumer of Kotlin pass after
two of these four tests fail against the original adapter. The permission test
also asserts the actual `AccountAliasDomain` JSON array without changing production
serialization or its rejection controls. The broader JVM selection passes nine
and fails ten because the mandatory ABI-23 native address validator is unavailable.
Those native controls, duplicate Java retirement and complete JVM delivery remain
unverified; see the [JVM inventory](jvm_consolidation_inventory.md#canonical-custom-instruction-bytes-2026-09-09).

`SamplePayload` and the SoraFS revocation preimage now have explicit identities
captured from the original compiler artifacts. Their canonical fixtures preserve
original complete bytes; existing streaming and signing fixtures remain unchanged.
Collection tests exercise explicit key identities, all seven collectors, both
map iterators and rejection of substituted headers. Relocation tests compare
complete frames and decode them through the relocated owner.

Evidence under ignored `target/architecture-redesign/norito-identity-cutover/`
retains source snapshots, overlays, actual compiler artifacts, runtime logs and
failed attempts. Default Norito qualification binds source `477519a40a51aab11797ba39d084b2ba504aae2df46caeac42929a3bfd16aafe`;
structural tests and Clippy bind `49ceaee184ae3934f775446122199201dae94fafbdc4cf6ca5819ae5c477f7a5`;
SoraFS binds `8fd5d380f9079cf1166075a1ee77e3f38f791ad0e2f94ffe5723307f21f9ee50`.
The final derive unit correction and doctests bind `5e710048ae3ba387ef32290863dc4f054500531123c333b8338b61bcc2f89a5e`.
All runs use the default stack and retain their source/artifact identities.

The subsequent model frame-owner capture observes 54 directions across 28 owners
from source `728f117b6a49428099460043e0aa152947073d4581e773938d5f29b53328ecfe`.
All selected probes pass; 91 instrumentation-only `unnameable_test_items` warnings
remain recorded. All 28 owner bodies match that reference before declaration.
The fixed [observations](../crates/iroha_data_model/tests/fixtures/frame_owner_identity_observations.md)
and co-located tests retain the actual nominal names, roots and direction hashes.
The model production check passes with zero warnings on consumer source
`70bf43693cbd3c0c637b0d1808f8cc2b72f34c129fed9195b061ac6edc0b1572`.

Bare AoS fields, canonical slice adapters, Register/Unregister children and version
payload decoders require payload contracts; actual instruction frames keep their
typed contracts. The config scalar suite passes 36 tests and version suites pass
12 tests; strict all-target Clippy passes for both packages on their retained
consumer snapshots. The model and ABI runtime results above retain their own
source and artifact identities.

The first check-profile candidate result reused a stale proc-macro artifact and
is discarded as candidate evidence. Subsequent overlays advance source mtimes
and actual rebuilds qualify the changed macro. Earlier race, launcher and
assertion failures are retained with their corrections; none becomes a pass
without executing the corrected artifact.

The sections below retain preceding declaration and reconstruction checkpoints.
Their pending-cutover statements and feature failures describe those historical
source snapshots, not the current codec. Complete model/consumer closure,
physical model extraction, memory measurements and release qualification remain
open.

## Streaming wire declaration checkpoint

The integrated batch closes declarations for all 84 current production binary
owners in `norito::streaming`: 70 root records and 14 `codec` records. Each
explicit nominal identity is captured from the pinned compiler and checked
against both existing codec directions. The immutable
[`streaming_wire_identities.json`](../crates/norito/tests/fixtures/streaming_wire_identities.json)
and [`streaming_wire_identity_frames.json`](../crates/norito/tests/fixtures/streaming_wire_identity_frames.json)
retain those observations and 396 complete/bare frame records across 132
populated values and their root, Option and two-element Vec forms. Root enum
variants are covered. Header checks include the actual required alignment
padding, zero padding bytes, advertised flags and exact payload length;
decode/re-encode comparisons preserve the captured bytes.

The implementation and its large test module move into `streaming/codec.rs`
and `streaming/codec/tests.rs`, retaining the original module namespaces,
visibility, declared identities and every existing assertion. Final default Norito tests pass 1,308 cases, and
`--no-default-features --features base-codec --lib` passes 456 tests; each
selection has one existing ignored case. Strict
`cargo clippy -p norito --tests --no-deps --locked --offline -- -D warnings`
also passes. All three runs retain the same 19,297 final candidate inputs
unchanged, with no stack override. The integrated code/budget paths match those
qualified inputs. A fresh rerun of eight settlement cases and the removed-layout
case also passes on that seal, without a stack override; the owning live model
and hash sources match the candidate. This includes the populated 4,096-source
schema/codec/hash/drop regression.

A subsequent isolated structural-feature check exposes an existing enum derive
mismatch: serialization selects the structural hash, while deserialization
retains the nominal default. The unfixed runtime regression fails at directional
hash equality. The integrated correction emits the same existing hash-selection
body in both directions, retaining explicit `schema_name` projections and
unchanged default-mode identities. Its regression checks high-level, reader,
core archived/slice and ArchiveView paths, including wrong-header rejection.

The streaming guards compare all 84 declared nominal identities to the
unchanged captures independently of the active hash mode. Default mode still
compares all 396 complete frames; the structural branch compares populated bare
bytes, advertised flags and alignment while checking active directional/header
equality, exact roundtrips and malformed-frame rejection. Runtime qualification
of these streaming guards is limited to default/base builds: the structural
library selection cannot yet compile. The captured rANS checksum stays fixed in
the fixture value, and default mode verifies the original checksum calculation.
These fixtures validate wire representation, not signed-table authorization.

The final combined default run passes 1,380 tests: 1,309 Norito, 57 derive-library
and 14 strict JSON cases, with one existing ignored case. Base-codec library
tests pass 456 cases with one ignored. Strict Norito `--tests --no-deps` and
isolated derive-library `--lib --no-deps` Clippy both pass with warnings denied.
The derive cleanup removes unused `Debug` from private attribute records,
retaining all parser diagnostics through explicit error extraction at 11 test
sites; no dependency or dependency feature is added. All final checkpoints bind
`qualified-correction-inputs.json`, with 19,297 unchanged inputs and no stack
override. These results are distinct from the earlier 1,308-test checkpoint;
the integrated correction paths match the qualified candidate exactly. The final Native AMX
selection also passes all 32 tests, with no failures or ignored cases and no
stack override on that same seal. It includes the populated 4,096-source
schema/codec/hash/drop and removed-recursive-layout regressions. The
`qualified-correction-native-amx-checkpoint.json` checkpoint binds this result
and exact live model/hash owner correspondence; the earlier nine-case run
remains separately bound to its prior seal.

Only the six focused schema integration tests ran successfully under
`--no-default-features --features base-codec,schema-structural`, with zero
failures or ignored cases on that same final seal. The complete structural
group diagnostic remains failed: 109 pass and ten fail, comprising eight
compression assumptions when compression is disabled and two existing nominal
streaming-ticket goldens. The separate structural library selection fails
compilation with 24 errors across 15 test owners. In particular, payload-only
generic decoder regressions must retain their schema-free leaves; adding
frame/schema bounds would weaken their contract. Closing that coupling requires
the planned identity separation. No tests are disabled to obtain a pass. The
atomic trait transition, remaining owner/feature closure and physical model
extraction are still pending.

## Source review queue

The 2026-09-06 lexical inventory scanned 4,808 Rust files under `crates`,
`integration_tests`, `mochi`, `xtask`, `data_model`, `scripts`, `tools` and `python`.
Its source-content digest is
`cc2c760fe2ec0080c200c9c096b8ae8f75d3acf120628958b7ce629dd5f0021e`.
Generated rows and the read-only scanner are retained, untracked, under
`target/architecture-redesign/norito-schema-source-inventory.*`.

The queue contains 5,557 codec-derive attribute sites (verified import aliases
included), 262 explicit Serialize implementation sites, 189 explicit
Deserialize sites and 155 `schema_name` attributes. Sites occur in 661 files
across 47 owners; 122 manual implementation sites have generic self types.
These are **lexical source sites**, including tests, cfg branches and macro
templates, not expanded types or production-only counts. They are historical
review evidence bound to the digest, not a numerical completion target.

| Owner | Codec/identity derive sites | Explicit Serialize | Explicit Deserialize |
| --- | ---: | ---: | ---: |
| iroha_data_model | 2692 | 52 | 54 |
| iroha_core | 757 | 19 | 7 |
| sorafs_node | 414 | 1 | 1 |
| sorafs_manifest | 276 | 34 | 0 |
| iroha_torii | 271 | 20 | 10 |
| norito | 235 | 71 | 55 |
| iroha_torii_shared | 141 | 12 | 12 |
| iroha_crypto | 119 | 13 | 11 |

The source queue is not a coverage proof. The syntax inventory follows
source declarations, local items, aliases and cfg attributes; compiler checks
must cover macro families and every supported target/feature selection.

The subsequent syntax scan contains 4,827 physical files, 5,551 candidate
codec/identity declarations and 452 manual implementation sites. Of the
declarations, 40 have generics and 148 are local items. Its source-set digest is
`7a8a9f89e332e1c56e74b3383acc98aaf01f4a6edd207c2861ce85d1293c8279`.
The expression-only `irohad/src/main/online_peers_provider.rs` include fragment
remains a parse gap in physical-file mode; the scan exits nonzero. These counts
include alias hints and inactive configurations, not compiler-confirmed types.
The compact review queue is retained under
`target/architecture-redesign/norito-syntax-codec-review-queue.json`.

The inventory's `--crate-root` mode retains each module/include occurrence,
raw cfg predicates and unresolved expansion sites while sharing physical file
records. Its 32 tests include five independent compiler checks for ordinary
modules, explicit paths and include-relative resolution. The model/crypto graph
visits 953 contexts across 367 physical files and resolves 951 edges. Three
dynamic include arguments in the model crate root remain explicit access gaps;
macros and attribute expansion are review records, not simulated expansion.
The graph source-set digest is
`b23217a8f1b81ee58fc2ecabd0fe8d5abf715792af18910a064d17ee9eae9abd`.
Physical-file mode and crate-root mode are mutually exclusive. Function-local
include fragments retain their occurrence and bytes but remain parse review.

### Compiler capture

`scripts/norito_schema_capture.py` prepares an isolated source snapshot and
runs one explicitly selected library or integration-test harness. Preparation
reuses the authoritative build profiler's source-copy and sealing primitives.
Initialized Git links are expanded into explicit dirty file inventories, with
indexed and checked-out revisions recorded. Absent links remain recorded.
Only the copied Norito derive entry points append capture probes; their
original codec generation bodies and the shipping source are unchanged.

Each registered nongeneric probe reports the actual compiler `type_name`,
the existing directional codec hash and its root-name hint. A mismatching hint
remains unresolved evidence. Generic declarations emit review records without
invented instantiations. Function-local tests are not registered by Rust and
remain inventory gaps; source lint policy is retained. Eight generator tests
pass, including an independent compiler fixture covering private, generated,
raw-identifier, generic and unregistered local cases.
For prepared nongeneric declarations, probes additionally check the explicit
identity against the still-active codec; this check is for the preparation
phase before physical moves and atomic codec cutover.

Seventeen driver tests cover source isolation, dirty Git links, drift rejection,
strict collection and preservation of prior evidence. Each actual run retains
the command, environment digest, source seals, concrete Cargo/rustc identities,
Cargo's test artifact, harness digest and transcript. Both compiler wrappers
are explicitly disabled, including configuration overrides. Each run builds
into a fresh target with `--no-run`, then directly invokes the sealed harness;
Cargo runner configuration cannot substitute the test process. Postchecks
also reject driver or capture-manifest drift. The collector requires
one successful harness and a record for each executed probe. This evidence
does not prove declaration coverage, wire-frame equivalence, or release
qualification. Remaining manual/generic/macro and feature/target gaps require
review and the immutable fixtures before the codec cutover.

```sh
python3 scripts/norito_schema_capture.py prepare --out /absolute/external/capture
python3 scripts/norito_schema_capture.py run \
  --snapshot /absolute/external/capture --name crypto-lib --package iroha_crypto
```

The controlled crypto library capture passes 206 probes: 110 concrete nominal
identities and two generic review records. All captured root hints match the
existing directional hashes. It binds source digest
`022600a39250a065c28d88855a141ce2587758928f6a66d15d9a7f79cd11fcf7`
and report SHA-256
`fb59df9e9407f74b2ec39d972ebcd1ebeb75ef78c52eda49b9dfec50793333ca`.
The earlier pilot lacked explicit wrapper controls; its retained records match
the controlled run exactly, but the controlled report owns this evidence.

The controlled model library-test capture passes 6,112 probes, yielding 3,121
concrete nominal identities and 34 generic review records. All root hints match;
54 directional records have explicit root projections. It uses the same frozen
source and report SHA-256
`be82d3661d9e2a79fd1a60d6922f1387d3821a0ad5a65d80d294aca1251caedd`.
Its resolved Cargo features, including `transparent_api` from the test graph,
are retained in the report. It does not qualify other feature combinations.
The source intersection matches 2,556 ordinary declaration sites; 842 generated
or unmatched observations and 288 observations with stale/missing physical
inventory remain separate review records. A reviewed 1,771-declaration ordinary
batch is applied across 107 files. Its 3,467 captured directions comprise 1,696
bidirectional types, 68 serializer-only types and seven decoder-only types.
Module-owned immutable fixture suites preserve those codec capabilities and
original cfg scopes. All 110 owner-scoped tests pass on the sealed
post-declaration harness, and a second controlled 6,112-probe capture is exactly
equal to the pre-declaration capture after excluding source coordinates. A
wider sealed model run completed 3,045 passes and exposed 37 failures that
still require disposition. That historical run predates the finite Native AMX
participant-settlement wire repair; therefore it does not qualify the complete
model suite.

### Batch declaration migration

The inventory counts derive sites, not distinct types. Insert one independent
`NoritoSchema` implementation per logical declaration; do not independently
generate identities from both Encode and Decode. A one-time syntax-aware source
tool can perform verified insertions without weakening the explicit contract.

Inventory package/source spans, inclusion contexts and cfg predicates. Resolve
derive aliases and follow module, path and include declarations, grouped test
roots and supported macro grammars. Unknown expansions, repeated inclusions and
ambiguous owners require review. Proposed names reconstructed from paths are
not evidence: isolated capture probes must obtain actual names and both codec
hashes from the pinned compiler before the tool inserts any literal. Source
hash checks, stale-source rejection, idempotence and duplicate-impl rejection
are mandatory. The runtime has no inferred-name fallback.

`scripts/apply_norito_schema_identities.py` implements the read-only patch stage
for reviewed ordinary struct/enum mappings. It validates the complete batch,
exact UTF-8 spans, original source digests and explicit names before emitting
one diff. Its 25 tests cover stale/ambiguous input, idempotence and actual Git
patch application with CRLF and missing final newlines. It deliberately rejects
unresolved contexts and visible alias/wildcard cases. External semantic
resolution and compiler checks still own trait-implementation uniqueness; this
helper is not a compiler capture or coverage proof.

| Generator | Required declaration input |
| --- | --- |
| `model` / `model_single` | Preserve explicit attributes through the expansion; capture actual private `model` names. The 12 Nexus `model_single!` records have their own captured declarations and complete populated frame/carrier fixtures. Remaining callers and features still require closure. |
| `EventSet` | All 25 production `*Set` types and the test caller supply a required literal child identity. The generator derives that identity once, independently of the parent, and shares strict metadata parsing with `RegistrableBuilder`. |
| `RegistrableBuilder` | Each of the two production callers supplies a required literal identity for its generated `New*` child. The generator has no fallback and rejects missing, duplicate, unknown, non-literal and invalid metadata. Eight generator tests, three compile-fail cases and 23 asset/NFT owner tests pass. |
| `data_event!` | All 12 generated parent enums and their set children have explicit captured identities; the template emits one parent identity derive. |
| `queries!` | All 127 concrete query declarations supply captured literal names; the template emits one identity derive and requires each declaration's identity. |
| `enum_type!` | All 12 current instruction enum callers supply captured literal identities; the template emits one identity derive. The compiler exposed two callers absent from the historical review, and both received their own pre-declaration capture. Private discriminators keep their visibility. |
| `isi_box!` | All 12 current callers supply captured literal identities; the template emits one identity derive. Exhaustive matches and immutable fixtures cover all 68 variants, including populated generic instruction payloads. |
| `isi!` | All 289 current declarations supply captured literal identities; the template emits one identity derive. The 280 nongeneric records and 39 instantiated generic forms preserve 354 values and 1,416 complete frames. Tests cover every retained record and the 12 generic argument markers. |
| Musubi digest/text/page macros | All 12 digests, three bounded-text wrappers and two page wrappers supply captured literal identities. Each template emits one identity derive. |
| Governance hash macros | All 16 handwritten-codec wrappers supply captured literal identities; the generator emits one independent identity derive and retains the codec bodies. |
| Privacy/spentness carrier macros | All 62 generated types supply required captured literals; each of the four templates emits one identity derive without changing constructors, codecs or validation. |
| `EnumRef` | Explicit child identities only for existing codec or typed-marker uses; no new wire surface for ordinary helpers. |

The historical generated-family review is a capture subset. A current source
inventory finds 289 `isi!`, 12 `isi_box!` and 12 `enum_type!` invocations,
compared with its 144, ten and ten named observations respectively. The two
additional enum callers now have separate compiler captures. The current
instruction callers now have their own capture and populated value coverage;
the historical counts must not be treated as closure.
The untracked `target/architecture-redesign/current-instruction-macro-inventory.json`
records source hashes and that intersection without inferring missing names.

A fresh local test capture now records 433 compiler identities, including every
current instruction registry entry, all nongeneric `isi!` and `isi_box!` callers,
39 concrete generic instruction forms and their model markers. Existing tests
supplied 386 distinct values across 303 concrete types; the initial intersection
exposed 51 nongeneric instruction records missing value fixtures. The
subsequent box capture adds deterministic generic values and closes all box
variants. A further capture fills all 51 record gaps from typed fixture values
before the declarations change. The [record fixture](../crates/iroha_data_model/tests/fixtures/instruction_record_generated_identity_frames.md)
now covers all 319 current instantiated record types and preserves 1,416 frames,
after removing three unimplemented citizen-bond operations from the instruction
surface without changing the remaining captures.
Neither the registry nor the historical capture is used as a proxy for this
coverage. Twelve additional generic argument markers retain their captured
nominal names; both existing codec directions match the independent identity.
The source hashes and original captures remain under untracked
`target/architecture-redesign/instruction-macro-current-before/`.

The event family is qualified locally by 27 derive unit tests and 21 integration
tests, including the compile-fail cases. The 25 set types preserve all 225
pre-declaration root/`Vec`/`Option` frames and 75 JSON values; the 12 generated
parent enums preserve captured nominal names and both directional hashes. The
[fixture record](../crates/iroha_data_model_derive/tests/fixtures/README.md)
records the capture digest and scope. Full-suite validation also removed the
utility parser's duplicate-attribute tolerance. The direct-FFI declaration
inventory was later removed with the retired `iroha_ffi` layer. These checks do
not qualify native execution or other feature selections.

The 17 Musubi generated types preserve 196 pre-declaration frames across 49
values, including text bounds, full-byte digests and populated pages. Root,
`Vec`, `Option` and `BTreeMap` frames, both directional hashes and JSON are
checked against the immutable [capture record](../crates/iroha_data_model/tests/fixtures/musubi_generated_identity_frames.md).
This remains preparation: no active codec or schema identity dispatch changes.

The 16 generated governance hash wrappers also preserve all 256 captured frames
and 64 JSON values. Their handwritten codecs were outside the derive-probe
inventory, so the unchanged generator received a separate direct compiler/frame
capture. Its actual `parliament_types` nominal names and both active hashes now
match the explicit declarations. The [capture record](../crates/iroha_data_model/tests/fixtures/governance_generated_identity_frames.md)
documents the source and fixture digests; the permanent test has no writer or
source-path inference.

The 127 generated query types preserve all 684 captured frames across 171
payloads, with JSON and frame roundtrips. Coverage includes both alias scopes,
optional anchors and all query-filter enum variants; the focused query suite
passes 28 tests. The [query capture record](../crates/iroha_data_model/tests/fixtures/query_generated_identity_frames.md)
records immutable fixture and pre-declaration source digests.

The [generic query captures](../crates/iroha_data_model/tests/fixtures/query_generic_identity_frames.md)
add 92 frames across 23 families. `SelectorTuple<T>` has one data-free wire layout,
so a single capture covers every build. Five generic owners, three concrete
query records and two typed-hash markers declare their captured nominal
identities. Permanent tests preserve complete frames, marker composition and
membership decode budgets. Active codec dispatch and schema export behavior
remain unchanged.

The [generic model fixtures](../crates/iroha_data_model/tests/fixtures/model_generic_identity_frames.md)
preserve another 68 complete frames and five actual FHE signing preimages.
MetadataChanged, Validate and Mismatch compose captured nominal argument names;
six concrete argument owners and the borrowed FHE preimage now declare their
identities. InstructionBox preserves its existing root projection to the wire-ID
and framed-payload pair while containers retain its nominal instruction identity.
The FHE helper exposes encoding only; its unusable borrowed Decode derive is
removed. All five model and four adjacent query identity tests pass on a rebuilt
default-feature artifact with 5,613 selected inputs unchanged. These checks do
not qualify other features or change active framing dispatch.

The 62 generated privacy/spentness carriers have a separate
[capture record](../crates/iroha_data_model/tests/fixtures/privacy_generated_identity_frames.md)
covering 248 payloads and 992 complete frames, including canonical six-lane
Goldilocks boundary values. Raw Ristretto carrier fixtures exercise byte
preservation only; native point validation remains a separate protocol check.
All four generated-model fixture suites pass together locally after these
declaration changes.

The instruction enum generator has one required identity derive for all 12
current callers. Its [capture record](../crates/iroha_data_model/tests/fixtures/instruction_enum_generated_identity_frames.md)
preserves 57 numeric tags and JSON values with 228 complete root and container
frames. Every possible byte tag is checked, and private discriminators remain
private. The two additional mint/burn callers received their own pre-declaration
capture without rewriting the earlier ten-type fixture. Both fixture suites
pass after the declarations; active codec bodies are unchanged.

The 12 Nexus `model_single!` instruction records preserve 120 captured frames
across 24 populated values, including root, container and `InstructionBox`
carriers. All nine Nexus instruction tests pass after their declarations.
Eleven records have no direct JSON codec; their supported instruction-carrier
JSON is captured without adding an extra wire API. Withdrawal also retains its
direct JSON fixture. The [Nexus capture record](../crates/iroha_data_model/tests/fixtures/nexus_instruction_generated_identity_frames.md)
binds the exact pre-declaration source and fixture digests. Synthetic proof
payloads establish codec preservation, not proof admission or finality.

The 12 generated instruction-box types now have required identities and an
immutable [box capture record](../crates/iroha_data_model/tests/fixtures/instruction_box_generated_identity_frames.md).
It preserves all 68 variants with 340 complete frames and 68 instruction-carrier
JSON values. The tests use exhaustive Rust variant matches and compare every
captured field; no writer or inferred identity remains in the model source.
That instruction library selection passed 336 tests after the box declarations.
The subsequent record suite passes 325 tests and the generic-argument test passes
for all 12 added markers. The current file-budget check reports 231 findings;
all newly added instruction fixture modules are within their existing limits.

The complete model `group_02` harness passes 178 tests, with two fixture writers
intentionally ignored. Its Soracloud quota tests now keep placement cardinality
consistent, check the pre-placement source quota, and prove acceptance at the
exact aggregate storage ceiling before rejecting an excess. Production
admission and codec implementations were not changed by that fixture repair.
At that checkpoint the file-budget check reported 232 findings; these
query/privacy production and test files were each within their existing limits.
All four focused Goldilocks library tests also pass, including noncanonical
field rejection through the fixed-width binary and JSON decoders. Strict
model-library Clippy remains unresolved across the wider model source; this
checkpoint does not claim a passing strict-lint or workspace qualification.
Its current run reports 130 diagnostics, including documentation, oversized
functions and comparison-grouping review. Exact primary spans and lint codes
are retained in the untracked
`target/architecture-redesign/model-clippy-query-privacy-review.json` for the
next scoped fixes; no lint suppression or file-budget exception was added.

Generic constructors require representative compiler captures preserving type,
const and erased lifetime order. Projection overrides, private/local borrowed
writers, foreign containers and marker-only types retain an explicit review
queue. Complete the batches in dependency order: Norito containers, primitives,
crypto, independent wire crates, aggregate models, then runtime/SDK consumers and
fixtures. Preparation must leave active frame bytes unchanged. Only after
coverage and fixture verification may the payload/typed-trait and codec-generator
cutover occur atomically; compile upward through supported features and targets.

## Required identity families and acceptance

- Prepared 19 primitive identities cover ConstVec, UniqueVec, SmallStr/SmallVec,
  ConstString, Json, BigInt, Numeric, Quantity, XorQuantity, NumericSpec, the three
  numeric ABI values and five private JSON/numeric wire helpers. SmallVec
  composes its array parameter, including capacity, independently of its
  Vec-shaped payload. The borrowed BigInt view retains its distinct nominal
  identity while projecting to BigInt at a frame root. Numeric ABI names/hashes
  and zero-flag fixed-width frames remain specified in
  `iroha_primitives/src/numeric_abi.rs:18–34`.
- Prepared MerkleTree, MerkleTreeCommitment, MerkleProof and CompactMerkleProof
  identities compose markers without payload or JSON codec bounds. The compact
  proof has no binary Norito codec; its identity and existing JSON/full-proof
  projection are tested without adding a new binary wire surface. Remaining
  cryptographic codecs and private borrowed writers still need declarations.
- Algorithm, PublicKeyCompact, PublicKey, ExposedPrivateKey and Signature now
  have explicit captured identities. The immutable fixture contains 73 records
  across 25 nominal identities, including all 11 available algorithm tags,
  generic frames and deterministic signed envelopes. Seven focused tests pass;
  they also reject truncation, substituted schema hashes and cross-decoding of
  distinct named roots that share a bare payload. The capture writer is removed.
  SHA-256: `27fd72e39a96118a8a32768ab08948c87db0b2158d854d1086adbf69bf014c88`.
- Another 108 ordinary crypto declarations now use compiler-captured nominal
  identities. Nine module-owned tests pass against 201 directional hashes in
  `captured_codec_schema_identities.json` (28,481 bytes; SHA-256
  `948233b20dd7f481885f8e0372398394667d02d6b661efab76f10c5398179d3b`).
  The source spans and names match the isolated capture exactly. This is
  identity/header evidence, not complete value/frame coverage. Seven existing
  crypto identity/wire-golden tests also pass after the declarations. One historical
  test type in a wildcard-import scope remains outside the ordinary batch;
  generic, manual and function-local writers still require explicit review.
- All 19 planned foundational model types have explicit captured identities.
  Two immutable tests pass both before and after declarations: 189 frames across
  105 nominal identities, 24 JSON/schema samples and 10 storage-key samples
  remain exact. The tests preserve signatures and scoped network formatting.
  The [extraction inventory](model_base_extraction.md) records their ownership
  closure and fixture digest. Physical moves still await the atomic cutover.
- `Owned<T>` now declares its compiler-captured nominal constructor and forwards
  `T::frame_name()`, including nested projections without codec bounds. Its
  [storage fixture](../crates/iroha_data_model/tests/fixtures/owned_storage_identity_frames.md)
  preserves 432 complete frames across nine values and 40 nominal identities;
  account/NFT/RWA storage records have their captured declarations too.
  Active codec selection remains unchanged by these declarations.
  Metadata's private `MetadataEntryRef` already implements `SerializePayload`
  for unframed borrowed fields. It needs no identity or further migration at
  the atomic cutover; it never enters typed framing.
- Preserve remaining forwarding projections such as InstructionBox's tuple
  frame (`isi/mod.rs:812`), and SoraFS
  borrowed signing views in orderbook, governance, por, potr, provider_advert and
  pop_credentials. Do not confuse a validated public type with its decode-only
  wire twin merely because their fields match.
- Capture actual nominal names, both codec-direction hashes and complete frames
  before model moves. The existing schema exporter is a seed, not exhaustive
  coverage. The initial kernel has 57 Norito and two crypto frame goldens;
  `Vec<&str>` and `Vec<Cow<str>>` currently lack the required higher-ranked
  decoder, so their recorded decode hashes are explicitly null. Status has a
  separate 32-type pre-move fixture. These fixtures do not qualify all models.
- Require explicit declarations in codec derives; add compile failures for
  missing identities, missing generic/marker bounds, duplicate declarations and
  collapsed generic projections. Keep positive object-safe payload and
  marker-only wrapper tests. Close manual and generated families before the
  active transition; do not suppress unresolved items with feature reductions.
- At cutover, replace every schema selection, including nested Option payload
  contexts (`norito/src/core.rs:3679`), core frame writers/checkers from `:6814`,
  framed decode entry points, streaming Vec/map readers (`lib.rs:9196`, `9222`,
  `9808`, `10363`, `10388`), and SignedBlock's canonical envelope checks
  (`iroha_data_model/src/block/mod.rs:1452`, `1493`).
- Require unchanged complete frames and bare payloads, including compressed and
  uncompressed input, bounded/streaming decode, root projections, signed blocks
  and numeric pointer ABI. Relocated generic headers must then match; the
  current preparation tests deliberately show that active headers still differ.
  Wrong headers, argument mismatches and truncation must reject. Run cross-SDK
  fixtures and ABI goldens without silently authorizing changed wire bytes.
- Require all supported workspace targets and feature selections to compile.
  Existing unrelated Core grouped-governance fixture failures remain unresolved;
  the integration core_api target now compiles, while its replacement
  four-validator configuration scenario still needs runtime validation. Finally,
  compare source-sealed per-unit build profiles; these preparation tests do not
  establish build-memory improvement or release qualification.

## Prepared wrapper fixtures

The primitive fixture at
`crates/iroha_primitives/tests/fixtures/schema_identity_frames.json` captures
23 complete pre-declaration frames, both available codec-direction hashes, and
actual compiler nominal/root names. Three private borrowed helpers serialize
only, so their decode-hash fields are explicitly null. The separate numeric ABI
fixture captures three complete fixed-layout frames; tests preserve zero flags,
roundtrip each numeric domain and reject the wrong domain header. The two
SmallVec capacities share payload bytes but must reject each other's headers.

`crates/iroha_crypto/tests/fixtures/merkle_schema_identity_frames.json` captures
four complete pre-declaration frames: tree, proof, commitment and a typed root
hash. Marker-only tests prove nominal composition and unchanged bare payloads
across equivalent declarations while explicitly retaining the pre-cutover
active-header difference. These files were recorded before adding the wrapper
identity implementations; capture writers were removed after verification.

Focused validation uses the existing `architecture-sdk` target slot with locked,
offline Cargo and no incremental compilation:

```sh
scripts/cargo_fast.sh --target-slot architecture-sdk --stable-local-metadata --no-incremental -- test --locked --offline -j 2 -p iroha_primitives --lib schema_identity
scripts/cargo_fast.sh --target-slot architecture-sdk --stable-local-metadata --no-incremental -- test --locked --offline -j 2 -p iroha_crypto --test iroha_crypto_group_01 schema_identity
scripts/cargo_fast.sh --target-slot architecture-sdk --stable-local-metadata --no-incremental -- test --locked --offline -j 2 -p norito_derive --features trybuild-tests --lib --test strict_json schema_identity
```

The derive emits Rust's standard `automatically_derived` marker; strict-lint UI
coverage includes lifetime-only uses so wrapper crates can retain
`deny(warnings)`. Complete generated/manual identity closure, the atomic active
codec transition, all-feature qualification and source-bound memory comparison
remain pending.

## Manual public frame ownership

Sixteen additional manual model owners now declare their actual captured
nominal identities. X.509 key usage retains its explicit boolean root
projection and distinct wrapper identity inside containers; every other owner
retains its own root identity. The complete fixtures and projections are
documented in the [public frame contract](../crates/iroha_data_model/tests/fixtures/public_frame_owner_identities.md).

`iroha_data_model` has one explicit `manual_frame_identity` integration target
for these public contracts. It also owns the existing IdBox and BlockSignature
assertions, preserving all 144 immutable frame records with one shared binary
checker and JSON checks only where supported. The seven tests pass after the
declarations and relocation, including direct fallible malformed-input checks,
on 19,313 unchanged default/HTTP inputs without a stack override. Prior full
library qualification remains tied to its separate preceding source seal.

The subsequent query/time stage adds fifteen declarations and two permanent
tests containing 181 unchanged pre-declaration frames. QueryBox remains
specialized to its existing aggregate output; QuerySignature forwards only its
root projection to SignatureOf<QueryRequestWithAuthority>. Query reconstruction
candidates have payload contracts only, and the redundant private TimeInterval
carrier is removed. The public target now passes nine tests and preserves all
325 frames, with 19,317 unchanged inputs and no stack override. Its callback
checker preserves complete semantics without expanding the public query API.

A further nine time-event and query-parameter declarations preserve 97 actual
pre-declaration frames. Schedule and fetch hints retain their structural codecs;
Core and service admission retain their execution policy. All 11 public tests
preserve 422 frames, and the same 19,321-input source passes 256 model, 33 query/SM
integration and one allocation test without a stack override. The single
combined build reports no warnings after removing an unused framing-trait
import. These counts have their own source seal in the public frame contract.

The next event stage adds 196 owner declarations and 103 fresh captured frames.
Four slice decoders now reconstruct the complete owner without dropping the
message envelope or resetting caller layout context. Nine direct regressions
retain typed budget errors, exact consumption and context restoration. All 21
public tests preserve 525 frames; the same 19,341-input source passes 329 model,
33 query/SM and one allocation test on the default stack. The complete Native
AMX include closure retains 104 functions and 75 tests after moving settlement
tests to their topic module. All 32 Native AMX cases pass. Source-size findings
fall to 235 with 173 unchanged exceptions. Strict Clippy stops at the model
library with 225 diagnostics, leaving the test target's strict lint unqualified.
See the event section of the public frame contract for precise scoped evidence.

Remaining generated/manual declarations and the atomic transition from
directional hashes still require completion before physical model moves. These
stages change no active frame-selection algorithm, codec layout, ABI version,
dependencies or optimization setting. Full workspace/release and strict-lint
qualification remain separate requirements.

## Version diagnostic ownership

The lower `iroha_version` dependency declares its two actual public frame owners:
RawVersioned and UnsupportedVersion. Their 20 captured root/Option/Vec frames
and complete rejection controls are documented in the
[version fixture contract](../crates/iroha_version/tests/fixtures/README.md).
RawVersioned's slice adapter now reconstructs the canonical complete enum;
its former one-byte parser rejected the derived encoder's u32-tagged payload.
RawVersioned carries only Norito bytes under the explicit tag 1; the retired
JSON variant is gone. Typed field/depth/allocation errors,
exact consumption and caller layout context survive reconstruction.

The crate explicitly selects Norito's existing base-codec surface and has no
optional features; the unused derive macros and JSON versioning helpers were
removed. No ABI version, accepted legacy layout or alternate frame identity is
introduced.

The reviewed dependency fingerprint now includes this explicit base-codec
selection and the earlier public model-test target registration. All five
scope counts/limits and all 16 resolved dependency boundaries remain intact.
Current-root CLI feature and Python packaging metadata changes have their own
manifest reconciliation; they do not extend this runtime qualification to the
whole root. Remaining aggregate and service declarations, atomic identity
selection, physical model extraction and full release checks remain open.

## Transaction owner declaration closure

The remaining 25 ordinary transaction frame owners now declare their captured
nominal identities: 15 fee/admission/signed/multisig/sealed/result records, five
executable records and five rejection records. Three private owner-scoped tests
check all captured names and both codec-direction hashes. Every existing item
body and codec/FFI attribute is retained; SignedTransaction, receipt records and
previously declared owners are not duplicated. TransactionSignature retains its
own tuple identity and its existing slice adapter, distinct from its inner typed
signature. No new frame corpus is claimed for these unchanged payload owners.

The exact five-path patch is
`cfffe049b5adf68b50e97a260c5c09495eb6cd1e8e362a12c2f525c87a46505d`.
The local `transaction-owner-closure-preparation/` record binds all 25 complete
items to the successful controlled compiler capture, checks both directions and
preserves 58 transaction/fixture/generator source files. The committed
`transaction/captured_transaction_identity_tests.rs` retains every expected
nominal name and directional hash for subsequent physical moves.

One combined build and its selected runtimes use 19,344 unchanged inputs without
a stack override. All **499 selected tests pass**: 442 model tests, 21 public
frame tests, 35 query/SM/signed-block integration tests and one allocation test.
The model selection includes all transaction tests, three new identity suites,
exact signed Norito RPC/hash fixtures, both base-model fixture tests, all 32
Native AMX regressions and all 16 preceding event-identity suites. The existing
operator-only intent KAT generator remains ignored; its expected constants and
ordinary verification tests are unchanged. Public tests preserve all 525 frame
rows, and base-model tests retain their separate 189-frame corpus.

Formatting and codec checks pass. Source budgets retain exactly 235 findings
and 173 exceptions with unchanged limits. Strict Clippy stops in the model
library with 225 reported errors, before linting the public test target. These
results qualify this captured selection, not other features, the concurrent
root workspace or a release. Remaining model/service owners, atomic frame
identity selection, physical extraction, memory reduction and full native/
consensus/workspace qualification remain outstanding.

## Parameter owner declaration closure

All 17 ordinary parameter frame owners now declare their actual captured
identities. The three private suites in
`parameter/captured_parameter_identity_tests.rs` retain every nominal name and
both independently observed codec hashes. Existing item bodies, field order,
validation, JSON behavior and the 23 parameter unit tests are unchanged. The
source patch is
`f2c09252ef2881e2e701fad035ef048e0c67c6b7cb270bd4f9ee56c77538b3c5`.

The isolated candidate passes 529 selected tests: 468 model, 21 public frame,
39 grouped integration and one allocation test. This includes all 26 parameter
unit tests, four defaults/transaction-parameter integration tests, unchanged
signed RPC fixtures, 525 public frames, 189 base frames and 32 Native AMX
regressions on the default stack. One existing operator-only KAT generator stays
ignored. Eight build/runtime/guard commands bind 19,345 identical source inputs.
Formatting and the codec guard pass. Strict Clippy still fails with the same
225 reported library errors; source-size checking retains the same 235 findings
and 173 exceptions. These are scoped candidate results; remaining model/service
identities, atomic codec selection, physical extraction and release gates remain
open. The local evidence is under `parameter-frame-closure/`.

## SoraFS owner and field boundary closure

All 284 captured concrete SoraFS owners now declare their nominal/frame identities,
retaining 275 serializer/decoder pairs and nine serializer-only capabilities. The
explicit CancelAssetLock projection keeps its observed aggregate instruction
frame. Thirty-two private suites retain the independently captured names and
hashes; no decoder is added to signing or negative-fixture carriers.

Seventeen borrowed Wire records now implement only `SerializePayload`. Twelve
private field helpers lose independent frame markers and accept payload-only
fields. The outer signing-frame adapters, field ordering and canonical signatures
are preserved. Six new tests compare bytes and exact/counting lengths across
both supported layouts, including fields with no typed-frame capability.

Governance's field codecs and tests have their own files without changing logical
type or test-module paths. Production is 4,965 lines, tests 2,413, and the borrowed
field module 65; its obsolete 7,401-line exception is removed. The existing
integration callers use canonical admission/orderbook/repair CLI options and an
explicit isolated PDP output directory. The replication fixture expectation now
contains the actual 32-byte order id. Existing fixture assertions are retained.

The final 78-path source patch is
`ee222ee98beafaf121aeb960407ac0d63a4aa4959e03b8c2c76684348935c030`.
Ten commands bind the same 19,699 inputs without source drift or a stack override.
All 1,271 selected test executions pass: 946 default SoraFS library tests, 101
fixture/CLI integration tests, 187 SoraNet cryptography tests, and 37 minimal-feature
identity/field tests. The default inventory retains all 908 preceding tests plus
38 new tests. Minimal features omit the existing PQC-only hybrid-envelope suite;
that suite passes under default features. No selected test is ignored. Four
SoraNet dependency lints are repaired without changing signing semantics.

Formatting and the codec guard pass. The complete source-size guard still fails
with 239 findings and 172 exceptions. Full strict Clippy stops on eight unchanged
`iroha_crypto` errors; package-only strict Clippy retains six existing SoraFS lint
sites. These remain failures. The source-bound evidence and independent reviews
are under `sorafs-frame-closure/`; only `final-source-review-v3` is the qualified
source patch. Atomic frame-identity selection, remaining manual projections,
physical model extraction, measured memory reductions, and full workspace/native/
consensus release qualification remain open.

## Orderbook signing-frame ownership

The three private order-request, cancellation and settlement-receipt signing
views now declare their captured nominal identities, including the erased
lifetime slot, and their existing owned-record root projections. Generic
containers retain the borrowed view's nominal identity. The nested signature
view loses its unused typed-frame marker and retains only payload serialization.
No borrowed decoder, alternate frame identity or compatibility path is added.
Existing signing, validation and fixture bodies remain unchanged; six test-only
fixture helpers gain sibling visibility so the new suite reuses the actual values.

The immutable
[`orderbook_signing_identity_frames.json`](../crates/sorafs_manifest/tests/fixtures/orderbook_signing_identity_frames.json)
is 51,868 bytes, SHA-256
`14e3c912214c6c92bf42273ba12f353d226a192f86ef9b72731ddaf9bc9338fc`.
Its pre-declaration compiler capture passes on 19,745 unchanged isolated inputs.
It records 15 canonical frames and 30 explicit-layout frames across the three
roots, None/Some and empty/two-element vectors. Records for the retired packed
layouts were dropped when Norito v1 was pinned to `0x00`/`COMPACT_LEN`; the
surviving records are byte-identical to the original capture. Permanent tests
compare declared names against those observations, preserving complete bytes,
advertised flags, exact sizes, owned payload decoding and malformed-frame
rejection. The temporary capture writer and its environment/file APIs are
removed.

The three-path source patch is
`1aa3b0fa781c42152a7dfa3ca726360dd975823e09160a7562b0331d8e387e6c`.
The final default library passes all 948 tests; the orderbook selection without
default features passes 62. Both builds report zero warnings, and both runtime
runs retain the same 19,746-input fingerprint
`10ece0db8ac46f85ac58f8ac972b346ab3ab70620b60c3fa1a6b8ae8e801bf49`.
No selected case is ignored and no stack override is used. The complete isolated
capture source and exact compiler-produced test executables are retained locally.
The final three source/fixture paths match their qualified isolated counterparts;
this does not qualify other concurrent working-tree changes.

Formatting and codec guards pass. The source-size guard still fails with 237
findings and 171 exceptions, with no finding in the changed orderbook paths.
Strict library Clippy fails at the same five baseline sites: three PoP proof APIs
with eight arguments and two signer digest APIs returning unit errors. Test-target
strict lint remains unqualified. No suppression or budget exception is added.

Evidence is under `target/architecture-redesign/orderbook-signing-identity/`.
The remaining manual signing owners are covered by the following checkpoint.
Atomic identity selection, physical model extraction, measured build-memory
reduction and full workspace/native/four-validator release qualification remain open.

## Remaining SoraFS manual signing identities

The twelve remaining production signing views declare their compiler-observed
nominal identities and existing owned-record root projections. Their Option and
Vec containers retain the borrowed view's nominal identity. The three local
encoder sentinels declare their observed names in their original function scopes;
their tests still reject before serialization. `PopSignatureSigningViewV1` now
exposes only payload serialization. No decoder or alternate signing API is added.

The immutable
[`sorafs_signing_identity_frames.json`](../crates/sorafs_manifest/tests/fixtures/sorafs_signing_identity_frames.json)
is 844,772 bytes, SHA-256
`dda0bc3becb7882a6efea86c2db2ca46007024e82e0d949069e84d88fa8521c0`.
Its 26 populated case groups cover 130 canonical frames and 260 explicit-layout
frames. Records for the retired packed layouts were dropped when Norito v1 was
pinned to `0x00`/`COMPACT_LEN`; the surviving records are byte-identical to the
original capture. The separate
[`sentinel fixture`](../crates/sorafs_manifest/tests/fixtures/sorafs_signing_identity_sentinels.jsonl)
preserves the three actual observation lines without reserialization, SHA-256
`0a4b18c8fb394f60905c4e625b899050cbd87598abad6ffec9249ea19cc46fd8`.
Permanent comparisons check identities, complete bytes, payload counts, advertised
layouts, owned decoding and malformed frames. The fifteen PoR rows retain their
existing encode-only projections. PoTR's missing request ID is explicitly
rejected with `MissingRequestId`; valid absent trace/note cases retain the required
request ID. The initial capture's fixture error remains recorded as a failure.

The bounded source inventory now contains eighteen manual typed serializers:
fifteen production signing views, including the three orderbook views, and three
test sentinels. All declare identities; no manual decoder remains in that
inventory. This is not compiler-expanded or workspace-wide declaration closure.
Original signing, validation and fixture bodies remain intact. Governance is
4,994 production lines, within the unchanged 5,000-line limit.

The isolated candidate passes all 950 default-feature and 941 minimal-feature
library tests, with zero failed, ignored or filtered cases and no stack override.
Both runs retain the same 19,755-input fingerprint
`5cba542ee69d9b6448d795d5159affc65290d0b3618968c7df1f23df4ece90cc`.
All seventeen final source/fixture paths match the qualified source snapshot.
Formatting, codec and historical archive guards pass. Strict library/test Clippy
still fails at five existing library API sites and one existing test-style site;
the candidate adds no diagnostic. The full source-size guard retains 237 findings
and 171 exceptions, with no finding in the changed files or policy changes.

Source, executable, failed/successful capture and replay evidence is retained under
`target/architecture-redesign/sorafs-signing-identity/`. These results do not qualify
concurrent working-tree changes or a release. Atomic codec identity selection,
remaining owner/feature closure, physical model extraction, measured memory
reduction and full workspace/native/four-validator qualification remain open.
