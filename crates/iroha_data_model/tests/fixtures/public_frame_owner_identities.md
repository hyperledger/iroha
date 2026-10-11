# Public manual model frame fixtures

The identifier JSON retains successful captures made after repairing fallible IdBox
delegation and before declaring its public owner's Norito identity. The block-signature
JSON was regenerated for the current first-release header, including its dedicated
threshold-beacon pulse commitment, by the canonical checked capture test. These captures
describe valid current frames; they do not preserve former malformed-input behavior.

| Fixture | Coverage | SHA-256 |
| --- | --- | --- |
| `id_box_identity_frames.json` | All 13 IdBox variants, None, Some(permission), empty Vec and all-variant Vec: 17 frames | `440a4413817a41e1e67d2c4a6623738d73e884ac4c993c9c2a334a2cc1533146` |
| `block_signature_identity_frames.json` | Two genuinely signed headers and root/Option/Vec containers: seven frames | `8e27aad16cffff5f7e0b8ba9c7b4dbf1fd397709ab2a5e3994c61ca7052cd7b8` |

The compiler-observed nominal owners are
`iroha_data_model::id::model::IdBox` and
`iroha_data_model::block::header::model::BlockSignature`.
Their observed directional frame hashes are respectively
`f9a45352fe84d322868b31b3df9717a2` and
`fdaf1f2144c1776ab93df942f7c2429e`.
Container rows retain their own observed names and hashes. The permanent tests
compare declared nominal names with the captured `actual_type_name` field;
physical source relocation must preserve this wire identity.

Every row checks complete frame/bare bytes, header schema/flags/length/alignment,
canonical and archived reconstruction, JSON, wrong-schema/truncated/trailing
rejection and successful decoding after those negative controls. The IdBox
suite fixes the 13 u32 tags in protocol order. The signature suite verifies
both actual signatures against their headers and compares payload bytes with
the unchanged `(index, signature bytes)` tuple. All signing seeds are explicit
public fixtures. Temporary capture writers are removed from production tests.

The separate IdBox rejection suite calls `try_deserialize` directly after
frame authentication. Unknown tags and each 0–3-byte tag truncation return typed
errors across every advertised layout, with valid controls before and after.
The payload-only tuple adapters keep their existing conversions and allocation
checks; none gains an independent frame identity.

The controlled capture uses pinned Rust 1.93.1, default model features plus
HTTP, with dev-dependency unification also selecting `transparent_api`.
`RUST_MIN_STACK` is unset. The ignored local evidence directory
`target/architecture-redesign/owned-storage-identity/model-identity-closure/wire-adapter-ownership/`
retains the capture sources, 19,303 input hashes, both successful runtime logs
and producer artifact SHA-256
`73a26f181a014d0c996f6acfdcb987f9f393cdb846683275284b7e4d6c6ab929`.
`capture-model-test-build`, `capture-block-signature` and `capture-id-box`
identify the producer and the two executions; the JSON files above are the
immutable repository fixtures. Active identity cutover, other feature
selections, physical model extraction and complete release qualification remain
separate requirements.

Before the following declaration stage, the owner candidate passed the complete
default/HTTP model library:
3,655 tests, zero failures and six existing ignored cases, on 19,306 unchanged
inputs with no stack override. The 89-case focused run includes all 32 Native
AMX regressions; the isolated signature allocation target passes two tests and
all three payload-adapter compile-fail examples pass. The nine source/fixture
paths are integrated from the exact reviewed patch
`bfd9bcfcbf193e3a5e291b823f36a0d001bd4a2f472fbea8705fb803b3bd0f18`.
These results qualify this model selection; they do not qualify the full live
workspace or its separate Core/Torii changes.

## Manual scalar, protocol and proof owners

The `manual_frame_identity` integration target now owns every assertion above
and the following three fixture families. Its seven tests share one binary
contract checker, adding JSON checks only for owners that expose JSON. The old
private unit-test modules and temporary capture writers are removed. Every
recorded `actual_type_name` is compared with the owner's declared nominal name;
root/Option/Vec frames retain their individually observed identities.

| Fixture | Coverage | SHA-256 |
| --- | --- | --- |
| `manual_scalar_identity_frames.json` | Five owners, 35 frames: X.509 key usage, contract argument, alias, address and manifest CID | `7326473b538f2ef1248d6c1c847fadccdc01a139bd199cec291479b8379c6ece` |
| `manual_protocol_identity_frames.json` | Seven owners, 47 frames: privacy magic/digest/catalog, confidential memo, device key/signature and repo instruction | `d5059a7ff54f00d3969fee4e62d1d05366b89ba4739d46330420b3d2e01dfb09` |
| `manual_proof_identity_frames.json` | Three owners, 29 frames: proof attachment/list and Kaigi authorization scalar | `dbaa4907c8c3076bf5fb3e436f6e1a8129de115734c31402c89b3a8f603e01d7` |

`PrivacyX509KeyUsageRequirementV1` alone projects its root frame to `bool`.
Its Option and Vec frames retain the wrapper's nominal identity and reject
boolean-container frames in both directions. The other fourteen owners retain
their own observed root identities. The old KAGEMUSHA IPM1 payload-kind owner and
its nine frames were deleted with that wire family. The full names and directional hashes are
stored in these immutable captures; no source-path lookup or alternate accepted
identity is introduced.

Controls authenticate complete frame metadata before calling the owner's
fallible decoder directly. They cover enum tags, checked aliases/CIDs, oversized
arguments, Goldilocks/Pasta field bounds, canonical P-256 points and low-S
signatures, memo shape and proof structure. Proof-list controls accept the
exact 16-element and 8-MiB limits and reject complete inputs one over each limit;
failed appends preserve exact prior bytes. Proof attachment rows cover every
optional-tail length, including None placeholders preceding a later Some.
Opaque proof and memo fixtures establish wire contracts, not engine or AEAD
verification.

The retained `manual-frame-closure/` evidence directory beside the earlier
capture contains exact capture source images and both producer binaries. The
scalar/protocol producer SHA-256 is
`3fbf6fb7b413a8247a1a94e3a81ea1bd7e9218314a48873e1026badd520b9586`;
the subsequent proof producer is
`842f2241ddcf23364a6ba73f37d6e21ab9c30a4cad5516832b8bda79e73ff395`.
The final rebuilt target passes all seven tests, with zero failures or ignored
cases, preserving all 144 complete captured frames on 19,313 unchanged inputs.
The run unsets `RUST_MIN_STACK`. The 29 source/fixture changes are bound to patch
`5587e6d335af84744c82cd1b1f5f3d01480084e458835c2cd89ef4798d90e94f`.

```sh
cargo test -p iroha_data_model --test manual_frame_identity --features http --locked
```

This is focused qualification after declaration and test relocation. The prior
3,655-test result above belongs to its earlier source seal. At that checkpoint,
query and generated declarations, active codec cutover, physical model extraction
and complete workspace/release qualification remained open. The preceding
source inventory recorded 236 paths and 173 exceptions, with KAGEMUSHA V1
growing from 6,254 to 6,258 lines in that capture. These historical measurements
impose no current code-size requirement. Dependency limits are unchanged.

## Query and time owners

Fifteen public owners now declare their observed identities. The same integration
target adds two permanent tests to the seven above, preserving **325 frames**.
The shared checker verifies complete public semantics for query owners without
requiring Clone, Debug, equality or a new JSON API. Every preceding assertion
and fixture remains; temporary capture writers are removed.

| Fixture | Coverage | SHA-256 |
| --- | --- | --- |
| `query_manual_identity_frames.json` | Seven owners, 59 root/Option/Vec frames: erased queries, typed signatures, authorized requests, signed envelopes, batch tuples, responses and time intervals | `c09e2059d0bd0f4a9eae6be22d87d764ed3f2e11cc7f8ab68857319452d6989c` |
| `query_derived_identity_frames.json` | Eight connected owners, 122 frames: requests, parameters, all 31 item-kind tags, output, batches, singular query/output and cursors | `a8f951911789c2c36bebb96e9aaf05c1a6ecd171bb503c8849acb50390f5b1b9` |

The query parameter frames were regenerated on 2026-09-27 from the current first-release
model using the ignored `capture_current_query_and_time_identity_frames` and
`capture_current_derived_query_identity_frames` tests. They include the nonempty-work payload
retry parameter and current execution-source budgets; no retired parameter wire layout is
accepted as a compatibility input.

QuerySignature retains its own nominal identity and projects its root to
`SignatureOf<QueryRequestWithAuthority>`; wrapper containers remain distinct.
QueryBox declares only its existing aggregate-output specialization. Stable
registry IDs remain separate from live Rust dispatch keys, which are checked
against concrete downcast types. The historical `concrete_type_name_key` fixture
field compares that owner's declared nominal name so a physical move preserves
the test's wire contract.

Controls preserve the exact shipping V1 signed envelope and signatures binding
all six request-context fields. Structurally valid context mutations fail
signature verification; ingress still owns network, freshness and replay checks.
Malformed lifetime and cursor fixtures first prove complete valid-payload
equality. Batch count/type failures leave exact prior bytes unchanged. Time
checks cover zero and maximal millisecond fields using the public owner.
Private query candidates now reconstruct payloads only; the redundant private
TimeIntervalWire and diagnostic fallback are removed.

The local `query-time-frame-closure/` evidence retains both actual capture
sources, source seals and producer binaries. Their SHA-256 values are
`fd224bb9248a7d1d9f8cd3a45ef706e5b3c3806afb53f092abfc90a4f294f3bc`
and `c4e73559134736e2c72817ec1029e81c1a5fb41ba580bf4264696178956faa64`.
The nine declared public tests pass on 19,317 unchanged inputs with no stack
override. The same source passes 256 affected model tests, 28 public query
integration tests and one allocation test,
with zero failures or ignored cases across all four runs.
The nine source/fixture paths are integrated from patch
`651a055911da35e46c6339d3356c6b9db6e3a544972417a12b5ef3221c9f122b`.
Codec checks pass; all 236 size findings and 173 exceptions remain unchanged.
The grouped integration build at this checkpoint reported an unused import in
`sm_norito_roundtrip.rs`; this is not strict-lint qualification. Remaining owner
coverage, active identity cutover, physical model moves and full release checks
remain open. No dependency, optimization or ABI version changes here.

## Remaining time events and query parameters

The next nine declarations close TimeEvent, TimeEventFilter, ExecutionTime,
Schedule, Pagination, SortOrder, Sorting, FetchSize and QueryParams. TimeInterval
and ForwardCursor retain their preceding declarations and fixtures. The public
target now has **11 tests and 422 immutable frames**; both new suites use the
same unchanged contract checker. Temporary writers and their duplicated checker
are removed, with all prior assertions retained.

| Fixture | Coverage | SHA-256 |
| --- | --- | --- |
| `time_event_identity_frames.json` | Four owners, 46 frames: every execution variant, period shape and zero/ordinary/maximum event interval | `c26c4544eb36f4860c1cdf5e80d8a7f6ca146e86ce043f26195b876a7b58ebad` |
| `query_parameter_identity_frames.json` | Five owners, 51 frames: pagination, both order tags, optional sorting fields, fetch hints and complete parameters | `f68214e76c45fa4a21050399f307ba816ef796eb2f25c0806293a900ada3f4f2` |

All nine root identities are nominal; TimeEventFilter keeps its own frame even
though it shares ExecutionTime's JSON representation. Every family includes
populated roots and Some values, None, empty vectors and populated vectors.
Controls check exact bounded JSON output, complete reconstructed values, enum
tags and fallible rejection after authenticating full frame metadata. Malformed
field composers must first reproduce a complete valid public payload.

Schedule remains a structural wire record: None, Some(0) and positive periods
are distinct. Core registration owns zero/sub-cadence rejection. Pagination and
fetch options reject zero through NonZeroU64; values above an executing service's
configured fetch limit remain representable and are admitted or rejected there.
The fixtures preserve this ownership boundary without adding a second policy.

The retained `time-event-frame-closure/` evidence binds both actual captures to
their producer binary and 19,319 unchanged pre-declaration inputs. The final
combined build and four runtime selections share 19,321 unchanged inputs and no
stack override. All **301 focused tests pass**: 11 public frame tests, 256 model
tests (including 21 time tests), 28 query plus
five SM integration tests, and one allocation test. The unused SM framing-trait
import is removed; the combined build reports no warnings.

The eight source/fixture paths are integrated from patch
`53638d8b1b2575240d98add873069a087a6ff6037abd3c80f41f6f40bd809bc5`.
Codec and formatting guards passed. The preceding source inventory recorded
236 findings and 173 exceptions under the now-retired size policy. Complete
declaration coverage, atomic
identity cutover, physical model extraction and workspace/release qualification
remain open; no dependency, optimization or ABI change is introduced here.

## Event owners and stream reconstruction

The event stage adds 196 explicit owner declarations: 192 checked against the
retained compiler capture and four captured before their declarations. Sixteen
owner-scoped library suites check the former group. The four fresh owners are
DataEventFilter, GameSessionEventV1, EventMessage and EventSubscriptionRequest.
Their immutable fixture contains 103 frames, with actual nominal names and both
codec-direction hashes, and uses the existing shared contract checker.

| Fixture | Coverage | SHA-256 |
| --- | --- | --- |
| `fresh_event_identity_frames.json` | 55 data filters, five governance filters, 11 game sessions, nine event messages and 23 subscriptions | `c32171f5c8e0cf816f51912e75ff6de296c23b29d1f0b183c2c23b142719164b` |

The default Configuration and Bridge filter masks each carry their single
event bit in their root/Some frames and in the combined Vec. The ignored
`capture_current_fresh_event_identity_frames` test reproduces this capture.

EventMessage's slice decoder previously skipped its own field envelope and
rejected its encoder's output. EventBox, EventFilterBox and subscriptions reset
the caller's advertised layout through DecodeAll. All four now reconstruct the
complete owner's canonical payload directly. Nine regression tests check exact
consumption, both advertised length layouts, typed field/depth limits,
truncated/trailing input and context restoration. Reconstruction invokes the
payload trait, not the slice adapter, so it introduces no recursive delegation.
Alternate archive layouts remain rejected by the canonical V1 boundary.

Fresh controls cover all data-filter tags, game-session fields and bounds,
subscription proof-option combinations, mandatory binary tails, malformed JSON
and successful recovery. A malformed-field composer must first reproduce a
complete valid payload. No public equality/debug traits or compatibility paths
are added. The governance-disabled branch retains 98 applicable frames but has
not been runtime-qualified in this stage.

The final build, four runtime selections and codec guard share 19,341 unchanged
inputs with no stack override. All **384 focused tests pass**, with no failures
or ignored cases: 21 public tests preserving **525 immutable frames**, 329 model
tests including 16 new identity suites, 33 query/SM
integration tests and one allocation test. Formatting and codec checks pass.
The preceding source inventory removed one finding, recording 235 findings
and 173 unchanged exceptions at that checkpoint. Its 5,000/3,000-line
requirements are now retired.

The 40-path source patch is
`f4a77b15755c25f43644b474852930a515ff4d322828053ad408981fbcc4ccd4`.
The local `event-model-frame-closure/` record retains the four genuine pre-fix
failures, capture executable/source, exact review and all terminal results.
Strict Clippy fails at the model library with 225 diagnostics; this is not a
passing library or public-test lint qualification. Atomic identity cutover,
physical model extraction and complete workspace/release checks remain open.
No dependency, optimization, active identity-selection or ABI version changes
are introduced here.
