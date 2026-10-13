# Kotodama V1 implementation alignment

This is a non-normative guide for contributors aligning the implementation
with the first release. The sole source-language specification is
[`specs/kotodama_grammar.md`](../../../specs/kotodama_grammar.md).
`status.md` records verified work and `roadmap.md` records only outstanding
work.

Kotodama targets deterministic Iroha Virtual Machine bytecode (`.to`). It does
not target RISC-V as a standalone architecture.

## Release surface

The V1 parser accepts one branded source unit:

- one deployable `seiyaku Name { ... }`/`誓約 Name { ... }`, or
- one reusable `module Name { ... }` linked before code generation.

Contracts use private `fn`, authorized mutating `kotoage fn`/`言挙げ fn`,
read-only `view fn`, and the dedicated `hajimari`/`始まり`, `kaizen`/`改善`,
and `trigger` declarations. English `contract`, `entry`, `init`, and `upgrade`
are not source keywords. Parameters, fields, constants, state, and locals use
the type-first `Type name` form. Locals use immutable `let` or mutable `var`;
duplicate names and shadowing are errors.

`authorize` is enforced uniformly for direct, nested, trigger, overlay, and
proved execution. Overlay artifacts retain the requirement and recheck the
live authority before applying any ledger or durable-state effect. Permission
and role mutations conflict through a conservative authorization scheduler
epoch, so a block-start permission snapshot cannot authorize a later revoked
call or permanently reject a call granted earlier in the same block.

There is no compatibility grammar, source edition, implicit entrypoint,
source-order dispatch, raw-call sugar, typeless parameter, wildcard import, or
source `meta` block. ABI v1 is unconditional. Execution capabilities and vector
metadata are derived by the compiler or supplied through trusted build
configuration, never selected by seiyaku source.

## Compiler pipeline

The implementation is currently organized around these boundaries:

1. one lossless scan produces a ranged recovery CST and the significant token
   stream used by the compiler AST parser; transient parser provenance is
   separated into a stable `NodeId`/`SourceRange` side table before the public,
   wrapper-free AST leaves parsing;
2. fail-closed resolution produces a distinct `ResolvedProgram` with stable
   `SymbolId` bindings and exact ranges for declarations, named type uses, and
   calls, rejecting unknown, duplicate, reserved, cyclic, and ambiguous names;
3. type and effect analysis requires resolved input, binds the immutable AST to
   that side table for the duration of analysis, and emits exact primary ranges,
   labels, and conservative fix recipes without embedding source wrappers in
   typed HIR;
4. transitive effects and access are computed through the complete call graph,
   then SSA-style MIR is optimized before register allocation and bytecode
   emission;
5. the assembler relaxes branches and calls and emits the canonical V1
   artifact plus hash-keyed debug sidecars.

The CST is genuinely lossless and ranged. Canonical preorder identities cover
expressions, statements, and types, while resolution records exact declaration,
name, type-use, and call identities. Semantic diagnostics resolve those facts
to their precise source file and byte range, including multi-source module
analysis. Source identity is deliberately orthogonal metadata: typed HIR keeps
only declaration-level source sidecars needed by reports, and optimized MIR and
executable code contain no source marker instructions. Tests prove that adding
or removing source metadata leaves optimized IR and final artifact bytes
identical and that an inconsistent origin tape fails with a diagnostic rather
than panicking.

`CompilerSession` explicitly owns deterministic compiler options and replaces
the old thread-local registries; reusable parsed-module caching currently lives
in the module build graph rather than the session itself. Public driver APIs
return either a `CompileOutput` or a `DiagnosticBundle`; diagnostics have stable
codes, phases, severities, optional primary spans, labels, notes, help, and
optional fixes.
Human, JSON, and SARIF renderings carry the same semantic fields.

Hard parser budgets are part of the release contract: 1 MiB of UTF-8 source,
250,000 tokens including EOF, and 256 levels of delimiter/parse nesting.
Recursive value types, recursive calls, `while`, and unproved loop bounds fail
closed.

Every artifact carries a positive `max_cycles` value in its hash-covered
execution header. The chain's `ivm_max_cycles_upper_bound` is a mandatory
non-zero field (default `1_000_000`) of the committed
`pipeline_validity_policy_v1` parameter, used by admission and every execution
path. An authorized `SetParameter` changes it from the next block and a zero
value is rejected; neither a node configuration file nor an environment
variable can set it.

## Security boundaries

The canonical artifact hash covers every deployable byte: all execution-header
fields, the embedded CNTR interface, typed literals, and executable code.
Source maps and debug data are sidecars keyed by that hash.

The compiler uses one exhaustive builtin registry for signature, effect,
syscall, scheduler access, gas class, and allowed execution modes. Source code
uses namespaces such as `context`, `ledger`, `state`, and `crypto`; allocation,
raw pointers, direct syscall variants, and opaque instruction submission are
not source capabilities.

CNTR is an interface, not a trust root. Admission validates control-flow
targets and ABI-v1 operations, then derives transitive effects and access from
bytecode. Dynamic or incomplete access forces conservative serialization.
Compiler fingerprints and access summaries remain informational until they are
independently verified.

The scheduler preserves an exact `StateMap` child key only when reachable
bytecode directly flows one authenticated, canonical `Name` literal into the
state syscall on every path. Distinct proven children can execute independently;
the same canonical child conflicts. Computed keys, helper-hidden state calls,
ambiguous control-flow joins, invalid hints, and unverifiable artifacts retain
the fail-closed `state:*` fence. Static scans use `state:Map[*]`. A CNTR key that
does not match the bytecode-derived operation shape is ignored.

Numeric host operations use the consensus-defined staged meter: each bounded
validation, byte, logical-limb, and output phase is debited immediately before
that phase performs work, with no up-front quote or refund. Other host
operations that retain prepare/quote metering debit the quote before execute.
Query, allocation, nested invocation, and state effects must not happen before
their applicable debit succeeds.

## Language safety

Arithmetic is checked by default; explicit `math::wrapping_*` operations are
the only modular arithmetic. Comparisons preserve signed ordering across the
complete 512-bit `int` domain. `&&` and `||` short-circuit and therefore do not
execute an unneeded right-hand side.

Durable scalar state is initialized in `hajimari`. `StateMap.get` and the mutating
`StateMap.remove` return `Option<V>`, iteration is in canonical Norito key
byte order, and collection iteration is capped at 64 items. Top-level structs,
tuples, `Option`, and `Result` values use one schema-bound canonical Norito
record and therefore one host read or write per state/StateMap entry. Nested
`StateMap` values and schema mismatches are rejected.

Public failure behavior uses explicitly numbered `error enum` variants and
`require(condition, Error::Variant)`. Stable error codes are exported in the
seiyaku interface; free-form strings are not a public error protocol.

Private input exists only as explicitly declared `Secret<int>`,
`Secret<decimal>`, or `Secret<quantity>` for a ZK-enabled build. The bounded
canonical Norito record carries the exact nominal kind and complete numeric
frame. Secret values can flow only into the full-width `crypto::valcom`
commitment boundary; both operands must be secret. They cannot affect public
returns, logs, error selection, control flow, state, ledger writes, host
queries, or seiyaku calls. Scalar Poseidon proof gadgets reject private
operands; the former truncated commitment, public-key, curve, and pairing
opcode slots are invalid in ABI V1 and are not source-level capabilities.

`Secret<T>` and `GET_PRIVATE_INPUT` currently execute only in local compiler
tests and explicitly provisioned prover/test hosts. Ordinary production
consensus dispatch rejects any seiyaku selector whose complete reachable
bytecode reads private input, including helper-hidden reads. The gate remains
until the proof-carrying invocation statement binds the seiyaku address and code
hash, seiyaku selector, public arguments, authority and chain, state root and
exact read/write sets, outputs and events, gas schedule and ceiling, and circuit
and verifier-key versions. Raw witness bytes must never enter signed
transactions, `IvmProved` payloads, overlays, public argument records, or
deterministic validator replay.

### Secret execution proof obligation

`Secret<T>` is a compiler and local-prover preparation surface in ABI V1, not
a production consensus execution feature. The source types and local host are
kept so the eventual proof path has one typed ABI, but production availability
must not be inferred from successful compilation.

The current proof machinery cannot soundly remove the gate above:

| Proof obligation | Required constrained relation | Current ABI V1 evidence | Release disposition |
|---|---|---|---|
| Invocation identity | Chain, authority, seiyaku address and complete code hash, selector, canonical public argument record, transaction gas ceiling, circuit id/version, and verifier-key commitment are one public statement. | `IvmExecutionStatementV1` and normalized signed intent define the canonical public claim, but its finalized anchor is not yet a Core-owned verified handle and no complete proof relation binds it. | Model complete; proof admission remains closed. |
| Initial state and reads | The authenticated pre-state root and every host query result are proven, with exact dynamic read/write keys and authorization snapshots. | Deterministic replay authenticates these values only when it can execute the call. They are not circuit constraints. | Missing for witness-bearing calls; reject. |
| IVM transition semantics | Every admitted opcode, register/tag transition, memory access, branch/call/return, syscall, and halt condition is constrained for every paid step. | Binding-only Halo2 and native-STARK IVM circuits and their production registrations have been retired. Ordinary Core admission rejects every `IvmProved` payload. | Missing; require the complete native STARK execution relation. |
| Typed private witness | Each private index resolves to one bounded canonical `int`, `decimal`, or `quantity` frame of the requested nominal kind without revealing its bytes. | `DefaultHost` validates this relation for explicitly provisioned local tests/provers. Consensus `CoreHost` has no witness transport and rejects `GET_PRIVATE_INPUT`. | Host validation is not a proof; reject in consensus. |
| `crypto::valcom` | The circuit constrains the complete canonical envelope projection, domain separation, scalar reduction, independent BLS12-381 generators, full Pedersen point, and canonical public `int` encoding. | The native local host computes this relation; no admitted IVM proof relation constrains it. | Missing; a witness/output equality alone would be unsound. |
| Noninterference | Private data influences only approved commitment/proof outputs, never control flow, public errors, logs, state keys/values, calls, queries, or ledger effects. | The typed compiler pass and VM taint checks enforce local execution policy, but those checks are not part of the proof statement. | Keep as defense in depth; still require proof. |
| Outputs and effects | Public return values, ordered host effects, durable-state writes, events, and exact access metadata are derived from the proven terminal state. | Ordinary public execution recomputes effects; `IvmProved` admission is closed until a complete execution proof can establish them from private execution. | Missing for witness-bearing calls; reject. |
| Gas and termination | The trace proves a valid halt within the artifact ceiling under the hash-bound gas schedule, with exact charged host work. | Ordinary public execution charges exact gas; no IVM proof currently establishes a private trace or its gas. | Missing for witness-bearing calls; reject. |

The final V1 private path requires one complete native STARK relation over the
whole IVM execution and typed `crypto::valcom` calculation, backed by the
verified complete State root. The public statement alone grants no execution
authority. Merely adding private bytes to `IvmProved`, trusting compiler
metadata, or comparing supplied commitments is unsound.

## Runtime and tooling

Public calls carry one canonical Norito argument record, with an inclusive
1 MiB limit. Prepared calls first validate the compiler-owned flat schema and
derive its conservative maximum aggregate and pointer-allocation bound. The
bound combines that maximum with the signed wire lengths and must be affordable
before the untrusted canonical record is decoded. The low-level raw decode
syscall cannot authenticate either VM envelope while quoting, so its quote uses
only bounded record/schema envelope lengths and reserves the full HEAP before
schema and record authentication.
After affordability is established, the host validates and decodes the record
exactly once. For prepared calls, the complete signed bytes stay host-owned;
the wrapper receives only a domain-separated binding and then reads the typed
ABI word table. Before allocating, the host preflights the complete aligned TLV
sequence together with
raw aggregate storage. Pointer TLVs and the table prefer INPUT and spill into
owned HEAP, while raw `List` and sum storage is always owned HEAP. External
JSON-to-argument-record conversion remains confined to Torii/CLI/SDK
construction boundaries. Inside a seiyaku, native `json { ... }`
and `json [ ... ]` expressions lower to the schema-bound `JSON_BUILD` syscall;
the host canonicalizes object keys, recursively converts supported typed
values, and exposes active-only `Option<T>` getters including `decimal` and
`quantity`.

Validated bytecode is cached as an immutable `PreparedContract` containing the
interface, metadata, predecode, and CFG. Warm execution reuses prepared state
and resets only dirty memory instead of cloning the full VM memory and Merkle
tree.

`koto check|build|test|fmt|doc|explain|lsp` is the single command surface. The
Rust compiler library is canonical for `koto`, Musubi, and the Node native bridge. Browsers use a compiler service; there is
no independent JavaScript or offline browser compiler.

`crates/kotodama_lang/grammar/v1.lex` is the machine-readable lexical source for
the scanner, LSP/TextMate patterns, and the keyword/operator tables rendered in
the normative grammar. The build generator emits those tables and the document
consistency tests compare the checked-in Markdown and editor grammar against
the generated values. CI also compiles every current `kotodama` documentation
fence so examples cannot silently define a second dialect.

The formatter is a canonical lossless-token consumer: it preserves comments
and literal spelling, emits deterministic four-space block layout, is
idempotent, and refuses invalid or post-format sources larger than 1 MiB.
The reusable module driver caps one graph at 512 source units/16 MiB and keeps
only a 64-entry/4 MiB exact-source LRU of parsed modules, so long-lived compiler
services cannot accumulate attacker-controlled ASTs without bound.

## Performance gate

`crates/ivm/benches/bench_kotodama.rs` measures the canonical compiler pipeline
at every opaque phase boundary: lossless parsing, resolved-HIR construction,
interface/effect signature summarization, typed/effect HIR, transport-IR
lowering, SSA construction, SSA optimization, de-SSA, final code generation,
and end-to-end compilation. The historical `kotodama_phase_semantic` identity
retains its exact `resolved.type_effect()` workload for real base comparison;
the distinct signature-only work uses the dedicated identity
`kotodama_phase_interface_summary`. Later phases use Criterion batched setup,
so cloning or reconstructing their trusted input is not charged to the phase
under test. The same suite measures cold execution and warm prepared execution
separately. Runtime samples explicitly select the embedded CNTR entrypoint, use
the canonical Norito argument record, and validate the result before Criterion
starts sampling. The warm sample prepares and loads its immutable contract
once, builds its reset template once, and measures only dirty-state reset plus
invocation.

The canonical golden pipeline also applies deterministic artifact gates before
publishing anything. Every compiler-generated instruction region must contain
strictly less than 1% unresolved relocation NOPs. It renders the complete owner
set into two independent temporary roots, validates every artifact and runtime
manifest in both, and requires identical sorted paths, modes, bytes, and owner
manifests before either `--check` or `--write` may continue. Performance
acceptance compares the untouched current release baseline and the final
candidate on the same quiet runner; it does not retain a pre-reset revision or
predicted size table as release evidence. These checks run for both `--check`
and `--write`:

```console
make kotodama-goldens-check
```

`--write` requires an absent absolute output root outside the source workspace;
there is no in-place write mode. The pipeline does not reserve that final name
until both renders and their tests pass. Publication is bound to held
parent/root directory descriptors, includes the exact directory and file modes
in the owner manifest, and creates that manifest last as the completion seal. A
root without the seal is failed create-only residue and is never accepted or
overwritten. Generate two independent sealed roots, require identical exact
paths, types, modes, owner manifests, and bytes, then refresh tracked artifacts
only as a reviewed identity-relative patch and rerun `--check`.

An authenticated second build in the same pipeline must report every source as
`fresh` and preserve every generated file's modification time, proving that a
no-op graph performs zero compilation and zero rewrites.

Capture the untouched current baseline and final candidate on the same quiet,
controlled runner. Use one shared `CARGO_TARGET_DIR`, but separate baseline and
candidate checkouts. Each checkout runs its own revision-native benchmark
source; the candidate harness is never copied into the baseline checkout.

The source-evidenced comparison revision is the reset anchor
`fc09b635df385d0488067f09baaa92a8d16fa124`. Its native sources contain all 46
required workload identities. Its original `Cargo.lock` is present and pinned
by SHA-256
`0ddb3f3938cf32035371317100674cd1601c3cb41232237f7a7d28b3aeab6222`.

```console
# In the base checkout:
cargo bench --locked -p ivm --bench bench_kotodama -- --save-baseline base
cargo bench --locked -p iroha_core --bench kotodama_runtime_cache -- --save-baseline base
cargo bench --locked -p iroha_core --bench queries -- \
  typed_core_query_ --save-baseline base

# Remove only Criterion `new` directories so candidate evidence cannot be reused.
find "$CARGO_TARGET_DIR/criterion" -type d -name new -prune -exec rm -rf {} +

# In the candidate checkout:
cargo bench --locked -p ivm --bench bench_kotodama -- --save-baseline candidate
cargo bench --locked -p iroha_core --bench kotodama_runtime_cache -- --save-baseline candidate
cargo bench --locked -p iroha_core --bench queries -- \
  typed_core_query_ --save-baseline candidate
python3 scripts/check_kotodama_perf.py \
  --criterion-dir "$CARGO_TARGET_DIR/criterion" \
  --baseline-root /path/to/base/checkout \
  --threshold 0.05
```

The checker fails closed on missing/malformed samples or benchmark coverage
changes. It extracts and whitespace-normalizes the actual Criterion timed
closure for all 46 identities, binds each closure to
the audited baseline SHA-256 inventory, and requires exact base/candidate
body equality. Shared rounded-Quantity and typed-query loops also bind each
name to its mode or family declaration. The typed-query contract separately
requires exact base/candidate equality for the full-entity `QueryResponse`
generator and its encoded-byte measurement, so inflating the raw comparator
cannot make the projection-size assertion pass. Its threshold cannot be
loosened above 5%; a stable release runner may set a tighter threshold with
`--threshold`.
Before any comparison it also requires `--baseline-root` to resolve to the
exact selected Git commit, rejects tracked-source drift, and hashes a regular,
non-symlink `Cargo.lock` against the independently authenticated policy digest.
There is no portable `--baseline` or candidate `--write-baseline` path: timing
samples are runner-local, and a candidate sample is never baseline evidence.

The `.github/workflows/kotodama_perf.yml` definition checks out the pinned
baseline and candidate and measures both on one runner with Criterion's named
baseline. Timing samples are deliberately runner-local; they are not portable
across CPU models or loaded hosts. The policy requires every workload in both
source sets and rejects missing, duplicated, renamed, or source-drifted
identities. It never manufactures a candidate self-baseline.

Parse, semantic, lowering, code-generation, List, Quantity, Decimal,
runtime-phase, query, and runtime identities all receive the five-percent
regression ceiling. Before timing
each typed-query family, the benchmark asserts one host query, one decode, and a
projection payload smaller than the raw entity `QueryResponse`; the timed
iterations reset and black-box those counters. The List comprehension runtime
has a separate zero-slowdown gate against its manual-loop baseline; the general
five-percent allowance cannot loosen that parity requirement. Missing required
base samples, candidate samples, coverage, or authenticated baseline
provenance fail closed.
