# Source-bound setup and fixed-Poseidon algebra controls

This standard-library Python package exercises an exact-source Pasta setup
simulation in an **ideal raw-hash model**, followed by fourteen small complete PIPA
proofs checked with the unchanged reference verifier and fixed RP57 transcript.
It is verification material, not a production prover or parameter loader.

From the repository root, choose a new output directory:

```sh
python3.12 -B -S -m formal.kagemusha_setup.check --output /absolute/new/output
```

The owner checks exact source pins before importing the subjects, runs the
maintained prime/group certificates, then one hundred controls. It refuses optimized
Python, bytecode-writing invocations (use `-B`) and existing output directories. It retains setup bytes, raw-model
tables, synthetic private logs, proofs and failures. Ordinary controls do not import or read a development output directory. Their
dependencies are relative to this repository; no Cargo build, large parameter
artifact or native prover execution is involved. The separately gated large
constructor below reads only its caller-selected originals directory.

The controls retain the five exact finite-map/law/cap cases, five single-map/KAT cases, eight raw-query cases, six
fresh-target/parameter cases and ten complete-proof cases, plus two source
custody cases, thirteen bounded-producer parity/resource/custody cases and
eleven sequential request/entropy/replay cases, nine request-shape cases and
seventeen generic public-table/rebinding cases and fourteen closed A1
constructor/custody cases. One complete-proof method checks exact retained diagnostic
proof/parameter hashes after the arithmetic-helper relocation. The only retired test checks the replaced fixed-target sampler;
its failure, zero-target and cap guarantees are covered by the fresh-target
controls. There is one maintained pair sampler, which draws a fresh private
target on every ordinary inverse miss. No compatibility sampler is retained.

The source inventory includes the exact-source VK-to-PK reconstruction module,
its exports and source-fingerprint implementation. The reconstruction reuses an
already admitted verifier after checking the same descriptor, key and synthesis
source; it does not choose a new commitment blind or parameter family. These
source checks do not execute reconstruction or qualify a native wallet. The
commitment counter is test-only instrumentation; proof and transcript semantics
remain covered by the existing exact-byte diagnostic controls.

## Exact setup boundary

`preimage.py` uses the native SWU/isogeny constants, canonical parity, exceptional
zero branch and complete ordered inverse of size at most nine. It reuses
`formal.kagemusha_pasta.auxiliary` for constant parsing and finite auxiliary
group arithmetic. The maintained prime/group certificates bind the bases and
isogenies; the geometric regularity argument is separate and is not needed for
this fresh-target sampler.

The sole raw oracle reserves native XMD's three entries atomically on the first
designated raw m0 query, including early queries. It never overwrites an input.
Caps, occupied entries and native identity points are retained failures, never
repaired or resampled. The sampler has J4096/h256 budgets; ordinary test cases
may deliberately select smaller caps to exercise failures.

Each k6 family uses 64 g messages plus shared W/U. Across both curves there are
132 contexts and one unrelated prior raw query. Prefixes, W/U and repeated
queries reuse exact originals. Lagrange logs use one n-inverse normalization;
the native encoding is 64n+68 bytes. Private logs use the source base
isogeny(SWU(1)), not an independently chosen unrelated base.

For every ordered pair of field inputs, one target scalar and inverse slot
return it, so successful pairs are exactly uniform without a regularity loss.
In the stated ideal-coin/raw-oracle experiment, the reviewed finite-pair, lift
and reduction terms are less than 12292·2^-256 per distinct setup context.
Both complete k≤16 families have 131076 contexts, giving local aggregate less
than 2^-224, plus the raw-query collision bound
`2*Q_s*(Q+3*Q_s)/2^512`. This is a sampler bound, not a protocol security-level
claim. The executable controls only construct k≤6 families; larger producer requests require an explicit resource opt-in.

## Verifier authority and proof scope

The family is constructed **before** writing its private authority, descriptor
and key. For every maintained small control, all seven Python reference verifier modules
are copied verbatim into a fresh namespace. Only that namespace's params_ipa authority data differs;
RP57 constants and all verifier checks, including the actual folded-generator
decision, remain unchanged. Repository KATS and parameter authorities are never
modified. Current-authority refusal is an explicit control.

Two families are reused across ordinary and contradictory relation examples.
The simulator samples points in native order, squeezes fixed RP57, handles the
exact coefficient-rank collapse branch and solves the final IPA blind from
private known logs. No transcript answer is programmed. Tests check every
derived commitment log, complete proof verification, f/c/G/instance mutations
and the declared contradictory relation. Acceptance of those contradictory
toy cases is confined to the simulator's newly constructed test authority.

The four relation-comparison proofs explicitly supply the same diagnostic
PRNG seed within each curve for the two relation examples. This is a common-coin, counterfactual algebra diagnostic. The other four proofs exercise sequential requests with an explicit
shared stream and an input chosen from the preceding public proof. Neither
experiment establishes an adaptive privacy theorem. Setup
coins use a separate deterministic seed. Python `random.Random` is test
reproducibility machinery; neither it nor the retained synthetic private logs
are part of a production wallet interface. The unchanged proof sampler has its
own 128-draw cap; the setup's h256 bound does not silently cover other draws.

These tests do not recover logs of current release parameters, instantiate an
ideal oracle with concrete BLAKE2b, prove the full adaptive outer-proof
distribution, satisfy all private fold/wallet relations, or close C12. See the
implementation-coupled [soundness memo](../../specs/kagemusha_recursion_soundness_v1.md)
for the separate remaining obligations. Test reports retain
`current_setup_qualified=false` and `C12_closed=false` even when all cases pass.


## Bounded parameter producer

`bounded.py` reuses the same sampler, raw oracle, and source-map/log check. One
owner shares contexts across curves and domain sizes, preserves early raw
queries and exact replay, and permanently stops after any cap, identity or
consistency failure. All g calls precede their first-identity check; each k has
its own inverse-omega scalar FFT with one normalization, followed by W/U and
encoding-order identity checks. It never truncates a larger Lagrange vector to
construct a smaller domain. The small quadratic helper remains an independent
bounded k≤6 control oracle; the scalable owner uses a radix-two transform.

The standalone producer is a diagnostic command with small defaults:

```sh
python3.12 -B -S -m formal.kagemusha_setup.produce_parameters --output /absolute/new/output
```

Defaults select both k6 curves,132 contexts,1024 raw calls,412 retained raw
entries,8 requests,1MiB parameter wire output and32MiB allocation allowance.
Every count has a finite absolute bound. k>6 additionally requires
`--allow-large`; the maximum is k16 and131076 distinct contexts across both
curves. Scheduling of other qualification or build work is not inferred
from this flag. Larger execution must be deliberately scheduled by its owner.

Memory admission distinguishes a conservative container reservation from
checkpointed `tracemalloc` peak allocations. The latter runs after each raw
call, point, FFT stage and final retention/hash pass. A bounded operation may
overshoot before its next checkpoint; this is not an instantaneous OS/RSS cap
or a performance qualification. Full two-curve k16 would require explicit
context/query/entry/output budgets and a larger memory option; no full-size
family is generated by the maintained checks or CI.

A fresh mode0700 directory retains exact parameter bytes, private logs, the
raw-oracle table, sampler attempts and failures. JSONL is streamed. Final
filename/size/SHA custody must match each generated wire record and the exact
selected artifact namespace before success. No crash-durability or resume
claim is made. Parameter identity records also derive the all-ones folded
G=sum(g_i), its private log and finite flag for that k. This is a candidate
mathematical ACC_TRIV value for a future private setup experiment, not a new
production literal or current verifier authority. An identity is retained,
never repaired; downstream relations still require finite admitted points.

The thirteen added controls compare k0/k2/k6 byte-for-byte with the unchanged
small family; verify shared context replay and direct scalar transforms;
refuse unsafe budgets, sampler exhaustion and native identity order; and
exercise fresh/existing output, CLI module prelaunch/source/optimized refusals,
allocation failure and mutated final artifact joins. CLI refusal tests use
`-B -S -m` and an isolated temporary repository copy for a missing-source case.
Only small parameters are constructed; they do not add a full-size proof or a
C12 claim.

## Sequential simulator requests

`simulate` requires an explicit bit source and never creates or resets a PRNG.
`requests.Owner` shares one entropy source across a finite sequential request
history. Its default uses `secrets.randbits`; tests explicitly supply a seeded
stream once per owner. Each invocation counts before calling the source, even
on error. Invalid bits, provider errors, field rejection exhaustion and either
draw cap retain a failed canonical request without retry or entropy fallback.
The toy still uses at most36 scalar samples and4608 source calls. The generic
engine derives `sample_budget(case)` from the descriptor: fresh point samples,
random advice/product/lookup evaluations, only the masked opening groups and
at most one final c. Every sample corresponds to a serialized32-byte message;
for an admitted proof≤10,000bytes there are at most312 samples, each allowing
128 rejection draws, hence at most39,936 source calls. Defaults of40,960 per
request and327,680 total cover eight requests at that conservative bound.
The exact historical Omega inventory has58 point samples,37 evaluation samples
and one possible c:96 samples or12,288 source calls. This is simulator scalar
sampling, not the native prover's131,218 polynomial/scalar draws. Smaller
explicit caps deliberately expose terminal failures; they do not change the
native distribution or authorize a retry. The descriptor bound is retained
in successful simulation metadata and every admitted request observation.

Exact descriptor/key/parameter/public-preprocessing bytes and canonical instance tuples bind each
request identity. A retry returns the same frozen outcome and consumes no new
entropy, including at capacity. New canonical requests use the next stream
portion. Syntax, changed-binding, capacity and reentrancy refusals publicly raise
`ValueError`; canonical attempts return only immutable proof bytes or failure.
Failure reasons, scalar logs and draw counts remain private diagnostic data.
All fallible proof validation and hash metadata precede success publication;
a caught failure or interrupt restores the failed outcome. Interrupts propagate.

Unused-tail independence holds for ideal independent bits at bounded stopping
points. It does not identify an OS source or seeded PRNG with that ideal, hide
observable failures/timing, or justify a low-quota/native draw-law substitution.
Shared mutable decoded case objects are trusted inputs, not Python capabilities.
This owner is neither thread-safe nor crash-durable wallet storage. Its synthetic
setup does not authorize foreign production parameters or resolve C12.

The eleven controls cover four complete proofs on both curves, golden first
proofs, adaptive second inputs, exact retry, altered bindings, invalid/provider/
exhausted entropy, interruptions, immutable outcomes, capacity, reentrancy,
storage failure and late-metadata failure. Two injected byte fixtures exercise
publication failures only; they are never counted as proofs.

Request containers have two named diagnostic caps: `MAX_INSTANCE_COLUMNS=256`
and `MAX_INSTANCE_VALUES=256`. The value cap applies to each column and their
aggregate. These finite resource limits are separate from the descriptor's
protocol bounds; exact descriptor column lengths, scalar types and canonical
field values remain required. Column counts and lengths are checked before
visiting scalar values. This admits Load A's69-word statement and Load Q0's
five-column `[124,2,1,1,1]` shape without selecting a special profile in the
Owner. Nine request-shape controls cover those shapes, exact failure replay
and changed bindings, the256/257-column and256-value boundaries, early shape
refusal, malformed containers, descriptor validation and unchanged explicit
k>6 opt-in. Their simulator is replaced by a failing sentinel: these controls
generate no proof or entropy draws and do not establish native Q0/A1 simulator
acceptance or privacy.


## One generic outer algorithm and historical public originals

`simulator.py` is the sole fixed-RP57 proof algorithm. Existing ordinary and
contradictory cases and the sequential request owner use its explicit entropy
argument. `public_setup.py` decodes the exact PIPAPK01 public fixed/sigma
evaluation tables, descriptor/VK bindings, canonical fields and copy digest.
Its domain-aware barycentric evaluation handles on-domain points exactly.
Public-only opening groups are evaluated from those tables; only groups with
witness masks draw random opening values. Multiple products/lookups retain the
native ordering. No transcript challenge or permutation is programmed.

`rebind.make_case` consumes caller-supplied exact descriptor, VK and public
original bytes plus already produced chosen parameters/logs. It retains the
historical bytes, changes only the descriptor parameter digest, rebuilds fixed
and sigma commitments using the native default blind1, and preserves the
public tables/copy digest/selectors. Its fresh private authority is established
before decoding the new descriptor and key. The sole accepted historical k16
triple is fixed in `rebind.OMEGA`; it is custody metadata, not a signed catalog
or current source qualification. This path never discovers or opens catalog
originals by itself.

k>6 rebinding and proof execution require explicit `allow_large=True`; defaults
refuse before private-reference creation/large hashing. Direct private-reference
entry also validates a supplied authority tag, integer k, raw byte extent and
explicit large opt-in before creating any directory or hashing supplied bytes.
An exact descriptor override must be a canonical64-character lowercase hexadecimal
string before it can be inserted into private copied source. A direct caller owns
any reads performed before supplying bytes. Ordinary checks never execute large parameter construction, rebinding or proving;
the closed A1 controls use explicit large flags only on inert/sentinel or small
descriptor paths. The generic
k16 private reference changes exactly two resource checks: it permits only the
specified Pallas V2 descriptor digest and Pallas k16 parameter extent. Parsing,
RP57, key binding, all verifier equations, full generator decision and parameter
hash authority remain unchanged. These private copies do not alter repository
or production acceptance and do not admit an arbitrary issuer CRS.

Historical inner curve points, trivial-accumulator constants and embedded
recursive keys remain the old relation's constants after this outer rebinding.
It is not a coherent recursive catalog re-key and supplies no native wallet
proof or release authority. Any such experiment needs separately re-synthesized
relations and authenticated artifacts under one coherent chosen setup.

The additional small controls preserve the original generic arithmetic's six
complete cases, ordinary proof/descriptor/key parity, exact table and original
custody, public-only values, two-product/two-lookup shapes, all point logs,
mutations, authority refusal and bounded replay. Five further methods check
interpolation/canonical-table rejection, query bounds, descriptor-derived
entropy accounting and pre-I/O large-mode refusal. They generate six additional
k6 proofs, for fourteen total across100 methods. The nine request-shape cases and fourteen
closed A1 constructor cases add no proofs. All prior60 assertions remain;
the request binding control additionally mutates public preprocessing bytes.
No k16 proof, large parameter family, timing qualification or C12 claim follows.


## Closed historical Load A1 outer constructor

`load_a1_case.Constructor(output, originals=directory, allow_large=True,
entropy=callable, limits=Limits())` is a separate diagnostic front for one exact
historical Eq/Vesta k16 Load A1 relation. Its required `originals` argument
selects an existing directory, not authority. There is no default development
path or automatic discovery. Three regular files directly in that directory
must have the exact SHA256 basenames and lengths below:

| Role | Bytes | SHA256 basename |
|---|---:|---|
| Descriptor |39,386 |`e7e535287ff5b2f41ff3c4a92dac549981b1dea243ba191930cc24932a51c087` |
| Verifying key |2,154 |`04c6acf9d714bf3259dfb1b71606f7f655419548ab2bd5e930ecbd2418b2762c` |
| Public proving original |140,511,414 |`04824c5fdb5d8f59ef66de7a822d170ece02134b50abe9b65b63ebe3b8fa3a34` |

The package includes only `load_a1_descriptor.norito`, the exact 39,386-byte
historical descriptor, as **DATA for decoder/custody tests**. It confers no
source, catalog, witness, parameter, or native verifier authority. Neither the
large original nor parameters are needed by ordinary tests. The package source
inventory pins that fixture. The fourteen controls use ordinary temporary
folders and small synthetic refusal inputs, without a development output tree.
They import an isolated reference for the small descriptor but do not construct
a real A1 case, derive setup parameters, perform an FFT/MSM, or generate a proof.
After a reviewed source installation, their no-proof command is:

```sh
python3.12 -B -S -m unittest -v formal.kagemusha_setup.test_load_a1_case
```

The front requires `-B` and unoptimized Python before any private import or
entropy use. It rejects unsafe/missing original directories and occupied output
paths before reading originals. `build()` reads each code-selected artifact
through the exact nofollow parent/file identity guard, full hash and EOF check;
partial observations survive failures. The historical reference retains official
KATS and permits only the exact Eq16 descriptor resource exception. Full table
and canonical-field decoding precedes the sole internal `bounded.Owner.derive(1,16)`.
No caller-supplied Parameters object, log map or JSON receipt is accepted by this
front. The same live owner, raw oracle and finite caps remain attached to a
successful case. Replay returns the same success/failure object without another
family; interruptions retain failure and propagate. `close()` ends residual
queries and does not provide restart or serialized trust.

`rebind.py` supplies the shared re-key implementation. Its existing `reference`
and `make_case` signatures, small defaults, 128MiB original guard and sole
Pallas-Omega k16 triple remain unchanged. Private factoring gives the closed A1
front its exact Vesta resource predicate, delegated output writes and allocation
checkpoints; it does not add an alternative public generic profile. The scalar
IFFT, ordered point/log equality, default commitment blind1, canonical parsing,
RP57 equations and full generator decision are unchanged. Chosen authority is
written only in a fresh private namespace, before importing that namespace.
Historical inner constants and recursive keys remain unchanged, so even a
successful future large construction would be a chosen **outer polynomial
relation**, not coherent recursive re-keying or current native authority.

A real construction requires a separately scheduled large handoff. One shared
tracer checks a 2GiB peak-allocation ceiling across intake, setup and rebinding.
The arithmetic allowance is 532,678,860 setup bytes plus 1,614,804,788 case and
transient bytes; these do not charge or reserve the ceiling twice. Full decoder
regions can allocate before the next checkpoint, and `tracemalloc` is neither an
instantaneous limit nor RSS measurement. The exact setup uses 65,538 contexts,
at most 262,144 raw queries/entries, one request, and 4,194,372 parameter bytes.
The output owner enforces at most1GiB,64 files,depth4 under a fresh0700 root,
charging chunks before writes;256KiB and three slots are retained for terminal
records. Exact namespace/hash/extent checks and a final allocation checkpoint
precede success. Private logs, original read observations and partial failure
DATA are retained; no crash-durability or performance claim is made.

Ordinary100 controls still produce only the existing fourteen small k6 proofs.
Their success cannot establish a large A1 construction, any native16 adapter
acceptance, the full joint sampler law, a coherent recursive setup, or C12.
