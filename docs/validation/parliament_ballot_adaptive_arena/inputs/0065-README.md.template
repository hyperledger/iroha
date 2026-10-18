# Legal public request families and the next bound

This is a read-only source/domain analysis, not a new resource certificate.
The frozen circuits, captures and published bundles are unchanged. Selected
identities are recorded in [source-pins.json](source-pins.json); no Rust build,
worker, factory, gate-stream or test execution is part of this analysis.

## The actual standalone Rust domain

The REG bounds in `PublicShape` match the Rust types. The VOTE shape helper's
upper bound 1024 does **not** describe the complete Rust typed request domain.

| Boundary | Source-admitted shape/content |
| --- | --- |
| `BodyContext::new` | Any byte string of length 0..4096, including empty; longer input returns `BoundExceeded { bound: 4096, actual }` before copying. |
| `OpaqueField::new` | Any byte string of length 0..256, including empty; longer input returns `BoundExceeded { bound: 256, actual }` before copying. |
| `RegistrationContext` | Six independent `OpaqueField` values: network, authority, assignment, governance attempt, election attempt, body role. No nonempty, cross-field, sum or semantic validation. The context's opaque body-role field is not the proof `Role` enum. |
| `RegistrationStatement::new` | Already constructed body/context plus arbitrary `Commitment([u8;128])` and `Digest64([u8;64])` authorization. The statement's private body digest is computed from its body; a separately supplied inconsistent B cannot be represented by this safe API. |
| REG `instance` | For these bounded types and the fixed profile, framing has no input-dependent refusal. A publicly well-shaped C/auth need not have an opening under the application's supplied witness. |
| `VoteStatement` | Public fields include unrestricted u8 vote, u16 declared count, and any ordinarily constructible `Vec<Commitment>`; the other values have fixed byte widths. Its fields can be mutated after construction. `new` is a valid convenience path, not the sole admissible typed input path. |
| VOTE `validate` | First invalid vote byte; then actual vector length outside 3..1000; then first adjacent non-increasing pair; then declared/actual count mismatch; then digest mismatch. No list hashing or ordering scan precedes the actual-size refusal. |
| Role and row | Safe APIs use the two Rust enum variants of each. There is no source-level invalid-string row/role error at this boundary. A raw selector decoder would be a distinct interface. |

Authoritative paths: [framing.rs](../../crates/iroha_parliament_ballot_proof/src/framing.rs)
(constants and constructors, lines25–29 and257–310),
[credential.rs](../../crates/iroha_parliament_ballot_proof/src/credential.rs)
(`RegistrationContext`, lines149–217),
[registration.rs](../../crates/iroha_parliament_ballot_proof/src/registration.rs)
(`new` and `instance`, lines51–201),
[vote.rs](../../crates/iroha_parliament_ballot_proof/src/vote.rs)
(public fields and validation, lines93–251), and
[sealed_list.rs](../../crates/iroha_parliament_ballot_proof/src/sealed_list.rs)
(limits and error order, lines23–73).

Thus a REG family has B in 0..4096 and six independent lengths c_i in 0..256.
There are exactly 4097*257^6 = 1,180,496,500,391,613,953 length tuples per row.
Every tuple is realizable at the bounded opaque interface. The derived sum
B+sum(c_i)<=5632 is not an additional policy. Byte values impose no further
public syntactic restriction. With a chosen secret, valid C/auth can be generated
for every such context; requiring an actual witness does not remove length tuples.

VOTE's passing actual sizes are the 998 integers 3..1000. At any such size the
content-invalid inputs are also part of the typed validator's domain. The
current totalized content family charges them with the same fixed computation.
The frozen rejected-size family separately covers a conservative mathematical
u64 length descriptor outside that interval, preserving borrowed list storage
and using the source's vote-first priority. Not every abstract u64 length is a
physically constructible native Vec: allocation/address-space/Vec invariants
constrain that further. No claim that every such descriptor is reachable is
needed for a conservative envelope, but authentication to the same actual Vec
and the chosen native usize width remain explicit premises. Neither 1024 nor a
new smaller resource policy can be installed as a source admission limit.

## Which boundary is still missing

1. **Typed construction versus raw bytes.** Oversized opaque slices and wrong
   fixed-width values are refused before a `RegistrationStatement` exists.
   Current REG circuits begin after that construction. If the experiment is
   extended to raw inputs, it must price and encode constructor errors, actual
   length metadata, copying and any input ownership policy. Do not invent a new
   P0 error for an impossible malformed typed REG object.
2. **Test codec versus typed validation.**
   [test_codec.rs](../../crates/iroha_parliament_ballot_proof/src/test_codec.rs)
   expressly prohibits use as a production schema. Its `decode_registration`
   additionally checks descriptor, framing, supplied B and fixed widths. Its
   `decode_vote` checks frame/descriptor, the size/vote field widths, list byte
   multiple and actual list bound before building a statement and calling
   `validate`. A raw invalid vote byte combined with an oversized list therefore
   does not share the typed validator's first-error ordering. Current header/P0
   circuits cannot be described as this raw decoder. Verifiers also check proof
   length before statement validation. These are distinct maps and counts.
3. **The game checks witnesses before simulator entry.**
   [arguments Property5](../../specs/parliament_ballot_proof_arguments.md),
   lines1472–1486, requires both public validation and R_role(x;w_app), then
   excludes invalid requests from simulator invocation. The Rust prover has
   `WitnessRejected` through `prove_relation`/backend `prove_bounded`. Current
   public-only request circuits intentionally have no application witness and
   do not price that external check, witness construction or all its refusal
   outcomes. Public validation coverage is not that full game-entry coverage.
4. **Production authority and canonical encodings.**
   [private ballot design](../../specs/parliament_private_ballot_design.md)
   identifies body_context as the canonical network/governance/election/role
   tuple, introducing semantic correlations in an eventual production adapter.
   Section 12 still requires the canonical Norito schemas, layout flags, field
   order and length rules to be specified and built. The standalone source
   treats the encodings as opaque and delegates eligibility, authority,
   seal/context authentication and canonicality to callers. This future subset
   cannot narrow the existing standalone theorem's domain without a specified
   and priced adapter. A source search of Core/data-model/Torii found no direct
   `RegistrationStatement`/`RegistrationContext`/`VoteStatement` integration.
5. **Counts beyond T.** The
   [hidden-assignment boundary](../../specs/parliament_ballot_b6_hidden_assignment_deletion.md)
   bounds valid requests by T. The
   [hybrid driver's §7](../../specs/parliament_ballot_b6_hybrid_driver.md)
   explicitly leaves invalid-request, application-context and direct-verification
   counts separate. Finite per-request families alone do not yield a finite
   complete lifetime vector if those invocation/input budgets remain unspecified.
   Optional policy/proposal digest helpers accept much longer preimages than the
   proof inputs and are caller work, not free hashes hidden inside a digest input.

The existing spec boundary in
[ideal_sampler_accounting §1](../../specs/parliament_ballot_b6_ideal_sampler_accounting.md)
is valid bounded typed public statements, with public bodies/lists/existing
digests supplied. It is coherent to finish a bound at that boundary first and
retain all the upstream terms explicitly. That is not production qualification.

## Why endpoint observations are insufficient

The older four accepted-only observations use REG at B=4096 and all c_i=256,
and VOTE at n=1000, for each row. They are exact cases, not uniform bounds.
The newer four content observations add n=3 and 1000 and P0/validated W/E/common
return, but still do not cover every family. For example, a maximum-sized length
prefix can have fewer one bits: popcount(4096)=1 versus popcount(4095)=12, and
popcount(256)=1 versus popcount(255)=8. Source constant-wire X costs depend on
those bit counts. Hash block counts depend on padding boundaries; list-order
indices and relation selectors also depend on shape. These facts do not prove
the endpoint is smaller overall, but they prevent inferring monotonicity merely
from its larger byte length. A proof must combine every relevant term.

## Concrete next component

Build a separate source-pinned **analytical family-envelope checker** without
changing the frozen emitters or adding admission limits. Its first scope should
be all bounded standalone typed REG shapes and all VOTE content shapes 3..1000,
with rejected-size typed maps accounted separately. Leave raw ingress and
witness/application checks as explicit unpriced terms.

For REG let s=sum(c_i). The actual frame byte lengths are:

| Message | Byte length |
| --- | ---: |
| BODY frame hashed by concrete SHA3 | 40+B |
| REG-AUTH frame hashed by concrete SHA3 | 343+B+s |
| F_REG | 314+B+s |
| Full H_mu backend address | 392+B+s, including 77-byte namespace and final 08 |

Profile/CRT hashing is fixed per row. The P1 relation/output widths are fixed
for REG (4736 relation bits, 6376 total P1 bits). S0, opening, VOLE, R0/R1, W/E,
proof length and private coin counts depend on role/row/M, not the seven opaque
lengths. Original public storage is 8*(B+s+192) bits. Hash lengths and dynamic
field copies depend on B and s; prefix-constant one bits retain dependence on
the individual c_i. Read and derive the emitter equations, including both clean
traversals and output copies, rather than importing a maximum from a native
permutation-count note.

A finite reduction avoids enumerating 1.18e18 tuples: if the derived expression
confirms that the individual context dependence is exactly its weighted prefix
popcounts, use an exact max-plus recurrence over the six fields, preserving
witness lengths and any differing multiplicities:

```text
H_0(0)=0; H_0(s>0)=-infinity
H_j(s)=max over a in 0..256 of H_(j-1)(s-a)+popcount(a).
```

Then enumerate B in 0..4096 and s in 0..1536 using the proved expression. A looser
coordinatewise analytic bound may instead use proved nonnegative length/block
envelopes and independent prefix-popcount bounds, explicitly labeled an upper
bound without claiming a simultaneously attaining shape. In either version,
record whether the witness maximizes X/CX/CCX, elementary gates, or wires; maxima
for distinct coordinates need not occur at the same shape. All public wire
inputs, retained outputs and max-reused scratch must remain charged.

For VOTE derive the P0/P1/R1 scalar dependence and evaluate every n in3..1000
(998 cases per row). This is small finite arithmetic, not full gate expansion.
Include invalid content's totalized cost, W/E validity deltas and the common
return. Outside that interval, the existing typed rejected-size formula is
5881+2*popcount(n) elementary gates, zero F and 519 work bits, plus all borrowed
input/list and output storage. An algebraic u64 over-envelope is permissible as
an explicitly conservative descriptor family, not a new claim of Vec reachability.

Meaningful controls should compare the derived formulas with retained exact
observations and a few independently constructed boundary shapes; exercise
zero lengths, 255/256,4095/4096, every relevant SHA3 rate boundary, mixed context
lengths, list 3/1000, and malformed content. Mutations must break prefix charges,
clean inverses, return extensions and max-work accounting. The DP reduction
itself needs small exhaustive controls and reconstructed argmax witnesses.

This can close uniform bounds on the stated typed-family body computation.
The complete experiment still needs priced authenticated family selection,
raw-input/constructor or declared typed-entry policy, witness and application
checks, initialization/entropy, invalid-request counts, external queries and
adversary resources. No endpoint observation or new production limit substitutes
for those obligations. All full resource and qualification flags remain false.
