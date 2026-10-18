# KAGEMUSHA recursive verifier and accumulation argument

The construction sections below describe the selected first-release C12
proposal. Its native, recursive, proof and wallet owners are coupled: source
review does not establish a buildable partial migration, current catalog
admission, joint privacy, or release qualification. Historical formal models
and executions retain their original source scope; see the transfer boundary
under Composition, keys and disclosure.

This is the implementation-coupled M4 engineering argument for
[`iroha_plonk_recursion`](../crates/iroha_plonk_recursion/src/lib.rs). It covers
the explicit PIPA-R profile, native PIPA-AS, the incoming-claim branch rule and
the obligations that the operation relations must bind. It is not an external
audit, a security reduction for arbitrary lineage depth, or acceptance of an
unimplemented operation circuit. The current evidence remains in the
[gate checklist](kagemusha_evidence_gate.md#8-recorded-results).

## Assumptions and theorem boundary

The construction assumes discrete-log hardness in the two pinned prime-order
Pasta groups; collision resistance of the pinned Poseidon hashes; and the
random-oracle model for the domain-separated RP57 transcripts. A concrete
Poseidon implementation is a heuristic instantiation of that model.

[BCMS20](https://eprint.iacr.org/2020/499.pdf) gives accumulation definitions,
a PCD construction and a discrete-log polynomial-commitment accumulation
construction (§§4–7 and Appendix A). [BCLMS21](https://eprint.iacr.org/2020/1618)
studies split accumulation under discrete-log assumptions in the ROM.
Its PCD transformation, like BCMS20's, instead assumes the required argument
and accumulation security in the standard CRS model; the concrete recursive
construction follows after heuristic instantiation. The ROM accumulation
results therefore do not by themselves establish security of the
oracle-dependent recursive relation implemented here.
[BGH19](https://eprint.iacr.org/2019/1021) is the underlying Halo construction.
These results motivate the architecture; citing them does not prove that the
particular layouts, encodings, mixed-curve wiring or containment rule here
satisfy all their hypotheses. The arguments below are local derivations for
this implementation. The canonical construction's caveat about unbounded
lineage depth remains in force.

### Selected recursive Fiat–Shamir assumption

For the first release, the owner explicitly selects the current Pasta/Poseidon
construction and accepts the following additional heuristic: instantiating the
argument and accumulation transcripts with the pinned RP57 function preserves
the knowledge-soundness and accumulation-security properties required by the
recursive PCD composition, including when its relations evaluate that concrete
function inside their verifier circuits. This is an assumption about this
recursive instantiation, beyond the single-proof ROM claims. It is not a theorem
from collision resistance, discrete-log hardness or the cited accumulation
results. [Halo Infinite](https://eprint.iacr.org/2020/1536) likewise distinguishes
its practical recursive construction from a proved black-box Fiat–Shamir use.

This selection retains the current parameters, curves, relations and proof
formats. It does not adopt a programmable setup oracle or an algebraic random
oracle as a new production primitive. In particular, it does not supply the
missing joint privacy simulator, justify programming a fixed circuit hash, or
make independently derived local oracle models consistent. The C12 argument
must still account for the actual public transcript, both fields, correlated
folds, checkpoints, retries and failure branches under one explicit interface.
Source-bound artifact admission, adversarial tests, performance gates and
physical-device qualification remain separate. Unbounded lineage depth remains
heuristic; accepting this premise does not establish a quantitative security
bound for arbitrary depth.

## Injective framing and challenge distributions

PIPA-R has an explicit V2 descriptor schema and decoder, with protocol version 1. Its key commits to the
descriptor, the pinned parameter digest, the transcript profile, Direct
instances and the FoldedGenerator suffix. No decoder retries a retired
profile. The transcript starts with the `pipa-rb1` domain and absorbs the key
representation, `pipainst`, column count, every column length, every type code
and the column-major instance values. This makes the statement's shape and
type part of the challenge input. Noncanonical integers and identity in ordinary
point roles are rejected. The final generator suffix and carried generator claims
alone admit the canonical full-group identity encoding.

Proof scalars use a single canonical base-field element when the scalar
modulus is smaller, and the S6 `(lo128, hi127)` encoding otherwise. Range and
modulus checks make S6 injective. Ordinary points use finite canonical `(x,y)`
pairs; the compressed byte decoder binds x and its sign bit to those pairs and
the circuit checks the curve equation. A scoped generator uses the same finite
encoding or exactly `(0,0)`/zero32 for identity, with no relaxation of decide. An outer byte-link relation must
bind the actual supplied length and every byte; a valid dummy used by a soft
decoder is never a replacement for that binding.

Let p be the Pallas base modulus, q the Vesta base modulus and δ = q−p.
The checked constants give
`δ = 86663725065984043395317760 = 0x47afc1f319ba3400000000`.
For a uniform Fp transcript word, identity embedding into Fq has statistical
distance δ/q from uniform Fq. For a uniform Fq word, reduction by one p gives
Fp probabilities 2/q on `[0,δ)` and 1/q elsewhere; its statistical distance
from uniform Fp is `δ(p−δ)/(pq)`, at most δ/q. This is the base-conversion
distance only. The selected role maps subsequently set `nz(0)=1`, `nz(a)=a`
otherwise, `x=5*nz(a)^2`, `x_3=25*nz(a)^4`, and map Xi and each actual IPA/fold
round through `nz`. Their maximum scalar fibers are respectively 3, 5 and 2;
the base conversion has multiplicity at most 1 for Pallas and 2 for Vesta.
These are pushforward laws, not approximately uniform scalar challenges.

Five is nonsquare in both scalar fields. Evaluation x is nonsquare, x_3 is
square but not a fourth power, and the supported domain rotations are fourth
powers. Thus domain/opening denominators are nonzero at the selected roles.
The permutation/lookup factors are separately `N(t)=t^2−5`, with final product
one. Raw zero is handled by the total map; only normalization padding remains
zero. Other raw roles, including alpha/z/zeta of the local fold, are unchanged.
Malformed values still produce refusal or a soft false bit under the owner's
contract. These source equations do not prove the soundness or privacy of the
concrete RP57 instantiation.

## What an accumulation fold proves

For an input `(G_j,k_j,u_j)`, normalized challenges have exactly `16−k_j`
leading zeros and k_j nonzero canonical suffix elements. They determine a
length-65536 vector s_j whose nonzero prefix agrees with the source generator
prefix. The deferred claim is `G_j=Commit(s_j)`; G_j may be identity.

The selected committed-mask construction consumes a private tape with 33
scalar coins: rho followed by 32 ordered L/R masks. Every coin may be zero.
The `pipa-in1` digest binds parameters, closed purpose, slot count, each exact
canonical source and all 32 masks. Its two canonical 128-bit digest limbs h0,h1
open `D=h0*g[0]+h1*g[1]+rho*W`. The `pipa-as1` challenge transcript absorbs
parameters, purpose and count, then finite D, before alpha,z,zeta. It does not
absorb an external salt or the private input list directly.

Purposes are closed: SigmaBatch uses Vesta; AInitial and AContinuation use
Pallas; ATerminal uses exactly four Pallas slots; WrapperVesta uses exactly four
Vesta slots. The terminal `pipa-tm1` projection binds the actual V slot, masks,
descriptor and raw first Theta from the same admitted proof. It is available
only through the non-Clone `TerminalPlan`/`TerminalFrame` owner, whose fixed
four-slot derivation and same-frame own-opening obligation remain mandatory.
Neither an arbitrary raw word nor an input digest is verification authority.

Set `h=sum_j alpha^j s_j`, `C=sum_j alpha^j G_j` and `v=h(z)`.
The IPA opens `h−v*e_0` with zero evaluation. Each round adds `ell_j*W`
to L_j and `r_j*W` to R_j, then obtains `u'_j=nz(raw_j)` from the existing
squeeze. With `gamma=sum_j(ell_j/u'_j+r_j*u'_j)`, the succinct equation is

```text
C − v*g[0] + sum_j(L_j/u'_j + u'_j*R_j)
  − c*G' − c*b(z)*zeta*U − gamma*W = O.
```

D and all L/R messages use the ordinary finite-point codec; G' uses the
scoped full-group codec. The body is D, 16 L/R pairs, c and G': 1,120 bytes.
The private witness appends rho and 32 masks (1,056 bytes), totaling 2,176
bytes. It is not a public Payment field. Input/mask binding, the D opening,
the exact gamma correction and the final generator decide are all necessary;
the earlier non-hiding extraction argument cannot be reused by dropping W.

The API returns an undecided accumulator. Parsing or `verify_fold` alone does
not authorize a payment. `ArtifactSet::verify_lineage_cancellable` fully
verifies Omega's own Pallas opening, then independently decides acc_P and
acc_V with pinned parameters. Checking only the exposed pair is insufficient.
The generic batch API is not this wallet acceptance boundary.

Every decide runs through the pinned parameter owner, which compares the
claimed `G` with `<s(u), g>` on every call. The owner may take that point from
its bounded process-local memo, which only an accepted decision or production
full verification of the same exact challenges on the same owner fills; a full
verification whose complete input digest the same owner accepted earlier may
reuse that acceptance, under SHA-256 collision resistance. Its key binds the
curve, k, descriptor, profile, verifying key, framed instances and proof bytes.
This cache does not grant masked-key or source-graph admission authority. Rejections, undecidable claims and cancellations are
never retained, Corrected-mode selection still compares every claim in order,
and a correction is still the exact point. A caller that needs a fully verified
proof's own opening as a decided claim obtains it from the same single read
(`verify_full_opening_cancellable`), and a prover-returned opening must equal it
exactly.

The caller still supplies a counted, explicit k16 trivial slot when all actual
sources are short; the implementation rejects an all-short set. That policy
must not be justified by the old claim that masked L is forced to identity.
Finite D/L/R failures and operational failures remain fallible outcomes, not
completed payments. A failed attempt does not authorize a new proof with the
same coins. Restoration verifies the exact retained witness and originals.

The selected arithmetic retains the source01b packed CRT, pooled/reduced
foreign values and canonical S6 ownership. Norm evaluation uses the exact
`m−5` padding and existing range/carry checks; it is not a new layout tuning.
The [carry memo](kagemusha_ff_carry_v1.md) supplies its stated integer premises;
layout tuple goldens and proof-byte fixtures still require actual synthesis
against the complete selected source, not guessed replacement constants.

## Branch uniqueness and containment

`ModeCells` constrains exactly one of Accept, Trivial and Corrected in each
incoming slot. `constrain_incoming_modes` constrains the sum of Corrected
bits to a boolean, computes `valid = AND(soft_bits) AND no_correction`, and
equates every Accept bit to valid. These equations imply the exact §2.7
branch rule: acceptance uses every original incoming claim; rejection uses
only trivial replacements except for at most one correction; if all soft
checks pass, rejection requires that correction.

Selection must preserve the original challenges and source k in Accept and
Corrected modes. Corrected also requires scoped full-group `G* != G`. Trivial selects
the pinned `ACC_TRIV` with source k16 and sixteen ones, including when the
original sigma source was k12 or k14. The selected k is constrained and
absorbed; relabeling a short padded input as k16 is invalid. A valid dummy
from soft decoding is not an authorized Trivial replacement.

Conditioned on accumulation soundness, a selected correction that eventually
decides demonstrates that the original claim failed. If all succinct and
consumer checks and all original deferred claims are true, neither a false
soft bit nor a distinct deciding correction exists. The receiver therefore
cannot choose burn for valid evidence. Conversely, an invalid deferred claim
has the deterministically computable correction `G*=Commit(s(u))`, including
identity under the scoped codec. The corrected decide must still hold; identity
is not a bypass. This removes the older correction-encoding exception, not all
proof/entropy/resource failures or the need for complete operation qualification.
Hard own/predecessor/Q/A obligations
never enter this selection API. Receive burn and ArchiveSent no-op effects
still require the complete operation, map and integer constraints; the
mode rule alone does not establish monetary conservation.

## Composition, keys and disclosure

The fixed ledger identifies each opening and each transported accumulator
separately, even if their bytes happen to be equal. Current construction
metadata covers all 14 unsplit variants. The single-sigma forwarding path
preserves its original source k; the two-sigma path includes its explicit
full-length trivial slot. Every consumer must constrain all forwarding
equalities and the mode instances across Q, A and Omega. Split operation
sources bind their fixed task/Q partition and complete context through each
preceding W key and continuation digest. Complete source execution and terminal
catalog admission must still be established separately for every operation;
the split metadata constructor alone is insufficient.

The `kgwvkey1` digest binds curve, k, descriptor digest, representation and
every fixed/permutation commitment in canonical order. One-hot allowlists
select sigma and A keys. The final native verifier pins `vkOmega_digest`;
each A proves that its witnessed predecessor key hashes to that carried
field and copies it forward. Bootstrap has no predecessor, and its free
digest is ultimately pinned by that same final native check. This induction
requires the actual key-hash and equality constraints in every operation,
not just a native digest helper.

Omega uses a hiding proof construction. Q/A and local fold proofs remain private.
An accumulator reveals G and its transcript challenge vector; for a deciding
accumulator, G is determined by that vector and the pinned generators.
`a_relation::binding::lineage_digest_fields` hashes exactly the 18 public lineage
words, two Pallas coordinates and 32 canonical challenge limbs. Thus D_A is a
deterministic function of the public tuple and adds no further information
conditional on that tuple. Neither fact proves that the tuple is zero knowledge.

### Retained arguments and selected-source transfer

The derivations below, including the non-hiding polynomial, salted-prefix and
local-sampler sections, retain their exact antecedent hypotheses and source
pins. References there to "current" sources or completed checks mean those
recorded bodies, not automatic qualification of the selected committed-mask
construction. Do not refresh a formal source manifest merely to make a changed
implementation pass its old model's custody check.

The [logical setup and causal composition argument](kagemusha_c12_composition_v1.md)
states the common raw-oracle setup-before-pins experiment and its conditional
theorem. Its selected-source interpretation uses the same current byte
materializer across semantic, proof and custody transitions. The experiment is
fixed before honest setup and retains setup failure; it does not condition on
a literal installed key or require a universal simulator for that fixed key.
The selected norm products and role-map distributions, opened D and correlated
mask tape, closed terminal projection, fresh-attempt accounting and
retained-original restoration joins are covered conditionally by that argument
under its named M-admitted local law, reached-source validity and byte-state
service premises. The joint public sigma/P/V/Omega simulator and stopped
refusal law use one coherent two-curve setup and coin experiment, with unchanged
RP57. The accepted recursive Fiat–Shamir soundness heuristic supplies none of
those privacy premises.

Concrete BLAKE2b uses the stated setup-instantiation assumption;
physical-storage refinement and current artifact qualification remain separate.
Source-level kernel/composition reviews and older native executions keep their
individual scope; new catalog/goldens, full native/circuit runs and physical
qualification remain separate unfinished checks.

C12 compares the full terminal public proof view under one persistent typed
random-oracle interface for RP57 transcripts. Addresses are the field and
pinned parameter/IV identity together with cumulative padded rate-two blocks;
logical absorb/squeeze aliases are identified. This is a proof model, with
Poseidon its stated heuristic instantiation. A programmed ROM proof simulator
need not be executable against the unmodified fixed hash. That distinction
neither extends the selected recursive soundness premise to privacy nor
establishes a coherent recursive-source experiment by itself.

The local outer simulator samples a complete PIPA transcript and programs only
its last IPA raw challenge. It includes c,f and the folded-generator suffix,
uses the native challenge map, and keeps occupied-prefix, zero/identity,
noncanonical and other failure branches explicit. Its application requires
the actual admitted descriptor/VK/public preprocessing to satisfy M(K): masked
domain-boundary independence, S7 residual evaluation rank, and the independent
R-last quotient-group mask. The test-only strict-catalog checker can establish
these algebraic conditions for the current Omega and all public sigma keys;
historical artifacts and sampled proof tests do not establish that current join.

The proposed order erases Omega, then the hidden final P/V folds it consumes, then
public sigma proofs. A finite reverse-dependency hybrid can replace each fresh
proof before its digest, receipt signature and Payment are published, then rerun
the adaptive causal suffix, including later credit roots, refusals and restarts.
Exact selected replay reuses the original bytes and oracle answers. This ordering
requires no witness for an intermediate sampled Omega tuple, but only applies
once its initial source and each remaining genuine proof cut are valid.

A coherent local endpoint experiment is available: the private source may
prepare a genuine witness and P/V using fixed Poseidon F, while only the new
outer Omega proof uses the shared transcript oracle H. The local lemma compares
that real Omega with its public-instance simulator for the same P/V and residual
oracle service. It does not require all private ancestors to use H. This local
cut is established in the independently agreeing source reviews
`c12-endpoint-outer-first-quotient-review-1` and
`c12-endpoint-only-rom-boundary-1` under `target/qualification`.

Erasing Omega leaves the exported P/V and any original public sigma proofs with
their F-derived joint law. The fresh-H fold lemma does not compare that law with
its own independent challenge tapes. The full argument still needs that
surviving-carrier comparison under the common query interface, or an alternative
coherent source and valid-cut comparison chain. A replacement witness for the
simulated Omega is unnecessary. Existing transcript domains separate encoded
addresses; they neither justify changing the surviving law nor give the same
address different answers when a public proof becomes a private input or replay.

On the deciding support, that remaining view has a smaller exact representation:
the original public sigma bodies, including c/f but excluding their unabsorbed
generator suffixes, jointly with the 16 Pallas and 16 Vesta accumulator
challenges. The pinned generators reconstruct deciding G values; public sigma
statements and their bodies reconstruct their own challenges and suffixes;
public18 and P reconstruct D_A. Projection and reconstruction are efficient
inverses on this support. Malformed inputs and failed decides keep their actual
branches. The required comparison is therefore the joint distribution of this
representation after executing the private source, not equality of its hidden
Direct prefixes or separate marginal hiding of each challenge vector.

For adaptive composition, a public-only sampler must also preserve related
durable selected-object states and the residual oracle service after every
fresh attempt, including refusals. A bound epsilon_t conditional on each reached
public history then composes by stopping at the first divergence and summing
`E[1_{attempt t reached before divergence} epsilon_t(h_t)]` over fresh attempts.
Exact replay of an already selected original
adds no fresh proof error; storage outcomes still need their own state-relation
argument. Equal returned errors alone are insufficient when immutable objects
can be written before manifest publication. This is a sufficient reduction to
prove, not a new privacy assumption or an established sampler. The
[same-frame opening result](kagemusha_local_zk_v1.md#same-direct-frame-and-the-actual-opening-value)
removes polynomial/blind differences within a common good fiber and preserves
complete private proof bytes through deterministic consumers. It does not
compare the distributions induced by different private Direct frames.

Substituting H in native producers while retaining their genuine fixed-F
consumers does not supply that alternative construction: the no-incoming Load
and Send Q branches bind the native own-claim challenges to round cells computed
by fixed Pow5 constraints. Generating fixed-Pow5 proofs and forcing H to their
answers instead changes the fresh-oracle law; Send later publishes the queried
proof prefix. These failures rule out those adapters, not the valid local
endpoint experiment, a different composition proof or the production design.

The [local auxiliary-input lemma](kagemusha_local_zk_v1.md) is derived for admitted
M(K) keys with ideal fresh scalar masks and the normalized shared oracle,
including the residual query service and joint final c/f law. A hybrid may retain
private prepared state and run the actual signing/storage suffix on either
proof. The final public-only proof simulator must eliminate that private proof
state; original private admission, signing and storage checks may remain in a
common experiment wrapper. It must preserve the experiment's observable typed
outcomes, durable publication order and exact replay without conditioning on
success. This logical terminal-proof claim adds no timing-obliviousness claim
or independence assumption for actual mid-call cancellation.

Existing primary results do not yet supply the remaining joint-law or
source-composition bridge.
[Arithmetized-random-oracle PCD](https://eprint.iacr.org/2023/587) adds oracle
interfaces and query accumulation absent from these fixed constraints;
[Plonk Without Random Oracles](https://eprint.iacr.org/2026/200) uses a
hash/commitment zero-testing condition whose reduction to this PIPA/IPA protocol
has not been established. Neither extension is adopted here. The accepted
recursive Fiat–Shamir knowledge/accumulation heuristic supplies no privacy premise.

C12 closes only with the surviving-carrier comparison or alternative coherent
source/valid-cut argument above and a total final public simulator, actual
current-key M(K) reports, and justified concrete OS/hedging/ChaCha conversion
bounds. If a chosen construction needs changed recursive transcript constraints
or an oracle-aware verification relation, those changes must be implemented,
re-keyed and proved; renaming the existing Pow5 gates is insufficient. No such
change is established by the current local lemma. Fresh-fold bounds apply to
all bounded attempts without conditioning on success. No unconditional
fixed-hash indistinguishability theorem or executable fixed-hash simulator is
required.

For terminal proof privacy with public18 and public sigma statements fixed,
the head and map roots are public inputs, so no head-hash hiding premise is
required. Hiding heads/statements generated from different private histories
is a stronger claim: their joint public law must then be proved under an
explicitly justified hash model. Collision resistance and the recursive-FS
soundness selection alone do not supply that stronger hiding claim. C12
remains open; no stronger privacy or linkability conclusion follows.

There is a concrete encoding obstacle to directly replacing the sponge by an
oracle on unrestricted logical absorb/squeeze histories. Starting from the same
state, absorbing `[x]` and squeezing twice processes the rate-two blocks
`(x,1),(1,0)`. Absorbing `[x,1]` and squeezing once processes exactly those
same blocks. The final answer is identical for every underlying permutation,
while the prototype's logical histories differ. Previous squeeze outputs are
not separately absorbed by the production sponge. A proposed idealization must
identify these aliases, for example through cumulative padded block prefixes,
and then justify its remaining sponge/permutation assumptions. This observation
does not establish a payment-proof forgery; it prevents claiming the current
unrestricted full-prefix model is a proven realization of the production hash.
Both fields reproduce the alias at three domain values, including `pipa-rb1`,
with identical complete states and outputs. The source audit and six checks are
retained in `target/qualification/c12-sponge-prefix-alias-audit-1`.

The revised target-only oracle indexes the cumulative padded rate-two blocks
and base field under the fixed parameter/initial-state identifier. It adds no
logical squeeze markers, previous outputs or extra protocol namespaces; native
domain words remain ordinary first inputs. Eight small controls pass, including
alias agreement, both fields, complete k6 verification and a shared adaptive
table. The selected deferred k16 runner passes ten boundary controls but has not
executed a k16 proof. Its phase guards require the original M3 phase receipts
and cannot turn a borderline measurement into a pass. The records are in
`target/qualification/c12-padded-prefix-model-1` and
`target/qualification/c12-actual-omega-model-draft`.

A source argument now transfers the earlier ideal-model address bounds using
two fixed positions: exact Omega's first advice point occupies block24, and each
honest final fold's block0 is `(pipa-as1, salt)`. Padding aliases still supply
at most one candidate point or salt per outside prefix. That conditional
transfer passes independent source/mathematical review in
`target/qualification/c12-normalized-prefix-lemma-1`. Distinct-prefix answer
independence remains an ideal-model assumption. Concrete permutation relations,
the outer public interface and inner fixed-Poseidon circuit constraints remain
unresolved by this addressing correction.

The actual recursive call sites make that last boundary concrete. A proof that
is an outer Omega today may be hard-verified as a predecessor, or soft-verified
as incoming evidence, inside a later A circuit under the same installed Omega
key and `pipa-rb1` profile. The circuit reproduces the fixed RP57 transcript;
there is no separate namespace reserved for a call labeled outer. Bootstrap has
no external predecessor Omega and instead verifies its pinned internal W0/Q
sources, but ordinary continuation has the same-key boundary. A call-site ideal
outer oracle can define a local hybrid while retaining the concrete arithmetic
relation. It does not itself show that an earlier programmed proof satisfies a
later fixed arithmetic verifier or supplies an honest wallet's next witness.
The joint argument must cover that continuation interface, including branches,
obligations and exact replay. Source mapping and review are retained in
`target/qualification/c12-inner-circuit-bridge-audit-1`. This is a missing model
and composition argument, not an observed attack on the concrete protocol.

For native-reachable cumulative block prefixes, removing only the final padding
gives a one-shot sponge input with exactly the same processed blocks and final
state. A fixed affine coordinate change also maps the native IV/rate placement
to a zero-IV ideal-permutation presentation. These algebraic correspondences do
not establish independent prefix answers or programmable Fiat–Shamir security.
The normalized model also permits raw prefixes outside the native padded suffix
grammar; a reduction must account for that larger interface. Ordinary sponge
indifferentiability does not by itself justify programming answers while keeping
forward and inverse permutation access consistent. The
[Chiesa–Orrù author presentation](https://zksc2026.secpriv.wien/static/talks/slides-michele-orru.pdf)
identifies this separate programming requirement on slides33–34. Primary-source
applicability findings, including retrieval limits and unmatched theorem
assumptions, are retained in
`target/qualification/c12-sponge-theorem-applicability-1`. No cited theorem has
been applied as a complete bridge for this implementation.

A separate target-only experiment replaces independent prefix answers with a
lazy width-three permutation in each base field. Direct forward and inverse
queries share the transcript's tables. Programming replays the prefix and
requires an unoccupied final primitive input, then samples an unused output
conditioned on its returned word. It never overwrites an edge; a fresh logical
address alone is insufficient. Frozen verification replays every primitive edge
without allocating new entries. Fifteen controls pass, including six complete
k6 curve/layout cases, mutations and a second proof sharing prior permutation
queries. Sources remain unchanged through execution. The independent source
review and result are retained in `target/qualification/c12-ideal-permutation-adapter-1`
and `c12-ideal-permutation-controls-1` (result SHA
`48fcc556b0c68d0586f60afd4cf8a4791decbe6b5eff4521db0716e08564e535`).
These finite executions establish primitive consistency for those examples.
They do not inherit the independent-prefix bounds: adaptive conditioning,
programming refusal probabilities, fixed-Poseidon circuits and recursive
continuation remain separate obligations. C12 remains open.

An independently reviewed local argument now bounds a particular programming
refusal in that ideal-permutation experiment. The final IPA round appends exactly
L's coordinates, R's coordinates and `(1,0)` padding. Conditional on its earlier
choices, a fresh uniform scalar masking the solved finite R makes R uniform over
the group's `r-1` finite points. With m previously installed permutation edges,
its block hits an occupied input with probability at most `m/(r-1)`; if fresh,
the next padding input hits an occupied input with probability at most
`(m+1)/(p^3-m)`. Here p is the base-field size, and all forward, inverse and
previously programmed edges count. This requires atomic processing before R is
exposed, ideal random tapes and explicit bounded sampling. It supplies no joint
law for the selected challenge and the later disclosed scalars. Exact conditional
output-fiber bias and those remaining obligations are recorded in
`target/qualification/c12-ideal-permutation-programming-obligations-1`.

A subsequent local final-round coupling passes independent mathematical/source
review in `target/qualification/c12-final-ipa-stopped-coupling-1`. In the stated
ideal-coin IPA experiment, fresh coefficient masking and point blinds preserve
the required conditional vector distribution; away from the explicit rank
exception, c is uniform and the full verification equation uniquely determines
the disclosed f. Coupling the complete permutation output also couples later
public-only forward/inverse queries and the pending transcript buffer. The bound
retains both freshness-stop terms, finite-point and sampling failures, and
averages over random prefixes rather than selecting a favorable observed prefix.
This supplies a conditional last-round argument, not the preceding PLONK
distribution, hidden-fold interface or recursive circuit composition.

A further independently reviewed argument treats the private `as1` paths under
the same ideal permutation as public forward, inverse and programming calls.
For a field of size p, at most B fresh paths, H primitive path positions and Q
outside operations, it bounds the first hidden-path interaction by
`min(1, [2Q(B+H)+B(B-1)/2+H(H+1)/2]/p)`. It counts early logical-address cache
replies even when they skip primitive evaluation. Fresh virtual salt and capacity
tapes justify the bound without assuming uniformity after prior misses; a first
extra rejection against a hidden edge is charged explicitly. Metadata, scheduling
and failure replies must jointly preserve the stated private-tape independence.
Hidden occupancy may not cause an uncharged budget refusal. Fold-abort,
generator-relation, entropy and operational terms remain separate. Exact retained
retries reuse their original paths. The source pins, full interface and reviews
are in `target/qualification/c12-hidden-as1-permutation-path-1`. This conditional
coupling does not prove that actual Omega and subsequent wallet operations expose
only that interface, or establish fixed-Poseidon circuit composition.

Two independently reviewed arguments now connect the public outer prefix to the
local IPA argument. In an atomic proof-request experiment, the first freshly
blinded advice point hides the first private path input. With T prior permutation
edges and at most H subsequent primitive positions, a stopped coupling costs at
most `min(1, T/(r-1) + [2TH+H(H+1)/2]/p)`, in addition to the first point's
identity cost. It couples complete permutation edges, so queries after publication
replay the same path. The local owned transcript buffer supports this API model;
it does not establish secrecy against operational observations or permit public
programming between a revealed prefix and its next challenge. The final IPA's
programming step has its separate bound. Details and source pins are retained in
`target/qualification/c12-atomic-outer-path-freshness-1`.

The stopped PLONK-prefix argument uses fresh commitment blinds, the full-rank
Lagrange evaluation map of the row masks, and the random polynomial R's final
coefficient in its opening group. It accounts for dependent quotient and
multiopen polynomials rather than treating them as independent. Conditional on
the quotient identity and the explicit challenge stops, it gives the joint
public-prefix law and the uniform zero-evaluation coefficient vector required
by the IPA argument. Its audited Omega shape has26 freshly blinded points and
131,186 scalar draws through S. The R residual argument conditions on other
original opening polynomials and h, but not the R-dependent q-prime coefficients.
Exact masked-relation validity, challenge freshness, native coin replacement,
operational observations and public preprocessing remain explicit premises.
The argument and reviews are in
`target/qualification/c12-outer-prefix-coupling-1`. Neither argument executes an
actual Omega simulator or resolves the fixed-Poseidon/recursive-circuit bridge;
C12 remains open.

The mask-validity premise is now checked for the exact historical full52 Omega
artifact. A symbolic audit substitutes its original fixed evaluations into all
156 gate expressions: the two usable boundary rows are independent of fresh tail
advice, and every gate vanishes on all six tail rows. Both lookup tuple sides at
the boundaries are independent of those masks, and all six sigma columns fix
every tail cell. The auxiliary product/lookup guards preserve their prescribed
padding. Given a satisfying original witness and nonzero usable denominators,
the numerator vanishes on the domain and its degree bound gives an honest
quotient of degree at most `8n-9`, within eight pieces. Ten small controls and
independent source review support this result. The original PK was hashed once;
only144 boundary scalars were decoded, with no FFT or proof execution. Records
are in `target/qualification/c12-omega-mask-boundary-audit-1`. This establishes
the stated predicate on that pinned artifact, not a current wallet witness or
current source-key admission.

An alternative setup-before-pins experiment now has small executable controls.
Knowing the discrete logs of independently simulated setup points lets the
simulator sample every IPA L/R in native order, use the unchanged RP57 transcript,
compute the actual folded generator and solve the final blind. Eight controls
pass on both curves, including four k6 ordinary/contradictory relation examples
and scalar, generator and instance mutations. All reference verifier sources
are unchanged; only each isolated test's parameter-authority table differs.
The current repository authority rejects those synthetic parameters. This is
conditional setup algebra, not a proof for the release's fixed parameter bytes.
Records are in `target/qualification/c12-known-log-setup-model-1` and
`c12-known-log-setup-controls-1`.

The exact generalized-SWU map also has a source-reviewed inverse using two
quadratic equations and complete branch/sign filtering. Six controls pass,
including all132 retained generator/W/U encodings. A bounded two-map inverse
is uniform in its fiber conditional on success; that does not establish the
forward map's regularity or a bound on its target-dependent failure. The records
are in `target/qualification/c12-swu-preimage-controls-1` and
`c12-small-controls-execution-20261009-1`. Those controls alone establish no
quantitative regularity or raw-XMD theorem. Subsequent source-bound arithmetic
and setup arguments are described below. Neither experiment changes production
parameters or closes C12.

The subsequent conditional composition note retains the finite sampler's
failure atom and target-dependent success probability. Given an explicit
two-SWU regularity bound, its total-variation calculation includes deficient
targets, draw exhaustion and the exact bias from lifting uniform residues to
512-bit words. The algebraic auxiliary-curve certificate separately verifies
the complete rational-map polynomial identity, reduced degree three, an
explicit order-r point and the unique Hasse-interval multiple on both curves.
The maintained [Pasta certificates](../formal/kagemusha_pasta/README.md) now
verify both source moduli with supplied recursive Lucas certificates before
checking the curve identities, orders and exact SWU cover hypotheses. The
combined checker and all sixteen controls pass, including a Fermat pseudoprime
that must fail the Lucas-order test and a mutated cover polynomial that must
fail the cleared identity. The maintained [regularity argument](../formal/kagemusha_pasta/REGULARITY.md)
applies FFSTV's general character-sum theorem to the two genus-six, totally
ramified covers. It preserves the native finite zero-input branch through an
explicit coupling cost, yielding TV at most `(441/8)*sqrt(r-1)/p + 2/p-1/p²`
for the sum of two uniform-field SWU images. The checker establishes the exact
arithmetic hypotheses; it does not execute the geometric theorem or Lean.
The earlier conditional results
remain in `target/qualification/c12-swu-conditional-composition-1` and
`c12-auxiliary-group-controls-1`; the maintained execution is in
`c12-pasta-cover-durable-publication-1/controls`. Current setup pins and recursive
privacy composition remain outside these local results.

A conditional raw-XMD adapter now intercepts each designated setup input at
its first raw oracle query, including predictable early queries. It reserves
the two inner XMD answers before exposing the first answer, reuses exact
generator-prefix/W/U queries, and refuses occupied inputs without overwriting
them. Eight controls pass, including both source maps, forced collisions,
identity outputs and finite failure paths. Its stopped coupling counts prior
hidden entries and retains the inverse/lift and scalar-sampling errors. This
uses an ideal 512-bit raw oracle; it neither establishes concrete BLAKE2b
security nor retroactively programs the current parameter pins. Source review
and execution are retained in `target/qualification/c12-raw-xmd-setup-model-1`
and `c12-raw-xmd-setup-controls-1`.

A subsequent fresh-target sampler removes the regularity premise from that
setup simulation route. Each attempt independently draws a private scalar t,
a field input u and one of nine complete inverse slots for `tB-F(u)`. Every
ordered pair `(u,v)` has exactly one t and one slot, hence equal probability
`1/(9rp)` per attempt. Success is exactly `p/(9r)`; holes or unequal target
fibers introduce no bias in the accepted pair. The bounded sampler retains
draw exhaustion and its terminal failure atom, whose probability is its exact
TV distance from an always-successful uniform pair. Five exhaustive small-map
and rational controls pass, with independent mathematical review, in
`target/qualification/c12-fresh-target-inverse-1` and
`c12-fresh-target-controls-1`. The proposed `J=4096`, 256-draw inner limits,
512-bit lifts and 131,076 unique setup inputs give an aggregate local error
below `2^-224`, plus the explicit raw-query collision term. This is a local
simulator bound, not a protocol security level. Six subsequent source-map
controls pass for the exact raw-XMD interface and native parameter ordering:
both k0/k2/k3 curve families, twenty shared derivation contexts, early queries,
exact replay, one-normalization Lagrange derivation and native identity refusal.
Sources remain unchanged through execution in
`target/qualification/c12-parameter-setup-seam-execution-1`. The subsequent
raw-setup integration passes nine controls and four complete k6 fixed-RP57
proof cases, using one source-derived parameter family per curve across the
ordinary and contradictory relation examples. All132 setup contexts share
one raw-query table; all parameter/log/IFFT and derived opening identities
are checked. The unchanged complete verifier accepts those cases only under
their private test authority; current release pins and changed f/c/G/instance
values reject. The two examples on each curve use common diagnostic coins,
not independent multi-request randomness. Raw exit, logs and unchanged
source/tool pins are retained in
`target/qualification/c12-raw-setup-proof-execution-1` (result SHA
`16be203eaa8c7d129dc7425ddcb02641a4d9c29bbf56288f34583938dc1db5ac`).
The repository-relative [maintained package](../formal/kagemusha_setup/README.md)
passes all77 inverse, finite-law, raw-query, setup, proof, custody, sequential
request and generic public-table controls. All prior60 methods and assertions
remain, with seventeen generic cases added. One generic fixed-RP57 algorithm
now handles the ordinary/contradictory examples, public-only opening groups and
multiple product/lookup layouts. It preserves the earlier parameter bytes and
four relation-comparison proof goldens. Explicit coins and one bounded owner
retain exact success/failure outcomes without reseeding. Retry identity includes
the exact public preprocessing original as well as descriptor/key/parameters
and instances; commitments alone cannot bind that table when logs are known.
Preflight refusals remain public exceptions.

All fourteen actual k6 proofs fully verify on the two curves, including four
sequential-stream adaptive-input cases and six generic cases. Controls retain
legal-bit rejection exhaustion, provider/draw failures, interrupts, reentrancy,
immutable outcomes, storage and late-metadata failures. Descriptor-derived
simulator budgets are separate from native polynomial randomness. Direct
private-reference entry rejects malformed digest/authority inputs and requires
large-mode opt-in before path creation or hashing supplied large bytes.
Injected failure fixtures are not counted as proofs. After the source-bound
reconstruction port, the maintained custody guard refused the stale keygen and
commit source pins. The reviewed refresh retains both old bodies, adds the new
reconstruction/export/source-fingerprint roles and checks missing/altered role
refusal. All77 current controls and fourteen diagnostic k6 proofs pass again
with zero failures/errors/skips and unchanged source/tool pins in
`target/qualification/setup-current-source-controls-1/subject/result.json`, SHA
`70375b8067d5d453cafb08d0c2926da93691df49895cd3c3215f28f4f9d976aa`.
The prior manifest, refusal and earlier157.94s result remain historical evidence;
this refresh supplies no native16 setup authority or C12 theorem.
The historical rebind changes outer parameters and public commitments only;
embedded recursive constants stay unchanged. No coherent recursive re-key or
k16 experiment is established by these controls.

The bounded producer's final wires must match generated sizes/hashes and exact
output namespace; traced allocations do not impose an instantaneous OS/RSS cap.
The separately retained small k0/k2 CLI reproduces all four earlier parameter
outputs. No full-size family or native proof runs in these controls. Ideal
unused-tail independence does not establish OS entropy, operational privacy,
all-history simulation or current parameter authority. C12 remains open.

Independent source/mathematical review also accepts the conditional known-log
IPA joint law with unchanged deterministic RP57. Fresh W blinds make the public
round path independent of the hidden coefficient vector in K_x. Its final
coefficient is zero on the exact rank-collapse branch and uniform otherwise;
nonzero W determines a unique final blind for that path and coefficient.
The actual folded generator is still computed and its obligation must be
decided. This removes the programmed-outer/fixed-inner transcript mismatch
within a coherent setup-before-pins experiment. It retains the joint masked
prefix premise, explicit prefix failure probabilities, finite entropy and
operational assumptions. It neither bounds those failures for concrete RP57
nor supplies the remaining operation witnesses or recursive wallet simulation.
The argument and independent reviews are retained in
`target/qualification/c12-known-log-outer-composition-1`. Actual Omega
integration, current fixed parameter pins, soundness and C12 remain open.

The source-bound composition review separates two hybrids: replace Omega on
real valid public accumulators, then replace the accumulator pair while applying
the same total public-instance-only known-log simulator. The second step needs
no replacement Omega witness. It still requires joint fold indistinguishability
under that private-log continuation; public-only computational hiding does not
imply this stronger auxiliary-state property. One fixed salted fold has support
at most its salt field, ruling out a statistical fixed-H claim against sixteen
independent mapped challenges. Computational hiding remains an open premise.

The pre-erasure online boundary is before the first fold record is published,
with exact public fields, P/V accumulators, burn result and map roots retained.
The inspected completion tail verifies and records one selected proof, then
clears the active checkpoint selection. Later consuming capsules, signatures,
Payments, credit roots and checkpoints must be generated from that single
record. Already signed or retained objects cannot be patched. A source audit
now enumerates all fourteen operation roles and the six successor native
owners. Their original-input preparation consumes the accepted replacement
proof and its actual opening without requiring the discarded Omega witness.
Load finality is native BLS verification before the credential-bound Advance signature under the selected released-app/uncompromised-OS assumption; it contributes no separate PLONK claims. This construction preserves Receive/Archive's immutable
incoming evidence. Fresh consuming capsules, receipts and downstream map
bindings must be reconstructed normally; stale capsules and checkpoints fail.
This establishes only a conditional input-construction argument. Completeness
of the native-to-circuit verifier boundary, stage contexts, soft modes and the
actual prover, with bounded total failure, remains necessary for an
all-operation forward-closure theorem. An outer coupling must also preserve
needed honest source witnesses; arbitrary auxiliary state containing the
original Omega coins/trace cannot be assumed hidden. Source reviews are retained in
`c12-fixed-rp57-hidden-fold-composition-1` and
`c12-proof-substitution-transition-audit-1`; the fourteen-role argument and its
source pins are in `c12-all-operation-forward-closure-1` under
`target/qualification`. These are source arguments, not executed continuation
tests or C12 qualification.

The common native-to-hard-verifier boundary has a separate conditional source
argument. Given an already constructible coherent A plan and the exact admitted
Omega descriptor, key, parameters, public18 and P/V, full native acceptance
supplies the shared hard predecessor verifier's message cells and arithmetic
witnesses directly from the replacement bytes. The key/lineage digests,
typed instances, RP57 schedule, PLONK identity, multiopen grouping and IPA
equation agree in the inspected sources. The exported suffix and sixteen
ordered challenges match the native opening; the operation must still retain
that generator obligation. This local deterministic implication requires no
discarded Omega witness or new challenge-distribution assumption. It remains
conditional on gadget completeness, actual row/table capacity and byte
provenance in the source owner. It neither proves complete operation/prover
continuation nor re-synthesizes a coherent experimental catalog. The pinned
argument, independent review and unexecuted Omega-specific test matrix are in
`target/qualification/c12-native-omega-hard-predecessor-1`. Existing small
differential tests do not establish this installed k16 integration; C12 remains
open.

For the inspected historical Omega descriptor, a Cauchy-minor argument extends
padding rank to each of the five common fresh product-domain rows. Each group's
last masked slot has Horner coefficient one for every grouping challenge,
including zero. Eight bounded algebra/inventory controls pass with no generated
proof (`c12-omega-pointwise-mask-rank-execution-1`). The unmasked product boundary
is an explicit counterexample to admitting all domain points. No frozen generic
simulator was relaxed, and the challenge-law, denominator and valid-witness
premises remain separate.

The generalized prefix implementation subsequently passes twelve controls and
six k6 proof cases across both curves. It derives fixed/sigma evaluations from
exact public preprocessing, handles public-only groups and multiple permutation
products/lookups, and retains unchanged RP57 and the complete IPA decision.
The ordinary cases reproduce the earlier proof bytes exactly. Rebinding changes
only the outer parameter digest and corresponding key commitments, preserving
relation fields, copy digest, selectors and public table scalars. Mutated
originals, logs, keys and proofs reject. Sources remain unchanged during the
26.91s run in `target/qualification/c12-known-log-generic-omega-execution-1`
(result SHA `e67722cc171910391d74f7a040faa41134cf35db1f53f7e881e87b3586944063`).
Its exact historical Omega adapter has not run at k16. That historical relation
still contains its old inner-verifier constants; changing outer commitments
does not establish a coherently re-keyed recursive catalog or complete C12.

The production wallet trace now identifies those draws. All six ordinary owner
families give the final A a fresh Fp salt; Bootstrap does so in its separate
terminal circuit. Native terminal extraction carries that checked Pallas result
into Omega. Omega preparation obtains a separate fresh Fq salt and folds its
four decided Vesta slots. The shared fallible sampler accepts canonical values
including zero, with no deterministic fallback. Under independent uniform OS
bytes its output is uniform conditioned on success, with 128-attempt exhaustion
below 2^-128. This describes entropy before disclosure, not statistical secrecy
after the concrete public transcript.

The exported transport is original Omega proof followed by P544 and V544; it
does not append either local fold witness or salt. Local checkpoints may retain
salts for restoration, so this is a remote-transport claim, not protection after
local custody compromise. The independently reviewed source trace is retained in
`target/qualification/c12-exported-salt-source-trace-1`. Existing checkpoints and
completed folds are restored before starting new work. Exact retries reuse their
retained proof and salt; interrupted attempts before publication may sample anew
and must count against the experiment's attempt/query budget. Input-dependent identity
aborts require a bound or a matching simulated distribution, beyond the existing
full-length-slot rule. The source-bound decomposition is retained in
`target/qualification/c12-joint-simulation-audit-1`; it closes no C12 gate.

The target-only complete outer-transcript prototype now exercises both curves,
lookup/permutation, multiopen and the complete hiding IPA under a consistent
programmable full-prefix oracle. Eight bounded-model controls pass, including
rejection under the unchanged fixed-Poseidon verifier. This is an executable
model of the proposed simulation, not a proof accepted by the production hash.
The accepted historical full52 Omega descriptor has k16, degree 9, b=5 and four
opening sets at rotations `{0,1,-1}`, `{0,1}`, `{0}`, and `{0,-1}`. Every set
ends with a fresh masked slot of coefficient one; the quotient set ends in R.
There is no public-only set, and the maximum disclosed-rotation count plus x3
is four, meeting `b−1`. The proposed simulator still requires public fixed and
permutation preprocessing polynomials; VK points alone are not their coefficient
encodings. Native acceptance independently decides Omega's opening and both
public accumulators, so a simulated outer transcript cannot make a nondeciding
pair acceptable. The source-pinned model and structural audit are retained in
`target/qualification/c12-outer-simulator-reference-1`. The actual Omega
simulation, adaptive theorem and concrete-sponge bridge remain open.

The historical target-only public-setup model decoded `PIPAPK01` fixed/sigma
evaluation tables, checking their externally selected original digest, descriptor,
VK, extent and scalar canonicality. Batch Lagrange evaluation supplies rotated
public queries and the computed public-only multiopen branch. Eight small-case
controls pass independently on both curves, including multiple permutation
products/lookups and a same-descriptor foreign-VK refusal. Five additional
controls exercise a target-only reference copy whose k16 exception is restricted
to the exact historical Omega descriptor and pinned Pallas parameters; all
semantic and generator checks remain. Repository reference limits are unchanged.
These records are in `target/qualification/c12-actual-omega-model-draft`.
No k16 proof has run under this adapter, and decoding tables is not native
installed-circuit or signed-package admission. The shipping importer now rejects
that retired dense format. Its sole `PIPACPK1` representation reconstructs these
tables from the installed native circuit and checks the source fingerprint,
descriptor, selectors, copy mapping and every VK commitment before admission.
This transport change does not close any of the simulation obligations above.

An independently reviewed local refinement bounds the hiding IPA's exceptional
events in that same unconditioned ideal fresh-answer game. For prime group order
`r`, any point with a fresh independent uniform W blind is identity with
probability `1/r`. The actual Omega shape has 58 such commitments, including
its 32 IPA L/R points, giving `58/r` by a union bound. This argument does not
apply to the nonhiding accumulation protocol's L/R points. The final generator
is the group-valued multilinear polynomial
`G(u) = sum_i g_i product_j u_j^(bit_{k−1−j}(i))`, with nonidentity constant
coefficient `g_0`. Its identity probability is at most `k lambda` by
Schwartz–Zippel; computing discrete logarithms is unnecessary for this argument.
The two hiding-IPA coefficient functionals lose rank only at one complete
nonzero challenge vector for fixed nonzero x3, costing at most `lambda^k`.
Zero challenges and prefix conflicts are separate events. These bounds use a
virtual fresh tape when execution stops early, not conditioning on future
successful challenges.

For one final-round simulation attempt, the solved R is affine in its fresh
uniform scalar blind. Conditional on R being finite, at most Q existing
full-prefix addresses can cause a collision, giving `min(1,Q/(r−1))` for
that draw. A complete adaptive simulator must aggregate its bounded retries;
it may never overwrite an occupied address. Scalar reduction bias, bounded
sampler exhaustion, entropy and operational errors also require their own
aggregate terms. The source argument and three passing small-field controls
are retained in `target/qualification/c12-hiding-ipa-abort-refinement-1`.
This refinement supplies conditional local bounds, not the missing adaptive
simulation or concrete-sponge theorem.

### Conditional honest-fold abort bound

The native non-hiding fold has a source-reviewed polynomial bound that permits
knowledge of every parameter logarithm. Let `n=2^k`, `k=16`, `m` be the ordered
input count and `d=m−1`. Fix inputs and finite generators before this fold's
challenges; require nonzero real source challenges and at least one full-length
source. Actually deciding every input is additionally required for successful
fold verification: syntax alone cannot prevent a final `FoldEquation` failure.

The experiment supplies an independent tape of mapped scalar challenges
`alpha,z,zeta,u_0,…,u_(k−1)`, each with maximum atom `lambda`. For uniform
base-field answers under the actual maps, `lambda=1/p` for Pallas Fp→Fq and
`lambda=2/q` for Vesta Fq→Fp, where `p<q<2p`. Sample the whole virtual tape,
including unused answers after a stop. A separate coupling term must account
for prequeried, conflicting or otherwise non-fresh shared-oracle paths. This
independent-tape premise is not established for concrete fixed RP57.

Write unshifted coefficients as `A_i(alpha)`. Their degree is at most `d`, and
`A_(n−1)` is a nonzero polynomial: each full input contributes its nonzero
challenge product at a distinct alpha power. Initially only the first
coefficient is shifted, to `a_0=−sum_(i>0) A_i z^i`; all other `a_i=A_i`.
Before round `j`, put `N=n/2^j`, `h=N/2`, `D_j=prod_(l<j)u_l`, and
`B_j(z)=prod_(l<j)(1+u_l z^(n/2^(l+1)))`. Source folding gives
`b_i=z^i B_j(z)` and `a_i=sum_(s<2^j) a_(i+sN) M_s(u^-1)`, with distinct
squarefree monomials `M_s` and final monomial `1/D_j`.

Clearing denominators by `D_j`, the L auxiliary inner product has highest
z-degree `n−h−1`, with coefficient `D_j [D_j a_(N−1)]`. The bracket's constant
monomial in earlier u variables is `A_(n−1)`, so it is nonzero. R has highest
z-degree `2n−h−1`, uniquely contributed by the shifted first coefficient; its
cleared coefficient is `−D_j² A_(n−1)`. In any scalar-log analysis basis,
finite U has nonzero log. Thus each full point polynomial `D_j L_j` and
`D_j R_j` has a nonzero zeta coefficient; its MSM term contains no zeta.
Knowing the generator logs does not make either polynomial identically zero.

Conservative total degrees are `d+2j+n−h` for L and `d+2j+2n−h` for R.
For independent coordinates with atom at most `lambda`, a nonzero polynomial
of total degree t vanishes with probability at most `t*lambda`. On `D_j≠0`,
a native point identity implies the corresponding cleared polynomial vanishes.
Charge any zero round challenge separately by `k*lambda`. Final G has a
multiaffine scalar-log polynomial of degree at most k with nonzero constant
g_0, adding `k*lambda`. Complete operations permit intermediate identity
generators; they require no separate rejection event.

Summing before conditioning on success gives the encoding/zero-event bound

`epsilon_fold = min(1, [2kd + 2k² + (3k−2)n + 2] lambda)`.

For k16 this coefficient is `3,015,170+32(m−1)`. No all-coordinate-nonzero
condition or generic relation-finding assumption is needed in this experiment.
Cancellation, storage, allocation, invalid/undecided inputs and entropy-source
failures retain separate treatment. Fresh attempts require bounded aggregation;
exact retained retries do not consume another experiment. The source derivation
and independent review are retained in
`target/qualification/c12-nonhiding-ipa-polynomial-audit-1`. This replaces the
older relation-finding route within the ideal-tape lemma, and establishes no
concrete Poseidon pseudorandomness, recursive composition or C12 qualification.

The maintained [fold controls](../formal/kagemusha_fold/README.md) pass
all 29 tests with unchanged source/tool pins. The ten polynomial cases check
exact leading coefficients and degrees through four rounds, dependent generator
logs, the short-only and missing-shift counterexamples, and the k16 bound's
arithmetic. An exhaustive F17 control checks all14,739 one-round challenge tapes
across three generator choices without conditioning away earlier failures.
Ten transcript cases reproduce the two native prelude KATs using the independent
RP57 reference, check its constants against the native tables, and compare every
primitive input across all19 squeezes with a separate rate-two block scheduler.
They retain canonical scalar/map boundaries, empty/even/odd padding and its
logical-history alias, unsqueezed final c/unabsorbed G, and mutation/refusal
controls. Exact counts are `52+ceil(35m/2)` for Pallas and `52+ceil(19m/2)` for
Vesta; the test traces use syntactic points and do not assert the IPA equation.
Nine further controls use a finite partial-permutation model with explicit
private tapes and both endpoints of every public attempt. Exhaustive counts
cover 83,521 single-edge tapes and 2,187 carried-capacity two-edge tapes, including
legal input/output vertex coalescence. Replay and refused candidates cannot
overwrite earlier edges; malformed public records cannot hide extra endpoints
inside one counted query. The conservative first-hit event yields

`min(1, [2Q(B+H) + B(B-1)/2 + H(H+1)/2] / p)`

for B fresh paths, H private edges and Q public attempts under independent
uniform private salt/capacity tapes conditional on disclosed words. The common
initial capacity must be fixed before or independent of those tapes, and public
endpoints must be independent of hidden salts/capacities given the disclosures.
Negative controls deliberately violate each hidden-state or causal premise.
The model cannot infer these independence assumptions from caller values, and
this finite exercise does not instantiate a random-permutation coupling for the
actual fixed RP57 implementation.

The current captured result is `c12-ideal-fold-maintained-execution-1/result.json`
(SHA `79f581777c5bd2ce71213ccfd679cff4221208f224a0f48d746bbee7e84ecbef`):
29 tests pass with 32 unchanged source/tool pins. These finite algebra,
transcript and ideal-model checks generate no native proof or key and supply
neither a general theorem proof nor the independent-tape premise. C12 remains
open.

### Conditional joint view in the full-prefix model

The independently reviewed ideal-model lemma is retained in
`target/qualification/c12-hidden-fold-ro-lemma-1`. It assumes a public interface
that exposes the final accumulators and public metadata but neither private
salts nor hidden transcript addresses. Every outside algorithm, including a
total adaptive outer simulator, accesses one shared typed full-prefix oracle
through queries/programming requests; it cannot inspect the private table.
That interface is an explicit hypothesis, not a consequence of omitting a salt
field from transport or of valid-instance zero knowledge.

Fix bounds `B_P`, `B_V` on fresh attempts and `Q_P`, `Q_V` on outside queries
in the two fold namespaces, including prior queries. In a virtual experiment
the hidden challenge tapes and public view are independent of the salts until
the first guessed salt or same-curve salt collision. A first-hit coupling and
union bound charge at most

`Q_P B_P/p + Q_V B_V/q + choose(B_P,2)/p + choose(B_V,2)/q`.

Vesta inputs may depend on the complete preceding private Pallas execution;
its fresh independent salt and challenge tape still permit the sequential pair
coupling. The ideal pair uses the actual mapped challenge laws and computes
each G from its challenges and pinned generators, retaining zero/identity
failures. Internal re-verification of the same hidden transcript is memoized,
as are exact retained retries. Fresh unpublished retries count as new attempts.

Add the preceding polynomial fold bounds using deterministic per-attempt
maxima `M_{C,i}` for input counts; no relation-finding term is needed in that
independent-tape experiment.
An observed random sum over one adaptive run is not an unconditional probability
bound. Entropy replacement, sampler exhaustion and operational disclosures need
their stated separate treatment. The result is an unconditional coupling of
bounded views inside the stipulated ideal interface, including aborts. Replacing
that interface by an actual outer proof with only computational zero knowledge
gives a PPT distinguishing bound, not statistical closeness of actual proofs.
Neither the required actual-Omega interface theorem nor the concrete Poseidon
realization follows from this lemma; C12 remains open.

### Post-erasure transcript-ROM interface

A further source-reviewed reduction uses one shared random function per field
on the actual canonical padded block tuples. It respects padding aliases rather
than assigning independent answers to distinct logical API-call histories. A
fresh native `as1` attempt has nineteen strictly extending squeeze addresses;
exact authenticated replay reuses the same addresses and outcomes. The salt
is needed by the private transcript handle, but not by the subsequent fold
arithmetic. This factors the public accumulator/error projection only: it does
not construct the salt-bearing native witness or checkpoint.

After a valid outer-proof and private-state erasure, assume that, apart from the
designated accumulator outputs, public messages, refusals and permitted auxiliary
state are jointly generated from permitted earlier public state and independent
coins. The interface cannot expose the salt, private transcript addresses, fold
body or salt-dependent scheduling information. Additional exposed functions of
private source history require their own coupling. With deterministic attempt/query maxima
`B_C`, `Q_C`, the hidden-address term is
`sum_C [B_C Q_C + B_C(B_C-1)/2] / p_C`. For deciding inputs fixed before each
fresh tape, a full-k16 source slot and input-count maximum `M_C,i`, the reviewed
non-hiding polynomial argument adds at most
`min(1, [3,015,170 + 32(M_C,i-1)] lambda_C)` per potential attempt, where
`lambda_Pallas = 1/|Fp|` and `lambda_Vesta = 2/|Fq|`. The final bound is capped
at one and includes the separate coin and operational terms. It uses
unconditioned virtual tapes and stops before extra private-history-dependent
aborts are exposed; it asserts no uniform law conditioned on prior misses or
successful completion. The polynomial bound remains valid with known setup
logs. A total public-instance-only outer simulator can postprocess this
restricted view without constructing a replacement Omega witness.

The actual `FoldWitness` and prepared Omega circuit still contain the salt.
The unused Omega checkpoint API and source-context hash have been removed;
this does not assert physical erasure of prior private data.
The missing theorem must couple the continuing honest wallet state while
preserving legitimate later source witnesses and exact retained replay. It must
also justify applying the chosen transcript ROM to the recursive relation,
whose native and circuit verifiers currently compute fixed RP57 arithmetic.
Changing only native transcript answers would break those circuit witnesses.
The accepted ROM and concrete Poseidon heuristic are unchanged; this argument
adds no PRF assumption and does not demand an unconditional proof of a fixed
hash's security. It neither establishes the adaptive state/interface coupling
nor closes C12. The complete argument and independent review are retained at
`target/qualification/c12-post-erasure-rom-interface-1` (review SHA
`8777f70d01f2b33ef23aeb9d30b4f5dff18d729bd11f818b2028d2e14e7698c2`).

A target-only public-view adapter now binds exact public18/P/V and request
identity before the existing diagnostic request owner. Its corrected projection
uses the domain/arity framing for the52-word lineage digest and the complete
`kgwvkey1` commitment/metadata digest; transcript representation alone is not
that key digest. Eleven bounded projection, canonical-shape, refusal and failed-
replay controls pass with unchanged captured inputs. The prior erroneous draft
and withdrawn review remain preserved. The adapter has not executed its positive
native16 path or generated any proof/parameter authority. A separate private
Vesta16 reader now preserves the existing exact parameter KAT, decoder and full
generator decision while narrowing its copied resource exception to Eq/k16.
Twelve bounded controls pass on the first run; its inode-replacement test fails
because the reader correctly rejects at an earlier identity check. The unchanged
reader and corrected single test then pass separately. Both results remain;
this is not a fresh13-case run. No native16 originals, large decode, adapter
success or proof is exercised. The reader does not admit chosen experimental
parameters. Its outcome is retained in
`target/qualification/c12-vesta16-private-intake-execution-2` (independent review
SHA `474da5e7f775244329ca564ddb0b04c16fdcb73d2aeeb7c0ab46ad114992e161`).
Coherent actual cases, native state coupling and recursive ROM lifting remain
open. The preceding adapter results and independent review are retained in
`target/qualification/c12-native-public-view-adapter-execution-1`; the independent
outcome receipt is `81b30c854a51b169760fc97bc89bc9bc11c02306619eceedf8d2455e123cbf35`.

The source-reviewed attempt map distinguishes an operation, its selected
checkpoint chain, each fresh final-Omega finish entry, and a completed record.
Charge every finish entry to the deterministic Vesta attempt budget, including
pre-entropy refusal; exact completed-record adoption adds no new attempt. A
restart before publication may draw fresh randomness and must be charged again.
Adoption validates checkpoint envelopes and the completed proof/head/maps but
bypasses restoration of the terminal native checkpoint. It therefore does not
compare checkpoint-derived P with the P carried by the completed Fold. Retained
Bootstrap salt and admitted Q/W originals can nevertheless reconstruct that P.
Replacing only transported P while exposing that complete private view admits
an equality distinguisher; unrestricted private-state coupling is not justified.
This is an interface limitation, not a demonstrated production soundness flaw
or a contradiction of the restricted remote post-erasure game. The eleven
illustrative trace contracts are unexecuted data. The argument, source mapping
and independent review are retained in
`target/qualification/c12-native-attempt-replay-map-1` (review SHA
`6428e293f0d2e98695fb02a79ad498a881008f619eab5edfa5912798b4f4ca2a`).

The canonical stock-OS target protects private proof transcripts from the
transported view; it does not disclose every local checkpoint to the observer.
A further source-scoped continuation reduction fixes the same acknowledged R
and shows that future released-wallet entrypoints do not decode its old Q/A/W
payloads. Collection removes their keys using retained count metadata. The
unacknowledged branch separately preserves its envelope reads and refusal
outcomes. This permits retaining dormant payloads privately without asserting
erasure or indistinguishability of two different R values.

For a fresh successor, a fully accepted R supplies the predecessor proof and
claim inputs. Its exact proof bytes form the next verifier circuit's witness;
the predecessor's Omega relation witness is not required. Legitimate private
application state, signatures, maps and external originals remain necessary.
Substitution must occur before public release and downstream exact-byte
commitments, with consistent Fold/index bindings. The conditional continuation
bound requires the joint live state, selected R and consistent future access to
the residual shared oracle, not merely two indistinguishable accumulator
marginals or a past query log. Coherent chosen setup, native/circuit completeness
and the hidden-fold model bridge remain open. The argument and independent
review are retained in `target/qualification/c12-continuing-private-state-coupling-1`
(review SHA `27228d464586aaa30a5cc10ab86a07bdda80f6e29aeedacf8ef5632c53e9f2e3`).

A further source-reviewed publication kernel permits the logical live state
after acknowledgement to be `Pub(L, R)`: legitimate application witnesses,
maps and earlier history in `L` are fixed before the current designated salts;
the selected accepted transport `R` determines the new Fold, index and manifest
bytes. Complete verifies the lineage and its public roots without requiring the
old Omega witness. The hidden-prefix bound can therefore carry correlated
pre-salt private application state as auxiliary input, subject to fresh
independent tapes and the stated total query/attempt accounting. Designated
private fold evaluations and exact replays belong to their tape handles, not
the independent public-query budget. Exact archive-digest replay is idempotent;
fresh publication still compares the expected old manifest. Those branches,
storage faults, unacknowledged adoption and retained physical checkpoint/marker
bytes require separate custody coupling. This does not permit rewriting an
already published record or its downstream commitments.

Historical no-hit alone does not justify future mixed native-ROM and fixed
circuit computations: even at a fresh disjoint address, an independent uniform
oracle word equals the fixed circuit word with probability only `1/p`. This
refutes that proposed general implication, not the actual protocol, whose two
paths use fixed RP57. The retained historical reverse-erasure argument has ten
suffix calls; the current native Load order is the lean
`A1,W0,A2,Omega` (owner decision 2026-10-17: A1 proves the Load transition
directly, with no own `Q_sigma`, and A2 owns the single own-receipt leaf).

There is a source-backed checkpoint boundary for this current order.
`native_worker/stages.rs` prepares a session from exact authenticated originals.
Within one live owner it may resume that session across fold calls, but only on
the prover instance that prepared it, only while the operation route, sequence,
capsule, predecessor fold and the digests of every authenticated source original
and preparation are unchanged (originals reached through the insert-once
issued-Request, direct-anchor and finality-epoch indexes are covered by those
indexes' insert-once rule), and only while the payloads restored in that session
are a byte-exact prefix of the durable checkpoint list. Every later durable A/W/Q
payload is restored strictly from its durable bytes before a later stage uses
it, in that session or in any new one. A resumed preparation equals the one a
fresh preparation computes from the same originals. Carried objects, including
the σ preparation, are always in restore form: no fresh fold body, prover coin
or producer-side checkpoint is carried between calls. A payment, cancellation,
error, mismatch, discarded publication, completion or loss of eligibility
releases the session.
`native/load/checkpoint.rs::Payload` retains authority/ordinal bindings,
`source_context`, proof and carried accumulator, but no prover coins or local
fold body. Restoration rederives public frames/openings with empty old fold
bodies; later continuation synthesis reads its new fold, not the old A1 fold.
Thus the logical next-stage kernel factors through those originals, payloads,
the full residual oracle and the matched entropy/fault interface. All native
checks, context queries and refusal outcomes remain. Correlated `source_context`
is retained data, not an independent auxiliary input. Changed selected proof or
claim bytes require consistently regenerated payloads, envelopes and hash-chain
bindings before publication; an already selected exact replay is not rewritten.

Fix the completed Q prefix and a deterministic cap `N` on fresh proof
invocations. At invocation `i`'s genuine pre-coin cut `C_i`, assume a total local
joint comparison with error `epsilon_i(C_i)`, retaining the legitimate state
and full residual oracle. Later samplers must be total even on canonically
admitted instances without a source witness. Replace fresh invocations in
reverse temporal order: the earlier prefix is still genuine and the later
suffix is the same total kernel in both games. Consequently
`Delta_proof <= min(1, epsilon_prior/setup +
sum_i E_real[1_reached_i * epsilon_i(C_i)])`.
Expectations use the unconditioned genuine execution, not eventual completion.
A failed call preserves its error and resulting custody state; later retries
remain possible and use new invocation slots. Exact durable replay adds no
sampling term, but retains verification, oracle and storage effects. For a
single no-retry pass the reverse order is
`Omega,A4,W2,A3,W1,A2,W0,A1`. Current profile errors remain symbolic: historical
ten-role mask counts and coefficients do not transfer.

Only at the all-erased endpoint may the designated fold tapes change. Under
the preceding restricted hidden-fold interface, the current no-retry pass has
Pallas input counts `(2,3,3,3)` and Vesta counts `(4,4,4,4)`, each with a full-k16
slot. Writing `p=|Fp|`, `q=|Fq|` and `b_C(m)` for the preceding generic fold
exception bound, its hidden term is at most
`min(1, (4*Q_P+6)/p + (4*Q_V+6)/q + b_P(2)+3*b_P(3)+4*b_V(4)
+ epsilon_coins + epsilon_operations)`.
Retries require the general deterministic attempt/input-count bounds, not
observed successful totals. Let `H` denote that hidden-term bound. Composing
the same total publication/adoption kernel gives
`Delta_total <= min(1, Delta_proof + H + epsilon_unmatched)`, where
`epsilon_unmatched` covers only custody/interface discrepancies not already
charged in the local or hidden terms. All full decisions and failures stay in
that kernel; this is a sufficient-condition reduction, not an established
current sampler or source qualification.

These reductions fix the same legitimate private state. For two histories
with different such states, their distinguishing bound still includes the
distance between the two erased endpoints, in addition to both reduction
errors. Equal external state alone does not remove that middle term. Coherent
setup/current source admission, actual entropy and operational laws, and the
shared normalized-oracle realization across future native/circuit fixed-RP57
work remain separate. No new primitive assumption, execution or C12
qualification follows.
The historical source/math note and independent reviews are retained at
`target/qualification/c12-publication-kernel-rom-localization-1` (argument SHA
`c386a561bac75fe809fe3dd9fc1fe0977b92a2dec55567be5c65415c6a2427a6`,
independent review SHA
`85335ca5f993552edaed63180c5ebe74da46a59b287b90ce6dd73f0f3b720466`).
The current-source memo preimage, source join and exact change are retained in
`target/qualification/c12-current-load-checkpoint-composition-update-1`.
No new execution or C12 qualification follows from this local result.

The historical fresh Load suffix below has five P and five V folds, each with a full-k16 slot. The current direct-BLS Load removes the finality stage; its four-A/three-W catalog must be re-keyed and requalified under [NF1–NF6](kagemusha_native_finality_goals.md).
Its source-reviewed local laws include the exact ideal advice-commitment and
identity-stop distribution, the explicit 512-bit modular-reduction bias, lookup
membership preservation under compression, and the generic admitted-descriptor
Cauchy rank bound. With an explicit conditional challenge atom bound `lambda`,
the conservative zero-denominator term is `(n*m + 2*u*L)*lambda`, capped at one,
for `m` equality columns and `L` lookups. Zero inversion is a ghost bad event,
not necessarily a native abort. The historical Load table predicates below supply
the mask-boundary checks for the selected A/W artifacts, conditional on valid
pre-mask advice and full copy-permutation admission. Current-source admission
and the complete joint composition are still required. Total sampler, challenge
freshness, private context/custody and operational laws, coherent setup and
all-operation completeness remain open. The argument and independent review
are retained at `target/qualification/c12-fresh-load-reverse-erasure-1`
(argument SHA `dd7746a5489bd056f506a5f24ef057791ee89fc702796392a20ff3f51f033ae5`,
review SHA `3ae32d31d5ac32bd94941380b5cec71a04f18dcb546eb409bed2c82acaa83715`).
This is source/math evidence, with no new runtime qualification.

The selected historical Load A1 (original24 of the complete52 inventory) passes
the exact-table audit at `target/qualification/c12-load-a1-mask-boundary-draft-1`.
Its Eq/k16 descriptor uses degree8, seven quotient pieces, 51 fixed columns,
16 equality columns and advice rotations -1,0,1,2. Those rotations require
usable boundary rows0,65527,65528 and tail rows65529..65535. All1,210 gate
expression checks and 42 lookup expression checks have no tail-advice dependence;
tail gates are identically zero, every fixed tail entry is zero and all16 sigma
tails self-map. Fourteen bounded-reader and symbolic controls pass. The single
audit hashes exactly140,511,414 PK bytes and then reads2,230 framing bytes plus
19,904 selected scalar bytes through the same held file descriptor. File and
parent identities and all source/tool pins remain unchanged. The retained
result SHA is `31b3a98a77995446c97a4a12adc55ebd51769cef92f43135d39a556b24ce7b14`.
Under separate valid-witness, full-copy-permutation and nonzero-denominator
premises, these predicates preserve the relation under the prescribed masks;
the numerator degree is at most524,280 and its domain-divisible quotient degree
at most458,744, below seven times65,536. The audit does not revalidate the whole
copy mapping or original source/VK commitments. Transfer to current Load requires
exact artifact equality and separate current-source admission. No proof, keygen,
FFT or MSM ran, and its diagnostic elapsed time is not a performance gate.
The complete source-bound sampler and fixed-RP57 composition obligations remain open.

The eight remaining selected Load keys also pass their exact-table predicates
(`target/qualification/c12-load-remaining-mask-boundary-preparation-1`). These
are A2–A5 at original indices 25–28 and W0–W3 at 29–32, each with a distinct VK/PK.
Eight new selection, layout, capacity and framing controls pass; the earlier
fourteen core controls were not rerun. Each A has the A1 descriptor profile and
passes 1,210 gate and 42 lookup expression checks against its own tables. Each W
uses Ep/k16, degree 6, five quotient pieces, b=5, 36 fixed and 20 equality columns,
and 11 lookups. Its advice rotations -1,0,1,6 and fixed rotations 0,6 require
seven usable boundary rows, 13 gate rows and 19 fixed rows. Each W passes 1,547
gate and 154 lookup expression checks. All selected fixed tails are zero and
sigma tails self-map. The W quotient degree bound is 327,674, below five times
65,536, under the same valid-relation and divisibility premises.

The one finite eight-key audit hashes 1,032,765,488 bytes, checks 966,704 framing
bytes and reads 182,528 sparse scalar bytes. All held file/parent identities,
source pins and Python/supervisor identities remain unchanged; both numeric
child exits are zero. In total 11,028 gate and 784 lookup checks pass, within the
unchanged per-key symbolic limits. The result SHA is
`3d2a5f9f8dce2549e4e50c16a46d1449ca5b801582074cd62016e152f1a64a5e`;
the independent outcome review SHA is
`ed222ea8d47389bce81486e41953439c242d5f9321a6798b08b5fbcbdc1b8ba2`.
Together with the earlier A1 audit and the exact matching previously audited
Omega D/V/PK triple, this covers the selected historical fresh-Load suffix's
mask-table predicates. It does not establish whole-copy bijectivity, a valid
original witness, current source/VK admission, or a local joint law by itself.
No parameters, proofs, keygens, FFTs or MSMs ran. The 5.515-second diagnostic
audit duration is not a proving or payment latency measurement.

A conditional A1 local law now couples the total response and the complete
residual normalized-prefix oracle jointly with the legitimate pre-coin state.
Both prover algorithms and their verifier are interpreted through that same
mathematical squeeze oracle. Assume valid pre-mask advice, full source/copy
admission, the exact audited tables, coherent known-log setup, independent new
coins and atomic publication. With `r=|Fp|`, `p=|Fq|` and at most `T` prior
addresses in this field, the ideal-byte experiment has the conservative bound
`min(1, epsilon_operational + 131411*delta_r + 173*q_cap +
2*T/(r-1) + 6815552/p)`, where `delta_r=t*(r-t)/(r*2^512)`,
`t=2^512 mod r`, and `q_cap=(1-r/2^255)^128`. Whole-group identity and IPA
rank-collapse stops are coupled directly; no success conditioning removes their
mass. Freshness uses both C0 coordinates at words75/76 of every squeeze prefix.
The first actual primitive sponge input contains only x(C0), so its separate
two-to-one first-input estimate does not establish a full primitive-table or
concrete-RP57 coupling. Operational costs may be large; OS/ChaCha replacement
is a separate computational hybrid. The six masked groups imply173 simulator
scalar samples and7,744 proof bytes by source arithmetic, with no Eq16 simulator
proof executed. The dedicated outer Eq16 constructor is integrated below, but
its actual large construction and coherent recursive authority remain untested.
The shared future native/circuit interface remains open. The argument and independent review are retained in
`target/qualification/c12-load-a1-joint-sampler-law-1` (argument SHA
`4f8d4991f6aeb98dadbbcdea9650c86fe30ad8776f66e4970620fa37def9c63d`,
review SHA `afb3ce8de2fa75adbfee4775e09690c7d65cd414582882efd303390e33da5d70`).

The same conditional normalized-oracle law now covers A2–A5 and W0–W3, with
each role's separately audited tables. W has seven opening groups, of which
six are masked. The seventh contains only fixed columns 10/11 at rotations 0/6;
its value is exactly `x1*F10(x3)+F11(x3)`, including its public correlations.
It must not be replaced by a uniform sample. Each individual W slot has enough
independent pads for its distinct initial queries and the residual evaluation;
the excluded global rotations are -6,-1,0,1,6. For W, the base-field Fp challenge
maps injectively into scalar Fq, so its maximum fresh atom is `1/|Fp|`.
Its denominator/exception count is `K=2883460`, giving the conditional bound
`min(1, epsilon_op,W + 131565*delta_|Fq| + 247*q_|Fq| +
2*T_W/(|Fq|-1) + 5766920/|Fp|)` with the same definitions and premises as above.
Whole-group identity and rank-collapse failures remain in the coupled response.

W uses 247 simulator samples and at most 31,616 provider calls. Its 108 points
and 200 scalars imply 9,856 bytes by arithmetic, not an executed proof. The 19
direct scalars in three columns produce a 48-word prelude and place C0 at 48/49;
rate alignment alone still supplies no complete primitive-table or concrete-RP57
bridge. Five A and four W local bounds can telescope through the reviewed
reverse order with the Omega local term below and under the complete
continuation/setup/source premises. Their maximum 237,184 provider calls fit the
default aggregate draw budget; request policy must also admit the distinct
requests explicitly.
The argument and independent review are retained in
`target/qualification/c12-load-aw-joint-sampler-laws-1` (argument SHA
`e05e3b03b2f645ad75dde1847ae8fc4e838eddb65466080120dcce1190e8bdda`,
review SHA `598236461c47a90871f57ccbc538f3ff0f704ef954443c5bfeae0e5971926075`).
This does not erase the Q prefix, construct the coherent recursive setup,
quantify actual operational/entropy costs, or close C12.

The independently reviewed Omega local law completes the ten conditional
proof-erasure terms for the selected historical fresh-Load suffix. Its four
opening groups each retain a coefficient-one residual mask; no group is
public-only. The direct columns have lengths [1,2,16], placing C0 at words
48/49. Its Fp-to-Fq challenge map is injective, giving maximum atom `1/|Fp|`.
The conservative denominator and algebra exception count is `K=655354`.
With the same ideal-byte and normalized-oracle definitions, the bound is
`min(1, epsilon_op,Omega + 131218*delta_|Fq| + 96*q_|Fq| +
2*T_Omega/(|Fq|-1) + 1310708/|Fp|)`.

The 131,218 native draws include all 32 IPA blinds. There are 58 fresh point
samples, 37 sampled evaluations and at most one final coefficient sample;
59 serialized points and 57 scalars imply 3,712 bytes by arithmetic only.
The local result fixes the transported P/V claims. Following the outer proof
with the same total native opening/Pallas/Vesta admission function preserves
distance only under the stated common-cut interface. The generic Python
simulator does not itself perform all three native transport decisions.

Before expectation over legitimate cuts and the outer cap at one, the ten-role
sum is `657055*delta_|Fp| + 657478*delta_|Fq| + 865*q_|Fp| +
1084*q_|Fq| + 34077760/|Fq| + 24378388/|Fp|`, plus
`2*sum_A(T_A)/(|Fp|-1) + 2*(sum_W(T_W)+T_Omega)/(|Fq|-1)` and the ten
operational terms. Add setup/prior distance and the separate source, actual
entropy and continuation/interface errors. Identity, rank-collapse and failed
attempts remain in the total response and residual oracle; none is conditioned
away. At most 249,472 provider calls fit the aggregate budget, but the default
eight-request policy must be explicitly raised to at least ten. The three-Q
prefix, coherent recursive setup, fixed-RP57/native/circuit interface and joint
fold/publication reduction remain open. The source/math packet is retained at
`target/qualification/c12-omega-joint-sampler-law-1` (argument SHA
`91b6991857ab1b7eed8626f4cb88403fbb5b176d972e8c787d1c6b0c7e381299`,
independent review SHA
`a23b51bc7e10734c2b829446ae17defa8b3e1d99f2ec161db264256da60c3735`).

For the exact no-incoming lean Load route, the one Q circuit witness, the own
Advance receipt signature leaf, has a deterministic inverse from its stage-public
column and admitted catalog. There is no `Q_sigma`: the route consumes no sigma
byte tape, and its Vesta part is the pinned trivial filler. The leaf exports every
signature-witness field through canonical digest and 128/128-bit integer limbs;
the unchanged native prover re-derives its hard low-S verdict. The credential and
Enrollment certificate are carried by continuity from the predecessor lineage, so
no second signature leaf exists (owner decision 2026-10-17). The maintained private inverse controls reject
malformed tape padding, lengths, fields and parts; reconstruction alone supplies
no admission.

At the native proof-entry cut, replace each Q call with that same native
algorithm on the recovered typed argument. For identical provider responses,
configuration and matched external events, the entire response, partial
transcript, residual oracle and provider trace are pointwise identical. Thus
each conditional local distance is zero without an ideal-entropy or random-
oracle substitution for these identical calls. The `kgwqnon1` query derives Q's
nonce from the authenticated signed public capsule commitment d, while private h
still selects and authenticates the original checkpoints. The query occurs before
preparation and remains in the common prior state, even though Load does not use
its result in a Q-local fold. This nonce is deterministic public data, not fresh
private entropy; complete ordered inputs are still absorbed before challenges. Additional decoding
or native validation work must occur before the cut or be charged explicitly;
silently repeating preparation afterward would invalidate this equality.

The Q0 comparison adds no local terms to the suffix bounds under the
same continuation/publication premises (four current lean Load suffix calls; ten
in the historical five-A/four-W argument). This lean-route reduction removes calls
from the previously argued eight-call order and introduces no new call kind; it
still requires the outside C12 review of its exact diff before qualification. Lean
lineage milestone 2 (owner decision 2026-10-17) extends the same reduction to every
remaining non-Refresh route. Bootstrap's only Q is its 2V/1F signature leaf and its A
is one unsplit terminal stage, so its order is Q, A, Ω with no W. Receive, Receive
(renewed) and ArchiveSent (i) keep a `Q_sigma` whose only slot is the incoming sigma
(soft, with its hard digest/selector/chunk binding and mode): the own-sigma slot, its
byte tape and its call disappear, and the stage-public inverse of the incoming slot is
the one the paired program already had. Their own receipt becomes hard slot 0 of the
incoming signature leaf, whose other slots stay soft; the native inverse of a mixed
hard/soft leaf is the existing per-slot one. ArchiveSent (ii) has no `Q_sigma`.
Receive's own step is proved by `ReceiveTransition`: A lays out σ_recv's relation on its
lane from the prepared step witness and equates each of the 26 statement inputs to its
own statement cell, which is exactly the statement whose digest σ_recv certifies; the
relation's hidden state enters A only through the predecessor and successor
commitments, which A binds to its authenticated openings. These changes remove calls
and introduce no new call kind; the outside C12 review must cover this diff (lean-1 and
lean-2 together) before qualification. They preserve exact checkpoint replay
and require later folds to use the selected Q proofs' actual outer openings.
Their stage-public inputs are not the final external wallet/payment view:
those inputs still include the original sigma and signatures. Their joint
distribution, hidden source hashing, coherent recursive setup and the different
A/W/Omega algorithms' shared RP57 interface remain obligations. The private
native inverse and proof-parity controls are integrated in
`q_sigma/native/public_witness_tests.rs` and
`q_signature/native/public_witness_tests.rs`. Eleven ordinary controls and two
explicitly scheduled genuine tests preserve canonical fields/tapes, exact native
policy and pre-cut validation, then compare the unchanged native prover under
matched deterministic recovery contexts and actual 32-byte provider responses.
The [recorded component capture](kagemusha_evidence_gate.md#8-recorded-results)
reports all eleven controls and both genuine tests passing, covering seven
proofs, four key generations and three strict original imports. The separate
`output/compact-wallet-proof-20261013/results.json` capture also records the
signature parity test passing with four proofs. These historical captures
retain their own source identities; they do not establish the current complete
catalog, different-history privacy or OS entropy. The earlier unapplied draft
at `target/qualification/c12-load-q-public-inverse-draft-1` is historical
preparation, not the state of the maintained implementation.
The source argument and independent review are retained at
`target/qualification/c12-load-q-public-reconstruction-1` (argument SHA
`6dca35a226079f9d317b40391d939871fcbc559867d01bcb844e2fcb894105ab`,
review SHA `2b05d7511881325eb5d96558d32bcfe0b06d96820314cd4989b562a714a9d2e5`).

A source-reviewed constructor draft for the exact historical outer Eq16 A1
relation passes 14 small custody, parser, ordering and failure/replay controls
(`target/qualification/c12-load-a1-chosen-eq-constructor-draft-2`, result SHA
`762524b6d42b193d1e1e811bb150fb964545181fa12e57b5510cc73b813ca010`,
independent outcome review SHA
`33188a4e9af1d3004f47f8d2d363860f26ebfc16cd5e548ca44005394f715e36`).
It keeps one internally derived setup owner, preserves original read observations,
uses one allocation tracer, and publishes only after retained-output and source
checks. Its 2 GiB checkpointed Python allocation ceiling is not an RSS or M3
guarantee. These controls use tiny DATA or sentinels; no real A1/parameter
construction, group arithmetic, transform or proof ran in those controls.
The constructor is now integrated in `formal/kagemusha_setup` with package
source custody, a DATA-only descriptor fixture and a caller-selected originals
directory; the D/V/PK profile and hashes remain fixed in code. The maintained
14 constructor and two custody controls pass once with unchanged execution
sources/tools and child exit zero (`target/qualification/c12-load-a1-constructor-maintained-controls-1`,
result SHA `79b9a6b247d0a67a80b447c47c63f3e0783fc6869789d0de44f23951b4265431`).
All 83 existing selectors remain and the 14 constructor selectors bring that
inventory to 97. The subsequent diagnostic Owner repair adds three request-
shape controls, bringing the full suite to 100 with the same 14 small proofs.
It names separate 256-column and 256-value resource caps, admitting Q0's five
columns while preserving exact descriptor checking, failure replay and early
over-budget refusal. The two new positive-boundary regression methods fail
against the old four-column guard; all nine request-shape methods pass against
the installed repair without proof or entropy execution
(`target/qualification/formal-owner-column-cap-execution-1`, result SHA
`0e682db8b80bc0eef61338071b3ef03715a2b393736411e5a6ffa2aa5b7bd623`,
independent review SHA
`a59de5a32838dc35af919bdbdebfa7ccbc021529dee98b9fc39c7cc8ffc93582`).
These are finite diagnostic bounds; the canonical descriptor limit remains
65,535 columns. The preceding maintained regression passes all 100 controls and
14 small k6 reference proofs with no failures, errors or skips (142.45 s). Its
source/interpreter pins remain unchanged (`target/qualification/setup-current-source-controls-2`,
result SHA `3a1d68c6ea2f92aabce9a109ab3812c58171e6da27bc2e74bffbdacfb6845efd`).
Before execution, an exact old/current source review updated the stale commitment
pin for the bounded-prefix helper and test-only observation changes; existing
non-probe bodies remain byte-identical. The initial source refusal is retained.
The maintained zero-grouping successor now passes 101 controls with no failures,
errors or skips (148.60 s), retaining all fourteen ordinary fixed-RP57 k6 proofs
and counting two explicitly adapted x1=0 proofs separately. It exercises the
actual simulator on both curves for public-last, masked-last and R-last groups;
the ordinary verifier rejects the adapted proofs after the adapter is removed.
Source pins remain unchanged (`target/qualification/c12-x1-zero-maintained-validation-1/result.json`,
SHA `aa3d3efb56768593b08080257b52180a76668e48adc67ab188749268f90a3e6c`).
These are diagnostic regression results, not operational equivalence,
current setup authority or C12. Actual large A1 construction remains unexecuted,
and unchanged inner recursive constants cannot supply coherent recursive authority.

### Conditional fresh Load head

The exact current head layout also admits a narrower, independently reviewed
local lemma under an **ordinary ideal-permutation interface**. This is not an
adopted release assumption about fixed RP57. The29 core words place the nonce
last; the six rest words and padding give the final two permutation edges

`X = (a, b + N, c + R), U = π(X), Z = U + (0, 1, 0), V = π(Z), head = V₁`.

For a fresh legal Load, all prefix values are independent of the new sampler
coins. The analysis conditions on the actual prior private/public table plus
five rest and fifteen head-prefix positions, with at most K edges. For an
ordinary nonzero predecessor nonce, the sampler accepts s=p−2 field values in
at most128 independent256-bit fills. Each fill clears only bit255 and then rejects
zero, the predecessor and noncanonical Fp values without modular reduction. Every
accepted scalar has exactly two raw preimages, so the conditional nonce remains
uniform over that same set. Its exhaustion branch is
`f = (1 − s/2²⁵⁵)¹²⁸ < 2⁻¹²⁸`, since the pinned modulus satisfies p−2 > 2²⁵⁴.
For Bootstrap's zero predecessor, s=p−1 and the same strict bound applies, but
its different exclusion set still requires its own branch comparison. Entropy
errors return immediately; the128-fill cap includes all rejected values. This
sampler improvement does not establish any OS entropy or full-view privacy claim.

With at most Q subsequent outside primitive operations, a conservative stopped
first-hit bound is

`e = min(1, K/s + (3K+2)/p³ + 2Q(1/s + 2/p³ + 1/p²))`.

This pays for both private edges and outside hits on their endpoints. The
`p⁻²` term is necessary because V₁ is disclosed. Private prefix evaluation only
reads the sampled permutation under the ordinary forward/inverse interface;
it exposes no occupancy, programming-refusal, cache-hit or table-size bit.
Thus unequal hidden balances and prefixes need not be equated. Retain d_B for
the actual prior joint-view distance, including nonce-independent public roots
and the ordinary residual oracle. A common continuation gives the conditional
bound `min(1, d_B + (1−f)(e₀+e₁) + ε_rng,0 + ε_rng,1 + ε_interface)`.
Provider/entropy failures, visible resource effects and the zero-head rejection
must remain explicit. Exact selected replay reuses its original head and nonce;
it is not another fresh sample.

The stronger interface with observable occupied-input programming refusals can
probe a guessed unsalted prefix before this late nonce. The ordinary lemma
therefore cannot be transferred to an arbitrary programmable simulator. This
interface counterexample is not an observed attack on fixed Poseidon. The
capsule commitment, public-map joint law, proof simulation and future
source-dependent wallet operations remain separate obligations. In particular,
the capsule commitment requires the independent-opening law below; its native
construction and failures cannot simply be placed in d_B as nonce-independent
data. No C12 or fixed-RP57 theorem follows from this local result. Exact arguments and root
source/mathematical review are retained in
`target/qualification/c12-fresh-head-ordinary-oracle-lemma-1` and
`c12-fresh-head-root-review-1` (review SHA
`cf56180dbeb4e9ffa1f6007737745ce51499f9a2c85be3250d99eced3200b9e2`).

### Selected recovery capsule commitment

The sole first-release custody design uses the exact frozen canonical body B,
`b = H("capsule-body", B)`, two injective LE128 digest limbs m0,m1 in Fp, and an
independent canonical opening r in Fp. Its Vesta point is
`C = m0 g[0] + m1 g[1] + r w`; the public receipt identifier is
`d = P_bytes(kgwcapc1, enc(C))`. The private canonical wrapper W=(B,r) is selected
and authenticated by `H("capsule", W)`. C and d are recomputed from validated W,
not trusted as serialized caches. Opening a commitment needs B and r. Custody
identities, the body hash and r are excluded from the public receipt.

For every fixed B and pre-opening auxiliary state, nonidentity w maps uniform
r bijectively onto the prime-order Vesta group. Thus the distribution of d is
independent of B for any fixed deterministic identifier hash, without a SHA
random-oracle or hiding premise. Applying the same explicit zero-d refusal to
that distribution preserves this local law. Identity C is accepted. Neither
d's uniformity nor a 1/p refusal probability follows. Under independent uniform
256-bit entropy fills, clear only bit 255 before rejecting noncanonical Fp
scalars, for at most 128 attempts. Every 255-bit candidate has exactly two raw
preimages, so accepted r is exactly uniform, including zero. Since
`2^254 < p < 2^255`, exhaustion is `(1 - p/2^255)^128 < 2^-128`. Real entropy errors and deviation from this ideal law
remain explicit rather than being conditioned away.

Two different accepted body/opening pairs sharing one signed d yield either a
Poseidon collision on distinct canonical C encodings, a SHA collision between
different B, or a nontrivial relation among g[0], g[1], w. The last case uses the
existing admitted IPA vector-commitment premise, not point validity or discrete
log hardness alone. The generator messages under `Halo2-Parameters` are
`[0,0,0,0,0]`, `[0,1,0,0,0]` and `[1]`. Generator derivation, installed tuple
identity and shared-setup assumptions remain part of qualification. No new
caller-supplied points or private-input variable-time kernel are permitted.

The independent-opening law holds jointly with the entire state fixed before r,
including the actual statement/head, public roots, σ and Ω(pred), even when they
are correlated with the hidden body. It adds no body-hiding premise to that
pre-opening tuple. It does not hide separately disclosed fields or establish
the joint law of commitments to hidden balances and maps. Receipt signing extends
this law only under the same admitted key/provider-state/randomness/error
interface and a common or explicitly charged release kernel. Public message
syntax alone does not couple resource or custody failures.

Keep pre-r freeze/cap failures and post-r private h-zero/custody refusals in the
total experiment. For an efficiently generated frozen B, two independent uniform
openings produce distinct canonical W frames hashing to zero with probability
at least `(E[Pr_r[h(B,r)=0]])² − 1/p`. Thus a collision-resistance bound ε_CR at
that reduction's actual budget gives an unconditional h-zero bound
`sqrt(ε_CR + 1/p)`. This includes the square-root security loss; neither a
`2^-256` zero probability nor 128-bit quantitative security follows by assertion.
It does not charge other provider failures, and finite-sampler/entropy deviations
remain explicit. The source-bound local argument is retained in
`target/qualification/c12-capsule-signed-publication-joint-law-1/argument.md`;
its review SHA is `63df45183f0c9e4e6fdcc240ec7eb9c1e14dca657a9bb3008fb56fa065eb805f`.
That memo precedes the public-d Q nonce amendment and does not qualify its runtime.

Future Q folding derives its deterministic nonce from authenticated public d;
h continues to authenticate private checkpoint/source custody. This removes one
private-h-dependent query without making Q's nonce fresh or hiding its source
witnesses. The final joint proof still needs the head/σ/Ω/public-root law, coherent
setup, the residual-oracle continuation and related private W/r/h successor
states, including total failures and exact replay. After durable W or selection,
replay uses the identical wrapper and recorded output; missing openings invoke
reconciliation or custody loss. Verification never draws a replacement opening.
C12 remains open pending that argument and validation of the current
implementation, keys, SDK vectors and durable retry joins.

## Executable checks and remaining review

Own-state policy fixes the independently selected provider and root key, while
scheme identity comes from constrained state cells. Bootstrap binds those same
scheme cells across state, statement, public lineage, signed certificate and
credential. Other own-object owners use the authenticated predecessor's state
scope. Native admission must still bind the carried scheme/relation to the
installed inventory. Compiling the derived SchemeID into these source policies
would instead make A keys depend cyclically on their finished Omega catalog.

The corrected Bootstrap regression constructs two complete genuine
sigma/Q/A1/W/A2 chains with different schemes and requires identical six source
VK byte strings and known/unknown layouts. A third chain retains actual proofs
and valid original signatures but rejects its foreign-scheme certificate at A2.
It passes 1/1 in 289.24 s (`target/qualification/bootstrap-carried-scheme`).
This establishes the tested source independence and authorization rejection,
not a complete acyclic artifact inventory or full operation soundness review.

The native PIPA-R tests pin both-curve transcript KATs, type boundaries,
profile rejection and proof-byte invariance across worker counts. Native
fold tests check genuine proof claims, nondeciding claims, omitted/reordered
inputs, source padding, trivial constants and mutation cases. Codec tests
exercise malformed points/scalars, modulus aliases, challenge-map endpoints
and every assigned cell. Obligation tests enumerate all four-slot mode
combinations on both fields and reject dropped, duplicated, gated or
reshaped fixed obligations.

The full operation relations must add the foreign-key, dropped-accumulator,
invalid-burn and middle-proof mutations, and the depth-16
cycle test. The carry argument is separately recorded in
[the reviewed M3b memo](kagemusha_ff_carry_v1.md). The final soundness review
must bind the actual descriptor/VK hashes and generated proof behavior.

## Receive raw ownership and sigma projection

The Receive context commits the complete Q public inputs, all eleven original
object triples, all four predicate claims, all incoming modes and the original
Omega verifier opening. `ReceiveStagePlan` requires every named operation task
exactly once. Each continuation verifies its exact preceding W key and the same
context; a component result is not an admission certificate for a stage key.

The separately scheduled hard ProofDigest owner derives the combined consuming
hash from both original active tapes and their LE32 lengths. It binds that result
to slot 4 and both original raw lengths/tape commitments to slots 4 and 5. This
owner has no soft result bit and is mandatory exactly once (task code 23). Objects
uses only the same context's claimed combined digest; it cannot admit a different
preimage because the hard producer and every W continuation authenticate it.

The Objects owner assigns the original active incoming sigma tape, including
zero-length, short and over-descriptor inputs within its fixed capacity. Its
safe Q view is `LE32(original length)` followed by the descriptor-sized original
prefix, padded with zero only when the original is short. The remaining active
tail remains in the exact step and combined consuming digests. The Objects
owner hard-binds the incoming statement digest, selected key and every Q-view
chunk to Q0. It also hard-binds the original tape's length, content address and
raw commitment to context slot 5. These equalities are unconditional: a false
Objects predicate does not release the sigma source or permit different Q
inputs.

The Proofs owner therefore consumes the same incoming sigma Q projection without
allocating a second maximum-capacity raw sigma tape. `from_active_omega` requires
original active provenance for Omega and an incoming sigma projection;
`bind_context` equates the projection's statement, selector and every chunk to
the identical committed Q0. Q0 is hard-verified at its unique scheduled owner.
The sigma proof validity bit and mode still come from `bind_sigma`; neither is
provided by the caller. This removes duplicate raw hashing without changing
which original sigma bytes enter the soft verdict or consuming digest. A fixed
schedule missing Objects, Q0 verification, a W/context equality or terminal
mode accounting does not satisfy this argument and must not be admitted.

Omega keeps its original active tape in the Proofs owner. That owner authenticates
its exact raw length and byte commitment, constrains its total public/point
projections, checks the carried Omega key, derives the recursive verifier verdict
and binds every exported opening cell. ProofDigest independently derives the
combined Omega-plus-sigma digest from both original active tapes. A safe decoder dummy is
not permission to omit an original deferred obligation; terminal mode selection
still follows the branch uniqueness argument above.

The transport verifier takes the trusted successor Omega-key digest explicitly.
Its verifier-key witness is hard-bound to that digest, while a foreign incoming
identity or proof contributes a false soft verdict. The digest is absent from
`public320`; the production active decoder already supplies the trusted successor
digest as lineage field 17. Removing the redundant owner equality therefore
hardens the shared API boundary without identifying a current-wire admission bug.
Substituting the verifier key itself remains a hard failure.
An actual k16 PIPA-R component regression generates proofs under two distinct
keys with the same descriptor. The foreign proof satisfies the transport
constraints only with a false verdict, both when field 17 uses the trusted key
and when it proposes the foreign identity. Substituting the verifier-key witness
fails for either verdict. The source relation binds public columns only; this
tests the cryptographic boundary, not admission of a complete Omega program.

Component tests construct a sigma projection with neither an active carrier nor
a step digest and require the complete fixed owners to reject all proposed raw
object triples, Q digest/index/chunk substitutions and original-length changes.
They additionally reject raw sigma and Q substitutions when Objects is false.
The recursive fixture separately distinguishes its authenticated receiver head
from the incoming payer head; an accepted-credit fixture uses actual payer Load
and receiver Bootstrap proofs rebuilt under one common compact Omega key.
TODO: complete that maximum-capacity owner chain, its corrected-claim branches
and final catalog admission before treating these component checks as a Receive
qualification result.

The pre-split canonical-capacity Receive run produced real A1–A3 proofs, including
all retained-object/result/context mutation checks. Objects A4 then failed the
unchanged k16 capacity gate: its diagnostic layout used 73,112 sponge rows,
62,148 main rows and 44,118 range rows. The diagnostic k18 layout was rejected,
not accepted as qualification. The new fixed ProofDigest stage separates the
combined hash from semantic decoding; every stage still checks known/unknown
layout equality and must produce and decide its actual k16 proof. The first nine-stage attempt produced genuine A1–A5 proofs with maxima of
29,600, 60,976, 55,056, 64,195 and 64,787 rows respectively, including the
maximum-capacity digest and Objects owners. A6 then failed at 67,044 sponge rows
when hard current authorization and own-sigma hashing were combined. The current
schedule moves the mandatory OwnProof task into A1, leaving Q0 verification at
A2 and current authorization/Q1 at A6. The same context binds OwnProof's exact
sigma bytes, Q0 exports and own Receipt before later Q verification; no task or
hard predicate is removed. An unknown-witness preflight now checks every fixed
owner's capacity before producing proofs; it does not replace the actual
known/unknown equality and real-proof checks. Moving OwnProof reduced A6 to
64,972 rows, with A1 at 35,446 rows; that nine-stage preflight then rejected
Signatures plus Q2 at 69,523 rows. No proof was produced by that preflight.

The measured ten-stage schedule hard-verifies and folds Q2 alone at A7, then
executes Signatures at A8. A9 owns Nonmembership/Blacklist. Signatures extracts a typed projection of the exact Q2 public cells in
`D_ctx`; it cannot construct a verified-Q result or a pending opening. The
complete ContextPlan pins the Q key digest and requires each Q exactly once;
the Receive plan rejects a missing or future Q2 owner. The projection checks the
fixed signature schema, retains all original 128-bit key/signature limbs and
boolean verdicts, and binds every scalar half to the same context. The Q2 proof
and its opening are still hard-verified and accumulated by A7, so these are
constrained exports of that exact proof, not caller-selected signature verdicts.
Omitting the Q2 owner, its W continuation, context equality or terminal obligation
closure invalidates this composition argument. The ten-stage preflight fit
A1–A9 with maxima 35,483, 61,013, 55,093, 64,232, 64,824, 65,009, 62,530,
57,794 and 62,715 rows. It then rejected terminal A10 at 84,545 sponge rows;
that attempt produced no Receive A proofs.

The twelve-stage candidate separated the two depth32 map effects into
mandatory hard owners: consumed-credit at A10 (task36) and permanent credit record
at A11 (task37), followed by terminal Effects at A12. Each map owner binds the
same complete statement/state/lineage context, all five result claims, all four
modes and exact Payment digest. Each independently derives the identical complete
mode verdict; no new result bit is proposed. The consumed owner authenticates the
exact insertion/no-op and successor consumed root, including empty insertion-slot
checks. The credit owner authenticates and preserves the first Payment/burn record
and successor credit root. Terminal Effects applies the exact adjusted-burn rule,
preserves unrelated roots, and closes the ordinary terminal obligations. Catalog
admission requires both hard owners exactly once before terminal; a terminal-only
map projection is not sufficient. The composed `MapEffectsChip::receive` calls all
three effect parts for standalone consumers. The twelve-stage preflight fit
A1–A9, then rejected consumed-effect A10 at 69,375 sponge rows. The current fixed
ten-stage candidate moves both hard map owners into A1 alongside OwnProof and
the authenticated receiver predecessor. This avoids the later accumulated trace
cost; it does not derive or accept a result early. A1 binds the same complete
context, including all five proposed results, while each mandatory later owner
still derives its result before terminal admission. The terminal A10 performs
burn/preservation and complete obligation closure. The ordinary burn candidate
now passes all ten actual A proofs and nine W proofs at these fixed capacities.
Independent code review found no omitted map predicate or premature acceptance
in this ordering; that review assumes the complete source-key chain executes
every declared owner and does not substitute for actual proof/restoration tests.

The ordinary full-capacity preflight now fits all ten stages, with maxima
65,157; 61,050; 55,130; 64,269; 64,861; 65,046; 62,567; 57,831; 62,752; and
54,945 rows. The first native A relation matches the independent test circuit's
public context, fixed columns, permutation and advice layout and passes strict
constraints. The ordinary burn chain also passes all ten native A layouts and
strict constraints against the independent proof keys, restores all ten A and
nine W checkpoints, rejects wrong stages, truncation, foreign sessions and
substituted original inputs, and preserves exact terminal exports. Its complete
test takes 1,819.06 seconds on this busy host; this is a component test duration,
not a qualified latency measurement or final Omega admission. The renewed
variant also passes its complete ten-A/nine-W proof chain, every native stage's
layout/strict constraints and checkpoint mutations in 1,990.77 seconds. Its A1
maximum is 65,527 rows, only two below the strict 65,529 gate; that actual stage
passes unchanged. Its larger Q2 owner uses 63,677 rows and terminal uses 55,315
rows. No spare-row or runtime margin is inferred from these constraint counts.

Lean lineage milestone 2 (owner decision 2026-10-17) replaces this ten-stage
schedule. A proves the Receive transition itself in A1 (`ReceiveTransition` 46, beside
the hard predecessor and `ReceiveConsumedEffects`), so `OwnProof` (17), the own
sigma slot of Q0 and the own sigma tape are removed. The current credential and its
certificate are no longer re-verified (C4 is carried by continuity), so their objects
leave the schema (nine slots). The own receipt becomes hard slot 0 of the incoming
signature leaf Q1, verified with Authorization at A6 and projected by Signatures at A7.
The schedule is nine A and eight W stages; every incoming check, result owner and
mode is unchanged. The measurements in this section describe the former schedules;
the lean schedule needs new capacity, proof and restoration runs.

The split map regression passes acceptance,
burn insertion and burn no-op with known/unknown equality and mutations of the
verdict, roots, authenticated paths, Payment and credit identity. The Receive
component suite passes eleven checks, including the fixed task/Q-owner
schema and original-byte context mutations. Corrected-claim no-insertion
closure now has its separate captured proof result, scoped below.

The first distinct-wallet accepted-chain attempt reached actual A1–A4 proofs,
then correctly rejected the fixture at Objects A5: its Payment encoded the
receiver's key in the payer-key field. The fixture now copies that key from the
retained payer credential and has a direct regression check. The repaired
distinct-wallet chain passes all ten A and nine W proofs, native descriptor/VK
and strict-constraint parity, checkpoint restores and terminal exports in
5,078.85 seconds on the busy host. This captured run uses the earlier resident-PK
test harness and superseded Load trust; it establishes neither final Omega
admission nor the newer canonical serialized-custody checks.

The native producer pins this full-envelope schedule, exact current internal
Tagged4 and terminal Tagged3 descriptors, installed A/W keys, and both k16
parameter sets. Incoming decoder fields, results and corrections remain witness
proposals whose fixed circuit owners authenticate the original sources. Native
preparation checks hard predecessor/Q proofs and decides selected incoming claims;
checkpoint restoration checks exact proof frames and complete accumulators. The
producer never generates runtime keys or chooses a witness-dependent profile.
The native key-ownership revision retains only installed descriptor/VK metadata.
Each proving call borrows its single exact stage PK, rejects a descriptor or VK
mismatch before proving, and releases the borrow on return. Restoration and
next-circuit preparation use no PK. Component tooling likewise releases each
generated PK and retains verifier metadata; later native parity reconstructs
one stage key at a time. This removes implicit simultaneous residency of nineteen
PKs without changing circuits or proof formats. Receive now uses the shared
`native::artifact::KeyArtifact` directly, with no local type or compatibility
alias. The focused native/shared suite passes all fifteen checks, including
same-descriptor foreign-key rejection, wrong descriptor/pair rejection and
both-curve metadata retained after the PK is dropped. Pair construction checks
identity only; authenticated installation and exact original-source validation
remain separate requirements. Receive's strict original-PK intake now reconstructs
one fixed unknown A or W source from the installed plan, including the complete
owner schedule, source capacities, preceding wrapper and internal Tagged4 versus
terminal Tagged3 profile. It bounds the original, validates its compiled source
tables, and checks the exact installed descriptor/VK before returning one PK.
The factory never returns a checked witness or checkpoint. Its source-shape and
intake-bound components pass for both Receive variants. The renewed variant
also passes all nineteen sequential original-key imports, exact verifier identity,
repeated unknown-layout equality and truncated/wrong-stage rejection in 719.11
seconds. That sweep uses constructor-only Q metadata and does not qualify genuine
proof workloads. The ordinary constructor-only sweep also passes in489.91 seconds.
Both sweeps precede the constant-size continuation rekey described below; their
original source keys do not qualify the new circuit.
A separate current-source regression constructs only a genuinely authenticated
zero-balance Bootstrap receiver. It alters the original incoming Send sigma before
Q preparation, signs the exact altered proof digest and Payment, and requires
Q's incoming verdict to be false with every incoming mode Trivial. The branch
preserves the consumed root and records the burned credit while keeping adjusted
spendable value zero. A locally generated Send witness supplies adversarial bytes
only; no funded Load lineage is admitted. This regression includes every fixed
owner, original-key import and canonical checkpoint. Its current constant-size
context source passes complete10A/9W execution in2,045.12 seconds, including all
nineteen strict original imports, borrowed-key exact proof parity and exact-byte
canonical replays after creating a fresh native session. All ten source layouts
fit k16, with maximum65,305 rows under65,529. Original/Q/context substitutions,
changed current P/W obligations, foreign sessions and malformed custody reject.
The captured executable, source and final log are retained in
`target/qualification/kagemusha-receive/o1-current/`. The prior2,580.44-second
history-hash capture remains historical evidence. A separate captured run
closes the Bootstrap-only burn through actual final Omega in 1,949.62 seconds.
It rebuilds the signed Bootstrap under the fresh immutable Bootstrap/Receive
catalog, reproduces the exact planned Receive terminal VK, executes all ten A and
nine W proofs with all nineteen original imports and exact native replay, and
proves the canonical four-input outer fold. Every selected input decides;
dropping the fourth is rejected. The genuine outer proof is 3,712 bytes and its
transport is 4,800 bytes, with burned-credit membership retained and adjusted
spendable value zero. The complete captured source, executable and final log are
in `target/qualification/kagemusha-receive/bootstrap-burn-omega-o1/`.
These captures predate the acyclic policy correction: signed scheme scope now
uses carried state/lineage cells rather than compiled SchemeID constants. The
changed source and all dependent A/W/catalog keys require fresh qualification.
This captured malformed-source burn result cannot qualify accepted payment,
corrected-claim closure, funded offline onward spending or the full catalog;
neither captured runtime is a performance gate.
The canonical Norito
checkpoint codec derives its exact stage/key/proof length from those installed
artifacts, bounds the original before decoding, and restores through the same
native proof and full-claim verifier. Its layout/codec component tests reject
changed role, stage, descriptor, VK, proof length and framing; the fresh integration
test's ordinary full-envelope burn now passes all nineteen exact-byte
encode/restore/re-encode checks in a fresh session, together with the complete
ten-A/nine-W proofs, native VK/strict-constraint parity and changed-original,
foreign-session, role/stage and framing rejection. The captured run completed
in 4,560.08 seconds on the busy host; it predates the shared helper extraction
and does not qualify the other branches or final Omega. The earlier captured full
borrowed-key regression passes all ten A and nine W proofs and native restores,
exact native VK/strict-constraint parity, pre-proving wrong-stage key rejection
and identical deterministic A2 proof bytes in 3,403.65 seconds on the busy host.
That duration is component evidence, not a latency gate; memory qualification
still requires actual peak measurements under the agreed harness.
Its sigma classes are pinned to the admitted k12 or k14 source descriptors. The
installed descriptor-sized Omega transport (excluding public320) plus incoming
sigma must fit the actual 8,277-byte proof budget; the full raw capacities remain
unchanged for total malformed-input handling.
Its pure component checks cover every result/mode combination, distinct deciding
corrections on both curves, exact original lengths/tails and all signed limbs.
The shared circuit joint-length predicate additionally passes every one of 8,278
boundary splits and both one-byte-over variants under identical fixed/permutation
layouts; native admission tests reject the corresponding over-bound inputs and
individual-capacity/overflow cases. This arithmetic component does not replace
the original active-tape provenance and capacity checks.
The separate renewed accepted-chain capture passes all ten A and nine W proofs,
exact native key/strict-constraint parity, borrowed-stage proof equality and all
nineteen canonical checkpoints with exact-byte replay in a fresh session. It also
rejects changed originals, foreign sessions, wrong stages and framing mutations.
The run took 8,181.79 seconds on the busy host and uses the superseded Load source;
it predates shared-helper extraction and strict original-PK intake. It does not
qualify current ordinary-finality Load, performance or final Omega.
TODO: requalify current original-key import and complete final Omega admission.

The separate Receive outer consumer now plans every exact A/W verifier key,
extends the common catalog, rebuilds the signed payer/receiver sources under the
resulting immutable outer key, and requires the actual terminal VK to match the
planned bytes. It calls the native `terminal_fold_inputs` selector and native
outer producer, retaining all four obligations and the exact resulting credit
membership path. The canonical selector is an encoding/selection API only;
source-proof verification, complete decisions and artifact authority remain
separate mandatory boundaries. The captured pinned-native test passes in7,069.43 seconds: common three-terminal
Bootstrap/Load/Receive key continuity, actual accepted Receive outer proof3,712 B /
transport4,800 B, all four selected obligations decided, droppedfourth rejection,
original import/canonical checkpoint replay and exact credit membership. Its final
log and binary provenance are retained in
`target/qualification/kagemusha-receive/pinned-omega-accept/`. This capture predates
the constant-size continuation rekey and uses superseded Load trust. It does not
qualify the current source, corrected-burn outer closure, ordinary-finality Load,
the full catalog or performance. Earlier witnessed-key results likewise do not
qualify another compiled source.

The captured distinct payer-Load/receiver-Bootstrap shared-key source fixture is
component evidence under the superseded Load voucher trust construction. Current
native Load admission verifies ordinary BLS transaction finality before signing Advance, and
the integration helpers require explicit genuine finality evidence and original
proving artifacts. The retired issuer fixture is removed. Installing the current
fixture and rebuilding the source/catalog remain prerequisites for release
qualification or artifact freezing. No result here establishes the final catalog,
phone performance or the durable-completion gate.

The adversarial test-only compact source helper uses a deliberately forged
succinct PIPA-AS transcript, following the recursion mutation test. It requires
the resulting original Vesta claim to fail decide and derives a distinct deciding
commitment under exactly the same challenges. The standalone forged-fold component
passes. The complete common-key helper also passes: a genuine 3,712-byte Omega
under the immutable shared key verifies while its original Vesta claim fails
decide, and the distinct correction with identical challenges decides. Both
signed source chains and the distinct receiver are rebuilt under that same key;
the adversarial Omega keeps its source A unchanged. This test takes 1,984.25
seconds on the busy host and is superseded-Load-trust component evidence, never
a valid monetary head. The corrected Receive burn with consumed-credit insertion
also passes the complete ten-A/nine-W chain, all native fixed/permutation and
strict-constraint parity, checkpoint restoration/mutations and exact terminal
exports in 4,883.52 seconds. Both actual sigma proofs remain valid and all five
result groups are true; the original non-deciding Vesta claim is the reason this
cannot take the acceptance branch. The captured run uses the earlier resident-PK
test harness, not the new serialized custody path. The separate corrected
no-insertion run passes all ten A and nine W proofs, native key/strict-constraint
parity, borrowed-stage proof equality, every canonical checkpoint with exact-byte
fresh-session replay and the custody mutations in 8,299.91 seconds on the busy
host. It retains the unchanged consumed root and exports the corrected incoming
Vesta obligation. This captured source uses superseded Load ancestry and predates
the shared helper extraction and strict original-PK importer; it is component
evidence, not latency or memory qualification. Final Receive Omega admission
remains open. Production proving and complete-decide checks are unchanged, and
the adversarial source never qualifies as a valid monetary head.

## Archive original sources and conditional terminal closure

`ArchiveStagePlan` requires exactly one owner for each of retained Proofs,
retained Payment, incoming Proofs, Evidence, Signatures, Authorization,
CorePending, LineagePending and Effects. Lean lineage milestone 2 (owner decision
2026-10-17) removes OwnProof: A already runs σ_archive's constraints in
LineagePending, and the own receipt is hard slot 0 of the merged signature leaf
that Signatures and Authorization share. The current credential and certificate
leave the schema (fifteen slots for Receive evidence, seventeen for Status). The
schedule is nine stages for Receive evidence (with an incoming-only Q0) and eight for
Status evidence; the paragraphs below describe the former ten-stage source.
Effects must be terminal, while Proofs must precede it. Q1 and Q2 execute at the
Authorization and Signatures owners respectively. In the fixed ten-stage
source, Q0 executes in its own stage: original-proof binding consumes the same
committed Q public words, and later hard Q verification closes that exact
opening. Every Q index occurs exactly once; index order need not match stage
order. No earlier checkpoint grants a terminal operation verdict. Every stage commits the same
original-object schema: seventeen slots for Receive evidence or nineteen for
Status evidence. The result object commits the three predicate bits together
with their fixed owner indices, plus the original Status verifier opening when
present. The native/context proposal helpers grant no proof authority.

Conditioned on collision resistance and authenticated execution of every fixed
stage, a result proposal cannot change between its producer and Effects: each
continuation binds the same context, and the unique producer equates its derived
bit to that proposal. Omitting a producer or admitting its key without executing
the complete prescribed source invalidates this argument. Full A/W and final
Omega verification must also close each Q opening and each intermediate A/W
opening; equal bytes do not permit merging distinct obligation slots.

Both retained owners are unconditional. The Payment owner binds the held Request, payer
Credential, original Send Receipt, quoted receiver Credential, exact Send
statement and pending descriptor. The separate Proofs owner derives both active
proof commitments and includes their original lengths in the combined consuming
digest. The Payment owner reads those same context slots9/10, hard-equals their
digests, and uses that digest in the signed receipt/package checks. Both owners
are mandatory; a proposed commitment does not replace proof-owner execution. Separate capacity bounds do
not imply the Payment bound: their exact UInt32 lengths are summed as UInt33
and constrained to at most 8,597 bytes, comprising the 8,277-byte combined proof
budget plus the 320-byte public transcript carried in the raw Omega source.
Neither field wraparound nor a false incoming verdict releases this constraint.
Historical proof bytes remain opaque in this owner; it does not verify an old
Payment's proof or receipt signature. The hard predecessor and pending opening
authenticate the seven-word Send descriptor, not the historical proof bytes or
their lengths. The native durable archive must supply the exact retained Payment;
the circuit then binds those supplied originals to the incoming evidence. Pending
membership alone cannot justify limiting a historical sigma to 3,456 bytes.

Receive evidence binds its original sigma to the incoming Q0 slot and uses the
Receive selector. Status instead binds the original active
Omega carrier, decoded public fields and both transported claims; its verified
key must hash to the current lineage's carried Omega-key identity. Its exact
soft-verifier opening is committed even when verification returns false.
Canonical content addresses bind their supplied preimages unconditionally;
a different canonical component cannot be used merely to force a false verdict.
Malformed originals retain their original digest and derive the corresponding
false predicate. Q2 independently binds the incoming receipt signature to the
receiver key quoted by the held Request.

At Effects, the three predicate groups and all incoming modes use the same
branch-uniqueness equations as Receive. For Status, terminal selection uses the
committed original opening, original P/V claims and at most one distinct
same-challenge correction. Both pending-map removal paths are authenticated. The separate CorePending
owner unconditionally removes the core pending entry and clears its physical
leaf. The separate LineagePending owner authenticates the adjusted path even on no-op; the adjusted
lineage pending root removes the entry only on acceptance and retains it on
no-op. It uses the same complete result/mode equations as terminal Effects,
including the no-Corrected condition. Three true soft predicates alone cannot
authorize adjusted removal. All unrelated monetary, credential and policy fields remain constrained.
Consequently a discretionary no-op for entirely valid evidence would require
breaking a producer binding, a mode equation or a deferred-claim decision.

The shared owner/schema, source and map tests support these local implications.
The joint-budget regression first reproduced acceptance of coherent oversized
originals, then rejected cap+1 in either tape after re-signing/re-hashing, while
accepting the inclusive bound. Complete seven-A/six-W ArchiveReceive runs remain
in progress; their captured binaries predate that constraint. ArchiveStatus full
composition, native installed production and complete common-key Omega admission
remain open. Independent internal review of the source-bound argument found no
binding gap, conditional on executing all fixed owners and deciding every
obligation; it does not qualify those pending implementations. No theorem or
release claim here assumes those checks have passed.

The complete current source schema therefore reserves 8,597 raw Omega bytes and
8,277 sigma bytes for the retained Payment, with the unconditional joint bound
above. Incoming Receive evidence reserves 9,321 sigma bytes (10,000 minus the
measured 679-byte Credited carrier); Status reserves 8,132 raw Omega bytes (the
320-byte public transcript plus 10,000 minus 2,188 fixed carrier bytes). Installed
descriptor equality remains a total proof-verdict check over those original
lengths; it cannot erase tails or replace mismatched bytes. Artifact admission
pins the allowed sigma classes and verifier identities. The Archive total-input
path still accepts every original length within its complete envelope capacity;
it cannot use descriptor length to exclude malformed tails from the no-op
relation. A narrow component circuit does not establish that relation. The captured seven-stage jobs
use the earlier 3,456-byte sigma capacities; the complete domains require fresh
sequential source-key preflight, actual proofs and native parity. Additional
independent capacity review established this retained/soft-input distinction and
corrected the history wording above. The isolated full-capacity retained owner
passes strict constraints and known/unknown layout equality at the inclusive
joint bound. The shared full-domain constructor also passes both-variant owner,
Q-placement and source-schema tests. Neither test verifies a recursive chain.

Independent source review of the full-tail fixture confirms that Q receives its
fixed descriptor-sized prefix and the original length9,321, producing a false
incoming verdict and Trivial selection. A reconstructs that same safe view while
hashing the entire original tail into its sigma and context digests. The incoming
receipt and Credited transcript are recomputed over that full original. This
review does not substitute for execution of the new complete no-op proof case.

The shared native Archive producer preserves these same ten operation owners
and separate Q0 stage. Its input
preparation verifies the hard predecessor and three Q proofs, retains every
original and selected claim, and grants no soft predicate by itself. Every A/W
checkpoint is bound to its original context, fixed role/stage and installed key;
a fresh session reconstructs current claims by verifying each previous checkpoint.
Independent source review found no omitted Pallas or Vesta obligation: terminal
Status folds both selected Pallas slots, while final Omega retains the original
Vesta claim with its committed mode and correction. Five constructor tests and
the checkpoint codec/import-bound tests pass, as does the Status safe-view sweep
across all8,133 admitted lengths. These are intake and source components; genuine
full-domain A/W replay and final Omega remain required before artifact admission.

The original full-domain seven-stage source failed k16 before original-key import:
constructor-only Q metadata overflowed Receive stage6 and Status stage1. The
failure is retained, and no source or proof gate was marked passed. The nine-stage
split isolates retained proof hashing and core pending removal without narrowing
any raw capacity or dropping a constraint. Isolated depth32 Core/Lineage owners
pass strict and known/unknown layout checks at16,983 rows each. Full native source
key/import sweeps and genuine proof workloads must re-establish the complete gate.

The subsequent nine-stage preflight uses actual Archive/Receive sigma and Q
source keys, retaining only a constructor predecessor. Both variants overflowed
k16 at the combined Proofs owner under tagged3. The candidate now fixes tagged4
for internal A sources and tagged3 for terminal A, as Receive already does.
Each W pins its exact preceding A key and descriptor; the common terminal catalog
admits only the tagged3 terminal source. This is a layout change, not a relaxation
of domain size, original-byte bounds, proof obligations or key authentication.
The failed immutable source runs remain recorded; the changed sources require
fresh capacity/import/proof evidence. A separate strict projection regression
copies all six retained proof commitment words and rejects mismatched consuming
digests, missing context slots and substituted slot schemas; it does not confer
raw-byte authentication before the mandatory retained-proofs owner executes.
The tagged4 attempt also exceeded k16 at the combined Proofs owner. Subsequent
eleven-stage attempts overflowed the signatures or later core-removal stage.
The current ten-stage source combines unconditional core removal with the first
own-proof stage and keeps hard Q0 verification, raw incoming proof binding and
adjusted removal separate. Each map owner receives its exact removal path.
Its captured actual-Q preflight fits stages0 through5 but exceeds k16 at the
hard Q0 owner:68,450 Status and73,001 Receive sponge rows. These source checks
still use a constructor predecessor. The layout remains unqualified; neither
a larger diagnostic synthesis domain nor an unexecuted original importer
counts as passing the fixed k16 gate.

## Fixed-stage continuation context

The current shared split implementation replaces historical hash replay with
`C = P(kgwctx_1, immutable context)` and
`D_i = P(kgwlink1, [1, variant, i, C, encode(P_i)])`. C includes every compiled
owner/Q/source schema, exact state/statement/object commitment, original proof
projection, proposed result, mode and correction previously committed. Only the
stage's carried P is separated into D_i. Every A computes C once; an internal
continuation reuses those cells for its next digest.

A_i hard-verifies its exact predecessor W key against recomputed D_(i-1) and
V_(i-1). Hash binding gives equal C and P_(i-1) to the authenticated preceding
A frame. That frame, through its exact source key, enforces the prior operation
owners and hard fold. The current A fold still includes prior P plus the W
opening, and every mandatory current Q/predecessor/incoming/source claim.
W retains the A opening and original V part through the unchanged four-slot
fold. Induction therefore retains every obligation without a history witness.
Only the terminal A exports the final lineage frame; no internal digest is
accepted as `kgwomg_1`. The compiled stage index is bounded and domain-separated.

Independent local review found no omitted context or P/V obligation in this
change. The old trace, its helper and private persisted copies are removed.
This is a deliberate source re-key across all staged producers; captured earlier
proofs establish their recorded sources only. Fresh layout, known/unknown parity,
original-key import, context/current-P/W-V mutations, actual A/W proofs and final
catalog qualification remain required for the new candidate.


### Exact message halves in the immutable context

Explicit Omega message projections now append low128 and
`high127 + 2^127 * top1` to C. The private `LeElement` representation already
constrains low128, high127 and Boolean top1. The combined high half is at most
2^128−1, strictly below Fp; equality of the two native words therefore implies
equality of every one of the256 original bits. No canonical-point or canonical-
scalar assumption is needed, so malformed inputs retain total soft semantics.
The fixed message count and original length remain bound, as do the independently
owned active-tape commitment, decoded claims, result and opening. The native
Archive Status preimage uses the same two little-endian16-byte halves. PIPA-R
message decoding and terminal obligation selection still use their original
constraints. This changes the Archive Status context source key; old three-word
context proofs are not admitted as current evidence.

Independent local review found no ambiguity in this encoding. The strict
regression passes for zero, all-ones, mixed and limb-boundary bytes, every changed
original byte and either changed public half, including bit255, with identical
known/unknown fixed, permutation and advice layouts. Its captured executable and
72.24s result are retained in `target/qualification/archive-two-half-context`;
this is binding evidence, not a performance gate or complete Archive proof.
