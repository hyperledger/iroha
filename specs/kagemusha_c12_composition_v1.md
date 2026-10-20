# KAGEMUSHA C12 logical setup and causal composition

This implementation-coupled argument composes the
[local fixed-function proof law](kagemusha_local_zk_v1.md) and
[recursive source/accumulator obligations](kagemusha_recursion_soundness_v1.md).
It covers one finite logical experiment with explicit assumptions. It does not
claim an efficient simulator for literal installed BLAKE2b parameters, a
physical resource theorem or completed release qualification.

## Selected first-release source interpretation

The interpretation here fixes the norm products and final product one, total
challenge-role maps, committed D and 33-coin fold tape, scoped full-group
accumulator encoding, and closed terminal projection of the selected source.
The local sampler premise concerns those exact equations and admitted masking
predicate M. The earlier linear-product/raw-role or salted-fold derivations in
the linked memos retain their own scope; their old exceptional-branch bounds
are not substituted for this premise.

Every semantic, proof and custody transition below uses the same selected byte
materializer: source frames, encodings, descriptor and original-key admission,
fresh-attempt rules, retained originals and refusal cuts. Equality of a few
kernels alone does not establish that whole invariant. The theorem is
conditional on the local law and exact reachable-source/custody invariant
stated below; source comparison and old executable results do not establish a
new current catalog, native run or physical qualification.

## Common setup before pins

Fix the public source template, canonical grammar, field/group algorithms,
actual RP57, finite query/operation/coin budgets, strict source admission and
the adaptive environment before either game. Substitute only the designated
512-bit raw hash interface used by native Pasta setup XMD. Real uses one ideal
random oracle H; Sim uses the append-only inverse-sampling adapter. All
designated calls, including the DataModel capsule-base derivation, use that
same interface. RP57 is never programmed. The simulator's private setup logs
are experiment state, not altered public source files.

Let D contain the raw transcript and parameter encodings. Both games execute
the same deterministic public construction T(D):

1. Derive both generator prefixes through k16, W/U, and every independent
   k6..k16 inverse transform. Encode all 22 bundles; a smaller Lagrange vector
   is not a prefix of the k16 vector.
2. Emit matching parameter digests, four wallet bundles, both trivial constants
   and DataModel capsule bases from the existing Eq g[0], g[1], W contexts.
3. Refresh public source-custody manifests actually consumed by the builder.
   Do not retain obsolete hashes or change unconsumed historical fixtures.
4. Compute source identity using the same current deterministic native-input
   inventory in both games, including its package/explicit-input precedence,
   membership and file-kind rules. The generated registry
   `crates/iroha_plonk/src/keys/keygen/builtin/generated.rs` remains excluded
   to avoid self-hashing; unrelated client owners and prose follow the actual
   inventory rule. The simulator adds no exclusion for its private logs.
5. Execute the actual catalog DAG: sigma/Q sources, Bootstrap, provisional
   Omega recipe, A/W sources, final Omega and complete strict closure. The
   provisional recipe creates no verifying-key fixed-point search.
6. Strictly admit all originals, including mandatory mask/rank/pivot predicate
   M, and emit source-bound registry DATA. Rebuild under the same identity rule.

Every constructor, refusal and finite work limit is common to both games.
Failure is an output, not a request to search for another setup. The experiment
does not condition on catalog success or a literal release source hash.
Source hashes may vary with D; that is the intended setup-before-pins game.

The raw-adapter coupling lemma gives, for Q external raw queries and Qs named
setup contexts,

```text
Qs <= 2 * (65536 + 2) = 131076
epsilon_setup <= Qs * 12292 / 2^256
               + 2 * Qs * (Q + 3*Qs) / 2^512.
```

This lemma includes canonical draws, inverse attempts, occupied entries and
terminal failure. Each failed ordinary inverse attempt refreshes its target,
first preimage and inverse slot. Outside the coupling bad event, the whole raw
transcript and residual interface agree. Deterministic reduction, curve maps,
FFT, encodings and T(D) then agree byte for byte, including earliest refusal.
Thus complete source/key/catalog authority and any common adaptive continuation
add zero setup distance. Conditioning on a successful or fixed literal setup
does not preserve this bound and is not part of the theorem.

Applying this model to the actual deterministic BLAKE2b implementation is an
explicit instantiation assumption. Discrete-log hardness, collision resistance
and recursive Fiat–Shamir soundness do not supply installed generator logs or
prove that instantiation.

## Private originals and public simulation

The semantic functionality privately owns balances, source-derived originals,
private frames, checkpoints, capsule bodies/openings and restricted signing
authority. The public simulator receives only declared semantic statements,
roles, disclosure, signing tickets and scheduling projection. It receives no
private wallet state or hardware keys.

At every fresh Q/A/W cut, the private owner first derives its frame from the
exact retained history. The M-admitted local sampler then uses the actual RP57
schedule, public-only evaluations, private pivots and complete final f/G
binding. Its full canonical checkpoint becomes the original consumed by later
frames. This applies to all three Q stages and restored incoming-Q custody.
Sampling an Omega beside an unrelated genuine checkpoint is not allowed.

For a private committed fold, fix its parameter owner, closed purpose, slot
count, admissible deciding inputs (including the explicit full-k16 slot), and
any source-derived TerminalFrame before the fresh tape. Let log(W)=w != 0.
Choose D first and derive the actual alpha, z and zeta from that D. Then choose
the 32 L/R point logs in native transcript order and set each mask:

```text
mask_L = (log(L) - log(left_offset)) / w
mask_R = (log(R) - log(right_offset)) / w.
```

Offsets depend only on the exact inputs and preceding path. After these masks,
the input digest and chosen D uniquely determine rho. On a non-refusing path,
this triangular map bijects accepted tape coordinates with the 33 nonidentity
point logs; the stopped extension below covers the remaining tapes. Before
imposing refusal, conditioning on D leaves the masks uniform even though the
input digest includes all masks.
At each reached point, retain the native finite-point identity refusal rather
than resampling until success. The native tape sampling, its coin consumption
and any bounded exhaustion occur before D; the lazy inverse description does
not reorder those cuts. At a D/L/R identity stop, independently complete any
as-yet-unspecified mask coordinates, solve rho using the full mask-dependent
digest, then project to the actual stopped state. This is a coupling of the
full pre-sampled tape, not native coin draws or a continuation after refusal.
For these fixed public parameters, purpose and count, the resulting stopped
D/L/R path law is independent of the deciding inputs. Applying the unchanged
deterministic transcript function gives the
same input-independent law for the exported challenge vector u and its decided
G(u). This does not assert that u is uniform or that RP57 is a random oracle.
The actual c, rho and masks remain private, source-derived retained witness
values; their joint law is preserved by the materializer, not discarded.
Entropy exhaustion remains at its original cut under the stated coin model.

At the terminal cut, materialize P, derive/sample terminal A, parse that exact
A through TerminalPlan, materialize V from its derived slots, then derive and
sample Omega on that exact O/P/V frame. This preserves joint P/V challenges and
their later uses; no independent marginal argument replaces that order.

At capsule publication, freeze the exact body before selecting independent
q and public commitment C=qB. With body digest limbs m0,m1, retain

```text
opening = (q - log(g0)*m0 - log(g1)*m1) / log(W).
```

This preserves the joint law of body, opening, C and custody hash. The actual
public Poseidon identifier-zero refusal remains. The body digest, public
identifier and private custody hash are distinct; none is assumed uniform
merely because C is uniform.

The source-validity premise is essential: each reached frame has its matching
source witness; every prior sampled proof is coupled to a genuine proof for
that then-current frame; every fold uses exact deciding inputs and binding.
M proves masking support, not arbitrary-frame validity. Reviewed native/circuit
operation and kernel arguments discharge their stated source obligations;
genuine all-route execution checks the implementation. Finite samples alone
cannot prove these universal source statements.

## Causal custody, retries and failure

The logical custody service is fixed before simulation. It runs actual byte
encodings, hashes, immutable deduplication and Patricia geometry on the retained
private originals. It owns uncertain writes, manifests, request bindings,
selected plans, collection cursor and signing-completion records. Each next
result follows from this state and the predeclared service transition/coins;
it is not a posthoc success/failure label chosen to fit an unrelated carrier.

An authorized exact replay adopts the same original. A fresh attempt requires
the source's definite-absence condition; missing acknowledgement is not definite
absence. Fresh interrupted attempts count in the coin ledger. Selected replay
draws no fresh proof coins, but retains its actual storage and error outcome.

The selected custody state includes the permanent operation-to-sequence locator
and matching `StepEntry`, selected together by one manifest publication and
preserved through collection. A low-level `Unknown` after loss of both historical
completion copies is not sufficient evidence of nonselection. The coordinator
checks the canonical bounded locator, the authenticated step's operation, and
its capsule binding where supplied by the request or direct-commit mapping.
An authenticated indexed match in this `Unknown` branch returns
`DeliveryDataLoss`; unavailable, corrupt or conflicting index paths propagate
their custody error.
These outcomes precede new preparation or signing in request execution and
operation commit; retry cannot convert them to a new Send. Authenticated index
nonmembership leaves the unselected path possible only subject to Advance's own
selected-state checks; a preparation binding alone does not establish a commit.
For an uncollected indexed operation, a restored completion must match the same
step's exact completion binding before replay. This is a source-state invariant
of the logical custody service, not a guarantee that lost bytes can be recovered
or that physical storage satisfies the service.

The custody service includes the bounded retirement journal, exact grave set
and their stopped/recovery states: slot and record identities, operational
nonce and stored Pending/Complete phase. Retirement and staging entropy draws
and failures belong to the predeclared service transitions and coins, distinct
from proof masking tapes. Recovery adopts the stored phase and retained
originals rather than resampling a replacement history. The latest completed
retirement metadata remains retained, so collection makes no forensic-erasure
claim. Any exposed static journal or grave failure labels remain in the typed
scheduling projection. This extends the exact-source custody invariant; it
does not discharge that invariant or the physical refinement below.

Storage use can depend on private request prefixes, exact proof hashes, dedup
and capsule openings. The private materializer computes those dependencies;
the simulator is not granted their values. Only declared typed scheduling
leakage leaves the functionality. Two secret histories with equal earlier
public carriers may have different permitted scheduling outcomes. This is
simulation relative to that leakage, not physical zero-leakage noninterference.

The selected process-local verified-opening memo is private derived state,
bounded to 256 entries per immutable parameter owner. Current statement
admission precedes lookup of the SHA-256 key binding the complete verifier
input; returning a hit still checks cancellation. Only successful production
full verification publishes its own opening, after the final checkpoint. A hit
reuses that exact k/G/challenge tuple, never a succinct-only acceptance. Under
the stated binding premises this preserves semantic acceptance; the memo is
never persisted and grants no monetary authority.

Its inputs may include privately retained proofs. Matching coupled private-owner
histories determine memo state; public carriers alone need not. Exposed
hit-dependent timing, cancellation, counters, RSS, contention and eviction
remain subject to the declared scheduling projection and physical refinement
below. A hit's cancellation checkpoint does not establish cold/warm equivalence
under wall-clock cancellation.

The selected transactional intake rule is part of the source invariant: native
semantic refusal before acknowledged batch retention retains only the fixed
request binding, without durably retaining variable rejected originals or map
drafts. A different native state transition cannot inherit this theorem merely
by using the same proof sampler.

## Finite composition and concrete assumptions

Assume the raw-adapter lemma, local PLONK law for M-admitted reached valid
frames, exact source-validity invariant and logical custody service above.
With ideal independent coins,

```text
distance(View_real, View_sim) <= epsilon_setup.
```

Induct on the next actual cut. Equal coupled public history gives the same
adaptive action. The owner derives its current frame before new coins. Its
local proof kernel, fold bijection or capsule bijection couples exact new
bytes. The same service on equal byte/state inputs has the same next outcome.
Refusal retains the same stopped state; recovery consumes the same original.
Restricted signing postprocesses the same authorized body. The induction
therefore couples private archive state as well as the declared public view,
without revealing that archive to the simulator or conditioning on publication.

Concrete coins add separately stated joint OS-entropy and hedge/PRG replacement
costs, reached 512-bit field-reduction costs and any exhaustion not retained
exactly. For scalar modulus r and s = 2^512 mod r, each field reduction has
distance s(r-s)/(r*2^512). The 33-scalar, 134-candidate sampler either retains
exhaustion or charges at most 33*(1-r/2^255)^134 under ideal bytes. Exact stopped
materialization adds no erased B/r or 33/r term; an argument that erases those
cuts must restore their costs for every fresh reached attempt. Never retain
and charge the same branch twice.

Binding, signatures, ledger finality and recursive knowledge/accumulation
security remain the separately stated authorization/soundness premises. The
source arguments use the specified prime fields, Pasta group/order properties,
frontend semantics and actual checked finite tables. They are not a theorem
about arbitrary compilers, machine code, operating systems or unbounded depth.

Physical RSS, allocation, filesystem free space, compression, Jetsam, deadlines
and power-loss/restore behavior are not this logical service. Observing those
outcomes adds a physical-to-logical refinement term that is not proved
negligible here. An honest OS assumption does not set it to zero. Genuine
catalog admission, monetary execution, device measurements and the release
durability boundary remain separate implementation requirements.
