# B6 joint mask-coordinate derivation

Status, 2026-10-13: **conditional derivation locally reviewed**. This note derives
an exact middle equality from a specified totalized H5-patched experiment
to an **ideal-material patched public simulator**. It retains the entered
commitment/opening distribution. That distribution is not asserted equal
to the real-root BAVC distribution used by frozen `Sim+`.

The [initial H5 note](parliament_ballot_b6_h5_fixed_opening.md),
[bounded driver proposal](parliament_ballot_b6_hybrid_driver.md), frozen
[arguments](parliament_ballot_proof_arguments.md) and ledger remain
unchanged. This note does not establish the computational entry, the later
oracle-deletion step, a reverse BAVC bridge, actual primitive advantages,
complete resources, independent review or production qualification.
The separate [receipt](../docs/validation/parliament_ballot_mask_coordinate/receipt.json)
binds the source and finite algebra checks used below.

## 1. Entry and conditioning

Use the same classical, atomic, adaptively chosen requests and persistent
oracle/adversary state as the H5 note. At every valid request, the bounded
primary schedule and its auxiliary selected opening are independent of the
fresh material coins. The selected opening may be any fixed admissible
pattern or such a mixture, including the exhaustion fallback.

This lemma needs **both** ideal material properties:

- Selected expanded rows are mutually fresh uniform, independent of the
  retained commitment/opening material, revealed expanded rows and entering
  oracle/adversary state.
- The root's high-mask output is a fresh independent string of
  `10*w_grind` bits, also independent of the root's tree output and the
  selected rows. The source computes it with
  `Prg(root).fill_bits(iv, MASK_TWEAK, 10*w_grind)`; replacing selected
  expanded rows alone does not make these high bits uniform. This is the
  additional output of the proposed **joint root/high-mask hybrid**, whose
  primitive reduction remains an obligation.

Keep the actual IV, root/tree keys, leaf seeds, commitments, revealed rows,
and all cached opening material fixed during the coordinate change. Only
the indicated already-ideal random output coordinates are reparameterized.
No committed seed is replaced and no real PRG output is declared freely
resamplable. Unused selected-row tail bits, including the `d_0-d_i` bits
of shorter instance blocks and final byte padding, retain their prescribed
values/distributions.

Challenges 1 and 2 are the **independently prescribed private samples** of
the entered challenge-programmed game. They are not the original outputs
obtained by conditioning on fixed values of the actual transcript hashes.
In the source, challenge 2 depends on the consistency responses; fixing an
ordinary hash output would not justify the uniform-mask argument below.
The existing outer-game transitions are prerequisites, not proved here.

The application witness is valid for its public statement. Write it as
`w(P) = (P, W_app)`, with fresh independent binary pad `P`. Every value of
the 256-bit pad is allowed: the production relation streams use application
coordinates starting at 256, while the backend applies Booleanity to all
coordinates. A false application witness, a malformed relation stream, and
an invalid request are outside this equality and retain their common
specified rejection path.

Fresh independent `P` is a premise on the experiment's latent randomness,
not a property enforced by the caller-facing API. `ProvingTape::fill_with`
delegates entropy to the caller and `from_bytes` accepts reproducible
bytes. Neither proves freshness, uniformity or independence. This is the
same fresh-tape premise as the initial H5 note; (M-11) does not upgrade the
API's contract into an entropy guarantee.

## 2. A precise H5 totalization

For each gate let `A_e` be its visible label, `gamma_e` its selector, `C_e`
its sampled ten correction bits, and `a_m` the ten field masks. First read
and cache the visible oracle value `V_e = H5(A_e)` **before any current
hidden assignment**. With `F_e(a)` denoting the ten corresponding mask bits,
define private slots

```text
Y_e = C_e XOR V_e XOR F_e(a)
H5(hidden_e) := Y_e, chronologically
h0_e = V_e XOR gamma_e*(C_e XOR F_e(a))
h1_e = h0_e XOR C_e XOR F_e(a).                             (M-1)
```

`h0_e,h1_e` feed the source's private gate-tag algebra; the reconstructed
gate value is the cached `V_e XOR gamma_e*C_e`. Call this experiment
`PatchH5_slots`. If the current prefix mask `U_P != 0`, the visible and
hidden addresses differ and these are exactly the ordinary two label
values of `PatchH5`. Different gates have distinct addresses.

If `U_P=0`, (M-1) intentionally keeps two logical private slots while the
actual oracle still has just one entry and the assignment overwrites it.
It does **not** assert that two ordinary source reads of the same address
return different values. A later lookup gets the current overwritten
value; prior cached reads are not rewritten. This specifies the otherwise
exceptional internal behavior without conditioning on its absence.

The initial H5 proof's endpoint coupling is identical until an invocation
has `U_P=0` and explicitly permits arbitrary divergence there. Therefore
the same coupling proves its displayed bound for this specified
totalization, with its already-present `T*2^-256` own-label term. This is an
endpoint choice justified by that proof, not a claim of exact equality
between different totalizations on the exceptional branch or an uncharged
change to an observable oracle. It avoids conditioning the mask law on a
good event. An interpretation with a different fixed exceptional branch
must state its comparison rather than silently using this equality.

All current visible values can be cached first: private gate computations
are independent of other gates' reads, and current hidden writes at other
gate indices cannot affect them. No field is published during the
request. Previous writes stay in the entering table and all subsequent
queries see the resulting chronological table.

## 3. The actual ten-mask map

Let `n = 256-w_grind`, with instance degrees `d_i`, so `sum_i d_i=n`.
For mask `m`, `Layout::mask_row(m)=ell+m*d_0`. The source reads exactly
`d_i` bits there from small-VOLE value `u_i` and places them in that
instance's residue coordinates. Denote the concatenated low vector by
`z_m in GF(2)^n`, and the root's high bits by `b_m in GF(2)^w_grind`.

One fresh hidden row contributes with coefficient one to the XOR defining
each `u_i`. The selected mask-coordinate blocks are disjoint across
instances and masks and from the witness head. Thus the `z_m` are
independent uniform vectors conditional on the fixed revealed rows. The
extra high-output premise makes all `b_m` independently uniform too.

The source's field-mask map, using its polynomial bit representation, is

```text
a_m = W_CRT*z_m XOR M_tree(x)*b_m(x).                         (M-2)
```

The multiplication by `M_tree` here is polynomial shift/XOR, not field
reduction: its degree is at most 255. The actual current table checks give:

| Row | `n` | high bits | rank `W_CRT` | joint rank of (M-2) |
| --- | ---: | ---: | ---: | ---: |
| candidate / 256f | 248 | 8 | 248 | 256 |
| comparator / 256s | 250 | 6 | 250 | 256 |

The finite check also verifies that `M_tree` is the product of the actual
instance moduli, that each `W_CRT` column has the stated unit residue in
one instance and zero in the others, and that its coefficients above
degree `n-1` vanish. Consequently (M-2) is bijective: the low polynomial is
determined by its residues, and division by the monic degree-`n` polynomial
uniquely separates the remaining high multiple. Equivalently the checked
256-by-256 binary matrix has full rank.

It follows that the ten `a_m` are independent uniform field elements,
independent of witness-head coins and retained revealed material, **before
their hidden H5 assignments are installed**. Their conditional entropy
after those assignments or later queries is not asserted.

Given new `a_m`, invert (M-2) to recover `z_m,b_m`. For each instance and
mask, set the selected row's used tail bits to its recovered `u_i` bits
XOR the known XOR of all revealed rows at those positions. Retain all
unused tail bits. This gives an explicit inverse on the original ideal
coin coordinates rather than changing the root, tree or leaf seeds.

## 4. Reconstructed keys and independence

The head-coordinate version of the H5 note's bijection applies to the
entire `ell`-bit witness head: independent hidden heads are equivalently
independent uniform common mask `U` and corrections `c_i=u_i XOR U`.
Here `U=u_0`, `c_0=0`, and only `c_i` for `1 <= i < tau` are sampled
uniformly or transmitted, matching the source's `tau-1` corrections.
For every fixed opening, the reconstructed witness columns cancel the
hidden rows. After the source's correction alignment and linear lift,

```text
Q_j = V_j + Delta*U_j,       Delta = W_CRT*beta,               (M-3)
```

where `beta` concatenates the decoded index bits. The `Q_j` are determined
by revealed rows and `c_i`, independently of `U` and all ten masks.

For the mask tails, the source hidden reconstruction has already removed
the hidden row. It does not add `c_i` beyond the witness head. Its tree
shares depend only on the revealed tail rows. The reconstructed gate
contribution uses cached `V_e XOR gamma_e*C_e`, where visible labels depend
only on reconstructed witness-head columns. Thus the reconstructed mask
keys `qbar_m` are independent of `a_m`, conditional on the entering oracle,
the retained material, the sampled corrections and visible H5 cache.

The separate correlation `qbar_m = vbar_m + Delta*a_m` needs more than
rank of (M-2). Here is its source-specific derivation. The difference of
prover and reconstructed tree shares in instance `i` is the residue

```text
beta_i(x) * (a_m mod M_i)(x) mod M_i(x).
```

This follows because hidden-row removal adds `beta_i,k*u_i` to each
column, and `fold_mask_rows` forms the polynomial column sum modulo `M_i`.
The difference between the private gate values of (M-1) and reconstructed
gate values is `(G*beta) AND (F*a_m)`. The actual tables satisfy

```text
W_TREE*tree_residues(a*beta)
  XOR W_GATE*((F*a) AND (G*beta))
    = a * (W_CRT*beta),                                      (M-4)
```

in the source field `GF(2)[x]/(x^256+x^10+x^5+x^2+1)`.
Both sides are binary bilinear in `a,beta`. The independent finite check
compares every standard-basis pair: `256*248=63,488` for the candidate and
`256*250=64,000` for the comparator. It checks the actual generated matrix
words, source row/word orientation and modulus. Agreement on those bases
establishes the identity for all inputs to this mathematical table model;
it does not certify compiled field code.

Applying (M-4) for each mask gives

```text
vbar_m = qbar_m + Delta*a_m.                                  (M-5)
```

This also holds when `Delta=0` and for the logical-slot totalization in
§2, since (M-1) is the algebra used in this experiment. It is not a
claim that a later ordinary oracle reconstruction agrees on an exceptional
own-label branch.

## 5. The source response map and its inverse

Fix the public reconstructed material, the independent challenges
`chall_1,chall_2`, the pad `P`, and an arbitrary witness correction `d`.
Set `U=w(P) XOR d` and reconstruct `V=Q+Delta*U`. The relation polynomial
stream and its hashes therefore depend only on these fixed values, not on
the ten field masks: `quicksilver::Prover` receives witness and tags before
`finish` applies the masks.

Let `h_j` be the coefficient-`j` stream hashed under `chall_2` with additive
mask zero. `ZkHasher::finalize(x1)` adds `x1` with coefficient one. At
degree seven the actual `Prover::finish` therefore computes

```text
A_0 = h_0 + vbar_0
A_j = h_j + a_(j-1) + vbar_j,             1 <= j <= 5
A_6 = h_6 + a_5.                                             (M-6)
```

Only `A_1,...,A_6` are transmitted. For any independently chosen six
field elements in those positions, recover uniquely

```text
a_5 = A_6 + h_6
for j = 5,4,3,2,1:
    a_(j-1) = A_j + h_j + qbar_j + Delta*a_j.                 (M-7)
```

This triangular inverse uses no division and works for every challenge,
including zero. It determines precisely masks 0–5.

The source's `proof::vole_hash` first absorbs the `ell` witness bits as
field elements, then masks 0–5, and passes masks 6–9 to
`VoleHasher::finalize`. That final operation adds each tail mask with
coefficient one. Write `B(chall_1;U,a_0,...,a_5)` for the four outputs with
zero tail. For any four independently chosen consistency fields `Utilde`,
the remaining inverse is

```text
(a_6,a_7,a_8,a_9) = Utilde + B(chall_1;U,a_0,...,a_5).         (M-8)
```

One must apply (M-7) first and then compensate with (M-8); they are a
single bijection on the ten field masks. In particular, `h_j` is not
recomputed after arbitrarily choosing an independent second set of masks.

VOLEHash is field-linear, so (M-3) and (M-5) imply

```text
Vtilde = VOLEHash(chall_1;Q,qbar) + Delta*Utilde.               (M-9)
```

This is the same value `grinder_of` reconstructs before challenge 2.
There is no additional sampled four-field `Vtilde`.

For a valid witness, every lifted relation polynomial has zero degree-seven
coefficient. Source prover/verifier evaluation uses the same degree
alignment. Linearity of ZKHash and cancellation of the adjacent masks in
(M-6) yield

```text
A_0 = ZKHash(chall_2; evaluated_constraint_stream,
             sum_(j=0..5) qbar_j*Delta^j)
        + sum_(j=1..6) A_j*Delta^j.                          (M-10)
```

The evaluated witness coordinates are `Q_j+d_j*Delta`, exactly the
source verifier's inputs. Equation (M-10) is its `Verifier::finish`, so
the remaining coefficient is determined by public reconstructed values,
`d`, the prescribed challenge and the six sampled coefficients. This
derivation requires witness validity; it is not a soundness proof for
invalid witnesses.

## 6. Exact joint-state equality

Condition on the entering classical oracle table and its correlated
adversary state, all retained commitment/opening/revealed material,
corrections, visible H5 values, the current request's salt, and independent
prescribed challenges and counter schedule. This conditioning is for the
equality proof; it is not a measurement or information given to the adversary.

The fresh coin coordinates left to consider are the pad `P`, common
witness mask `U`, and ten field masks `a`. Perform the following joint
change of variables:

```text
(P,U,a_0,...,a_9)
    <-> (P,d,A_1,...,A_6,Utilde_0,...,Utilde_3).               (M-11)
```

For each fixed `P`, `d=w(P) XOR U` is a bijection on the witness head.
For each fixed `P,d`, (M-7)–(M-8) invert the response map. Section 3 then
recovers the underlying low/high mask coins, and the head bijection
recovers the selected row heads. Thus (M-11) is a bijection of finite
uniform coin spaces conditional on the retained material. Its right-side
public fields are independent uniform samples; the recovered private
coordinates retain their original joint distribution.

After the inverse, compute every hidden address from the same recovered
`U_P` and every hidden value from (M-1) using the same recovered masks.
The address, value and chronological position of every H5 assignment are
unchanged for each pair of coupled coin choices. This preserves the
**joint oracle state**, not merely the public proof bytes. Previous
assignments and their collisions stay in the entering table; later
queries see the same final function. The pad/witness-dependent assignments
remain present and are not yet declared harmless.

Defer the current hidden assignments until the visible cache, response
coordinate change and private recovery are complete. No subsequent
source proving operation reads H5, and no adversarial action occurs
inside the request. Challenge 1 and 2 writes use their private prescribed
values, with exact locations computed from the coupled final fields.
They are in different oracle domains and can likewise be deferred without
changing subsequent internal reads. Every primary challenge-3 write uses
the same `(chall_2,A_0,...,A_6,counter)` location and its same prescribed
`Y_c`, with the same stopping counter or exhaustion outcome. Neither a
counter write nor its history is omitted.

On exhaustion the auxiliary selected pattern is still private. Its
reconstructed values can be computed from retained revealed rows and
cached commitment material for this mathematical experiment; no auxiliary
opening is returned or additionally hashed. A proof builder that actually
recomputes such material has additional costs to account for and is not
silently equated to this cached driver.

The resulting experiment, `IdealPublicPatched`, runs the retained ideal
commitment/opening sampler, samples uniform `c_i,C_e,d`, reconstructs
`Q,qbar,Delta` using the visible cache, samples the four consistency fields
and six transmitted coefficients, and derives (M-9)–(M-10). Only its
private bookkeeping needs the witness and pad to recover (M-7)–(M-8) and
the hidden assignments. Its public computation has no direct witness or
pad input. The equality of this experiment and `PatchH5_slots` holds
request by request and hence inductively for the full adaptive state and
the adversary's final output.

This last statement does **not** say that the patched experiment's entire
public execution is statistically independent of every pad. Its oracle
still contains pad-dependent assignments, which may affect later queries
and requests. The separate deletion argument needs an unpatched baseline
whose complete public algorithm and oracle state are independent of the
unused pads. No such oracle removal is performed by (M-11).

## 7. Why this is not exact equality to frozen Sim+

Frozen `Sim+` samples a real 256-bit root and constructs real BAVC material.
`IdealPublicPatched` keeps the material after the proposed forward
root/path/leaf replacements. A mask-coordinate bijection changes none of
that material, so it cannot establish equality of these distributions.

For a concrete distinction, consider the proposal's **fully replaced**
hidden-path endpoint with fresh independent output for each replaced node
slot, and the candidate zero opening. Its 11 revealed frontier keys are
the distinct unmarked children of marked ancestors. Each comes from a
distinct coordinate of one fresh replacement output, giving a uniform
vector of `11*256` bits in that explicitly defined endpoint. Fix the IV
and concrete generator functions. In real BAVC the frontier-key vector is
a deterministic function of a 256-bit root and has support at most
`2^256`. These supports cannot give the same uniform distribution. This
argument does not apply an independent-key assumption to a partial hybrid
or to a differently cached ideal experiment.

A full simulator proof must therefore supply one of the following
additional interfaces, with its own analysis:

- A reverse material bridge from the ideal public material to real BAVC.
  It must simulate the entire adaptive experiment, use the actual IV,
  preserve cached openings and the full counter/assignment history, and
  charge every generator/leaf transition and its resources. Once hidden
  patches are deleted, the public simulator may be a simpler place to
  attempt this bridge; its exact order and distributions still need proof.
- A separately specified bounded public simulator that directly samples
  the required ideal frontier keys and hidden leaf commitments, derives
  the remaining public material, and reproduces the entered ideal
  distribution. That would be a distinct simulator proposal, not the
  unchanged frozen `Sim+`, and needs its own dependency and resource check.

The support distinction is an information-theoretic obstruction to the
claimed **exact** material equality, not a cryptanalytic attack or a
disproof of a computational bridge. No reverse primitive reduction,
doubling/omission of a ledger factor, or alternate simulator acceptance is
assumed here. This note isolates the exact middle transformation while
retaining that remaining qualification obligation.

## 8. Source and review scope

The source map in the receipt binds the exact ranges for
[`vole.rs`](../crates/iroha_zkp_vole/src/vole.rs),
[`quicksilver::Prover`](../crates/iroha_zkp_vole/src/quicksilver/prover.rs),
[`quicksilver::Verifier`](../crates/iroha_zkp_vole/src/quicksilver/verifier.rs),
[`universal_hash.rs`](../crates/iroha_zkp_vole/src/universal_hash.rs),
[`proof.rs`](../crates/iroha_zkp_vole/src/proof.rs), and the two relation
emitters. The separate retained finite checker reads the actual CRT table
words, tests elementary orientation/arithmetic controls, and detects a
bit mutation in each of `W_CRT`, `W_TREE`, and `W_GATE` for both rows. Its
source hashes must match the receipt before its result is reused.

The root and ownership agents completed local mathematical/source
consistency reviews under the explicit entry premises. Those reviews are
not independent cryptographic review or owner acceptance. In particular,
they do not certify the entry hybrids, a complete patched-to-unpatched
deletion proof, the bridge to frozen `Sim+`, or full quantum resources.
