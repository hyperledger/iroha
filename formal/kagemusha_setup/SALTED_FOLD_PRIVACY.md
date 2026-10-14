# The surviving salted-fold law: exact barrier and a narrower target

This is a construction-coupled reduction, not a proof of fixed-RP57 fold
privacy. It uses one unchanged deterministic RP57 implementation F everywhere.
The selected recursive Fiat–Shamir premise in
[the recursion argument](../../specs/kagemusha_recursion_soundness_v1.md) promises knowledge soundness and
accumulation security. It does not promise the distributional property defined
below. No property is silently added to that accepted premise.

## 1. Source law and the observable carrier

Fix a coherent public parameter family K, curve C, an ordered list X of deciding
`FoldInput<C>` values, and a base-field salt s. X is canonical, nonempty and
contains a full-k16 slot. Fix arithmetic and exclude external faults for this
algebraic experiment. The function

    Phi_C(K,X,s) = create_fold(K,X,s).claim, or its cryptographic error

is deterministic. `accumulation.rs::prelude` absorbs s, count, each point,
source k and all sixteen normalized challenges before alpha,z,zeta. The prover
then derives every coefficient, L/R pair, challenge and final scalar from those
values. It takes no RNG argument and adds no W blind to L/R. Native salt sampling
is outside this function. Cancellation/resource/entropy laws must be supplied
separately when mapping this experiment to the wallet.

On success, let u be its sixteen challenges. Generator folding is
`g_low <- g_low + u_j*g_high`; induction gives

    G_K(u) = sum_(i<65536) g_i * product_(j<16) u_j^bit_(15-j)(i).

Thus a successful deciding claim is exactly `(G_K(u),u)`. The checked claim
serializer publishes the compressed point followed by every canonical u_j,
544 bytes total. `omega/native.rs::Output::transport` appends both such claims
unchanged to the Omega proof. Projection to u and reconstruction of G from K,u
are efficient inverses on this support. The outer proof cannot hide u through
the lineage digest: P.u remains in the transport and V.u is also a Direct
instance. Public full decisions retain their actual refusal branches.

For the terminal proof projection, also retain each exported sigma proof body
including c/f, its public statement/descriptor/key, and all disclosed outcome
and scheduling data. On deciding support the public statement and body recover
its challenges and generator suffix. The surviving carrier Y is this joint
sigma-body/P.u/V.u representation. Its joint law matters: equality of either
curve's marginal or each separate sigma marginal is insufficient.

## 2. A lossless-output lemma, with the failure cost explicit

Assume the honest-to-public-sampler replacements have already been justified.
Let mu_0,mu_1 be two surviving-carrier laws at that erased cut with the same
complete public leakage ell and setup K,tau. tau is the fixed coherent private
setup-log state used by the Omega sampler. Suppose the rest of the terminal
proof projection is the same total Markov kernel Q(ell,K,tau,Y), including
public verification, decisions and errors. This supposition is the actual
erasure/factorization premise; it is not inferred from local proof hiding.

On every successful transport, a deterministic public decoder recovers Y from
Q's output. On a failure it returns a distinguished bottom. Let eta_j be the
unconditioned probability in world j that this decoder cannot recover Y. This
includes failure branches whose source distinctions were projected away.
Then, writing TV for total variation,

    max(0, TV(mu_0,mu_1)-eta_0-eta_1)
      <= TV(Q(mu_0),Q(mu_1)) <= TV(mu_0,mu_1).

Proof: the upper bound is data processing. Couple Y with the decoder of Q(Y)
using the same execution. They disagree with probability at most eta_j. The
triangle inequality and data processing for the decoder give the lower bound.
For computational distinguishing, compose any carrier test with the public
decoder, choosing any output on bottom; its advantage changes by at most
eta_0+eta_1. Runtime grows by decoding. Composing an endpoint test with Q gives
the upper computational reduction when the reducer possesses the stated tau.
For a successful-only, always-decodable kernel, the distances are equal.

Consequently a deterministic/public erasure of the hidden fold body and salt
does not eliminate the surviving challenge law. Outer sampling can suppress a
carrier distinguisher only through the explicitly charged lost-output mass.
This is a source-specific obstruction to *that shortcut*, not a privacy attack
against actual RP57. It also does not justify conditioning either law on success.

## 3. Full independent tapes are not necessary

A different public endpoint can use the actual fold rather than sixteen
independent challenge words. Define a public template X*_C(K,m) consisting of
m repetitions of the full-k16 trivial deciding claim `(sum_i g_i,[1;16])`.
The sum must be finite and source-admitted; if not, the template construction
has an explicit error. No literal from a different parameter family is reused.
Repeated deciding slots are permitted by the native input contract. The public
count m can be fixed by the selected role/leakage; it need not be secret state.

Define the canonical-real-fold endpoint as follows:

* Generate each exported sigma body with the same-F public-frame sampler and
  fresh independent coins, as in the [erased endpoint](ERASED_ENDPOINT.md).
* Independently draw one native-law salt per final curve and run Phi_C on the
  public template. Keep every cryptographic error; do not resample failures.
* From the resulting P,V and public18 derive the actual 52-word lineage digest
  and Omega Direct columns, run the total same-F Omega sampler, and execute
  the same public checks/serialization. A failure is an endpoint output.

For equal ell,K,tau, this endpoint has exactly the same law across private
histories: couple every new coin and follow deterministic code. No hidden
history is an input. Unlike the independent-tape target, its challenge vectors
can have only salt-sized support. Its definition neither programs F nor needs
a witness for the changed Omega frame. This is a mathematical simulation target,
not an instruction to replace production accumulators or modify an old session.

The sufficient missing bridge is now strictly narrower than full tape
pseudorandomness. Compare the actual *joint surviving carrier*, after the
justified local replacements, with this canonical-real-fold carrier under the
same pre-salt auxiliary state, known-log continuation, future F computations,
and complete outcome interface. Call its advantage h_can. For two histories,
the already derived local/operational/setup costs plus h_can,0+h_can,1 bound
the proof-view difference; the canonical middle term is exactly zero. Every
other custody/continuation cost remains. No bound on h_can is established here.

There is no need to claim that canonical real-fold tapes are uniform. In a
finite example, `Phi_x(s)=(t,t^2,t^3)`, t=s+x over F5, has exactly the same law
for every x but is distance 24/25 from three independent field words. Different
outputs for the *same* salt therefore do not refute input privacy. Conversely
`Psi_x(s)=(s,x,s+x)` has the same seed entropy and disjoint laws for distinct x.
Determinism, salt length and fresh salts alone imply neither input privacy nor
its negation. These examples are logical controls, not RP57 implementations.

## 4. A precise optional theorem premise

An auditable sufficient premise can be stated as **salted-fold input privacy**,
restricted to the current source and the allowed catalog, rather than a general
PRF assumption. It is a candidate theorem hypothesis, not an adopted release
assumption:

Fix the joint coherent setup experiment `(K,tau,Z)` used by the local sampler
reduction. For each reached permitted pre-salt prefix, fix an admissible ordered
deciding input list X and permitted auxiliary state A. A may include setup logs,
the previous public view, the input list, already sampled exported sigma bytes,
and legitimate application state fixed before the fresh salt. The challenged
salt and local fold witness/round transcript are never released. Compare

    (K,tau,Z,A, Phi_C(K,X,S))
    (K,tau,Z,A, Phi_C(K,X*_C(K,m),S*))

where S,S* are independently fresh salts with the specified native sampling law,
F is unchanged and freely computable, and m is the same permitted public count.
Both are total cryptographic responses with the same designated error alphabet.
Ask for advantage at most h_C(prefix,t), for all allowed computations of budget
t. To cover native execution, add justified salt/operation/custody differences;
do not claim external faults automatically have this distribution.

For adaptive hidden fold slots, require this comparison uniformly over prefixes
reachable in the comparison games, or state a sequential left/right experiment
directly. Replacing slot i must rerun the same total continuation from its
response and retained pre-salt state; that continuation cannot require its newly
discarded salt/body. Otherwise the old-witness recomputation distinguisher
applies. Sum the conditional costs over a deterministic cap on fresh slots;
exact selected replay supplies no new slot. If source restoration or a later
genuine circuit still needs a replaced fold witness, erase that consumer first
or retain the corresponding separate proof; this static premise alone does not
authorize the swap. A global joint carrier comparison may be narrower than this
per-slot sufficient hypothesis and avoids asserting unnecessary intermediate
state independence.

An independent-tape H premise would imply this pairwise comparison by a triangle
inequality if it covered both the genuine and template inputs under exactly
these same interfaces. The converse fails by the F5 example. Acceptance of
recursive knowledge/accumulation soundness, however, supplies neither premise.
For a generic demonstration of the logical distinction, append a witness bit
to any knowledge-sound proof and let its verifier ignore the added bit. The old
extractor/security reduction is unchanged while that bit leaks perfectly. This
is not the native format and is not a counterexample to concrete fixed RP57;
it disproves treating a soundness property itself as a privacy theorem.

## 5. What can be ruled out for the actual source

At a fixed pre-salt cut with fixed K,X and no external faults, a real fold has
at most b=|C::Base| successful output vectors. Let rho be its success probability.
An independent mapped-word target gives any particular sixteen-vector mass at
most lambda^16; subsequent error checks only decrease that successful mass.
Using the real success set as a distinguishing event therefore gives

    TV(real fold, independent tapes) >= max(0, rho-b*lambda^16).

Write p=|Fp| and q=|Fq| for the Pasta field orders, with p<q.
For the current Pallas direction, lambda=1/p and this is rho-p^-15. For Vesta,
lambda=2/q and it is rho-2^16/q^15. It is unconditioned and does not assume rho
is large. This rules out a small *statistical* full-tape bound when honest
success is frequent. Membership in the actual success set may require an
exhaustive salt search; no efficient membership test or computational attack is
derived. The argument does not rule out statistical equality of two real-fold
input laws, since those sets could coincide, nor computational input privacy.

The local W-blind fiber proof cannot be reused here: L/R are fixed MSMs of the
already fixed coefficient state, U and zeta. There are no independent W-blind
coordinates after that state. Replacing the hidden body with public randomness
would change the law being proved. The accepted recursive Fiat–Shamir heuristic
and the inspected source give no small bound for h_can or h_C.

## 6. First-release design implications

The unresolved issue is an unproved privacy property of a deterministic salted
construction, not an identified source soundness defect. Keeping the current
wire format and performant accumulation design requires either proving the
joint fixed-RP57 property in the stated model, or explicitly adopting a reviewed
construction-specific computational hypothesis and quantifying its scope.
The hypothesis must mention both fields, known-log setup/continuation state,
correlated carriers, fresh-attempt budgets and total outcomes; a label such as
"Poseidon is secure" or the current recursive FS soundness sentence is too weak.
Adopting it would cause no native proof-size/runtime change, but would change the
theorem boundary and would not resolve setup, source, regularity or device gates.

Increasing the salt to sixteen words only removes the cardinality obstruction;
it does not prove fixed-F input privacy and adds absorption/constraint work.
Adding free W blinds to this non-hiding fold is not a justified local repair:
the current obligation is the pure equation G=<s(u),g>. A verifier which instead
accepts a free Pedersen blind admits G=<s(u),g>+rW for any chosen nonzero r, even
though the old decision fails. A redesign must bind and preserve the intended
pure obligation, not merely reuse the ordinary hiding IPA relation.

Eliminating the public challenge-vector carrier would change the recursive
verification boundary. For example, keeping the claims private and proving
their complete decisions in the outer relation requires implementing and
qualifying those full-k16 generator decisions in circuit, or another proved
hiding accumulation construction. That changes constraints, keys and performance;
no two-second or proof-size claim for it follows from current measurements.
It should not be introduced as a masking patch during a frozen candidate build.

The narrowest reviewable next step is to assess the computational input-privacy
hypothesis above against the actual fixed-RP57 source and permitted auxiliary
state, with the existing ideal-permutation result clearly separated. This note
does not ask for or record owner acceptance of a new assumption and does not
close C12.

## Maintained source map

The deterministic fold law and lack of independent L/R blinds follow from
[`accumulation.rs`](../../crates/iroha_plonk_recursion/src/accumulation.rs),
including `prelude`, `create_fold`, and `fold_generators`.
The generator polynomial is specified by
[`fold_scalars`](../../crates/iroha_plonk/src/pcs/ipa/mod.rs).
The checked transport carrier, trivial claim and expected-generator computation
are in [`claim.rs`](../../crates/iroha_plonk_recursion/src/claim.rs).
The terminal transport/digest/frame law and exact old-session binding are in
[`omega/native.rs`](../../crates/iroha_kagemusha_proof/src/omega/native.rs).
The salt owner is
[`native_worker.rs`](../../crates/iroha_core_zk/src/kagemusha_wallet_state_v1/native_worker.rs).
The separate ideal-permutation and transcript controls are described by the
[fold README](../kagemusha_fold/README.md); those experiments do not prove
fixed-RP57 input privacy. The [local sampler proof](PUBLIC_SAMPLER.md) and
[independent-tape endpoint factorization](ERASED_ENDPOINT.md) retain their
separate premises.
