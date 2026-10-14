# Exact factorization of the fully erased terminal proof view

The [public-input sampler comparison](PUBLIC_SAMPLER.md) gives the local premise.
This note gives a precise zero middle term for the terminal *proof projection*, once
all preceding local and hidden-fold replacements are justified. It does not
assert that the original wallet reaches this endpoint law, or that all payment,
storage, timing and future state views factor in the same way.

## Leakage and endpoint kernel

Fix the following leakage ell: the complete admitted public setup/key catalog;
the ordered list of every exported sigma descriptor/key and its canonical
Direct statement (including count, order, public role and framing); the exact
18 public lineage words; the selected outer Omega descriptor/key; and the
permitted already public history Z. Any publicly observable choice of proof
shape, selected protocol role or retry/response schedule must also be equal, or
remain an explicitly charged observable. Equal external asset/account state
alone is not this leakage condition.

The private setup logs tau are fixed coherently with this public K, held by the
simulation owner, and identical in the two endpoint experiments. They need not
be included in ell's public view. Fresh endpoint coins are independent of all
pre-coin private histories and Z conditional on the stated setup experiment.
Define a total canonical kernel E_F(K,tau,ell;rho) as follows:

1. For each listed public sigma frame, run the public-input same-F sampler with
   its own fresh coins; retain the whole proof, c/f and suffix, or its exact
   declared endpoint refusal. Counts/order/preflight are public inputs.
2. Draw sixteen independent base-field words on each curve, apply the native
   challenge maps once, and reject any required zero without resampling. Compute
   each full-k16 folded generator from the corresponding sixteen challenges and
   K's exact generator prefix. Retain an identity/error outcome, or construct
   the deciding claims P and V. These are the explicitly defined erased tapes,
   not claimed to be the law of the actual fixed-F salted folds.
3. Compute `D_A=F_kgwomg_1(public18 || P.x || P.y || limbs(P.u[0..15]))` using
   the unchanged native encodings. Construct the Omega Direct frame
   `[[D_A], [V.x,V.y], [V.u[0..15]]]` with its native field conversions.
4. Run the total public-input Omega sampler on that frame and selected key.
   Apply the same public full verification/decisions, framing/size checks and
   proof-transport serialization. A failure is an output of E, not a condition
   under which this kernel is renormalized.

The source map is explicit: `omega/native.rs::lineage_digest` hashes precisely
52 fields; `outer_instances` yields the 1/2/16 columns; `Output::transport`
returns `Omega proof || P.to_bytes() || V.to_bytes()`. The old A proof, A's
69-word private frame, P/V local fold bodies and salts are absent from these
three functions. `a_relation/binding.rs::lineage_digest_fields` implements the
same 18+2+32-word digest in circuit. A deciding claim's generator is reconstructed
from its public challenge vector and K, so it adds no independent input to E.

## Theorem and proof

Let L0,L1 be any two valid source histories sharing the above ell and coherent
setup experiment; they may contain different private Direct frames, witnesses,
predecessor proofs, maps and ephemeral fold sources. Suppose both *fully erased*
terminal proof experiments are the kernel E just defined, including its refusal
law. Then their complete proof-view laws are identical, conditional on K,tau,
ell,Z. In particular the middle endpoint statistical distance is zero, rather
than an additional unexplained epsilon_end.

Proof: use the same rho in both executions. Step1 receives exactly the same
ordered public frames and source keys, so every sampler prelude, point, challenge,
scalar, suffix and error agrees under deterministic F. Step2 reads no L value and
uses equal coins, field maps and generators; all refusals and P/V bytes agree.
Step3 is a deterministic function of the equal public18 and P/V; thus both Omega
Direct frames agree even though the earlier hidden A frames differed. Step4
therefore receives equal complete inputs and coins, so the Omega bytes, public
verification results and final concatenation agree. This is pointwise equality
for every rho; integration proves the claim without conditioning on success.

This factorization is stronger than marginal hiding: P and V are coupled
jointly with every sigma body, Omega response and the residual service F. It
uses the same fixed function throughout, so later free computations of F on
public data cannot separate equal outputs. No fresh-oracle programming or
recursive-FS privacy axiom appears in the proof.

## Exact limits and a necessary counterexample

The theorem does not apply to `Session::restore_transport` with the old genuine
session. That function explicitly requires supplied P/V to equal the session's
retained P/V. Passing independently replaced claims to that old session is
rejected. Replacements must live in the proved erased endpoint/publication
kernel; they cannot be implemented by patching already selected source objects.
The existing source-scoped publication/continuation reductions and their custody
costs are needed to connect that kernel to actual wallet states.

More generally, if a continuation emits `bit(L)` in addition to the kernel's
proof response, histories with opposite bits are perfectly distinguishable even
when all proof bytes are equal. If a continuation discloses a designated old
fold salt plus its inputs, recomputation similarly separates replaced claims.
Thus the exact middle-term conclusion is for the stated proof projection and
any continuation that factors through ell,Z and E's output with a common event
kernel. It is not for unrestricted private-state disclosure or arbitrary wallet
continuations. Public signatures/receipt bytes, storage faults, unacknowledged
adoption, and observed retry schedules need that additional factorization.

## What must connect the real construction to E

Same-frame native-to-sampler comparison replaces an honest proof at its genuine
valid cut. Because the sampler is total on canonical frames, the already-erased
suffix can continue after earlier proof/fold changes without inventing relation
witnesses. The source-coupled compact Send argument is one such local comparison;
it is not a current Omega/A/W catalog result.

The remaining cryptographic edge is actual fixed-F salted-fold output versus
Step2 under the same setup logs and all allowed pre-salt auxiliary state. It
must be joint across adaptive folds and include refusal law. The existing
selected recursive Fiat–Shamir assumption promises knowledge soundness and
accumulation security, which place no distributional condition on this edge.
The hidden-prefix H-ROM lemma proves a different explicitly ideal experiment;
source code that evaluates F does not become that experiment by being hidden.
No efficiency or negligibility for this missing edge is asserted here.

Subject to justified local replacements, the corresponding setup/randomness/
operation/custody bridges and that actual salted-fold comparison, the theorem
removes the cross-history middle term for equal-leakage terminal proof views.
It does not remove those costs or close C12.

## Maintained source map and narrower target

The transport, lineage digest, outer Direct instances and exact old-session
claim check are in [`omega/native.rs`](../../crates/iroha_kagemusha_proof/src/omega/native.rs).
The circuit digest is in
[`a_relation/binding.rs`](../../crates/iroha_kagemusha_proof/src/a_relation/binding.rs).
Claim decoding, encoding and full decisions are in
[`claim.rs`](../../crates/iroha_plonk_recursion/src/claim.rs).
The [recursion argument](../../specs/kagemusha_recursion_soundness_v1.md)
retains the selected assumption and publication/continuation boundaries.
[SALTED_FOLD_PRIVACY.md](SALTED_FOLD_PRIVACY.md) proves that canonical real folds
can replace the independent-tape target in this factorization, under a narrower
but still unproved joint computational comparison.
