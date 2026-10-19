# B6 application reductions for the frontier simulator

Status: **conditional application reconciliation, not qualification**. This
note connects the [new entry argument](parliament_ballot_b6_initial_programming.md)
and [post-entry composition](parliament_ballot_b6_conditional_composition.md)
to the application games in [the original arguments](parliament_ballot_proof_arguments.md)
§§5–6. It explicitly changes the credential experiment's simulator. It does
not revise the frozen arguments, accept a cryptographic premise, or supply a
complete numerical security bound. Development testing remains enabled;
binding production activation remains gated.

The [review record](../docs/validation/parliament_ballot_application_reconciliation/README.md)
identifies the inspected sources and the limits of this checkpoint.

## 1. Two experiments that must remain distinct

Write `Z_F(R_Z)` for a uniform upper bound on the **whole-lifetime** joint
valid-witness experiment with the real prover on one side and one persistent
`IdealFrontierSim` on the other. Both proof roles, the permitted adaptive
continuation and final observation are included. The preceding conditional
derivations give

```text
Z_F(R_Z) = min(1, E_entry + E_AES + K),                          (A-1)
```

at their actual resources and under all their stated premises. `E_AES` is
still unknown; (A-1) is not a numerical certificate. It is not the old `Z`
for real-root `Sim+`. Each use below needs the resources of that complete
application wrapper, including its final event test. A common symbol denotes
a ceiling valid for every wrapper where it is used, not an assertion that
their costs coincide.

Define the proposed credential experiment `P_F^beta` by taking the complete
credential game of the original arguments §5.1 and replacing **both** proof
interfaces' shared `Sim+` by one shared, persistent `IdealFrontierSim`:

- Presample distinct uniform 384-bit honest secrets. Keep commitments
  concrete, including those published before registration or corruption.
- Keep the three test families `PNF1`, `PAU1`, `PAV1`, concrete untested
  outputs, fresh-entry checks, consistent random functions in branch 1,
  and the `Protected`, `Exposed` and `Tested` state and corruption rules.
- Retain actual public validation, authenticated context/list handling,
  malicious registration and submission, public concrete primitive
  computation and the persistent backend-oracle interface.
- Serve public-valid proof requests from their role and complete public
  statement only. Include false intermediate statements and exhaustion in
  the simulator-call budget. Preserve every programming effect and the
  prescribed error behavior.
- Charge the complete reduction: preprocessing, credential computations,
  request handling, simulation, verification, final tests/comparisons,
  oracle realization, time, gates, memory and advice. The experiment inherits
  the original independence restrictions on initial advice.

Let `alpha_F(R_P)` bound the real/random distinguishing gap in this newly
specified experiment. **This is a proposed changed premise.** The old `P`
and `alpha_P`, whose experiment contains real-root `Sim+`, do not establish
it. A separate simulator-switch reduction would have to cover false-input
credential contexts and their retained oracle state to relate the two
premises. The valid-witness comparison (A-1) does not provide that bridge.
Generic claims about SHAKE or a different resource argument do not provide
it either.

Let

```text
rho_rep = binom(U,2) * 2^-384.                                  (A-2)
```

This couples the real independently sampled credentials to the distinct
secrets in `P_F`, including adaptively requested handles by presampling up to
the lifetime cap `U`. It is not a charge for output collisions.

## 2. Why the middle credential hybrids are defined

The sampler's algorithmic totality and its valid-witness comparison are
different obligations. [RegistrationStatement::new/instance](../crates/iroha_parliament_ballot_proof/src/registration.rs)
derive the body/authorization frames and `mu` while accepting supplied
commitment and authorization bytes; they do not test for a secret opening.
[VoteStatement::validate](../crates/iroha_parliament_ballot_proof/src/vote.rs)
checks vote value, sealed-list shape/order, size and list digest. It does not
test whether the nullifier or authorization belongs to a secret. Keeping
the authenticated context/list fixed, substituting those public values and
recomputing the actual `D_v` therefore preserves public validity.

The [sampler](parliament_ballot_b6_ideal_public_sampler.md) §§4, 6–7 produces
canonical, correctly sized opening/material fields and an admissible selected
pattern using the bounded schedule and verified fallback. The fixed relation
stream and [QuickSilver public evaluation](../crates/iroha_zkp_vole/src/quicksilver.rs)
operate on these public fields without a witness-existence test.
[Verifier::finish](../crates/iroha_zkp_vole/src/quicksilver/verifier.rs)
reconstructs `A_0` using field sums and powers; it never divides by `Delta`.
Zero and arbitrary correctly sized field values are allowed. Thus falsity
introduces no new undefined arithmetic or structural rejection in this
mathematical sampler.

This is totality within the source-informed mathematical model. It is not
zero knowledge for false statements, a deployed programmable-oracle API,
an authentication proof for application histories, or a compiler/OS resource
certificate. Invalid external requests retain the common validation path.
The `T` cap counts valid witnessed requests in (A-1), but counts all
public-valid simulated requests, including false ones, inside `P_F`.
The same application request ceiling may bound both without conflating them.

## 3. Anonymity and cross-scope unlinkability

Use the original left/right game, including its disclosure exclusions and
both equality partitions. The complete sequence is:

| Transition | Charge |
| --- | --- |
| Real left world to `IdealFrontierSim` | `Z_F` |
| Independently sampled secrets to distinct secrets | `rho_rep` |
| Concrete challenge credential entries to random entries in `P_F` | `alpha_F` |
| Switch the challenge bit with random entries | `0` |
| Restore concrete entries on the right | `alpha_F` |
| Restore independently sampled secrets | `rho_rep` |
| Restore real right-world proofs | `Z_F` |

The ZK transitions occur before credential randomization and after its
restoration. Honest requests then have real witnesses. In the middle, the
total simulator can serve false statements; no false-statement ZK theorem
is invoked.

For each challenge, test the selected candidate's nullifier entry first,
derive `D_v` from the **actually returned** nullifier and the complete public
context, and then test the authorization entry at that digest. Reserve and
block both candidates as in the original game. Retain symmetric quota/error
handling, both nullifier and authorization equality partitions, protection
after late rejection, and the exclusion of identity-labelled challenge logs.

Couple random nullifier functions by the allowed equality partition. The
same returned bytes give the same actual digest. Couple authorization
functions by their second equality partition. Distinct random entries may
accidentally have equal outputs, and different frames may have equal
digests; the rules use actual bytes/digests, so the same coupling retains
these events. Every public statement and rejection effect then agrees.
Using the same simulator coins and oracle state gives identical continuation
distributions. This proves the zero-charge switch without conditioning away
output collisions or charging a separate digest-collision event.

With uniform resource ceilings for both sides,

```text
Delta_anonymity, Delta_unlinkability
    <= min(1, 2*Z_F + 2*alpha_F + 2*rho_rep).                    (A-3)
```

There is no extra lifetime or handle-guessing multiplier. Unlinkability is
the specified restriction of this game; it does not hide distinctive public
votes, timing, transport, singleton electorates or later disclosure of a
protected secret. Non-frameability retains its reductions to properties 2
and 8 below.

## 4. Authorization and nullifier-counting reductions

Keep the original event inclusions in the **real game**, before simulation.
Their false-statement soundness, existential opening-uniqueness and legal
frame-collision terms remain real-game premises. Only the remaining
efficiently testable fresh-authorization event is transferred with (A-1).
The challenger knows its honest secrets and can test that event. No
reduction decides arbitrary language falsity or extracts a witness.

The prediction experiment has concrete disclosed credential outputs, both
proof interfaces supplied by `IdealFrontierSim`, and no `Test` call while
the predictor runs. After its output list is fixed, reserve eligible honest
uncorrupted targets and test the fresh authorization entries. The concrete
branch recognizes a correct guess. In the random branch each fresh entry is
uniform over 512 bits; a union bound over the committed guesses works even
with repeated guesses. This yields

```text
Pr[fresh authorization prediction]
    <= rho_rep + alpha_F(R'_prediction) + q_guess*2^-512.       (A-4)
```

Freshness is per handle, family and digest. Other-handle or other-family
disclosures remain allowed. Log each authorization and complete statement
before exposure, including proving failure/exhaustion. The issued nullifier
set likewise includes exposures followed by failure. Simulator errors do
not erase either application logs or oracle writes.

Consequently, with every right side clipped at 1 if needed,

```text
epsilon_2 <= s_mix + delta_tag,target + CR_vote
             + Z_F + alpha_F(R'_V) + rho_rep + 2^-512;

epsilon_3 <= s_batch + delta_Com,seal + CR_vote,batch
             + Z_F + alpha_F(R'_batch) + rho_rep
             + 1,001,000*2^-512;

epsilon_8 <= s_mix + delta_Com,target + CR_reg
             + Z_F + alpha_F(R'_R) + rho_rep + 2^-512.           (A-5)
```

Here `s_mix` and `s_batch` are applicable soundness bounds with real honest
proof interfaces, not bounds in a programmed credential hybrid. The `delta`
terms are the original existential uniqueness restrictions; ordinary
computational collision resistance does not replace them. `CR` refers to
the corresponding legal authorization-frame collision event in the real
game. Registration's target-context uniqueness includes contexts never
sealed. None of these terms receives a numerical value here; candidate
soundness is not automatically comparator soundness.

For property 3, retain at most 1,001 relevant ballots. Outside real-game
false acceptance, sealed-commitment ambiguity and frame collisions, more
than `k` distinct non-issued nullifiers require a fresh correct authorization
for some honest sealed entry: each of the `k` controlled entries explains
at most one nullifier. Controlled entries include malicious registrations
whose creators know no opening. Enumerating at most `1001*1000` ballot/handle
pairs recognizes the event and produces one prediction list. This pays one
joint `Z_F` and one `alpha_F`, with no additional factor of 1,000 or `U`.
All enumeration, digest computation, final verification and comparisons
must be charged. If a different application interpretation requires proof
of honest registration origin, it must additionally charge property 8 as
specified in the original argument.

## 5. Query budgets and full resources

The default `Q_all=2^64` in the new arithmetic reports is an illustrative
**aggregate non-prover** ceiling. It does not convert the profile §8.8
requirement of an adversary budget `2^64` plus all actual overhead.
Conversely, the original arguments §6.1 define `q_pub` to include adversary
queries **and** backend calls induced by public verification, registration
and submission. Those calls must not be added to `q_pub` twice.

`q_pub` can serve as `Q_all` only after showing that its charged interface
includes the same diagnostics, invalid-input paths, preprocessing and access
through final observation. For an adversary-only ceiling, a disjoint ledger
instead needs a conversion of the form

```text
Q_all <= q_adv + sum_h(n_h*b_h) + q_other,                       (A-6)
```

where classes `h` partition additional non-prover requests, `n_h` bounds
their counts, `b_h` bounds their actual backend calls, and `q_other` counts
remaining non-prover backend evaluations without overlap. Relation-valid
prover count `T`
does not bound invalid requests or public diagnostics. Request count alone
does not supply `b_h`; lengths and allowed interfaces matter. The
[candidate request accounting](parliament_ballot_b6_request_accounting.md)
has a scoped normal-path `0/1/744` backend-call partition, not a universal
bound for every interface or for the comparator.

For illustration only, separate caps `q_adv=2^64` and `2^64` full candidate
verifications permit a subtotal `(1+744)*2^64` in (A-6). This workload is
**excluded** by a simultaneous aggregate cap `q_pub<=2^64`; it is not added
to such a cap. An actual conversion still needs all other classes. The
entry theorem's dispatcher then uses `2*Q_all+T`; its doubled target calls
are not another set of application queries to add back into `Q_all`.
Soundness certificate/final-verifier constants have their own defined
boundary and likewise must not be charged twice.

The required resource vector also includes concrete credential/frame hashes,
actual revealed-subtree AES, fresh frontier randomness, one nested VOLE
reconstruction, public relation evaluation, up to `2M` schedule trials,
programming and coherent persistent lookup, controller/preparation, memory,
advice and final observation. Base QROM functions supplied to a mathematical
reduction do not by themselves implement independent oracles at finite cost.
The frontier/reconstruction counts describe the endpoint sampler. Earlier
root/path/leaf/row reductions also execute real or mixed full commitment and
proof generation throughout the lifetime; endpoint costs alone do not bound
those drivers.

There is already a construction-level efficiency limitation. The captured
[request-machine observation](../docs/validation/parliament_ballot_request_machine/README.md)
prices a specified candidate VOTE body at
`166702860207775482442106240502206` elementary gates per request with
`T=2^44` persistent-log capacity. Repeating that fixed body circuit `T` times
costs exactly

```text
2932667730911459172349823042824132140461981696 > 2^151
```

in its `X+CNOT+5*Toffoli` convention, before external lookup, base-function
implementation and controller costs. This is the cost of that explicit
construction, not a family maximum, a lower bound on all reductions, a
protocol runtime estimate or an attack. Elementary gates cannot be equated
with the old nominal AES-block/Keccak subtotal. These counts supply no
quantitative AES bound; a justified bound must use the full resulting
resources, or a more efficient construction.

## 6. Remaining qualification work

The application joins (A-3)–(A-5) are now conditional derivations for the new
simulator. They leave quantitative `P_F`, AES, soundness, uniqueness and frame
premises, the backend model, full resources and independent review open.
Neither the older ledger's numbers nor the new known-term arithmetic becomes
a complete application-security bound by substitution.

TODO: construct and price the complete oracle environment for one
whole-lifetime root reduction, beginning with the total source-domain
dispatcher and persistent overlay. Distinguish a supplied oracle-relative
environment from a finite-cost independent-oracle implementation. Establish
the actual adversary/request budget conversion and assess a more efficient
overlay before extending the primitive resource ledger. The other material
families share this unresolved boundary. This work does not require delaying
the already-authorized development and integration tests.
