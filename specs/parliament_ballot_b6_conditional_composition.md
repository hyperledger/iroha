# B6 conditional composition to the public frontier simulator

Status: **conditional argument and arithmetic, not qualification**. The
post-entry stages below compose under their common experiment and primitive
premises. The original real prover still needs its initial challenge-programming
reductions. AES advantages, complete reduction resources, model acceptance and
independent review remain open. Development testing is enabled; binding
production activation remains gated.

This is a separate derivation. It does not revise the frozen
[security ledger](parliament_ballot_b6_security_review.md), identify its real-root
`Sim+` with the new endpoint, or replace its terms piecemeal. The
[calculation](../scripts/parliament_ballot_conditional_composition.py) and
[validation record](../docs/validation/parliament_ballot_conditional_composition/README.md)
retain that distinction.

## 1. One experiment and one observation boundary

Use the [bounded hybrid driver](parliament_ballot_b6_hybrid_driver.md): an
adaptive environment makes classical atomic requests and retains quantum state
and backend-oracle access across the whole lifetime. The outer experiment
checks the application witness before invoking the witness-free public
simulator. Application witnesses may be reused, correlated or adaptively
chosen; the environment cannot choose or disclose honest fresh tapes, pads or
private logs. No within-request timing, cancellation or allocation trace is an
output of this experiment.

Let `T` bound valid proving invocations, including those that exhaust, jointly
across both roles and rows. Invalid requests follow the same outer path in
every game; their resources are not bounded by `T`. Let `Q_all` bound every
non-prover combined backend evaluation, including preprocessing, interleaving,
verification, permitted public diagnostics, relevant invalid-request checks
and access after the final proof. Count actual lookup/unlookup calls. Any
additional surrounding honest evaluations must be included in `Q_all` or
added explicitly. Counting a query does not authorize access to private state.

All comparisons end at the same final measurement within that budget.
The source's actual H4-derived IV and previously programmed oracle state
persist. Distinct slots may have equal key bytes. Writes overwrite in
chronological order, including on exhaustion. No global IV, key, hash-output
or salt-distinctness condition is introduced at this boundary.

`B_0` already uses prescribed independent challenges 1/2 and the bounded
opening schedule. Their law is not obtained by conditioning on actual hash
outputs. The schedule supplies the same primary values, stopping result and
private auxiliary/fallback opening throughout this chain. Each game's write
locations are computed from its own material; coupled equal material gives
equal locations. Failed invocations keep all required primary writes and
never publish their auxiliary opening.

## 2. Adjacent stages and their joins

| Transition | Bound or identity | Required join |
| --- | --- | --- |
| `B_0` to `FullMaterial/RealH5` | `E_AES + E_switch` | [Root](parliament_ballot_b6_root_entry.md) and [material entry](parliament_ballot_b6_material_entry.md) use the proposed chosen-input AES/`Γ` game; each parent reaches independent outputs before the child-key embedding. Full selected rows and root high-mask coordinates become independent; H5 stays real. |
| `FullMaterial/RealH5` to `PatchH5_slots` | `E_refresh + E_own` | [H5](parliament_ballot_b6_h5_fixed_opening.md) refreshes one fixed gate domain at a time over the full lifetime. Select its logical-slot endpoint directly using the one own-label coupling. |
| `PatchH5_slots` to `IdealPublicPatched` | Exact joint change of coordinates | [Ten-mask bijection](parliament_ballot_b6_mask_coordinate.md) retains the pre-assignment visible H5 cache, hidden addresses/values, all challenge writes and future oracle state. Its inverse is total, including zero challenge. |
| `IdealPublicPatched` to `IdealPublicLogged` | `E_delete` | [Deletion](parliament_ballot_b6_hidden_assignment_deletion.md) uses joint pad independence only in the unpatched baseline. Oracle lookup changes; the same private log bookkeeping remains. |
| `IdealPublicLogged` to `IdealPublic` to `IdealFrontierSim` | Exact observable identity | Trace unused private bookkeeping, then apply the [direct frontier sampler](parliament_ballot_b6_ideal_public_sampler.md). The public transcript and future bounded interaction agree under a coupling. |

The coordinate change preserves a pad-dependent programmed oracle; it does not
itself remove that dependence. Deletion compares bounded observations, not
expanded oracle tables. The final sampler identity is after private-state
projection and does not provide a secret root/tree representation for the
new simulator.

The H5 logical-slot convention caches every visible value before hidden
assignments. Running ordinary reconstruction again afterward is not the same
algorithm and would add queries. At a nonzero hidden offset it agrees with
ordinary refreshed H5 processing. At zero offset the single `E_own` charge
permits the totalized endpoint directly; a second charge for changing
totalization would count the same exceptional event twice.

## 3. Quantitative composition

Write `F(q,p) = sqrt(q*p) + q*p/2`. Let `E_AES` be the sum of advantages of
the actual whole-lifetime root/path/leaf/row drivers at their full resource
vectors. Private primitive challenge queries are classical, while the
persistent `Γ` environment must support the required quantum interaction.
No numerical value of `E_AES` is supplied here.

For at most `T` valid invocations, the uniform mixed-row ceilings give

```text
E_switch  = T * 2,892,601 / 2^128
E_refresh = 704*T * F(2*Q_all + 2*T, 2^-512)
E_own     = T / 2^256
N         = Q_all + 704*T
E_delete  = min(1, 2*N / 2^128 + binom(T,2) / 2^256)

K = E_switch + E_refresh + E_own + E_delete

Adv(B_0, IdealFrontierSim) <= min(1, E_AES + K).                 (C-1)
```

`E_switch` includes each root/path/leaf/row permutation-to-independent-output
switch once. It is not added to the frozen PRP-native exponential factor for
those same transitions. The coefficient follows
`10 + 260*6 + 33*(36 + binom(419,2)) = 2,892,601`.

The refresh term uses the conservative fixed-gate dispatcher from the H5
note: at most two target-oracle calls per combined external evaluation and
two honest selected-gate reads per invocation. This is the direct
[GHHM Figure 2/Theorem 1](https://arxiv.org/pdf/2010.15103v2#page=7)
application already specified there. It has no extra role multiplier.
Deletion instead uses one combined lookup per external evaluation and one
cached visible H5 read per gate. Its sharper actual count is
`Q_all + sum_t(g_t)`; `704*T` uniformly bounds that sum. These are different
reductions, so their query counts must not be conflated.

The deletion salt-collision term is paid once. H5 refresh allows repeated
salts and chronological collisions without an additional union bound. The
same bounded schedule/fallback is used on both sides throughout; this chain
adds no exhaustion slack or inverse acceptance-probability factor.

To start from the actual real prover, a separate established initial-entry
bound `E_entry` would be needed:

```text
Adv(RealProver, IdealFrontierSim) <= min(1, E_entry + E_AES + K). (C-2)
```

This is a conditional schema, not a completed real-prover result. The older
initial-programming text states entropy figures and counterwise transitions;
their protocol-specific joint samplers, adjacent-game equivalences and query
dispatch still require an explicit audit. The old `Q+T` accounting cannot be
silently mixed with the H5 note's documented two-query convention. This note
assigns no value to `E_entry` and adopts none of the old numerical entry terms.

## 4. Executable arithmetic and remaining work

The helper computes exact rational components and rational lower/upper
enclosures of the square root. With fixed scale `s = 10^120` and rational
`x = n/d >= 0`, set `k = floor(sqrt(floor(n*s*s/d)))`. The lower endpoint is
`k/s`; the upper is equal only when `k*k*d = n*s*s`, otherwise `(k+1)/s`. A
rational square need not have its square root on this decimal grid. The two
squared endpoints enclose `x` by integer comparison. Decimal strings and
logarithms are display approximations, never qualification decisions.

The report's interval encloses **the formula `K`**, not an adversary's
advantage. In particular its lower endpoint is not a security lower bound or
an attack. The default illustrative ceilings are `T=2^44`, `Q_all=2^64`.
The separately reported `min(1,K)` still omits unknown terms; it is not a
complete security bound. The helper keeps entry, AES and full-resource fields
`null`, reports `qualified=false`, and makes `--require-qualified` exit 2 for
every input, including zero invocations.

**TODO:** establish the real-prover entry lemma; price the complete adjacent
drivers and supply justified or explicitly accepted AES/QROM premises;
reconcile this distinct simulator with all dependent anonymity/authorization
reductions; complete the concrete ledger and independent attack-cost review.
Current scope hashes authenticate this source-informed derivation and
arithmetic only. Historical receipts retain their own inputs; changed whole
files are not reauthenticated by matching excerpts. Hardware and full native
resource qualification remain separate requirements.
