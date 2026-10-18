# B6 adaptive hidden-assignment deletion

Status, 2026-10-13: **conditional derivation locally reviewed**. This note defines
the unpatched baseline at the same ideal-material boundary as the frozen
[mask-coordinate note](parliament_ballot_b6_mask_coordinate.md). It proves
a query-bounded comparison with `IdealPublicPatched` by keeping its private
assignment log in both experiments and changing only the lookup operation.
The comparison covers the full adaptive execution, not just proof bytes.

The computational entry, real-material bridge, complete resource vector,
independent review and qualification remain open. The earlier notes,
[arguments](parliament_ballot_proof_arguments.md) and ledger are unchanged.
The separate [receipt](../docs/validation/parliament_ballot_hidden_assignment_deletion/receipt.json)
pins source and theorem identities; no numerical ledger term is adopted.

## 1. Entry and the same-material baseline

Use exactly the ideal boundary and totalized `PatchH5_slots` endpoint of
the mask note. In particular, retain the same joint distribution of BAVC
commitment/opening material, revealed rows and cached generator values.
Do not substitute a real-root BAVC sampler. The selected-row and independent
high-mask entry premises are still prerequisites to reaching this boundary.

There are at most `T` valid, classical, atomic requests across both roles
and rows. Each has a fresh independent 256-bit pad `P_t` and 256-bit salt
`S_t`. Initial advice, oracle functions and other coins are independent of
these fresh pads and salts; previous quantum oracle access is retained.
Application witnesses and their auxiliary information may be arbitrarily
correlated across requests. Requests may adapt to the complete preceding
observable execution. Invalid requests follow the same rejection path.

Write `A_(t,e)` for the **32-byte visible label** of gate `e`, and
`Enc_(t,e)(A)` for the full 162-byte address
`PREFIX_R || IV_t || S_t || LE32(e) || A || 05`. Label XORs below act
only on those 32 bytes. The separately indexed `A_0,...,A_6` are the
QuickSilver field coefficients, as in the mask note.

For a request, run the following public computation with the entered
ideal-material sampler:

1. Compute the actual namespace, statement digest and IV. Obtain the bounded
   primary schedule and selected admissible opening, with the same bounded
   auxiliary sampler and zero fallback on exhaustion as before.
2. Retain the entered commitment/opening distribution. Sample canonical
   uniform `c_1,...,c_(tau-1)`, gate corrections `C_e`, and witness correction
   `d`; `c_0=0`. Reconstruct the head columns and visible labels `A_e`.
3. Cache each visible value `V_e=H5(Enc_(t,e)(A_(t,e)))` before installing
   any hidden assignment for this request. Reconstruct `Q,qbar,Delta` from
   these values.
4. Sample the prescribed independent challenges 1 and 2, four uniform
   consistency fields and six uniform transmitted coefficients. Compute
   `Vtilde` and `A_0` by the public equations (M-9) and (M-10).
5. Make the same challenge-1/2 writes and every attempted primary counter
   write at the exact resulting transcript locations. Return the same
   proof or typed exhaustion. Keep all prior effects on exhaustion.

The placement of step 4's private challenge samples may be moved earlier,
as in the entered game; the sampling distribution and resulting writes are
unchanged. This baseline does not condition on actual hash outputs to make
those samples independent. The chosen opening can be fixed or any of the
independent mixtures allowed by the preceding notes.

Augment the public algorithm with **private bookkeeping**. Sample `P_t`,
put `U=w(P_t) XOR d`, recover all ten masks by (M-7)/(M-8), and record

```text
X_(t,e) = PREFIX_R || IV_t || S_t || LE32(e)
            || (A_(t,e) XOR d_(P,t) XOR P_t) || 05
Y_(t,e) = C_(t,e) XOR V_(t,e) XOR F_e(a_t).                    (D-1)
```

Append the records in the frozen chronological order after the visible
cache is complete. Keep an ordered log `L` of all records. Equal addresses
are permitted; the latest active record wins. The cached-slot exceptional
branch from the mask note is retained exactly. No ordinary lookup at a
hidden address is needed to create a record.

`IdealPublicPatched` answers H5 from the base function with this log as an
overwrite overlay. Define `IdealPublicLogged` to run precisely the same
code, including private mask recovery and record creation, but answer H5
from the base function while ignoring the log. Finally `IdealPublic` omits
that unused bookkeeping. These are three named experiments; only the last
has no private pad/witness bookkeeping.

## 2. The noninterference invariant

In `IdealPublicLogged`, the entire public computation and its quantum
query state are independent of the vector of fresh pads. This is a
statement about the unpatched baseline, proved by its dependencies:

| Operation | Inputs relevant to the invariant |
| --- | --- |
| Ideal material and selected opening | Retained sampler, statement, actual IV and independent schedule; no pad or recovered mask |
| `Q`, visible labels and `qbar` | Revealed rows, `c_i,C_e`, selected opening and cached ordinary H5 values |
| Public responses, `Vtilde`, `A_0` | Public samples, prescribed challenges, `Q,qbar,Delta,d` and the public relation evaluator |
| Challenge writes and primary stopping rule | Those public values and the prescribed counter schedule |
| Private masks and hidden records | May depend on pad/witness; outputs go only to private records/scratch |
| Later oracle responses in this baseline | Base H5 and common other-domain state; never the private log |

The six triangular and four additive inverses are total on every field
input, including `Delta=0`. They do not have a pad-dependent failure,
acceptance test or retry. Used/unused row coordinates are handled as in
the mask note. All sampled fields are canonical and dimensions are fixed.
No query address, visible result, error, timing trace or later material
choice is allowed to depend on private recovered masks or records. This
is the abstract atomic experiment, not a claim about implementation timing
or faults. Source wrappers do not enforce the fresh-pad entropy premise.

Induct over public operations and classical requests. Before a request,
the pad-free public state and adversary registers have the claimed product
law with all latent pads. Public samples, base-oracle queries and public
challenge writes preserve it. The adversary's next query or measured
classical request is a channel on that pad-free state, so also preserves
it. Private bookkeeping at a classical request copies functions of already
classical game values into private scratch and the log and has no feedback
into that state. Tracing those private outputs restores the same public
state. Thus the invariant holds throughout, including after exposing
`d`, the six coefficients and the four consistency responses.

More precisely, let `Z_j` contain all pad-free classical driver history
needed at a lookup, including prior visible labels, correction prefixes,
salts, material, prescribed challenges and schedules. Let `B_j` contain
the adversary/query registers and the rest of the pad-free oracle state.
After tracing private pad-dependent scratch and log, the baseline state
has the form

```text
rho_(P,Z_j,B_j) = Uniform(P_1,...,P_T) tensor rho_(Z_j,B_j).    (D-2)
```

Conditioning on a value of `Z_j`, or on the initial base function, does
not break (D-2). Its assertion does not extend to conditioning on the
private log or recovered masks. Those can reveal pads. It also does not
extend to the actual patched oracle or the patched adversary's state.
The proof below needs only baseline query mass, not post-query conditional
entropy in the patched experiment.

## 3. Fixed reversible lookups and adaptive history

Represent H5 by one retained base table `H` and the chronological log `L`.
For each finite distinguisher, fix sufficient finite register widths and
the bounded log capacity. An H5 address has the injective 162-byte encoding
checked in the initial H5 note; invalid encodings and other domains are
handled identically in both experiments.

On the combined input `(enable,X,Y;H,L,K)`, where `K` includes all common
other-domain state, define two fixed permutations:

```text
P_0: if enable, XOR the ordinary base/domain answer into Y.
P_1: if enable and X is a valid H5 address with active matches in L,
         XOR the value in the latest matching record into Y;
     otherwise perform P_0.
```

All other registers are unchanged. Both are response-XOR permutations and
are self-inverse. They are fixed functions of the complete input, even
though the driver adaptively changes the tables and log supplied to them.
When `enable=0`, both are identity; this supplies harmless padding up to
the chosen query bound. For a combined backend query, the non-H5 branches
perform the same operation coherently. If a surrounding interface exposes
additional H5 output bits, the overlay replaces only the specified ten bits
and leaves those other bits unchanged in both operations.

All code between lookups is identical in the two experiments, including
mask recovery, log appends and challenge writes. A lookup can change later
public values, later requests and consequently later log contents; none is
held artificially equal between runs. The common driver recomputes them
from the values in its own run. This is why the pair is represented as
fixed permutations on the evolving state rather than two static functions
whose difference set was chosen in advance.

Classical measurements, erasure and overwrite can be dilated by retaining
the outcome and old registers privately. This gives common isometries
between lookups. The driver never supplies an address chosen by reading
its private log; in particular it performs no hidden-label verification
or diagnostic query. A generic distinguisher with direct log access would
not satisfy the invariant or the bound.

An observable result means any final adversarial measurement after its
allowed future queries. This is not a bound on revealing a complete
expanded oracle table or on the distance between a literal patched table
and a base table after deleting private state. The shared representation
and the restricted query interface are essential.

## 4. Joint difference-projector mass

Presample `T` salts, including unused slots. Let `G` be the event that all
are distinct. Salt has 256 bits, whereas IV has 128 bits. Consequently

```text
Pr[not G] <= binom(T,2) * 2^-256 = delta_salt.                (D-3)
```

`G` is independent of every pad. Conditioning on `G` changes the salt
distribution but preserves the product law (D-2). No condition on
`U_P != 0`, oracle collisions or the log is imposed.

Fix a baseline query position and a pad-free classical history `Z_j` in
this good-salt experiment. Let `p_j(x | Z_j)` be the distribution obtained
by measuring its address register, including an enable flag. This
distribution is independent of the pads even after arbitrary preceding
quantum queries, by (D-2).

For each enabled valid encoded address `x`, its salt identifies at most
one active request `t`; its gate field identifies at most one of that
request's records. The namespace and IV can only remove matches. If such
a record exists, membership in its hidden-address set forces

```text
P_t = label(x) XOR A_(t,e) XOR d_(P,t).                       (D-4)
```

The right side is fixed by `x,Z_j`. All gates of this request share `P_t`;
their labels are not independent, and no independence between them is
assumed. Nevertheless each individual address has at most one matching
pad value. Thus, averaging over the jointly independent pads,

```text
E_P Pr[queried address is an active hidden address | Z_j,G]
  = sum_x p_j(x | Z_j,G) Pr_P[x is active | Z_j,G]
  <= 2^-256.                                                (D-5)
```

The same reasoning applies when `Z_j` and the query distribution adapt
to earlier oracle responses and proof requests. It uses the baseline's
joint product state, not a marginal claim that each hidden label is
uniform in isolation. On a disabled or non-H5 branch the mass is zero.

Let `Pi` project onto complete lookup inputs where `P_0` and `P_1` differ.
Such a difference requires an active hidden-address match. The additional
requirement that the assigned value differ from the base answer only
shrinks the projector. The latter event may depend on private masks and
pads, so it is deliberately not factored or conditioned on. Equation
(D-5) therefore gives

```text
E[ ||Pi |psi_j^0>||^2 | G ] <= 2^-256,                       (D-6)
```

where `psi_j^0` is the full baseline pre-query state, including private
registers in any purification. Although that full state need not factor
from the private log, the diagonal address-match expectation uses only
the marginal (D-2). This distinguishes the valid claim from conditioning
on a log that already specifies the hidden point.

## 5. Quantum comparison and query convention

The primary fixed-permutation formulation is Jaeger,
[Nonadaptive One-Way to Hiding Implies Adaptive Quantum Reprogramming,
arXiv:2511.16009v1](https://arxiv.org/pdf/2511.16009v1), §1.1 and Theorem 1
in §2.1 (PDF page 8). Its measured-query game runs the baseline permutation
and tests whether the other permutation differs on that full input. It
therefore permits the evolving private log in §3.

Here the needed inequality also follows directly. Telescope the two
dilated executions using a baseline `P_0` prefix before each changed
lookup and a `P_1` suffix afterward. The suffix is norm-preserving; the
common inter-query operations are the same. On any input state,

```text
||(P_1-P_0)|psi>|| <= 2*||Pi|psi>||.
```

Triangle inequality, averaging over classical initial coins and Jensen's
inequality with (D-6) bound the final state-vector distance by
`2*N*2^-128`. The difference in any final output probability is at most
that distance. Mixed auxiliary states are handled by purification. No
hybrid query-mass estimate is made in a patched prefix.

Let `Q` bound all external combined-backend quantum evaluations in the
full lifetime, including before, between and after proof requests. Let
`g_t` count the current row's visible H5 calls in request `t`. The cached
public driver makes one such call per gate, with `g_t<=704`. Private
record generation requires none. It is safe to use

```text
N = Q + sum_t g_t <= Q + 704*T.                              (D-7)
```

Each combined evaluation is one call to the full fixed permutation here;
this is not the two-query fixed-gate dispatcher of the initial H5 proof.
Any implementation using an extra lookup/unlookup must count it. Later
verification or diagnostics are included in `Q`, or added explicitly if
performed by the surrounding honest driver. Other-domain work, reversible
gates and private memory have not become free computational resources.

All current visible queries precede the request's log appends. With unique
salts they cannot hit previous requests' records. The conservative bound
(D-7) nevertheless retains their cost; no ledger reduction is claimed.

Both experiments have the same probability of `G`, since salts are fresh
presampled coins. Split their unconditioned output probabilities over
`G` and its complement. On the complement bound their conditional
difference by one; do not separately charge each experiment. Therefore

```text
|Pr[IdealPublicPatched outputs 1] - Pr[IdealPublicLogged outputs 1]|
  <= min(1, 2*N*2^-128 + binom(T,2)*2^-256).                  (D-8)
```

There is one salt-collision term outside the square root. This new local
derivation does not remove any conservative exceptional terms already
retained in the frozen outer ledger. The logical-slot totalization and its
earlier own-label coupling charge also remain as previously specified.

## 6. Removing bookkeeping, exhaustion and remaining boundary

In `IdealPublicLogged`, pads, recovered masks and the log are never read
by public routines or by any oracle answer. Omitting those computations
gives `IdealPublic` with exactly the same joint public transcript,
adversary state and future base-oracle interface. This is an exact
noninterference equality after tracing unused private bookkeeping, not
an additional oracle reprogramming step. `IdealPublic` needs no pad or
application witness for the public formulas.

No abort is introduced for an own-label equality or conflicting record.
Both logged experiments remain total with chronological overwrite. On
exhaustion the private selected opening still drives the same public
equations and log generation; no opening is published. Every primary
counter write and all earlier state changes remain. The auxiliary search
only selects private material, and its fallback or bounded stopping law
does not depend on pads. Thus (D-2) and (D-8) include exhaustion without an
acceptance-probability factor.

Both roles and rows are in the same game with one lifetime pad/salt list
and one log. Their differing namespaces and gate counts require no
independence of application witnesses or multiplication by the number of
roles. All prior and future query histories remain in the comparison.

Together with the frozen exact middle equality, this proves conditional
oracle removal at the **same ideal-material boundary**. The unchanged
real-root `Sim+` does not yet have that material distribution. Reaching
this boundary from actual generators, reaching an accepted final simulator,
and giving the full computational quantum resource costs still require
the separate reductions identified by the preceding notes. This note
does not establish a production qualification or independent review.

The root and ownership agents completed local mathematical/source
consistency reviews of this derivation and read the primary fixed-
permutation formulation. These reviews do not attest owner acceptance,
independent cryptographic review, or the unresolved entry/material/resource
requirements.
