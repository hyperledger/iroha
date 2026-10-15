# Non-hiding IPA polynomial and transcript controls

**Retained model scope.** This package models the earlier non-hiding salted
fold, with the source versions and hashes named below. The selected C12
construction instead uses an opened D commitment and 32 W masks, total actual
round challenges, and a scoped full-group suffix; its private witness is 2,176
bytes. The recurrence, first-L argument and transcript counts below retain
their original hypotheses. They are not tests or a privacy theorem for that
selected construction. Existing source manifests must continue to refuse
changed bodies until the model and its source joins are independently updated;
do not refresh their pins as a documentation fix. See the
[transfer boundary](../../specs/kagemusha_recursion_soundness_v1.md#retained-arguments-and-selected-source-transfer).

Run the standard-library Python controls from the repository root:

```sh
python3.12 -B -m unittest discover -s formal/kagemusha_fold -p 'test_*.py' -v
```

The original polynomial controls check the algebra in the
[conditional honest-fold abort bound](../../specs/kagemusha_recursion_soundness_v1.md#conditional-honest-fold-abort-bound).
The symbolic recurrence follows `accumulation.rs::create_fold`: combine the
ordered source coefficient vectors with powers of alpha, subtract H(z) from
coefficient zero, form each L/R point, then fold a with inverse u and b/g with u.
Source vectors are generated independently from the bit-product definition.
Logs model an additive cyclic group, including adversarially dependent generators.
No discrete-log independence is assumed by the tested polynomial claim.

For one through four rounds, the tests verify the exact leading z coefficients
after clearing Laurent denominators, the nonzero top coefficient and the total
degree bounds. Finite-characteristic cases use dependent generator logs and
compare the symbolic expressions with a separate scalar recurrence. Short-only
sources make the first L identically zero; removing the evaluation shift changes
R's leading coefficient. These negatives check two essential hypotheses.
The sum of the degree bounds is also checked at native k16: its coefficient is
3,015,170 + 32(m−1), before multiplying by the mapped challenge's maximum atom.
An exhaustive one-round experiment over the field of order17 counts every
zero/identity event for three dependent-generator choices, including tapes
after an earlier exceptional message, and checks the stated union bound.

`source_manifest.json` binds the inspected three native sources and these three
control files. The exact inventory and hashes are checked during the suite.
This is a source-consistency check, not authenticated artifact admission. Nothing
under `target/` or any external Python package is needed.

The all-k mathematical derivation remains in the linked memo; bounded symbolic
examples do not constitute a general theorem prover. These polynomial controls
produce no native proof and do not model RP57 or actual challenge independence.

The separate `transcript.py`/`test_transcript.py` controls execute the unchanged
standard-library RP57 reference arithmetic, with the exact two small native
constant tables checked against the retained KAT constants. They reproduce the
two Rust PIPA-AS prelude KATs, check canonical scalar limbs/maps and trace every
primitive input/output for all nineteen squeeze calls. A separate block scheduler
checks the carried state, padding and counts `52+ceil(35m/2)` for Pallas and
`52+ceil(19m/2)` for Vesta. Empty/even/odd buffers and the logical-history padding
alias are explicit cases. The unmodified reference reader checks final scalar
absorption and the unabsorbed generator suffix without a later squeeze.

These traces use syntactically canonical messages. They do not assert the
non-hiding IPA equation or generate a fold proof, a key or a size65536 generator
vector. Mutated messages demonstrate schedule sensitivity or expected lack of
later absorption; unchanged prior challenges do not make a bad witness valid.
Missing/changed sources and invalid/unbounded inputs refuse. The separate exact
`transcript_source_manifest.json` pins these controls, their reference imports,
native/circuit schedule sources and the Rust KAT test. The original algebra
inventory and mathematical assertions remain unchanged; source refreshes are
reviewed separately below.

Transcript agreement supplies no fresh-answer law for fixed public RP57. The
conditional ideal-permutation first-hit argument still needs its salt/capacity
interface and shared-oracle assumptions; these controls do not instantiate or
test that security theorem. Neither control group establishes adaptive privacy,
entropy or resource guarantees, recursive continuation, C12, current artifact
validity or release qualification. No external Python dependency or `target/`
input is needed.

The current source refresh compares the former IPA module from commit
`6df11a47f7bc51ace2384696196b8507faf192c2` and accumulation circuit from
`4d4385af26803909b2800570a3ea1899d07b2393` with their bodies in
`687058065dcf6a461b1953d8f975ec9589f8578d`. The IPA module adds bounded,
parameter-owned memos and embedded-parameter loading; its coefficient recurrence,
parameter digest and trusted decoding checks are unchanged. The circuit's only
change delegates its deciding dummy's ordered generator sum to
`PinnedParams::generator_prefix_sum`. That method performs the same ordered sum
after the same domain bound, retaining a point only inside its immutable
parameter owner. The circuit still rejects an identity dummy. Its transcript
schedule is unchanged. The transcript inventory now includes both the parameter
owner and the delegated sum implementation, with missing-role and changed-body
controls. This refresh does not qualify the separate public-column memo, embedded
artifacts, current setup or any native proof.

The separate `ideal_game.py`/`test_ideal_game.py` controls implement a finite
partial-bijection game. They never call RP57. A private path begins at its first
salt-bearing input `(initial_capacity, domain, salt)` and carries each output's
capacity through rate-two absorption. Its supplied output tapes disclose only
one rate coordinate. Public attempts name both primitive endpoints, including
inverse, replay and refused-candidate attempts. These endpoint records must be
independent of private salts/capacities given the disclosed words; the Python
model cannot infer that hypothesis from arbitrary caller data. The common initial
capacity must be fixed before, or independent of, the virtual private output
capacities, conditionally on disclosed words. Choosing it after seeing the
private capacity tape is an explicit hypothesis-violation control.

The conservative bad event charges fresh salt collisions, a private output
capacity equal to the common initial capacity or an earlier private capacity,
a public endpoint equal to a salt-bearing initial input, or a public endpoint's
capacity equal to a private output capacity. With B fresh attempts, H private
edges and Q public attempts, independent uniform virtual salt/capacity tapes
(conditional on disclosed words) give

`min(1, [2Q(B+H) + B(B-1)/2 + H(H+1)/2] / p)`.

Each public attempt contributes two endpoints, each guessing at most one salt
per initial path and one value per private capacity. Salt-pair and private
capacity-pair/initial collisions give the remaining terms. This is an
unconditioned first-hit union bound on complete virtual tapes, not a claim that
secrets remain uniform after conditioning on prior misses. On no-bad tapes,
private inputs have distinct capacities except for the distinct salted initial
inputs; private outputs have distinct capacities. Their consistency with the
public table follows from the excluded endpoint hits. Input/output vertex
coalescence within a path is legal: only duplicate inputs with different outputs
or duplicate outputs with different inputs violate a permutation. Rejected
attempts retain all earlier edges. Coupling a genuinely random permutation still
requires the stipulated hidden interface and its sampling model.

Nine additional controls include every one of 83,521 independent p17 single-edge
tapes, with 13,889 bad tapes and 69,632 no-bad tapes, below the nonvacuous 5/17 bound.
A separate 2,187-tape two-edge case checks carried capacity and exact replay even
when its probability bound is vacuous. Forward/inverse conflicts retain their
original table, and same-salt changed-input attempts cannot masquerade as retained
replay. Deliberately leaking a salt/capacity or basing public admission on private
table occupancy defeats the interface premise; those negative controls are not
protocol attacks or tests of a concrete sponge. `ideal_source_manifest.json`
pins exactly these two model files and this README. Existing polynomial and
actual-RP57 transcript controls remain unchanged. None of these conditional-model
controls establishes fixed-RP57 joint hiding, actual Omega composition or C12.
