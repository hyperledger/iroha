# KAGEMUSHA protocol model

The provider model covers the durable Advance publication boundary in canonical
design [§4.1 and §5.2](../../specs/kagemusha_single_design_proposal.md). The separate
[accounting model and conditional induction](ACCOUNTING.md) track reserve
liabilities, core versus folded balance, fees, Archive no-op and retirement races.
A bounded Send publication/accounting composition is also checked. Composition
across all operations, native refinement and the complete protocol model remain open.

Run from the repository root with the Python standard library only:

```sh
python3 -B -S formal/kagemusha_protocol/provider.py
python3 -B -S formal/kagemusha_protocol/schedules.py
python3 -B -S formal/kagemusha_protocol/publication_accounting.py
python3 -B -S -m unittest discover -s formal/kagemusha_protocol -p 'test_*.py' -v
```

Optimized Python is refused because it would remove assertion gates. A search
limit is an error; a partial traversal never reports success. The command emits
actual state/edge counts and a shortest counterexample for every unsafe rule.
The [focused workflow](../../.github/workflows/kagemusha_protocol.yml) runs these
commands and retains failure logs. Local commands pass; hosted CI has not run.
Discovery includes the accounting schedule and mutation controls; the 484-state
exhaustive result below belongs only to the provider model.
The combined unit suite has 55 checks: 14 provider, 23 accounting, eight
schedule-explorer controls and ten Send composition controls. The accounting
suite includes eight rejected state mutations.
Its reserve equation distinguishes actual burned backing from unbacked rejected
input and checks each wallet/account effect separately. It covers split and
cyclic transfers, fee entitlement before delivery, both Archive outcomes and
retirement/load races. Those hand-selected schedules are not exhaustive.

`schedules.py` separately explores immutable accounting worlds with explicit
finite supply and record inventories. Its two-wallet, two-unit fee graph exhausts
56,910 states and 508,958 permitted transitions, reaches every modeled operation,
and counts 575,055 rejected actions. The zero-funded unbacked-input graph exhausts
289 states without enabling any debit. Four faulty transition rules have exact,
replayable shortest counterexamples: refunded Send, omitted burn, duplicate credit
and redirected Unload payout. These do not replace the accounting premises.

The explorer shares immutable action inventories and checks a state-only
invariant once per distinct immutable world. It performs no state quotienting or
partial-order reduction. Self-loops and every permitted transition still count;
the cached implementation preserves the uncached fee graph's counts. Any search
limit raises an error and cannot produce an overall success record. The larger
three-wallet graph exhausts 4,146,534 states and 57,063,475 permitted transitions,
with maximum shortest-path depth 31. Its vocabulary has one initial unit, at
most one Load, two Payments and one Unload claim, and no unbacked-input identity.
The separate unbacked profile covers that branch. The earlier 500,000- and
2,000,000-state cutoffs remain retained as inconclusive attempts; the completed
run uses a 5,000,000-state safety limit. These four finite graphs are separate;
their state counts do not combine into an exhaustive unbounded protocol graph.

`publication_accounting.py` composes every provider transition with the monetary
effect of one selected Send. Its graph exhausts 3,076 states and 25,836 transitions
for two competing one-/two-unit Send capsules, one three-unit funded folded payer,
one receiver, both Receive outcomes and a completed receiver fold. Selection
projects the irreversible debit into the accounting liabilities even if signing
is pending. This projection grants no delivered bytes or spending authority.
Only a readable released original may reach a carrier. Carrier loss, payer loss,
unavailable storage and retries preserve both that debit and permanent first credit.
Four composition mutations have replayable shortest counterexamples: refunding
uncertain selection, exposing an unpersisted Payment, debiting on replay and
reconstructing erased Payment bytes from a ghost identity. Ten controls pass.
Receive's own durable provider operation, the preceding authentic Load and
successful fold verification remain premises. This one-head product does not
establish arbitrary multi-wallet provider composition or a native refinement.

## State and scope

`provider.py` has one existing head, two competing exact capsule names, two
possible signature/output names for each capsule, and zero, one or two valid
copies of each retained object. Storage and signing availability vary separately.
Crashes discard volatile staging and a signature that has not reached a
completion record. Before selection, staging can be discarded and replaced.
After selection, only the exact selected capsule can finish.

An uncertain publication can leave the old head or select its exact successor;
only observed authoritative state resolves it. Successful selection is already
irreversible while signing is unavailable. Release requires the selected capsule
and redundant completion originals. A surviving completion is reused without
another signature. First release seals its exact bytes; every later output
must come from a surviving retained copy. Losing every output copy is delivery
data loss, and losing a selected capsule is custody loss. Neither authorizes
reselection or regeneration. Unavailable storage supplies neither absence nor a
loss verdict.

`winner`, `sealed` and `observed` include ghost history for assertions. They
name exact originals but cannot reconstruct their bytes. The honest retry rule
reads only `retained_receipt` with a positive copy count. The mutation that uses
`sealed` to replace erased originals must fail. Explicit erasure transitions
exercise failure reporting beyond ordinary crash durability; they are not a
claim that the production profile tolerates malicious OS rollback or deletion.

The model's `released` phase is the provider's completed release capability,
including required anchor advancement and marker retirement. It is not merely
the earlier on-disk publication of a Released marker. Internal publication,
anchor and directory operations are abstracted; their individual crash points
remain the Rust provider crash-matrix tests' responsibility. Opaque capsules are
assumed to have passed the native transition checks before selection. This model
does not implement signatures, BLS, σ/Λ/Ω, map authentication, filesystem codecs
or an OS durability refinement.

## Obligations and native correspondence

| Model obligation | Current native owner |
| --- | --- |
| Verify and retain the exact frozen transition before Advance | `Coordinator::commit` in [`kagemusha_wallet_state_v1.rs`](../../crates/iroha_core_zk/src/kagemusha_wallet_state_v1.rs) |
| One selected successor; uncertain outcomes remain pending | A4–A6 in [`advance.rs`](../../crates/iroha_core_zk/src/kagemusha_wallet_advance_v1/advance.rs) |
| Selected capability binds the receipt body; adopt an existing completion before signing | `finish_selected_inner`, A7–A8, in the same file |
| Redundant completion, Released publication and anchor before return | A9–A12 and [`completion.rs`](../../crates/iroha_core_zk/src/kagemusha_wallet_advance_v1/completion.rs) |
| Recover the selected frozen capsule and resume its exact operation | `Coordinator::resume`; native [`reconcile.rs`](../../crates/iroha_core_zk/src/kagemusha_wallet_advance_v1/reconcile.rs) |
| Concrete I/O crash boundaries and storage availability | [`crash_matrix_tests.rs`](../../crates/iroha_core_zk/src/kagemusha_wallet_advance_v1/crash_matrix_tests.rs) and provider/store tests |

This table records a source review, not a machine-checked refinement or proof
that the current Rust binary implements the abstraction. Its tests do not run
the wallet or replace its native acceptance suite.

## Checked properties

The baseline graph exhausts 484 states and 2,792 transitions. Its maximum
shortest-path distance is 13. Exhausting the graph covers arbitrarily repeated
crashes, availability changes and retries within this fixed vocabulary; 13 is
not a bound on trace length. It establishes no property for additional wallets,
new heads, unbounded monetary histories or different copy/identity bounds.

Fourteen controls include recovery with signing unavailable, same-original retry,
single-copy repair, permanent output loss, discarded preselection work and exact
counterexample replay. Seven unsafe rules are rejected: reselection, release
with only one durable completion, unavailable-as-absent, a fresh retry receipt,
regeneration after total output loss, signing a foreign capsule, and reporting
a selected operation as not performed.

The local history argument is explicit: selection assigns `winner` once;
every permitted later action preserves it. Release assigns `sealed` from the
retained completion after redundant durability; no later permitted action
changes it. Observations of bytes require a surviving retained copy equal to
that seal. These facts are preserved by crash, repair and loss transitions.
This is a conditional invariant of this abstract provider, not the required
inductive conservation argument for arbitrary protocol executions.

TODO: Compose the models, including partial
fold scheduling, enrollment markers and historical controls. Connect those
transitions to native/circuit differential evidence and discharge the conditional
accounting argument's premises for the implementation. Independent model review,
full monetary-network acceptance, C12 and physical-phone qualification remain
open.
