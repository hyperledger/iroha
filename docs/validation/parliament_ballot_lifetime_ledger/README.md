# Conditional lifetime resource ledger

This extends the [mathematical request-machine milestone](../parliament_ballot_request_machine/README.md)
with a typed **metadata ledger**, not an executed adaptive driver. It prices exactly
four captured accepted cases (candidate/comparator REG with body4096 and six
context256 lengths; candidate/comparator VOTE with1000 entries), fixed size-rejected
VOTE requests, and external L0 queries. Other accepted/content families are refused.
It does not infer a family maximum or adopt primitive advantages.

The ledger checks one common N=T*(2^20+2), length width b, and named immutable F/
total-completion contract. It rebases W gates, counter, staging, log and shared work;
retains full caller inputs, original coins and outputs; and checks disjoint logical
allocations. Reserved append capacity remains distinct from unknown actual occupancy.
Uniform canonical quantum support, fresh coins, atomic classical requests, descriptor
authentication and the supplied joint oracle contract remain caller premises.

The [example report](capture/example.stdout) leaves adversary, preparation, initialization,
routing, adaptive control, base-oracle implementation/state, family-wide envelopes,
and primitive entry terms unknown. Logical allocations are not physical qubits or
native64MiB workspace. Complete-resource, independent cryptographic-review,
current-candidate and production qualification remain false.

## Frozen evidence

- [Owned receipt](capture/receipt.json):68 tests passed, CLI0/refusal2 with identical
  report bytes;72 selected source pins plus6 execution/config inputs stable.
- [Independent local review](review/ledger-review.md) and [receipt](review/review-receipt.json):
  72 controls passed against the exact final helper bytes;77 selected inputs stable.
  This is local consistency review, not independent external cryptographic review.
- [Original capture manifest](capture/SHA256SUMS) preserves all86 entries and their
  original paths/bytes. Earlier reviewer receipts and exploratory records remain
  under `review/`, distinguishable from the final result.
- [Ledger source](capture/source-snapshots/target/parliament-lifetime-composition-stage/ledger.py.template),
  [design](capture/source-snapshots/target/parliament-lifetime-composition-stage/design.md.template),
  and [original README](capture/source-snapshots/target/parliament-lifetime-composition-stage/README.md.template)
  are unchanged. All retained executable sources are inert `.template` snapshots.

## Guarded replay

From a repository root with an ignored `target/`, run the recipe into a **new absent**
destination. It validates exact package membership and hashes before restoring the
78 owned receipt snapshots,2 selected reviewer inputs and2 separate import supplements:

```sh
python3 -B docs/validation/parliament_ballot_lifetime_ledger/replay.py.template --destination target/lifetime-ledger-replay
```

Add `--run-owned` for the68 tests and example/refusal CLI; add `--run-independent`
for the72 review controls. The default pytest command is `/opt/homebrew/bin/pytest`,
which can be overridden with `--pytest`. Python, pytest, stdlib and runtime behavior
remain installed-environment premises. Restored source hashes are checked again
following the replay; results are written only below that new ignored tree.

The two import supplements (`content_request.py` and `validated_request.py`) are
individually authenticated against the copied frozen main-machine manifest. They
were absent from the historical independent review's selected77-pin map and are
**not** retroactively added to it. They enable replay of imported module definitions;
they do not expand this ledger's supported request types. The selected snapshot
inventory is not a claim of complete runtime/dependency capture or current-checkout
qualification. The published main-machine package is unchanged.

TODO: cover remaining full-family resource observations, preparation and adaptive
driver resources, and discharge primitive-entry obligations. This ledger always
refuses a complete-resource certificate.
