# B6 finite request/lookup sequence composition

The new [sequence binder](capture/source/target/parliament-sequential-composition-stage/sequence.py.template)
emits actual lazy component streams in one address space: one chronological
log/counter, distinct retained interfaces, and shared workspace that is clean
at each atomic boundary. It implements a finite sequence chosen in advance.
Adaptive selection, preparation, a complete experiment theorem and production
qualification remain open.

The [design and scope](capture/source/target/parliament-sequential-composition-stage/README.md.template)
explain wire ownership, full-message oracle relocation, conservative append
reservations and actual inverse composition. The sequence counts invalid
requests too; that is not the source theorem's valid-request-only T. Inputs,
coins, descriptors and the same immutable source-padded oracle remain supplied
premises. Logical register counts are not native verifier-memory measurements.

## Captured results

The combined suite passed **75 tests: 24 owned and 51 independent controls**,
with no failures, errors or skips. The [receipt](capture/receipt.json) binds
159 selected inputs and their restored execution copies. All stayed stable.
The [independent review](review/README.md) found two validation gaps, both
repaired: invalid private-coin metadata and malformed wire operand types.
No further actionable wiring defect was found within its scope. This is local
implementation review, not external cryptographic acceptance.

A [supplemental capture review](review/supplemental/README.md) independently
verifies the exact ordered 75-test membership, all 159 captured inputs, resource
totals, ten allocation regions and twelve observed prefix gates. It closes the
capture wrapper's count-only membership check for this capture. Six changed-report
controls are refused. The original review and capture receipts remain unchanged.

A [fresh full-cap metadata observation](capture/observation.stdout) constructs
candidate VOTE/count3, a full-message L0 lookup, and a size-rejected VOTE/count1001
at M=2^20, T=2^44, b=64. The actual request metadata exactly matches its preserved
content observation. The combined vector is:

| Quantity | Value |
|---|---:|
| Elementary gates, X + CX + 5 CCX | 166703749452958142616028467210236 |
| Supplied base-oracle calls | 6202 |
| Known allocated logical bits | 31790791991013480033925054 |

Only four relocated gate prefixes per call were emitted in this full-cap
observation. Complete synthetic streams are exercised by the tests; no full-cap
stream, physical quantum circuit or adaptive experiment was executed. The
observation includes source/component contracts and explicit unknown costs.

The first preflight stopped at an observer comparison between Python tuples
and JSON arrays. Its [stderr](preflight-attempt-1/observation.stderr) and empty
stdout are retained. The observer now compares normalized JSON values, and
a new complete capture passed. The first attempt's source was not separately
sealed; no source-custody claim is made for that failed attempt.

## Current source limitation

The 152 frozen component inputs come from the preserved request-machine package.
The live ballot Cargo manifest differs: its Norito dependency now disables
default features. This capture restores the old authenticated bytes into a
separate execution tree and records the live difference explicitly. No old
evidence was repinned. It does not qualify the changed current native candidate.
Python, pytest and the selected component semantics remain trusted; this is a
selected source inventory, not a full dependency or atomic filesystem attestation.

The captured receipt SHA-256 is
`5472577d2daca72943bd173bb0f1fdff0b47b62b4542e0007a68d61abde70498`.
The original capture manifest is
`b3033bbf656d63500fdfef5136d384bf9e042110f03d75a0e29b9f4a95f1d367`.
The package manifest authenticates this layout; `inventory.json` maps unchanged
bytes to original locations. Original manifests retain original path names.
Source files carry `.template` suffixes to avoid test/build discovery.

## Replay

Restore each receipt `source_sha256_before` entry from `capture/source/<path>.template`
into a new isolated root at `<path>`, checking its SHA-256 before writing. Refuse
absolute paths, parent traversal and an existing destination. The snapshot is
self-contained for these selected source inputs. From that restored root, with
Python 3.11 and pytest 9.1.0:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_ADDOPTS='' PYTEST_PLUGINS='' PYTHONPATH='' \
python3.11 -m pytest -q -c /dev/null --noconftest -p no:cacheprovider \
  target/parliament-sequential-composition-stage/test_sequence.py \
  target/parliament-sequential-composition-review/test_independent.py
python3.11 -B target/parliament-sequential-composition-stage/observe.py
```

TODO: authenticate and price input/witness entry, initialization, purifying
environments, adaptive selection/routing, upstream errors, application/verifier
and adversary work, the base oracle, uniform family resources and primitive
entry. Native workspace, named hardware and independent qualification remain
separate requirements. Production remains gated.
