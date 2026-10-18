# Conditional full typed-request body families

This package closes the local body-computation family gap for the captured
request-machine model. It covers every bounded typed REG public length tuple,
and VOTE actual sizes 3..1000 with either valid or invalid content. It reports
exact local counts and attaining family maxima at explicit log-sizing T and b.
It does **not** establish a complete adaptive experiment resource bound, native
verifier workspace bound, primitive-security bridge or production qualification.

The original envelope capture passed **44 tests**. The separate independent
review passed **42 tests**, including full-source metadata builds of
new interior request shapes, actual W emitter comparisons at extreme T/b,
recomputation of all 1996 VOTE row/size cases, storage ownership and refusals.
These are circuit metadata and scalar checks, not expansion or physical
execution of the enormous full elementary gate streams.

## Scope and exact witnesses

The [source-dependence derivation](record/README.md) establishes that REG opaque
lengths change only P1 and original public storage. For bounded VOTE, only
P0/P1/R1, P1 retained output width and original public storage vary. All other
stage shapes are fixed by role, row and M. Source-pinned component envelopes
prove that fixed stage workspace dominates all varying stage workspace. Static
wire relocation adds no gates. Both generator traversals, one W mutation, the
clean return, all retained input/coin/output registers and the full shared
log/counter/workspace are charged.

REG's exact maximum elementary cost and total logical storage occur at
B=4096 and six context lengths 256. The exact X maximum instead occurs at
B=4095 and six context lengths 255. At the full-request level, that witness has
468 more X, 1024 fewer CX, 556 fewer elementary gates and 56 fewer public bits.
The report keeps those witnesses separate. Its coordinatewise gate upper
vector obeys X+CX+5*CCX and is 468 elementary gates above the exact REG maximum;
it is not mislabelled as a simultaneously attained vector. VOTE's displayed
maxima are attained at n=1000 after checking every n=3..1000.

Both bounded VOTE content outcomes pay the full computation. No validity hint
can refund work. Rejected actual sizes are a separate mathematical u64
descriptor family: 5881+2*popcount(n) elementary gates, zero F calls, 519 work
bits, 3608+1024*n borrowed public bits and the full caller output. This is not
an assertion that every u64-sized native Vec exists. T sizes the log here; it
does not infer any valid-request or invalid-invocation budget. Native descriptor
authentication and raw decoding remain external.

REG's domain is already constructed bounded typed public inputs; application
witness validation, constructor refusal, authority and canonical production
encoding work are not included. Family selection, input/coin preparation and
purification, initialization, external queries/adversary work, the adaptive
controller and base-oracle implementation also remain unpriced. Logical bits
are neither native allocation measurements nor physical qubits.

## Historical custody and current-source refusal

The envelope capture retained 161 catalog inputs plus four owned inputs, all
unchanged before and after execution. The independent review has its own
receipt and source inventory. The original capture receipts and manifests are
preserved separately and unchanged; the independent checks do not overwrite or
retroactively extend the original 44-test receipt.

The current native candidate differs from this historical source selection.
The live `crates/iroha_parliament_ballot_proof/Cargo.toml` observed at capture had
SHA-256 `3224f341475b4e60fb4e8d778c43971a94d77534670cd2c9bebad444e76de904`, while the frozen
catalog requires `f1b9e23aceb1039ff92b3d4dc2f9a94d63afa35842b5b3541b7c9e32b00f76d5`.
The live CLI correctly refused with exit 1 and no JSON. Sources were restored
into a separate tree for historical replay; no live file was overwritten or
repinned. These results do not qualify the changed current native candidate.

The ordinary historical CLI emits the conditional report with exit 0.
`--require-qualified` emits byte-identical JSON with exit 2. Complete-experiment,
physical-workspace, primitive-bridge, external cryptographic review and
production qualification flags remain false. Production stays gated.

## Records and replay

- [Captured envelope report](capture/envelopes.stdout).
- [Original 44-test receipt](capture/receipt.json) and [manifest](capture/SHA256SUMS).
- [Independent review](review/README.md), [receipt](review/capture/receipt.json)
  and [manifest](review/capture/SHA256SUMS).
- [Replay inputs](replay-inputs.json), [dependency identities](dependencies.json)
  and [original logical capture membership](logical-captures.json).

The 154 common catalog files are mapped to exact members of the already
published request-machine, lifetime-ledger and content-resource packages.
The seven component inputs, four envelope inputs and independent review inputs
are archived here. Executable source copies use `.template` suffixes. Original
review notes retain their historical relative source links; the replay map
restores those sources at their original paths.

From the repository root, use Python 3.11 or newer and the outer manifest digest
supplied with this package to restore an absent destination:

```sh
python3 -B <package>/restore.py.template --package <package> --repository . --destination <new-replay-root> --manifest-sha256 <outer-manifest-digest>
```

The restorer authenticates this package, all three dependency manifests, every
replay input and every original logical capture member before writing. It
refuses an existing destination. From the new replay root, run:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_ADDOPTS='' PYTEST_PLUGINS='' /opt/homebrew/bin/pytest -q -c /dev/null --noconftest -p no:cacheprovider target/parliament-request-family-envelope-stage/test_envelope.py target/parliament-request-family-envelope-review/test_review.py
python3 -B target/parliament-request-family-envelope-stage/envelope.py --root . --require-qualified
```

The second command intentionally returns exit 2. Installed Python, pytest and
the standard library are trusted runtime premises. Selected-source hashing
does not attest an atomic filesystem or complete runtime dependency closure.

TODO: complete the remaining entry, preparation, adaptive, primitive, native,
hardware and external-review requirements before any full qualification claim.
