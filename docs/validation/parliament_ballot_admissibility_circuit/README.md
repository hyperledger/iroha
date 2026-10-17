# Clean challenge-admissibility circuit evidence

This bundle records the focused Python gate-emitter checks for the
[component construction](../../../specs/parliament_ballot_b6_admissibility_circuit.md).
It covers the candidate and comparator rows, input preservation, reversible
cleanup, independent opening-frontier expectations and exact emitted gate counts.
This analytical circuit operates on supplied challenge wires; it is not a native
ballot verifier or a physical workspace measurement.

The [capture receipt](receipt.json) retains the actual focused pytest command,
exit and duration. [JUnit](tests.xml), stdout and stderr under `commands/` retain
all outcomes, including failures. The same capture executes the report at
`T=2^44` and at zero requests, then requires `--require-qualified` to exit 2 with
byte-identical output to the `T=2^44` report. Each report keeps the complete
resource, actual-input bridge, independent review, physical workspace and
qualification flags false. No earlier ledger is replaced or rerun.

Exactly five selected Rust/spec correspondence inputs come from the helper's
fixed `PINS`. The capture additionally watches the helper, tests, component spec,
pytest configuration and conftest, three central documents and its own recipe:
14 selected files in total. Exact before-bytes are in `sources/`, with their
[map](captured-sources.json). Two absent ancestor conftest paths are checked.
The installed pytest launcher and Python executable identities are recorded.
These observations do not trace a full compiler, Python import, subprocess or
dependency closure; interpreter/pytest dependencies, cache coherence and
unobserved child reads remain trusted. Before/after reads are not an atomic
filesystem snapshot.

The three [prior document snapshots](pre-component-documents/sources.json) retain
the exact earlier document bytes authenticated by the previous B6 manifest.
Their current replacements are captured separately. The previous aggregate and
its manifest remain historical and unchanged; this bundle does not refresh their
live-source applicability or transfer prior device/resource results.

The [capture recipe](capture.py.template) refuses existing capture outputs and
retains actual failure records. The [freeze recipe](freeze.py.template) requires
a passing, stable receipt, validates all snapshots and outputs, and writes the
[freeze receipt](freeze-review.json) and exact-membership [manifest](SHA256SUMS).
Full-resource qualification and production remain gated.
