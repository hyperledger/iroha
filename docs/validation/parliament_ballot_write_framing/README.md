# Reversible write framing evidence

This bundle captures the separate
[write-frame preparation proposal](../../../specs/parliament_ballot_b6_write_framing.md).
It prices packing already available classical field values into the prior
oracle log's incoming record, then clearing that staging register after append.
It does not qualify the full simulator, cryptography, physical workspace or
production. All qualification flags remain false.

The [helper](../../../scripts/parliament_ballot_write_framing.py) binds the
actual profile namespace, transcript field order, final domain byte, recovered
Dtilde/A0 fields and little-endian message counter for both rows and roles.
Twelve frame layouts and 20 conditional schedule contracts are retained in the
[report](report.json). The counts include every primary counter write on
exhaustion and no auxiliary writes.

Preparation and cleanup together have exact X/CNOT counts for each layout.
At `b=64`, the largest bounded per-request sum is 7,291,167,830 elementary
gates. For the illustrative `T=2^44`, the resulting framing upper bound is
128,267,580,946,420,890,337,280 gates. This is an upper bound for this particular
component, not a lower bound, hardware cost or complete reduction budget.

The component adds zero oracle calls and zero clean work wires. It reuses
1,723,376 incoming-record wires already counted by the older log construction.
Its source-field registers are an explicit supplied interface and are not
added a second time to the sampler payload. Source generation, validation,
addressing, counter/controller work and all other computation remain excluded.
Source registers must be disjoint from staging, log, append counter and scratch.
The joint circuit preserves source basis labels; it may entangle coherent
fields with appended records and does not claim unchanged reduced source state.

[The test log](tests.txt) records **11 passing controls**. They include expected
source-ordered bytes for all 12 layouts, actual largest-frame scatter/inverse,
canonical padding, independent gate counts, exact schedule charges, and a
finite three-slot composition using the unchanged prior append emitter.
That composition checks repeated keys, retained older records, distinct trial
and append counters, source labels, clean staging/work, and the inverse of the
whole operation. Mutation/refusal controls cover bad cleanup, domain/counter
encoding, dirty staging, wire aliasing, input drift, geometry and schedules.
Tests do not establish a general Rust or quantum runtime proof.

The [capture recipe](capture.py.template), [commands](commands.json), and
[receipt](receipt.json) preserve 69 frozen source/metadata pins plus six explicit
helper/test/spec/config/recipe inputs, all unchanged before and after execution.
Exact snapshots of those six execution inputs are under `sources/`. Third-party
pytest plugin autoload was disabled. The installed Python/pytest/standard
library is trusted. This is a reviewed read-closure check, not independently
traced child-process reads, an atomic snapshot or a hermetic build.

The [zero-request report](zero-request-report.json) prices zero framing gates
and uses zero staging wires. The [18-bit report](framing-only-width-report.json)
fits all programmed keys but explicitly fails the preceding combined interface's
honest-read length envelope, which requires at least 23 bits. Both components
must use the same sufficiently large width; the illustrative report uses 64.
The [qualification refusal](qualification-refusal.txt) exits 2 and has stdout
identical to the ordinary illustrative report.

Root and `security_obligations` completed local source/count/scope reviews.
The peer also independently ran the 11 controls. These are local consistency
checks, not independent cryptographic review or owner acceptance.
[The freeze receipt](freeze-review.json) records final identity verification.
`SHA256SUMS` binds repository-relative bundle paths and excludes itself.

From the repository root:

```sh
shasum -a 256 -c docs/validation/parliament_ballot_write_framing/SHA256SUMS
```

TODO: price the remaining source preparation, controller, base-oracle, simulator
and reduction resources and complete the actual-input bridges, external review
and required hardware qualification. The original frozen log construction and
main security ledger have not been modified. Production remains gated.
