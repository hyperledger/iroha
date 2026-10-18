# Borrowed beacon witness source boundary

This repairs the source guard's stale owned encoder call. No Rust implementation,
production availability gate, qualified latency or dependency boundary changed.

Commit `1a6270412cbb10a7ab83b91080e0da595c303a35` changed the producer's
`control::encode(pulse)` call to `control::encode(pulse.as_ref())` and the codec
parameter from `Option<Pulse>` to `Option<&Pulse>`, passing that reference to the
canonical writer. The [entry history comparison](borrowed-entry-history.json)
retains both exact items and confirms that reversing only those changes in
comparison data reproduces their pre-commit bytes. The producer still holds its
local `Option<Pulse>` before borrowing. This observation is not a serializer
byte-equivalence, compilation, allocation or runtime proof.

The [checker](../../../scripts/formal/check_sora_parliament_source_contract.py)
now binds the complete `build` method under the original unconditional
`impl NativeBeaconProducer`. It preserves every original context field, the
prepared-context equality guard, no-demand absence, and the demanded pulse's
`AwaitingShares` refusal before encoding. Only the exact local borrowed pulse
reaches `control::encode`, with its original typed error mapping. The exact
module-level codec signature/body streams the pulse into the same returned
witness and propagates writer errors.

Direct producer/control module declarations and the producer's direct codec
import are also bound. A complete token pin covers the small control module,
including imports and macros. Surrounding producer type/name resolution,
`Pulse`/`ControlWitness` definitions, Norito serializer semantics and compiler
and runtime behavior remain explicit premises. The guard rejects changed
handoffs, early empty-witness returns, discarded errors, conditional branches,
disabled or foreign owners, and source text hidden in comments. Comments and
code spacing remain accepted. Subsequent signing and readiness assertions are
unchanged.

The [focused capture](beacon-borrow-controls.json) passes 182 controls against
13 unchanged source/config/recipe inputs. It includes 86 new borrowed-witness
controls and 96 existing beacon requirement controls. The [independent local
agent review](peer-review.json) reports a separate run of the 86 new controls
against the same final checker/tests. That reviewer-reported run is not a
capture recipe result or external cryptographic or implementation review.

The [actual full source check](source-check.json) observes 390 unchanged
repository inputs and stops at the following execution-test guard mismatch:

```text
crates/iroha_core/src/sumeragi/epoch_beacon/producer/execution_tests.rs: fn invalid( must contain 'assert!(matches!(executor.execute(candidate,&hash,false),Some(ExecOutcome::Invalid)));' exactly once, found 0
```

That next failure is retained without repair. Later assertions remain
unexecuted. The instrumented in-process probe and separate actual CLI agree,
but the CLI read set is not independently traced. Installed Python/pytest
runtime remains trusted. This capture runs no Rust suites and establishes no
physical, latency or production qualification.

[prior-sources.json](prior-sources.json) preserves the exact preceding daemon
checker/test versions. `captured-sources.json` maps the retained snapshots;
`SHA256SUMS` covers the complete frozen bundle and `freeze-receipt.json` records
its scope and source identity checks. Later source drift does not extend this
evidence to another candidate.

Replay with:

```sh
.venv/bin/python -m pytest scripts/tests/check_sora_parliament_source_contract_test.py -q -k 'indexed_beacon_requirement or beacon_requirement or beacon_borrow'
.venv/bin/python scripts/formal/check_sora_parliament_source_contract.py
```

Capture recipes intentionally refuse to overwrite existing outputs.

TODO: Review the next execution-test assertion mismatch separately and satisfy
all remaining B6 requirements before production integration or activation.
