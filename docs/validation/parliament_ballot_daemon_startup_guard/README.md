# Boxed daemon startup source boundary

This repairs a stale source-guard expectation. No Rust runtime implementation,
production availability gate, qualified latency or dependency boundary changed.

Commit `1a6270412cbb10a7ab83b91080e0da595c303a35` wrapped preparation and
activation in `Box::pin` inside `Iroha::start_with_runtime_deps`. The
[entry-only history comparison](boxed-entry-history.json) verifies that removing
only those two wrappers in comparison data reproduces the pre-commit entry's
literal-preserving tokens. Other changes in that commit or daemon are outside
this observation. The comparison is not an allocation or runtime equivalence
proof, and the checker does not accept the old unboxed entry.

The [checker](../../../scripts/formal/check_sora_parliament_source_contract.py)
now accepts exactly the current boxed body under the original unconditional
`impl Iroha`. It pins the complete signature and body, both direct awaits,
preparation error propagation, and original prepared/logger/shutdown/runtime
and publication-factory handoff. It rejects removed or changed pins, altered
arguments, discarded errors, added branching and nonoriginal or disabled
owners. Harmless comments and code spacing remain accepted. Surrounding
`Box`/name resolution and allocator, compiler and runtime behavior remain
explicit premises. This establishes source structure only.

The subsequent custody preflight check is unchanged. The existing actual clause
still matches exactly once: local consensus peer, awaited consensus-native
preflight with error propagation, startup trace, then
`prepared.start_on_network`. Preparation/activation future boxing does not
require stripping arbitrary wrappers or relaxing that clause.

The [focused capture](daemon-startup-controls.json) passes 181 threshold,
readiness and startup controls against eight unchanged source/config/recipe
inputs. It includes 43 added boxed-entry controls. The [independent local agent
review](peer-review.json) also ran those 43 controls against the final checker
and tests. That reviewer-reported result is explicitly separate from the
capture recipe and is not external cryptographic or implementation review.

The [actual full source check](source-check.json) observes 112 unchanged
repository inputs and reaches the next failure:

```text
crates/iroha_core/src/sumeragi/epoch_beacon/producer.rs: a demanded pulse must await actual shares, never an empty witness
```

That failure is retained; later assertions remain unexecuted. The instrumented
in-process probe and actual CLI agree, but the CLI read set is not independently
traced. Installed Python/pytest runtime remains trusted. No Rust build, runtime
startup or memory qualification was performed by this phase.

[prior-sources.json](prior-sources.json) preserves the exact preceding Torii
checker/test versions. [captured-sources.json](captured-sources.json) maps every
captured input to an exact retained snapshot. `SHA256SUMS` covers the complete
bundle, and the `freeze-receipt.json` records its scope and
source identity checks. Later worktree drift does not extend this evidence to a
new candidate.

Replay with:

```sh
.venv/bin/python -m pytest scripts/tests/check_sora_parliament_source_contract_test.py -q -k 'threshold_signer or threshold_startup or daemon_boxed_startup'
.venv/bin/python scripts/formal/check_sora_parliament_source_contract.py
```

Capture recipes intentionally refuse to overwrite existing outputs.
TODO: Review the next demanded-pulse witness mismatch separately and satisfy
all remaining B6 obligations before production integration or activation.
