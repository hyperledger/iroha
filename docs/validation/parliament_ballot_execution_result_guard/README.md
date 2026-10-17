# Execution-result pulse-isolation source boundary

This repairs three stale source expectations to match the current executor and
borrowed beacon codec. No Rust implementation, production availability gate,
qualified latency or dependency boundary changed.

The [history and API comparison](execution-result-history.json) retains the
current trait and implementation signatures, `ExecOutcome` definition and codec
entry. `Executor::execute` returns `Result<Option<ExecOutcome>, PublicationError>`;
its successful outcome has `result` and `admission` fields. The invalid assertion
must match `Ok(Some(ExecOutcome::Invalid))`; the valid assertion must match
`Ok(Some(ExecOutcome::Valid { .. }))`. Neither a local execution error nor absent
execution can satisfy these patterns. The genuine pulse is encoded through
`Some(genuine_pulse_at_next_height(...)).as_ref()` and the existing fallible
encoder still must succeed.

The comparison records the changes from commits `94e8c18d23e769dba1174d8e12a26d317eb489d0`
(Result), `30079d9e024f82f3e7a8f16f00318840774ee6a8` (the valid outcome's fields)
and `1a6270412cbb10a7ab83b91080e0da595c303a35` (borrowing). Reversing those explicit
spellings and the already-required `certified = false` argument in comparison
data recovers the pre-Result tokens of the invalid helper and both affected
tests. The complete cold-replay test remains token-identical without reversal.
This is source correspondence, not runtime or serialization equivalence.

Independent review found that the earlier ordered-token matcher accepted an
intact invalid assertion under `if false`. The
[checker](../../../scripts/formal/check_sora_parliament_source_contract.py) now
also pins the complete literal-preserving tokens of the two changed assertion
owners: module-level `fn invalid` with no attributes, and the module-level HC224
test with exactly `#[test]`. The existing detailed assertion checks remain.
Dormant branches, loops, closures, macros, changed owners and attributes are
rejected; comments and code spacing remain accepted. The concrete counterexample
is retained as a regression control.

Surrounding helpers and fixtures, macro/type/name resolution, compiler and
runtime behavior remain explicit premises. The API definitions and history are
recorded source premises; this narrow repair does not prove their native
semantics. These checks neither run the Rust tests nor qualify their runtime
results, resource bounds or cryptographic implementation.

The [focused capture](execution-result-controls.json) passes all 204 selected
pulse-isolation, restore-module and HC224 spec/mutation-gate controls, including
68 new Result and assertion-owner controls, against 11 unchanged inputs. Existing mutation cases are preserved; three anchors now
use their exact current Result or borrowed spelling. The [independent local
agent review](peer-review.json) reports 68 controls against the exact staged
checker/test bytes and matching parser dependency. That injected-module preview
is separate from the final capture recipe and is not external review.

The [actual full source checker](source-check.json) exits successfully over
402 unchanged observed repository inputs. The production binding gate remains
false, qualified attempt latency remains unset, and Core/Torii retain no
experimental ballot dependencies. No later source assertion remains skipped.

`prior-sources.json` preserves the preceding borrowed-beacon checker/test bytes.
`captured-sources.json` maps retained input snapshots. `SHA256SUMS` covers the
frozen bundle, and `freeze-receipt.json` records source identity and scope.
Source-check success means that its structural assertions passed; it does not
run native Rust suites, mutation builds, the formal model or performance checks.
The in-process probe and separate CLI are compared, but the CLI read set is not
independently traced. Installed Python/pytest runtime remains trusted.

Replay with:

```sh
.venv/bin/python -m pytest scripts/tests/check_sora_parliament_source_contract_test.py -q -k 'parliament_pulse_isolation or parliament_pulse_restore_tests or execution_result_guard'
.venv/bin/python scripts/formal/check_sora_parliament_source_contract.py
```

Capture recipes intentionally refuse to overwrite existing outputs.
TODO: Complete the broader Python regression capture and all remaining B6
requirements before production integration or activation.
