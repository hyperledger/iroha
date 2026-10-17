# Torii local partial-release source boundary

This is a scoped source-guard repair, not anonymous-ballot qualification. The
availability gate remains false, qualified attempt latency remains `None`, and
Core/Torii do not gain experimental ballot dependencies.

Commit `1a6270412cbb10a7ab83b91080e0da595c303a35` changed only
`pub(crate)` to `pub` on `require_empty_body_v1` and
`request_local_partial_release_v1`. Their module remains private under the exact
`app_api` feature predicate. The existing physical signer admission and
recoverable spawn/join code preceded that visibility edit. The old checker
refused the current visibility before inspecting later obligations.

The repaired [checker](../../../scripts/formal/check_sora_parliament_source_contract.py)
binds nine complete items with literal-preserving tokens:

- The bounded empty-body gate, exact nonzero identifier parser, closed error
  mapping, and local release service.
- The original `app_api` handler, complete `QueryAdmissionPermit` fields, and
  general/heavy admission implementation with one queue deadline.
- The physical recovery spawn and opaque recovery join helpers.

It checks the private service module and recovery module declarations under
their exact attributes, removes only the four reviewed leading Torii lint
attributes, and pins the complete small service/recovery modules to retain
imports and macro bindings. The handler keeps access checking, empty-body
rejection, heavy admission, service invocation and response projection in order.
The service validates the identifier before spawning, moves the same permit
into the physical closure, and retains it through the committed-view lookup and
coordinator call. Worker and coordinator error mappings retain closed classes
and constant text.

Independent local review found a real gap in the first draft: a custom `Drop`
for `QueryAdmissionPermit` could release its heavy field before fanout/body
retirement while leaving all nine pinned item bodies unchanged. The repair now
rejects direct custom `Drop` implementations for that owner, including
qualified/raw and parenthesized owner spellings. The regression controls retain
that counterexample and verify that a comment mentioning it is not code.

This remains a conservative lexical check. Canonical authentication depends on
the upstream route macro, mount and middleware chain; `check_access` alone is
not that proof. Surrounding Torii aliases/name resolution, Rust dependency
semantics, Tokio behavior, native execution and actual cancellation behavior
remain explicit premises. No runtime code changed or Rust suite was run in this
phase. The existing generic cancellation test targets
`routing::run_admitted_blocking`, not this exact service, and was not rerun.

The [focused controls](torii-release-controls.json) pass all 136 cases against
nine unchanged source/config/recipe inputs and retain their actual log. The
independent reviewer additionally ran ten focused controls against the final
checker and tests. Their mutations cover disabled,
nested, macro and raw-identifier decoy owners; early returns and changed body/ID
rejection; capacity release outside or before the physical signer; wrong state,
coordinator, identifier and permit handoffs; reordered handler/custody steps;
error text/classes; exact attributes; recovery changes; and module import/macro
changes. Comments and code spacing remain accepted. Independent agent review is
recorded separately in [peer-review.json](peer-review.json); it is not external
cryptographic or implementation review.

The [actual source check](source-check.json) observed 93 repository inputs with
no before/after drift, then ran the real CLI against those guarded sources. It
now reaches the next failure:

```text
crates/irohad/src/main.rs: startup must propagate original preparation into awaited activation
```

That failure is retained. Later assertions remain unexecuted; the full source
check is not passing. The CLI's read set is not independently traced: the
receipt explicitly distinguishes the instrumented in-process probe from the
actual CLI result. Installed Python/pytest runtime remains trusted.

[prior-sources.json](prior-sources.json) preserves the exact pre-edit checker and
test bytes. [captured-sources.json](captured-sources.json) maps every captured
source/config/recipe input to its exact retained snapshot. `SHA256SUMS` covers
this complete evidence bundle. Later worktree drift does not change a captured
result into a current-source qualification claim.

Replay focused controls with:

```sh
.venv/bin/python -m pytest scripts/tests/check_sora_parliament_source_contract_test.py -q -k torii_release
.venv/bin/python scripts/formal/check_sora_parliament_source_contract.py
```

The capture recipes intentionally refuse to overwrite their existing outputs.
TODO: Review the next daemon startup mismatch separately, and complete all
remaining B6 security, resource, external-review and named-hardware obligations
before allowing production integration or activation.
