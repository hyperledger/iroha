# State construction source guard

This bundle preserves a structural checker repair and its captured results:
121 focused Python controls passed, while the full source-contract CLI exited
1 at a separate Torii TLE release binding. It does not qualify Core runtime,
Parliament resource bounds, cryptography, or production integration.

The original observations were internally stable: the
[controls receipt](construction-controls.json) records 11 unchanged input pins,
and the [source-check receipt](source-check.json) records 66. During the later
freeze, six source files had changed, including `state.rs`, which the controls
read. These are therefore historical results. The
[post-capture review](post-capture-review.json) records each captured and current
hash; every drifted original was recovered from an exact Git object and retained.
No original receipt or input hash was replaced. A later current-source check
must be recorded separately.

The prior guard rejected an added Clippy `expect` attribute and the consistently
conditional DA rewind custody. The repaired `construction_rust_item` accepts
only the reviewed exact attribute run before invoking the existing
unconditional-owner locator. It rejects disabled or foreign parents, qualifier
changes, duplicate or raw equivalent item names, and disconnected declarations.
The construction check binds creation, transfer, and retirement to the same
`cfg(any(test, feature = "iroha-core-tests", feature = "bench"))` predicate.
Ordinary World, transaction, Cell, hash and writer-retirement ownership remains
unconditional.

[The binding map](checked-bindings.json), extracted from the exact captured
checker, lists 16 complete item pins, five live module/reexport routes, and four
complete defining-module pins. Literal-preserving token hashes retain exact
literals while allowing code whitespace and comments. Complete module pins
also bind imports, aliases, macros, and surrounding items in those four files:
identical function bodies alone cannot rule out changed name resolution. The
surrounding Rust crate, dependency resolution, compiler and runtime semantics
remain trusted. This is a conservative source correspondence check, not a
semantic proof of arbitrary Rust or concurrent execution.

The [actual pytest log](construction-controls.txt) reports 121 passed and 1301
deselected in 112.82 seconds. The selected controls cover paired predicates,
original writer transfer, release/refund/notification ordering, foreign source
substitution, early returns, hidden/disabled owners, raw macro shadowing,
changed imports or aliases, exact literals, and permitted comments/spacing.
The mandatory-construction sentinel remains included. Prior queue/Kura and
phase-call helpers were not changed by this repair. This freeze verifies the
recorded evidence and does not rerun those tests.

The [capture recipe](construction-controls.py.template) disables third-party
pytest plugin autoload and records the effective pytest arguments, including
the duplicated import-mode option inserted by the existing pytest configuration.
It audits repository reads and pins the checker, tests, masker, pytest config,
conftest, and capture recipe. Installed Python and pytest remain trusted; their
versions and the interpreter hash are recorded. Python bytecode caches and
generated evidence outputs are outside the audited source read scope.

The [source-check recipe](source-check.py.template) first observes the helper's
executed read set and then runs the ordinary CLI separately. Probe and CLI agree
on this [first failure](source-check.txt):

```text
crates/iroha_torii/src/parliament_tle_release.rs: missing modeled source binding(s): 'pub(crate) async fn request_local_partial_release_v1('
```

The ordinary child CLI's read set is not independently traced. Before/after
hash equality is an observation, not an atomic filesystem snapshot. Later
assertions were not executed after this first failure. The captured gate
checks retain binding-ballot availability `false`, qualified attempt latency
`None`, and no experimental ballot/VOLE dependency in Core or Torii. No Torii
repair or production gate change is part of this bundle.

[The snapshot map](source-snapshots.json) identifies the exact captured
checker/test/config bytes, four complete defining modules, and all six drifted
source inputs. Other inputs remain hash-pinned in the original receipts; this
is not a complete repository snapshot. [The freeze recipe](freeze.py.template)
verifies receipt/log identities, source copies, the extracted binding counts,
and post-capture drift. It refuses existing outputs. `SHA256SUMS` uses
repository-relative paths and excludes itself.

From the repository root, verify these frozen files with:

```sh
shasum -a 256 -c docs/validation/parliament_ballot_construction_guard/SHA256SUMS
```

TODO: review the Torii TLE release binding separately and retain a fresh source
check after any repair. Revalidate relevant controls against changed source
before treating them as current-candidate evidence. Production remains gated.
