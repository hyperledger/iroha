# Historical adapter input recovery

The [validated receipt](validated/receipt.json) resolves all 2,081 byte identities
from the frozen [adapter report](../parliament_ballot_adapter_bound/report.json).
Four changed inputs were recovered from exact Git revisions into separate files;
the other 2,077 inputs matched at their original guarded paths. Every resolved
path was checked again, including missing-file handling. This recovers input
content for the historical argument; it does not transfer the argument to the
current source or rerun a build, test suite or machine-code analysis.

| Historical input | Exact matching Git revision |
| --- | --- |
| `Cargo.lock` | `984343b41db8da310e0059f7a5cbdfdd15df9b90` |
| `crates/iroha_allocation/src/allocation/shared.rs` | `17677530eea0e95b51ea404db7a5ff33a2f66688` |
| `crates/iroha_allocation/src/shared.rs` | `17677530eea0e95b51ea404db7a5ff33a2f66688` |
| `crates/iroha_allocation/src/shared_reservation_tests.rs` | `624a10be76963eda2ee1aa585ec719c9d82919f8` |

Each recovered file's SHA-256 equals the corresponding input hash in the
unchanged historical report. The recorded `git show` command and destination
are retained in the receipt. This neither claims that all four revisions form
one repository commit nor invents a historical checkout: the build originally
recorded its individual source bytes, and those are the identities recovered.

The [initial observation](receipt.json) and its
[executed recipe](executed-initial-recipe.py.template) are retained. Before
freezing this bundle, its second-pass missing-file check was tightened and a
fresh observation was written under `validated/`, with an
[exact executed recipe](validated/executed-recipe.py.template). Both observations
found all 2,081 resolved inputs matching; neither changed any live source.

A separate local review verified the exact historical input set, all resolved
digests, the four recorded Git recovery commands and the retained recipe
identity. The [review receipt](review.json) records that limited integrity
check. This is not the independent cryptographic or implementation review
required for qualification.

Reproduce into a new directory using the original checkout paths, retained Git
objects, registry files, tools and artifacts named by the historical report:

```sh
.venv/bin/python docs/validation/parliament_ballot_b6/recover-adapter-sources.py.template \
  --root "$PWD" --output /private/tmp/parliament-adapter-source-recovery-new
```

The program refuses an existing output and reports unknown/missing identities
as failures. The remaining files are referenced at their original paths; this
is not a complete portable source/compiler/runtime archive. No recovered file
is installed over the working tree, no build pin is refreshed, and the current
adapter checker continues to refuse mismatched live inputs. Full verifier/native
bounds, independent review and qualification remain open.
