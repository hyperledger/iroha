# Four full-cap content-family resource observations

The retained metadata construction passed for candidate and comparator VOTE
families at list counts 3 and 1000, each with M=2^20, T=2^44 and b=64.
The [exact outcome table](record/outcome.md) and
[full stage/resource report](record/capture/observation.json) include P0,
validity-controlled writes and return, both generator traversals, the common
253+8*proof_bytes return, original coins, retained stages and reused workspace.
These are four per-request observations at the specified lifetime log capacity,
not a maximum over public shapes or a complete adaptive-lifetime bound.

The [original command receipt](record/capture/receipt.json) records both commands
exiting zero, four metadata constructions in 139.58 seconds and scalar checking
in 0.05 seconds. The [scalar checks](record/capture/checks.json) independently
recompute the source geometry and composition equations and reject seven
changed-report examples. No complete gate stream or native worker was executed.
Candidate uses 6200 base F calls; comparator uses 5960. All qualification flags
remain false and production stays gated.

The original checker parsed JSON and later reread paths for hashes. Its command
therefore does not establish atomic identity of the parsed and hashed bytes.
The separate [root review receipt](reviews/root-byte-buffer-review.json) records
validation of exact single-read, hash-verified observation, accepted-reference
and checker buffers. It is retained as a local review receipt, not a claim that
the original execution was atomic or an external cryptographic review. The
original checker and every original outcome remain unchanged.

The [source dependency](dependency.json) identifies the published
[request-machine snapshot](../parliament_ballot_request_machine/README.md), its
152 selected source identities, corrected capture receipt and original manifest.
This bundle does not duplicate those 152 source files. Their scope is selected
source custody, not a complete compiler/runtime closure. The earlier
accepted-only observation remains unchanged and is used only for the n=1000
scalar delta comparison. [Inventory](inventory.json) maps all 12 original files
to their retained paths; executable Python files use `.template` suffixes.
[The original manifest](record/SHA256SUMS) preserves its original names and bytes;
this bundle's [manifest](SHA256SUMS) authenticates the renamed layout.

## Reproduction

First follow the request-machine README's source restoration instructions into
a **new ignored repository-shaped directory**. Those instructions verify and
restore all 152 source bytes; do not run its 350-test suite for this observation.
Then, from the original repository root, perform the following additional
copies. This assumes the restored root is
`target/parliament-request-machine-replay`; choose a fresh directory when needed.

```python
from pathlib import Path
import hashlib, json
main = Path("docs/validation/parliament_ballot_request_machine")
bundle = Path("docs/validation/parliament_ballot_content_resources")
replay = Path("target/parliament-request-machine-replay")
dependency = json.loads((bundle / "dependency.json").read_text())
inventory = json.loads((bundle / "inventory.json").read_text())
copies = []
for name, digest in dependency["capture_files"].items():
    raw = (main / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest
    copies.append((replay / "target/parliament-machine-final-capture" / name, raw))
for name in ("README.md", "observe.py", "check.py", "capture.py"):
    retained = "record/" + name + (".template" if name.endswith(".py") else "")
    raw = (bundle / retained).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == inventory["files"][retained]["sha256"]
    copies.append((replay / "target/parliament-content-resources-stage" / name, raw))
assert all(not destination.exists() for destination, _ in copies)
for destination, raw in copies:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(raw)
```

Run the following from the restored root; the original observation used
Python 3.15.0. The original recipe refuses an existing output directory and
retains new command outcomes. The copies above intentionally exclude the old
observation outputs. The scripts retain their original bytes, paths and source
checks; the original corrected receipt/manifest must exist at their expected
`target/parliament-machine-final-capture/capture/` paths. A new run is a new
observation, not a replacement for this retained receipt.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B target/parliament-content-resources-stage/capture.py
```

The arithmetic uses the existing X+CX+5*CCX convention and prices F separately.
Immutable source-padded F, disjoint generator/programming domains, clean stage
contracts, canonical log capacity and authenticated classical shape selection
remain premises. Raw descriptor authentication, a full adaptive driver,
family-wide maxima, complete external-resource accounting and physical/native
qualification are not established here.
