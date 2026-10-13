# Conditional adaptive hidden-assignment deletion

The [derivation](../../../specs/parliament_ballot_b6_hidden_assignment_deletion.md)
defines an unpatched public baseline at the same ideal-material boundary
as the frozen mask-coordinate note. It compares patched and unpatched
lookups while retaining the same private chronological log in both
experiments, then removes unused bookkeeping exactly from the baseline.

The proof establishes joint pad/public-query independence only in the
unpatched baseline. Under the event of distinct 256-bit salts, a complete
H5 address identifies at most one request and gate. The corresponding
baseline difference-projector mass is at most `2^-256`, without assuming
independence among gate labels or entropy after patched-oracle queries.
Fixed-permutation telescoping bounds the full adaptive output difference.

The [receipt](receipt.json) binds 16 source/specification/evidence inputs
and 15 source excerpts, including the frozen prior notes. It pins the
primary Jaeger PDF and records both automated local consistency reviews.
No executable code was changed and no runtime test establishes this
mathematical statement.

From the repository root, verify the retained documents and source pins:

```sh
shasum -a 256 -c docs/validation/parliament_ballot_hidden_assignment_deletion/SHA256SUMS
python3.11 - <<'PY'
import hashlib
import json
from pathlib import Path

root = Path.cwd()
base = root / "docs/validation/parliament_ballot_hidden_assignment_deletion"
receipt = json.loads((base / "receipt.json").read_text())
for name, expected in receipt["source_sha256_at_freeze"].items():
    actual = hashlib.sha256((root / name).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"Frozen input changed: {name}")
for ref in receipt["source_references"]:
    lines = (root / ref["path"]).read_bytes().splitlines(keepends=True)
    excerpt = b"".join(lines[ref["start_line"] - 1:ref["end_line"]])
    if hashlib.sha256(excerpt).hexdigest() != ref["excerpt_sha256"]:
        raise SystemExit(f"Source excerpt changed: {ref['path']}")
print("All frozen inputs and source excerpts match")
PY
```

Source mismatch requires new evidence for the changed candidate. Keep
these frozen results unchanged.

The result applies to the named cached mathematical driver. Every actual
overlay evaluation, including later verification or added reconstruction,
must be counted. Complete primitive reductions, gates, memory, the bridge
between ideal and real BAVC material, and independent cryptographic review
remain open. No frozen ledger number or production gate is changed;
qualification remains false.
