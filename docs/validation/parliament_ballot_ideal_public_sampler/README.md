# Conditional direct sampler for ideal public material

The [derivation](../../../specs/parliament_ballot_b6_ideal_public_sampler.md)
defines `IdealFrontierSim`, a bounded mathematical public sampler for the
fully replaced material endpoint retained after the earlier mask-coordinate
and hidden-assignment deletion steps. It samples independent hidden leaf
commitments and frontier keys in the actual canonical opening format, then
performs one source-shaped VOLE reconstruction with its nested BAVC pass.

The exact equality concerns public material, transcripts, persistent oracle
interfaces and adaptive adversary state after unused private coordinates
are discarded. It preserves the actual H0/H1 evaluations and deterministic
correlations within revealed subtrees. It covers every admissible opening,
including the bounded schedule's exhaustion fallback.

The [receipt](receipt.json) binds 22 source/specification/evidence inputs
and 25 exact source excerpts. Both automated local consistency reviews
completed without a blocking finding under the explicit premises; the
second reviewer also checked all input/excerpt hashes and the two rows'
source arithmetic. No executable code was added and no runtime test
establishes this mathematical statement.

From the repository root, verify retained documents and source identities:

```sh
shasum -a 256 -c docs/validation/parliament_ballot_ideal_public_sampler/SHA256SUMS
python3.11 - <<'PY'
import hashlib
import json
from pathlib import Path

root = Path.cwd()
base = root / "docs/validation/parliament_ballot_ideal_public_sampler"
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

Changed inputs require new evidence; keep this frozen result unchanged.

Fresh replacement outputs are independent per invocation/node or selected
leaf slot. Their law is an explicit mathematical entry premise. This note
does not embed it into a globally consistent PRG or ideal-cipher interface
when actual key/IV/tweak inputs coincide, or identify this simulator with
the real-root frozen `Sim+`. It offers one selected opening per invocation,
not an arbitrary later secret-tree opening API. The programmable quantum
oracle interface is not implemented by this artifact.

The operation inventory covers concrete reconstruction calls and bounded
logical buffers. A complete quantum resource vector, computational entry
reductions, accepted primitive advantages, owner acceptance and independent
cryptographic review remain open. Earlier frozen notes and ledger numbers
are unchanged; qualification remains false and production stays gated.
