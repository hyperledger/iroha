# Conditional joint mask-coordinate evidence

The [derivation](../../../specs/parliament_ballot_b6_mask_coordinate.md)
establishes an exact joint-state middle transformation under explicit ideal
material, fresh-pad and independently programmed challenge premises. It
preserves the entered ideal opening material and all chronological hidden
oracle assignments and primary counter writes. It does not establish an
exact transformation to the real-root material of frozen `Sim+`.

The [receipt](receipt.json) binds 27 source/specification/evidence inputs
and 29 source excerpts. Root and ownership agents completed local
consistency reviews. These are not independent cryptographic review or
owner acceptance. Production qualification remains false.

## Finite table verification

The retained [checker](finite_crt_check.py) and [report](finite_crt_report.json)
establish both actual low/high mask maps have rank 256, verify all 13,684
CRT unit-residue conditions, and check all 127,488 bilinear basis pairs for
the source table model. Bilinearity extends the latter identity to all
field masks and decoded index vectors. This is a finite mathematical check,
not execution or formal verification of the compiled Rust implementation.

The checker includes asymmetric matrix orientation, cross-word packing,
elementary polynomial/rank controls, and six deliberate single-bit table
mutations. It rejects optimized Python because its assertions are part of
the check. An independently repeated run matched the retained report byte
for byte in the recorded checkout.

From the repository root, verify the retained artifacts and rerun:

```sh
shasum -a 256 -c docs/validation/parliament_ballot_mask_coordinate/SHA256SUMS
python3.11 docs/validation/parliament_ballot_mask_coordinate/finite_crt_check.py --root "$PWD" > /tmp/parliament-mask-rerun.json
```

The checker reports the hashes it reads and checks they remain stable
during execution. It does not itself hardcode the frozen source hashes.
The following separate check requires every receipt-bound input to match
and compares the new result to the retained result, ignoring only the
absolute checkout path:

```sh
python3.11 - <<'PY'
import hashlib
import json
from pathlib import Path

root = Path.cwd()
base = root / "docs/validation/parliament_ballot_mask_coordinate"
receipt = json.loads((base / "receipt.json").read_text())
for name, expected in receipt["source_sha256_at_freeze"].items():
    actual = hashlib.sha256((root / name).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"Frozen input changed: {name}")
old = json.loads((base / "finite_crt_report.json").read_text())
new = json.loads(Path("/tmp/parliament-mask-rerun.json").read_text())
old.pop("root")
new.pop("root")
if old != new:
    raise SystemExit("Finite report does not match the frozen result")
print("All frozen inputs and finite results match")
PY
```

Do not reuse this receipt after a source mismatch. Review a new candidate
and create new evidence instead of rewriting these frozen results.

## Remaining boundary

The separate ideal high-mask stream is an entry premise: replacing hidden
expanded rows alone does not supply it. The API does not enforce the
latent pad's freshness or independence. The note also distinguishes cached
private slots on the already-charged `U_P=0` branch from ordinary oracle
reads of a single address.

The complete entry reductions, oracle-patch deletion, ideal-to-real
material bridge or distinct ideal public simulator, actual primitive
interface and quantum resources remain open. No security-ledger number,
frozen argument, production gate or qualification manifest is changed by
this evidence.
