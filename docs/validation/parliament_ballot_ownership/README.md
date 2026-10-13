# B6 source ownership boundary

This manual source audit supports a **conditional ownership argument** for the
frozen standalone `budget::Reservation::verify` call. All **ten unconditional
System `free` sites per image remain open**. This is not a machine ownership
proof, native-allocation exclusion, stack bound, workspace certificate or profile
qualification.

[report.json](report.json) records 12 findings with 65 source ranges and their
file/excerpt hashes. Its 61 local files and 20 vendor AES files still match
`started_source_sha256` in the original
[resource-contract build receipt](../parliament_ballot_resource_contract/build-receipt.json).
These counts describe the scoped hash inventory, including generated files and
one license; they do not assert that every inventoried line is reachable. No
worker was rebuilt or executed for this audit, and the old evidence was not
repinned.

The concrete entry consumes a `Reservation` containing only `Charge`, scalar
`Row`/`Role` values, and a borrowed record slice. Record/proof framing returns
borrowed subslices. Registration decoding creates seven fresh byte-vector
owners (body context and six opaque context fields); vote decoding creates one
fresh commitment vector. These are eight fields across two alternative roles,
not eight simultaneous statement vectors. The profile, frame, public-instance,
BAVC/VOLE scratch and private AES boxes are constructed during the call. CRT
storage is borrowed from embedded static tables. The `Copy` receipt and error
values return no heap owner, and ordinary error classification does not format
an error.

Consequently, under the pinned compiler/default-allocator semantics, memory
safety, valid layouts and stable active arena, successful nonzero allocations
in these source paths originate in the arena and ownership-preserving moves
retain that origin. This leaves two distinct obligations: every compiled
`free` operand must correspond to the live source allocation, and the current
arena/flag/provider state must remain intact despite opaque code, other threads,
signals or callbacks. The
[compiled ACTIVE analysis](../parliament_ballot_allocator_activation/README.md)
is conditional on related premises; it does not discharge them. The private
AES construction case also depends on the
[indirect-target analysis](../parliament_ballot_indirect_targets/README.md)
and intact provider/vtable state.

The larger worker opens its `File` before activation, then allocates and reads
its record after activation. The file, I/O errors, native `close`, outer record
drop and pthread/supervisor objects are outside this `Reservation` boundary.
Panic, unwind, allocation failure, traps and native runtime resources retain the
[separate failure-frontier obligations](../parliament_ballot_stack_frontiers/README.md).

TODO: establish universal source-to-machine pointer ownership for the eight
statement drop sites and two generic deallocation/reallocation sites, discharge
noninterference, and bound the retained native and exceptional paths. Production
activation remains gated.

To check this artifact and its pinned source comparison from the repository root:

```sh
shasum -a 256 -c docs/validation/parliament_ballot_ownership/SHA256SUMS
python3.11 - <<'PY'
import hashlib, json
from pathlib import Path
report = json.loads(Path('docs/validation/parliament_ballot_ownership/report.json').read_text())
for path, expected in report['source_comparison']['files'].items():
    assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected, path
for finding in report['findings']:
    for ref in finding['evidence']:
        lines = Path(ref['path']).read_text().splitlines(keepends=True)
        excerpt = ''.join(lines[ref['start_line'] - 1:ref['end_line']]).encode()
        assert hashlib.sha256(excerpt).hexdigest() == ref['excerpt_sha256'], ref
print('81 source files and 65 source excerpts match')
PY
```
